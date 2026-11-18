use super::Remote;
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub deadline: Duration,
    pub listing_bytes: u64,
    pub refs: usize,
    pub blob_bytes: u64,
    pub total_bytes: u64,
}

impl Limits {
    pub const PLAN: Self = Self {
        deadline: Duration::from_secs(60),
        listing_bytes: 16 * 1024 * 1024,
        refs: 100_000,
        blob_bytes: 64 * 1024 * 1024,
        total_bytes: 512 * 1024 * 1024,
    };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    LsRemote,
    Fetch,
    CatFile,
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::LsRemote => "ls-remote",
            Self::Fetch => "fetch",
            Self::CatFile => "cat-file",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    Run(Operation),
    Exit(Operation, i32),
    Signal(Operation, i32),
    Wait(Operation),
    Output(Operation),
    Deadline(Duration),
    ListingBytes(u64),
    ListingRefs(usize),
    Listing,
    NotListed,
    Changed,
    BlobBytes(u64),
    TotalBytes(u64),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run(op) => write!(f, "cannot run git {op}"),
            Self::Exit(op, code) => write!(f, "git {op} failed with exit status {code}"),
            Self::Signal(op, signal) => write!(f, "git {op} ended by signal {signal}"),
            Self::Wait(op) => write!(f, "cannot wait for git {op}"),
            Self::Output(op) => write!(f, "unexpected output from git {op}"),
            Self::Deadline(duration) if duration.subsec_nanos() == 0 => {
                write!(f, "remote did not finish within {}s", duration.as_secs())
            }
            Self::Deadline(duration) => {
                write!(f, "remote did not finish within {}ms", duration.as_millis())
            }
            Self::ListingBytes(n) => write!(f, "ref listing exceeds {n} bytes"),
            Self::ListingRefs(n) => write!(f, "ref listing exceeds {n} refs"),
            Self::Listing => f.write_str("invalid ref listing"),
            Self::NotListed => f.write_str("requested ref was not listed"),
            Self::Changed => f.write_str("a listed ref changed or is not a blob"),
            Self::BlobBytes(n) => write!(f, "a stoop ref exceeds {n} bytes"),
            Self::TotalBytes(n) => write!(f, "stoop refs exceed {n} bytes in total"),
        }
    }
}

pub struct Snapshot<'a> {
    remote: &'a Remote,
    refs: BTreeMap<String, String>,
    limits: Limits,
    deadline: Instant,
    left: Cell<u64>,
}

impl Remote {
    /// List once and share one deadline and byte budget across all fetches.
    pub fn snapshot(&self, limits: Limits) -> Result<Snapshot<'_>, String> {
        let deadline = Instant::now()
            .checked_add(limits.deadline)
            .ok_or_else(|| Failure::Deadline(limits.deadline).to_string())?;
        let listing = run_git(
            self,
            Operation::LsRemote,
            deadline,
            limits.deadline,
            &["ls-remote", "--", &self.remote, "refs/stoop/*"],
            (false, true),
            |_, output| {
                let output =
                    output.ok_or_else(|| Failure::Output(Operation::LsRemote).to_string())?;
                let mut bytes = Vec::new();
                output
                    .take(limits.listing_bytes.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|_| Failure::Output(Operation::LsRemote).to_string())?;
                if bytes.len() as u64 > limits.listing_bytes {
                    return Err(Failure::ListingBytes(limits.listing_bytes).to_string());
                }
                Ok(bytes)
            },
        )?;
        let refs = parse_listing(&listing, limits.refs).map_err(|e| e.to_string())?;
        Ok(Snapshot {
            remote: self,
            refs,
            limits,
            deadline,
            left: Cell::new(limits.total_bytes),
        })
    }
}

fn parse_listing(listing: &[u8], limit: usize) -> Result<BTreeMap<String, String>, Failure> {
    let mut refs = BTreeMap::new();
    if listing.is_empty() {
        return Ok(refs);
    }
    let lines = listing.strip_suffix(b"\n").ok_or(Failure::Listing)?;
    for (index, line) in lines.split(|byte| *byte == b'\n').enumerate() {
        if index >= limit {
            return Err(Failure::ListingRefs(limit));
        }
        let tab = line
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(Failure::Listing)?;
        let (oid, name) = (&line[..tab], &line[tab + 1..]);
        if !matches!(oid.len(), 40 | 64)
            || !oid
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Failure::Listing);
        }
        if !name.starts_with(b"refs/stoop/") {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| Failure::Listing)?;
        if name.len() == "refs/stoop/".len() || name.chars().any(char::is_control) {
            return Err(Failure::Listing);
        }
        // The OID was checked as ASCII hex above.
        let oid = std::str::from_utf8(oid).map_err(|_| Failure::Listing)?;
        if refs.insert(name.to_owned(), oid.to_owned()).is_some() {
            return Err(Failure::Listing);
        }
    }
    Ok(refs)
}

impl Snapshot<'_> {
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.refs.contains_key(name)
    }

    pub fn fetch(
        &self,
        names: &[String],
        mut each: impl FnMut(&str, &[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        if names.is_empty() {
            return Ok(());
        }
        if names.iter().any(|name| !self.refs.contains_key(name)) {
            return Err(Failure::NotListed.to_string());
        }
        for chunk in names.chunks(500) {
            let specs: Vec<String> = chunk.iter().map(|name| format!("+{name}:{name}")).collect();
            let mut args = vec![
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                self.remote.remote.as_str(),
            ];
            args.extend(specs.iter().map(String::as_str));
            run_git(
                self.remote,
                Operation::Fetch,
                self.deadline,
                self.limits.deadline,
                &args,
                (false, false),
                |_, _| Ok(()),
            )?;
        }
        run_git(
            self.remote,
            Operation::CatFile,
            self.deadline,
            self.limits.deadline,
            &["cat-file", "--batch"],
            (true, true),
            |input, output| {
                let output_error = || Failure::Output(Operation::CatFile).to_string();
                let mut input = input.ok_or_else(output_error)?;
                let mut output = BufReader::new(output.ok_or_else(output_error)?);
                for name in names {
                    writeln!(input, "{name}")
                        .and_then(|()| input.flush())
                        .map_err(|_| output_error())?;
                    let mut header = [0u8; 512];
                    let mut length = 0;
                    loop {
                        if length == header.len() {
                            return Err(output_error());
                        }
                        output
                            .read_exact(&mut header[length..length + 1])
                            .map_err(|_| output_error())?;
                        if header[length] == b'\n' {
                            break;
                        }
                        length += 1;
                    }
                    let mut fields = header[..length].split(|byte| *byte == b' ');
                    let oid = fields.next();
                    let kind = fields.next();
                    let size = fields.next();
                    if oid != self.refs.get(name).map(|value| value.as_bytes())
                        || kind != Some(&b"blob"[..])
                        || size.is_none()
                        || fields.next().is_some()
                    {
                        return Err(Failure::Changed.to_string());
                    }
                    let size = size.ok_or_else(output_error)?;
                    if size.is_empty() || !size.iter().all(u8::is_ascii_digit) {
                        return Err(output_error());
                    }
                    let size: u64 = std::str::from_utf8(size)
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(output_error)?;
                    if size > self.limits.blob_bytes {
                        return Err(Failure::BlobBytes(self.limits.blob_bytes).to_string());
                    }
                    if size > self.left.get() {
                        return Err(Failure::TotalBytes(self.limits.total_bytes).to_string());
                    }
                    self.left.set(self.left.get() - size);
                    let capacity = usize::try_from(size).map_err(|_| output_error())?;
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(capacity)
                        .map_err(|_| output_error())?;
                    bytes.resize(capacity, 0);
                    (&mut output)
                        .take(size)
                        .read_exact(&mut bytes)
                        .map_err(|_| output_error())?;
                    let mut delimiter = [0u8];
                    output
                        .read_exact(&mut delimiter)
                        .map_err(|_| output_error())?;
                    if delimiter != *b"\n" {
                        return Err(output_error());
                    }
                    each(name, &bytes)?;
                }
                Ok(())
            },
        )
    }
}

struct Control {
    io_done: AtomicBool,
    abort: AtomicBool,
}

enum Outcome {
    Exited(ExitStatus),
    TimedOut,
    Aborted,
    Lost,
}

// Owns the unreaped leader. In particular, a failed watcher-thread spawn must
// not strand the child, and an unreaped leader keeps its process-group id ours.
struct ManagedChild(Option<Child>);

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            stop(&mut child);
        }
    }
}

fn stop(child: &mut Child) {
    let pgid = child.id() as libc::pid_t;
    // The leader has not been reaped, so this process-group id cannot be reused.
    unsafe { libc::kill(-pgid, libc::SIGTERM) };
    thread::sleep(Duration::from_millis(200));
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
}

fn watch(child: &mut Child, control: &Control, deadline: Instant) -> Outcome {
    loop {
        let now = Instant::now();
        if now >= deadline {
            stop(child);
            return Outcome::TimedOut;
        }
        if control.abort.load(Ordering::SeqCst) {
            stop(child);
            return Outcome::Aborted;
        }
        // Do not reap before I/O completes. A leader can exit while a helper
        // still holds a pipe; retaining its pid lets us terminate the group.
        if control.io_done.load(Ordering::SeqCst) {
            match child.try_wait() {
                Ok(Some(status)) => return Outcome::Exited(status),
                Ok(None) => {}
                Err(_) => {
                    stop(child);
                    return Outcome::Lost;
                }
            }
        }
        thread::sleep(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
    }
}

fn timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "git deadline expired")
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_ready(fd: RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        if remaining.is_zero() {
            return Err(timeout_error());
        }
        let millis = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pollfd, 1, millis) };
        if rc > 0 {
            return Ok(());
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }
}

// Nonblocking pipes are also necessary if a descendant escapes the group while
// retaining a descriptor. The deadline still bounds the caller's reads/writes.
struct TimedPipe<T> {
    inner: T,
    deadline: Instant,
}

impl<T: Read + AsRawFd> Read for TimedPipe<T> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(timeout_error());
            }
            match self.inner.read(buffer) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.inner.as_raw_fd(), libc::POLLIN, self.deadline)?;
                }
                result => return result,
            }
        }
    }
}

impl<T: Write + AsRawFd> Write for TimedPipe<T> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(timeout_error());
            }
            match self.inner.write(buffer) {
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.inner.as_raw_fd(), libc::POLLOUT, self.deadline)?;
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn run_git<T>(
    remote: &Remote,
    op: Operation,
    deadline: Instant,
    duration: Duration,
    args: &[&str],
    pipes: (bool, bool),
    work: impl FnOnce(
        Option<TimedPipe<ChildStdin>>,
        Option<TimedPipe<ChildStdout>>,
    ) -> Result<T, String>,
) -> Result<T, String> {
    let (input, output) = pipes;
    if Instant::now() >= deadline {
        return Err(Failure::Deadline(duration).to_string());
    }
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(&remote.repo)
        .args([
            "-c",
            "http.lowSpeedLimit=1000",
            "-c",
            "http.lowSpeedTime=20",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_ATTR_SOURCE")
        .stdin(if input { Stdio::piped() } else { Stdio::null() })
        .stdout(if output {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stderr(Stdio::null())
        .process_group(0);
    #[cfg(test)]
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ALLOW_PROTOCOL", "file");
    let mut child = command.spawn().map_err(|_| Failure::Run(op).to_string())?;
    let stdin = child.stdin.take();
    let stdout = child.stdout.take();
    let control = Arc::new(Control {
        io_done: AtomicBool::new(false),
        abort: AtomicBool::new(false),
    });
    let watched = Arc::clone(&control);
    let mut child = ManagedChild(Some(child));
    let watcher = thread::Builder::new()
        .spawn(move || {
            let outcome = watch(child.0.as_mut().expect("owned child"), &watched, deadline);
            // watch reaps the leader on every return path.
            child.0.take();
            outcome
        })
        .map_err(|_| Failure::Run(op).to_string())?;
    let result = (|| {
        let input = stdin
            .map(|pipe| {
                nonblocking(pipe.as_raw_fd()).map_err(|_| Failure::Output(op).to_string())?;
                Ok::<_, String>(TimedPipe {
                    inner: pipe,
                    deadline,
                })
            })
            .transpose()?;
        let output = stdout
            .map(|pipe| {
                nonblocking(pipe.as_raw_fd()).map_err(|_| Failure::Output(op).to_string())?;
                Ok::<_, String>(TimedPipe {
                    inner: pipe,
                    deadline,
                })
            })
            .transpose()?;
        work(input, output)
    })();
    if result.is_err() {
        control.abort.store(true, Ordering::SeqCst);
    }
    control.io_done.store(true, Ordering::SeqCst);
    let outcome = watcher.join().unwrap_or(Outcome::Lost);
    match outcome {
        Outcome::TimedOut => Err(Failure::Deadline(duration).to_string()),
        _ if result.is_err() => result,
        Outcome::Exited(status) if status.success() => result,
        Outcome::Exited(status) => {
            if let Some(code) = status.code() {
                Err(Failure::Exit(op, code).to_string())
            } else if let Some(signal) = status.signal() {
                Err(Failure::Signal(op, signal).to_string())
            } else {
                Err(Failure::Output(op).to_string())
            }
        }
        Outcome::Aborted => Err(Failure::Output(op).to_string()),
        Outcome::Lost => Err(Failure::Wait(op).to_string()),
    }
}

#[cfg(test)]
#[path = "bounded_tests.rs"]
mod tests;
