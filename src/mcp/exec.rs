//! Run the stoop binary as a child: bounded output, a deadline, cancellation, and a watchdog.
//!
//! Each child leads its own process group, so a timeout, a cancellation or a signal takes the
//! whole tree with it. A watchdog shell holds a heartbeat pipe: when the server exits without
//! finishing (SIGKILL included), the pipe closes and the watchdog kills the group. The decision
//! of `stoop run` comes back on a pipe the wrapped command never holds (see `STATUS_FD`).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The descriptor `stoop run --status-fd` reports on. `stoop run` makes it close-on-exec before
/// it starts the command, so the command never holds it and cannot write a decision.
pub const STATUS_FD: RawFd = 3;

/// The group of the child in flight, read by the signal handler. 0 when no child runs.
static CHILD_GROUP: AtomicI32 = AtomicI32::new(0);

/// The watchdog reads the group id from the heartbeat, then one more line. Only "done" leaves the
/// group alone. Anything else, end of input included, means the server is gone. The kill is
/// written `kill -s KILL -- "-$pgid"`: dash, Linux's /bin/sh, does not kill the group for
/// `kill -KILL -- "-$pgid"`, and the 2>/dev/null hides why.
const WATCHDOG: &str = r#"read pgid; read line; if [ "$line" != done ]; then kill -s KILL -- "-$pgid" 2>/dev/null; fi; exit 0"#;

/// The most a decision report may hold.
const REPORT_CAP: usize = 64 * 1024;

pub struct Keep {
    pub cap: usize,
    /// Keep the last `cap` bytes (a run's output) rather than the first (a plan's JSON).
    pub tail: bool,
}

pub struct Limits {
    pub timeout: Duration,
    pub stdout: Keep,
    pub stderr: Keep,
    /// Variables the child must not inherit: the sync settings, for the read-only tools.
    pub drop_env: &'static [&'static str],
    /// Whether `stoop run` reports its decision on `STATUS_FD`.
    pub report: bool,
}

/// Bytes kept from one stream, and the true total they came from.
#[derive(Debug, Clone)]
pub struct Stream {
    pub text: String,
    pub bytes: u64,
    pub truncated: bool,
}

pub struct Finished {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Stream,
    pub stderr: Stream,
    pub timed_out: bool,
    pub cancelled: bool,
    /// The one-line decision `stoop run` reported, if it reported one.
    pub report: Option<String>,
}

struct Tail {
    keep: Keep,
    total: u64,
    buf: Vec<u8>,
}

impl Tail {
    fn new(keep: Keep) -> Tail {
        Tail {
            keep,
            total: 0,
            buf: Vec::new(),
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.total += chunk.len() as u64;
        if self.keep.tail {
            self.buf.extend_from_slice(chunk);
            // Trim in batches so a long stream is not shifted on every read.
            if self.buf.len() > 2 * self.keep.cap {
                let cut = self.buf.len() - self.keep.cap;
                self.buf.drain(..cut);
            }
        } else if self.buf.len() < self.keep.cap {
            let room = self.keep.cap - self.buf.len();
            self.buf.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
    }

    fn finish(&self) -> Stream {
        let kept = if self.keep.tail && self.buf.len() > self.keep.cap {
            &self.buf[self.buf.len() - self.keep.cap..]
        } else {
            &self.buf[..]
        };
        Stream {
            text: String::from_utf8_lossy(kept).into_owned(),
            bytes: self.total,
            truncated: self.total > kept.len() as u64,
        }
    }
}

fn spawn_reader<R: Read + Send + 'static>(mut source: R, sink: Arc<Mutex<Tail>>, done: Sender<()>) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = source.read(&mut chunk) {
            if n == 0 {
                break;
            }
            sink.lock().unwrap().push(&chunk[..n]);
        }
        let _ = done.send(());
    });
}

fn set_flag(fd: RawFd, command: libc::c_int, value: libc::c_int) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor this process owns.
    if unsafe { libc::fcntl(fd, command, value) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A pipe whose two ends are close-on-exec, so no child started later inherits them.
fn pipe() -> io::Result<(File, File)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe writes two new descriptors into the array it is given.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors are new and owned by nothing else.
    let read = unsafe { File::from_raw_fd(fds[0]) };
    // SAFETY: as above.
    let write = unsafe { File::from_raw_fd(fds[1]) };
    set_flag(read.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC)?;
    set_flag(write.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC)?;
    Ok((read, write))
}

/// A shell that kills the group named on its first line, unless its heartbeat ends with "done".
/// It keeps its own group, so that kill does not reach it.
fn start_watchdog() -> io::Result<(Child, File)> {
    let (read, write) = pipe()?;
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg(WATCHDOG)
        .arg("stoop-watchdog")
        .stdin(Stdio::from(read))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    Ok((child, write))
}

/// Runs in the child between fork and exec: the report pipe becomes `STATUS_FD` there.
fn place_status_fd(fd: RawFd) -> io::Result<()> {
    if fd == STATUS_FD {
        return set_flag(fd, libc::F_SETFD, 0);
    }
    // SAFETY: dup2 is async-signal-safe and runs only in the child.
    if unsafe { libc::dup2(fd, STATUS_FD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The one line `stoop run` wrote, if it wrote one. Every writer has exited by now, so this
/// reads what is there and never waits.
fn read_report(mut file: File) -> Option<String> {
    set_flag(file.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK).ok()?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    while bytes.len() < REPORT_CAP {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let text = String::from_utf8(bytes).ok()?;
    text.lines().next().map(str::to_string)
}

/// SIGKILL the child's process group. Only called while the child is still unreaped, so its
/// process group id cannot have been reused.
fn kill_group(pid: i32) {
    // SAFETY: killpg only sends a signal; a failure (the group is already gone) is harmless.
    unsafe {
        libc::killpg(pid, libc::SIGKILL);
    }
}

extern "C" fn stop_on_signal(signal: libc::c_int) {
    let group = CHILD_GROUP.load(Ordering::SeqCst);
    if group > 0 {
        // SAFETY: killpg and _exit are async-signal-safe.
        unsafe {
            libc::killpg(group, libc::SIGKILL);
        }
    }
    // SAFETY: as above.
    unsafe { libc::_exit(128 + signal) }
}

/// SIGTERM, SIGINT and SIGHUP kill the child in flight and exit, so no run outlives the server.
/// SIGKILL cannot be caught; the watchdog covers it.
pub fn install_signal_handlers() {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        // SAFETY: the handler makes only async-signal-safe calls.
        unsafe {
            libc::signal(signal, stop_on_signal as *const () as libc::sighandler_t);
        }
    }
}

/// Run `exe` with `args` in `cwd`. `cancelled` is polled while it runs; returning true stops it.
pub fn run(
    exe: &Path,
    args: &[String],
    cwd: &Path,
    limits: Limits,
    cancelled: &mut dyn FnMut() -> bool,
) -> io::Result<Finished> {
    let (mut watchdog, mut heartbeat) = start_watchdog()?;
    let (report_read, report_write) = if limits.report {
        let (read, write) = pipe()?;
        (Some(read), Some(write))
    } else {
        (None, None)
    };
    let mut command = Command::new(exe);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    for name in limits.drop_env {
        command.env_remove(name);
    }
    if let Some(write) = &report_write {
        let fd = write.as_raw_fd();
        // SAFETY: runs in the child after fork and before exec, with only async-signal-safe calls.
        unsafe {
            command.pre_exec(move || place_status_fd(fd));
        }
    }
    let spawned = command.spawn();
    drop(report_write);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _ = heartbeat.write_all(b"done\n");
            let _ = watchdog.wait();
            return Err(error);
        }
    };
    let pid = child.id() as i32;
    // The watchdog learns the group now. Its heartbeat must end with "done" on a normal finish.
    let _ = writeln!(heartbeat, "{pid}");
    CHILD_GROUP.store(pid, Ordering::SeqCst);

    let out = Arc::new(Mutex::new(Tail::new(limits.stdout)));
    let err = Arc::new(Mutex::new(Tail::new(limits.stderr)));
    let (done_tx, done_rx) = channel();
    spawn_reader(
        child.stdout.take().expect("piped"),
        Arc::clone(&out),
        done_tx.clone(),
    );
    spawn_reader(
        child.stderr.take().expect("piped"),
        Arc::clone(&err),
        done_tx,
    );

    let started = Instant::now();
    let mut timed_out = false;
    let mut was_cancelled = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if started.elapsed() >= limits.timeout {
            timed_out = true;
            kill_group(pid);
            break child.wait().ok();
        }
        if cancelled() {
            was_cancelled = true;
            kill_group(pid);
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    CHILD_GROUP.store(0, Ordering::SeqCst);
    let report = report_read.and_then(read_report);
    // A normal finish leaves the group alone: a background process the command started may
    // outlive it. A timeout or cancellation already killed the group above.
    let _ = heartbeat.write_all(b"done\n");
    let _ = watchdog.wait();

    // A grandchild may hold a pipe open. Wait briefly for the readers, then take what is there.
    let deadline = Instant::now() + Duration::from_millis(500);
    for _ in 0..2 {
        let left = deadline.saturating_duration_since(Instant::now());
        if done_rx.recv_timeout(left).is_err() {
            break;
        }
    }
    let stdout = out.lock().unwrap().finish();
    let stderr = err.lock().unwrap().finish();
    Ok(Finished {
        code: status.and_then(|s| s.code()),
        signal: status.and_then(|s| s.signal()),
        stdout,
        stderr,
        timed_out,
        cancelled: was_cancelled,
        report,
    })
}
