//! Bounded, read-only Git probes that feed object-ID evidence.
//!
//! A probe runs one allowlisted Git invocation in its own process group under
//! a fixed deadline. Stdout is capped before it is retained, stderr is
//! discarded, and the leader is killed and reaped on every path. Bytes are
//! returned only when Git exits zero, so every failure looks the same to the
//! caller and leaks nothing.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const DEADLINE: Duration = Duration::from_secs(3);
const CHUNK: usize = 64 * 1024;

// The only invocations a probe may run, matched exactly. None runs a hook,
// filter, pager, shell or transport. Adding one needs the same review.
const ALLOWED: &[&[&str]] = &[
    &[
        "rev-parse",
        "--path-format=absolute",
        "--show-toplevel",
        "--absolute-git-dir",
        "--git-common-dir",
        "--show-object-format",
    ],
    &["config", "--null", "--list", "--no-includes", "--show-origin"],
    &["ls-files", "--stage", "-z"],
    &["ls-files", "--others", "--exclude-standard", "-z"],
    &["check-attr", "--all", "-z", "--stdin"],
];

fn allowed(args: &[&str]) -> bool {
    ALLOWED.iter().any(|candidate| *candidate == args)
}

/// Runs `git -C root <args>` with `input` on stdin. Returns stdout only when
/// Git exits zero within the deadline and writes at most `max_bytes`. Every
/// other outcome returns `None`, including an argument vector outside
/// `ALLOWED`.
///
/// This bounds how Git runs. It does not establish that the repository's
/// configuration and attribute sources are safe; the caller must do that first.
pub fn output(root: &Path, args: &[&str], input: &[u8], max_bytes: usize) -> Option<Vec<u8>> {
    if !allowed(args) {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let mut command = Command::new("git");
    for (key, _) in std::env::vars_os() {
        if key.as_os_str().as_bytes().starts_with(b"GIT_") {
            command.env_remove(key);
        }
    }
    if let Some(parent) = root.parent() {
        // Discovery may end at root but never above its parent.
        command.env("GIT_CEILING_DIRECTORIES", std::env::join_paths([parent]).ok()?);
    }
    command
        .arg("-C")
        .arg(&root)
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "maintenance.auto=false",
            "-c",
            "protocol.allow=never",
        ])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_ALLOW_PROTOCOL", "");
    run(command, input, max_bytes, DEADLINE)
}

fn run(mut command: Command, input: &[u8], max_bytes: usize, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now().checked_add(timeout)?;
    let child = spawn(&mut command).ok()?;
    collect(child, input, max_bytes, deadline)
}

fn spawn(command: &mut Command) -> io::Result<Child> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()
}

// Owns the leader until it is reaped. Its PID doubles as its process-group ID,
// and that ID cannot be reused while the leader is unreaped.
struct Leader {
    child: Child,
    reaped: bool,
}

impl Leader {
    fn signal_group(&self) {
        unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
    }

    // Reports whether the leader has exited, leaving it unreaped so the group
    // ID stays ours until the group has been signalled.
    fn exited(&self) -> io::Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc == 0 {
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err);
            }
        }
    }

    // Kills whatever remains in the group, then reaps the leader.
    fn finish(&mut self) -> Option<ExitStatus> {
        self.signal_group();
        self.reaped = true;
        self.child.wait().ok()
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if !self.reaped {
            self.signal_group();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn retryable(err: &io::Error) -> bool {
    matches!(err.kind(), io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock)
}

// Grows `out` for `extra` bytes that were just read, never past `max_bytes`.
fn reserve(out: &mut Vec<u8>, extra: usize, max_bytes: usize) -> Option<()> {
    let needed = out.len().checked_add(extra)?;
    if needed > max_bytes {
        return None;
    }
    if out.capacity() < needed {
        let target = out.capacity().saturating_mul(2).max(needed).min(max_bytes);
        out.try_reserve_exact(target - out.len()).ok()?;
    }
    Some(())
}

fn collect(child: Child, input: &[u8], max_bytes: usize, deadline: Instant) -> Option<Vec<u8>> {
    let mut leader = Leader { child, reaped: false };
    let mut stdin = leader.child.stdin.take().filter(|_| !input.is_empty());
    let mut stdout = leader.child.stdout.take();
    if let Some(pipe) = &stdin {
        nonblocking(pipe.as_raw_fd()).ok()?;
    }
    if let Some(pipe) = &stdout {
        nonblocking(pipe.as_raw_fd()).ok()?;
    }
    let mut written: usize = 0;
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; CHUNK];

    loop {
        if Instant::now() >= deadline {
            return None;
        }
        let mut progressed = false;

        if let Some(mut pipe) = stdout.take() {
            // One byte past the room left tells "exactly at the cap" from "over".
            let room = max_bytes - out.len();
            let want = room.saturating_add(1).min(CHUNK);
            match pipe.read(&mut chunk[..want]) {
                Ok(0) => progressed = true, // EOF; dropping the pipe closes it
                Ok(n) if n > room => return None,
                Ok(n) => {
                    reserve(&mut out, n, max_bytes)?;
                    out.extend_from_slice(&chunk[..n]);
                    stdout = Some(pipe);
                    progressed = true;
                }
                Err(err) if retryable(&err) => stdout = Some(pipe),
                Err(_) => return None,
            }
        }

        if let Some(mut pipe) = stdin.take() {
            let end = written.saturating_add(CHUNK).min(input.len());
            match pipe.write(&input[written..end]) {
                Ok(0) => return None,
                Ok(n) => {
                    written += n;
                    progressed = true;
                    // Dropping the pipe after the last byte closes stdin, so Git sees the end of input.
                    if written < input.len() {
                        stdin = Some(pipe);
                    }
                }
                Err(err) if retryable(&err) => stdin = Some(pipe),
                Err(_) => return None,
            }
        }

        if stdin.is_none() && stdout.is_none() {
            match leader.exited() {
                Ok(true) => return leader.finish()?.success().then_some(out),
                Ok(false) => {}
                Err(_) => return None,
            }
        }
        if progressed {
            continue;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut fds = [
            libc::pollfd { fd: -1, events: 0, revents: 0 },
            libc::pollfd { fd: -1, events: 0, revents: 0 },
        ];
        let mut count: usize = 0;
        if let Some(pipe) = &stdout {
            fds[count] = libc::pollfd { fd: pipe.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            count += 1;
        }
        if let Some(pipe) = &stdin {
            fds[count] = libc::pollfd { fd: pipe.as_raw_fd(), events: libc::POLLOUT, revents: 0 };
            count += 1;
        }
        let mut millis = remaining.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32;
        if count == 0 {
            // Only the leader's exit remains, and poll cannot wait on it.
            millis = millis.min(10);
        }
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), count as libc::nfds_t, millis) };
        if rc < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return None;
        }
        if fds[..count].iter().any(|fd| (fd.revents & libc::POLLNVAL) != 0) {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stoop-gitprobe-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // Kills the escaped holder even when an assertion fails first.
    struct Holder(PathBuf);

    impl Drop for Holder {
        fn drop(&mut self) {
            if let Some(pid) = read_pid(&self.0) {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }

    fn read_pid(path: &Path) -> Option<libc::pid_t> {
        fs::read_to_string(path).ok()?.trim().parse().ok()
    }

    fn assert_reaped(pid: u32) {
        let mut status = 0;
        let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    }

    // Fixture setup runs outside the probe, so it also drops inherited GIT_* overrides.
    fn git(dir: &Path, args: &[&str]) {
        let mut command = Command::new("git");
        for (key, _) in std::env::vars_os() {
            if key.as_os_str().as_bytes().starts_with(b"GIT_") {
                command.env_remove(key);
            }
        }
        let status = command
            .arg("-C")
            .arg(dir)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn repo() -> Dir {
        let dir = Dir::new();
        git(&dir.0, &["init", "-q"]);
        dir
    }

    fn sh(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn only_the_snapshot_invocations_are_allowed() {
        assert!(allowed(&["ls-files", "--stage", "-z"]));
        assert!(allowed(&["check-attr", "--all", "-z", "--stdin"]));
        assert!(!allowed(&["var", "GIT_ATTR_SYSTEM"]));
        assert!(!allowed(&["var", "-l"]));
        assert!(!allowed(&["version"]));
        assert!(!allowed(&["ls-files"]));
        assert!(!allowed(&["ls-files", "--stage", "-z", "--debug"]));
        assert!(!allowed(&["config", "--list", "--edit"]));
        assert!(!allowed(&["config", "--edit"]));
        assert!(!allowed(&["-c", "alias.x=!sh", "x"]));
        assert!(!allowed(&["status"]));
    }

    #[test]
    fn allowed_invocation_returns_stdout_and_a_disallowed_one_never_runs() {
        let dir = repo();
        fs::write(dir.0.join("file.txt"), b"x").unwrap();
        git(&dir.0, &["add", "file.txt"]);
        let stage = output(&dir.0, &["ls-files", "--stage", "-z"], &[], 4096).unwrap();
        assert!(stage.starts_with(b"100644 "));
        assert!(stage.ends_with(b"\tfile.txt\0"));

        fs::write(dir.0.join(".gitattributes"), b"*.txt eol=crlf\n").unwrap();
        let attrs = output(
            &dir.0,
            &["check-attr", "--all", "-z", "--stdin"],
            b"file.txt\0",
            4096,
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&attrs).contains("file.txt\0eol\0crlf\0"));

        assert_eq!(output(&dir.0, &["config", "--edit"], &[], 4096), None);
    }

    #[test]
    fn nonzero_exit_and_stderr_never_return_bytes() {
        let outside = Dir::new();
        let rev_parse: &[&str] = &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-object-format",
        ];
        assert_eq!(output(&outside.0, rev_parse, &[], 4096), None);
        assert_eq!(
            run(sh("printf secret >&2; printf ok; exit 3"), b"", 16, Duration::from_secs(2)),
            None
        );
        assert_eq!(
            run(sh("printf secret >&2; printf ok"), b"", 16, Duration::from_secs(2)),
            Some(b"ok".to_vec())
        );
    }

    #[test]
    fn output_is_capped_before_it_is_retained() {
        let timeout = Duration::from_secs(2);
        assert_eq!(run(sh("head -c 100000 /dev/zero"), b"", 1000, timeout), None);
        assert_eq!(run(Command::new("/bin/cat"), b"x", 0, timeout), None);
        assert_eq!(run(Command::new("/bin/cat"), b"abc", 3, timeout), Some(b"abc".to_vec()));
        assert_eq!(run(Command::new("/bin/cat"), b"", 0, timeout), Some(Vec::new()));
        let big = vec![b'a'; CHUNK * 4];
        assert_eq!(run(Command::new("/bin/cat"), &big, big.len() - 1, timeout), None);
    }

    #[test]
    fn deadline_kills_and_reaps_a_stalled_leader() {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let child = spawn(&mut command).unwrap();
        let pid = child.id();
        let start = Instant::now();
        assert_eq!(collect(child, &[], 16, start + Duration::from_millis(300)), None);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_reaped(pid);
    }

    // Re-entered only by the escape test, through STOOP_GITPROBE_HELPER. The
    // leader starts a holder in its own group that inherits stdout, records
    // the holder's PID, and exits, so the holder alone keeps the pipe open.
    #[test]
    fn held_pipe_helper() {
        match std::env::var("STOOP_GITPROBE_HELPER").as_deref() {
            Ok("escape") => {
                let holder = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "gitprobe::tests::held_pipe_helper"])
                    .env("STOOP_GITPROBE_HELPER", "hold")
                    .stdin(Stdio::null())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::null())
                    .process_group(0)
                    .spawn()
                    .unwrap();
                let pid_path = std::env::var_os("STOOP_GITPROBE_PID").unwrap();
                fs::write(pid_path, holder.id().to_string()).unwrap();
                std::process::exit(0);
            }
            Ok("hold") => {
                thread::sleep(Duration::from_secs(10));
                std::process::exit(0);
            }
            _ => {}
        }
    }

    #[test]
    fn escaped_holder_of_stdout_cannot_extend_the_deadline() {
        let dir = Dir::new();
        let pid_path = dir.0.join("holder.pid");
        let _holder = Holder(pid_path.clone());
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "gitprobe::tests::held_pipe_helper"])
            .env("STOOP_GITPROBE_HELPER", "escape")
            .env("STOOP_GITPROBE_PID", &pid_path);
        let leader = spawn(&mut command).unwrap();
        let leader_pid = leader.id();
        let waited = Instant::now();
        while read_pid(&pid_path).is_none() {
            assert!(waited.elapsed() < Duration::from_secs(30), "holder never started");
            thread::sleep(Duration::from_millis(10));
        }
        let start = Instant::now();
        assert_eq!(collect(leader, &[], 4096, start + Duration::from_secs(1)), None);
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_reaped(leader_pid);
    }

    #[test]
    fn large_input_and_output_are_pipelined_without_deadlock() {
        let input: Vec<u8> = (0..1_048_576usize).map(|i| (i % 251) as u8).collect();
        let echoed = run(Command::new("/bin/cat"), &input, input.len(), Duration::from_secs(10));
        assert_eq!(echoed.as_deref(), Some(input.as_slice()));
    }

    #[test]
    fn a_reader_that_never_drains_input_cannot_hold_the_caller() {
        let input = vec![0u8; 4 * 1024 * 1024];
        let start = Instant::now();
        assert_eq!(run(sh("sleep 30"), &input, 16, Duration::from_millis(300)), None);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn missing_root_fails_closed() {
        let missing = std::env::temp_dir().join("stoop-gitprobe-no-such-root");
        assert_eq!(output(&missing, &["ls-files", "--stage", "-z"], &[], 16), None);
    }
}
