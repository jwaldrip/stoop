//! A diagnostic macOS tracer: DTrace under passwordless `sudo`.
//!
//! Diagnostic only. The observations are returned with a standing `unsound` reason, so no
//! caller can record a proof from them. The privileged spike found DTrace the only tool that
//! saw every category it can observe on hosted runners, and it still lacks symlink targets,
//! errno and exact directory listings, so a recorded proof waits on those gaps.
//!
//! How a run goes:
//! 1. The command is started inside a wrapper that blocks on a pipe, so its pid is known
//!    before it can do anything.
//! 2. DTrace is armed for that pid's process tree. The command is released only after the
//!    script prints `READY`, so a tracer that never arms never lets the command run.
//! 3. DTrace stops itself shortly after the root process exits. Every loss or error it can
//!    report, every line this parser cannot read and every missing marker makes the
//!    observation unsound.
//!
//! A failure before the command starts is an `Err` and the caller runs the command untraced.
//! A failure after it starts is never an `Err`: the command's status comes back with
//! `unsound` set, because an `Err` would make the caller run the command a second time.

use super::Trace;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The reason every macOS observation carries.
pub const DIAGNOSTIC_ONLY: &str =
    "diagnostic backend: macOS observations are not recorded as proofs";

/// `AT_FDCWD` on macOS.
const AT_FDCWD: i32 = -2;
const O_WRONLY: i32 = 0x1;
const O_RDWR: i32 = 0x2;
const O_APPEND: i32 = 0x8;
const O_CREAT: i32 = 0x200;
const O_TRUNC: i32 = 0x400;
/// The script's strings are cut at this many bytes, so a path this long may be truncated.
const STRSIZE: usize = 1024;
const MAX_REASONS: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Tree membership starts at the command's pid (`$1`) and grows through `proc:::create`.
/// A path-taking probe reports only for members. The tracer stops itself half a second after
/// the root exits, which flushes every buffer first.
const SCRIPT: &str = r#"#pragma D option quiet
#pragma D option zdefs
#pragma D option dynvarsize=128m
#pragma D option strsize=1024
#pragma D option switchrate=10ms

int tree[pid_t];
int done;

BEGIN
{
	tree[$1] = 1;
	printf("READY\n");
}

proc:::create
/tree[pid]/
{
	tree[args[0]->pr_pid] = 1;
	printf("SPAWN\t%d\t%d\n", pid, args[0]->pr_pid);
}

proc:::exec-success
/tree[pid]/
{
	printf("EXEC\t%d\t%s\n", pid, execname);
}

proc:::exit
/tree[pid]/
{
	printf("EXIT\t%d\n", pid);
}

proc:::exit
/pid == $1/
{
	done = timestamp;
}

tick-50ms
/done != 0 && timestamp > done + 500000000/
{
	printf("STOP\n");
	exit(0);
}

syscall::open:entry, syscall::open_nocancel:entry
/tree[pid]/
{
	printf("EV\t%d\topen\t-\t%d\t%s\n", pid, (int)arg1, copyinstr(arg0));
}

syscall::openat:entry, syscall::openat_nocancel:entry
/tree[pid]/
{
	printf("EV\t%d\topenat\t%d\t%d\t%s\n", pid, (int)arg0, (int)arg2, copyinstr(arg1));
}

syscall::stat:entry, syscall::stat64:entry
/tree[pid]/
{
	printf("EV\t%d\tstat\t-\t-\t%s\n", pid, copyinstr(arg0));
}

syscall::lstat:entry, syscall::lstat64:entry
/tree[pid]/
{
	printf("EV\t%d\tlstat\t-\t-\t%s\n", pid, copyinstr(arg0));
}

syscall::access:entry, syscall::getattrlist:entry, syscall::readlink:entry
/tree[pid]/
{
	printf("EV\t%d\t%s\t-\t-\t%s\n", pid, probefunc, copyinstr(arg0));
}

syscall::faccessat:entry, syscall::fstatat:entry, syscall::fstatat64:entry
/tree[pid]/
{
	printf("EV\t%d\tstat\t%d\t-\t%s\n", pid, (int)arg0, copyinstr(arg1));
}

syscall::execve:entry
/tree[pid]/
{
	printf("EV\t%d\texec\t-\t-\t%s\n", pid, copyinstr(arg0));
}

syscall::posix_spawn:entry
/tree[pid]/
{
	printf("EV\t%d\texec\t-\t-\t%s\n", pid, copyinstr(arg1));
}

syscall::mkdir:entry, syscall::rmdir:entry, syscall::unlink:entry
/tree[pid]/
{
	printf("EV\t%d\t%s\t-\t-\t%s\n", pid, probefunc, copyinstr(arg0));
}

syscall::rename:entry
/tree[pid]/
{
	printf("EV\t%d\trenamefrom\t-\t-\t%s\n", pid, copyinstr(arg0));
	printf("EV\t%d\trenameto\t-\t-\t%s\n", pid, copyinstr(arg1));
}

syscall::chdir:entry
/tree[pid]/
{
	self->cdset = 1;
	self->cd = copyinstr(arg0);
}

syscall::chdir:return
/self->cdset/
{
	printf("EV\t%d\tchdir\t-\t%d\t%s\n", pid, (int)arg1, self->cd);
	self->cdset = 0;
	self->cd = 0;
}

syscall::fchdir:entry
/tree[pid]/
{
	printf("EV\t%d\tfchdir\t%d\t-\t-\n", pid, (int)arg0);
}
"#;

/// What a diagnostic run found.
pub struct Diagnostic {
    pub trace: Trace,
    /// Processes in the traced tree, the command included.
    pub processes: usize,
    /// Path events read from the tracer.
    pub events: usize,
}

enum Event {
    Spawn {
        child: u32,
    },
    Exec,
    Exit,
    Path {
        op: String,
        dirfd: Option<i32>,
        value: Option<i32>,
        path: String,
    },
}

struct Member {
    /// `None` once the working directory is unknown.
    cwd: Option<PathBuf>,
    exited: bool,
}

/// Turns the tracer's lines into a `Trace`, one process at a time.
pub struct Observer {
    root: u32,
    members: HashMap<u32, Member>,
    /// Events from pids that are not in the tree, held until a spawn edge links them.
    pending: HashMap<u32, Vec<Event>>,
    trace: Trace,
    events: usize,
    saw_root_exit: bool,
    saw_stop: bool,
}

impl Observer {
    pub fn new(root: u32, cwd: &Path) -> Self {
        let mut members = HashMap::new();
        members.insert(
            root,
            Member {
                cwd: Some(lexical(Path::new("/"), &cwd.to_string_lossy())),
                exited: false,
            },
        );
        let mut observer = Self {
            root,
            members,
            pending: HashMap::new(),
            trace: Trace::default(),
            events: 0,
            saw_root_exit: false,
            saw_stop: false,
        };
        observer.flag(DIAGNOSTIC_ONLY);
        observer
    }

    fn flag(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if self.trace.unsound.len() < MAX_REASONS && !self.trace.unsound.contains(&reason) {
            self.trace.unsound.push(reason);
        }
    }

    /// One line of tracer output (without its newline). A line that is not a known record
    /// makes the observation unsound.
    pub fn feed(&mut self, line: &str) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line == "READY" {
            return;
        }
        if line == "STOP" {
            self.saw_stop = true;
            return;
        }
        if line.starts_with("dtrace:") {
            if let Some(reason) = tracer_message(line) {
                self.flag(reason);
            }
            return;
        }
        let mut parts = line.splitn(6, '\t');
        let kind = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        let parsed = match (kind, rest.as_slice()) {
            ("SPAWN", [parent, child]) => match (parent.parse(), child.parse()) {
                (Ok(parent), Ok(child)) => Some((parent, Event::Spawn { child })),
                _ => None,
            },
            ("EXEC", [pid, _image]) => pid.parse().ok().map(|pid| (pid, Event::Exec)),
            ("EXIT", [pid]) => pid.parse().ok().map(|pid| (pid, Event::Exit)),
            ("EV", [pid, op, dirfd, value, path]) => {
                let number = |text: &str| {
                    if text == "-" {
                        Some(None)
                    } else {
                        text.parse().ok().map(Some)
                    }
                };
                match (pid.parse(), number(dirfd), number(value)) {
                    (Ok(pid), Some(dirfd), Some(value)) => Some((
                        pid,
                        Event::Path {
                            op: (*op).to_owned(),
                            dirfd,
                            value,
                            path: (*path).to_owned(),
                        },
                    )),
                    _ => None,
                }
            }
            _ => None,
        };
        match parsed {
            Some((pid, event)) => self.dispatch(pid, event),
            None => self.flag("the tracer printed a line that could not be read"),
        }
    }

    fn dispatch(&mut self, pid: u32, event: Event) {
        if matches!(event, Event::Path { .. }) {
            self.events += 1;
        }
        if self.members.get(&pid).is_some_and(|m| !m.exited) {
            self.apply(pid, event);
        } else {
            self.pending.entry(pid).or_default().push(event);
        }
    }

    fn apply(&mut self, pid: u32, event: Event) {
        match event {
            Event::Spawn { child } => {
                let cwd = self.members.get(&pid).and_then(|m| m.cwd.clone());
                if self.members.get(&child).is_some_and(|m| !m.exited) {
                    self.flag("a pid was reused before its exit was seen");
                }
                self.members.insert(child, Member { cwd, exited: false });
                if let Some(held) = self.pending.remove(&child) {
                    for event in held {
                        self.apply(child, event);
                    }
                }
            }
            Event::Exec => {}
            Event::Exit => {
                if let Some(member) = self.members.get_mut(&pid) {
                    member.exited = true;
                }
                if pid == self.root {
                    self.saw_root_exit = true;
                }
            }
            Event::Path {
                op,
                dirfd,
                value,
                path,
            } => self.path_event(pid, &op, dirfd, value, &path),
        }
    }

    fn path_event(
        &mut self,
        pid: u32,
        op: &str,
        dirfd: Option<i32>,
        value: Option<i32>,
        path: &str,
    ) {
        if op == "fchdir" {
            if let Some(member) = self.members.get_mut(&pid) {
                member.cwd = None;
            }
            self.flag("fchdir: the working directory is no longer known");
            return;
        }
        if path.len() >= STRSIZE - 1 {
            self.flag("a path was long enough to be cut off by the tracer");
            return;
        }
        if path.is_empty() {
            return;
        }
        let Some(resolved) = self.resolve(pid, dirfd, path) else {
            return;
        };
        match op {
            "stat" | "lstat" | "access" | "getattrlist" | "readlink" | "exec" => {
                self.read(resolved);
            }
            "open" | "openat" => {
                let flags = value.unwrap_or(0);
                if flags & (O_WRONLY | O_RDWR | O_APPEND | O_CREAT | O_TRUNC) != 0 {
                    self.trace.written.insert(resolved);
                } else {
                    self.read(resolved);
                }
            }
            "chdir" => {
                self.read(resolved.clone());
                if value == Some(0) {
                    if let Some(member) = self.members.get_mut(&pid) {
                        member.cwd = Some(resolved);
                    }
                }
            }
            "mkdir" => self.trace.created_dirs.push(resolved),
            "rmdir" | "unlink" | "renamefrom" | "renameto" => {
                self.trace.written.insert(resolved);
            }
            _ => self.flag("the tracer printed an operation this parser does not know"),
        }
    }

    fn read(&mut self, path: PathBuf) {
        self.trace.touched.entry(path).or_default().read = true;
    }

    fn resolve(&mut self, pid: u32, dirfd: Option<i32>, path: &str) -> Option<PathBuf> {
        if path.starts_with('/') {
            return Some(lexical(Path::new("/"), path));
        }
        if !matches!(dirfd, None | Some(AT_FDCWD)) {
            self.flag("a path relative to a directory descriptor cannot be placed");
            return None;
        }
        match self.members.get(&pid).and_then(|m| m.cwd.clone()) {
            Some(cwd) => Some(lexical(&cwd, path)),
            None => {
                self.flag("a relative path was used where the working directory is unknown");
                None
            }
        }
    }

    /// The observation, once the tracer's output has ended.
    pub fn finish(mut self, status: i32) -> Diagnostic {
        if !self.saw_root_exit {
            self.flag("the command's exit was not seen by the tracer");
        }
        if !self.saw_stop {
            self.flag("the tracer did not report a clean stop");
        }
        let unlinked = self.pending.len();
        if unlinked > 0 {
            self.flag(format!(
                "{unlinked} process(es) touched paths without a spawn edge from the command"
            ));
        }
        if self.members.values().any(|m| !m.exited) {
            self.flag("processes were still running when the tracer stopped");
        }
        self.trace.status = status;
        Diagnostic {
            processes: self.members.len(),
            events: self.events,
            trace: self.trace,
        }
    }
}

/// A line DTrace printed about itself. Returns the reason it makes the observation unsound,
/// or `None` when it is harmless. A NULL pointer on a probe with no path is harmless; this
/// script has no such probe that dereferences one, so only `proc` probes qualify.
fn tracer_message(line: &str) -> Option<String> {
    if line.contains("invalid address (0x0)") && line.contains("proc:") {
        return None;
    }
    let shown: String = line.chars().filter(|c| !c.is_control()).take(160).collect();
    Some(format!("the tracer reported a loss or error: {shown}"))
}

/// `path` joined to `base` with `.` and `..` resolved by name only.
fn lexical(base: &Path, path: &str) -> PathBuf {
    let mut out = PathBuf::new();
    let joined = if path.starts_with('/') {
        PathBuf::from(path)
    } else {
        base.join(path)
    };
    for part in joined.components() {
        match part {
            Component::RootDir => out.push("/"),
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    if out.as_os_str().is_empty() {
        out.push("/");
    }
    out
}

fn make_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    Ok((high_cloexec(read)?, high_cloexec(write)?))
}

/// A duplicate at fd 10 or above that closes on exec, so only the fd the wrapper gets leaks in.
fn high_cloexec(fd: OwnedFd) -> io::Result<OwnedFd> {
    let moved = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if moved < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(moved) })
}

fn sudo_usable() -> bool {
    Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn dtrace_command() -> Command {
    let mut command = Command::new("sudo");
    command.args([
        "-n",
        "/bin/sh",
        "-c",
        "exec /usr/sbin/dtrace -q -s /dev/stdin \"$0\" 2>&1",
    ]);
    command
}

/// Runs `argv` once under DTrace and returns what was observed. `Err` means the command was
/// not run and the caller should run it untraced.
pub fn diagnose(argv: &[OsString], cwd: &Path) -> io::Result<Diagnostic> {
    if !sudo_usable() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "DTrace diagnostics need passwordless sudo",
        ));
    }
    run_with(
        dtrace_command(),
        SCRIPT,
        argv,
        cwd,
        READY_TIMEOUT,
        STOP_TIMEOUT,
    )
}

/// The launcher, with the tracer program and its timeouts supplied.
pub(crate) fn run_with(
    mut tracer: Command,
    script: &str,
    argv: &[OsString],
    cwd: &Path,
    ready_timeout: Duration,
    stop_timeout: Duration,
) -> io::Result<Diagnostic> {
    let (release_read, release_write) = make_pipe()?;
    let mut wrapper = Command::new("/bin/sh");
    wrapper
        .arg("-c")
        .arg("read -r _ <&3; exec 3<&-; exec \"$@\"")
        .arg("stoop")
        .args(argv)
        .current_dir(cwd);
    let read_fd = release_read.as_raw_fd();
    // SAFETY: only dup2, which is async-signal-safe, runs between fork and exec.
    unsafe {
        wrapper.pre_exec(move || {
            if libc::dup2(read_fd, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut command = wrapper.spawn()?;
    drop(release_read);
    let root = command.id();

    tracer
        .arg(root.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    let mut tracing = match tracer.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = command.kill();
            let _ = command.wait();
            return Err(error);
        }
    };
    let tracer_pid = tracing.id();
    let stdout = tracing.stdout.take();
    let stdin = tracing.stdin.take();
    let abort = |command: &mut std::process::Child, reason: &str| -> io::Error {
        unsafe { libc::kill(tracer_pid as i32, libc::SIGINT) };
        let _ = command.kill();
        let _ = command.wait();
        io::Error::other(reason.to_owned())
    };
    let (Some(mut stdin), Some(mut stdout)) = (stdin, stdout) else {
        return Err(abort(&mut command, "the tracer has no pipes"));
    };
    if stdin.write_all(script.as_bytes()).is_err() {
        return Err(abort(
            &mut command,
            "the tracer closed before it read its script",
        ));
    }
    drop(stdin);

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<Observer>();
    let start_cwd = cwd.to_owned();
    std::thread::spawn(move || {
        let mut observer = Observer::new(root, &start_cwd);
        let mut ready = Some(ready_tx);
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 65536];
        loop {
            let read = match stdout.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(read) => read,
            };
            buffer.extend_from_slice(&chunk[..read]);
            while let Some(newline) = buffer.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = buffer.drain(..=newline).collect();
                let line = &line[..line.len() - 1];
                let text = match std::str::from_utf8(line) {
                    Ok(text) => text.to_owned(),
                    Err(_) => {
                        observer.flag("a path was not valid UTF-8");
                        String::from_utf8_lossy(line).into_owned()
                    }
                };
                if text == "READY" {
                    if let Some(tx) = ready.take() {
                        let _ = tx.send(());
                    }
                }
                observer.feed(&text);
            }
        }
        if !buffer.is_empty() {
            observer.flag("the tracer's output ended inside a line");
        }
        drop(ready);
        let _ = done_tx.send(observer);
    });

    if ready_rx.recv_timeout(ready_timeout).is_err() {
        return Err(abort(
            &mut command,
            "the tracer did not report READY, so the command was not run",
        ));
    }
    // Armed: release the command, which now runs exactly once.
    let mut release = std::fs::File::from(release_write);
    let released = release.write_all(b"\n").is_ok();
    drop(release);
    let status = command.wait()?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));

    let mut observer = match done_rx.recv_timeout(stop_timeout) {
        Ok(observer) => observer,
        Err(_) => {
            unsafe { libc::kill(tracer_pid as i32, libc::SIGINT) };
            match done_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(mut observer) => {
                    observer.flag("the tracer had to be interrupted to stop");
                    observer
                }
                Err(_) => {
                    let mut observer = Observer::new(root, cwd);
                    observer.flag("the tracer did not stop and its output was lost");
                    observer
                }
            }
        }
    };
    if !released {
        observer.flag("the command's release could not be confirmed");
    }
    let _ = tracing.wait();
    Ok(observer.finish(code))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observer() -> Observer {
        Observer::new(100, Path::new("/work"))
    }

    fn feed(observer: &mut Observer, lines: &[&str]) {
        for line in lines {
            observer.feed(line);
        }
    }

    fn clean_end(observer: &mut Observer) {
        feed(observer, &["EXIT\t100", "STOP"]);
    }

    fn reasons(diagnostic: &Diagnostic) -> Vec<&str> {
        diagnostic
            .trace
            .unsound
            .iter()
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn a_clean_run_is_unsound_only_because_it_is_diagnostic() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                "READY",
                "EV\t100\tstat\t-\t-\tin.txt",
                "EV\t100\topen\t-\t0\t/work/in.txt",
                "EV\t100\topen\t-\t1537\tout.txt",
                "EV\t100\tmkdir\t-\t-\t../work/build",
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
        assert!(d.trace.touched[Path::new("/work/in.txt")].read);
        assert!(d.trace.written.contains(Path::new("/work/out.txt")));
        assert_eq!(d.trace.created_dirs, [PathBuf::from("/work/build")]);
        assert_eq!(d.events, 4);
    }

    #[test]
    fn open_flags_tell_reads_from_writes() {
        let mut o = observer();
        for (flags, writes) in [
            (0, false),
            (1, true),
            (2, true),
            (8, true),
            (0x200, true),
            (0x400, true),
        ] {
            feed(&mut o, &[&format!("EV\t100\topen\t-\t{flags}\t/f{flags}")]);
            assert_eq!(
                o.trace.written.contains(Path::new(&format!("/f{flags}"))),
                writes,
                "flags {flags}"
            );
        }
    }

    #[test]
    fn children_join_through_spawn_edges_and_inherit_the_directory() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                "EV\t100\tchdir\t-\t0\tsub",
                "SPAWN\t100\t200",
                "EV\t200\tstat\t-\t-\ta.txt",
                "EXIT\t200",
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.contains_key(Path::new("/work/sub/a.txt")));
        assert_eq!(d.processes, 2);
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn a_failed_chdir_leaves_the_directory_alone() {
        let mut o = observer();
        feed(
            &mut o,
            &["EV\t100\tchdir\t-\t-1\tmissing", "EV\t100\tstat\t-\t-\ta"],
        );
        assert!(o.trace.touched.contains_key(Path::new("/work/a")));
        assert!(o.trace.touched.contains_key(Path::new("/work/missing")));
    }

    #[test]
    fn events_that_arrive_before_their_spawn_edge_are_held_then_placed() {
        let mut o = observer();
        feed(
            &mut o,
            &["EV\t300\tstat\t-\t-\tearly", "SPAWN\t100\t300", "EXIT\t300"],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.contains_key(Path::new("/work/early")));
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn a_pid_that_never_links_to_the_tree_is_unsound() {
        let mut o = observer();
        feed(&mut o, &["EV\t999\tstat\t-\t-\tx"]);
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.is_empty());
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("without a spawn edge")));
    }

    #[test]
    fn dtrace_loss_and_error_lines_are_unsound() {
        for line in [
            "dtrace: 81747 dynamic variable drops with non-empty dirty list",
            "dtrace: 12 drops on CPU 0",
            "dtrace: error on enabled probe ID 5 (ID 99: syscall::stat64:entry): invalid address (0x0) in action #2 at DIF offset 28",
            "dtrace: error on enabled probe ID 5 (ID 99: syscall::open:entry): invalid address (0x7ffd1000) in action #2",
        ] {
            let mut o = observer();
            o.feed(line);
            clean_end(&mut o);
            let d = o.finish(0);
            assert!(
                reasons(&d).iter().any(|r| r.contains("loss or error")),
                "{line}: {:?}",
                reasons(&d)
            );
        }
    }

    #[test]
    fn a_null_pointer_on_a_probe_with_no_path_is_harmless() {
        let mut o = observer();
        o.feed("dtrace: error on enabled probe ID 7 (ID 12: proc:::create): invalid address (0x0) in action #1");
        clean_end(&mut o);
        assert_eq!(reasons(&o.finish(0)), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn unreadable_lines_and_unknown_operations_are_unsound() {
        for line in [
            "garbage",
            "EV\tnotapid\tstat\t-\t-\tx",
            "EV\t100\tstat\t-\t-",
            "SPAWN\t100",
            "EV\t100\tfrobnicate\t-\t-\tx",
        ] {
            let mut o = observer();
            o.feed(line);
            clean_end(&mut o);
            let d = o.finish(0);
            assert_eq!(reasons(&d).len(), 2, "{line}: {:?}", reasons(&d));
        }
    }

    #[test]
    fn markers_and_running_processes_are_checked_at_the_end() {
        let d = observer().finish(0);
        assert!(reasons(&d).iter().any(|r| r.contains("exit was not seen")));
        assert!(reasons(&d).iter().any(|r| r.contains("clean stop")));
        let mut o = observer();
        feed(&mut o, &["SPAWN\t100\t200", "EXIT\t100", "STOP"]);
        let d = o.finish(0);
        assert!(reasons(&d).iter().any(|r| r.contains("still running")));
    }

    #[test]
    fn paths_that_cannot_be_placed_are_unsound() {
        let mut o = observer();
        feed(&mut o, &["EV\t100\topenat\t7\t0\trel.txt"]);
        assert!(o.trace.unsound.iter().any(|r| r.contains("descriptor")));
        let mut o = observer();
        feed(
            &mut o,
            &["EV\t100\tfchdir\t7\t-\t-", "EV\t100\tstat\t-\t-\trel"],
        );
        assert!(o.trace.unsound.iter().any(|r| r.contains("fchdir")));
        assert!(o.trace.unsound.iter().any(|r| r.contains("unknown")));
        let mut o = observer();
        o.feed(&format!("EV\t100\tstat\t-\t-\t/{}", "a".repeat(STRSIZE)));
        assert!(o.trace.unsound.iter().any(|r| r.contains("cut off")));
    }

    #[test]
    fn at_fdcwd_paths_resolve_against_the_directory() {
        let mut o = observer();
        feed(&mut o, &["EV\t100\topenat\t-2\t0\trel.txt"]);
        assert!(o.trace.touched.contains_key(Path::new("/work/rel.txt")));
    }

    #[test]
    fn paths_resolve_lexically() {
        assert_eq!(
            lexical(Path::new("/a/b"), "../c/./d"),
            PathBuf::from("/a/c/d")
        );
        assert_eq!(lexical(Path::new("/a"), "/x//y/.."), PathBuf::from("/x"));
        assert_eq!(lexical(Path::new("/a"), "../.."), PathBuf::from("/"));
    }

    fn fake(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    fn marker(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("stoop-macos-{name}-{}", std::process::id()))
    }

    #[test]
    fn a_tracer_that_never_arms_stops_the_command_from_running() {
        let file = marker("never");
        let _ = std::fs::remove_file(&file);
        let argv = [
            OsString::from("/usr/bin/touch"),
            file.clone().into_os_string(),
        ];
        let started = run_with(
            fake("cat >/dev/null; sleep 30"),
            "",
            &argv,
            Path::new("/"),
            Duration::from_millis(400),
            Duration::from_secs(1),
        );
        assert!(started.is_err());
        assert!(
            !file.exists(),
            "the command ran although the tracer never armed"
        );
    }

    #[test]
    fn a_tracer_that_exits_at_once_never_runs_the_command() {
        let file = marker("exits");
        let _ = std::fs::remove_file(&file);
        let argv = [
            OsString::from("/usr/bin/touch"),
            file.clone().into_os_string(),
        ];
        let started = run_with(
            fake("exit 1"),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(1),
        );
        assert!(started.is_err());
        assert!(!file.exists());
    }

    #[test]
    fn a_tracer_that_dies_after_arming_returns_the_status_unsound() {
        let file = marker("dies");
        let _ = std::fs::remove_file(&file);
        let argv = [
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from(format!("echo x >> '{}'; exit 7", file.display())),
        ];
        let d = run_with(
            fake("echo READY"),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(d.trace.status, 7);
        assert!(reasons(&d).iter().any(|r| r.contains("exit was not seen")));
        assert!(reasons(&d).iter().any(|r| r.contains("clean stop")));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "x\n");
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn a_tracer_that_reports_a_loss_marks_the_run_unsound() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake(
                "echo READY; echo 'dtrace: 3 drops on CPU 1'; printf 'EXIT\\t%s\\nSTOP\\n' \"$0\"",
            ),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(d.trace.status, 0);
        assert!(reasons(&d).iter().any(|r| r.contains("drops on CPU")));
        assert!(!reasons(&d).iter().any(|r| r.contains("clean stop")));
    }

    #[test]
    fn a_complete_fake_run_sees_the_commands_paths() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake(
                "echo READY; printf 'EV\\t%s\\tstat\\t-\\t-\\t/etc/hosts\\nEXIT\\t%s\\nSTOP\\n' \"$0\" \"$0\"",
            ),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
        assert!(d.trace.touched.contains_key(Path::new("/etc/hosts")));
        assert_eq!(d.trace.status, 0);
    }
}
