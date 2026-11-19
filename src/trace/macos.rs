//! A diagnostic macOS tracer: DTrace under passwordless `sudo`.
//!
//! Diagnostic only. Every observation carries a standing `unsound` reason, so no caller can
//! record a proof from it. The privileged spike found DTrace the only tool that saw every
//! category it can observe on hosted runners, and it still lacks symlink targets, errno and
//! exact directory listings. It also cannot yet place a path relative to a directory
//! descriptor, and the system loader makes such lookups in every process, so a run that starts
//! a process is unsound on the hosted runners for that reason alone.
//!
//! How a run goes:
//! 1. The command is started inside a wrapper that blocks on a pipe, so its pid is known
//!    before it can do anything.
//! 2. DTrace is armed for that pid's process tree. The command is released only after the
//!    script prints `READY`, so a tracer that never arms never lets the command run.
//! 3. DTrace stops itself shortly after the root process exits. Its records carry a timestamp,
//!    and they are applied in timestamp order. Anything DTrace writes to its error stream, every
//!    loss or error line, every line this parser cannot read, every path whose length does not
//!    match its record and every missing marker makes the observation unsound.
//!
//! A failure before the command starts is an `Err`, and the caller runs the command untraced
//! with an UNKNOWN verdict. A failure after it starts is never an `Err`: the command's status
//! comes back with `unsound` set, because an `Err` would make the caller run the command a
//! second time.

use super::Trace;
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The reason every macOS observation carries.
pub const DIAGNOSTIC_ONLY: &str =
    "diagnostic backend: macOS observations are not recorded as proofs";

/// The reason every descriptor-relative lookup that cannot be placed shares. The tracer does not
/// follow descriptors yet, so such a lookup makes the run unsound (the spike's gap two).
const DESCRIPTOR_GAP: &str =
    "a path relative to a directory descriptor cannot be placed: descriptors are not followed yet";
const UNKNOWN_CWD: &str = "a relative path was used where the working directory is unknown";
const LENGTH_MISMATCH: &str =
    "a path did not match the length the tracer gave it: its record was split or altered";
const FCHDIR_LOST: &str = "fchdir: the working directory is no longer known";
const PTHREAD_CHDIR_LOST: &str =
    "pthread chdir: the working directory of the process is no longer known";
const AFTER_EXIT: &str = "the tracer reported an event after its process had exited";
const PID_REUSED: &str = "a pid was reused before its exit was seen";
const ROOT_EXIT_UNSEEN: &str = "the command's exit was not seen by the tracer";
const NO_CLEAN_STOP: &str = "the tracer did not report a clean stop";
const STILL_RUNNING: &str = "processes were still running when the tracer stopped";
const INTERRUPTED: &str = "the tracer had to be interrupted to stop";
const DID_NOT_STOP: &str = "the tracer did not stop and its output was lost";
const STDERR_STALLED: &str = "the tracer's error stream did not close";
const LEFT_RUNNING: &str = "the tracer was left running after the command finished";
const STATUS_UNKNOWN: &str = "the command's exit status could not be read";
const NOT_UTF8: &str = "a traced path was not valid UTF-8";
const ENDED_IN_LINE: &str = "the tracer's output ended inside a line";
const EMPTY_LINE: &str = "the tracer printed an empty line";
const CUT_OFF: &str = "a path was long enough to be cut off by the tracer";
const OUTPUT_LOST: &str = "the tracer's output could not be read, so the rest of it is unknown";

/// `AT_FDCWD` on macOS.
const AT_FDCWD: i32 = -2;
const O_WRONLY: i32 = 0x1;
const O_RDWR: i32 = 0x2;
const O_APPEND: i32 = 0x8;
const O_CREAT: i32 = 0x200;
const O_TRUNC: i32 = 0x400;
/// The script's strings are cut at this many bytes, so a path this long may be truncated.
const STRSIZE: usize = 1024;
/// Distinct reasons from the records, before the end-of-run reasons, which are never capped.
const MAX_REASONS: usize = 16;
const READY_TIMEOUT: Duration = Duration::from_secs(60);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

/// Tree membership starts at the command's pid (`$1`) and grows through `proc:::create`, and a
/// pid leaves it at `proc:::exit`, so a reused pid is not counted. A path-taking probe reports
/// only for members. A NULL path pointer is never copied: the kernel fails such a call with
/// EFAULT before any lookup, so there is nothing to report. Every record starts with its kind
/// and a timestamp `seconds.nanoseconds`. A path record ends with the path's length in bytes
/// and then the path, which is the last field, so a path that holds a newline cannot pass as
/// two records. A call that returns -1 also prints `FAIL`. The tracer stops itself half a
/// second after the root exits, which flushes every buffer first.
const SCRIPT: &str = r#"#pragma D option quiet
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
/tree[pid] && arg0 != 0 && self->spawning/
{
	tree[args[0]->pr_pid] = 1;
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("SPAWNX\t%u.%u\t%d\t%d\n", (unsigned int)this->s, (unsigned int)this->n, pid, args[0]->pr_pid);
}

proc:::create
/tree[pid] && arg0 != 0 && !self->spawning/
{
	tree[args[0]->pr_pid] = 1;
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("SPAWN\t%u.%u\t%d\t%d\n", (unsigned int)this->s, (unsigned int)this->n, pid, args[0]->pr_pid);
}

proc:::exec
/tree[pid] && arg0 != 0/
{
	this->p = stringof(args[0]);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\texec\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(this->p), this->p);
}

proc:::exit
/tree[pid]/
{
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EXIT\t%u.%u\t%d\n", (unsigned int)this->s, (unsigned int)this->n, pid);
	tree[pid] = 0;
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

syscall::posix_spawn:entry
/tree[pid]/
{
	self->spawning = 1;
}

syscall::posix_spawn:return
/self->spawning/
{
	self->spawning = 0;
}

syscall::open:entry, syscall::open_nocancel:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\topen\t-\t%d\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, (int)arg1, strlen(self->path), self->path);
}

syscall::openat:entry, syscall::openat_nocancel:entry
/tree[pid] && arg1 != 0/
{
	self->lookup = 1;
	self->fd = (int)arg0;
	self->path = copyinstr(arg1);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\topenat\t%d\t%d\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, (int)arg0, (int)arg2, strlen(self->path), self->path);
}

syscall::stat:entry, syscall::stat64:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tstat\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::lstat:entry, syscall::lstat64:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tlstat\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::fstatat:entry, syscall::fstatat64:entry
/tree[pid] && arg1 != 0/
{
	self->lookup = 1;
	self->fd = (int)arg0;
	self->path = copyinstr(arg1);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tstat\t%d\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, (int)arg0, strlen(self->path), self->path);
}

syscall::access:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\taccess\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::faccessat:entry
/tree[pid] && arg1 != 0/
{
	self->lookup = 1;
	self->fd = (int)arg0;
	self->path = copyinstr(arg1);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\taccess\t%d\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, (int)arg0, strlen(self->path), self->path);
}

syscall::getattrlist:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tgetattrlist\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::readlink:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\treadlink\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::mkdir:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tmkdir\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::rmdir:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\trmdir\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::unlink:entry
/tree[pid] && arg0 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tunlink\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
}

syscall::rename:entry
/tree[pid] && arg0 != 0 && arg1 != 0/
{
	self->lookup = 1;
	self->fd = -2;
	self->path = copyinstr(arg0);
	self->path2 = copyinstr(arg1);
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\trenamefrom\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
	printf("EV\t%u.%u\t%d\trenameto\t-\t-\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path2), self->path2);
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return,
syscall::stat:return, syscall::stat64:return,
syscall::lstat:return, syscall::lstat64:return,
syscall::fstatat:return, syscall::fstatat64:return,
syscall::access:return, syscall::faccessat:return,
syscall::getattrlist:return, syscall::readlink:return,
syscall::mkdir:return, syscall::rmdir:return, syscall::unlink:return
/self->lookup/
{
	if ((int)arg0 == -1) {
		this->s = timestamp / 1000000000;
		this->n = timestamp % 1000000000;
		printf("FAIL\t%u.%u\t%d\t%d\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, self->fd, strlen(self->path), self->path);
	}
	self->lookup = 0;
}

syscall::rename:return
/self->lookup/
{
	if ((int)arg0 == -1) {
		this->s = timestamp / 1000000000;
		this->n = timestamp % 1000000000;
		printf("FAIL\t%u.%u\t%d\t-2\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path), self->path);
		printf("FAIL\t%u.%u\t%d\t-2\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, strlen(self->path2), self->path2);
	}
	self->lookup = 0;
}

syscall::chdir:entry
/tree[pid] && arg0 != 0/
{
	self->cdset = 1;
	self->cd = copyinstr(arg0);
}

syscall::chdir:return
/self->cdset/
{
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("EV\t%u.%u\t%d\tchdir\t-\t%d\t%d\t%s\n", (unsigned int)this->s, (unsigned int)this->n, pid, (int)arg0, strlen(self->cd), self->cd);
	self->cdset = 0;
}

syscall::fchdir:entry
/tree[pid]/
{
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("FCHDIR\t%u.%u\t%d\n", (unsigned int)this->s, (unsigned int)this->n, pid);
}

syscall::__pthread_chdir:entry, syscall::__pthread_fchdir:entry
/tree[pid]/
{
	this->s = timestamp / 1000000000;
	this->n = timestamp % 1000000000;
	printf("PTHCHDIR\t%u.%u\t%d\n", (unsigned int)this->s, (unsigned int)this->n, pid);
}
"#;

/// What a diagnostic run found.
pub struct Diagnostic {
    pub trace: Trace,
    /// Processes in the traced tree, the command included.
    pub processes: usize,
    /// Path events read from the tracer.
    pub events: usize,
    /// Lookups that returned an error (`-1`). DTrace gives no errno, so a missing file and any
    /// other failure look the same here.
    pub failed: BTreeSet<PathBuf>,
    /// Lines DTrace printed about its own losses or errors, on either stream.
    pub losses: usize,
    /// Every line the tracer printed, kept only when asked (`STOOP_DTRACE_DIAGNOSTIC=raw`).
    pub raw: Vec<String>,
    /// Parent and child pid of each process the tree started.
    pub spawns: Vec<(u32, u32)>,
    /// Pid and path of each exec attempt made inside the tree.
    pub execs: Vec<(u32, PathBuf)>,
    /// Descriptor-relative lookups that could not be placed: the descriptor and the path as passed.
    pub unplaced: BTreeSet<(i32, String)>,
}

/// One record the tracer printed, checked and decoded.
enum Record {
    /// A process the tree started; `posix` when a posix_spawn call made it, so its working
    /// directory may have been changed by a file action this tracer cannot see.
    Spawn {
        child: u32,
        posix: bool,
    },
    Exit,
    FchdirLost,
    PthreadChdirLost,
    /// A path the process named, and the flags or return value that came with it.
    Path {
        op: String,
        dirfd: Option<i32>,
        value: Option<i32>,
        path: String,
    },
    /// A lookup that returned -1: the path as passed, relative to `dirfd` when given.
    Fail {
        dirfd: Option<i32>,
        path: String,
    },
}

/// A record, ordered by its timestamp and then by the order it was read.
struct Queued {
    ts: u64,
    seq: u64,
    pid: u32,
    record: Record,
}

struct Member {
    /// `None` once the working directory is unknown.
    cwd: Option<PathBuf>,
    exited: bool,
}

/// Turns the tracer's lines into a `Trace`. Records are held until `settle`, then applied in
/// timestamp order, so a chdir printed late by one CPU is still applied before a lookup that
/// happened after it.
pub struct Observer {
    root: u32,
    members: HashMap<u32, Member>,
    /// Records for pids not in the tree yet, held until a spawn edge links them.
    pending: HashMap<u32, Vec<Record>>,
    queued: Vec<Queued>,
    seq: u64,
    trace: Trace,
    events: usize,
    failed: BTreeSet<PathBuf>,
    losses: usize,
    loss_reported: bool,
    raw: Vec<String>,
    spawns: Vec<(u32, u32)>,
    execs: Vec<(u32, PathBuf)>,
    unplaced: BTreeSet<(i32, String)>,
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
            queued: Vec::new(),
            seq: 0,
            trace: Trace::default(),
            events: 0,
            failed: BTreeSet::new(),
            losses: 0,
            loss_reported: false,
            raw: Vec::new(),
            spawns: Vec::new(),
            execs: Vec::new(),
            unplaced: BTreeSet::new(),
            saw_root_exit: false,
            saw_stop: false,
        };
        observer.flag(DIAGNOSTIC_ONLY);
        observer
    }

    /// A reason from a record, capped so that many distinct lines cannot grow it without bound.
    fn flag(&mut self, reason: impl Into<String>) {
        if self.trace.unsound.len() < MAX_REASONS {
            self.push_reason(reason);
        }
    }

    /// A reason that is always kept: the end-of-run reasons must not be dropped by the cap.
    fn push_reason(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.trace.unsound.contains(&reason) {
            self.trace.unsound.push(reason);
        }
    }

    /// One line of tracer output (without its newline). Records are queued; a line that is not
    /// a known record makes the observation unsound.
    pub fn feed(&mut self, line: &str) {
        if line == "READY" {
            return;
        }
        if line == "STOP" {
            self.saw_stop = true;
            return;
        }
        if line.is_empty() {
            self.flag(EMPTY_LINE);
            return;
        }
        if line.starts_with("dtrace:") {
            self.loss(line);
            return;
        }
        let mut parts = line.splitn(8, '\t');
        let kind = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();
        let number = |text: &str| -> Option<Option<i32>> {
            if text == "-" {
                Some(None)
            } else {
                text.parse::<i32>().ok().map(Some)
            }
        };
        let parsed = match (kind, rest.as_slice()) {
            ("SPAWN" | "SPAWNX", [ts, pid, child]) => {
                match (stamp(ts), pid.parse::<u32>(), child.parse::<u32>()) {
                    (Some(ts), Ok(pid), Ok(child)) => Some((
                        ts,
                        pid,
                        Record::Spawn {
                            child,
                            posix: kind == "SPAWNX",
                        },
                    )),
                    _ => None,
                }
            }
            ("EXIT", [ts, pid]) => match (stamp(ts), pid.parse::<u32>()) {
                (Some(ts), Ok(pid)) => Some((ts, pid, Record::Exit)),
                _ => None,
            },
            ("FCHDIR", [ts, pid]) => match (stamp(ts), pid.parse::<u32>()) {
                (Some(ts), Ok(pid)) => Some((ts, pid, Record::FchdirLost)),
                _ => None,
            },
            ("PTHCHDIR", [ts, pid]) => match (stamp(ts), pid.parse::<u32>()) {
                (Some(ts), Ok(pid)) => Some((ts, pid, Record::PthreadChdirLost)),
                _ => None,
            },
            ("EV", [ts, pid, op, dirfd, value, len, path]) => {
                match (
                    stamp(ts),
                    pid.parse::<u32>(),
                    number(dirfd),
                    number(value),
                    len.parse::<usize>(),
                ) {
                    (Some(ts), Ok(pid), Some(dirfd), Some(value), Ok(len)) => {
                        if path.len() != len {
                            self.flag(LENGTH_MISMATCH);
                            return;
                        }
                        Some((
                            ts,
                            pid,
                            Record::Path {
                                op: (*op).to_owned(),
                                dirfd,
                                value,
                                path: (*path).to_owned(),
                            },
                        ))
                    }
                    _ => None,
                }
            }
            ("FAIL", [ts, pid, dirfd, len, path]) => {
                match (
                    stamp(ts),
                    pid.parse::<u32>(),
                    dirfd.parse::<i32>(),
                    len.parse::<usize>(),
                ) {
                    (Some(ts), Ok(pid), Ok(dirfd), Ok(len)) => {
                        if path.len() != len {
                            self.flag(LENGTH_MISMATCH);
                            return;
                        }
                        Some((
                            ts,
                            pid,
                            Record::Fail {
                                dirfd: Some(dirfd),
                                path: (*path).to_owned(),
                            },
                        ))
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        match parsed {
            Some((ts, pid, record)) => self.queue(ts, pid, record),
            None => {
                let shown = shown_text(line);
                self.flag(format!(
                    "the tracer printed a line that could not be read: {shown}"
                ));
            }
        }
    }

    /// A line DTrace printed about itself on stdout: a loss or an error. Only the first is named;
    /// the rest are counted.
    fn loss(&mut self, line: &str) {
        self.losses += 1;
        if !self.loss_reported {
            self.loss_reported = true;
            self.flag(format!(
                "the tracer reported a loss or error: {}",
                shown_text(line)
            ));
        }
    }

    /// The tracer wrote `lines` lines to its error stream, starting with `first`. Anything there
    /// is a message from DTrace or sudo about a loss or an error, so it is never a clean run.
    pub fn tracer_stderr(&mut self, lines: usize, first: &str) {
        self.losses += lines.max(1);
        self.flag(format!(
            "the tracer wrote to its error stream: {}",
            shown_text(first)
        ));
    }

    fn queue(&mut self, ts: u64, pid: u32, record: Record) {
        if matches!(record, Record::Path { .. }) {
            self.events += 1;
        }
        self.seq += 1;
        self.queued.push(Queued {
            ts,
            seq: self.seq,
            pid,
            record,
        });
    }

    /// Applies every queued record in timestamp order (ties keep the order they were read).
    pub fn settle(&mut self) {
        let mut queued = std::mem::take(&mut self.queued);
        queued.sort_by_key(|q| (q.ts, q.seq));
        for q in queued {
            self.dispatch(q.pid, q.record);
        }
    }

    fn dispatch(&mut self, pid: u32, record: Record) {
        match self.members.get(&pid) {
            Some(member) if !member.exited => self.apply(pid, record),
            Some(_) => self.flag(AFTER_EXIT),
            None => self.pending.entry(pid).or_default().push(record),
        }
    }

    fn apply(&mut self, pid: u32, record: Record) {
        match record {
            Record::Spawn { child, posix } => self.spawn(pid, child, posix),
            Record::Exit => {
                if let Some(member) = self.members.get_mut(&pid) {
                    member.exited = true;
                }
                if pid == self.root {
                    self.saw_root_exit = true;
                }
            }
            Record::FchdirLost => {
                if let Some(member) = self.members.get_mut(&pid) {
                    member.cwd = None;
                }
                self.flag(FCHDIR_LOST);
            }
            Record::PthreadChdirLost => {
                if let Some(member) = self.members.get_mut(&pid) {
                    member.cwd = None;
                }
                self.flag(PTHREAD_CHDIR_LOST);
            }
            Record::Path {
                op,
                dirfd,
                value,
                path,
            } => self.path_event(pid, &op, dirfd, value, &path),
            Record::Fail { dirfd, path } => self.failed_lookup(pid, dirfd, &path),
        }
    }

    /// A new process. A child of a posix_spawn call has no known working directory: a file
    /// action may have changed it, and no syscall shows that.
    fn spawn(&mut self, parent: u32, child: u32, posix: bool) {
        let cwd = if posix {
            None
        } else {
            self.members.get(&parent).and_then(|m| m.cwd.clone())
        };
        if self.members.get(&child).is_some_and(|m| !m.exited) {
            self.flag(PID_REUSED);
        }
        self.members.insert(child, Member { cwd, exited: false });
        self.spawns.push((parent, child));
        if let Some(held) = self.pending.remove(&child) {
            for record in held {
                self.apply(child, record);
            }
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
        if path.len() >= STRSIZE - 1 {
            self.flag(CUT_OFF);
            return;
        }
        if path.is_empty() {
            return;
        }
        let Some(resolved) = self.resolve(pid, dirfd, path) else {
            return;
        };
        match op {
            "stat" | "lstat" | "access" | "getattrlist" | "readlink" => {
                self.read(resolved);
            }
            "exec" => {
                self.execs.push((pid, resolved.clone()));
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
                if value == Some(-1) {
                    self.failed.insert(resolved);
                } else if value == Some(0) {
                    if let Some(member) = self.members.get_mut(&pid) {
                        member.cwd = Some(resolved);
                    }
                }
            }
            "mkdir" => self.trace.created_dirs.push(resolved),
            "rmdir" | "unlink" | "renamefrom" | "renameto" => {
                self.trace.written.insert(resolved);
            }
            _ => self.flag(format!(
                "the tracer printed an operation this parser does not know: {}",
                shown_text(op)
            )),
        }
    }

    /// A lookup that returned -1, placed the way its lookup was placed.
    fn failed_lookup(&mut self, pid: u32, dirfd: Option<i32>, path: &str) {
        if path.is_empty() || path.len() >= STRSIZE - 1 {
            return;
        }
        if let Some(resolved) = self.resolve(pid, dirfd, path) {
            self.failed.insert(resolved);
        }
    }

    fn read(&mut self, path: PathBuf) {
        self.trace.touched.entry(path).or_default().read = true;
    }

    fn resolve(&mut self, pid: u32, dirfd: Option<i32>, path: &str) -> Option<PathBuf> {
        if path.starts_with('/') {
            return Some(lexical(Path::new("/"), path));
        }
        if let Some(fd) = dirfd.filter(|fd| *fd != AT_FDCWD) {
            self.unplaced.insert((fd, path.to_owned()));
            self.flag(DESCRIPTOR_GAP);
            return None;
        }
        match self.members.get(&pid).and_then(|m| m.cwd.clone()) {
            Some(cwd) => Some(lexical(&cwd, path)),
            None => {
                self.flag(UNKNOWN_CWD);
                None
            }
        }
    }

    /// The observation, once the tracer's output has ended.
    pub fn finish(mut self, status: i32) -> Diagnostic {
        self.settle();
        if !self.saw_root_exit {
            self.push_reason(ROOT_EXIT_UNSEEN);
        }
        if !self.saw_stop {
            self.push_reason(NO_CLEAN_STOP);
        }
        let unlinked = self.pending.len();
        if unlinked > 0 {
            self.push_reason(format!(
                "{unlinked} process(es) touched paths without a spawn edge from the command"
            ));
        }
        if self.members.values().any(|m| !m.exited) {
            self.push_reason(STILL_RUNNING);
        }
        self.trace.status = status;
        Diagnostic {
            processes: self.members.len(),
            events: self.events,
            failed: self.failed,
            losses: self.losses,
            raw: self.raw,
            spawns: self.spawns,
            execs: self.execs,
            unplaced: self.unplaced,
            trace: self.trace,
        }
    }
}

/// A timestamp `seconds.nanoseconds` as nanoseconds, or `None` when it is not one.
fn stamp(text: &str) -> Option<u64> {
    let (seconds, nanos) = text.split_once('.')?;
    let seconds: u64 = seconds.parse().ok()?;
    let nanos: u64 = nanos.parse().ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

/// Text for a reason: control characters removed and the length capped.
fn shown_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(120).collect()
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
        "exec /usr/sbin/dtrace -q -s /dev/stdin \"$0\"",
    ]);
    command
}

/// Runs `argv` once under DTrace and returns what was observed. `Err` means the command was
/// not run and the caller should run it untraced.
pub fn diagnose(argv: &[OsString], cwd: &Path, raw: bool) -> io::Result<Diagnostic> {
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
        raw,
    )
}

/// Whether the child has exited within `timeout`.
fn wait_up_to(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => return false,
        }
    }
}

/// Waits up to `timeout` for the tracer to exit. If it has not, it is killed (sudo runs as this
/// user's real id, so the signal is allowed) and the wait is bounded again. Returns whether the
/// tracer exited.
fn reap(tracing: &mut Child, pid: u32, timeout: Duration) -> bool {
    if wait_up_to(tracing, timeout) {
        return true;
    }
    unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    wait_up_to(tracing, timeout)
}

/// Stops a run that cannot continue: the command is killed if it has not run, and the tracer is
/// interrupted and reaped within the stop timeout.
fn abort_run(
    command: &mut Child,
    tracing: &mut Child,
    tracer_pid: u32,
    timeout: Duration,
    reason: &str,
) -> io::Error {
    let _ = command.kill();
    let _ = command.wait();
    unsafe { libc::kill(tracer_pid as i32, libc::SIGINT) };
    reap(tracing, tracer_pid, timeout);
    io::Error::other(reason.to_owned())
}

/// Starts `argv` as a wrapper that does not run it until one byte arrives on fd 3, and returns
/// the command with that release. Dropping the release without writing makes the wrapper exit
/// 125 without running the command. The wrapper closes fd 3 before `exec -- "$@"`, so the
/// command never inherits the pipe, and `--` starts the command by its exact name even when that
/// name begins with `-`.
fn start_held(argv: &[OsString], cwd: &Path) -> io::Result<(Child, std::fs::File)> {
    let (release_read, release_write) = make_pipe()?;
    let mut wrapper = Command::new("/bin/sh");
    wrapper
        .arg("-c")
        .arg("read -r _ <&3 || exit 125; exec 3<&-; exec -- \"$@\"")
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
    let child = wrapper.spawn()?;
    drop(release_read);
    Ok((child, std::fs::File::from(release_write)))
}

/// Reads the tracer's output to its end. Each complete line goes to the observer, and the first
/// line that reads `READY` releases `ready`. Bytes after the last newline are a line that never
/// ended, and a read error leaves the rest of the output unknown: both are unsound. Lines are
/// split in one pass per chunk, so a long run costs time in proportion to its output.
fn read_lines(
    mut reader: impl Read,
    observer: &mut Observer,
    ready: &mut Option<mpsc::Sender<()>>,
    keep_raw: bool,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let read = match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                observer.push_reason(OUTPUT_LOST);
                break;
            }
        };
        pending.extend_from_slice(&chunk[..read]);
        let mut start = 0;
        while let Some(offset) = pending[start..].iter().position(|byte| *byte == b'\n') {
            let end = start + offset;
            let line = &pending[start..end];
            start = end + 1;
            let text = match std::str::from_utf8(line) {
                Ok(text) => text.to_owned(),
                Err(_) => {
                    observer.flag(NOT_UTF8);
                    String::from_utf8_lossy(line).into_owned()
                }
            };
            if text == "READY" {
                if let Some(tx) = ready.take() {
                    let _ = tx.send(());
                }
            }
            if keep_raw {
                observer.raw.push(text.clone());
            }
            observer.feed(&text);
        }
        pending.drain(..start);
    }
    if !pending.is_empty() {
        observer.push_reason(ENDED_IN_LINE);
    }
}

/// What the tracer wrote to its error stream.
#[derive(Default)]
struct StderrSeen {
    bytes: usize,
    lines: usize,
    /// The start of the output, for the reason text.
    first: String,
    /// A read failed, so the rest of the stream is unknown.
    failed: bool,
}

/// Reads the error stream to its end. Anything in it is DTrace or sudo reporting a loss or an
/// error, so every byte counts.
fn read_stderr(mut reader: impl Read) -> StderrSeen {
    let mut seen = StderrSeen::default();
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                seen.bytes += read;
                seen.lines += chunk[..read].iter().filter(|byte| **byte == b'\n').count();
                if seen.first.len() < 256 {
                    seen.first
                        .push_str(&String::from_utf8_lossy(&chunk[..read]));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                seen.failed = true;
                break;
            }
        }
    }
    seen
}

/// Records what the error stream held: any byte there is a loss, and a failed read leaves the
/// rest of the stream unknown.
fn note_stderr(observer: &mut Observer, seen: &StderrSeen) {
    if seen.bytes > 0 {
        observer.tracer_stderr(seen.lines, &seen.first);
    }
    if seen.failed {
        observer.push_reason(OUTPUT_LOST);
    }
}

/// The launcher, with the tracer program and its timeouts supplied.
pub(crate) fn run_with(
    mut tracer: Command,
    script: &str,
    argv: &[OsString],
    cwd: &Path,
    ready_timeout: Duration,
    stop_timeout: Duration,
    keep_raw: bool,
) -> io::Result<Diagnostic> {
    let (mut command, mut release) = start_held(argv, cwd)?;
    let root = command.id();

    tracer
        .arg(root.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut tracing = match tracer.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = command.kill();
            let _ = command.wait();
            return Err(error);
        }
    };
    let tracer_pid = tracing.id();
    let (stdin, stdout, stderr) = (
        tracing.stdin.take(),
        tracing.stdout.take(),
        tracing.stderr.take(),
    );
    let (Some(mut stdin), Some(stdout), Some(stderr)) = (stdin, stdout, stderr) else {
        return Err(abort_run(
            &mut command,
            &mut tracing,
            tracer_pid,
            stop_timeout,
            "the tracer has no pipes",
        ));
    };
    if stdin.write_all(script.as_bytes()).is_err() {
        return Err(abort_run(
            &mut command,
            &mut tracing,
            tracer_pid,
            stop_timeout,
            "the tracer closed before it read its script",
        ));
    }
    drop(stdin);

    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<Observer>();
    let (err_tx, err_rx) = mpsc::channel::<StderrSeen>();
    let start_cwd = cwd.to_owned();
    std::thread::spawn(move || {
        let mut observer = Observer::new(root, &start_cwd);
        let mut ready = Some(ready_tx);
        read_lines(stdout, &mut observer, &mut ready, keep_raw);
        drop(ready);
        let _ = done_tx.send(observer);
    });
    // The error stream is read on its own, so a message from DTrace cannot join a record.
    std::thread::spawn(move || {
        let _ = err_tx.send(read_stderr(stderr));
    });

    if ready_rx.recv_timeout(ready_timeout).is_err() {
        return Err(abort_run(
            &mut command,
            &mut tracing,
            tracer_pid,
            stop_timeout,
            "the tracer did not report READY, so the command was not run",
        ));
    }
    // Armed: release the command, which now runs exactly once.
    let released = release.write_all(b"\n").is_ok();
    drop(release);
    if !released {
        let _ = command.wait();
        unsafe { libc::kill(tracer_pid as i32, libc::SIGINT) };
        reap(&mut tracing, tracer_pid, stop_timeout);
        return Err(io::Error::other(
            "the command could not be released, so it was not run",
        ));
    }
    // The command has started from here on. A failure is reported as unsound, never as `Err`:
    // the caller would run the command a second time.
    let code = match command.wait() {
        Ok(status) => Some(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        ),
        Err(_) => None,
    };

    let mut observer = match done_rx.recv_timeout(stop_timeout) {
        Ok(observer) => observer,
        Err(_) => {
            unsafe { libc::kill(tracer_pid as i32, libc::SIGINT) };
            match done_rx.recv_timeout(stop_timeout) {
                Ok(mut observer) => {
                    observer.push_reason(INTERRUPTED);
                    observer
                }
                Err(_) => {
                    let mut observer = Observer::new(root, cwd);
                    observer.push_reason(DID_NOT_STOP);
                    observer
                }
            }
        }
    };
    match err_rx.recv_timeout(stop_timeout) {
        Ok(seen) => note_stderr(&mut observer, &seen),
        Err(_) => observer.push_reason(STDERR_STALLED),
    }
    if !reap(&mut tracing, tracer_pid, stop_timeout) {
        observer.push_reason(LEFT_RUNNING);
    }
    if code.is_none() {
        observer.push_reason(STATUS_UNKNOWN);
    }
    Ok(observer.finish(code.unwrap_or(1)))
}

/// The lines `stoop run` prints for a diagnostic run, without the `stoop: ` prefix. `paths`
/// adds what each path was (read, failed, written, unplaced) and the tree; `raw` adds every
/// tracer line. The verdict is UNSOUND for any reason. Otherwise it says that no loss was
/// announced, and that calls the script does not trace are not seen: that is not a claim that
/// the observation is complete.
pub(crate) fn report(d: &Diagnostic, paths: bool, raw: bool) -> Vec<String> {
    let t = &d.trace;
    let read: BTreeSet<&PathBuf> = t
        .touched
        .keys()
        .filter(|p| !d.failed.contains(*p))
        .collect();
    let written: BTreeSet<PathBuf> = t.written.iter().chain(&t.created_dirs).cloned().collect();
    let mut out = vec![format!(
        "DTrace diagnostic: {} process(es), {} path event(s), {} read, {} failed, {} written or attempted; not recorded",
        d.processes,
        d.events,
        read.len(),
        d.failed.len(),
        written.len()
    )];
    let reasons: Vec<&String> = t
        .unsound
        .iter()
        .filter(|reason| reason.as_str() != DIAGNOSTIC_ONLY)
        .collect();
    if reasons.is_empty() {
        out.push(
            "DTrace diagnostic verdict: no loss announced; calls the script does not trace are not seen; not recorded"
                .into(),
        );
    } else {
        out.push(format!(
            "DTrace diagnostic verdict: UNSOUND ({} reason(s), {} tracer loss or error line(s), {} descriptor-relative path(s) not placed); not recorded",
            reasons.len(),
            d.losses,
            d.unplaced.len()
        ));
        for reason in reasons {
            out.push(format!(
                "DTrace diagnostic UNSOUND: {}",
                crate::run::safe(reason)
            ));
        }
    }
    if paths {
        for path in &read {
            out.push(format!("dtrace read {}", shown_path(path)));
        }
        for path in &d.failed {
            out.push(format!("dtrace failed {}", shown_path(path)));
        }
        for path in &written {
            out.push(format!("dtrace wrote {}", shown_path(path)));
        }
        for (parent, child) in &d.spawns {
            out.push(format!("dtrace spawn {parent} {child}"));
        }
        for (pid, path) in &d.execs {
            out.push(format!("dtrace exec {pid} {}", shown_path(path)));
        }
        for (fd, path) in &d.unplaced {
            out.push(format!("dtrace unplaced {fd} {}", crate::run::safe(path)));
        }
    }
    if raw {
        for line in &d.raw {
            out.push(format!("dtrace raw {}", crate::run::safe(line)));
        }
    }
    out
}

fn shown_path(path: &Path) -> String {
    crate::run::safe(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observer() -> Observer {
        Observer::new(100, Path::new("/work"))
    }

    /// One path record, as the script prints it at timestamp 1.
    fn ev(pid: u32, op: &str, dirfd: &str, value: &str, path: &str) -> String {
        ev_at(1, pid, op, dirfd, value, path)
    }

    fn ev_at(ts: u64, pid: u32, op: &str, dirfd: &str, value: &str, path: &str) -> String {
        format!(
            "EV\t0.{ts}\t{pid}\t{op}\t{dirfd}\t{value}\t{}\t{path}",
            path.len()
        )
    }

    fn fail(pid: u32, dirfd: i32, path: &str) -> String {
        format!("FAIL\t0.1\t{pid}\t{dirfd}\t{}\t{path}", path.len())
    }

    fn feed(observer: &mut Observer, lines: &[&str]) {
        for line in lines {
            observer.feed(line);
        }
    }

    fn clean_end(observer: &mut Observer) {
        feed(observer, &["EXIT\t0.2\t100", "STOP"]);
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
                &ev(100, "stat", "-", "-", "in.txt"),
                &ev(100, "open", "-", "1537", "/work/out.txt"),
                &ev(100, "mkdir", "-", "-", "../work/build"),
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
        assert!(d.trace.touched[Path::new("/work/in.txt")].read);
        assert!(d.trace.written.contains(Path::new("/work/out.txt")));
        assert_eq!(d.trace.created_dirs, [PathBuf::from("/work/build")]);
        assert_eq!(d.events, 3);
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
            let path = format!("/f{flags}");
            feed(&mut o, &[&ev(100, "open", "-", &flags.to_string(), &path)]);
            o.settle();
            assert_eq!(
                o.trace.written.contains(Path::new(&path)),
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
                &ev(100, "chdir", "-", "0", "sub"),
                "SPAWN\t0.1\t100\t200",
                &ev(200, "stat", "-", "-", "a.txt"),
                "EXIT\t0.1\t200",
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
            &[
                &ev(100, "chdir", "-", "-1", "missing"),
                &ev(100, "stat", "-", "-", "a"),
            ],
        );
        o.settle();
        assert!(o.trace.touched.contains_key(Path::new("/work/a")));
        assert!(o.trace.touched.contains_key(Path::new("/work/missing")));
    }

    #[test]
    fn a_failed_chdir_is_a_failed_lookup() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "chdir", "-", "-1", "missing")]);
        o.settle();
        assert!(o.failed.contains(Path::new("/work/missing")));
    }

    #[test]
    fn events_that_arrive_before_their_spawn_edge_are_held_then_placed() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                &ev(300, "stat", "-", "-", "early"),
                "SPAWN\t0.1\t100\t300",
                "EXIT\t0.1\t300",
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.contains_key(Path::new("/work/early")));
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn a_pid_that_never_links_to_the_tree_is_unsound() {
        let mut o = observer();
        feed(&mut o, &[&ev(999, "stat", "-", "-", "x")]);
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
    fn a_null_pointer_error_is_unsound_on_every_probe() {
        for line in [
            "dtrace: error on enabled probe ID 7 (ID 12: proc:::create): invalid address (0x0) in action #1",
            "dtrace: error on enabled probe ID 8 (ID 13: syscall::fstatat64:entry): invalid address (0x0) in action #2",
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
    fn failed_lookups_are_listed_as_failed_and_still_touched() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                &ev(100, "stat", "-", "-", "missing/x"),
                &fail(100, -2, "missing/x"),
                &ev(100, "stat", "-", "-", "in.txt"),
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.failed.contains(Path::new("/work/missing/x")));
        assert!(!d.failed.contains(Path::new("/work/in.txt")));
        assert!(d.trace.touched.contains_key(Path::new("/work/missing/x")));
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn a_failed_lookup_relative_to_a_descriptor_is_unsound_and_not_placed() {
        let mut o = observer();
        feed(&mut o, &[&fail(100, 7, "rel.txt")]);
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.failed.is_empty());
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("directory descriptor")));
    }

    #[test]
    fn descriptor_relative_paths_are_listed_as_unplaced_and_share_one_reason() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                "SPAWN\t0.1\t100\t200",
                &ev(100, "openat", "7", "0", "rel.txt"),
                &ev(200, "openat", "7", "0", "rel.txt"),
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(
            d.unplaced.contains(&(7, "rel.txt".to_string())),
            "{:?}",
            d.unplaced
        );
        let descriptor_reasons = reasons(&d)
            .iter()
            .filter(|r| r.contains("directory descriptor"))
            .count();
        assert_eq!(descriptor_reasons, 1, "{:?}", reasons(&d));
        assert!(report(&d, true, false)
            .iter()
            .any(|l| l == "dtrace unplaced 7 rel.txt"));
    }

    #[test]
    fn paths_that_cannot_be_placed_are_unsound() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "openat", "7", "0", "rel.txt")]);
        o.settle();
        assert!(o.trace.unsound.iter().any(|r| r.contains("descriptor")));
        let mut o = observer();
        feed(
            &mut o,
            &["FCHDIR\t0.1\t100", &ev(100, "stat", "-", "-", "rel")],
        );
        o.settle();
        assert!(o.trace.unsound.iter().any(|r| r.contains("fchdir")));
        assert!(o.trace.unsound.iter().any(|r| r.contains("unknown")));
        let mut o = observer();
        let long = format!("/{}", "a".repeat(STRSIZE));
        feed(&mut o, &[&ev(100, "stat", "-", "-", &long)]);
        o.settle();
        assert!(o.trace.unsound.iter().any(|r| r.contains("cut off")));
    }

    #[test]
    fn at_fdcwd_paths_resolve_against_the_directory() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "openat", "-2", "0", "rel.txt")]);
        o.settle();
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

    #[test]
    fn tracer_losses_are_counted_and_the_first_is_named() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                "dtrace: 3 drops on CPU 1",
                "dtrace: 9 dynamic variable drops with non-empty dirty list",
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert_eq!(d.losses, 2);
        assert_eq!(
            reasons(&d)
                .iter()
                .filter(|r| r.contains("loss or error"))
                .count(),
            1
        );
    }

    #[test]
    fn a_path_whose_length_does_not_match_is_unsound_and_not_applied() {
        let mut o = observer();
        feed(&mut o, &["EV\t0.1\t100\tstat\t-\t-\t7\tx"]);
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.is_empty());
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("did not match the length")));
    }

    #[test]
    fn a_newline_in_a_path_makes_the_run_unsound_even_when_the_rest_looks_like_a_clean_end() {
        let mut o = observer();
        feed(
            &mut o,
            &["EV\t0.1\t100\tstat\t-\t-\t7\tx", "EXIT\t0.1\t100", "STOP"],
        );
        let d = o.finish(0);
        assert!(d.trace.touched.is_empty());
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("did not match the length")));
    }

    #[test]
    fn a_path_with_a_trailing_carriage_return_keeps_it() {
        let mut o = observer();
        feed(&mut o, &["EV\t0.1\t100\tstat\t-\t-\t4\tfoo\r"]);
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(d.trace.touched.contains_key(Path::new("/work/foo\r")));
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
    }

    #[test]
    fn an_empty_line_is_unsound() {
        let mut o = observer();
        feed(&mut o, &[""]);
        clean_end(&mut o);
        assert!(reasons(&o.finish(0))
            .iter()
            .any(|r| r.contains("empty line")));
    }

    #[test]
    fn records_are_applied_in_timestamp_order_not_arrival_order() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                &ev_at(20, 100, "stat", "-", "-", "a"),
                &ev_at(10, 100, "chdir", "-", "0", "sub"),
            ],
        );
        o.settle();
        assert!(o.trace.touched.contains_key(Path::new("/work/sub")));
        assert!(o.trace.touched.contains_key(Path::new("/work/sub/a")));
        let mut o = observer();
        feed(
            &mut o,
            &[
                &ev_at(10, 100, "stat", "-", "-", "a"),
                &ev_at(20, 100, "chdir", "-", "0", "sub"),
            ],
        );
        o.settle();
        assert!(o.trace.touched.contains_key(Path::new("/work/a")));
        assert!(!o.trace.touched.contains_key(Path::new("/work/sub/a")));
    }

    #[test]
    fn a_pid_reused_while_its_process_is_alive_is_unsound() {
        let mut o = observer();
        feed(&mut o, &["SPAWN\t0.1\t100\t200", "SPAWN\t0.2\t100\t200"]);
        clean_end(&mut o);
        assert!(reasons(&o.finish(0)).iter().any(|r| r.contains("reused")));
    }

    #[test]
    fn an_event_after_its_process_exited_is_unsound_and_not_applied() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                "SPAWN\t0.1\t100\t200",
                "EXIT\t0.2\t200",
                &ev_at(3, 200, "stat", "-", "-", "late"),
            ],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(!d.trace.touched.contains_key(Path::new("/work/late")));
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("after its process had exited")));
    }

    #[test]
    fn a_posix_spawn_child_has_no_known_working_directory() {
        let mut o = observer();
        feed(
            &mut o,
            &["SPAWNX\t0.1\t100\t200", &ev(200, "stat", "-", "-", "rel")],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(!d.trace.touched.contains_key(Path::new("/work/rel")));
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("working directory is unknown")));
    }

    #[test]
    fn a_pthread_chdir_makes_the_working_directory_unknown() {
        let mut o = observer();
        feed(
            &mut o,
            &["PTHCHDIR\t0.1\t100", &ev(100, "stat", "-", "-", "rel")],
        );
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(!d.trace.touched.contains_key(Path::new("/work/rel")));
        assert!(reasons(&d).iter().any(|r| r.contains("pthread chdir")));
    }

    #[test]
    fn reasons_are_capped_but_the_end_of_run_reasons_are_kept() {
        let mut o = observer();
        for n in 0..40 {
            o.feed(&format!("frobnicate{n}\t1"));
        }
        let d = o.finish(0);
        assert!(reasons(&d).len() <= MAX_REASONS + 3, "{:?}", reasons(&d));
        assert!(reasons(&d).iter().any(|r| r.contains("clean stop")));
        assert!(reasons(&d).iter().any(|r| r.contains("exit was not seen")));
    }

    #[test]
    fn unreadable_lines_and_unknown_operations_are_unsound() {
        for line in [
            "garbage",
            "EV\tnotapid\tstat\t-\t-\t1\tx",
            "EV\t0.1\t100\tstat\t-\t-\t1",
            "SPAWN\t0.1\t100",
            "EV\t0.1\t100\tfrobnicate\t-\t-\t1\tx",
        ] {
            let mut o = observer();
            o.feed(line);
            clean_end(&mut o);
            let d = o.finish(0);
            assert!(reasons(&d).len() >= 2, "{line}: {:?}", reasons(&d));
        }
    }

    #[test]
    fn markers_and_running_processes_are_checked_at_the_end() {
        let d = observer().finish(0);
        assert!(reasons(&d).iter().any(|r| r.contains("exit was not seen")));
        assert!(reasons(&d).iter().any(|r| r.contains("clean stop")));
        let mut o = observer();
        feed(&mut o, &["SPAWN\t0.1\t100\t200", "EXIT\t0.2\t100", "STOP"]);
        let d = o.finish(0);
        assert!(reasons(&d).iter().any(|r| r.contains("still running")));
    }

    #[test]
    fn the_recorder_refuses_a_diagnostic_trace() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "stat", "-", "-", "in.txt")]);
        clean_end(&mut o);
        let d = o.finish(0);
        let root = Path::new("/work");
        let mut phys = crate::pathutil::Physical::new(root, root);
        let ignore = crate::ignore::Ignore::new(&[], None, &[]);
        match crate::run::build_inputs(
            root,
            &mut phys,
            &d.trace,
            &ignore,
            &std::collections::BTreeSet::new(),
        ) {
            Err(reason) => assert!(reason.contains("diagnostic backend"), "{reason}"),
            Ok(_) => panic!("the recorder accepted a diagnostic trace"),
        }
    }

    #[test]
    fn the_report_says_no_loss_is_announced_and_never_claims_completeness() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "stat", "-", "-", "in.txt")]);
        clean_end(&mut o);
        let lines = report(&o.finish(0), false, false);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("no loss announced") && l.contains("not seen")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("UNSOUND")), "{lines:?}");
    }

    #[test]
    fn a_loss_is_reported_as_unsound_with_its_text() {
        let mut o = observer();
        feed(&mut o, &["dtrace: 3 drops on CPU 1"]);
        clean_end(&mut o);
        let lines = report(&o.finish(0), false, false);
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("DTrace diagnostic verdict: UNSOUND")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("DTrace diagnostic UNSOUND: ")
                    && l.contains("3 drops on CPU 1")),
            "{lines:?}"
        );
    }

    #[test]
    fn listings_separate_reads_failed_lookups_writes_and_the_tree() {
        let mut o = observer();
        feed(
            &mut o,
            &[
                &ev(100, "stat", "-", "-", "in.txt"),
                &ev(100, "stat", "-", "-", "missing"),
                &fail(100, -2, "missing"),
                &ev(100, "open", "-", "1537", "/work/out.txt"),
                "SPAWN\t0.1\t100\t200",
                &ev(200, "exec", "-", "-", "/usr/bin/true"),
                "EXIT\t0.2\t200",
            ],
        );
        clean_end(&mut o);
        let lines = report(&o.finish(0), true, false);
        for expected in [
            "dtrace read /work/in.txt",
            "dtrace failed /work/missing",
            "dtrace wrote /work/out.txt",
            "dtrace spawn 100 200",
            "dtrace exec 200 /usr/bin/true",
        ] {
            assert!(lines.iter().any(|l| l == expected), "{expected}: {lines:?}");
        }
        assert!(
            !lines.iter().any(|l| l == "dtrace read /work/missing"),
            "{lines:?}"
        );
    }

    #[test]
    fn raw_lines_are_printed_only_in_raw_mode_and_paths_only_when_asked() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "stat", "-", "-", "in.txt")]);
        o.raw.push("EV\t0.1\t100\tstat\t-\t-\t6\tin.txt".into());
        clean_end(&mut o);
        let d = o.finish(0);
        let summary_only = report(&d, false, false);
        assert!(
            !summary_only.iter().any(|l| l.starts_with("dtrace ")),
            "{summary_only:?}"
        );
        let with_paths = report(&d, true, false);
        assert!(with_paths.iter().any(|l| l == "dtrace read /work/in.txt"));
        assert!(!with_paths.iter().any(|l| l.starts_with("dtrace raw")));
        let with_raw = report(&d, true, true);
        assert!(
            with_raw.iter().any(|l| l.starts_with("dtrace raw EV")),
            "{with_raw:?}"
        );
    }

    #[test]
    fn control_characters_in_paths_are_escaped_on_the_report() {
        let mut o = observer();
        feed(&mut o, &["EV\t0.1\t100\tstat\t-\t-\t3\ta\u{1b}b"]);
        clean_end(&mut o);
        let lines = report(&o.finish(0), true, false);
        assert!(
            lines.iter().any(|l| l == "dtrace read /work/a\\u{1b}b"),
            "{lines:?}"
        );
    }

    /// The fake tracer: a shell script that stands in for DTrace. The root pid is `$0`.
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
            false,
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
            false,
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
            false,
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
            fake("echo READY; echo 'dtrace: 3 drops on CPU 1'; printf 'EXIT\\t0.1\\t%s\\nSTOP\\n' \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .unwrap();
        assert_eq!(d.trace.status, 0);
        assert!(reasons(&d).iter().any(|r| r.contains("drops on CPU")));
        assert!(!reasons(&d).iter().any(|r| r.contains("clean stop")));
    }

    #[test]
    fn stderr_output_is_a_loss_and_makes_the_run_unsound() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake("echo READY; echo 'dtrace: 12 drops on CPU 0' >&2; printf 'EXIT\\t0.1\\t%s\\nSTOP\\n' \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .unwrap();
        assert!(d.losses >= 1);
        assert!(reasons(&d)
            .iter()
            .any(|r| r.contains("error stream") && r.contains("12 drops")));
    }

    #[test]
    fn a_complete_fake_run_sees_the_commands_paths() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake("echo READY; printf 'EV\\t0.1\\t%s\\tstat\\t-\\t-\\t10\\t/etc/hosts\\nEXIT\\t0.2\\t%s\\nSTOP\\n' \"$0\" \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .unwrap();
        assert_eq!(reasons(&d), [DIAGNOSTIC_ONLY]);
        assert!(d.trace.touched.contains_key(Path::new("/etc/hosts")));
        assert_eq!(d.trace.status, 0);
    }

    #[test]
    fn raw_mode_keeps_every_line_the_tracer_printed() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake("echo READY; printf 'EV\\t0.1\\t%s\\tstat\\t-\\t-\\t10\\t/etc/hosts\\nEXIT\\t0.2\\t%s\\nSTOP\\n' \"$0\" \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            true,
        )
        .unwrap();
        assert_eq!(d.raw.len(), 4, "{:?}", d.raw);
    }

    #[test]
    fn a_non_utf8_path_makes_the_run_unsound() {
        let argv = [OsString::from("/usr/bin/true")];
        let d = run_with(
            fake("echo READY; printf 'EV\\t0.1\\t%s\\tstat\\t-\\t-\\t1\\t\\377\\nEXIT\\t0.2\\t%s\\nSTOP\\n' \"$0\" \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .unwrap();
        assert!(
            reasons(&d).iter().any(|r| r.contains("not valid UTF-8")),
            "{:?}",
            reasons(&d)
        );
    }

    #[test]
    fn a_command_named_with_a_dash_runs_as_it_does_untraced() {
        let argv = [OsString::from("-a")];
        let d = run_with(
            fake("echo READY; printf 'EXIT\\t0.1\\t%s\\nSTOP\\n' \"$0\""),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_secs(5),
            false,
        )
        .unwrap();
        assert_eq!(d.trace.status, 127);
    }

    #[test]
    fn a_tracer_that_ignores_interrupts_does_not_hold_the_run() {
        let argv = [OsString::from("/usr/bin/true")];
        let started = Instant::now();
        let d = run_with(
            fake("echo READY; trap '' INT; sleep 30"),
            "",
            &argv,
            Path::new("/"),
            Duration::from_secs(5),
            Duration::from_millis(300),
            false,
        )
        .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the run waited {:?} for a tracer that never exits",
            started.elapsed()
        );
        assert_eq!(d.trace.status, 0);
        assert!(
            reasons(&d).iter().any(|r| r.contains("did not stop")),
            "{:?}",
            reasons(&d)
        );
    }

    /// A reader whose first read fails, as a broken pipe does.
    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the pipe is broken"))
        }
    }

    #[test]
    fn a_wrapper_whose_release_is_dropped_exits_without_running_the_command() {
        let file = marker("released");
        let _ = std::fs::remove_file(&file);
        let argv = [
            OsString::from("/usr/bin/touch"),
            file.clone().into_os_string(),
        ];
        let (mut child, release) = start_held(&argv, Path::new("/")).unwrap();
        drop(release);
        assert_eq!(child.wait().unwrap().code(), Some(125));
        assert!(!file.exists(), "the command ran without its release");
    }

    #[test]
    fn a_released_command_starts_without_the_release_pipe() {
        let argv = [
            OsString::from("/bin/sh"),
            OsString::from("-c"),
            OsString::from("test -e /dev/fd/3 && exit 9; exit 0"),
        ];
        let (mut child, mut release) = start_held(&argv, Path::new("/")).unwrap();
        release.write_all(b"\n").unwrap();
        drop(release);
        assert_eq!(child.wait().unwrap().code(), Some(0));
    }

    #[test]
    fn a_line_that_never_ends_is_unsound() {
        let mut o = observer();
        let mut ready = None;
        read_lines(&b"EXIT\t0.1\t100\nSTOP"[..], &mut o, &mut ready, false);
        let d = o.finish(0);
        assert!(
            reasons(&d)
                .iter()
                .any(|r| r.contains("ended inside a line")),
            "{:?}",
            reasons(&d)
        );
    }

    #[test]
    fn a_read_error_on_the_tracers_output_is_unsound() {
        let mut o = observer();
        let mut ready = None;
        read_lines(Broken, &mut o, &mut ready, false);
        let d = o.finish(0);
        assert!(
            reasons(&d).iter().any(|r| r.contains("could not be read")),
            "{:?}",
            reasons(&d)
        );
    }

    #[test]
    fn a_read_error_on_the_error_stream_is_unsound() {
        let mut o = observer();
        note_stderr(&mut o, &read_stderr(Broken));
        clean_end(&mut o);
        let d = o.finish(0);
        assert!(
            reasons(&d).iter().any(|r| r.contains("could not be read")),
            "{:?}",
            reasons(&d)
        );
    }

    #[test]
    fn every_byte_on_the_error_stream_is_a_loss_even_without_a_newline() {
        let mut o = observer();
        note_stderr(&mut o, &read_stderr(&b"drop"[..]));
        clean_end(&mut o);
        let d = o.finish(0);
        assert_eq!(d.losses, 1);
        assert!(reasons(&d).iter().any(|r| r.contains("error stream")));
    }

    #[test]
    fn an_exec_is_listed_and_counts_as_a_read() {
        let mut o = observer();
        feed(&mut o, &[&ev(100, "exec", "-", "-", "/usr/bin/true")]);
        clean_end(&mut o);
        let d = o.finish(0);
        assert_eq!(d.execs, [(100, PathBuf::from("/usr/bin/true"))]);
        assert!(d.trace.touched[Path::new("/usr/bin/true")].read);
    }
}
