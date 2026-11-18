//! Linux tracer: ptrace plus a seccomp-bpf filter.
//!
//! The filter makes the kernel stop the tracee only on the syscalls that name
//! files (open, stat, exec, rename and so on). Every other syscall runs at
//! full speed, which keeps the overhead to one stop per file touched.
//!
//! Paths are read from the tracee at syscall entry, before the call runs. Whether a
//! path existed is decided later, by looking at the tree after the command exits,
//! except for priors: what a path held before the run first wrote it is read at the
//! same stop, because the write is about to change it.

use super::{ExecEvent, Scope, Trace};
use crate::ignore::Ignore;
use crate::input::{file_id, hash_file};
use crate::pathutil::{absolutize, to_key, without_dots, Physical};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

const PR_SET_SECCOMP: libc::c_int = 22;
const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const NT_PRSTATUS: usize = 1;
const AT_FDCWD: i32 = -100;
const PATH_MAX: usize = 4096;

/// Linux ABI flags, the same on every architecture.
const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
const AT_REMOVEDIR: i32 = 0x200;
const AT_EMPTY_PATH: i32 = 0x1000;
const RENAME_EXCHANGE: u32 = 2;

/// `fchmodat2` is missing from the libc crate on these targets; the number is 452 on both.
const SYS_FCHMODAT2: i64 = 452;

/// Prior content is hashed up to this size per file, and this total per run.
const MAX_FILE_BYTES: u64 = 8 << 20;
const MAX_RUN_BYTES: u64 = 256 << 20;
/// Same cap as the tracer's other reasons.
const MAX_REASONS: usize = 16;

// Observation is informational, so an unreadable or oversized chain is discarded without
// affecting the legacy trace or the command. Bounds include live tasks as well as execs.
const MAX_EXEC_EVENTS: usize = 1024;
const MAX_EXEC_TASKS: usize = 1024;
const MAX_EXEC_ARGS: usize = 128;
const MAX_EXEC_ARG_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
enum Op {
    /// open-family call. `flags` is the open-flags argument; None is `creat`.
    Open {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
    },
    /// stat, access, readlink, link source: a look at the name.
    Look {
        dirfd: Option<usize>,
        path: usize,
    },
    Exec {
        dirfd: Option<usize>,
        path: usize,
    },
    /// getdents on an fd: the directory's entries were listed.
    List,
    Chdir {
        path: usize,
    },
    Fchdir,
    /// mkdir, symlink, link: creates a name (`dir` for mkdir).
    Create {
        dirfd: Option<usize>,
        path: usize,
        dir: bool,
    },
    /// unlink, unlinkat, rmdir: removes a name. `flags` carries AT_REMOVEDIR for unlinkat;
    /// `dir` marks rmdir.
    Remove {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
        dir: bool,
    },
    /// rename family. `flags` carries RENAME_EXCHANGE for renameat2.
    Rename {
        from_dirfd: Option<usize>,
        from: usize,
        to_dirfd: Option<usize>,
        to: usize,
        flags: Option<usize>,
    },
    /// truncate.
    Truncate {
        path: usize,
    },
    /// chmod family. Calls follow links unless `flags` carries AT_SYMLINK_NOFOLLOW.
    Chmod {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
    },
    /// fchmod: the file is named by its fd.
    Fchmod {
        fd: usize,
    },
    /// Something this tracer cannot see through.
    Unsound(&'static str),
    /// clone-family calls are unsound only when they create a namespace.
    Clone {
        modern: bool,
    },
    /// A connection: what is on the other side is not a file.
    Connect,
}

#[allow(clippy::unnecessary_cast)] // c_long is i64 on the supported arches, but not everywhere
fn table() -> Vec<(i64, Vec<Op>)> {
    use Op::*;
    let s = |n: libc::c_long| n as i64;
    let mut t: Vec<(i64, Vec<Op>)> = vec![
        (
            s(libc::SYS_openat),
            vec![Open {
                dirfd: Some(0),
                path: 1,
                flags: Some(2),
            }],
        ),
        (
            s(libc::SYS_openat2),
            vec![Unsound("it used openat2, which the tracer cannot follow")],
        ),
        (
            s(libc::SYS_open_by_handle_at),
            vec![Unsound(
                "it opened a file by handle, which the tracer cannot follow",
            )],
        ),
        (
            s(libc::SYS_execve),
            vec![Exec {
                dirfd: None,
                path: 0,
            }],
        ),
        (
            s(libc::SYS_execveat),
            vec![Exec {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (
            s(libc::SYS_newfstatat),
            vec![Look {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (
            s(libc::SYS_statx),
            vec![Look {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (
            s(libc::SYS_faccessat),
            vec![Look {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (
            s(libc::SYS_faccessat2),
            vec![Look {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (
            s(libc::SYS_readlinkat),
            vec![Look {
                dirfd: Some(0),
                path: 1,
            }],
        ),
        (s(libc::SYS_getdents64), vec![List]),
        (s(libc::SYS_chdir), vec![Chdir { path: 0 }]),
        (s(libc::SYS_fchdir), vec![Fchdir]),
        (
            s(libc::SYS_unlinkat),
            vec![Remove {
                dirfd: Some(0),
                path: 1,
                flags: Some(2),
                dir: false,
            }],
        ),
        (
            s(libc::SYS_mkdirat),
            vec![Create {
                dirfd: Some(0),
                path: 1,
                dir: true,
            }],
        ),
        (
            s(libc::SYS_renameat2),
            vec![Rename {
                from_dirfd: Some(0),
                from: 1,
                to_dirfd: Some(2),
                to: 3,
                flags: Some(4),
            }],
        ),
        (
            s(libc::SYS_symlinkat),
            vec![Create {
                dirfd: Some(1),
                path: 2,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_linkat),
            vec![
                Look {
                    dirfd: Some(0),
                    path: 1,
                },
                Create {
                    dirfd: Some(2),
                    path: 3,
                    dir: false,
                },
            ],
        ),
        (s(libc::SYS_truncate), vec![Truncate { path: 0 }]),
        (s(libc::SYS_connect), vec![Connect]),
        (s(libc::SYS_clone), vec![Clone { modern: false }]),
        (s(libc::SYS_clone3), vec![Clone { modern: true }]),
        (
            s(libc::SYS_open_tree),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_move_mount),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_fsopen),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_fsconfig),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_fsmount),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_fspick),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_mount_setattr),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_mount),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_umount2),
            vec![Unsound("it attempted to change mount topology")],
        ),
        (
            s(libc::SYS_unshare),
            vec![Unsound("it attempted to change namespaces")],
        ),
        (
            s(libc::SYS_chroot),
            vec![Unsound("it attempted to change its filesystem root")],
        ),
        (
            s(libc::SYS_pivot_root),
            vec![Unsound("it attempted to change its filesystem root")],
        ),
        (
            s(libc::SYS_setns),
            vec![Unsound("it attempted to change namespaces")],
        ),
        (
            s(libc::SYS_fchmodat),
            vec![Chmod {
                dirfd: Some(0),
                path: 1,
                flags: None,
            }],
        ),
        (
            SYS_FCHMODAT2,
            vec![Chmod {
                dirfd: Some(0),
                path: 1,
                flags: Some(3),
            }],
        ),
        (s(libc::SYS_fchmod), vec![Fchmod { fd: 0 }]),
    ];
    #[cfg(target_arch = "x86_64")]
    t.extend([
        (
            s(libc::SYS_open),
            vec![Open {
                dirfd: None,
                path: 0,
                flags: Some(1),
            }],
        ),
        (
            s(libc::SYS_creat),
            vec![Open {
                dirfd: None,
                path: 0,
                flags: None,
            }],
        ),
        (
            s(libc::SYS_stat),
            vec![Look {
                dirfd: None,
                path: 0,
            }],
        ),
        (
            s(libc::SYS_lstat),
            vec![Look {
                dirfd: None,
                path: 0,
            }],
        ),
        (
            s(libc::SYS_access),
            vec![Look {
                dirfd: None,
                path: 0,
            }],
        ),
        (
            s(libc::SYS_readlink),
            vec![Look {
                dirfd: None,
                path: 0,
            }],
        ),
        (s(libc::SYS_getdents), vec![List]),
        (
            s(libc::SYS_unlink),
            vec![Remove {
                dirfd: None,
                path: 0,
                flags: None,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_mkdir),
            vec![Create {
                dirfd: None,
                path: 0,
                dir: true,
            }],
        ),
        (
            s(libc::SYS_rmdir),
            vec![Remove {
                dirfd: None,
                path: 0,
                flags: None,
                dir: true,
            }],
        ),
        (
            s(libc::SYS_rename),
            vec![Rename {
                from_dirfd: None,
                from: 0,
                to_dirfd: None,
                to: 1,
                flags: None,
            }],
        ),
        (
            s(libc::SYS_symlink),
            vec![Create {
                dirfd: None,
                path: 1,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_link),
            vec![
                Look {
                    dirfd: None,
                    path: 0,
                },
                Create {
                    dirfd: None,
                    path: 1,
                    dir: false,
                },
            ],
        ),
        (
            s(libc::SYS_chmod),
            vec![Chmod {
                dirfd: None,
                path: 0,
                flags: None,
            }],
        ),
    ]);
    // renameat (no flags) exists on both; it takes the same argument positions.
    t.push((
        s(libc::SYS_renameat),
        vec![Rename {
            from_dirfd: Some(0),
            from: 1,
            to_dirfd: Some(2),
            to: 3,
            flags: None,
        }],
    ));
    t
}

/// Syscalls the kernel refuses with ENOSYS for traced processes. io_uring moves file
/// operations out of reach of a syscall tracer; runtimes that use it (libuv, tokio)
/// fall back to ordinary syscalls when it is unavailable, so denying it keeps every
/// file access visible.
#[allow(clippy::unnecessary_cast)] // c_long is i64 on the supported arches, but not everywhere
fn denied() -> Vec<i64> {
    vec![libc::SYS_io_uring_setup as i64]
}

fn bpf_filter(nrs: &[i64], deny: &[i64]) -> Vec<libc::sock_filter> {
    const LD_W_ABS: u16 = 0x20;
    const JEQ_K: u16 = 0x15;
    const RET_K: u16 = 0x06;
    let (n, d) = (nrs.len(), deny.len());
    let l_allow = 3 + n + d;
    let l_trace = l_allow + 1;
    let l_errno = l_allow + 2;
    let mut f = Vec::with_capacity(l_errno + 1);
    let ins = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    f.push(ins(LD_W_ABS, 0, 0, 4)); // arch
    f.push(ins(JEQ_K, 0, (l_trace - 2) as u8, AUDIT_ARCH));
    f.push(ins(LD_W_ABS, 0, 0, 0)); // syscall number
    for (i, nr) in nrs.iter().enumerate() {
        let idx = 3 + i;
        f.push(ins(JEQ_K, (l_trace - idx - 1) as u8, 0, *nr as u32));
    }
    for (i, nr) in deny.iter().enumerate() {
        let idx = 3 + n + i;
        f.push(ins(JEQ_K, (l_errno - idx - 1) as u8, 0, *nr as u32));
    }
    f.push(ins(RET_K, 0, 0, SECCOMP_RET_ALLOW));
    f.push(ins(RET_K, 0, 0, SECCOMP_RET_TRACE));
    f.push(ins(RET_K, 0, 0, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    f
}

#[cfg(target_arch = "x86_64")]
fn decode(r: &libc::user_regs_struct) -> (i64, [u64; 6]) {
    (r.orig_rax as i64, [r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9])
}

#[cfg(target_arch = "aarch64")]
fn decode(r: &libc::user_regs_struct) -> (i64, [u64; 6]) {
    (
        r.regs[8] as i64,
        [
            r.regs[0], r.regs[1], r.regs[2], r.regs[3], r.regs[4], r.regs[5],
        ],
    )
}

/// What priors need beyond the trace: where paths live, what is excluded, and how much
/// content has been read so far.
struct Rec<'a> {
    phys: Physical,
    ignore: &'a Ignore,
    /// The root as the user spelled it; keys in reasons are relative to it.
    root: PathBuf,
    hashed: u64,
    link_walks: BTreeMap<PathBuf, Vec<PathBuf>>,
    redirected_reads: HashSet<String>,
}

struct Tracer<'a> {
    ops: HashMap<i64, Vec<Op>>,
    cwds: HashMap<i32, PathBuf>,
    magic_epoch: u64,
    magic_cache: HashMap<PathBuf, (u64, bool)>,
    pending_topology: HashSet<i32>,
    syscall: i64,
    allow_network: bool,
    /// Present when priors are recorded (not with `--no-record`).
    rec: Option<Rec<'a>>,
    execs: Option<ExecObserver>,
    t: Trace,
}

pub fn run<'a>(
    argv: &[String],
    cwd: &Path,
    allow_network: bool,
    scope: Option<&Scope<'a>>,
    observe_execs: bool,
) -> io::Result<Trace> {
    if argv.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty command"));
    }
    let tbl = table();
    let nrs: Vec<i64> = tbl.iter().map(|(n, _)| *n).collect();
    let filter = bpf_filter(&nrs, &denied());
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // Everything the child needs is built before fork: no allocation after it.
    let cargs: Vec<CString> = argv
        .iter()
        .map(|a| {
            CString::new(a.as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
        })
        .collect::<io::Result<_>>()?;
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME as _, 0, 0, 0) < 0 {
                libc::_exit(126);
            }
            libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if libc::prctl(
                PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const _ as libc::c_ulong,
                0,
                0,
            ) != 0
            {
                libc::_exit(126);
            }
            libc::kill(libc::getpid(), libc::SIGSTOP);
            libc::execvp(ptrs[0], ptrs.as_ptr());
            libc::_exit(127);
        }
    }

    let mut tr = Tracer {
        ops: tbl.into_iter().collect(),
        cwds: HashMap::new(),
        allow_network,
        magic_epoch: 0,
        magic_cache: HashMap::new(),
        pending_topology: HashSet::new(),
        syscall: 0,
        execs: observe_execs.then(|| ExecObserver::new(pid)),
        rec: scope.map(|s| Rec {
            phys: Physical::new(s.root, &s.real_root),
            ignore: s.ignore,
            root: s.root.to_path_buf(),
            hashed: 0,
            link_walks: BTreeMap::new(),
            redirected_reads: HashSet::new(),
        }),
        t: Trace {
            status: 1,
            ..Trace::default()
        },
    };
    tr.cwds.insert(pid, cwd.to_path_buf());

    let mut st: libc::c_int = 0;
    loop {
        if unsafe { libc::waitpid(pid, &mut st, libc::__WALL) } >= 0 {
            break;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        let _ = kill_and_reap(pid);
        return Err(err);
    }
    if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
        // The child died before exec (seccomp refused, for instance).
        return Err(io::Error::other("could not start the traced command"));
    }
    let opts = libc::PTRACE_O_TRACESECCOMP
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_EXITKILL;
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS as _, pid, 0, opts as libc::c_long) } < 0 {
        let e = io::Error::last_os_error();
        let _ = kill_and_reap(pid);
        return Err(e);
    }
    cont(pid, 0);
    let mut root_finished = false;
    let mut wait_failed = false;

    loop {
        let p = unsafe { libc::waitpid(-1, &mut st, libc::__WALL) };
        if p < 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ECHILD) => {
                    if !root_finished {
                        tr.flag("tracer wait ended before the command exit status was observed");
                        if let Some(execs) = &mut tr.execs {
                            execs.invalidate();
                        }
                    }
                    break;
                }
                Some(libc::EINTR) => continue,
                _ => {
                    tr.flag(&format!("tracer wait failed: {err}"));
                    if let Some(execs) = &mut tr.execs {
                        execs.invalidate();
                    }
                    if wait_failed {
                        if !root_finished {
                            tr.t.status = kill_and_reap(pid).unwrap_or(1);
                        }
                        break;
                    }
                    wait_failed = true;
                    continue;
                }
            }
        }
        wait_failed = false;
        // Topology syscalls resume with PTRACE_SYSCALL, so their next syscall
        // stop occurs after the kernel has applied or rejected the mutation.
        let syscall_exit = libc::WIFSTOPPED(st) && libc::WSTOPSIG(st) == (libc::SIGTRAP | 0x80);
        if syscall_exit || libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
            tr.after_topology_stop(p);
        }
        if libc::WIFEXITED(st) {
            if p == pid {
                tr.t.status = libc::WEXITSTATUS(st);
                root_finished = true;
            }
            tr.cwds.remove(&p);
            if let Some(execs) = &mut tr.execs {
                execs.exit(p);
            }
            continue;
        }
        if libc::WIFSIGNALED(st) {
            if p == pid {
                tr.t.status = 128 + libc::WTERMSIG(st);
                root_finished = true;
            }
            tr.cwds.remove(&p);
            if let Some(execs) = &mut tr.execs {
                execs.exit(p);
            }
            continue;
        }
        if !libc::WIFSTOPPED(st) {
            continue;
        }
        let sig = libc::WSTOPSIG(st);
        match (st >> 16) & 0xff {
            0 => {
                // A fresh tracee announces itself with SIGSTOP; swallow that one.
                let pass = if sig == libc::SIGSTOP || sig == libc::SIGTRAP || syscall_exit {
                    0
                } else {
                    sig
                };
                resume(p, pass, tr.pending_topology.contains(&p));
            }
            e if e == libc::PTRACE_EVENT_SECCOMP => {
                tr.on_syscall(p);
                resume(p, 0, tr.pending_topology.contains(&p));
            }
            e if matches!(
                e,
                libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE
            ) =>
            {
                if let Some(execs) = &mut tr.execs {
                    execs.fork(p);
                }
                cont(p, 0);
            }
            e if e == libc::PTRACE_EVENT_EXEC => {
                if let Some(execs) = &mut tr.execs {
                    execs.exec(p);
                }
                cont(p, 0);
            }
            _ => cont(p, 0),
        }
    }
    tr.t.execs = tr.execs.and_then(ExecObserver::finish);
    Ok(tr.t)
}

/// Stop a child and reap it after an unrecoverable tracer failure.
fn kill_and_reap(pid: i32) -> Option<i32> {
    unsafe { libc::kill(pid, libc::SIGKILL) };
    loop {
        let mut st = 0;
        if unsafe { libc::waitpid(pid, &mut st, libc::__WALL) } < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        if libc::WIFEXITED(st) {
            return Some(libc::WEXITSTATUS(st));
        }
        if libc::WIFSIGNALED(st) {
            return Some(128 + libc::WTERMSIG(st));
        }
        if libc::WIFSTOPPED(st) {
            cont(pid, libc::SIGKILL);
        }
    }
}

fn cont(pid: i32, sig: libc::c_int) {
    unsafe {
        libc::ptrace(libc::PTRACE_CONT as _, pid, 0, sig as libc::c_long);
    }
}

fn resume(pid: i32, sig: libc::c_int, syscall_exit: bool) {
    if syscall_exit {
        unsafe {
            libc::ptrace(libc::PTRACE_SYSCALL as _, pid, 0, sig as libc::c_long);
        }
    } else {
        cont(pid, sig);
    }
}

fn get_regs(pid: i32) -> Option<libc::user_regs_struct> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET as _,
            pid,
            NT_PRSTATUS,
            &mut iov as *mut _,
        )
    };
    (r >= 0).then_some(regs)
}

/// Read up to `len` bytes of the tracee's memory; fewer if the range ends early.
fn read_mem(pid: i32, addr: u64, len: usize) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut _,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut _,
        iov_len: len,
    };
    let mut n = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if n <= 0 {
        // Some sandboxes block process_vm_readv; /proc/pid/mem is the fallback.
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
        n = f.read_at(&mut buf, addr).ok()? as isize;
        if n <= 0 {
            return None;
        }
    }
    buf.truncate(n as usize);
    Some(buf)
}

fn read_cstr(pid: i32, addr: u64) -> Option<Vec<u8>> {
    let mut buf = read_mem(pid, addr, PATH_MAX)?;
    let end = buf.iter().position(|&b| b == 0)?;
    buf.truncate(end);
    Some(buf)
}
struct PendingExec {
    requested: PathBuf,
    argv: Vec<OsString>,
}

struct ExecObserver {
    // The current image for each traced task; a fork inherits its parent's image.
    tasks: HashMap<i32, Option<usize>>,
    pending: HashMap<i32, Option<PendingExec>>,
    events: Vec<ExecEvent>,
    valid: bool,
}

impl ExecObserver {
    fn new(root: i32) -> Self {
        Self {
            tasks: HashMap::from([(root, None)]),
            pending: HashMap::new(),
            events: Vec::new(),
            valid: true,
        }
    }

    fn invalidate(&mut self) {
        self.valid = false;
        self.tasks.clear();
        self.pending.clear();
        self.events.clear();
    }

    fn enter(&mut self, pid: i32, nr: i64, args: &[u64; 6]) {
        if !self.valid {
            return;
        }
        if !self.tasks.contains_key(&pid) {
            self.invalidate();
            return;
        }
        let (path, argv) = if nr == libc::SYS_execve {
            (args[0], args[1])
        } else {
            (args[1], args[2])
        };
        let candidate = read_cstr(pid, path).and_then(|path| {
            read_exec_argv(pid, argv).map(|argv| PendingExec {
                requested: PathBuf::from(OsString::from_vec(path)),
                argv,
            })
        });
        // A failed PATH lookup never gets an exec event. Only the candidate associated
        // with a successful PTRACE_EVENT_EXEC is promoted into the observation.
        self.pending.insert(pid, candidate);
    }

    fn fork(&mut self, parent: i32) {
        if !self.valid {
            return;
        }
        let child = event_message(parent);
        let inherited = self.tasks.get(&parent).copied();
        match (child, inherited) {
            (Some(child), Some(image)) if self.tasks.len() < MAX_EXEC_TASKS => {
                self.tasks.insert(child, image);
                self.pending.remove(&child);
            }
            _ => self.invalidate(),
        }
    }

    fn exec(&mut self, pid: i32) {
        if !self.valid {
            return;
        }
        // A non-leader thread takes the leader's TID at exec. Linux reports its former
        // TID in the event message, which identifies the pending entry and ancestry.
        let Some(former) = event_message(pid) else {
            self.invalidate();
            return;
        };
        let Some(parent) = self.tasks.remove(&former) else {
            self.invalidate();
            return;
        };
        let Some(Some(pending)) = self.pending.remove(&former) else {
            self.invalidate();
            return;
        };
        if former != pid {
            self.tasks.remove(&pid);
            self.pending.remove(&pid);
        }
        let Some((executable, effective_argv, cwd)) = exec_image(pid) else {
            self.invalidate();
            return;
        };
        if self.events.len() >= MAX_EXEC_EVENTS {
            self.invalidate();
            return;
        }
        let index = self.events.len();
        self.events.push(ExecEvent {
            parent,
            requested: pending.requested,
            argv: pending.argv,
            executable,
            effective_argv,
            cwd,
        });
        self.tasks.insert(pid, Some(index));
    }

    fn exit(&mut self, pid: i32) {
        self.tasks.remove(&pid);
        self.pending.remove(&pid);
    }

    fn finish(self) -> Option<Vec<ExecEvent>> {
        self.valid.then_some(self.events)
    }
}

fn event_message(pid: i32) -> Option<i32> {
    let mut value = 0u64;
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_GETEVENTMSG as _,
            pid,
            0,
            &mut value as *mut u64,
        )
    };
    if result < 0 {
        None
    } else {
        i32::try_from(value).ok()
    }
}

fn read_exec_argv(pid: i32, address: u64) -> Option<Vec<OsString>> {
    if address == 0 {
        return Some(Vec::new());
    }
    let pointers = read_mem(pid, address, (MAX_EXEC_ARGS + 1) * 8)?;
    let mut argv = Vec::new();
    let mut bytes = 0;
    for raw in pointers.chunks_exact(8).take(MAX_EXEC_ARGS + 1) {
        let pointer = u64::from_ne_bytes(raw.try_into().ok()?);
        if pointer == 0 {
            return Some(argv);
        }
        if argv.len() == MAX_EXEC_ARGS {
            return None;
        }
        let mut arg = read_mem(pid, pointer, MAX_EXEC_ARG_BYTES.checked_sub(bytes)? + 1)?;
        let end = arg.iter().position(|byte| *byte == 0)?;
        bytes += end + 1;
        if bytes > MAX_EXEC_ARG_BYTES {
            return None;
        }
        arg.truncate(end);
        argv.push(OsString::from_vec(arg));
    }
    None
}

fn exec_image(pid: i32) -> Option<(PathBuf, Vec<OsString>, PathBuf)> {
    use std::io::Read;

    let proc = format!("/proc/{pid}");
    let executable = fs::read_link(format!("{proc}/exe")).ok()?;
    let cwd = fs::read_link(format!("{proc}/cwd")).ok()?;
    let mut raw = Vec::new();
    fs::File::open(format!("{proc}/cmdline"))
        .ok()?
        .take((MAX_EXEC_ARG_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .ok()?;
    if raw.len() > MAX_EXEC_ARG_BYTES || raw.last() != Some(&0) {
        return None;
    }
    raw.pop();
    let argv: Vec<OsString> = raw
        .split(|byte| *byte == 0)
        .map(|arg| OsString::from_vec(arg.to_vec()))
        .collect();
    (argv.len() <= MAX_EXEC_ARGS).then_some((executable, argv, cwd))
}

/// `ip:port` for an IPv4 or IPv6 sockaddr, so a refusal says what the step talked to.
fn describe_dest(sa: &[u8]) -> String {
    let family = u16::from_ne_bytes([sa[0], sa[1]]) as i32;
    let port = |i: usize| sa.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    match family {
        libc::AF_INET => match (port(2), sa.get(4..8)) {
            (Some(p), Some(a)) => format!("connect to {}.{}.{}.{}:{p}", a[0], a[1], a[2], a[3]),
            _ => "connect to an IPv4 address".to_string(),
        },
        libc::AF_INET6 => match (port(2), sa.get(8..24)) {
            (Some(p), Some(a)) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(a);
                format!("connect to [{}]:{p}", std::net::Ipv6Addr::from(octets))
            }
            _ => "connect to an IPv6 address".to_string(),
        },
        _ => "connect to a vsock peer".to_string(),
    }
}

/// Whether `e` says the path, or one of its parents, is not there.
fn is_absent(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound || e.raw_os_error() == Some(libc::ENOTDIR)
}

fn is_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

/// Read an ELF PT_INTERP pathname without loading the executable into memory.
fn elf_interpreter(file: &mut fs::File, header: &[u8]) -> io::Result<Option<PathBuf>> {
    use std::io::{Read, Seek, SeekFrom};
    if !header.starts_with(b"\x7fELF") {
        return Ok(None);
    }
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid ELF header");
    if header.len() < 64 || !matches!(header[4], 1 | 2) || !matches!(header[5], 1 | 2) {
        return Err(invalid());
    }
    let little = header[5] == 1;
    let u16_at = |b: &[u8], i| {
        let x: [u8; 2] = b[i..i + 2].try_into().unwrap();
        if little {
            u16::from_le_bytes(x)
        } else {
            u16::from_be_bytes(x)
        }
    };
    let u32_at = |b: &[u8], i| {
        let x: [u8; 4] = b[i..i + 4].try_into().unwrap();
        if little {
            u32::from_le_bytes(x)
        } else {
            u32::from_be_bytes(x)
        }
    };
    let u64_at = |b: &[u8], i| {
        let x: [u8; 8] = b[i..i + 8].try_into().unwrap();
        if little {
            u64::from_le_bytes(x)
        } else {
            u64::from_be_bytes(x)
        }
    };
    let wide = header[4] == 2;
    let (phoff, entsize, count, need) = if wide {
        (
            u64_at(header, 32),
            u16_at(header, 54) as u64,
            u16_at(header, 56) as u64,
            56usize,
        )
    } else {
        (
            u32_at(header, 28) as u64,
            u16_at(header, 42) as u64,
            u16_at(header, 44) as u64,
            32usize,
        )
    };
    if count == 0 {
        return Ok(None);
    }
    let length = file.metadata()?.len();
    let total = entsize.checked_mul(count).ok_or_else(invalid)?;
    if entsize < need as u64
        || total > 65536
        || phoff.checked_add(total).is_none_or(|end| end > length)
    {
        return Err(invalid());
    }
    let mut program = [0u8; 56];
    for i in 0..count {
        file.seek(SeekFrom::Start(phoff + i * entsize))?;
        file.read_exact(&mut program[..need])?;
        if u32_at(&program, 0) != 3 {
            continue;
        }
        let (offset, size) = if wide {
            (u64_at(&program, 8), u64_at(&program, 32))
        } else {
            (u32_at(&program, 4) as u64, u32_at(&program, 16) as u64)
        };
        if size < 2
            || size > PATH_MAX as u64
            || offset.checked_add(size).is_none_or(|end| end > length)
        {
            return Err(invalid());
        }
        let mut target = [0u8; PATH_MAX];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut target[..size as usize])?;
        if target[size as usize - 1] != 0 || target[..size as usize - 1].contains(&0) {
            return Err(invalid());
        }
        return Ok(Some(PathBuf::from(OsString::from_vec(
            target[..size as usize - 1].to_vec(),
        ))));
    }
    Ok(None)
}

fn proc_magic_link(path: &Path) -> bool {
    let parts: Vec<&str> = path.iter().filter_map(|part| part.to_str()).collect();
    if parts.len() < 4 || parts[1] != "proc" || !parts[2].bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let mut index = 3;
    if parts.get(index) == Some(&"task") {
        if !parts
            .get(index + 1)
            .is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit()))
        {
            return false;
        }
        index += 2;
    }
    match parts.get(index) {
        Some(&"cwd" | &"root" | &"exe") => parts.len() == index + 1,
        Some(&"fd" | &"map_files") => parts.len() == index + 2,
        _ => false,
    }
}

/// A reason the planner cannot replay the run. The first one also stops content hashing.
fn push_reason(t: &mut Trace, why: String) {
    if t.unplannable.len() < MAX_REASONS && !t.unplannable.contains(&why) {
        t.unplannable.push(why);
    }
}

impl Rec<'_> {
    fn key_text(&self, lex: &Path) -> String {
        to_key(&self.root, lex)
    }

    /// The repository key of a physical path, when the path is recordable: inside the
    /// root, not under `.git`, not ignored. A non-UTF-8 name is refused with a reason.
    fn key_of(&self, phys: &Path, t: &mut Trace) -> Option<String> {
        let rel = self.phys.repo_rel(phys)?;
        if rel.components().any(|c| c.as_os_str() == ".git") {
            return None;
        }
        let Some(key) = rel.to_str() else {
            if t.unsound.len() < 16 {
                t.unsound
                    .push("it used a path in the repository that is not valid UTF-8".into());
            }
            return None;
        };
        if self.ignore.is_ignored(key) {
            return None;
        }
        Some(key.to_string())
    }

    /// Follow each parent component in kernel order. A preceding outside alias may enter
    /// the repository before another symlink is encountered; `..` follows link targets.
    fn links_below_root(&mut self, raw: &Path) -> Option<Vec<PathBuf>> {
        use std::collections::VecDeque;
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStrExt;
        let parent = raw.parent()?.to_path_buf();
        if let Some(cached) = self.link_walks.get(&parent) {
            return Some(cached.clone());
        }
        let mut parts: VecDeque<OsString> = raw
            .parent()?
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .filter(|p| !p.is_empty() && *p != b".")
            .map(|p| OsString::from_vec(p.to_vec()))
            .collect();
        let mut current = PathBuf::from("/");
        let mut links = 0;
        let mut found = Vec::new();
        while let Some(part) = parts.pop_front() {
            if part.as_bytes() == b".." {
                current.pop();
                continue;
            }
            current.push(part);
            if fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
                if current.starts_with(self.phys.real()) {
                    found.push(current.clone());
                }
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = fs::read_link(&current).ok()?;
                current.pop();
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                let expanded: Vec<OsString> = target
                    .as_os_str()
                    .as_bytes()
                    .split(|b| *b == b'/')
                    .filter(|p| !p.is_empty() && *p != b".")
                    .map(|p| OsString::from_vec(p.to_vec()))
                    .collect();
                for part in expanded.into_iter().rev() {
                    parts.push_front(part);
                }
            }
        }
        self.link_walks.insert(parent, found.clone());
        Some(found)
    }

    fn forget_walks(&mut self, path: &Path) {
        let keys: Vec<PathBuf> = self
            .link_walks
            .range(path.to_path_buf()..)
            .take_while(|(key, _)| key.starts_with(path))
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.link_walks.remove(&key);
        }
    }

    /// Record a write to `raw` (absolute, possibly with `..`). `follows` indicates
    /// whether a symlink at `raw` is followed. Returns the key when in scope.
    fn write(&mut self, t: &mut Trace, raw: &Path, follows: bool) -> Option<String> {
        let lex = absolutize(Path::new("/"), raw);
        self.forget_walks(&lex);
        self.forget_walks(raw);
        self.phys.forget(&lex);
        self.phys.forget(raw);
        let mut target = raw.to_path_buf();
        if follows && fs::symlink_metadata(raw).is_ok_and(|m| m.file_type().is_symlink()) {
            // The write lands on the link's target, which is not named here. A link whose
            // link and target are both outside the repository is nothing to record.
            let resolved = fs::canonicalize(raw).ok();
            let link_path = self.phys.locate(raw)?.path;
            let link_in_scope = self.key_of(&link_path, t).is_some();
            let target_in_scope = match &resolved {
                Some(r) => {
                    let target_path = self.phys.locate(r)?.path;
                    self.key_of(&target_path, t).is_some()
                }
                None => false,
            };
            if !link_in_scope && !target_in_scope {
                return None;
            }
            let link = self.key_text(&lex);
            push_reason(t, format!("it wrote through the symlink {link}"));
            target = resolved?;
        }
        let loc = self.phys.locate(&target)?;
        self.forget_walks(&loc.path);
        self.phys.forget(&loc.path);
        let key = self.key_of(&loc.path, t)?;
        for link in self.links_below_root(raw).unwrap_or_default() {
            let name = to_key(self.phys.real(), &link);
            t.touched.entry(link).or_default().read = true;
            push_reason(t, format!("it wrote through the symlink {name}"));
        }
        if !t.priors.contains_key(&key) {
            // A create fails when its parent is missing or is not a directory. A later commit
            // that adds the parent would change that outcome, so the parent's state is recorded.
            self.parent_prior(t, &loc.path);
            if let Some(id) = self.prior_id(t, &loc.path, &key) {
                t.priors.insert(key.clone(), id);
            }
        }
        t.keys.insert(loc.path, key.clone());
        Some(key)
    }

    fn parent_prior(&mut self, t: &mut Trace, phys: &Path) {
        let Some(parent) = phys.parent() else { return };
        let Some(pkey) = self.key_of(parent, t) else {
            return;
        };
        if t.priors.contains_key(&pkey) {
            return;
        }
        match fs::symlink_metadata(parent) {
            Err(e) if is_absent(&e) => {
                t.priors.insert(pkey, "a".to_string());
            }
            Ok(m) if m.is_file() => {
                if let Some(id) = self.prior_id(t, parent, &pkey) {
                    t.priors.insert(pkey, id);
                }
            }
            _ => {}
        }
    }

    /// What `phys` holds right now, in the id form a proof uses. `None` when it cannot be
    /// stated (and the run is then unplannable with a reason).
    fn prior_id(&mut self, t: &mut Trace, phys: &Path, key: &str) -> Option<String> {
        let m = match fs::symlink_metadata(phys) {
            Ok(m) => m,
            Err(e) if is_absent(&e) => return Some("a".to_string()),
            Err(_) => {
                push_reason(
                    t,
                    format!("could not read what {key} held before the run wrote it"),
                );
                return None;
            }
        };
        let ft = m.file_type();
        if ft.is_symlink() {
            return match fs::read_link(phys)
                .ok()
                .and_then(|p| p.into_os_string().into_string().ok())
            {
                Some(target) => Some(format!("l:{target}")),
                None => {
                    t.unsound.push(format!(
                        "the link {key} has an unreadable or non-UTF-8 target"
                    ));
                    None
                }
            };
        }
        if ft.is_dir() {
            return Some("d".to_string());
        }
        if !ft.is_file() {
            push_reason(t, format!("{key} is a special file"));
            return None;
        }
        let exec = m.mode() & 0o111 != 0;
        let size = m.len();
        if size > MAX_FILE_BYTES || self.hashed + size > MAX_RUN_BYTES {
            push_reason(
                t,
                format!("{key} is too large to record before the run wrote it ({size} bytes)"),
            );
            return None;
        }
        if !t.unplannable.is_empty() {
            // Once replay is already impossible, avoid hashing more content.
            return None;
        }
        match hash_file(phys) {
            Ok(h) => {
                self.hashed += size;
                Some(file_id(exec, &h))
            }
            Err(_) => {
                push_reason(t, format!("could not read {key} before the run wrote it"));
                None
            }
        }
    }
}

impl Tracer<'_> {
    fn flag(&mut self, why: &str) {
        if self.t.unsound.len() < 16 && !self.t.unsound.iter().any(|u| u == why) {
            self.t.unsound.push(why.to_string());
        }
    }

    fn cwd(&mut self, pid: i32) -> Option<PathBuf> {
        if let Some(c) = self.cwds.get(&pid) {
            return Some(c.clone());
        }
        let c = std::fs::read_link(format!("/proc/{pid}/cwd")).ok()?;
        self.cwds.insert(pid, c.clone());
        Some(c)
    }

    /// Resolve proc magic links in the tracee's namespace, not stoop's own `/proc/self`.
    /// Ordinary names remain as written so the regular link walker can track their links.
    fn map_magic_path(&mut self, pid: i32, raw: PathBuf) -> Option<PathBuf> {
        use std::collections::VecDeque;
        use std::os::unix::ffi::OsStrExt;
        if self.rec.is_none() {
            return Some(raw);
        }
        let parent = raw.parent()?.to_path_buf();
        if self.magic_cache.get(&parent) == Some(&(self.magic_epoch, false))
            && !fs::symlink_metadata(&raw).is_ok_and(|m| m.file_type().is_symlink())
        {
            return Some(raw);
        }
        let mut parts: VecDeque<OsString> = raw
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .filter(|part| !part.is_empty() && *part != b".")
            .map(|part| OsString::from_vec(part.to_vec()))
            .collect();
        let mut current = PathBuf::from("/");
        let mut magic = false;
        let mut links = 0;
        let mut repository_links = Vec::new();
        while let Some(part) = parts.pop_front() {
            if part.as_bytes() == b".." {
                current.pop();
                continue;
            }
            if current == Path::new("/proc")
                && (part.as_bytes() == b"self" || part.as_bytes() == b"thread-self")
            {
                current.push(pid.to_string());
            } else {
                current.push(part);
            }
            let special = proc_magic_link(&current);
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {}
                _ if special => {
                    self.flag("could not resolve a process path alias");
                    return None;
                }
                _ => continue,
            }
            links += 1;
            if links > 40 {
                self.flag("too many links while resolving a path");
                return None;
            }
            if special {
                magic = true;
            } else if let Some(rec) = &self.rec {
                if current.starts_with(rec.phys.real()) {
                    self.t.touched.entry(current.clone()).or_default().read = true;
                    repository_links.push(current.clone());
                }
            }
            let target = match fs::read_link(&current) {
                Ok(target) => target,
                Err(_) if special => {
                    self.flag("could not resolve a process path alias");
                    return None;
                }
                Err(_) => return Some(raw),
            };
            if special
                && (!target.is_absolute() || target.as_os_str().as_bytes().ends_with(b" (deleted)"))
            {
                if matches!(self.syscall, libc::SYS_execve | libc::SYS_execveat) {
                    self.flag("it executed an unkeyable file descriptor");
                } else if self.syscall == libc::SYS_linkat
                    && target.as_os_str().as_bytes().ends_with(b" (deleted)")
                {
                    self.flag("it accessed an unkeyable descriptor alias");
                }
                return None;
            }
            current.pop();
            if target.is_absolute() {
                current = PathBuf::from("/");
            }
            let expanded: Vec<OsString> = target
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .filter(|part| !part.is_empty() && *part != b".")
                .map(|part| OsString::from_vec(part.to_vec()))
                .collect();
            for part in expanded.into_iter().rev() {
                parts.push_front(part);
            }
        }
        // A final-component symlink can be retargeted or removed later in this run.
        // Preserve its call-time in-repository target instead of relying on the
        // post-run link lookup to recover what was actually read.
        if links > 0
            && self
                .rec
                .as_ref()
                .is_some_and(|r| r.phys.repo_rel(&current).is_some())
        {
            self.t.touched.entry(current.clone()).or_default().read = true;
        }
        self.magic_cache.insert(parent, (self.magic_epoch, magic));
        if magic {
            self.t.magic_links.extend(repository_links);
            Some(current)
        } else {
            Some(raw)
        }
    }

    /// The path a call names, joined onto its directory. Not normalized: the kernel
    /// resolves `..` through symlinks, and so must the physical lookups.
    fn resolve(
        &mut self,
        pid: i32,
        args: &[u64; 6],
        dirfd: Option<usize>,
        path: usize,
    ) -> Option<PathBuf> {
        if args[path] == 0 {
            return None; // statx(fd, NULL, AT_EMPTY_PATH): no name involved
        }
        let raw = match read_cstr(pid, args[path]) {
            Some(r) => r,
            None => {
                let why = if std::env::var_os("STOOP_DEBUG").is_some() {
                    format!("could not read a path from the traced process (pid {pid}, addr {:#x}, arg {path})", args[path])
                } else {
                    "could not read a path from the traced process".to_string()
                };
                self.flag(&why);
                return None;
            }
        };
        if raw.is_empty() {
            return None; // AT_EMPTY_PATH: the fd itself, which was opened by name earlier
        }
        let p = PathBuf::from(OsString::from_vec(raw));
        if p.is_absolute() {
            return self.map_magic_path(pid, without_dots(&p));
        }
        let base = match dirfd.map(|i| args[i] as i32) {
            None | Some(AT_FDCWD) => self.cwd(pid),
            Some(fd) => std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok(),
        };
        match base {
            Some(b) if b.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") => {
                self.flag("it accessed a deleted directory through a file descriptor");
                None
            }
            Some(b) => self.map_magic_path(pid, without_dots(&b.join(&p))),
            None => {
                self.flag("could not resolve a relative path");
                None
            }
        }
    }

    fn touch(&mut self, lex: PathBuf, read: bool) {
        let mut path = lex;
        if let Some(rec) = &mut self.rec {
            for link in rec.links_below_root(&path).unwrap_or_default() {
                self.t.touched.entry(link).or_default().read = true;
            }
            // Record observations where the call resolved them, not after the run.
            if let Some(loc) = rec.phys.locate(&path) {
                if loc.path != path && rec.phys.repo_rel(&loc.path).is_some() {
                    if read && loc.redirected {
                        if let Some(key) = rec.key_of(&loc.path, &mut self.t) {
                            if self.t.keys.contains_key(&loc.path) {
                                push_reason(
                                    &mut self.t,
                                    format!(
                                        "it read {key} through a directory alias and also wrote it"
                                    ),
                                );
                            }
                            rec.redirected_reads.insert(key);
                        }
                    }
                    path = loc.path;
                }
            }
        }
        self.t.touched.entry(path).or_default().read |= read;
    }

    /// The kernel loads shebang and ELF interpreters without a traceable open syscall.
    fn exec_path(&mut self, pid: i32, mut path: PathBuf) {
        use std::io::Read;
        if self.rec.is_none() {
            return;
        }
        // Linux permits at most four recursive script interpreters.
        for _ in 0..=4 {
            self.touch(path.clone(), true);
            let mut bytes = [0u8; 256];
            let Ok(mut file) = fs::File::open(&path) else {
                return;
            };
            let Ok(n) = file.read(&mut bytes) else { return };
            if let Some(rest) = bytes[..n].strip_prefix(b"#!") {
                let rest = rest.split(|b| *b == b'\n').next().unwrap_or_default();
                let Some(start) = rest.iter().position(|b| !matches!(*b, b' ' | b'\t')) else {
                    return;
                };
                let name = rest[start..]
                    .split(|b| matches!(*b, b' ' | b'\t'))
                    .next()
                    .unwrap_or_default();
                if name.is_empty() {
                    return;
                }
                let interpreter = PathBuf::from(OsString::from_vec(name.to_vec()));
                let absolute = if interpreter.is_absolute() {
                    interpreter
                } else if let Some(cwd) = self.cwd(pid) {
                    without_dots(&cwd.join(interpreter))
                } else {
                    self.flag("could not resolve a shebang interpreter");
                    return;
                };
                let Some(next) = self.map_magic_path(pid, absolute) else {
                    return;
                };
                path = next;
                continue;
            }
            match elf_interpreter(&mut file, &bytes[..n]) {
                Ok(Some(interpreter)) => {
                    let absolute = if interpreter.is_absolute() {
                        interpreter
                    } else if let Some(cwd) = self.cwd(pid) {
                        without_dots(&cwd.join(interpreter))
                    } else {
                        self.flag("could not resolve an ELF interpreter");
                        return;
                    };
                    if let Some(interpreter) = self.map_magic_path(pid, absolute) {
                        self.touch(interpreter, true);
                    }
                }
                Ok(None) => {}
                Err(_) => self.flag("could not inspect an ELF interpreter"),
            }
            return;
        }
    }

    /// Record a write, and what the path held before the first one. Returns the key when in scope.
    fn write(&mut self, raw: &Path, follows: bool) -> Option<String> {
        self.rec.as_ref()?;
        // A write through a link changes what the link points to, not the link itself.
        let through_link =
            follows && fs::symlink_metadata(raw).is_ok_and(|m| m.file_type().is_symlink());
        if !through_link {
            self.t.written.insert(raw.to_path_buf());
        } else {
            self.touch(raw.to_path_buf(), true);
        }
        let rec = self.rec.as_mut()?;
        let key = rec.write(&mut self.t, raw, follows)?;
        if rec.redirected_reads.contains(&key) {
            push_reason(
                &mut self.t,
                format!("it read {key} through a directory alias and also wrote it"),
            );
        }
        Some(key)
    }

    /// An alias topology change invalidates cache entries under every spelling.
    fn clear_topology(&mut self) {
        self.magic_epoch = self.magic_epoch.wrapping_add(1);
        if let Some(rec) = &mut self.rec {
            rec.phys.clear();
            rec.link_walks.clear();
        }
    }

    fn topology_changed(&mut self, pid: i32) {
        self.clear_topology();
        self.pending_topology.insert(pid);
    }

    fn after_topology_stop(&mut self, pid: i32) {
        if self.pending_topology.remove(&pid) {
            self.clear_topology();
        }
    }

    /// Sockets that name services use. A shell or libc touches these on startup, and
    /// what they answer is the machine's identity data, not the job's behavior.
    fn check_connect(&mut self, pid: i32, args: &[u64; 6]) {
        const NAME_SERVICE_SOCKETS: &[&[u8]] = &[
            b"/var/run/nscd/socket",
            b"/run/nscd/socket",
            b"/run/systemd/resolve/io.systemd.Resolve",
            b"/run/systemd/userdb/io.systemd.DynamicUser",
            b"/run/systemd/userdb/io.systemd.Multiplexer",
            b"/run/systemd/userdb/io.systemd.NameServiceSwitch",
        ];
        let blind = "pass --allow-network to record it anyway";
        let len = (args[2] as usize).clamp(2, 128);
        let Some(sa) = read_mem(pid, args[1], len).filter(|s| s.len() >= 2) else {
            self.flag(&format!(
                "it made a connection the tracer could not inspect; {blind}"
            ));
            return;
        };
        match u16::from_ne_bytes([sa[0], sa[1]]) as i32 {
            libc::AF_INET | libc::AF_INET6 | libc::AF_VSOCK => {
                let dest = describe_dest(&sa);
                self.flag(&format!(
                    "it used the network ({dest}), whose results a file trace cannot see; cover it with --probe, or {blind}"
                ));
            }
            libc::AF_UNIX => {
                let rest = &sa[2..];
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                if end == 0 || !NAME_SERVICE_SOCKETS.contains(&&rest[..end]) {
                    let what = if end == 0 {
                        "an abstract socket".to_string()
                    } else {
                        String::from_utf8_lossy(&rest[..end]).into_owned()
                    };
                    self.flag(&format!(
                        "it connected to a local service ({what}), whose behavior a file trace cannot see; {blind}"
                    ));
                }
            }
            _ => {}
        }
    }

    fn open(
        &mut self,
        pid: i32,
        args: &[u64; 6],
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
    ) {
        let Some(p) = self.resolve(pid, args, dirfd, path) else {
            return;
        };
        match flags.map(|i| args[i] as i32) {
            // An O_TMPFILE open writes nothing; the later linkat names the file.
            Some(f) if f & libc::O_TMPFILE == libc::O_TMPFILE => {
                self.touch(p, false);
            }
            // creat truncates the named file.
            None => {
                self.write(&p, true);
            }
            Some(f) => {
                let writes = f
                    & (libc::O_WRONLY
                        | libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_TRUNC
                        | libc::O_APPEND)
                    != 0;
                if writes {
                    let creates_exclusively = f & libc::O_CREAT != 0 && f & libc::O_EXCL != 0;
                    let follows = f & libc::O_NOFOLLOW == 0 && !creates_exclusively;
                    self.write(&p, follows);
                } else {
                    self.touch(p, true);
                }
            }
        }
    }

    fn create(&mut self, pid: i32, args: &[u64; 6], dirfd: Option<usize>, path: usize, dir: bool) {
        let Some(p) = self.resolve(pid, args, dirfd, path) else {
            return;
        };
        if dir {
            // mkdir on a path that exists fails with EEXIST and creates nothing: `mkdir -p`
            // and `create_dir_all` do this for every ancestor. The existence is an input.
            if fs::symlink_metadata(&p).is_ok() {
                self.touch(p, false);
                return;
            }
        }
        if !dir {
            self.topology_changed(pid);
        }
        self.write(&p, false);
        if dir {
            if let Some(loc) = self.rec.as_mut().and_then(|r| r.phys.locate(&p)) {
                self.t.created_dirs.push(loc.path);
            }
        }
    }

    fn remove(
        &mut self,
        pid: i32,
        args: &[u64; 6],
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
        dir: bool,
    ) {
        let Some(p) = self.resolve(pid, args, dirfd, path) else {
            return;
        };
        let removes_dir = dir || flags.is_some_and(|i| args[i] as i32 & AT_REMOVEDIR != 0);
        if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir() || m.file_type().is_symlink()) {
            self.topology_changed(pid);
        }
        // Read the directory's contents before the call, while they are still there.
        let key = self.write(&p, false);
        if let Some(key) = key.filter(|_| removes_dir && is_dir(&p)) {
            if let Ok(mut entries) = fs::read_dir(&p) {
                if entries.next().is_some() {
                    push_reason(
                        &mut self.t,
                        format!("it removed the non-empty directory {key}"),
                    );
                }
            }
        }
    }

    fn rename(
        &mut self,
        pid: i32,
        args: &[u64; 6],
        from: (Option<usize>, usize),
        to: (Option<usize>, usize),
        flags: Option<usize>,
    ) {
        let (Some(a), Some(b)) = (
            self.resolve(pid, args, from.0, from.1),
            self.resolve(pid, args, to.0, to.1),
        ) else {
            return;
        };
        let exchange = flags.is_some_and(|i| args[i] as u32 & RENAME_EXCHANGE != 0);
        let directory = is_dir(&a) || (exchange && is_dir(&b));
        if [&a, &b].iter().any(|p| {
            fs::symlink_metadata(p).is_ok_and(|m| m.is_dir() || m.file_type().is_symlink())
        }) {
            self.topology_changed(pid);
        }
        let ka = self.write(&a, false);
        let kb = self.write(&b, false);
        if directory && (ka.is_some() || kb.is_some()) {
            let name = |k: Option<String>, p: &Path| {
                k.unwrap_or_else(|| absolutize(Path::new("/"), p).to_string_lossy().into_owned())
            };
            let (from_s, to_s) = (name(ka, &a), name(kb, &b));
            push_reason(
                &mut self.t,
                format!("it renamed the directory {from_s} to {to_s}"),
            );
        }
    }

    /// A chmod or fchmod. Mode changes are writes: the executable bit is part of a file's id.
    /// The bytes survive a mode change, so the content is recorded too.
    fn chmod(&mut self, raw: &Path, follows: bool) {
        if !raw.is_absolute() {
            return;
        }
        match fs::symlink_metadata(raw) {
            Ok(m) if m.is_dir() => self.touch(raw.to_path_buf(), false),
            Ok(_) => {
                self.write(raw, follows);
            }
            Err(_) => {}
        }
    }

    fn on_syscall(&mut self, pid: i32) {
        let Some(regs) = get_regs(pid) else {
            self.flag("could not read registers");
            if let Some(execs) = &mut self.execs {
                execs.invalidate();
            }
            return;
        };
        let (nr, args) = decode(&regs);
        if matches!(nr, libc::SYS_execve | libc::SYS_execveat) {
            if let Some(execs) = &mut self.execs {
                execs.enter(pid, nr, &args);
            }
        }
        self.syscall = nr;
        let Some(ops) = self.ops.get(&nr).cloned() else {
            self.flag(
                "it ran code under a foreign syscall ABI (32-bit) that the tracer cannot follow",
            );
            return;
        };
        for op in ops {
            match op {
                Op::Open { dirfd, path, flags } => self.open(pid, &args, dirfd, path, flags),
                Op::Look { dirfd, path } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        self.touch(p, true);
                    }
                }
                Op::Exec { dirfd, path } => {
                    let empty_fd_exec = nr == libc::SYS_execveat
                        && args[4] as i32 & AT_EMPTY_PATH != 0
                        && (args[path] == 0
                            || read_cstr(pid, args[path]).is_some_and(|s| s.is_empty()));
                    if empty_fd_exec {
                        let fd = args[dirfd.expect("execveat has a dirfd")] as i32;
                        match std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
                            Ok(p)
                                if p.is_absolute()
                                    && !p
                                        .as_os_str()
                                        .as_encoded_bytes()
                                        .ends_with(b" (deleted)") =>
                            {
                                self.exec_path(pid, p)
                            }
                            _ => self.flag("it executed an unkeyable file descriptor"),
                        }
                    } else if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        self.exec_path(pid, p);
                    }
                }
                Op::List => {
                    let fd = args[0] as i32;
                    if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
                        self.t.touched.entry(p).or_default().listed = true;
                    }
                }
                Op::Chdir { path } => {
                    if let Some(p) = self.resolve(pid, &args, None, path) {
                        self.touch(p, false);
                    }
                    // Threads can share a cwd, so any chdir drops every cached value.
                    self.cwds.clear();
                }
                Op::Fchdir => self.cwds.clear(),
                Op::Create { dirfd, path, dir } => self.create(pid, &args, dirfd, path, dir),
                Op::Remove {
                    dirfd,
                    path,
                    flags,
                    dir,
                } => self.remove(pid, &args, dirfd, path, flags, dir),
                Op::Rename {
                    from_dirfd,
                    from,
                    to_dirfd,
                    to,
                    flags,
                } => self.rename(pid, &args, (from_dirfd, from), (to_dirfd, to), flags),
                Op::Truncate { path } => {
                    if let Some(p) = self.resolve(pid, &args, None, path) {
                        self.write(&p, true);
                    }
                }
                Op::Chmod { dirfd, path, flags } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        let nofollow =
                            flags.is_some_and(|i| args[i] as i32 & AT_SYMLINK_NOFOLLOW != 0);
                        self.chmod(&p, !nofollow);
                    }
                }
                Op::Fchmod { fd } => {
                    // The fd was opened by name; its path is the file's physical location.
                    if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/fd/{}", args[fd] as i32))
                    {
                        if !p.to_string_lossy().ends_with(" (deleted)") {
                            self.chmod(&p, false);
                        }
                    }
                }
                Op::Unsound(why) => self.flag(why),
                Op::Clone { modern } => {
                    let flags = if modern {
                        read_mem(pid, args[0], 8)
                            .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                            .map(u64::from_ne_bytes)
                    } else {
                        Some(args[0])
                    };
                    // CLONE_NEWTIME and all CLONE_NEW* namespace bits.
                    const NAMESPACE_FLAGS: u64 = 0x0000_0080 | 0x7e02_0000;
                    if flags.is_none_or(|f| f & NAMESPACE_FLAGS != 0) {
                        self.flag("it attempted to change namespaces");
                    }
                }
                Op::Connect => {
                    if !self.allow_network {
                        self.check_connect(pid, &args);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_cache_is_cleared_again_on_the_changing_process_stop() {
        let mut tracer = Tracer {
            ops: HashMap::new(),
            cwds: HashMap::new(),
            magic_epoch: 0,
            magic_cache: HashMap::new(),
            pending_topology: HashSet::new(),
            syscall: 0,
            allow_network: false,
            rec: None,
            execs: None,
            t: Trace::default(),
        };
        tracer.topology_changed(42);
        assert_eq!(tracer.magic_epoch, 1);
        tracer.after_topology_stop(43);
        assert_eq!(tracer.magic_epoch, 1);
        tracer.after_topology_stop(42);
        assert_eq!(tracer.magic_epoch, 2);
        tracer.after_topology_stop(42);
        assert_eq!(tracer.magic_epoch, 2);
    }
}
