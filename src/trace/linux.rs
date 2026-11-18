//! Linux tracer: ptrace plus a seccomp-bpf filter.
//!
//! The filter makes the kernel stop the tracee only on the syscalls that name
//! files (open, stat, exec, rename and so on). Every other syscall runs at
//! full speed, which keeps the overhead to one stop per file touched.
//!
//! Paths are read from the tracee at syscall entry. Whether a path existed is
//! decided later, by looking at the tree after the command exits.

use super::Trace;
use crate::pathutil::absolutize;
use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStringExt;
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

#[derive(Clone, Copy)]
enum Op {
    /// open-family call; the flags argument decides read or write.
    Open {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
    },
    /// stat, access, readlink, link source: a read of the name.
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
    /// A path the call creates, removes or replaces.
    Write {
        dirfd: Option<usize>,
        path: usize,
        dir: bool,
    },
    /// Something this tracer cannot see through.
    Unsound(&'static str),
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
            vec![Write {
                dirfd: Some(0),
                path: 1,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_mkdirat),
            vec![Write {
                dirfd: Some(0),
                path: 1,
                dir: true,
            }],
        ),
        (
            s(libc::SYS_renameat2),
            vec![
                Write {
                    dirfd: Some(0),
                    path: 1,
                    dir: false,
                },
                Write {
                    dirfd: Some(2),
                    path: 3,
                    dir: false,
                },
            ],
        ),
        (
            s(libc::SYS_symlinkat),
            vec![Write {
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
                Write {
                    dirfd: Some(2),
                    path: 3,
                    dir: false,
                },
            ],
        ),
        (
            s(libc::SYS_truncate),
            vec![Write {
                dirfd: None,
                path: 0,
                dir: false,
            }],
        ),
        (s(libc::SYS_connect), vec![Connect]),
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
            vec![Write {
                dirfd: None,
                path: 0,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_mkdir),
            vec![Write {
                dirfd: None,
                path: 0,
                dir: true,
            }],
        ),
        (
            s(libc::SYS_rmdir),
            vec![Write {
                dirfd: None,
                path: 0,
                dir: false,
            }],
        ),
        (
            s(libc::SYS_rename),
            vec![
                Write {
                    dirfd: None,
                    path: 0,
                    dir: false,
                },
                Write {
                    dirfd: None,
                    path: 1,
                    dir: false,
                },
            ],
        ),
        (
            s(libc::SYS_symlink),
            vec![Write {
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
                Write {
                    dirfd: None,
                    path: 1,
                    dir: false,
                },
            ],
        ),
    ]);
    // renameat (no flags) exists on both; it takes the same argument positions.
    t.push((
        s(libc::SYS_renameat),
        vec![
            Write {
                dirfd: Some(0),
                path: 1,
                dir: false,
            },
            Write {
                dirfd: Some(2),
                path: 3,
                dir: false,
            },
        ],
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

struct Tracer {
    ops: HashMap<i64, Vec<Op>>,
    cwds: HashMap<i32, PathBuf>,
    allow_network: bool,
    t: Trace,
}

pub fn run(argv: &[String], cwd: &Path, allow_network: bool) -> io::Result<Trace> {
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
                    }
                    break;
                }
                Some(libc::EINTR) => continue,
                _ => {
                    tr.flag(&format!("tracer wait failed: {err}"));
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
        if libc::WIFEXITED(st) {
            if p == pid {
                tr.t.status = libc::WEXITSTATUS(st);
                root_finished = true;
            }
            tr.cwds.remove(&p);
            continue;
        }
        if libc::WIFSIGNALED(st) {
            if p == pid {
                tr.t.status = 128 + libc::WTERMSIG(st);
                root_finished = true;
            }
            tr.cwds.remove(&p);
            continue;
        }
        if !libc::WIFSTOPPED(st) {
            continue;
        }
        let sig = libc::WSTOPSIG(st);
        match (st >> 16) & 0xff {
            0 => {
                // A fresh tracee announces itself with SIGSTOP; swallow that one.
                let pass = if sig == libc::SIGSTOP || sig == libc::SIGTRAP {
                    0
                } else {
                    sig
                };
                cont(p, pass);
            }
            e if e == libc::PTRACE_EVENT_SECCOMP => {
                tr.on_syscall(p);
                cont(p, 0);
            }
            _ => cont(p, 0),
        }
    }
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

impl Tracer {
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
            return Some(absolutize(Path::new("/"), &p));
        }
        let base = match dirfd.map(|i| args[i] as i32) {
            None | Some(AT_FDCWD) => self.cwd(pid),
            Some(fd) => std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok(),
        };
        match base {
            Some(b) => Some(absolutize(&b, &p)),
            None => {
                self.flag("could not resolve a relative path");
                None
            }
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

    fn on_syscall(&mut self, pid: i32) {
        let Some(regs) = get_regs(pid) else {
            self.flag("could not read registers");
            return;
        };
        let (nr, args) = decode(&regs);
        let Some(ops) = self.ops.get(&nr).cloned() else {
            self.flag(
                "it ran code under a foreign syscall ABI (32-bit) that the tracer cannot follow",
            );
            return;
        };
        for op in ops {
            match op {
                Op::Open { dirfd, path, flags } => {
                    let Some(p) = self.resolve(pid, &args, dirfd, path) else {
                        continue;
                    };
                    let write = match flags {
                        None => true, // creat
                        Some(i) => {
                            let f = args[i] as i32;
                            f & (libc::O_WRONLY
                                | libc::O_RDWR
                                | libc::O_CREAT
                                | libc::O_TRUNC
                                | libc::O_APPEND)
                                != 0
                        }
                    };
                    if write {
                        self.t.written.insert(p);
                    } else {
                        self.t.touched.entry(p).or_insert(false);
                    }
                }
                Op::Look { dirfd, path } | Op::Exec { dirfd, path } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        self.t.touched.entry(p).or_insert(false);
                    }
                }
                Op::List => {
                    let fd = args[0] as i32;
                    if let Ok(p) = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
                        self.t.touched.insert(p, true);
                    }
                }
                Op::Chdir { path } => {
                    if let Some(p) = self.resolve(pid, &args, None, path) {
                        self.t.touched.entry(p).or_insert(false);
                    }
                    // Threads can share a cwd, so any chdir drops every cached value.
                    self.cwds.clear();
                }
                Op::Fchdir => self.cwds.clear(),
                Op::Write { dirfd, path, dir } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        if dir {
                            // We see the call before it runs. mkdir on a path that already
                            // exists fails with EEXIST and creates nothing: `create_dir_all`
                            // and `mkdir -p` do this for every ancestor, and recording those
                            // would turn the whole repository into "output".
                            if std::fs::symlink_metadata(&p).is_ok() {
                                continue;
                            }
                            self.t.created_dirs.push(p.clone());
                        }
                        self.t.written.insert(p);
                    }
                }
                Op::Unsound(why) => self.flag(why),
                Op::Connect => {
                    if !self.allow_network {
                        self.check_connect(pid, &args);
                    }
                }
            }
        }
    }
}
