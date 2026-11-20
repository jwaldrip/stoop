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

use super::identity::{self, ListSeen, Seen};
use super::{ExecEvent, Removal, Scope, Trace};
use crate::ignore::Ignore;
use crate::input::{file_id, hash_file, hash_file_with_oid};
use crate::oid_attrs::is_absent;
use crate::pathutil::{absolutize, to_key, without_dots, Physical};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{CString, OsString};
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
const AT_SYMLINK_FOLLOW: i32 = 0x400;
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
const MAX_EXEC_HOLD: Duration = Duration::from_secs(1);

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
    /// fstat: metadata was read through an already open descriptor.
    FdLook,
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
    /// symlink, symlinkat: a new name, and the argument that holds its target path.
    Symlink {
        dirfd: Option<usize>,
        path: usize,
        target: usize,
    },
    /// link, linkat: the existing file the new name refers to. `flags` may carry AT_EMPTY_PATH,
    /// which names that file by descriptor instead.
    LinkSource {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
    },
    /// chown, lchown, fchownat: an owner change named by path. `flags` may carry
    /// AT_SYMLINK_NOFOLLOW or AT_EMPTY_PATH; `nofollow` is set for lchown.
    Owner {
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
        nofollow: bool,
    },
    /// fchown: an owner change named by descriptor.
    OwnerFd {
        fd: usize,
    },
    /// The operation may change attribute sources without a known pathname.
    UncertainOidState,
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
        (s(libc::SYS_fstat), vec![FdLook]),
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
            vec![Symlink {
                dirfd: Some(1),
                path: 2,
                target: 0,
            }],
        ),
        (
            s(libc::SYS_linkat),
            vec![
                LinkSource {
                    dirfd: Some(0),
                    path: 1,
                    flags: Some(4),
                },
                Create {
                    dirfd: Some(2),
                    path: 3,
                    dir: false,
                },
            ],
        ),
        (s(libc::SYS_truncate), vec![Truncate { path: 0 }]),
        (s(libc::SYS_recvmsg), vec![UncertainOidState]),
        (s(libc::SYS_recvmmsg), vec![UncertainOidState]),
        (s(libc::SYS_pidfd_getfd), vec![UncertainOidState]),
        (s(libc::SYS_fchown), vec![OwnerFd { fd: 0 }]),
        (
            s(libc::SYS_fchownat),
            vec![Owner {
                dirfd: Some(0),
                path: 1,
                flags: Some(4),
                nofollow: false,
            }],
        ),
        (
            s(libc::SYS_mknodat),
            vec![Create {
                dirfd: Some(0),
                path: 1,
                dir: false,
            }],
        ),
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
            s(libc::SYS_chown),
            vec![Owner {
                dirfd: None,
                path: 0,
                flags: None,
                nofollow: false,
            }],
        ),
        (
            s(libc::SYS_lchown),
            vec![Owner {
                dirfd: None,
                path: 0,
                flags: None,
                nofollow: true,
            }],
        ),
        (
            s(libc::SYS_mknod),
            vec![Create {
                dirfd: None,
                path: 0,
                dir: false,
            }],
        ),
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
            vec![Symlink {
                dirfd: None,
                path: 1,
                target: 0,
            }],
        ),
        (
            s(libc::SYS_link),
            vec![
                LinkSource {
                    dirfd: None,
                    path: 0,
                    flags: None,
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

#[cfg(target_arch = "x86_64")]
fn syscall_result(r: &libc::user_regs_struct) -> i64 {
    r.rax as i64
}

#[cfg(target_arch = "aarch64")]
fn syscall_result(r: &libc::user_regs_struct) -> i64 {
    r.regs[0] as i64
}

type FileIdentity = (u64, u64);

/// A watched mkdir of an existing name preserves OIDs only when it fails with EEXIST.
fn deferred_mkdir_invalidates_oid(deferred: bool, result: i64) -> bool {
    deferred && result != -(libc::EEXIST as i64)
}

#[derive(Clone)]
enum WriteKind {
    Open {
        creates: bool,
        exclusive: bool,
    },
    Create {
        directory: bool,
    },
    Symlink {
        target: Option<OsString>,
    },
    Link {
        source: Option<(Option<PathBuf>, FileIdentity)>,
    },
    Remove,
    Rename {
        source: bool,
        exchange: bool,
        supported: bool,
    },
    Modify,
}

impl WriteKind {
    fn changes_entry(&self, absent: bool) -> bool {
        match self {
            Self::Open { creates, .. } => *creates && absent,
            Self::Create { .. }
            | Self::Symlink { .. }
            | Self::Link { .. }
            | Self::Remove
            | Self::Rename { .. } => true,
            Self::Modify => false,
        }
    }
}

fn removal(kind: &WriteKind) -> Option<Removal> {
    match kind {
        WriteKind::Remove => Some(Removal::Unlinked),
        WriteKind::Rename {
            source: true,
            exchange: false,
            ..
        } => Some(Removal::MovedAway),
        _ => None,
    }
}

/// A write at a name invalidates removal evidence at, above and below it.
fn forget_removals(removed: &mut BTreeMap<PathBuf, Removal>, path: &Path) {
    if removed.is_empty() {
        return;
    }
    for ancestor in path.ancestors() {
        removed.remove(ancestor);
    }
    let descendants: Vec<PathBuf> = removed
        .range(path.to_path_buf()..)
        .take_while(|(name, _)| name.starts_with(path))
        .map(|(name, _)| name.clone())
        .collect();
    for descendant in descendants {
        removed.remove(&descendant);
    }
}

/// A removed name is excluded from metadata-only inode joins only while still absent.
fn removed_and_absent(removed: &BTreeMap<PathBuf, Removal>, path: &Path) -> bool {
    removed.contains_key(path) && matches!(identity::observe(path, false), Seen::Absent)
}

struct PendingPath {
    raw: PathBuf,
    expected: Option<PathBuf>,
    follows: bool,
    key: Option<String>,
    before: Option<FileIdentity>,
    absent: bool,
    /// The name existed at a watched mkdir entry, so its OID effect depends on the exit result.
    deferred_mkdir_oid: bool,
    /// A successful namespace mutation would change this previously observed parent.
    read_parent: Option<PathBuf>,
    read_priors: Vec<PathBuf>,
    rename_before: Option<Seen>,
    confirmed_after: Option<FileIdentity>,
    kind: WriteKind,
}

struct PendingWrite {
    syscall: i64,
    paths: Vec<PendingPath>,
}

/// What priors need beyond the trace: where paths live, what is excluded, and how much
/// content has been read so far.
struct Rec<'a> {
    phys: Physical,
    ignore: &'a Ignore,
    /// The root as the user spelled it; keys in reasons are relative to it.
    root: PathBuf,
    hashed: u64,
    oid_epoch: Option<Arc<crate::oid_attrs::Epoch>>,
    link_walks: BTreeMap<PathBuf, Vec<PathBuf>>,
    redirected_reads: HashSet<String>,
    /// Bytes hashed at read stops and the debug lines printed about them.
    reads: identity::ReadBudget,
}

struct Tracer<'a> {
    ops: HashMap<i64, Vec<Op>>,
    cwds: HashMap<i32, PathBuf>,
    magic_epoch: u64,
    magic_cache: HashMap<PathBuf, (u64, bool)>,
    pending_topology: HashSet<i32>,
    /// A write may be attributed only at its matching syscall-exit stop.
    pending_writes: HashMap<i32, PendingWrite>,
    /// Actual read dependencies and the physical identities reached by successful opens.
    read_files: HashSet<PathBuf>,
    read_inodes: HashMap<FileIdentity, HashSet<PathBuf>>,
    read_routes: HashMap<PathBuf, PathBuf>,
    /// Own-removal absence looks to recheck at the next write at or below the name.
    own_absence_looks: HashSet<PathBuf>,
    written_files: HashMap<FileIdentity, HashSet<PathBuf>>,
    /// Last inode confirmed at each successfully landed destination.
    landed_inodes: HashMap<PathBuf, FileIdentity>,
    uncertain_paths: HashSet<PathBuf>,
    uncertain_inodes: HashSet<FileIdentity>,
    resolving_write: bool,
    linking: bool,
    link_source: Option<(Option<PathBuf>, FileIdentity)>,
    /// The pid whose stop is being handled.
    current: i32,
    syscall: i64,
    allow_network: bool,
    /// Present when priors are recorded (not with `--no-record`).
    rec: Option<Rec<'a>>,
    execs: Option<ExecObserver>,
    t: Trace,
}

/// What a traced call did with a path. The funnel sets the matching `Touch` bits and, when the run
/// is recorded, captures the path's read-time identity on its first look.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Use {
    /// A name the call creates, removes or renames, or a directory it only checks for. Not a look
    /// at what the path holds.
    Name,
    /// The call stats, accesses or reads the link of the path, or links from it.
    Look,
    /// The call opens the path for reading without `O_PATH`, or executes it: its bytes are read.
    Content,
    /// The call lists the directory's entries.
    List,
}

/// Every traced use of a path goes through here, and nothing else inserts into `Trace::touched`.
/// On a path's first look its read-time identity is captured. A later look checks that the path
/// still holds what it held: an absence stays absent, and a file read again is still that file.
fn observe(rec: Option<&mut Rec<'_>>, t: &mut Trace, lex: PathBuf, how: Use) {
    {
        let touch = t.touched.entry(lex.clone()).or_default();
        match how {
            Use::Name => {}
            Use::Look => touch.read = true,
            Use::Content => {
                touch.read = true;
                touch.content = true;
            }
            Use::List => touch.listed = true,
        }
    }
    let Some(rec) = rec else { return };
    // A proc magic link resolves in the tracer's namespace, so it is never followed here. Dynamic
    // files (proc, sys, dev) describe the process reading them, so their bytes are never hashed.
    let resolve = !lex.starts_with("/proc");
    let hash = !is_dynamic(&lex);
    let now = identity::now_ns();
    let rechecked = matches!(how, Use::Look | Use::Content);
    let Some(seen) = t.seen.as_mut() else { return };
    let mut changed = false;
    match seen.get_mut(&lex) {
        None => {
            let mut fresh = identity::observe(&lex, resolve);
            if how == Use::Content && hash {
                rec.read_hash(&mut fresh, &lex, now);
            }
            seen.insert(lex.clone(), fresh);
        }
        Some(Seen::Absent) => {
            // Name-only observations are write bookkeeping, not another lookup by the command.
            changed = rechecked && !matches!(identity::observe(&lex, resolve), Seen::Absent);
        }
        Some(before) if rechecked && !matches!(before, Seen::Dir(_)) => {
            if identity::same_identity(before, &identity::observe(&lex, resolve)) {
                if how == Use::Content && hash {
                    rec.read_hash(before, &lex, now);
                }
            } else {
                changed = true;
            }
        }
        Some(_) => {}
    }
    if changed {
        push_changed(t, &lex);
    }
}

/// Record that `path` changed while the command was running, once.
fn push_changed(t: &mut Trace, path: &Path) {
    t.changed_during.insert(path.to_path_buf());
}

/// Resolve the destination without `Physical`'s cache, including every expanded symlink hop.
/// An absent final name is allowed; an absent parent or an unreadable route is not.
fn write_destination(raw: &Path, follows: bool) -> Option<PathBuf> {
    use std::collections::VecDeque;

    if !raw.is_absolute() {
        return None;
    }
    let mut parts: VecDeque<OsString> = raw
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty() && *part != b".")
        .map(|part| OsString::from_vec(part.to_vec()))
        .collect();
    let mut current = PathBuf::from("/");
    let mut links = 0;
    while let Some(part) = parts.pop_front() {
        if part.as_bytes() == b".." {
            current.pop();
            continue;
        }
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() && (follows || !parts.is_empty()) => {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = fs::read_link(&current).ok()?;
                current.pop();
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                for component in target
                    .as_os_str()
                    .as_bytes()
                    .split(|byte| *byte == b'/')
                    .filter(|part| !part.is_empty() && *part != b".")
                    .rev()
                {
                    parts.push_front(OsString::from_vec(component.to_vec()));
                }
            }
            Ok(metadata) if !parts.is_empty() && !metadata.is_dir() => return None,
            Ok(_) => {}
            Err(error) if is_absent(&error) && parts.is_empty() => return Some(current),
            Err(_) => return None,
        }
    }
    Some(current)
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    (metadata.dev(), metadata.ino())
}

/// The returned descriptor must identify both the expected physical name and object.
fn verified_open(
    expected: Option<&Path>,
    actual: Option<&Path>,
    before: Option<FileIdentity>,
    after: Option<FileIdentity>,
    may_have_created: bool,
) -> bool {
    expected.is_some()
        && expected == actual
        && after.is_some()
        && (before.is_some_and(|id| after == Some(id)) || (before.is_none() && may_have_created))
}

fn same_rename_stat(before: &identity::FileStat, after: &identity::FileStat) -> bool {
    (
        before.dev,
        before.ino,
        before.size,
        before.mode,
        before.mtime_ns,
    ) == (after.dev, after.ino, after.size, after.mode, after.mtime_ns)
}

fn verified_rename_snapshot(before: &identity::FileSeen, after: &identity::FileSeen) -> bool {
    same_rename_stat(&before.stat, &after.stat)
        && matches!(
            (&before.read_hash, &after.read_hash),
            (identity::ReadHash::Hashed(a), identity::ReadHash::Hashed(b)) if a == b
        )
}

/// The path-only checks detect persistent alias retargets and inconsistent post-state. They cannot
/// rule out a foreign retarget and restoration during the syscall because it returns no descriptor.
fn verified_path_mutation(path: &PendingPath, all: &[PendingPath]) -> Option<Option<FileIdentity>> {
    let expected = path.expected.as_deref()?;
    if write_destination(&path.raw, path.follows).as_deref() != Some(expected) {
        return None;
    }
    let after = fs::symlink_metadata(expected);
    let after_id = after.as_ref().ok().map(file_identity);
    let verified = match &path.kind {
        WriteKind::Create { directory } => {
            path.absent && after.as_ref().is_ok_and(|m| m.is_dir() == *directory)
        }
        WriteKind::Symlink { target } => {
            path.absent
                && after.as_ref().is_ok_and(|m| m.file_type().is_symlink())
                && target.as_ref().is_some_and(|target| {
                    fs::read_link(expected)
                        .is_ok_and(|actual| actual.as_os_str() == target.as_os_str())
                })
        }
        WriteKind::Link { source } => {
            path.absent
                && source
                    .as_ref()
                    .is_some_and(|(_, id)| after.as_ref().is_ok_and(|m| file_identity(m) == *id))
        }
        WriteKind::Remove => {
            path.before.is_some()
                && match after {
                    Err(error) => is_absent(&error),
                    Ok(metadata) => Some(file_identity(&metadata)) != path.before,
                }
        }
        WriteKind::Rename {
            source,
            exchange,
            supported,
        } => {
            if !*supported {
                return None;
            }
            let other = all.iter().find(|candidate| {
                matches!(&candidate.kind, WriteKind::Rename { source: side, exchange: other_exchange, supported: true }
                    if side != source && other_exchange == exchange)
            });
            let other = other?;
            let other_path = other.expected.as_deref()?;
            if write_destination(&other.raw, other.follows).as_deref() != Some(other_path) {
                return None;
            }
            let (from, to, from_after, to_after) = if *source {
                (path, other, after, fs::symlink_metadata(other_path))
            } else {
                (other, path, fs::symlink_metadata(other_path), after)
            };
            let from_id = from.before?;
            let destination_matches = to_after.as_ref().is_ok_and(|m| file_identity(m) == from_id);
            let source_matches = if *exchange {
                to.before
                    .is_some_and(|id| from_after.as_ref().is_ok_and(|m| file_identity(m) == id))
            } else {
                match from_after {
                    Err(error) => is_absent(&error),
                    Ok(metadata) => file_identity(&metadata) != from_id,
                }
            };
            destination_matches && source_matches
        }
        WriteKind::Modify => path.before.is_some_and(|before| {
            after
                .as_ref()
                .is_ok_and(|metadata| file_identity(metadata) == before)
        }),
        WriteKind::Open { .. } => false,
    };
    if !verified {
        return None;
    }
    // A successful remove or rename source does not create the object now at that name.
    let removed = removal(&path.kind).is_some();
    Some(if removed { None } else { after_id })
}

/// Names that describe the process reading them (proc, sys and dev). They are never resolved here
/// and their contents are never hashed.
fn is_dynamic(path: &Path) -> bool {
    ["/proc", "/sys", "/dev"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

impl Rec<'_> {
    /// A content read of `lex`: a racy file is hashed now, with a debug line under `STOOP_DEBUG`.
    fn read_hash(&mut self, seen: &mut Seen, lex: &Path, now: i128) {
        let hashed = identity::hash_racy_at_read(seen, lex, now, &mut self.reads);
        if hashed && self.reads.logged < 32 && std::env::var_os("STOOP_DEBUG").is_some() {
            self.reads.logged += 1;
            eprintln!("stoop: debug: hashed {} at the read", self.key_text(lex));
        }
    }
}

pub fn run<'a>(
    argv: &[std::ffi::OsString],
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
            CString::new(a.as_encoded_bytes())
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
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
        pending_writes: HashMap::new(),
        read_files: HashSet::new(),
        read_inodes: HashMap::new(),
        read_routes: HashMap::new(),
        own_absence_looks: HashSet::new(),
        written_files: HashMap::new(),
        landed_inodes: HashMap::new(),
        uncertain_paths: HashSet::new(),
        uncertain_inodes: HashSet::new(),
        resolving_write: false,
        linking: false,
        link_source: None,
        current: 0,
        syscall: 0,
        execs: observe_execs.then(|| ExecObserver::new(pid)),
        rec: scope.map(|s| Rec {
            phys: Physical::new(s.root, &s.real_root),
            ignore: s.ignore,
            root: s.root.to_path_buf(),
            oid_epoch: s.oid_epoch.clone(),
            hashed: 0,
            link_walks: BTreeMap::new(),
            redirected_reads: HashSet::new(),
            reads: identity::ReadBudget::default(),
        }),
        t: Trace {
            status: 1,
            oid_epoch: scope.and_then(|s| s.oid_epoch.clone()),
            seen: scope.map(|_| HashMap::new()),
            #[cfg(test)]
            oid_epoch_captured: scope.is_some(),
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
    tr.inspect_inherited_fds(pid);
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
        // A missing parent notification must not leave a child stopped forever.
        // Poll only while a child is held, and discard the diagnostic on expiry.
        let remaining = tr
            .execs
            .as_ref()
            .and_then(|execs| execs.hold_remaining(Instant::now()));
        if remaining.is_some_and(|duration| duration.is_zero()) {
            if let Some(execs) = &mut tr.execs {
                execs.invalidate();
            }
        }
        let polling = remaining.is_some_and(|duration| !duration.is_zero());
        let options = libc::__WALL | if polling { libc::WNOHANG } else { 0 };
        let p = unsafe { libc::waitpid(-1, &mut st, options) };
        if p == 0 {
            if let Some(remaining) = remaining {
                std::thread::sleep(remaining.min(Duration::from_millis(1)));
            }
            continue;
        }
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
        // A write gets an additional syscall-exit stop before it can be attributed.
        let syscall_exit = libc::WIFSTOPPED(st) && libc::WSTOPSIG(st) == (libc::SIGTRAP | 0x80);
        tr.current = p;
        if syscall_exit {
            tr.after_topology_stop(p);
            tr.complete_write(p);
        } else if libc::WIFEXITED(st) || libc::WIFSIGNALED(st) {
            tr.after_topology_stop(p);
            tr.discard_write(p);
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
                // A child can report its initial stop before waitpid delivers its
                // parent's fork event. Hold that already-stopped child until its
                // inherited image is known; it has not executed user code yet.
                if sig == libc::SIGSTOP
                    && tr
                        .execs
                        .as_mut()
                        .is_some_and(|execs| execs.defer(p, Instant::now()))
                {
                    continue;
                }
                // A fresh tracee announces itself with SIGSTOP; swallow that one.
                let pass = if sig == libc::SIGSTOP || sig == libc::SIGTRAP || syscall_exit {
                    0
                } else {
                    sig
                };
                resume(
                    p,
                    pass,
                    tr.pending_topology.contains(&p) || tr.pending_writes.contains_key(&p),
                );
            }
            e if e == libc::PTRACE_EVENT_SECCOMP => {
                tr.on_syscall(p);
                resume(
                    p,
                    0,
                    tr.pending_topology.contains(&p) || tr.pending_writes.contains_key(&p),
                );
            }
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                if let Some(execs) = &mut tr.execs {
                    execs.fork(p);
                }
                resume(p, 0, tr.pending_writes.contains_key(&p));
            }
            e if e == libc::PTRACE_EVENT_EXEC => {
                if let Some(former) = event_message(p) {
                    tr.discard_write(former);
                }
                tr.discard_write(p);
                if let Some(execs) = &mut tr.execs {
                    execs.exec(p);
                }
                cont(p, 0);
            }
            _ => resume(p, 0, tr.pending_writes.contains_key(&p)),
        }
    }
    if !tr.pending_writes.is_empty() {
        tr.flag("it lost the exit stop of a pending write");
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
    deferred: HashMap<i32, Instant>,
    events: Vec<ExecEvent>,
    valid: bool,
    collecting: bool,
}

impl ExecObserver {
    fn new(root: i32) -> Self {
        Self {
            tasks: HashMap::from([(root, None)]),
            deferred: HashMap::new(),
            pending: HashMap::new(),
            events: Vec::new(),
            valid: true,
            collecting: true,
        }
    }

    fn stop_collecting(&mut self) {
        self.collecting = false;
        self.tasks.clear();
        self.pending.clear();
        // Never leave a tracee stopped solely for diagnostic collection.
        for (pid, _) in self.deferred.drain() {
            cont(pid, 0);
        }
    }

    fn invalidate(&mut self) {
        self.stop_collecting();
        self.valid = false;
        self.events.clear();
    }

    fn defer(&mut self, pid: i32, now: Instant) -> bool {
        if !self.collecting || self.tasks.contains_key(&pid) {
            return false;
        }
        if self.deferred.len() >= MAX_EXEC_TASKS {
            self.stop_collecting();
            return false;
        }
        self.deferred.entry(pid).or_insert(now);
        true
    }

    fn hold_remaining(&self, now: Instant) -> Option<Duration> {
        self.deferred
            .values()
            .min()
            .map(|oldest| MAX_EXEC_HOLD.saturating_sub(now.saturating_duration_since(*oldest)))
    }

    fn enter(&mut self, pid: i32, nr: i64, args: &[u64; 6]) {
        if !self.collecting {
            return;
        }
        if !self.tasks.contains_key(&pid) {
            self.stop_collecting();
            return;
        }
        let (path, argv) = if nr == libc::SYS_execve {
            (args[0], args[1])
        } else {
            (args[1], args[2])
        };
        let raw_path = if path == 0 {
            Some(Vec::new())
        } else {
            read_cstr(pid, path)
        };
        let candidate = raw_path.and_then(|path| {
            let requested = if nr == libc::SYS_execveat
                && args[4] as i32 & AT_EMPTY_PATH != 0
                && path.is_empty()
            {
                fs::read_link(format!("/proc/{pid}/fd/{}", args[0] as i32)).ok()?
            } else {
                PathBuf::from(OsString::from_vec(path))
            };
            read_exec_argv(pid, argv).map(|argv| PendingExec { requested, argv })
        });
        // A failed PATH lookup never gets an exec event. Only the candidate associated
        // with a successful PTRACE_EVENT_EXEC is promoted into the observation.
        self.pending.insert(pid, candidate);
    }

    fn fork(&mut self, parent: i32) {
        if !self.collecting {
            return;
        }
        let Some(child) = event_message(parent) else {
            self.stop_collecting();
            return;
        };
        if self.register_child(parent, child) {
            cont(child, 0);
        }
    }

    // Returns whether this child stopped before the fork event and must now resume.
    fn register_child(&mut self, parent: i32, child: i32) -> bool {
        let Some(image) = self.tasks.get(&parent).copied() else {
            self.stop_collecting();
            return false;
        };
        if self.tasks.len() >= MAX_EXEC_TASKS {
            self.stop_collecting();
            return false;
        }
        self.tasks.insert(child, image);
        self.pending.remove(&child);
        self.deferred.remove(&child).is_some()
    }

    fn exec(&mut self, pid: i32) {
        if !self.collecting {
            return;
        }
        // A non-leader thread takes the leader's TID at exec. Linux reports its former
        // TID in the event message, which identifies the pending entry and ancestry.
        let Some(former) = event_message(pid) else {
            self.stop_collecting();
            return;
        };
        let Some(parent) = self.tasks.remove(&former) else {
            self.stop_collecting();
            return;
        };
        let Some(Some(pending)) = self.pending.remove(&former) else {
            self.stop_collecting();
            return;
        };
        if former != pid {
            self.tasks.remove(&pid);
            self.pending.remove(&pid);
        }
        let Some((executable, effective_argv, cwd)) = exec_image(pid) else {
            self.stop_collecting();
            return;
        };
        if !self.reserve_event() {
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

    fn reserve_event(&mut self) -> bool {
        if self.events.len() >= MAX_EXEC_EVENTS {
            self.stop_collecting();
            return false;
        }
        true
    }

    fn exit(&mut self, pid: i32) {
        self.tasks.remove(&pid);
        self.pending.remove(&pid);
        self.deferred.remove(&pid);
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
    let mut mem = None;
    for raw in pointers.as_chunks::<8>().0.iter().take(MAX_EXEC_ARGS + 1) {
        let pointer = u64::from_ne_bytes(*raw);
        if pointer == 0 {
            return Some(argv);
        }
        if argv.len() == MAX_EXEC_ARGS {
            return None;
        }
        let arg = read_exec_arg(
            pid,
            pointer,
            MAX_EXEC_ARG_BYTES.checked_sub(bytes)?,
            &mut mem,
        )?;
        bytes += arg.len() + 1;
        argv.push(OsString::from_vec(arg));
    }
    None
}

// Read short arguments into a stack buffer instead of allocating and copying the
// entire remaining argv budget for each one.
fn read_exec_arg(
    pid: i32,
    mut address: u64,
    mut remaining: usize,
    mem: &mut Option<fs::File>,
) -> Option<Vec<u8>> {
    use std::os::unix::fs::FileExt;

    let mut arg = Vec::new();
    let mut buffer = [0u8; 256];
    while remaining > 0 {
        let len = remaining.min(buffer.len());
        let local = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: len,
        };
        let remote = libc::iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: len,
        };
        let result = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
        let n = if result > 0 {
            result as usize
        } else {
            if mem.is_none() {
                *mem = Some(fs::File::open(format!("/proc/{pid}/mem")).ok()?);
            }
            mem.as_ref()?.read_at(&mut buffer[..len], address).ok()?
        };
        if n == 0 {
            return None;
        }
        if let Some(end) = buffer[..n].iter().position(|byte| *byte == 0) {
            arg.extend_from_slice(&buffer[..end]);
            return Some(arg);
        }
        arg.extend_from_slice(&buffer[..n]);
        remaining -= n;
        address = address.checked_add(n as u64)?;
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
    /// Whether a write, a namespace change or an owner change at `raw` can change what Git reads
    /// for attributes or configuration. The watched set names those files (see `oid_attrs`), so
    /// writes to other paths keep the run's blob ids. Inside the repository, the git directory
    /// counts by the same names, and a file with a second name, an attribute file or a nested
    /// `.git` counts too. Physical paths that cannot be placed count.
    fn invalidates_oids(&mut self, raw: &Path, follows: bool) -> bool {
        let Some(epoch) = self.oid_epoch.clone() else {
            return false;
        };
        let link_meta = fs::symlink_metadata(raw);
        let metadata = if follows {
            fs::metadata(raw)
        } else {
            fs::symlink_metadata(raw)
        };
        if metadata.as_ref().is_err_and(|e| !is_absent(e)) {
            return true;
        }
        if metadata.as_ref().is_ok_and(|m| {
            let kind = m.file_type();
            kind.is_char_device() || kind.is_block_device() || kind.is_fifo() || kind.is_socket()
        }) {
            return false;
        }
        let physical = if follows && link_meta.as_ref().is_ok_and(|m| m.file_type().is_symlink()) {
            fs::canonicalize(raw).ok()
        } else {
            self.phys.locate(raw).map(|location| location.path)
        };
        let Some(physical) = physical else {
            return true;
        };
        let watched = epoch.watch.names_contain(&physical)
            || metadata
                .as_ref()
                .is_ok_and(|m| epoch.watch.is_watched_file(m));
        if !physical.starts_with(self.phys.real()) {
            return watched;
        }
        if physical.starts_with(&epoch.git_dir) || physical.starts_with(&epoch.common_dir) {
            return watched;
        }
        watched
            || physical
                .file_name()
                .is_some_and(|name| name == ".gitattributes")
            || physical
                .components()
                .any(|component| component.as_os_str() == ".git")
            // An attribute file or a config file may share an inode with another name.
            || metadata.is_ok_and(|m| m.is_file() && m.nlink() > 1)
    }

    /// Whether the name `raw` lies in the repository, or cannot be placed at all.
    fn in_repo(&mut self, raw: &Path) -> bool {
        let real = self.phys.real().to_path_buf();
        self.phys
            .locate(raw)
            .is_none_or(|location| location.path.starts_with(&real))
    }

    /// Whether the name `raw` is a watched name, or cannot be placed at all.
    fn watched_name(&mut self, raw: &Path) -> bool {
        let Some(epoch) = self.oid_epoch.clone() else {
            return false;
        };
        self.phys
            .locate(raw)
            .is_none_or(|location| epoch.watch.names_contain(&location.path))
    }

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

    /// Capture the prior at entry; the caller adds the output key only after a verified exit.
    fn write(&mut self, t: &mut Trace, raw: &Path, destination: &Path) -> Option<String> {
        let lex = absolutize(Path::new("/"), raw);
        self.forget_walks(&lex);
        self.forget_walks(raw);
        self.phys.forget(&lex);
        self.phys.forget(raw);
        self.forget_walks(destination);
        self.phys.forget(destination);
        let key = self.key_of(destination, t)?;
        if fs::symlink_metadata(raw).is_ok_and(|m| m.file_type().is_symlink()) {
            push_reason(
                t,
                format!("it wrote through the symlink {}", self.key_text(&lex)),
            );
        }
        for link in self.links_below_root(raw).unwrap_or_default() {
            let name = to_key(self.phys.real(), &link);
            observe(Some(&mut *self), t, link, Use::Name);
            push_reason(t, format!("it wrote through the symlink {name}"));
        }
        if !t.priors.contains_key(&key) {
            self.parent_prior(t, destination);
            if let Some(id) = self.prior_id(t, destination, &key) {
                t.priors.insert(key.clone(), id);
            }
        }
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
        let basis = (!t.oid_attrs_changed)
            .then(|| {
                self.oid_epoch
                    .as_ref()
                    .and_then(|epoch| epoch.basis.get(key))
            })
            .flatten()
            .cloned();
        let hash = if basis.as_ref().is_some_and(|basis| basis.allows_oid()) {
            hash_file_with_oid(phys)
        } else {
            hash_file(phys).map(|hash| (hash, None))
        };
        match hash {
            Ok((h, oid)) => {
                if let Some(basis) = basis {
                    if let Some(oid) = oid {
                        t.prior_oids.insert(key.to_owned(), oid);
                    }
                    t.prior_oid_bases.insert(key.to_owned(), basis);
                }
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
    /// A tracee can write through an inherited descriptor without opening a path
    /// under ptrace. Inspect writable regular descriptors before its first exec.
    fn inspect_inherited_fds(&mut self, pid: i32) {
        let Some(rec) = self.rec.as_mut().filter(|rec| rec.oid_epoch.is_some()) else {
            return;
        };
        let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
            self.t.oid_attrs_changed = true;
            return;
        };
        for entry in entries {
            let Ok(entry) = entry else {
                self.t.oid_attrs_changed = true;
                return;
            };
            let Ok(metadata) = fs::metadata(entry.path()) else {
                self.t.oid_attrs_changed = true;
                return;
            };
            if !metadata.is_file() {
                continue;
            }
            let info = PathBuf::from(format!("/proc/{pid}/fdinfo")).join(entry.file_name());
            let flags = fs::read_to_string(info).ok().and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("flags:"))
                    .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
            });
            let Some(flags) = flags else {
                self.t.oid_attrs_changed = true;
                return;
            };
            if flags & libc::O_ACCMODE as u32 == libc::O_RDONLY as u32
                || flags & libc::O_CLOEXEC as u32 != 0
            {
                continue;
            }
            let Ok(path) = fs::read_link(entry.path()) else {
                self.t.oid_attrs_changed = true;
                return;
            };
            // The descriptor's identity counts even when its name is gone: a hard link may have
            // given the watched file a name outside the watched set.
            let watched = rec
                .oid_epoch
                .as_ref()
                .is_some_and(|epoch| epoch.watch.is_watched_file(&metadata));
            if !path.is_absolute() || watched || rec.invalidates_oids(&path, true) {
                self.t.oid_attrs_changed = true;
                return;
            }
        }
    }

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
                if self.rec.is_some() {
                    self.t.oid_attrs_changed = true;
                }
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
        let link_use = if self.resolving_write {
            Use::Name
        } else {
            Use::Look
        };
        for link in repository_links.clone() {
            self.observe(link, link_use);
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
            self.observe(current.clone(), link_use);
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

    /// A metadata look is bookkeeping only for the inode last confirmed at this exact destination.
    /// A foreign process can still change that inode's metadata between the write and the look;
    /// this is the accepted v9 parity gap, not a guarantee about the observed metadata.
    fn own_output_metadata(&self, physical: &Path, inode: Option<FileIdentity>) -> bool {
        let Some(id) = inode else { return false };
        self.t.landed.contains(physical)
            && self.landed_inodes.get(physical) == Some(&id)
            && !self.uncertain_paths.contains(physical)
            && !self.uncertain_inodes.contains(&id)
            && !self.pending_writes.values().any(|pending| {
                pending.paths.iter().any(|path| {
                    path.expected.is_none()
                        || path.expected.as_deref() == Some(physical)
                        || path.before == Some(id)
                        || matches!(&path.kind, WriteKind::Link { source: Some((_, source)), .. } if *source == id)
                })
            })
    }

    /// Read/write ordering is tracked separately from the synthetic observations used to
    /// describe a write's link route. Inode identity also joins distinct hard-link names.
    fn note_real_read(&mut self, raw: &Path, how: Use) -> bool {
        if self.rec.is_none() || is_dynamic(raw) {
            return true;
        }
        let Some(physical) = write_destination(raw, true) else {
            return true;
        };
        let metadata = fs::metadata(raw).ok();
        if metadata.as_ref().is_some_and(|m| {
            let kind = m.file_type();
            kind.is_char_device() || kind.is_block_device() || kind.is_fifo() || kind.is_socket()
        }) {
            return true;
        }
        let new_route = if let Some(first) = self.read_routes.get(raw) {
            if first != &physical {
                let first = first.clone();
                push_changed(&mut self.t, &first);
                push_changed(&mut self.t, &physical);
            }
            false
        } else {
            true
        };
        let inode = metadata.as_ref().map(file_identity);
        if how == Use::Look
            && self.own_output_metadata(&physical, inode)
            && fs::symlink_metadata(raw).is_ok_and(|m| !m.file_type().is_symlink())
        {
            return false;
        }
        // Unlike a content read of an output, a metadata look at a verified removed name can
        // depend on its original absence. Keep that absence as an input and check it again later.
        if how == Use::Look
            && self.t.removed_by_run.contains_key(&physical)
            && matches!(identity::observe(raw, false), Seen::Absent)
            && (physical == raw || matches!(identity::observe(&physical, false), Seen::Absent))
            && !self.pending_writes.values().any(|pending| {
                pending.paths.iter().any(|path| {
                    path.expected.as_deref().is_none_or(|destination| {
                        destination.starts_with(&physical) || physical.starts_with(destination)
                    })
                })
            })
            && !self.t.read_write_conflicts.contains(&physical)
            && [raw, physical.as_path()].into_iter().all(|name| {
                !self.t.touched.get(name).is_some_and(|touch| touch.content)
                    || (self.t.read_before_write.contains(&physical)
                        && self
                            .t
                            .seen
                            .as_ref()
                            .and_then(|seen| seen.get(name))
                            .is_some_and(|seen| matches!(seen, Seen::Absent)))
            })
            && self
                .rec
                .as_ref()
                .and_then(|rec| rec.key_of(&physical, &mut self.t))
                .is_some_and(|key| self.t.priors.get(&key).map(String::as_str) == Some("a"))
        {
            self.t.read_before_write.insert(physical.clone());
            self.t.absent_after_removal.insert(physical.clone());
            self.own_absence_looks.insert(physical);
            return false;
        }
        if new_route {
            self.read_routes.insert(raw.to_path_buf(), physical.clone());
        }
        let already_written = self.t.landed.contains(&physical)
            || self.uncertain_paths.contains(&physical)
            || inode.is_some_and(|id| {
                self.written_files.contains_key(&id) || self.uncertain_inodes.contains(&id)
            })
            || self.pending_writes.values().any(|pending| {
                pending.paths.iter().any(|path| {
                    path.expected.as_ref() == Some(&physical)
                        || inode.is_some_and(|id| path.before == Some(id))
                })
            });
        if already_written {
            self.t.read_write_conflicts.insert(physical.clone());
            if let Some(written) = inode.and_then(|id| self.written_files.get(&id)) {
                let removed = &self.t.removed_by_run;
                self.t.read_write_conflicts.extend(
                    written
                        .iter()
                        .filter(|path| how != Use::Look || !removed_and_absent(removed, path))
                        .cloned(),
                );
            }
            for pending in self.pending_writes.values() {
                for path in &pending.paths {
                    if path.expected.as_ref() == Some(&physical)
                        || inode.is_some_and(|id| path.before == Some(id))
                    {
                        if let Some(destination) = &path.expected {
                            self.t.read_write_conflicts.insert(destination.clone());
                        }
                    }
                }
            }
        }
        self.read_files.insert(physical.clone());
        if let Some(id) = inode {
            self.read_inodes
                .entry(id)
                .or_default()
                .insert(physical.clone());
        }
        if physical != raw {
            observe(self.rec.as_mut(), &mut self.t, raw.to_path_buf(), how);
            observe(self.rec.as_mut(), &mut self.t, physical, how);
        }
        true
    }

    fn observe_fd_look(&mut self, pid: i32, fd: i32) {
        if self.rec.is_none() {
            return;
        }
        let fd_path = format!("/proc/{pid}/fd/{fd}");
        let path = if fd == AT_FDCWD {
            self.cwd(pid)
        } else {
            fs::read_link(&fd_path).ok()
        };
        let Some(path) = path.filter(|path| path.is_absolute()) else {
            return;
        };
        let metadata = if fd == AT_FDCWD {
            fs::metadata(&path).ok()
        } else {
            fs::metadata(&fd_path).ok()
        };
        let inode = metadata.as_ref().map(file_identity);
        if !path.as_os_str().as_bytes().ends_with(b" (deleted)")
            && inode.is_some_and(|id| self.written_files.contains_key(&id))
            && fs::metadata(&path).ok().as_ref().map(file_identity) == inode
            && write_destination(&path, true)
                .is_some_and(|physical| self.own_output_metadata(&physical, inode))
        {
            return;
        }
        if let Some(written) = inode.and_then(|id| self.written_files.get(&id)) {
            let removed = &self.t.removed_by_run;
            self.t.read_write_conflicts.extend(
                written
                    .iter()
                    .filter(|path| !removed_and_absent(removed, path))
                    .cloned(),
            );
        }
        for pending in self.pending_writes.values() {
            for pending_path in &pending.paths {
                if inode.is_some_and(|id| pending_path.before == Some(id)) {
                    if let Some(destination) = &pending_path.expected {
                        self.t.read_write_conflicts.insert(destination.clone());
                    }
                }
            }
        }
        let bytes = path.as_os_str().as_bytes();
        if let Some(name) = bytes.strip_suffix(b" (deleted)") {
            let physical = PathBuf::from(OsString::from_vec(name.to_vec()));
            // The descriptor still names an inode even after its last pathname was removed.
            if self.t.landed.contains(&physical)
                || inode.is_some_and(|id| {
                    self.written_files.contains_key(&id) || self.uncertain_inodes.contains(&id)
                })
            {
                self.t.read_write_conflicts.insert(physical);
            } else if self
                .rec
                .as_ref()
                .and_then(|rec| rec.key_of(&physical, &mut self.t))
                .is_some()
            {
                self.flag("it looked at a deleted file descriptor");
            }
        } else {
            if inode.is_some() && fs::metadata(&path).ok().as_ref().map(file_identity) != inode {
                push_changed(&mut self.t, &path);
            }
            self.touch(path, Use::Look);
        }
    }

    fn touch(&mut self, lex: PathBuf, how: Use) {
        let observed = if matches!(how, Use::Look | Use::Content) && !self.note_real_read(&lex, how)
        {
            Use::Name
        } else {
            how
        };
        let mut path = lex;
        if let Some(rec) = &mut self.rec {
            for link in rec.links_below_root(&path).unwrap_or_default() {
                let link_use = if how == Use::Name {
                    Use::Name
                } else {
                    Use::Look
                };
                observe(Some(&mut *rec), &mut self.t, link, link_use);
            }
            // Record observations where the call resolved them, not after the run.
            if let Some(loc) = rec.phys.locate(&path) {
                if loc.path != path && rec.phys.repo_rel(&loc.path).is_some() {
                    if how != Use::Name && loc.redirected {
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
        observe(self.rec.as_mut(), &mut self.t, path, observed);
    }

    /// Record a use of `lex` through the funnel.
    fn observe(&mut self, lex: PathBuf, how: Use) {
        observe(self.rec.as_mut(), &mut self.t, lex, how);
    }

    /// `getdents` on a directory: the run lists it, so its entries are pinned as they are now.
    fn observe_list(&mut self, dir: PathBuf) {
        observe(self.rec.as_mut(), &mut self.t, dir.clone(), Use::List);
        if self.rec.is_none() || self.t.listings.contains_key(&dir) {
            return;
        }
        let Ok(metadata) = fs::symlink_metadata(&dir) else {
            return;
        };
        if !metadata.is_dir() {
            return;
        }
        let stat = identity::dir_stat(&metadata);
        let names = if identity::racy(stat.mtime_ns, stat.ctime_ns, identity::now_ns()) {
            self.read_listing(&dir)
        } else {
            None
        };
        self.t.listings.insert(dir, ListSeen { stat, names });
    }

    /// The names of a listed directory, counted against the run's cap. A directory that cannot be
    /// read, or a run past the cap, refuses the record.
    fn read_listing(&mut self, dir: &Path) -> Option<identity::Names> {
        let remaining = identity::MAX_LISTED_NAMES.saturating_sub(self.t.listed_names);
        match identity::read_names_capped(dir, remaining) {
            identity::NameSnapshot::Names { names, entries } => {
                self.t.listed_names += entries;
                Some(names)
            }
            identity::NameSnapshot::OverCap => {
                self.flag(&format!(
                    "it listed more than {} directory entries",
                    identity::MAX_LISTED_NAMES
                ));
                None
            }
            identity::NameSnapshot::Unreadable => {
                let key = self
                    .rec
                    .as_ref()
                    .map(|rec| rec.key_text(dir))
                    .unwrap_or_default();
                self.flag(&format!("could not read the entries of {key}"));
                None
            }
        }
    }

    /// Before the run's first change to a listed directory, pin what the listing showed. A directory
    /// whose stat moved since the listing changed while the command ran. Otherwise its names are read
    /// now, before the change, so the run's own change can be told apart from anything else.
    fn pin_listing(&mut self, dir: &Path) {
        let Some(listing) = self.t.listings.get(dir) else {
            return;
        };
        if listing.names.is_some() {
            return;
        }
        let listed = listing.stat;
        let moved = match fs::symlink_metadata(dir) {
            Ok(metadata) => identity::dir_stat(&metadata) != listed,
            Err(_) => true,
        };
        if moved {
            push_changed(&mut self.t, dir);
            return;
        }
        if let Some(names) = self.read_listing(dir) {
            if let Some(listing) = self.t.listings.get_mut(dir) {
                listing.names = Some(names);
            }
        }
    }

    /// A change the run makes to a directory itself (chmod, chown): pin its listing first.
    fn note_listed_change(&mut self, path: &Path) {
        let Some(rec) = self.rec.as_mut() else {
            return;
        };
        let Some(loc) = rec.phys.locate(path) else {
            return;
        };
        self.pin_listing(&loc.path);
    }

    /// Pin a listing before a possible namespace mutation. Ownership is decided at exit.
    fn note_entry_change(&mut self, entry: &Path) {
        if let Some(dir) = entry.parent() {
            self.pin_listing(dir);
        }
    }

    fn mark_entry_change(&mut self, entry: &Path) {
        if let (Some(dir), Some(name)) = (entry.parent(), entry.file_name()) {
            self.t
                .own_names
                .entry(dir.to_path_buf())
                .or_default()
                .insert(name.as_encoded_bytes().into());
        }
    }

    /// The kernel loads shebang and ELF interpreters without a traceable open syscall.
    fn exec_path(&mut self, pid: i32, mut path: PathBuf) {
        use std::io::Read;
        if self.rec.is_none() {
            return;
        }
        // Linux permits at most four recursive script interpreters.
        for _ in 0..=4 {
            self.touch(path.clone(), Use::Content);
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
                        self.touch(interpreter, Use::Content);
                    }
                }
                Ok(None) => {}
                Err(_) => self.flag("could not inspect an ELF interpreter"),
            }
            return;
        }
    }
    /// Compare a prior real read at the first write stop. Hard-link aliases are not equivalent:
    /// an outside writer can restore one after our write and make both prior and output match.
    fn capture_read_prior(
        &mut self,
        destination: &Path,
        before: Option<FileIdentity>,
    ) -> Vec<PathBuf> {
        if let Some(reads) = before.and_then(|id| self.read_inodes.get(&id)) {
            for read in reads.iter().filter(|read| read.as_path() != destination) {
                self.t.read_write_conflicts.insert(read.clone());
                self.t
                    .read_write_conflicts
                    .insert(destination.to_path_buf());
            }
        }
        if !self.read_files.contains(destination) || self.t.read_before_write.contains(destination)
        {
            return Vec::new();
        }
        let in_flight = self.pending_writes.values().any(|pending| {
            pending.paths.iter().any(|path| {
                path.expected.as_deref() == Some(destination)
                    || before.is_some_and(|id| path.before == Some(id))
            })
        });
        if in_flight
            || self.t.landed.contains(destination)
            || before.is_some_and(|id| self.written_files.contains_key(&id))
        {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        }
        let Some(seen) = self
            .t
            .seen
            .as_ref()
            .and_then(|seen| seen.get(destination))
            .cloned()
        else {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        };
        if !matches!(&seen, Seen::File(_) | Seen::Absent) {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        }
        let Some(rec) = self.rec.as_mut() else {
            return Vec::new();
        };
        let Some(key) = rec.key_of(destination, &mut self.t) else {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        };
        let prior_bytes = match &seen {
            Seen::File(file) => file.stat.size,
            _ => 0,
        };
        let new_prior = !self.t.priors.contains_key(&key);
        if prior_bytes > MAX_FILE_BYTES
            || (new_prior && rec.hashed.saturating_add(prior_bytes) > MAX_RUN_BYTES)
        {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        }
        if !identity::still_holds(&seen, destination, &mut rec.reads) {
            push_changed(&mut self.t, destination);
            return Vec::new();
        }
        let prior = match &seen {
            Seen::Absent => Some("a".to_string()),
            Seen::File(file) => match &file.read_hash {
                identity::ReadHash::Hashed(hash) => {
                    Some(file_id(file.stat.mode & 0o111 != 0, hash))
                }
                identity::ReadHash::NotNeeded => {
                    match identity::hash_bound(destination, &file.stat, &mut rec.reads) {
                        identity::ReadHash::Hashed(hash) => {
                            Some(file_id(file.stat.mode & 0o111 != 0, &hash))
                        }
                        _ => None,
                    }
                }
                _ => None,
            },
            _ => None,
        };
        let Some(prior) = prior else {
            self.t
                .read_write_conflicts
                .insert(destination.to_path_buf());
            return Vec::new();
        };
        if self
            .t
            .priors
            .get(&key)
            .is_some_and(|existing| existing != &prior)
        {
            push_changed(&mut self.t, destination);
            return Vec::new();
        }
        if new_prior {
            rec.hashed += prior_bytes;
        }
        self.t.priors.entry(key).or_insert(prior);
        vec![destination.to_path_buf()]
    }
    fn invalidate_settled(&mut self, destination: Option<&Path>, inode: Option<FileIdentity>) {
        if let Some(destination) = destination {
            self.t.settled_outputs.remove(destination);
        }
        if let Some(paths) = inode.and_then(|id| self.written_files.get(&id)) {
            for path in paths {
                self.t.settled_outputs.remove(path);
            }
        }
    }

    /// Snapshot a rename source before the kernel acts only when its destination was read.
    fn prepare_rename_evidence(&mut self, pid: i32) {
        let Some(pending) = self.pending_writes.get(&pid) else {
            return;
        };
        let Some((source_index, source)) = pending
            .paths
            .iter()
            .enumerate()
            .find(|(_, path)| matches!(&path.kind, WriteKind::Rename { source: true, .. }))
        else {
            return;
        };
        let Some((target_index, target)) = pending
            .paths
            .iter()
            .enumerate()
            .find(|(_, path)| matches!(&path.kind, WriteKind::Rename { source: false, .. }))
        else {
            return;
        };
        let exchange = matches!(&source.kind, WriteKind::Rename { exchange: true, .. });
        let needs = |path: &PendingPath| {
            !path.read_priors.is_empty()
                || path
                    .expected
                    .as_ref()
                    .is_some_and(|p| self.t.read_before_write.contains(p))
        };
        let mut captures = Vec::new();
        if needs(target) {
            if let (Some(path), Some(id)) = (&source.expected, source.before) {
                captures.push((source_index, path.clone(), id));
            }
        }
        if exchange && needs(source) {
            if let (Some(path), Some(id)) = (&target.expected, target.before) {
                captures.push((target_index, path.clone(), id));
            }
        }
        for (index, path, expected) in captures {
            let mut seen = identity::observe(&path, true);
            let Seen::File(file) = &mut seen else {
                continue;
            };
            if (file.stat.dev, file.stat.ino) != expected {
                continue;
            }
            let Some(rec) = self.rec.as_mut() else {
                continue;
            };
            file.read_hash = identity::hash_bound(&path, &file.stat, &mut rec.reads);
            if !matches!(&file.read_hash, identity::ReadHash::Hashed(_)) {
                continue;
            }
            if let Some(pending) = self.pending_writes.get_mut(&pid) {
                pending.paths[index].rename_before = Some(seen);
            }
        }
    }

    /// Bind the renamed destination to the source bytes observed before rename.
    fn rename_output_snapshot(&mut self, destination: &Path, before: &Seen) -> Option<Seen> {
        let Seen::File(before) = before else {
            return None;
        };
        let mut seen = identity::observe(destination, true);
        let Seen::File(after) = &mut seen else {
            return None;
        };
        if !same_rename_stat(&before.stat, &after.stat) {
            return None;
        }
        let rec = self.rec.as_mut()?;
        let hash = identity::hash_bound(destination, &after.stat, &mut rec.reads);
        after.read_hash = hash;
        if !verified_rename_snapshot(before, after) {
            return None;
        }
        Some(seen)
    }

    fn rename_snapshots(&mut self, paths: &[PendingPath]) -> Vec<(PathBuf, Seen)> {
        let mut snapshots = Vec::new();
        for path in paths {
            let WriteKind::Rename {
                source, exchange, ..
            } = &path.kind
            else {
                continue;
            };
            if *source && !*exchange {
                continue;
            }
            let Some(destination) = &path.expected else {
                continue;
            };
            if path.read_priors.is_empty() && !self.t.read_before_write.contains(destination) {
                continue;
            }
            let Some(other) = paths.iter().find(|candidate| {
                matches!(&candidate.kind, WriteKind::Rename { source: side, .. } if side != source)
            }) else { continue };
            let Some(before) = &other.rename_before else {
                continue;
            };
            let inode = match before {
                Seen::File(file) => Some((file.stat.dev, file.stat.ino)),
                _ => None,
            };
            if self.pending_writes.values().any(|pending| {
                pending.paths.iter().any(|other| {
                    other.expected.as_ref() == Some(destination)
                        || inode.is_some_and(|id| other.before == Some(id))
                })
            }) {
                continue;
            }
            if let Some(seen) = self.rename_output_snapshot(destination, before) {
                snapshots.push((destination.clone(), seen));
            }
        }
        snapshots
    }

    /// Capture entry state without granting ownership. Only a verified successful exit can land it.
    fn write(&mut self, raw: &Path, follows: bool, kind: WriteKind) -> Option<String> {
        self.rec.as_ref()?;
        if is_dynamic(raw) {
            return None;
        }
        let expected = write_destination(raw, follows);
        if expected.as_deref().is_some_and(is_dynamic) {
            return None;
        }
        if !self.t.removed_by_run.is_empty() || !self.own_absence_looks.is_empty() {
            // Even a failed attempt invalidates removal evidence. For a missing parent, resolve
            // the longest available prefix so the attempt still invalidates the affected name.
            let unresolved = if expected.is_none() {
                raw.ancestors().skip(1).find_map(|ancestor| {
                    let prefix = write_destination(ancestor, true)?;
                    Some(prefix.join(raw.strip_prefix(ancestor).ok()?))
                })
            } else {
                None
            };
            if let Some(destination) = expected.as_ref().or(unresolved.as_ref()) {
                for name in destination.ancestors() {
                    if self.own_absence_looks.remove(name)
                        && !matches!(identity::observe(name, false), Seen::Absent)
                    {
                        push_changed(&mut self.t, name);
                    }
                }
                forget_removals(&mut self.t.removed_by_run, destination);
            }
        }
        let metadata = expected.as_deref().map(fs::symlink_metadata);
        if metadata
            .as_ref()
            .and_then(|m| m.as_ref().ok())
            .is_some_and(|m| {
                let kind = m.file_type();
                kind.is_char_device()
                    || kind.is_block_device()
                    || kind.is_fifo()
                    || kind.is_socket()
            })
        {
            return None;
        }
        let absent = metadata
            .as_ref()
            .is_some_and(|m| m.as_ref().is_err_and(is_absent));
        let before = metadata
            .as_ref()
            .and_then(|m| m.as_ref().ok())
            .map(file_identity);
        let oid_sensitive = !self.t.oid_attrs_changed
            && self
                .rec
                .as_mut()
                .is_some_and(|rec| rec.oid_epoch.is_some() && rec.invalidates_oids(raw, follows));
        let deferred_mkdir_oid = oid_sensitive
            && matches!(&kind, WriteKind::Create { directory: true })
            && metadata.as_ref().is_some_and(Result::is_ok);
        if oid_sensitive && !deferred_mkdir_oid {
            self.t.oid_attrs_changed = true;
        }
        self.touch(raw.to_path_buf(), Use::Name);
        self.invalidate_settled(expected.as_deref(), before);
        let mut read_parent = None;
        if let Some(destination) = &expected {
            if kind.changes_entry(absent) {
                self.note_entry_change(destination);
                read_parent = destination
                    .parent()
                    .filter(|parent| self.read_files.contains(*parent))
                    .map(Path::to_path_buf);
            }
            if self
                .t
                .touched
                .get(destination)
                .is_some_and(|touch| touch.read)
                && self
                    .t
                    .seen
                    .as_ref()
                    .and_then(|seen| seen.get(destination))
                    .is_some_and(|seen| matches!(seen, Seen::Symlink { .. }))
            {
                self.t.read_write_conflicts.insert(destination.clone());
            }
        }
        if let WriteKind::Link {
            source: Some((_, id)),
        } = &kind
        {
            self.invalidate_settled(None, Some(*id));
            if let Some(reads) = self.read_inodes.get(id) {
                self.t.read_write_conflicts.extend(reads.iter().cloned());
                if let Some(destination) = &expected {
                    self.t.read_write_conflicts.insert(destination.clone());
                }
            }
        }
        let read_priors = expected
            .as_deref()
            .map(|destination| self.capture_read_prior(destination, before))
            .unwrap_or_default();
        let rec = self.rec.as_mut()?;
        let key = expected
            .as_deref()
            .and_then(|destination| rec.write(&mut self.t, raw, destination))
            .or_else(|| {
                expected
                    .is_none()
                    .then(|| rec.key_of(raw, &mut self.t))
                    .flatten()
            });
        if key
            .as_ref()
            .is_some_and(|key| rec.redirected_reads.contains(key))
        {
            push_reason(
                &mut self.t,
                format!(
                    "it read {} through a directory alias and also wrote it",
                    key.as_ref().unwrap()
                ),
            );
        }
        let pending = self
            .pending_writes
            .entry(self.current)
            .or_insert_with(|| PendingWrite {
                syscall: self.syscall,
                paths: Vec::new(),
            });
        pending.paths.push(PendingPath {
            raw: raw.to_path_buf(),
            expected,
            follows,
            key: key.clone(),
            before,
            absent,
            deferred_mkdir_oid,
            read_parent,
            read_priors,
            confirmed_after: None,
            rename_before: None,
            kind,
        });
        key
    }

    fn discard_write(&mut self, pid: i32) {
        if let Some(pending) = self.pending_writes.remove(&pid) {
            for path in pending.paths {
                self.uncertain_write(&path);
                self.refuse_landing(&path);
            }
        }
    }

    fn uncertain_write(&mut self, path: &PendingPath) {
        if path.deferred_mkdir_oid {
            self.t.oid_attrs_changed = true;
        }
        if let Some(expected) = &path.expected {
            self.landed_inodes.remove(expected);
            self.uncertain_paths.insert(expected.clone());
            if path.kind.changes_entry(path.absent) {
                if let Some(parent) = expected.parent() {
                    self.uncertain_paths.insert(parent.to_path_buf());
                }
            }
        }
        if let Some(id) = path.before {
            self.uncertain_inodes.insert(id);
        }
    }

    fn refuse_landing(&mut self, path: &PendingPath) {
        if self
            .t
            .touched
            .get(&path.raw)
            .is_some_and(|touch| touch.read || touch.listed)
        {
            self.t.read_write_conflicts.insert(path.raw.clone());
        }
        if path.key.is_some() || path.expected.is_none() {
            let name = path
                .key
                .clone()
                .unwrap_or_else(|| path.raw.display().to_string());
            self.flag(&format!(
                "it could not confirm where its change to {name} landed"
            ));
        }
    }

    fn complete_write(&mut self, pid: i32) {
        let Some(mut pending) = self.pending_writes.remove(&pid) else {
            return;
        };
        let deferred_mkdir_oid = pending.paths.iter().any(|path| path.deferred_mkdir_oid);
        let Some(regs) = get_regs(pid) else {
            self.t.oid_attrs_changed |= deferred_mkdir_oid;
            self.flag("could not read registers at a write exit");
            return;
        };
        if decode(&regs).0 != pending.syscall {
            self.t.oid_attrs_changed |= deferred_mkdir_oid;
            self.flag("it lost the exit stop of a pending write");
            return;
        }
        let result = syscall_result(&regs);
        if deferred_mkdir_invalidates_oid(deferred_mkdir_oid, result) {
            self.t.oid_attrs_changed = true;
        }
        if result < 0 {
            // Internal restart results may resume a syscall after a signal rather than fail it.
            if matches!(result, -512 | -513 | -514 | -516) {
                for path in pending.paths {
                    self.uncertain_write(&path);
                    self.refuse_landing(&path);
                }
            }
            return;
        }
        if !matches!(
            pending.paths.first().map(|path| &path.kind),
            Some(WriteKind::Open { .. })
        ) {
            let mut verified = !pending.paths.is_empty();
            for index in 0..pending.paths.len() {
                match verified_path_mutation(&pending.paths[index], &pending.paths) {
                    Some(after) => pending.paths[index].confirmed_after = after,
                    None => {
                        verified = false;
                        break;
                    }
                }
            }
            let snapshots = if verified {
                self.rename_snapshots(&pending.paths)
            } else {
                Vec::new()
            };
            for path in pending.paths {
                if verified {
                    let after = path
                        .expected
                        .as_deref()
                        .and_then(|destination| fs::symlink_metadata(destination).ok())
                        .as_ref()
                        .map(file_identity);
                    self.land_write(path, after, true);
                } else {
                    self.uncertain_write(&path);
                    self.refuse_landing(&path);
                }
            }
            self.t.settled_outputs.extend(snapshots);
            return;
        }

        for mut path in pending.paths {
            let (creates, exclusive) = match &path.kind {
                WriteKind::Open { creates, exclusive } => (*creates, *exclusive),
                _ => {
                    self.uncertain_write(&path);
                    self.refuse_landing(&path);
                    continue;
                }
            };
            let fd = format!("/proc/{pid}/fd/{result}");
            let actual = fs::read_link(&fd)
                .ok()
                .filter(|p| p.is_absolute() && !p.as_os_str().as_bytes().ends_with(b" (deleted)"));
            let metadata = fs::metadata(&fd).ok();
            let actual_identity = metadata.as_ref().map(file_identity);
            let may_have_created = creates && path.absent;
            if !verified_open(
                path.expected.as_deref(),
                actual.as_deref(),
                path.before,
                actual_identity,
                may_have_created,
            ) {
                if let Some(actual) = actual {
                    let actual_key = self
                        .rec
                        .as_ref()
                        .and_then(|rec| rec.key_of(&actual, &mut self.t));
                    if let Some(actual_key) = actual_key {
                        self.flag(&format!(
                            "it could not confirm where its change to {actual_key} landed"
                        ));
                    }
                    self.landed_inodes.remove(&actual);
                    self.uncertain_paths.insert(actual);
                }
                if let Some(id) = actual_identity {
                    self.uncertain_inodes.insert(id);
                }
                self.uncertain_write(&path);
                self.refuse_landing(&path);
                continue;
            }
            // Without O_EXCL another writer may have created the name after entry. The fd proves
            // the output destination, but not who created the name or the captured absent prior.
            path.confirmed_after = actual_identity;
            self.land_write(path, actual_identity, may_have_created && exclusive);
        }
    }

    fn land_write(&mut self, path: PendingPath, after: Option<FileIdentity>, mark_name: bool) {
        if let WriteKind::Link {
            source: Some((Some(source), _)),
        } = &path.kind
        {
            // A link source is bookkeeping, not a read by the command. Capture its post-link ctime
            // only when no earlier real observation exists; observe() preserves an earlier one.
            observe(self.rec.as_mut(), &mut self.t, source.clone(), Use::Name);
        }
        let Some(destination) = path.expected else {
            self.flag("it could not confirm where its change landed");
            return;
        };
        if let Some(parent) = path.read_parent {
            self.t.read_write_conflicts.insert(parent);
        }
        self.t.read_before_write.extend(path.read_priors);
        self.t.landed.insert(destination.clone());
        // An overlapping in-flight write may have entered before this removal landed, so its
        // entry could not invalidate the new evidence. Do not create that evidence in the overlap.
        if let Some(removal) = path.key.as_ref().and_then(|_| removal(&path.kind)) {
            if !self.pending_writes.values().any(|pending| {
                pending.paths.iter().any(|other| {
                    other.expected.as_deref().is_none_or(|other| {
                        other.starts_with(&destination) || destination.starts_with(other)
                    })
                })
            }) {
                self.t.removed_by_run.insert(destination.clone(), removal);
            }
        }
        if let Some(id) = path.confirmed_after {
            self.landed_inodes.insert(destination.clone(), id);
        } else {
            self.landed_inodes.remove(&destination);
        }
        self.t.written.insert(destination.clone());
        if let Some(key) = path.key {
            self.t.keys.insert(destination.clone(), key);
        }
        if path.kind.changes_entry(path.absent) && mark_name {
            self.mark_entry_change(&destination);
        }
        for id in [path.before, after].into_iter().flatten() {
            self.written_files
                .entry(id)
                .or_default()
                .insert(destination.clone());
        }
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
            // O_PATH ignores access mode and does not open file content.
            Some(f) if f & libc::O_PATH != 0 => self.touch(p, Use::Look),
            // An O_TMPFILE open writes nothing; the later linkat names the file.
            Some(f) if f & libc::O_TMPFILE == libc::O_TMPFILE => {
                self.touch(p, Use::Name);
            }
            // creat truncates the named file.
            None => {
                self.write(
                    &p,
                    true,
                    WriteKind::Open {
                        creates: true,
                        exclusive: false,
                    },
                );
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
                    if !creates_exclusively
                        && f & libc::O_ACCMODE != libc::O_WRONLY
                        && f & libc::O_PATH == 0
                    {
                        self.touch(p.clone(), Use::Content);
                    }
                    self.write(
                        &p,
                        follows,
                        WriteKind::Open {
                            creates: f & libc::O_CREAT != 0,
                            exclusive: creates_exclusively,
                        },
                    );
                } else {
                    let how = if f & libc::O_PATH != 0 || (f & libc::O_DIRECTORY != 0 && is_dir(&p))
                    {
                        // O_PATH reads no bytes, and O_DIRECTORY cannot open a regular file here.
                        Use::Look
                    } else {
                        Use::Content
                    };
                    self.touch(p, how);
                }
            }
        }
    }

    fn create(&mut self, pid: i32, args: &[u64; 6], dirfd: Option<usize>, path: usize, dir: bool) {
        let Some(p) = self.resolve(pid, args, dirfd, path) else {
            return;
        };
        let kind = if self.linking {
            WriteKind::Link {
                source: self.link_source.clone(),
            }
        } else {
            WriteKind::Create { directory: dir }
        };
        self.create_at(pid, p, kind);
    }

    /// A name the call creates: a directory, a symbolic link, a hard link or a node.
    fn create_at(&mut self, pid: i32, p: PathBuf, kind: WriteKind) {
        if !matches!(&kind, WriteKind::Create { directory: true }) {
            // A new link or node inside the repository can change how an attribute source is
            // reached. Outside it, only a watched name matters, and write() checks that.
            if self.rec.as_mut().is_some_and(|rec| rec.in_repo(&p)) {
                self.t.oid_attrs_changed = true;
            }
            self.topology_changed(pid);
        }
        self.write(&p, false, kind);
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
        // Inside the repository, a removed directory may hide attribute sources and a removed
        // symbolic link changes how they are reached. Outside it, the watched names decide.
        let inside = self.rec.as_mut().is_some_and(|rec| rec.in_repo(&p));
        if removes_dir && inside && crate::oid_attrs::directory_removal_invalidates(&p) {
            self.t.oid_attrs_changed = true;
        }
        if let Ok(metadata) = fs::symlink_metadata(&p) {
            if metadata.file_type().is_symlink() && inside {
                self.t.oid_attrs_changed = true;
            }
            if metadata.is_dir() || metadata.file_type().is_symlink() {
                self.topology_changed(pid);
            }
        }
        // Read the directory's contents before the call, while they are still there.
        let key = self.write(&p, false, WriteKind::Remove);
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
        let rename_flags = flags.map_or(0, |i| args[i] as u32);
        let exchange = rename_flags & RENAME_EXCHANGE != 0;
        let supported = rename_flags & !(RENAME_EXCHANGE | 1) == 0;
        let a_meta = fs::symlink_metadata(&a).ok();
        let b_meta = fs::symlink_metadata(&b).ok();
        let a_dir = a_meta.as_ref().is_some_and(|m| m.is_dir());
        let b_dir = b_meta.as_ref().is_some_and(|m| m.is_dir());
        let symlink = a_meta.as_ref().is_some_and(|m| m.file_type().is_symlink())
            || b_meta.as_ref().is_some_and(|m| m.file_type().is_symlink());
        let directory = a_dir || (exchange && b_dir);
        // A moved directory may contain attribute sources, and a symlink changes their
        // resolution, even when neither endpoint names an attribute file. Outside the repository
        // only a watched name matters, and write() checks each endpoint for it.
        if (directory || symlink)
            && self
                .rec
                .as_mut()
                .is_some_and(|rec| rec.in_repo(&a) || rec.in_repo(&b))
        {
            self.t.oid_attrs_changed = true;
        }
        if a_dir || b_dir || symlink {
            self.topology_changed(pid);
        }
        let ka = self.write(
            &a,
            false,
            WriteKind::Rename {
                source: true,
                exchange,
                supported,
            },
        );
        let kb = self.write(
            &b,
            false,
            WriteKind::Rename {
                source: false,
                exchange,
                supported,
            },
        );
        self.prepare_rename_evidence(pid);
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
            if self.rec.is_some() {
                self.t.oid_attrs_changed = true;
            }
            return;
        }
        match fs::symlink_metadata(raw) {
            Ok(m) if m.is_dir() => {
                // Directory permissions can change which attribute files Git can read.
                let inside = self.rec.as_mut().is_some_and(|rec| rec.in_repo(raw));
                if inside || self.oid_sensitive(raw, follows) {
                    self.t.oid_attrs_changed = true;
                }
                self.note_listed_change(raw);
                self.write(raw, follows, WriteKind::Modify);
            }
            Ok(_) => {
                self.write(raw, follows, WriteKind::Modify);
            }
            Err(_) => {
                if self.rec.is_some() {
                    self.t.oid_attrs_changed = true;
                }
                self.write(raw, follows, WriteKind::Modify);
            }
        }
    }

    /// Resolve descriptor-only chmods, including fchmodat2 with AT_EMPTY_PATH.
    fn chmod_fd(&mut self, pid: i32, fd: i32) {
        let path = if fd == AT_FDCWD {
            self.cwd(pid)
        } else {
            fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()
        };
        match path {
            Some(path)
                if path.is_absolute() && !path.as_os_str().as_bytes().ends_with(b" (deleted)") =>
            {
                self.chmod(&path, false);
            }
            _ if self.rec.is_some() => {
                self.t.oid_attrs_changed = true;
                self.flag("it changed an unkeyable file descriptor");
            }
            _ => {}
        }
    }

    /// Whether a call at `raw` changes what Git reads for attributes or configuration. Only a run
    /// that has an attribute snapshot can lose evidence this way.
    fn oid_sensitive(&mut self, raw: &Path, follows: bool) -> bool {
        self.rec
            .as_mut()
            .is_some_and(|rec| rec.oid_epoch.is_some() && rec.invalidates_oids(raw, follows))
    }

    /// A symbolic link whose target lies in the repository, or is a watched name, brings a source
    /// under another path, whatever the link's own name is. An unreadable target counts.
    fn symlink_target(&mut self, pid: i32, args: &[u64; 6], link: &Path, target: usize) {
        let Some(rec) = self.rec.as_mut() else {
            return;
        };
        let Some(bytes) = read_cstr(pid, args[target]) else {
            self.t.oid_attrs_changed = true;
            return;
        };
        let target = PathBuf::from(OsString::from_vec(bytes));
        let base = link.parent().unwrap_or(Path::new("/"));
        let joined = without_dots(&if target.is_absolute() {
            target
        } else {
            base.join(target)
        });
        if rec.in_repo(&joined) || rec.watched_name(&joined) {
            self.t.oid_attrs_changed = true;
        }
    }

    /// chown, lchown and fchownat. An owner change inside the repository counts, because a path's
    /// owner decides whether Git can read its attribute files. Outside it, the watched names do.
    fn owner(
        &mut self,
        pid: i32,
        args: &[u64; 6],
        dirfd: Option<usize>,
        path: usize,
        flags: Option<usize>,
        nofollow: bool,
    ) {
        let Some(p) = self.resolve(pid, args, dirfd, path) else {
            // fchownat with AT_EMPTY_PATH names its descriptor, not a path.
            if let Some(fd) =
                dirfd.filter(|_| flags.is_some_and(|i| args[i] as i32 & AT_EMPTY_PATH != 0))
            {
                self.owner_fd(pid, args[fd] as i32, true);
            }
            return;
        };
        let nofollow = nofollow || flags.is_some_and(|i| args[i] as i32 & AT_SYMLINK_NOFOLLOW != 0);
        let inside = self.rec.as_mut().is_some_and(|rec| rec.in_repo(&p));
        if inside || self.oid_sensitive(&p, !nofollow) {
            self.t.oid_attrs_changed = true;
        }
        self.note_listed_change(&p);
        self.write(&p, !nofollow, WriteKind::Modify);
    }

    /// fchown. The descriptor's name decides when it has one. A descriptor whose file is deleted
    /// counts only by identity, and an identity that cannot be read counts.
    fn owner_fd(&mut self, pid: i32, fd: i32, mutate: bool) {
        let proc_path = PathBuf::from(format!("/proc/{pid}/fd/{fd}"));
        let identity = fs::metadata(&proc_path).ok();
        let named = fs::read_link(&proc_path).ok().filter(|path| {
            path.is_absolute() && !path.as_os_str().as_bytes().ends_with(b" (deleted)")
        });
        let Some(rec) = self.rec.as_mut() else {
            return;
        };
        let risky = match &named {
            Some(path) => {
                rec.in_repo(path) || rec.oid_epoch.is_some() && rec.invalidates_oids(path, true)
            }
            None => identity.as_ref().is_none_or(|m| {
                rec.oid_epoch
                    .as_ref()
                    .is_some_and(|epoch| epoch.watch.is_watched_file(m))
            }),
        };
        if risky {
            self.t.oid_attrs_changed = true;
        }
        if mutate {
            if let Some(path) = named {
                self.write(&path, false, WriteKind::Modify);
            } else {
                self.flag("it changed an unkeyable file descriptor");
            }
        }
    }

    fn on_syscall(&mut self, pid: i32) {
        self.discard_write(pid);
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
        self.linking = ops.iter().any(|op| matches!(op, Op::LinkSource { .. }));
        self.link_source = None;
        self.resolving_write = ops.iter().any(|op| match op {
            Op::Open { flags, .. } => flags.is_none_or(|index| {
                let open_flags = args[index] as i32;
                open_flags & libc::O_PATH == 0
                    && open_flags
                        & (libc::O_WRONLY
                            | libc::O_RDWR
                            | libc::O_CREAT
                            | libc::O_TRUNC
                            | libc::O_APPEND)
                        != 0
            }),
            Op::Create { .. }
            | Op::Remove { .. }
            | Op::Rename { .. }
            | Op::Truncate { .. }
            | Op::Chmod { .. }
            | Op::Fchmod { .. }
            | Op::Symlink { .. }
            | Op::Owner { .. }
            | Op::OwnerFd { .. } => true,
            _ => false,
        });
        for op in ops {
            match op {
                Op::Open { dirfd, path, flags } => self.open(pid, &args, dirfd, path, flags),
                Op::Look { dirfd, path } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        self.touch(p, Use::Look);
                    } else {
                        let empty_fd = (nr == libc::SYS_newfstatat
                            && args[3] as i32 & AT_EMPTY_PATH != 0)
                            || (nr == libc::SYS_statx && args[2] as i32 & AT_EMPTY_PATH != 0);
                        if empty_fd {
                            if let Some(fd) = dirfd {
                                self.observe_fd_look(pid, args[fd] as i32);
                            }
                        }
                    }
                }
                Op::FdLook => self.observe_fd_look(pid, args[0] as i32),
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
                        self.observe_list(p);
                    }
                }
                Op::Chdir { path } => {
                    if let Some(p) = self.resolve(pid, &args, None, path) {
                        self.touch(p, Use::Name);
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
                        self.write(&p, true, WriteKind::Modify);
                    }
                }
                Op::Chmod { dirfd, path, flags } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        let nofollow =
                            flags.is_some_and(|i| args[i] as i32 & AT_SYMLINK_NOFOLLOW != 0);
                        self.chmod(&p, !nofollow);
                    } else if flags.is_some_and(|i| args[i] as i32 & AT_EMPTY_PATH != 0) {
                        if let Some(fd) = dirfd {
                            self.chmod_fd(pid, args[fd] as i32);
                        } else if self.rec.is_some() {
                            self.t.oid_attrs_changed = true;
                        }
                    }
                }
                Op::Fchmod { fd } => self.chmod_fd(pid, args[fd] as i32),
                Op::Symlink {
                    dirfd,
                    path,
                    target,
                } => {
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        let link_text = read_cstr(pid, args[target]).map(OsString::from_vec);
                        self.symlink_target(pid, &args, &p, target);
                        self.create_at(pid, p, WriteKind::Symlink { target: link_text });
                    }
                }
                Op::LinkSource { dirfd, path, flags } => {
                    let by_fd = flags.is_some_and(|i| args[i] as i32 & AT_EMPTY_PATH != 0);
                    if let Some(p) = self.resolve(pid, &args, dirfd, path) {
                        let follows =
                            flags.is_some_and(|i| args[i] as i32 & AT_SYMLINK_FOLLOW != 0);
                        let metadata = if follows {
                            fs::metadata(&p)
                        } else {
                            fs::symlink_metadata(&p)
                        };
                        self.link_source = metadata
                            .ok()
                            .map(|m| (write_destination(&p, follows), file_identity(&m)));
                        if self.oid_sensitive(&p, true) {
                            self.t.oid_attrs_changed = true;
                        }
                    } else if let (Some(fd), true) = (dirfd, by_fd) {
                        // AT_EMPTY_PATH names the source by descriptor, as fchownat does.
                        self.owner_fd(pid, args[fd] as i32, false);
                        let proc_fd = format!("/proc/{pid}/fd/{}", args[fd] as i32);
                        let source_name = fs::read_link(&proc_fd).ok().filter(|name| {
                            name.is_absolute()
                                && !name.as_os_str().as_bytes().ends_with(b" (deleted)")
                        });
                        self.link_source = fs::metadata(&proc_fd)
                            .ok()
                            .map(|m| (source_name, file_identity(&m)));
                    }
                }
                Op::Owner {
                    dirfd,
                    path,
                    flags,
                    nofollow,
                } => self.owner(pid, &args, dirfd, path, flags, nofollow),
                Op::OwnerFd { fd } => self.owner_fd(pid, args[fd] as i32, true),
                Op::UncertainOidState => {
                    if self.rec.is_some() {
                        self.t.oid_attrs_changed = true;
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
    fn watched_mkdir_preserves_oid_only_on_eexist() {
        assert!(!deferred_mkdir_invalidates_oid(
            true,
            -(libc::EEXIST as i64)
        ));
        assert!(deferred_mkdir_invalidates_oid(true, -(libc::EACCES as i64)));
        assert!(deferred_mkdir_invalidates_oid(true, -(libc::EPERM as i64)));
        assert!(deferred_mkdir_invalidates_oid(true, 0));
        assert!(!deferred_mkdir_invalidates_oid(false, 0));
    }

    #[test]
    fn fd_attribution_requires_the_exact_resolved_destination() {
        let expected = Path::new("/repo/a");
        let other = Path::new("/repo/b");
        let inode = Some((3, 9));
        assert!(verified_open(
            Some(expected),
            Some(expected),
            inode,
            inode,
            false
        ));
        assert!(!verified_open(
            Some(expected),
            Some(other),
            inode,
            inode,
            false
        ));
        assert!(!verified_open(Some(expected), None, inode, inode, false));
    }

    #[test]
    fn fd_attribution_rejects_an_unresolved_expected_destination() {
        let actual = Path::new("/repo/a");
        assert!(!verified_open(None, Some(actual), None, Some((3, 9)), true));
        assert!(!verified_open(None, None, None, None, true));
    }

    #[test]
    fn fd_attribution_requires_the_same_inode_or_an_actual_creation() {
        let path = Path::new("/repo/a");
        assert!(!verified_open(
            Some(path),
            Some(path),
            Some((3, 9)),
            Some((3, 10)),
            true
        ));
        assert!(!verified_open(
            Some(path),
            Some(path),
            None,
            Some((3, 9)),
            false
        ));
        assert!(!verified_open(Some(path), Some(path), None, None, true));
        assert!(verified_open(
            Some(path),
            Some(path),
            None,
            Some((3, 9)),
            true
        ));
    }

    #[test]
    fn rename_snapshot_requires_source_bytes_and_identity() {
        let before = identity::FileSeen {
            stat: identity::FileStat {
                dev: 3,
                ino: 9,
                size: 4,
                mtime_ns: 10,
                ctime_ns: 11,
                mode: 0o100644,
            },
            read_hash: identity::ReadHash::Hashed("source".into()),
        };
        let mut after = before.clone();
        after.stat.ctime_ns += 1;
        assert!(verified_rename_snapshot(&before, &after));
        after.read_hash = identity::ReadHash::Hashed("restored-prior".into());
        assert!(!verified_rename_snapshot(&before, &after));
        after.read_hash = identity::ReadHash::NotNeeded;
        assert!(!verified_rename_snapshot(&before, &after));
        after = before.clone();
        after.stat.dev += 1;
        assert!(!verified_rename_snapshot(&before, &after));
        after = before.clone();
        after.stat.ino += 1;
        assert!(!verified_rename_snapshot(&before, &after));
        after = before.clone();
        after.stat.mtime_ns += 1;
        assert!(!verified_rename_snapshot(&before, &after));
        after = before.clone();
        after.stat.size += 1;
        assert!(!verified_rename_snapshot(&before, &after));
        after = before.clone();
        after.stat.mode ^= 0o111;
        assert!(!verified_rename_snapshot(&before, &after));
    }

    #[test]
    fn watched_names_decide_which_changes_drop_blob_ids() {
        let base = std::env::temp_dir().join(format!(
            "stoop-oid-watch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(base.join("repo/.git/info")).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        fs::write(base.join("repo/.git/config"), "[core]\n").unwrap();
        fs::write(base.join("home/.gitconfig"), "[user]\n").unwrap();
        let base = fs::canonicalize(&base).unwrap();
        let root = base.join("repo");
        let git_dir = root.join(".git");
        let ignore = Ignore::new(&[], None, &[]);
        let watch =
            crate::oid_attrs::build_watch(&git_dir, &[base.join("home/.gitconfig")]).unwrap();
        let mut rec = Rec {
            phys: Physical::new(&root, &root),
            ignore: &ignore,
            root: root.clone(),
            hashed: 0,
            oid_epoch: Some(Arc::new(crate::oid_attrs::Epoch {
                basis: HashMap::new(),
                git_dir: git_dir.clone(),
                common_dir: git_dir.clone(),
                watch,
                watched: Vec::new(),
            })),
            link_walks: BTreeMap::new(),
            redirected_reads: HashSet::new(),
            reads: identity::ReadBudget::default(),
        };

        let outside_file = base.join("outside/file");
        fs::write(&outside_file, b"x").unwrap();
        assert!(!rec.invalidates_oids(&outside_file, true));
        let ordinary = root.join("ordinary");
        fs::write(&ordinary, b"x").unwrap();
        assert!(!rec.invalidates_oids(&ordinary, true));
        fs::create_dir_all(git_dir.join("objects")).unwrap();
        assert!(!rec.invalidates_oids(&git_dir.join("objects/aa"), false));

        assert!(rec.invalidates_oids(&base.join("home/.gitconfig"), true));
        assert!(rec.invalidates_oids(&git_dir.join("config"), true));
        assert!(rec.invalidates_oids(&git_dir.join("info/attributes"), true));
        assert!(rec.invalidates_oids(&git_dir.join("index"), true));

        let alias = base.join("outside/alias");
        fs::hard_link(base.join("home/.gitconfig"), &alias).unwrap();
        assert!(rec.invalidates_oids(&alias, true));
        let link = base.join("outside/link");
        std::os::unix::fs::symlink(git_dir.join("info"), &link).unwrap();
        assert!(rec.invalidates_oids(&link.join("attributes"), true));

        fs::create_dir_all(root.join("nested/.git")).unwrap();
        assert!(rec.invalidates_oids(&root.join("nested/.gitattributes"), false));
        assert!(rec.invalidates_oids(&root.join("nested/.git/config"), true));
        fs::hard_link(&ordinary, root.join("linked")).unwrap();
        assert!(rec.invalidates_oids(&ordinary, true));
        // A path that cannot be placed, and a name that cannot be read, both count.
        assert!(
            rec.invalidates_oids(Path::new("/"), true),
            "an unplaceable path counts"
        );
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let locked = base.join("locked");
            fs::create_dir_all(locked.join("inner")).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let unreadable = rec.invalidates_oids(&locked.join("inner/file"), true);
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(unreadable, "a name that cannot be read counts");
        }
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn forget_removals_clears_ancestors_name_and_descendants_on_component_boundaries() {
        let mut removed = BTreeMap::from([
            (PathBuf::from("/r/a"), Removal::MovedAway),
            (PathBuf::from("/r/a/b"), Removal::Unlinked),
            (PathBuf::from("/r/a/b/c"), Removal::MovedAway),
            (PathBuf::from("/r/a/bc"), Removal::Unlinked),
            (PathBuf::from("/r/x"), Removal::Unlinked),
        ]);

        forget_removals(&mut removed, Path::new("/r/a/b"));

        assert_eq!(
            removed,
            BTreeMap::from([
                (PathBuf::from("/r/a/bc"), Removal::Unlinked),
                (PathBuf::from("/r/x"), Removal::Unlinked),
            ])
        );
    }

    #[test]
    fn only_moved_away_ancestors_explain_descendant_absence() {
        let mut trace = Trace::default();
        trace
            .removed_by_run
            .insert(PathBuf::from("/r/unlinked"), Removal::Unlinked);
        trace
            .removed_by_run
            .insert(PathBuf::from("/r/moved"), Removal::MovedAway);

        assert!(trace.removal_explains_absence(Path::new("/r/unlinked")));
        assert!(!trace.removal_explains_absence(Path::new("/r/unlinked/child")));
        assert!(trace.removal_explains_absence(Path::new("/r/moved/child")));
        assert!(!trace.removal_explains_absence(Path::new("/r/moved-other/child")));
    }

    #[test]
    fn removed_name_is_omitted_from_metadata_join_only_while_truly_absent() {
        let base = std::env::temp_dir().join(format!(
            "stoop-removal-join-{}-{}",
            std::process::id(),
            identity::now_ns()
        ));
        fs::create_dir(&base).unwrap();
        let name = base.join("name");
        let mut removed = BTreeMap::new();
        assert!(!removed_and_absent(&removed, &name));
        removed.insert(name.clone(), Removal::MovedAway);
        assert!(removed_and_absent(&removed, &name));

        fs::write(&name, b"outside").unwrap();
        assert!(!removed_and_absent(&removed, &name));
        fs::remove_file(&name).unwrap();
        std::os::unix::fs::symlink("missing", &name).unwrap();
        assert!(!removed_and_absent(&removed, &name));

        fs::remove_dir_all(base).unwrap();
    }

    fn empty_tracer() -> Tracer<'static> {
        Tracer {
            ops: HashMap::new(),
            cwds: HashMap::new(),
            magic_epoch: 0,
            magic_cache: HashMap::new(),
            pending_topology: HashSet::new(),
            pending_writes: HashMap::new(),
            read_files: HashSet::new(),
            read_inodes: HashMap::new(),
            read_routes: HashMap::new(),
            own_absence_looks: HashSet::new(),
            written_files: HashMap::new(),
            landed_inodes: HashMap::new(),
            uncertain_paths: HashSet::new(),
            uncertain_inodes: HashSet::new(),
            resolving_write: false,
            linking: false,
            link_source: None,
            current: 0,
            syscall: 0,
            allow_network: false,
            rec: None,
            execs: None,
            t: Trace::default(),
        }
    }

    #[test]
    fn overlapping_in_flight_write_prevents_new_removal_evidence() {
        let mut tracer = empty_tracer();
        let output = PathBuf::from("/repo/output");
        let path = |name: PathBuf, kind, key| PendingPath {
            raw: name.clone(),
            expected: Some(name),
            follows: false,
            key,
            before: Some((3, 9)),
            absent: false,
            deferred_mkdir_oid: false,
            read_parent: None,
            read_priors: Vec::new(),
            rename_before: None,
            confirmed_after: None,
            kind,
        };
        tracer.pending_writes.insert(
            1,
            PendingWrite {
                syscall: 0,
                paths: vec![path(output.join("child"), WriteKind::Modify, None)],
            },
        );
        tracer.land_write(
            path(output.clone(), WriteKind::Remove, Some("output".into())),
            None,
            true,
        );
        assert!(!tracer.t.removed_by_run.contains_key(&output));

        tracer.pending_writes.get_mut(&1).unwrap().paths[0].expected =
            Some(PathBuf::from("/repo/other"));
        tracer.land_write(
            path(output.clone(), WriteKind::Remove, Some("output".into())),
            None,
            true,
        );
        assert_eq!(
            tracer.t.removed_by_run.get(&output),
            Some(&Removal::Unlinked)
        );
    }

    #[test]
    fn metadata_exemption_requires_the_exact_unambiguous_landing() {
        let mut tracer = empty_tracer();
        let output = PathBuf::from("/repo/output");
        let other = PathBuf::from("/repo/other");
        let own = (3, 9);
        let other_inode = (3, 10);
        tracer.t.landed.insert(output.clone());
        tracer.t.landed.insert(other.clone());
        tracer.landed_inodes.insert(output.clone(), own);
        tracer.landed_inodes.insert(other.clone(), other_inode);
        tracer
            .written_files
            .entry(own)
            .or_default()
            .insert(output.clone());
        tracer
            .written_files
            .entry(other_inode)
            .or_default()
            .insert(other.clone());
        assert!(tracer.own_output_metadata(&output, Some(own)));
        assert!(!tracer.own_output_metadata(&output, Some(other_inode)));
        assert!(!tracer.own_output_metadata(&output, None));
        tracer.t.landed.remove(&output);
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        tracer.t.landed.insert(output.clone());
        tracer.landed_inodes.remove(&output);
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        tracer.landed_inodes.insert(output.clone(), own);

        tracer.uncertain_paths.insert(output.clone());
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        tracer.uncertain_paths.clear();
        tracer.uncertain_inodes.insert(own);
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        tracer.uncertain_inodes.clear();

        tracer.pending_writes.insert(
            1,
            PendingWrite {
                syscall: 0,
                paths: vec![PendingPath {
                    raw: other.clone(),
                    expected: Some(other.clone()),
                    follows: true,
                    key: None,
                    before: Some(own),
                    absent: false,
                    deferred_mkdir_oid: false,
                    read_parent: None,
                    read_priors: Vec::new(),
                    rename_before: None,
                    confirmed_after: None,
                    kind: WriteKind::Modify,
                }],
            },
        );
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        let pending = &mut tracer.pending_writes.get_mut(&1).unwrap().paths[0];
        pending.before = None;
        pending.expected = Some(output.clone());
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        let pending = &mut tracer.pending_writes.get_mut(&1).unwrap().paths[0];
        pending.expected = None;
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        let pending = &mut tracer.pending_writes.get_mut(&1).unwrap().paths[0];
        pending.expected = Some(other);
        pending.kind = WriteKind::Link {
            source: Some((None, own)),
        };
        assert!(!tracer.own_output_metadata(&output, Some(own)));
        tracer.pending_writes.clear();
        assert!(tracer.own_output_metadata(&output, Some(own)));
    }

    #[test]
    fn topology_cache_is_cleared_again_on_the_changing_process_stop() {
        let mut tracer = empty_tracer();
        tracer.topology_changed(42);
        assert_eq!(tracer.magic_epoch, 1);
        tracer.after_topology_stop(43);
        assert_eq!(tracer.magic_epoch, 1);
        tracer.after_topology_stop(42);
        assert_eq!(tracer.magic_epoch, 2);
        tracer.after_topology_stop(42);
        assert_eq!(tracer.magic_epoch, 2);
    }

    fn sample_exec() -> ExecEvent {
        ExecEvent {
            parent: None,
            requested: PathBuf::from("/bin/pytest"),
            argv: vec![OsString::from("pytest")],
            executable: PathBuf::from("/bin/sh"),
            effective_argv: vec![OsString::from("sh")],
            cwd: PathBuf::from("/"),
        }
    }

    #[test]
    fn child_stop_before_fork_preserves_its_inherited_image() {
        let mut observer = ExecObserver::new(10);
        observer.events.push(sample_exec());
        observer.tasks.insert(10, Some(0));
        assert!(observer.defer(11, Instant::now()));
        assert!(observer.register_child(10, 11));
        assert_eq!(observer.tasks.get(&11), Some(&Some(0)));
        assert!(!observer.defer(11, Instant::now()));
        assert!(!observer.deferred.contains_key(&11));
    }

    #[test]
    fn oldest_deferred_child_controls_the_deadline() {
        let mut observer = ExecObserver::new(10);
        let start = Instant::now();
        let later = start + Duration::from_millis(250);
        assert!(observer.defer(11, start));
        assert!(observer.defer(12, later));
        assert_eq!(
            observer.hold_remaining(later),
            Some(Duration::from_millis(750))
        );
        assert!(observer.register_child(10, 11));
        assert_eq!(observer.hold_remaining(later), Some(MAX_EXEC_HOLD));
        observer.exit(12);
        assert_eq!(observer.hold_remaining(later), None);
    }

    #[test]
    fn argument_reads_stop_at_nul_across_chunk_boundaries() {
        let pid = unsafe { libc::getpid() };
        let mut bytes = vec![b'x'; 257];
        bytes[256] = 0;
        let address = bytes.as_ptr() as u64;
        assert_eq!(
            read_exec_arg(pid, address, 257, &mut None).unwrap(),
            vec![b'x'; 256]
        );
        assert!(read_exec_arg(pid, address, 256, &mut None).is_none());
        bytes[4] = 0;
        assert_eq!(
            read_exec_arg(pid, address, 257, &mut None).unwrap(),
            vec![b'x'; 4]
        );
    }

    #[test]
    fn exec_event_cap_keeps_the_completed_prefix() {
        let mut observer = ExecObserver::new(10);
        observer
            .events
            .extend((1..MAX_EXEC_EVENTS).map(|_| sample_exec()));
        assert!(observer.reserve_event());
        observer.events.push(sample_exec());
        assert!(!observer.reserve_event());
        assert!(!observer.collecting);
        assert_eq!(observer.finish().unwrap().len(), MAX_EXEC_EVENTS);
    }

    #[test]
    fn live_task_cap_and_exit_cleanup_are_bounded() {
        let mut observer = ExecObserver::new(10);
        for child in 11..(10 + MAX_EXEC_TASKS as i32) {
            assert!(!observer.register_child(10, child));
            assert!(observer.collecting);
        }
        assert_eq!(observer.tasks.len(), MAX_EXEC_TASKS);
        assert!(!observer.register_child(10, 100_000));
        assert!(!observer.collecting);

        let mut observer = ExecObserver::new(10);
        for child in 11..(11 + MAX_EXEC_TASKS as i32 * 2) {
            assert!(!observer.register_child(10, child));
            observer.exit(child);
        }
        assert!(observer.collecting);
        assert_eq!(observer.tasks.len(), 1);
    }
}
