//! Read-time identity: what a path held when a traced command first looked at it, and what it
//! holds once the command has exited. A difference means the command may have read something
//! other than the bytes the record will describe, so the run is not recorded.
//!
//! The types and comparisons are plain data and compile on every platform, so their unit tests
//! run on every CI runner. Only the Linux tracer takes captures.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::oid_attrs::is_absent;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Git's racy-clean rule: a file changed this recently may change again without its stat data
/// changing, so its bytes are compared as well. A timestamp in the future counts as recent.
pub const RACY_WINDOW_NS: i128 = 2_000_000_000;
/// Bytes read for hashing at read stops in one run. One extra byte detects overflow.
pub const READ_HASH_BUDGET: u64 = 1 << 30;
/// Directory entries snapshotted in one run. Past it the record is refused.
pub const MAX_LISTED_NAMES: usize = 1 << 20;

/// The raw names of one directory's entries, sorted by bytes.
pub type Names = BTreeSet<Box<[u8]>>;

/// What a path held when the run first looked at it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    /// Nothing at the path.
    Absent,
    /// Stat failed for a reason other than absence.
    Unreadable,
    File(FileSeen),
    Dir(DirSeen),
    /// A symbolic link: its target text, what it resolved to at the first look (`Absent` when
    /// dangling), and the canonical path it resolved to (`None` when dangling or not resolved).
    Symlink {
        target: OsString,
        followed: Box<Seen>,
        resolved: Option<PathBuf>,
    },
    /// A device, FIFO or socket: never an input.
    Special,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSeen {
    pub stat: FileStat,
    pub read_hash: ReadHash,
}

/// The stat fields that identify a regular file's bytes and metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub mode: u32,
}

/// Whether the bytes were hashed when the run read the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadHash {
    /// Not racy when read: the stat fields are the comparison.
    NotNeeded,
    /// Racy when read: the blake3 hex of the bytes the run read.
    Hashed(String),
    /// Racy when read, and the read-hash budget had no room: the record is refused.
    OverBudget,
    /// Racy when read, and its bytes could not be read to hash them: the record is refused.
    Unhashable,
    /// The opened file no longer has the identity captured at the read stop.
    Moved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirSeen {
    pub dev: u64,
    pub ino: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

/// A directory the run listed: its state at the listing, and its names when they were read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListSeen {
    pub stat: DirSeen,
    /// Present when the listing was racy, or when the names were read before the run's first
    /// change to the directory. Absent means the stat is the comparison.
    pub names: Option<Names>,
}

/// What a path holds after the command has exited, in the shape `Seen` takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Post {
    Absent,
    Unreadable,
    Special,
    File { stat: FileStat, hash: String },
    Dir { stat: DirSeen, names: Option<Names> },
    Symlink { target: OsString },
}

/// Why a comparison refuses the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Changed,
    OverBudget,
    Unhashable,
}

/// Bytes actually read at read stops, including any overflow byte, and debug-line count.
#[derive(Default)]
pub struct ReadBudget {
    pub hashed: u64,
    pub logged: u32,
}

pub fn now_ns() -> i128 {
    system_ns(SystemTime::now())
}

fn system_ns(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    }
}

/// Whether a file or directory changed recently enough that its bytes could change without its
/// stat data changing. A timestamp in the future is recent.
pub fn racy(mtime_ns: i128, ctime_ns: i128, now_ns: i128) -> bool {
    mtime_ns.max(ctime_ns) >= now_ns - RACY_WINDOW_NS
}

#[cfg(unix)]
pub fn file_stat(metadata: &fs::Metadata) -> FileStat {
    use std::os::unix::fs::MetadataExt;
    let at = |seconds: i64, nanos: i64| i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    FileStat {
        dev: metadata.dev(),
        ino: metadata.ino(),
        size: metadata.size(),
        mtime_ns: at(metadata.mtime(), metadata.mtime_nsec()),
        ctime_ns: at(metadata.ctime(), metadata.ctime_nsec()),
        mode: metadata.mode(),
    }
}

/// Windows has no stable device and inode in the standard library, so a file there compares by
/// size and time only. The recorder runs on Linux; this keeps the module compiling everywhere.
#[cfg(not(unix))]
pub fn file_stat(metadata: &fs::Metadata) -> FileStat {
    let mtime_ns = metadata.modified().map_or(0, system_ns);
    FileStat {
        dev: 0,
        ino: 0,
        size: metadata.len(),
        mtime_ns,
        ctime_ns: mtime_ns,
        mode: 0,
    }
}

pub fn dir_stat(metadata: &fs::Metadata) -> DirSeen {
    let stat = file_stat(metadata);
    DirSeen {
        dev: stat.dev,
        ino: stat.ino,
        mtime_ns: stat.mtime_ns,
        ctime_ns: stat.ctime_ns,
    }
}

/// The raw names of `dir`'s entries. None when the directory cannot be read.
pub fn read_names(dir: &Path) -> Option<Names> {
    let mut names = Names::new();
    for entry in fs::read_dir(dir).ok()? {
        names.insert(entry.ok()?.file_name().as_encoded_bytes().into());
    }
    Some(names)
}

/// The result of a directory snapshot, including why no snapshot could be made.
#[derive(Debug, PartialEq, Eq)]
pub enum NameSnapshot {
    /// Deduplicated raw names and the number of entries consumed from the directory.
    Names {
        names: Names,
        entries: usize,
    },
    OverCap,
    Unreadable,
}

/// Read at most `cap + 1` directory entries, preserving the raw-name ordering of `read_names`.
pub fn read_names_capped(dir: &Path, cap: usize) -> NameSnapshot {
    match fs::read_dir(dir) {
        Ok(entries) => take_names(
            entries.map(|entry| entry.map(|entry| entry.file_name())),
            cap,
        ),
        Err(_) => NameSnapshot::Unreadable,
    }
}

fn take_names<I>(entries: I, cap: usize) -> NameSnapshot
where
    I: IntoIterator<Item = io::Result<OsString>>,
{
    let mut names = Names::new();
    let mut count = 0;
    for entry in entries {
        let name = match entry {
            Ok(name) => name,
            Err(_) => return NameSnapshot::Unreadable,
        };
        if count == cap {
            return NameSnapshot::OverCap;
        }
        count += 1;
        names.insert(name.as_encoded_bytes().into());
    }
    NameSnapshot::Names {
        names,
        entries: count,
    }
}

fn from_metadata(metadata: &fs::Metadata) -> Seen {
    let kind = metadata.file_type();
    if kind.is_dir() {
        Seen::Dir(dir_stat(metadata))
    } else if kind.is_file() {
        Seen::File(FileSeen {
            stat: file_stat(metadata),
            read_hash: ReadHash::NotNeeded,
        })
    } else {
        Seen::Special
    }
}

/// What `path` holds now, as the run first looks at it. A symbolic link also records what it
/// resolves to, unless `follow` is false (proc, sys and dev names are not resolved here).
pub fn observe(path: &Path, follow: bool) -> Seen {
    match fs::symlink_metadata(path) {
        Err(error) if is_absent(&error) => Seen::Absent,
        Err(_) => Seen::Unreadable,
        Ok(metadata) if metadata.file_type().is_symlink() => {
            let Ok(target) = fs::read_link(path) else {
                return Seen::Unreadable;
            };
            let (followed, resolved) = if follow {
                let followed = match fs::metadata(path) {
                    Ok(resolved) => from_metadata(&resolved),
                    Err(error) if is_absent(&error) => Seen::Absent,
                    Err(_) => Seen::Unreadable,
                };
                (followed, fs::canonicalize(path).ok())
            } else {
                (Seen::Unreadable, None)
            };
            Seen::Symlink {
                target: target.into_os_string(),
                followed: Box::new(followed),
                resolved,
            }
        }
        Ok(metadata) => from_metadata(&metadata),
    }
}

fn needs_hash(file: &FileSeen, now: i128) -> bool {
    file.read_hash == ReadHash::NotNeeded && racy(file.stat.mtime_ns, file.stat.ctime_ns, now)
}

/// Hash an opened regular file only when its full stat matches `expected` before and after the read.
pub(crate) fn hash_bound(path: &Path, expected: &FileStat, budget: &mut ReadBudget) -> ReadHash {
    if budget.hashed > READ_HASH_BUDGET {
        return ReadHash::OverBudget;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    #[cfg(windows)]
    options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    let Ok(file) = options.open(path) else {
        return ReadHash::Unhashable;
    };
    hash_opened(&file, &file, expected, budget)
}

/// Hash bytes from the opened descriptor, requiring the full captured stat on both sides.
fn hash_opened<R: Read>(
    file: &fs::File,
    mut reader: R,
    expected: &FileStat,
    budget: &mut ReadBudget,
) -> ReadHash {
    let Ok(before) = file.metadata() else {
        return ReadHash::Unhashable;
    };
    if !before.is_file() || file_stat(&before) != *expected {
        return ReadHash::Moved;
    }
    let remaining = READ_HASH_BUDGET.saturating_sub(budget.hashed);
    let mut consumed = 0_u64;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let limit = (remaining + 1 - consumed).min(buffer.len() as u64) as usize;
        let n = match reader.read(&mut buffer[..limit]) {
            Ok(n) => n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return ReadHash::Unhashable,
        };
        if n == 0 {
            break;
        }
        consumed += n as u64;
        budget.hashed = budget.hashed.saturating_add(n as u64);
        if consumed > remaining {
            return ReadHash::OverBudget;
        }
        hasher.update(&buffer[..n]);
    }
    let Ok(after) = file.metadata() else {
        return ReadHash::Unhashable;
    };
    if !after.is_file() || file_stat(&after) != *expected || consumed != expected.size {
        return ReadHash::Moved;
    }
    ReadHash::Hashed(hasher.finalize().to_hex().to_string())
}

/// At a read stop for `path`, hash its bytes if the file is racy and not yet hashed. A symbolic
/// link hashes what it resolved to. Returns whether a hash was taken.
pub fn hash_racy_at_read(seen: &mut Seen, path: &Path, now: i128, budget: &mut ReadBudget) -> bool {
    match seen {
        Seen::File(file) if needs_hash(file, now) => {
            file.read_hash = hash_bound(path, &file.stat, budget);
            matches!(file.read_hash, ReadHash::Hashed(_))
        }
        Seen::Symlink {
            followed,
            resolved: Some(target),
            ..
        } => match followed.as_mut() {
            Seen::File(file) if needs_hash(file, now) => {
                file.read_hash = hash_bound(target.as_path(), &file.stat, budget);
                matches!(file.read_hash, ReadHash::Hashed(_))
            }
            _ => false,
        },
        _ => false,
    }
}

/// Check the first-seen identity at a later stop, charging any repeat hash to the run's budget.
/// Unreadable or special paths cannot establish that the first identity still holds.
pub fn still_holds(seen: &Seen, path: &Path, budget: &mut ReadBudget) -> bool {
    let current = observe(path, true);
    match (seen, &current) {
        (Seen::Absent, Seen::Absent) => true,
        (Seen::Dir(before), Seen::Dir(now)) => before == now,
        (Seen::File(before), Seen::File(now)) if before.stat == now.stat => {
            match &before.read_hash {
                ReadHash::NotNeeded => true,
                ReadHash::Hashed(expected) => {
                    matches!(hash_bound(path, &before.stat, budget), ReadHash::Hashed(actual) if actual == *expected)
                }
                ReadHash::OverBudget | ReadHash::Unhashable | ReadHash::Moved => false,
            }
        }
        (
            Seen::Symlink {
                target,
                followed,
                resolved,
            },
            Seen::Symlink {
                target: now_target,
                followed: now_followed,
                resolved: now_resolved,
            },
        ) if target == now_target
            && resolved == now_resolved
            && snapshot_matches(followed, now_followed) =>
        {
            let held = match (followed.as_ref(), resolved.as_deref()) {
                (Seen::Absent, None) => true,
                (Seen::File(_) | Seen::Dir(_), Some(destination)) => {
                    still_holds(followed, destination, budget)
                }
                _ => false,
            };
            held && matches!(
                observe(path, true),
                Seen::Symlink {
                    target: later_target,
                    followed: later_followed,
                    resolved: later_resolved,
                } if *target == later_target
                    && *resolved == later_resolved
                    && snapshot_matches(followed, &later_followed)
            )
        }
        _ => false,
    }
}

/// Match the non-symlink target states that an observed link can safely resolve to.
fn snapshot_matches(before: &Seen, now: &Seen) -> bool {
    match (before, now) {
        (Seen::Absent, Seen::Absent) => true,
        (Seen::File(before), Seen::File(now)) => before.stat == now.stat,
        (Seen::Dir(before), Seen::Dir(now)) => before == now,
        _ => false,
    }
}

/// Whether the state `now` holds is the state `before` recorded, for the parts a read depends on.
/// Directories are judged by the listing rules, so a directory always passes here.
pub fn same_identity(before: &Seen, now: &Seen) -> bool {
    match (before, now) {
        (Seen::Absent, Seen::Absent)
        | (Seen::Unreadable, Seen::Unreadable)
        | (Seen::Special, Seen::Special)
        | (Seen::Dir(_), Seen::Dir(_)) => true,
        (Seen::File(a), Seen::File(b)) => a.stat == b.stat,
        (
            Seen::Symlink {
                target: a,
                followed: followed_a,
                resolved: resolved_a,
                ..
            },
            Seen::Symlink {
                target: b,
                followed: followed_b,
                resolved: resolved_b,
                ..
            },
        ) => a == b && resolved_a == resolved_b && same_identity(followed_a, followed_b),
        _ => false,
    }
}

fn compare_file(seen: &FileSeen, stat: &FileStat, hash: &str) -> Result<(), Refusal> {
    match &seen.read_hash {
        ReadHash::OverBudget => Err(Refusal::OverBudget),
        ReadHash::Unhashable => Err(Refusal::Unhashable),
        ReadHash::Moved => Err(Refusal::Changed),
        ReadHash::Hashed(before) => {
            let same = seen.stat == *stat && before == hash;
            if same {
                Ok(())
            } else {
                Err(Refusal::Changed)
            }
        }
        ReadHash::NotNeeded if seen.stat == *stat => Ok(()),
        ReadHash::NotNeeded => Err(Refusal::Changed),
    }
}

/// Compare a listed directory with its state after the run. With a snapshot, the entries that
/// differ must all be names the run itself changed; without one, the directory's stat must be
/// unchanged.
fn compare_listing(
    listed: &ListSeen,
    stat: &DirSeen,
    names: Option<&Names>,
    own: &Names,
) -> Result<(), Refusal> {
    let same = match (&listed.names, names) {
        (Some(before), Some(now)) => before
            .symmetric_difference(now)
            .all(|name| own.contains(name)),
        (Some(_), None) => false,
        (None, _) => listed.stat == *stat,
    };
    if same {
        Ok(())
    } else {
        Err(Refusal::Changed)
    }
}

/// Compare what a path held at its first look with what it holds after the run. For a listed
/// directory, `listing` carries the listing and the names the run itself changed in it.
pub fn compare(
    seen: &Seen,
    post: &Post,
    listing: Option<(&ListSeen, &Names)>,
) -> Result<(), Refusal> {
    match (seen, post) {
        (Seen::Absent, Post::Absent)
        | (Seen::Unreadable, Post::Unreadable)
        | (Seen::Special, Post::Special) => Ok(()),
        (Seen::File(file), Post::File { stat, hash }) => compare_file(file, stat, hash),
        (Seen::Dir(_), Post::Dir { stat, names }) => match listing {
            None => Ok(()),
            Some((listed, own)) => compare_listing(listed, stat, names.as_ref(), own),
        },
        (Seen::Symlink { target, .. }, Post::Symlink { target: now }) if target == now => Ok(()),
        _ => Err(Refusal::Changed),
    }
}

/// Whether a watched name still holds what it held before the command ran. Watched names are
/// small and compared by stat; a racy one is compared by its bytes.
pub fn watched_matches(seen: &Seen, path: &Path) -> bool {
    match (seen, fs::symlink_metadata(path)) {
        (Seen::File(file), Ok(metadata))
            if metadata.is_file() && file.read_hash == ReadHash::NotNeeded =>
        {
            file_stat(&metadata) == file.stat
        }
        (Seen::Dir(_), Ok(metadata)) => metadata.is_dir(),
        (Seen::Symlink { target, .. }, Ok(metadata)) if metadata.file_type().is_symlink() => {
            fs::read_link(path).is_ok_and(|now| now.as_os_str() == target)
        }
        (Seen::Absent, Err(error)) => is_absent(&error),
        _ => {
            let (_, post) = crate::input::identify_post(path, true, false, false);
            compare(seen, &post, None).is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i128 = 10_000_000_000_000;

    fn stat(mtime_ns: i128, ctime_ns: i128) -> FileStat {
        FileStat {
            dev: 1,
            ino: 2,
            size: 3,
            mtime_ns,
            ctime_ns,
            mode: 0o644,
        }
    }

    fn file(stat: FileStat, read_hash: ReadHash) -> Seen {
        Seen::File(FileSeen { stat, read_hash })
    }

    fn post(stat: FileStat, hash: &str) -> Post {
        Post::File {
            stat,
            hash: hash.into(),
        }
    }

    #[test]
    fn racy_includes_the_boundary_and_the_future() {
        let edge = NOW - RACY_WINDOW_NS;
        assert!(racy(edge, 0, NOW));
        assert!(racy(0, edge, NOW));
        assert!(!racy(edge - 1, edge - 1, NOW));
        assert!(racy(NOW + 60_000_000_000, 0, NOW));
        assert!(racy(0, NOW + 60_000_000_000, NOW));
    }

    #[test]
    fn a_file_compares_field_by_field_when_nothing_was_hashed() {
        let base = stat(NOW - 100 * RACY_WINDOW_NS, NOW - 100 * RACY_WINDOW_NS);
        let seen = match file(base, ReadHash::NotNeeded) {
            Seen::File(f) => f,
            _ => unreachable!(),
        };
        assert!(compare_file(&seen, &base, "h").is_ok());
        for changed in [
            FileStat { dev: 9, ..base },
            FileStat { ino: 9, ..base },
            FileStat { size: 9, ..base },
            FileStat {
                mtime_ns: base.mtime_ns + 1,
                ..base
            },
            FileStat {
                ctime_ns: base.ctime_ns + 1,
                ..base
            },
            FileStat {
                mode: 0o755,
                ..base
            },
        ] {
            assert_eq!(
                compare_file(&seen, &changed, "h"),
                Err(Refusal::Changed),
                "{changed:?}"
            );
        }
    }

    #[test]
    fn a_hashed_file_requires_both_the_bytes_and_every_stat_field() {
        let base = stat(NOW, NOW);
        let seen = FileSeen {
            stat: base,
            read_hash: ReadHash::Hashed("abc".into()),
        };
        assert!(compare_file(&seen, &base, "abc").is_ok());
        assert_eq!(compare_file(&seen, &base, "abd"), Err(Refusal::Changed));
        for changed in [
            FileStat { dev: 9, ..base },
            FileStat { ino: 9, ..base },
            FileStat { size: 9, ..base },
            FileStat {
                mtime_ns: base.mtime_ns + 1,
                ..base
            },
            // Restored bytes and mtime cannot hide a changed ctime.
            FileStat {
                ctime_ns: base.ctime_ns + 1,
                ..base
            },
            FileStat {
                mode: 0o755,
                ..base
            },
        ] {
            assert_eq!(
                compare_file(&seen, &changed, "abc"),
                Err(Refusal::Changed),
                "{changed:?}"
            );
        }
        let moved = FileSeen {
            stat: base,
            read_hash: ReadHash::Moved,
        };
        assert_eq!(compare_file(&moved, &base, "abc"), Err(Refusal::Changed));
    }

    #[test]
    fn a_budget_refusal_is_never_a_pass() {
        let base = stat(NOW, NOW);
        let seen = match file(base, ReadHash::OverBudget) {
            Seen::File(f) => f,
            _ => unreachable!(),
        };
        assert_eq!(compare_file(&seen, &base, "x"), Err(Refusal::OverBudget));
    }

    #[test]
    fn a_post_state_of_another_kind_is_a_change() {
        let base = stat(NOW, NOW);
        let seen = file(base, ReadHash::NotNeeded);
        assert_eq!(compare(&seen, &Post::Absent, None), Err(Refusal::Changed));
        assert_eq!(
            compare(
                &seen,
                &Post::Dir {
                    stat: dir(),
                    names: None
                },
                None
            ),
            Err(Refusal::Changed)
        );
        assert_eq!(
            compare(&Seen::Absent, &post(base, "h"), None),
            Err(Refusal::Changed)
        );
        assert!(compare(&Seen::Absent, &Post::Absent, None).is_ok());
        assert!(compare(&Seen::Special, &Post::Special, None).is_ok());
    }

    fn dir() -> DirSeen {
        DirSeen {
            dev: 1,
            ino: 4,
            mtime_ns: NOW,
            ctime_ns: NOW,
        }
    }

    fn names(list: &[&str]) -> Names {
        list.iter()
            .map(|n| Box::<[u8]>::from(n.as_bytes()))
            .collect()
    }

    #[test]
    fn a_listing_passes_when_only_the_runs_own_names_differ() {
        let listed = ListSeen {
            stat: dir(),
            names: Some(names(&["a", "b"])),
        };
        let own = names(&["out"]);
        let with_own = names(&["a", "b", "out"]);
        assert!(compare_listing(&listed, &dir(), Some(&with_own), &own).is_ok());
        let foreign = names(&["a", "b", "new"]);
        assert_eq!(
            compare_listing(&listed, &dir(), Some(&foreign), &own),
            Err(Refusal::Changed)
        );
        let removed = names(&["a"]);
        assert_eq!(
            compare_listing(&listed, &dir(), Some(&removed), &own),
            Err(Refusal::Changed)
        );
    }

    #[test]
    fn a_listing_without_names_compares_the_directory_stat() {
        let listed = ListSeen {
            stat: dir(),
            names: None,
        };
        assert!(compare_listing(&listed, &dir(), None, &Names::new()).is_ok());
        let touched = DirSeen {
            mtime_ns: NOW + 1,
            ..dir()
        };
        assert_eq!(
            compare_listing(&listed, &touched, None, &Names::new()),
            Err(Refusal::Changed)
        );
    }

    #[test]
    fn a_symlink_compares_its_target_text() {
        let seen = Seen::Symlink {
            target: "a".into(),
            followed: Box::new(Seen::Absent),
            resolved: None,
        };
        let same = Post::Symlink { target: "a".into() };
        let retargeted = Post::Symlink { target: "b".into() };
        assert!(compare(&seen, &same, None).is_ok());
        assert_eq!(compare(&seen, &retargeted, None), Err(Refusal::Changed));
        assert_eq!(compare(&seen, &Post::Absent, None), Err(Refusal::Changed));
    }

    #[test]
    fn a_symlink_read_compares_what_it_resolved_to() {
        let link = |resolved: Option<&str>| Seen::Symlink {
            target: "a".into(),
            followed: Box::new(Seen::Absent),
            resolved: resolved.map(PathBuf::from),
        };
        assert!(same_identity(&link(Some("/r/a")), &link(Some("/r/a"))));
        assert!(!same_identity(&link(Some("/r/a")), &link(Some("/r/b"))));
        assert!(!same_identity(&link(None), &link(Some("/r/a"))));
        assert!(same_identity(&Seen::Absent, &Seen::Absent));
        assert!(!same_identity(&Seen::Absent, &Seen::Special));
    }

    #[test]
    fn a_read_stop_hashes_only_a_racy_file() {
        let dir = std::env::temp_dir().join(format!("stoop-identity-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let metadata = fs::metadata(&path).unwrap();
        let recent = file_stat(&metadata);
        let now = recent.mtime_ns.max(recent.ctime_ns);
        let mut budget = ReadBudget::default();

        let mut aged = observe(&path, true);
        assert!(!hash_racy_at_read(
            &mut aged,
            &path,
            now + 10 * RACY_WINDOW_NS,
            &mut budget
        ));
        assert_eq!(budget.hashed, 0);

        let mut racy_seen = observe(&path, true);
        assert!(hash_racy_at_read(&mut racy_seen, &path, now, &mut budget));
        assert_eq!(budget.hashed, 5);
        match racy_seen {
            Seen::File(file) => assert!(matches!(file.read_hash, ReadHash::Hashed(_))),
            _ => panic!("a regular file"),
        }

        let mut over = observe(&path, true);
        budget.hashed = READ_HASH_BUDGET;
        assert!(!hash_racy_at_read(&mut over, &path, now, &mut budget));
        match over {
            Seen::File(file) => assert_eq!(file.read_hash, ReadHash::OverBudget),
            _ => panic!("a regular file"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    fn test_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("stoop-identity-{}-{name}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn replacement_before_open_is_reported_as_moved() {
        let dir = test_dir("replaced");
        let path = dir.join("payload");
        let replacement = dir.join("replacement");
        fs::write(&path, b"old").unwrap();
        let mut seen = observe(&path, true);
        let now = match &seen {
            Seen::File(file) => file.stat.mtime_ns.max(file.stat.ctime_ns),
            _ => panic!("a regular file"),
        };
        fs::write(&replacement, b"new").unwrap();
        fs::rename(&replacement, &path).unwrap();

        let mut budget = ReadBudget::default();
        assert!(!hash_racy_at_read(&mut seen, &path, now, &mut budget));
        assert!(matches!(
            seen,
            Seen::File(FileSeen {
                read_hash: ReadHash::Moved,
                ..
            })
        ));
        assert_eq!(budget.hashed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_replacement_symlink_is_not_followed_for_hashing() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("symlink");
        let path = dir.join("payload");
        let original = dir.join("original");
        fs::write(&path, b"bytes").unwrap();
        fs::rename(&path, &original).unwrap();
        let expected = file_stat(&fs::metadata(&original).unwrap());
        symlink(&original, &path).unwrap();

        let mut budget = ReadBudget::default();
        assert_eq!(
            hash_bound(&path, &expected, &mut budget),
            ReadHash::Unhashable
        );
        assert_eq!(budget.hashed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn changed_metadata_before_hashing_refuses_without_reading() {
        let dir = test_dir("changed-stat");
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let mut expected = file_stat(&fs::metadata(&path).unwrap());
        expected.mtime_ns -= 1;
        let mut budget = ReadBudget::default();

        assert_eq!(hash_bound(&path, &expected, &mut budget), ReadHash::Moved);
        assert_eq!(budget.hashed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    struct AppendOnRead<'a> {
        file: &'a fs::File,
        path: &'a Path,
        consumed: &'a std::cell::Cell<u64>,
        appended: bool,
    }

    impl Read for AppendOnRead<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            use std::io::Write;

            if !self.appended {
                fs::OpenOptions::new()
                    .append(true)
                    .open(self.path)?
                    .write_all(b"defghi")?;
                self.appended = true;
            }
            let n = self.file.read(buffer)?;
            self.consumed.set(self.consumed.get() + n as u64);
            Ok(n)
        }
    }

    #[test]
    fn growing_past_the_remaining_budget_reads_only_the_extra_byte() {
        let dir = test_dir("grows-over-budget");
        let path = dir.join("payload");
        fs::write(&path, b"abc").unwrap();
        let file = fs::File::open(&path).unwrap();
        let expected = file_stat(&file.metadata().unwrap());
        let consumed = std::cell::Cell::new(0);
        let reader = AppendOnRead {
            file: &file,
            path: &path,
            consumed: &consumed,
            appended: false,
        };
        let mut budget = ReadBudget {
            hashed: READ_HASH_BUDGET - expected.size,
            ..ReadBudget::default()
        };

        assert_eq!(
            hash_opened(&file, reader, &expected, &mut budget),
            ReadHash::OverBudget
        );
        assert_eq!(consumed.get(), expected.size + 1);
        assert_eq!(budget.hashed, READ_HASH_BUDGET + 1);
        let now = file_stat(&file.metadata().unwrap());
        assert_eq!(hash_bound(&path, &now, &mut budget), ReadHash::OverBudget);
        assert_eq!(budget.hashed, READ_HASH_BUDGET + 1);
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn growth_within_the_budget_fails_the_post_read_stat_check() {
        let dir = test_dir("grows-within-budget");
        let path = dir.join("payload");
        fs::write(&path, b"abc").unwrap();
        let file = fs::File::open(&path).unwrap();
        let expected = file_stat(&file.metadata().unwrap());
        let consumed = std::cell::Cell::new(0);
        let reader = AppendOnRead {
            file: &file,
            path: &path,
            consumed: &consumed,
            appended: false,
        };
        let mut budget = ReadBudget::default();

        assert_eq!(
            hash_opened(&file, reader, &expected, &mut budget),
            ReadHash::Moved
        );
        assert_eq!(consumed.get(), 9);
        assert_eq!(budget.hashed, 9);
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn restored_bytes_with_changed_metadata_fail_the_post_read_stat_check() {
        struct RewriteAndRestore<'a> {
            file: &'a fs::File,
            path: &'a Path,
            modified: SystemTime,
            done: bool,
        }
        impl Read for RewriteAndRestore<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if !self.done {
                    fs::write(self.path, b"other")?;
                    fs::write(self.path, b"bytes")?;
                    fs::OpenOptions::new()
                        .write(true)
                        .open(self.path)?
                        .set_modified(self.modified)?;
                    self.done = true;
                }
                self.file.read(buffer)
            }
        }
        let dir = test_dir("rewrite-restore");
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let file = fs::File::open(&path).unwrap();
        let expected = file_stat(&file.metadata().unwrap());
        let seconds = if expected.mtime_ns == 1_000_000_000 {
            2
        } else {
            1
        };
        let reader = RewriteAndRestore {
            file: &file,
            path: &path,
            modified: UNIX_EPOCH + std::time::Duration::from_secs(seconds),
            done: false,
        };
        let mut budget = ReadBudget::default();

        assert_eq!(
            hash_opened(&file, reader, &expected, &mut budget),
            ReadHash::Moved
        );
        assert_eq!(budget.hashed, expected.size);
        assert_eq!(fs::read(&path).unwrap(), b"bytes");
        assert_ne!(
            file_stat(&file.metadata().unwrap()).mtime_ns,
            expected.mtime_ns
        );
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hashing_exactly_the_remaining_budget_succeeds() {
        let dir = test_dir("exact-budget");
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let expected = file_stat(&fs::metadata(&path).unwrap());
        let mut budget = ReadBudget {
            hashed: READ_HASH_BUDGET - expected.size,
            ..ReadBudget::default()
        };

        assert_eq!(
            hash_bound(&path, &expected, &mut budget),
            ReadHash::Hashed(blake3::hash(b"bytes").to_hex().to_string())
        );
        assert_eq!(budget.hashed, READ_HASH_BUDGET);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn failed_hashes_charge_bytes_already_read() {
        struct FailAfterRead<'a> {
            file: &'a fs::File,
            used: bool,
        }
        impl Read for FailAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.used {
                    return Err(io::Error::from(io::ErrorKind::PermissionDenied));
                }
                self.used = true;
                let length = buffer.len().min(2);
                self.file.read(&mut buffer[..length])
            }
        }
        let dir = test_dir("read-error");
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let file = fs::File::open(&path).unwrap();
        let expected = file_stat(&file.metadata().unwrap());
        let reader = FailAfterRead {
            file: &file,
            used: false,
        };
        let mut budget = ReadBudget::default();

        assert_eq!(
            hash_opened(&file, reader, &expected, &mut budget),
            ReadHash::Unhashable
        );
        assert_eq!(budget.hashed, 2);
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn capped_snapshot_stops_at_the_first_entry_over_the_limit() {
        let visited = std::cell::Cell::new(0);
        let entries = (0..).map(|index| {
            assert!(index < 3, "the iterator was read beyond cap + 1");
            visited.set(visited.get() + 1);
            Ok(OsString::from(format!("name-{index}")))
        });
        assert_eq!(take_names(entries, 2), NameSnapshot::OverCap);
        assert_eq!(visited.get(), 3);

        let repeated = ["same", "same", "third"]
            .into_iter()
            .map(|name| Ok(OsString::from(name)));
        assert_eq!(take_names(repeated, 2), NameSnapshot::OverCap);
        let repeated = ["same", "same"]
            .into_iter()
            .map(|name| Ok(OsString::from(name)));
        assert_eq!(
            take_names(repeated, 2),
            NameSnapshot::Names {
                names: names(&["same"]),
                entries: 2,
            }
        );
    }

    #[test]
    fn capped_snapshot_accepts_exact_limit_and_distinguishes_errors() {
        let dir = test_dir("names");
        fs::write(dir.join("b"), b"").unwrap();
        fs::write(dir.join("a"), b"").unwrap();
        assert_eq!(
            read_names_capped(&dir, 2),
            NameSnapshot::Names {
                names: names(&["a", "b"]),
                entries: 2,
            }
        );
        assert_eq!(read_names_capped(&dir, 1), NameSnapshot::OverCap);
        assert_eq!(read_names_capped(&dir, 0), NameSnapshot::OverCap);
        assert_eq!(
            read_names_capped(&dir.join("missing"), 2),
            NameSnapshot::Unreadable
        );
        let entries = vec![
            Ok(OsString::from("a")),
            Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        ];
        assert_eq!(take_names(entries, 2), NameSnapshot::Unreadable);
        assert_eq!(
            take_names(std::iter::empty::<io::Result<OsString>>(), 0),
            NameSnapshot::Names {
                names: Names::new(),
                entries: 0,
            }
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn still_holds_checks_absence_and_full_directory_stat() {
        let dir = test_dir("still-holds-directory");
        let missing = dir.join("missing");
        let mut budget = ReadBudget::default();
        assert!(still_holds(&Seen::Absent, &missing, &mut budget));
        fs::write(&missing, b"bytes").unwrap();
        assert!(!still_holds(&Seen::Absent, &missing, &mut budget));

        let directory = observe(&dir, true);
        assert!(still_holds(&directory, &dir, &mut budget));
        let Seen::Dir(stat) = directory else {
            panic!("a directory");
        };
        let moved = Seen::Dir(DirSeen {
            ctime_ns: stat.ctime_ns + 1,
            ..stat
        });
        assert!(!still_holds(&moved, &dir, &mut budget));
        assert!(!still_holds(&Seen::Unreadable, &dir, &mut budget));
        assert!(!still_holds(&Seen::Special, &dir, &mut budget));
        assert_eq!(budget.hashed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn still_holds_hashes_within_the_remaining_budget_and_fails_closed() {
        let dir = test_dir("still-holds-file");
        let path = dir.join("payload");
        fs::write(&path, b"bytes").unwrap();
        let stat = file_stat(&fs::metadata(&path).unwrap());
        let hash = blake3::hash(b"bytes").to_hex().to_string();
        let seen = file(stat, ReadHash::Hashed(hash));
        let mut budget = ReadBudget {
            hashed: READ_HASH_BUDGET - stat.size,
            ..ReadBudget::default()
        };
        assert!(still_holds(&seen, &path, &mut budget));
        assert_eq!(budget.hashed, READ_HASH_BUDGET);
        assert!(!still_holds(&seen, &path, &mut budget));
        assert_eq!(budget.hashed, READ_HASH_BUDGET + 1);
        assert!(!still_holds(&seen, &path, &mut budget));
        assert_eq!(budget.hashed, READ_HASH_BUDGET + 1);

        let mut budget = ReadBudget::default();
        let wrong = file(stat, ReadHash::Hashed("different".into()));
        assert!(!still_holds(&wrong, &path, &mut budget));
        assert_eq!(budget.hashed, stat.size);
        let stale = file(
            FileStat {
                ctime_ns: stat.ctime_ns + 1,
                ..stat
            },
            ReadHash::NotNeeded,
        );
        assert!(!still_holds(&stale, &path, &mut budget));
        for reason in [ReadHash::OverBudget, ReadHash::Unhashable, ReadHash::Moved] {
            assert!(!still_holds(&file(stat, reason), &path, &mut budget));
        }
        assert_eq!(budget.hashed, stat.size);
        assert!(still_holds(
            &file(stat, ReadHash::NotNeeded),
            &path,
            &mut budget
        ));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn still_holds_checks_symlink_route_and_followed_identity() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("still-holds-link");
        let target = dir.join("payload");
        let replacement = dir.join("replacement");
        let link = dir.join("link");
        fs::write(&target, b"bytes").unwrap();
        symlink("payload", &link).unwrap();
        let mut seen = observe(&link, true);
        let now = match &seen {
            Seen::Symlink { followed, .. } => match followed.as_ref() {
                Seen::File(file) => file.stat.mtime_ns.max(file.stat.ctime_ns),
                _ => panic!("a link to a regular file"),
            },
            _ => panic!("a symbolic link"),
        };
        let mut budget = ReadBudget::default();
        assert!(hash_racy_at_read(&mut seen, &link, now, &mut budget));
        let mut budget = ReadBudget::default();
        assert!(still_holds(&seen, &link, &mut budget));
        assert_eq!(budget.hashed, 5);
        fs::write(&replacement, b"other").unwrap();
        fs::rename(&replacement, &target).unwrap();
        assert!(!still_holds(&seen, &link, &mut budget));

        let unresolved = observe(&link, false);
        assert!(!still_holds(&unresolved, &link, &mut budget));
        let new_target = dir.join("new-target");
        fs::write(&new_target, b"bytes").unwrap();
        fs::remove_file(&link).unwrap();
        symlink("new-target", &link).unwrap();
        assert!(!still_holds(&seen, &link, &mut budget));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn still_holds_tracks_a_dangling_link_becoming_present() {
        use std::os::unix::fs::symlink;

        let dir = test_dir("still-holds-dangling");
        let target = dir.join("missing");
        let link = dir.join("link");
        symlink("missing", &link).unwrap();
        let seen = observe(&link, true);
        let mut budget = ReadBudget::default();
        assert!(still_holds(&seen, &link, &mut budget));
        fs::write(&target, b"bytes").unwrap();
        assert!(!still_holds(&seen, &link, &mut budget));
        assert_eq!(budget.hashed, 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}
