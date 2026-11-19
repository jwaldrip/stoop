//! Read-time identity: what a path held when a traced command first looked at it, and what it
//! holds once the command has exited. A difference means the command may have read something
//! other than the bytes the record will describe, so the run is not recorded.
//!
//! The types and comparisons are plain data and compile on every platform, so their unit tests
//! run on every CI runner. Only the Linux tracer takes captures.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::oid_attrs::is_absent;
use crate::pathutil::absolutize;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Git's racy-clean rule: a file changed this recently may change again without its stat data
/// changing, so its bytes are compared as well. A timestamp in the future counts as recent.
pub const RACY_WINDOW_NS: i128 = 2_000_000_000;
/// Bytes hashed at read stops in one run. Past it a racy file refuses the record.
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
        /// The links the path passes through on its way to what it names (see `link_hops`).
        hops: Vec<PathBuf>,
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

/// Bytes hashed at read stops in one run, and the debug lines printed about them.
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
                hops: if follow { link_hops(path) } else { Vec::new() },
            }
        }
        Ok(metadata) => from_metadata(&metadata),
    }
}

/// The symbolic links a path passes through on its way to what it names, in order. The path itself
/// and the final target are not included. A run that writes one of them has changed what the path
/// resolves to, so that change is the run's own.
fn link_hops(path: &Path) -> Vec<PathBuf> {
    let mut hops = Vec::new();
    let mut current = path.to_path_buf();
    while hops.len() < 40 {
        let Ok(target) = fs::read_link(&current) else {
            break;
        };
        let parent = current.parent().unwrap_or(Path::new("/"));
        let next = absolutize(parent, &target);
        if !fs::symlink_metadata(&next).is_ok_and(|m| m.file_type().is_symlink()) {
            break;
        }
        hops.push(next.clone());
        current = next;
    }
    hops
}

fn needs_hash(file: &FileSeen, now: i128) -> bool {
    file.read_hash == ReadHash::NotNeeded && racy(file.stat.mtime_ns, file.stat.ctime_ns, now)
}

/// Hash a racy file the run is reading now, charging its size to the budget.
fn hash_at_read(path: &Path, size: u64, budget: &mut ReadBudget) -> ReadHash {
    if budget.hashed.saturating_add(size) > READ_HASH_BUDGET {
        return ReadHash::OverBudget;
    }
    match crate::input::hash_file(path) {
        Ok(hash) => {
            budget.hashed += size;
            ReadHash::Hashed(hash)
        }
        Err(_) => ReadHash::Unhashable,
    }
}

/// At a read stop for `path`, hash its bytes if the file is racy and not yet hashed. A symbolic
/// link hashes what it resolved to. Returns whether a hash was taken.
pub fn hash_racy_at_read(seen: &mut Seen, path: &Path, now: i128, budget: &mut ReadBudget) -> bool {
    match seen {
        Seen::File(file) if needs_hash(file, now) => {
            file.read_hash = hash_at_read(path, file.stat.size, budget);
            matches!(file.read_hash, ReadHash::Hashed(_))
        }
        Seen::Symlink {
            followed,
            resolved: Some(target),
            ..
        } => match followed.as_mut() {
            Seen::File(file) if needs_hash(file, now) => {
                file.read_hash = hash_at_read(target.as_path(), file.stat.size, budget);
                matches!(file.read_hash, ReadHash::Hashed(_))
            }
            _ => false,
        },
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
        ReadHash::Hashed(before) => {
            let same = (seen.stat.dev, seen.stat.ino, seen.stat.mode)
                == (stat.dev, stat.ino, stat.mode)
                && before == hash;
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
    fn a_hashed_file_compares_bytes_and_ignores_timestamps() {
        let base = stat(NOW, NOW);
        let seen = match file(base, ReadHash::Hashed("abc".into())) {
            Seen::File(f) => f,
            _ => unreachable!(),
        };
        let touched = FileStat {
            mtime_ns: NOW + 5,
            ctime_ns: NOW + 5,
            ..base
        };
        assert!(compare_file(&seen, &touched, "abc").is_ok());
        assert_eq!(compare_file(&seen, &base, "abd"), Err(Refusal::Changed));
        assert_eq!(
            compare_file(&seen, &FileStat { ino: 7, ..base }, "abc"),
            Err(Refusal::Changed)
        );
        assert_eq!(
            compare_file(
                &seen,
                &FileStat {
                    mode: 0o755,
                    ..base
                },
                "abc"
            ),
            Err(Refusal::Changed)
        );
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
            hops: Vec::new(),
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
            hops: Vec::new(),
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
}
