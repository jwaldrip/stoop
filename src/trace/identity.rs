//! Read-time identity for the candidate inputs of a recorded run.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const RACY_WINDOW_NS: i128 = 2_000_000_000;
pub const READ_HASH_BUDGET: u64 = 1 << 30;
pub const MAX_LISTED_NAMES: usize = 1 << 20;
pub type Names = BTreeSet<Box<[u8]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStat {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirSeen {
    pub dev: u64,
    pub ino: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkSeen {
    pub dev: u64,
    pub ino: u64,
    pub ctime_ns: i128,
    pub target: OsString,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadHash {
    NotNeeded,
    Hashed(String),
    /// The bounded read or either identity check failed; compare stat only.
    StatOnly,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Seen {
    Absent,
    Unreadable,
    Special,
    File(FileStat, ReadHash),
    Dir(DirSeen),
    Symlink(LinkSeen),
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub seen: Seen,
    pub route_physical: bool,
    pub appeared: bool,
}

#[derive(Clone, Debug)]
pub struct ListSeen {
    pub stat: DirSeen,
    pub names: Option<Names>,
}

#[derive(Default)]
pub struct Footprint {
    pub entries: HashSet<PathBuf>,
    /// Directory inodes containing names the command may have changed.
    pub parent_inodes: HashSet<(u64, u64)>,
    pub inodes: HashSet<(u64, u64)>,
    /// A directory permission or ownership change may hide descendants through an alias.
    pub access_changed: bool,
    /// A hard link was made while another traced task was alive.
    pub link_with_live_task: bool,
    /// A directory was exchanged or renamed, or a rename could not be classified.
    pub dir_swap_seen: bool,
    pub unknown: bool,
}

#[derive(Clone, Debug)]
pub enum Post {
    Absent,
    Unreadable,
    Special,
    File {
        stat: FileStat,
        hash: String,
    },
    /// The file can be stated, but its contents cannot be read.
    FileStat(FileStat),
    Dir {
        stat: DirSeen,
        names: Option<Names>,
    },
    Symlink(LinkSeen),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    NotObserved,
    Route,
    Unknown,
    OwnPath,
    OwnEntries,
    OwnInode,
    OwnAccess,
}

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

pub fn link_stat(metadata: &fs::Metadata, target: OsString) -> LinkSeen {
    let stat = file_stat(metadata);
    LinkSeen {
        dev: stat.dev,
        ino: stat.ino,
        ctime_ns: stat.ctime_ns,
        target,
    }
}

/// Read at most cap plus one directory entries, returning no snapshot on failure or overflow.
pub fn read_names_capped(dir: &Path, cap: usize) -> Option<Names> {
    take_names(
        fs::read_dir(dir)
            .ok()?
            .map(|entry| entry.map(|e| e.file_name())),
        cap,
    )
}

/// Snapshot a directory without advancing its access time. Any failure falls back to stat-only.
#[cfg(target_os = "linux")]
pub fn read_names_quiet(dir: &Path, expected: &DirSeen, cap: usize) -> Option<Names> {
    use std::ffi::CStr;
    use std::os::fd::{FromRawFd, IntoRawFd};

    let mut options = fs::OpenOptions::new();
    options.read(true).custom_flags(
        libc::O_DIRECTORY | libc::O_NOATIME | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
    );
    let file = options.open(dir).ok()?;
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata.is_dir() && dir_stat(&metadata) == *expected)
    {
        return None;
    }
    let fd = file.into_raw_fd();
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        unsafe { libc::close(fd) };
        return None;
    }
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = Stream(stream);
    let mut names = Names::new();
    let mut count = 0;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if unsafe { *libc::__errno_location() } != 0 {
                return None;
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if count == cap {
            return None;
        }
        count += 1;
        names.insert(name.into());
    }
    let borrowed =
        std::mem::ManuallyDrop::new(unsafe { fs::File::from_raw_fd(libc::dirfd(stream.0)) });
    if !borrowed
        .metadata()
        .is_ok_and(|metadata| metadata.is_dir() && dir_stat(&metadata) == *expected)
    {
        return None;
    }
    Some(names)
}

fn take_names<I>(entries: I, cap: usize) -> Option<Names>
where
    I: IntoIterator<Item = io::Result<OsString>>,
{
    let mut names = Names::new();
    for (count, entry) in entries.into_iter().enumerate() {
        let name = entry.ok()?;
        if count == cap {
            return None;
        }
        names.insert(name.as_encoded_bytes().into());
    }
    Some(names)
}

pub fn observe(path: &Path) -> Seen {
    match fs::symlink_metadata(path) {
        Err(error) if crate::oid_attrs::is_absent(&error) => Seen::Absent,
        Err(_) => Seen::Unreadable,
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::read_link(path) {
            Ok(target) => Seen::Symlink(link_stat(&metadata, target.into_os_string())),
            Err(_) => Seen::Unreadable,
        },
        Ok(metadata) if metadata.is_file() => Seen::File(file_stat(&metadata), ReadHash::NotNeeded),
        Ok(metadata) if metadata.is_dir() => Seen::Dir(dir_stat(&metadata)),
        Ok(_) => Seen::Special,
    }
}

/// Hash only an opened regular file whose descriptor retains the first stat throughout the read.
pub fn hash_bound(path: &Path, expected: &FileStat, budget: &mut ReadBudget) -> ReadHash {
    if budget.hashed > READ_HASH_BUDGET {
        return ReadHash::StatOnly;
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOATIME);
    #[cfg(all(unix, not(target_os = "linux")))]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    #[cfg(windows)]
    options.custom_flags(0x0020_0000);
    let Ok(file) = options.open(path) else {
        return ReadHash::StatOnly;
    };
    hash_opened(&file, &file, expected, budget)
}

fn hash_opened<R: Read>(
    file: &fs::File,
    mut reader: R,
    expected: &FileStat,
    budget: &mut ReadBudget,
) -> ReadHash {
    let Ok(before) = file.metadata() else {
        return ReadHash::StatOnly;
    };
    if !before.is_file() || file_stat(&before) != *expected {
        return ReadHash::StatOnly;
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
            Err(_) => return ReadHash::StatOnly,
        };
        if n == 0 {
            break;
        }
        consumed += n as u64;
        budget.hashed = budget.hashed.saturating_add(n as u64);
        if consumed > remaining {
            return ReadHash::StatOnly;
        }
        hasher.update(&buffer[..n]);
    }
    let Ok(after) = file.metadata() else {
        return ReadHash::StatOnly;
    };
    if !after.is_file() || file_stat(&after) != *expected || consumed != expected.size {
        return ReadHash::StatOnly;
    }
    ReadHash::Hashed(hasher.finalize().to_hex().to_string())
}

pub fn hash_racy_at_read(seen: &mut Seen, path: &Path, now: i128, budget: &mut ReadBudget) -> bool {
    if let Seen::File(stat, hash) = seen {
        if *hash == ReadHash::NotNeeded && racy(stat.mtime_ns, stat.ctime_ns, now) {
            *hash = hash_bound(path, stat, budget);
            return matches!(hash, ReadHash::Hashed(_));
        }
    }
    false
}

fn seen_inode(seen: &Seen) -> Option<(u64, u64)> {
    match seen {
        Seen::File(stat, _) => Some((stat.dev, stat.ino)),
        Seen::Dir(stat) => Some((stat.dev, stat.ino)),
        Seen::Symlink(stat) => Some((stat.dev, stat.ino)),
        _ => None,
    }
}

fn post_inode(post: &Post) -> Option<(u64, u64)> {
    match post {
        Post::File { stat, .. } => Some((stat.dev, stat.ino)),
        Post::FileStat(stat) => Some((stat.dev, stat.ino)),
        Post::Dir { stat, .. } => Some((stat.dev, stat.ino)),
        Post::Symlink(stat) => Some((stat.dev, stat.ino)),
        _ => None,
    }
}

/// A hard link made while another task is alive can link the inode that a concurrent directory
/// exchange or rename moved into its path. Either event alone does not redirect a link, so the
/// footprint is unknown only when both occur in the run.
pub fn link_route_unknown(footprint: &Footprint) -> bool {
    footprint.link_with_live_task && footprint.dir_swap_seen
}

/// Skip comparisons not covered by the observed physical route and the command's footprint.
pub fn skip(
    footprint: &Footprint,
    observation: Option<&Observation>,
    path: &Path,
    listed: bool,
    post: &Post,
) -> Option<Skip> {
    let Some(observation) = observation else {
        return Some(Skip::NotObserved);
    };
    if !observation.route_physical {
        return Some(Skip::Route);
    }
    if footprint.unknown || link_route_unknown(footprint) {
        return Some(Skip::Unknown);
    }
    if path
        .ancestors()
        .any(|ancestor| footprint.entries.contains(ancestor))
    {
        return Some(Skip::OwnPath);
    }
    if listed
        && (footprint
            .entries
            .iter()
            .any(|entry| entry.parent() == Some(path))
            || [seen_inode(&observation.seen), post_inode(post)]
                .into_iter()
                .flatten()
                .any(|inode| footprint.parent_inodes.contains(&inode)))
    {
        return Some(Skip::OwnEntries);
    }
    if [seen_inode(&observation.seen), post_inode(post)]
        .into_iter()
        .flatten()
        .any(|inode| footprint.inodes.contains(&inode))
    {
        return Some(Skip::OwnInode);
    }
    if footprint.access_changed
        && matches!(post, Post::Unreadable)
        && !matches!(observation.seen, Seen::Unreadable)
    {
        return Some(Skip::OwnAccess);
    }
    None
}

/// Compare lstat identity, and listing names when a racy listing was snapshotted.
pub fn matches(observation: &Observation, post: &Post, listing: Option<&ListSeen>) -> bool {
    match (&observation.seen, post) {
        (Seen::Absent, Post::Absent) => !observation.appeared,
        (Seen::Unreadable, Post::Unreadable) | (Seen::Special, Post::Special) => true,
        (Seen::File(first, _), Post::FileStat(last)) => first == last,
        (
            Seen::File(first, hash),
            Post::File {
                stat,
                hash: final_hash,
            },
        ) => {
            first == stat
                && match hash {
                    ReadHash::Hashed(first_hash) => first_hash == final_hash,
                    ReadHash::NotNeeded | ReadHash::StatOnly => true,
                }
        }
        (Seen::Dir(_), Post::Dir { stat, names }) => match listing {
            None => true,
            Some(first) => {
                first.stat == *stat
                    && match &first.names {
                        Some(first_names) => names.as_ref() == Some(first_names),
                        None => true,
                    }
            }
        },
        (Seen::Symlink(first), Post::Symlink(last)) => first == last,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i128 = 10_000_000_000_000;

    fn stat() -> FileStat {
        FileStat {
            dev: 1,
            ino: 2,
            size: 3,
            mtime_ns: NOW,
            ctime_ns: NOW,
            mode: 0o644,
        }
    }

    fn observation(seen: Seen) -> Observation {
        Observation {
            seen,
            route_physical: true,
            appeared: false,
        }
    }

    fn directory() -> DirSeen {
        DirSeen {
            dev: 1,
            ino: 4,
            mtime_ns: NOW,
            ctime_ns: NOW,
        }
    }

    fn names(values: &[&str]) -> Names {
        values
            .iter()
            .map(|value| Box::<[u8]>::from(value.as_bytes()))
            .collect()
    }

    #[test]
    fn racy_includes_the_boundary_and_the_future() {
        let edge = NOW - RACY_WINDOW_NS;
        assert!(racy(edge, 0, NOW));
        assert!(racy(0, edge, NOW));
        assert!(!racy(edge - 1, edge - 1, NOW));
        assert!(racy(NOW + 1, 0, NOW));
        assert!(racy(0, NOW + 1, NOW));
    }

    #[test]
    fn file_comparison_checks_every_field_and_the_read_hash() {
        let base = stat();
        for read_hash in [
            ReadHash::NotNeeded,
            ReadHash::StatOnly,
            ReadHash::Hashed("hash".into()),
        ] {
            let first = observation(Seen::File(base, read_hash));
            let post = |stat| Post::File {
                stat,
                hash: "hash".into(),
            };
            assert!(matches(&first, &post(base), None));
            for changed in [
                FileStat { dev: 9, ..base },
                FileStat { ino: 9, ..base },
                FileStat { size: 9, ..base },
                FileStat {
                    mtime_ns: NOW + 1,
                    ..base
                },
                FileStat {
                    ctime_ns: NOW + 1,
                    ..base
                },
                FileStat {
                    mode: 0o755,
                    ..base
                },
            ] {
                assert!(!matches(&first, &post(changed), None), "{changed:?}");
            }
        }
        let first = observation(Seen::File(base, ReadHash::Hashed("first".into())));
        assert!(!matches(
            &first,
            &Post::File {
                stat: base,
                hash: "other".into()
            },
            None
        ));
    }

    #[test]
    fn comparison_covers_absence_special_links_and_listings() {
        let mut absent = observation(Seen::Absent);
        assert!(matches(&absent, &Post::Absent, None));
        absent.appeared = true;
        assert!(!matches(&absent, &Post::Absent, None));
        assert!(!matches(&absent, &Post::Unreadable, None));
        assert!(matches(
            &observation(Seen::Unreadable),
            &Post::Unreadable,
            None
        ));
        assert!(matches(&observation(Seen::Special), &Post::Special, None));
        let link = LinkSeen {
            dev: 1,
            ino: 5,
            ctime_ns: NOW,
            target: "a".into(),
        };
        let first = observation(Seen::Symlink(link.clone()));
        assert!(matches(&first, &Post::Symlink(link.clone()), None));
        for changed in [
            LinkSeen {
                dev: 9,
                ..link.clone()
            },
            LinkSeen {
                ino: 9,
                ..link.clone()
            },
            LinkSeen {
                ctime_ns: NOW + 1,
                ..link.clone()
            },
            LinkSeen {
                target: "b".into(),
                ..link
            },
        ] {
            assert!(!matches(&first, &Post::Symlink(changed), None));
        }
        let stat = directory();
        let first = observation(Seen::Dir(stat));
        let same = Post::Dir {
            stat,
            names: Some(names(&["a", "b"])),
        };
        assert!(matches(&first, &same, None));
        let listed = ListSeen {
            stat,
            names: Some(names(&["a", "b"])),
        };
        assert!(matches(&first, &same, Some(&listed)));
        let changed = Post::Dir {
            stat,
            names: Some(names(&["a", "c"])),
        };
        assert!(!matches(&first, &changed, Some(&listed)));
        let changed = Post::Dir {
            stat: DirSeen {
                ctime_ns: NOW + 1,
                ..stat
            },
            names: listed.names.clone(),
        };
        assert!(!matches(&first, &changed, Some(&listed)));
        let stat_only = ListSeen { stat, names: None };
        assert!(matches(&first, &same, Some(&stat_only)));
    }

    #[test]
    fn each_skip_reason_has_a_distinct_control() {
        let first = observation(Seen::File(stat(), ReadHash::NotNeeded));
        let post = Post::File {
            stat: stat(),
            hash: "h".into(),
        };
        let path = Path::new("/root/d/f");
        let mut footprint = Footprint::default();
        assert_eq!(
            skip(&footprint, None, path, false, &post),
            Some(Skip::NotObserved)
        );
        let mut route = first.clone();
        route.route_physical = false;
        assert_eq!(
            skip(&footprint, Some(&route), path, false, &post),
            Some(Skip::Route)
        );
        footprint.unknown = true;
        assert_eq!(
            skip(&footprint, Some(&first), path, false, &post),
            Some(Skip::Unknown)
        );
        footprint.unknown = false;
        footprint.entries.insert(PathBuf::from("/root/d"));
        assert_eq!(
            skip(&footprint, Some(&first), path, false, &post),
            Some(Skip::OwnPath)
        );
        footprint.entries.clear();
        footprint.entries.insert(path.to_path_buf());
        assert_eq!(
            skip(&footprint, Some(&first), path, false, &post),
            Some(Skip::OwnPath)
        );
        footprint.entries.clear();
        footprint.entries.insert(path.join("out"));
        assert_eq!(
            skip(&footprint, Some(&first), path, true, &post),
            Some(Skip::OwnEntries)
        );
        assert_eq!(skip(&footprint, Some(&first), path, false, &post), None);
        footprint.entries.clear();
        footprint.inodes.insert((1, 2));
        assert_eq!(
            skip(&footprint, Some(&first), path, false, &post),
            Some(Skip::OwnInode)
        );
        footprint.inodes.clear();
        let replaced = Post::File {
            stat: FileStat {
                dev: 9,
                ino: 10,
                ..stat()
            },
            hash: "h".into(),
        };
        footprint.inodes.insert((9, 10));
        assert_eq!(
            skip(&footprint, Some(&first), path, false, &replaced),
            Some(Skip::OwnInode)
        );
    }

    #[test]
    fn access_change_skips_every_first_look_that_became_unreadable() {
        let path = Path::new("/root/d/f");
        let footprint = Footprint {
            access_changed: true,
            ..Footprint::default()
        };
        let link = LinkSeen {
            dev: 1,
            ino: 5,
            ctime_ns: NOW,
            target: "t".into(),
        };
        for seen in [
            Seen::File(stat(), ReadHash::NotNeeded),
            Seen::Dir(directory()),
            Seen::Absent,
            Seen::Symlink(link),
            Seen::Special,
        ] {
            let label = format!("{seen:?}");
            assert_eq!(
                skip(
                    &footprint,
                    Some(&observation(seen)),
                    path,
                    false,
                    &Post::Unreadable
                ),
                Some(Skip::OwnAccess),
                "{label}"
            );
        }
    }

    #[test]
    fn access_change_leaves_readable_and_already_unreadable_looks_to_the_comparison() {
        let path = Path::new("/root/d/f");
        let footprint = Footprint {
            access_changed: true,
            ..Footprint::default()
        };
        let file = Post::File {
            stat: stat(),
            hash: "h".into(),
        };
        let first = observation(Seen::File(stat(), ReadHash::NotNeeded));
        assert_eq!(skip(&footprint, Some(&first), path, false, &file), None);
        assert_eq!(
            skip(
                &footprint,
                Some(&observation(Seen::Unreadable)),
                path,
                false,
                &Post::Unreadable
            ),
            None
        );
        let quiet = Footprint::default();
        assert_eq!(
            skip(&quiet, Some(&first), path, false, &Post::Unreadable),
            None
        );
    }

    #[test]
    fn a_listed_directory_inside_an_own_parent_inode_skips_as_own_entries() {
        let path = Path::new("/root/d");
        let dir = directory();
        let seen = observation(Seen::Dir(dir));
        let post = Post::Dir {
            stat: dir,
            names: None,
        };
        let mut footprint = Footprint::default();
        footprint.parent_inodes.insert((dir.dev, dir.ino));
        assert_eq!(
            skip(&footprint, Some(&seen), path, true, &post),
            Some(Skip::OwnEntries)
        );
        assert_eq!(skip(&footprint, Some(&seen), path, false, &post), None);
        footprint.parent_inodes.clear();
        footprint.parent_inodes.insert((dir.dev, dir.ino + 1));
        assert_eq!(skip(&footprint, Some(&seen), path, true, &post), None);
    }

    #[test]
    fn a_hard_link_and_a_directory_swap_are_unknown_only_together() {
        let neither = Footprint::default();
        let link = Footprint {
            link_with_live_task: true,
            ..Footprint::default()
        };
        let swap = Footprint {
            dir_swap_seen: true,
            ..Footprint::default()
        };
        let both = Footprint {
            link_with_live_task: true,
            dir_swap_seen: true,
            ..Footprint::default()
        };
        assert!(!link_route_unknown(&neither));
        assert!(!link_route_unknown(&link));
        assert!(!link_route_unknown(&swap));
        assert!(link_route_unknown(&both));
        let path = Path::new("/root/d/f");
        let first = observation(Seen::File(stat(), ReadHash::NotNeeded));
        let post = Post::File {
            stat: stat(),
            hash: "h".into(),
        };
        assert_eq!(skip(&link, Some(&first), path, false, &post), None);
        assert_eq!(skip(&swap, Some(&first), path, false, &post), None);
        assert_eq!(
            skip(&both, Some(&first), path, false, &post),
            Some(Skip::Unknown)
        );
    }

    #[test]
    fn capped_names_consume_no_more_than_one_extra_entry() {
        let visited = std::cell::Cell::new(0);
        let entries = (0..).map(|index| {
            assert!(index < 3);
            visited.set(index + 1);
            Ok(OsString::from(format!("name-{index}")))
        });
        assert_eq!(take_names(entries, 2), None);
        assert_eq!(visited.get(), 3);
        let entries = ["a", "b"]
            .into_iter()
            .map(|value| Ok(OsString::from(value)));
        assert_eq!(take_names(entries, 2), Some(names(&["a", "b"])));
    }

    #[test]
    fn bounded_hash_falls_back_on_overflow_and_stat_mismatch() {
        let dir = std::env::temp_dir().join(format!("stoop-core3a-hash-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("file");
        fs::write(&path, b"bytes").unwrap();
        let expected = file_stat(&fs::metadata(&path).unwrap());
        let mut budget = ReadBudget {
            hashed: READ_HASH_BUDGET - 2,
            logged: 0,
        };
        assert_eq!(
            hash_bound(&path, &expected, &mut budget),
            ReadHash::StatOnly
        );
        assert_eq!(budget.hashed, READ_HASH_BUDGET + 1);
        let mut budget = ReadBudget::default();
        assert_eq!(
            hash_bound(
                &path,
                &FileStat {
                    size: expected.size + 1,
                    ..expected
                },
                &mut budget
            ),
            ReadHash::StatOnly
        );
        assert_eq!(budget.hashed, 0);
        assert_eq!(
            hash_bound(&path, &expected, &mut budget),
            ReadHash::Hashed(blake3::hash(b"bytes").to_hex().to_string())
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
