//! Read-only unit catalog and the directory listings that define it.

use super::filter::Filter;
use crate::ignore::Ignore;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::input;
use crate::input::Input;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::collections::HashSet;
use std::path::Path;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use std::path::PathBuf;

const MAX_UNITS: usize = 4096;
const MAX_DIRS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnitId(pub String);

#[allow(dead_code)]
pub(crate) struct Catalog {
    pub units: Vec<UnitId>,
    pub inputs: Vec<Input>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct GitInventory {
    files: HashSet<String>,
    ignored_dirs: HashSet<String>,
    prefix: String,
}

/// A valid Git record uses root-relative UTF-8 paths and no control characters.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn parse_git_records(bytes: &[u8], directories: bool) -> Result<Vec<String>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(bytes) = bytes.strip_suffix(&[0]) else {
        return Err("Git inventory is not NUL terminated".into());
    };
    bytes
        .split(|&byte| byte == 0)
        .map(|raw| {
            let text = std::str::from_utf8(raw).map_err(|_| "Git inventory is not UTF-8")?;
            let path = if directories {
                text.strip_suffix('/').unwrap_or(text)
            } else {
                text
            };
            if path.is_empty()
                || Path::new(path).is_absolute()
                || path.starts_with('/')
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| matches!(part, "" | "." | ".."))
                || (path.len() >= 2
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && path.as_bytes()[1] == b':')
                || (!directories && text.ends_with('/'))
            {
                return Err("Git inventory contains an invalid path".into());
            }
            Ok(text.to_string())
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl GitInventory {
    fn from_outputs(
        root: &Path,
        repo: &Path,
        files: &[u8],
        ignored: &[u8],
    ) -> Result<Self, String> {
        let files: HashSet<_> = parse_git_records(files, false)?.into_iter().collect();
        let ignored = parse_git_records(ignored, true)?;
        let ignored_dirs: HashSet<String> = ignored
            .iter()
            .filter(|path| path.ends_with('/'))
            .cloned()
            .collect();
        let ignored_files: HashSet<&str> = ignored
            .iter()
            .filter(|path| !path.ends_with('/'))
            .map(String::as_str)
            .collect();
        for file in &files {
            if ignored_files.contains(file.as_str())
                || file
                    .match_indices('/')
                    .any(|(at, _)| ignored_dirs.contains(&file[..=at]))
            {
                return Err("Git inventory disagrees with its ignored paths".into());
            }
        }
        let relative = root
            .strip_prefix(repo)
            .map_err(|_| "selected root is outside the Git worktree")?;
        let mut components = Vec::new();
        for component in relative.components() {
            let component = component
                .as_os_str()
                .to_str()
                .ok_or("Git root path is not UTF-8")?;
            components.push(component);
        }
        let prefix = if components.is_empty() {
            String::new()
        } else {
            format!("{}/", components.join("/"))
        };
        Ok(Self {
            files,
            ignored_dirs,
            prefix,
        })
    }

    fn includes(&self, path: &str) -> bool {
        self.files.contains(&format!("{}{path}", self.prefix))
    }

    fn prunes(&self, path: &str) -> bool {
        let path = format!("{}{path}/", self.prefix);
        self.ignored_dirs.contains(&path)
            || path
                .match_indices('/')
                .any(|(at, _)| self.ignored_dirs.contains(&path[..=at]))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn git_available() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        #[cfg(windows)]
        let names = ["git.exe", "git"];
        #[cfg(not(windows))]
        let names = ["git", "git"];
        names.iter().any(|name| {
            std::fs::metadata(dir.join(name)).is_ok_and(|metadata| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    metadata.is_file()
                }
            })
        })
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn inventory(root: &Path) -> Result<Option<GitInventory>, String> {
    let Some(repo) = root.ancestors().find(|dir| dir.join(".git").exists()) else {
        return Ok(None);
    };
    if !git_available() {
        return Ok(None);
    }
    let files =
        crate::gitprobe::unit_files(repo).ok_or("Git unit inventory failed or exceeded 64 MiB")?;
    let ignored = crate::gitprobe::ignored_unit_dirs(repo)
        .ok_or("Git ignored-directory inventory failed or exceeded 64 MiB")?;
    GitInventory::from_outputs(root, repo, &files, &ignored).map(Some)
}

pub(crate) fn discover(
    root: &Path,
    ignore: &Ignore,
    filter: &Filter,
    default: Option<&Filter>,
) -> Result<Catalog, String> {
    discover_with_limits(root, ignore, filter, default, MAX_UNITS, MAX_DIRS)
}

pub(crate) fn explain(
    root: &Path,
    ignore: &Ignore,
    inline: Option<&Filter>,
    configured: Option<(&Filter, &str)>,
) -> String {
    if let Some(filter) = inline.or(configured.map(|(filter, _)| filter)) {
        let default = configured.map(|(filter, _)| filter);
        return match discover(root, ignore, filter, default) {
            Ok(catalog) => {
                let source = if inline.is_some() {
                    "inline".to_string()
                } else {
                    format!(
                        ".stoop.toml suite {}",
                        super::hook::safe(configured.unwrap().1)
                    )
                };
                format!(
                    "stoop: tracked {} units; filter '{}' ({source})",
                    catalog.units.len(),
                    super::hook::safe(filter.text())
                )
            }
            Err(reason) => format!("stoop: no unit universe: {}", super::hook::safe(&reason)),
        };
    }
    let patterns = ["**/*.test.*", "**/*_test.*", "**/test_*.py", "**/*_spec.*"];
    let candidates = Filter::inline(&patterns.join("|"));
    match discover(root, ignore, &candidates, None) {
        Ok(catalog) => {
            let suggestion = patterns.iter().find(|pattern| {
                let filter = Filter::inline(pattern);
                catalog
                    .units
                    .iter()
                    .any(|unit| filter.matches(&unit.0, false))
            });
            match suggestion {
                Some(pattern) => format!(
                    "stoop: no unit universe: add a filter, for example '{{changed:{pattern}}}'"
                ),
                None => "stoop: no unit universe: add a filter or configure suite units".into(),
            }
        }
        Err(reason) => format!("stoop: no unit universe: {}", super::hook::safe(&reason)),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn discover_with_limits(
    root: &Path,
    ignore: &Ignore,
    filter: &Filter,
    default: Option<&Filter>,
    max_units: usize,
    max_dirs: usize,
) -> Result<Catalog, String> {
    discover_with_hook(
        root,
        ignore,
        filter,
        default,
        max_units,
        max_dirs,
        &mut |_| {},
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn discover_with_limits(
    _root: &Path,
    _ignore: &Ignore,
    _filter: &Filter,
    _default: Option<&Filter>,
    _max_units: usize,
    _max_dirs: usize,
) -> Result<Catalog, String> {
    Err("unit universe is not available on this platform".into())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Directory {
    file: std::fs::File,
    key: String,
    names: Vec<Vec<u8>>,
    next: usize,
    listing: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Directory {
    fn new(file: std::fs::File, key: String) -> Result<Self, String> {
        let mut names = directory_names(&file)?;
        let listing = input::list_hash_of_names(&mut names);
        Ok(Self {
            file,
            key,
            names,
            next: 0,
            listing,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_child(dir: &std::fs::File, name: &mut Vec<u8>) -> Result<std::fs::File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    name.push(0);
    // The final component must be a directory and cannot be followed through a symlink.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr().cast(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    name.pop();
    if fd < 0 {
        return Err(format!(
            "cannot open a directory without following links: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_root(root: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Component;
    let mut dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")
        .map_err(|error| format!("cannot open root directory: {error}"))?;
    for component in root.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                dir = open_child(&dir, &mut name.as_bytes().to_vec())?;
            }
            _ => return Err("invalid root directory".into()),
        }
    }
    Ok(dir)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn directory_names(dir: &std::fs::File) -> Result<Vec<Vec<u8>>, String> {
    use std::ffi::CStr;
    use std::os::fd::AsRawFd;
    struct Stream(*mut libc::DIR);
    impl Drop for Stream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    // Open a fresh description so reading the duplicate does not advance the caller's offset.
    let fresh = open_child(dir, &mut b".".to_vec())?;
    let duplicate = unsafe { libc::fcntl(fresh.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(format!(
            "cannot duplicate a directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe {
            libc::close(duplicate);
        }
        return Err(format!("cannot read a directory: {error}"));
    }
    let stream = Stream(stream);
    let mut names = Vec::new();
    loop {
        #[cfg(target_os = "linux")]
        let errno = unsafe { libc::__errno_location() };
        #[cfg(target_os = "macos")]
        let errno = unsafe { libc::__error() };
        unsafe {
            *errno = 0;
        }
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let code = unsafe { *errno };
            if code != 0 {
                return Err(format!(
                    "cannot read a directory entry: {}",
                    std::io::Error::from_raw_os_error(code)
                ));
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            names.push(name.to_vec());
        }
    }
    Ok(names)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn entry_mode(dir: &std::fs::File, name: &mut Vec<u8>) -> Result<libc::mode_t, String> {
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    name.push(0);
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            name.as_ptr().cast(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    name.pop();
    if rc != 0 {
        return Err(format!(
            "cannot inspect a directory entry: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { stat.assume_init() }.st_mode)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn discover_with_hook<F: FnMut(&str)>(
    root: &Path,
    ignore: &Ignore,
    filter: &Filter,
    default: Option<&Filter>,
    max_units: usize,
    max_dirs: usize,
    before_open: &mut F,
) -> Result<Catalog, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot read root: {error}"))?;
    let git = inventory(&root)?;
    if max_dirs == 0 {
        return Err("more than 0 walked directories".into());
    }
    let mut stack = vec![Directory::new(open_root(&root)?, String::new())?];
    let mut visited = 1;
    let mut units = Vec::new();
    let mut inputs = Vec::new();
    while let Some(directory) = stack.last_mut() {
        if directory.next == directory.names.len() {
            let mut after = directory_names(&directory.file)?;
            if input::list_hash_of_names(&mut after) != directory.listing {
                return Err("a directory changed while its units were listed".into());
            }
            let directory = stack.pop().unwrap();
            inputs.push(Input {
                path: if directory.key.is_empty() {
                    ".".to_string()
                } else {
                    directory.key
                },
                id: format!("dl:{}", directory.listing),
                oid: None,
                oid_basis: None,
            });
            continue;
        }
        let name = &mut directory.names[directory.next];
        directory.next += 1;
        let Some(text) = std::str::from_utf8(name).ok() else {
            continue;
        };
        if text == ".git" || text == ".stoop" {
            continue;
        }
        let child = if directory.key.is_empty() {
            text.to_string()
        } else {
            format!("{}/{text}", directory.key)
        };
        if ignore.is_ignored(&child) {
            continue;
        }
        let mode = entry_mode(&directory.file, name)? & libc::S_IFMT;
        if mode == libc::S_IFDIR {
            if git.as_ref().is_some_and(|git| git.prunes(&child)) {
                continue;
            }
            if visited >= max_dirs {
                return Err(format!("more than {max_dirs} walked directories"));
            }
            before_open(&child);
            let child_dir = open_child(&directory.file, name)?;
            stack.push(Directory::new(child_dir, child)?);
            visited += 1;
        } else if mode == libc::S_IFREG {
            if git.as_ref().is_some_and(|git| !git.includes(&child)) {
                continue;
            }
            if child.len() > 4096 {
                return Err("a unit path cannot be represented".into());
            }
            let matches = if filter.exclusion_only() {
                default.is_some_and(|base| base.matches(&child, false))
                    && filter.matches(&child, false)
            } else {
                filter.matches(&child, false)
            };
            if !matches {
                continue;
            }
            if child.chars().any(|c| c == '\0' || c == '\n')
                || child.split('/').any(|part| matches!(part, "" | "." | ".."))
            {
                return Err("a unit path cannot be represented".into());
            }
            if units.len() >= max_units {
                return Err(format!("more than {max_units} units"));
            }
            units.push(UnitId(child));
        }
    }
    units.sort();
    inputs.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Catalog { units, inputs })
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stoop-universe-unit-{}-{}",
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

    fn git(dir: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .env("HOME", dir)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn malformed_git_records_and_disagreement_refuse_the_universe() {
        let root = Path::new("/");
        for bad in [
            &b"not-terminated"[..],
            b"\0",
            b"../bad\0",
            b"/absolute\0",
            b"a/./b\0",
            b"a/../b\0",
            b"a\nb\0",
            b"\xff\0",
        ] {
            assert!(
                GitInventory::from_outputs(root, root, bad, b"").is_err(),
                "{bad:?}"
            );
            assert!(
                GitInventory::from_outputs(root, root, b"", bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            GitInventory::from_outputs(root, root, b"ignored/tracked.t\0", b"ignored/\0").is_err()
        );
        assert!(GitInventory::from_outputs(root, root, b"ignored.t\0", b"ignored.t\0").is_err());
    }

    #[test]
    fn empty_directories_are_catalog_inputs_and_their_listing_changes() {
        let dir = Dir::new();
        fs::create_dir(dir.0.join("empty")).unwrap();
        let ignore = Ignore::new(&[], None, &[]);
        let filter = Filter::inline("**/*.t");
        let before = discover(&dir.0, &ignore, &filter, None).unwrap();
        let empty = before
            .inputs
            .iter()
            .find(|input| input.path == "empty")
            .unwrap();
        assert_eq!(
            empty.id,
            format!("dl:{}", input::list_hash(&dir.0.join("empty")).unwrap())
        );
        fs::write(dir.0.join("empty/new.t"), b"x").unwrap();
        let after = discover(&dir.0, &ignore, &filter, None).unwrap();
        assert_ne!(
            empty.id,
            after
                .inputs
                .iter()
                .find(|input| input.path == "empty")
                .unwrap()
                .id
        );
        assert_eq!(after.units, vec![UnitId("empty/new.t".into())]);
    }

    #[test]
    fn exact_unit_and_directory_limits_refuse_the_next_item() {
        assert_eq!(MAX_UNITS, 4096);
        assert_eq!(MAX_DIRS, 65_536);
        let dir = Dir::new();
        fs::create_dir(dir.0.join("a")).unwrap();
        fs::write(dir.0.join("a/one.t"), b"1").unwrap();
        fs::write(dir.0.join("a/two.t"), b"2").unwrap();
        let ignore = Ignore::new(&[], None, &[]);
        let filter = Filter::inline("**/*.t");
        assert_eq!(
            discover_with_limits(&dir.0, &ignore, &filter, None, 2, 2)
                .unwrap()
                .units
                .len(),
            2
        );
        assert!(discover_with_limits(&dir.0, &ignore, &filter, None, 1, 2).is_err());
        assert!(discover_with_limits(&dir.0, &ignore, &filter, None, 2, 1).is_err());
    }

    #[test]
    fn a_git_worktree_tracks_empty_directories_and_their_new_files() {
        let dir = Dir::new();
        git(&dir.0, &["init", "-q"]);
        fs::create_dir(dir.0.join("empty")).unwrap();
        let ignore = Ignore::new(&[], None, &[]);
        let filter = Filter::inline("**/*.t");
        let before = discover(&dir.0, &ignore, &filter, None).unwrap();
        let old = before
            .inputs
            .iter()
            .find(|input| input.path == "empty")
            .unwrap()
            .id
            .clone();
        fs::write(dir.0.join("empty/new.t"), b"x").unwrap();
        let after = discover(&dir.0, &ignore, &filter, None).unwrap();
        assert_ne!(
            old,
            after
                .inputs
                .iter()
                .find(|input| input.path == "empty")
                .unwrap()
                .id
        );
        assert_eq!(after.units, vec![UnitId("empty/new.t".into())]);
    }

    #[test]
    fn pruned_git_directories_do_not_count_toward_the_walk_limit() {
        let dir = Dir::new();
        git(&dir.0, &["init", "-q"]);
        fs::write(dir.0.join(".gitignore"), b"ignored/\n").unwrap();
        fs::create_dir(dir.0.join("ignored")).unwrap();
        fs::write(dir.0.join("ignored/a.t"), b"x").unwrap();
        let catalog = discover_with_limits(
            &dir.0,
            &Ignore::new(&[], None, &[]),
            &Filter::inline("**/*.t"),
            None,
            4096,
            1,
        )
        .unwrap();
        assert!(catalog.units.is_empty());
        assert_eq!(catalog.inputs.len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seventy_thousand_files_in_a_wholly_ignored_directory_are_pruned() {
        let dir = Dir::new();
        git(&dir.0, &["init", "-q"]);
        fs::write(dir.0.join(".gitignore"), b"ignored/\n").unwrap();
        fs::create_dir(dir.0.join("ignored")).unwrap();
        for i in 0..70_000 {
            fs::write(dir.0.join("ignored").join(format!("{i:05}.t")), b"").unwrap();
        }
        let catalog = discover_with_limits(
            &dir.0,
            &Ignore::new(&[], None, &[]),
            &Filter::inline("**/*.t"),
            None,
            4096,
            1,
        )
        .unwrap();
        assert!(catalog.units.is_empty());
        assert_eq!(catalog.inputs.len(), 1);
    }

    #[test]
    fn force_added_file_under_an_ignored_directory_is_a_unit_or_unknown() {
        let dir = Dir::new();
        git(&dir.0, &["init", "-q"]);
        fs::write(dir.0.join(".gitignore"), b"ignored/\n").unwrap();
        fs::create_dir(dir.0.join("ignored")).unwrap();
        fs::write(dir.0.join("ignored/tracked.t"), b"x").unwrap();
        git(&dir.0, &["add", "-f", "ignored/tracked.t"]);
        match discover(
            &dir.0,
            &Ignore::new(&[], None, &[]),
            &Filter::inline("**/*.t"),
            None,
        ) {
            Ok(catalog) => assert!(catalog.units.contains(&UnitId("ignored/tracked.t".into()))),
            Err(reason) => assert!(reason.contains("disagrees"), "{reason}"),
        }
    }

    #[test]
    fn swapping_a_directory_for_an_outside_symlink_refuses_the_universe() {
        use std::os::unix::fs::symlink;
        let dir = Dir::new();
        let outside = Dir::new();
        fs::create_dir(dir.0.join("victim")).unwrap();
        fs::write(outside.0.join("outside.t"), b"x").unwrap();
        let triggered = std::cell::Cell::new(false);
        let mut swap = |child: &str| {
            if child == "victim" {
                triggered.set(true);
                fs::rename(dir.0.join("victim"), dir.0.join("old-victim")).unwrap();
                symlink(&outside.0, dir.0.join("victim")).unwrap();
            }
        };
        let result = discover_with_hook(
            &dir.0,
            &Ignore::new(&[], None, &[]),
            &Filter::inline("**/*.t"),
            None,
            4096,
            65_536,
            &mut swap,
        );
        assert!(triggered.get(), "the directory swap did not run");
        match result {
            Ok(_) => panic!("the swapped symlink was followed"),
            Err(reason) => assert!(
                reason.contains("cannot open a directory without following links"),
                "{reason}"
            ),
        }
    }

    #[test]
    fn a_replaced_parent_path_cannot_redirect_an_open_directory_handle() {
        use std::os::unix::fs::symlink;
        let dir = Dir::new();
        let outside = Dir::new();
        fs::create_dir_all(dir.0.join("parent/child")).unwrap();
        fs::write(dir.0.join("parent/child/safe.t"), b"safe").unwrap();
        fs::create_dir(outside.0.join("child")).unwrap();
        fs::write(outside.0.join("child/outside.t"), b"outside").unwrap();
        let parent = open_root(&dir.0.join("parent").canonicalize().unwrap()).unwrap();
        fs::rename(dir.0.join("parent"), dir.0.join("old-parent")).unwrap();
        symlink(&outside.0, dir.0.join("parent")).unwrap();
        let child = open_child(&parent, &mut b"child".to_vec()).unwrap();
        let names = directory_names(&child).unwrap();
        assert!(names.contains(&b"safe.t".to_vec()), "{names:?}");
        assert!(!names.contains(&b"outside.t".to_vec()), "{names:?}");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn windows_reports_the_universe_unknown() {
        let result = discover(
            Path::new("."),
            &Ignore::new(&[], None, &[]),
            &Filter::inline("**/*.t"),
            None,
        );
        match result {
            Ok(_) => panic!("Windows must not claim a discovered unit universe"),
            Err(reason) => assert_eq!(reason, "unit universe is not available on this platform"),
        }
    }
}
