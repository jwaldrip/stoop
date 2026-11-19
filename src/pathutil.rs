//! Lexical path handling shared by the tracer and the manifest, and the physical
//! location of a path: where it really lives once symlinks above its name are followed.

use crate::input::par_map;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Join `p` onto `base` when relative, then resolve `.` and `..` lexically.
/// Symlinks are not followed: the tracer reports names, not inodes.
pub fn absolutize(base: &Path, p: &Path) -> PathBuf {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    };
    let mut out = PathBuf::new();
    for c in joined.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Remove `.` components without collapsing `..` across symlinks.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn without_dots(path: &Path) -> PathBuf {
    path.components().collect()
}

/// Whether a path component names the Git directory. Windows ignores case and trailing dots
/// and spaces, and `GIT~1` is the short name its file systems may give `.git`.
pub fn is_git_name(name: &std::ffi::OsStr) -> bool {
    #[cfg(unix)]
    {
        name == ".git"
    }
    #[cfg(windows)]
    {
        name.to_str().is_some_and(|name| {
            let name = name.trim_end_matches(['.', ' ']);
            name.eq_ignore_ascii_case(".git") || name.eq_ignore_ascii_case("git~1")
        })
    }
}

/// Root-relative text for paths under `root`, absolute text otherwise.
/// A relative result never starts with `/`, so the two cannot collide.
pub fn to_key(root: &Path, p: &Path) -> String {
    #[cfg(unix)]
    {
        match p.strip_prefix(root) {
            Ok(rel) => rel.to_string_lossy().into_owned(),
            Err(_) => p.to_string_lossy().into_owned(),
        }
    }
    #[cfg(windows)]
    {
        match windows::strip_root(root, p) {
            Some(rel) => windows::relative_key(&rel, false),
            None => windows::absolute_key(p),
        }
    }
}

/// The relative working directory used to identify a command. Percent escapes
/// preserve non-UTF-8 bytes without colliding with literal percent signs.
pub fn cwd_key(root: &Path, cwd: &Path) -> String {
    #[cfg(unix)]
    {
        use std::fmt::Write;
        use std::os::unix::ffi::OsStrExt;

        let path = cwd.strip_prefix(root).unwrap_or(cwd);
        if let Some(text) = path.to_str() {
            return text.replace('%', "%25");
        }
        let mut key = String::new();
        for &byte in path.as_os_str().as_bytes() {
            if byte.is_ascii() && byte != b'%' {
                key.push(char::from(byte));
            } else {
                write!(key, "%{byte:02X}").unwrap();
            }
        }
        key
    }
    #[cfg(windows)]
    {
        match windows::strip_root(root, cwd) {
            Some(rel) => windows::relative_key(&rel, true),
            None => windows::absolute_key(cwd),
        }
    }
}

pub fn from_key(root: &Path, key: &str) -> PathBuf {
    #[cfg(unix)]
    {
        if key.starts_with('/') {
            PathBuf::from(key)
        } else {
            root.join(key)
        }
    }
    #[cfg(windows)]
    {
        if key.starts_with('/') {
            windows::from_absolute_key(key)
        } else {
            root.join(windows::unescape(key))
        }
    }
}

/// Keys on Windows: `/`-separated, so they match across machines and the `.git` component
/// check splits them the same way. A DOS path outside the root is `/C:/dir/file`, a UNC path
/// is `//server/share/dir`. Names are never case-folded; only the root prefix is matched
/// without regard to case. Unpaired UTF-16 surrogates are written `%uXXXX`.
#[cfg(windows)]
mod windows {
    use std::ffi::OsStr;
    use std::fmt::Write;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Path, PathBuf, Prefix};

    fn canon(component: Component<'_>) -> String {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                    format!("{}:", (letter as char).to_ascii_uppercase())
                }
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => format!(
                    "//{}/{}",
                    server.to_string_lossy().to_lowercase(),
                    share.to_string_lossy().to_lowercase()
                ),
                _ => prefix.as_os_str().to_string_lossy().to_lowercase(),
            },
            other => other.as_os_str().to_string_lossy().to_lowercase(),
        }
    }

    /// `p` below `root`, comparing the root's components without regard to case.
    pub fn strip_root(root: &Path, p: &Path) -> Option<PathBuf> {
        if let Ok(rel) = p.strip_prefix(root) {
            return Some(rel.to_path_buf());
        }
        let mut rest = p.components();
        for want in root.components() {
            if canon(want) != canon(rest.next()?) {
                return None;
            }
        }
        Some(rest.as_path().to_path_buf())
    }

    fn push_name(name: &OsStr, escape_percent: bool, out: &mut String) {
        for unit in char::decode_utf16(name.encode_wide()) {
            match unit {
                Ok('%') if escape_percent => out.push_str("%25"),
                Ok(c) => out.push(c),
                Err(e) => write!(out, "%u{:04X}", e.unpaired_surrogate()).unwrap(),
            }
        }
    }

    pub fn relative_key(rel: &Path, escape_percent: bool) -> String {
        let mut key = String::new();
        for component in rel.components() {
            if let Component::Normal(name) = component {
                if !key.is_empty() {
                    key.push('/');
                }
                push_name(name, escape_percent, &mut key);
            }
        }
        key
    }

    pub fn absolute_key(p: &Path) -> String {
        let mut key = String::new();
        let mut components = p.components().peekable();
        match components.peek() {
            Some(Component::Prefix(prefix)) => {
                match prefix.kind() {
                    Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                        write!(key, "/{}:", (letter as char).to_ascii_uppercase()).unwrap();
                    }
                    Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                        key.push_str("//");
                        push_name(server, false, &mut key);
                        key.push('/');
                        push_name(share, false, &mut key);
                    }
                    _ => {
                        key.push('/');
                        let text = prefix.as_os_str().to_string_lossy().replace('\\', "/");
                        key.push_str(text.trim_start_matches('/'));
                    }
                }
                components.next();
            }
            _ => key.push('/'),
        }
        for component in components {
            if let Component::Normal(name) = component {
                key.push('/');
                push_name(name, false, &mut key);
            }
        }
        key
    }

    /// Undoes `%uXXXX` escapes in a relative key.
    pub fn unescape(key: &str) -> std::ffi::OsString {
        let mut units: Vec<u16> = Vec::new();
        let bytes = key.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && bytes.get(i + 1) == Some(&b'u') && i + 6 <= bytes.len() {
                if let Ok(unit) = u16::from_str_radix(&key[i + 2..i + 6], 16) {
                    units.push(unit);
                    i += 6;
                    continue;
                }
            }
            let ch = key[i..].chars().next().unwrap();
            let mut buf = [0u16; 2];
            units.extend_from_slice(ch.encode_utf16(&mut buf));
            i += ch.len_utf8();
        }
        std::ffi::OsString::from_wide(&units)
    }

    pub fn from_absolute_key(key: &str) -> PathBuf {
        if let Some(unc) = key.strip_prefix("//") {
            return PathBuf::from(format!(
                r"\\{}",
                unescape(unc).to_string_lossy().replace('/', r"\")
            ));
        }
        let rest = &key[1..];
        let bytes = rest.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            let tail = unescape(&rest[2..]);
            let tail = tail.to_string_lossy().replace('/', r"\");
            return PathBuf::from(format!(
                "{}:{}",
                rest.as_bytes()[0] as char,
                if tail.is_empty() {
                    r"\".to_owned()
                } else {
                    tail
                }
            ));
        }
        PathBuf::from(format!(
            r"\\?\{}",
            unescape(rest).to_string_lossy().replace('/', r"\")
        ))
    }
}

/// Where a path physically lives: its canonical parent directory plus its own name.
/// The name itself is not resolved, so a symbolic link stays a link.
pub struct Location {
    pub path: PathBuf,
    /// A symlink above the name moved its parent somewhere else.
    #[allow(dead_code)]
    pub redirected: bool,
}

/// Physical locations of paths under one repository root. Canonical parents are cached.
/// A write that changes a path drops the cached entries at or below it, so a later
/// lookup sees the new layout.
pub struct Physical {
    lexical: PathBuf,
    real: PathBuf,
    parents: BTreeMap<PathBuf, PathBuf>,
}

impl Physical {
    /// `lexical` is the root as the user spelled it; `real` is its canonical path.
    pub fn new(lexical: &Path, real: &Path) -> Physical {
        Physical {
            lexical: lexical.to_path_buf(),
            real: real.to_path_buf(),
            parents: BTreeMap::new(),
        }
    }

    pub fn real(&self) -> &Path {
        &self.real
    }

    /// The part of a physical path below the canonical root, if it is inside it and not the root.
    pub fn repo_rel<'p>(&self, phys: &'p Path) -> Option<&'p Path> {
        let rel = phys.strip_prefix(&self.real).ok()?;
        (!rel.as_os_str().is_empty()).then_some(rel)
    }

    fn canonical_dir(&mut self, dir: &Path) -> Option<PathBuf> {
        if let Some(c) = self.parents.get(dir) {
            return Some(c.clone());
        }
        let c = fs::canonicalize(dir).ok()?;
        self.parents.insert(dir.to_path_buf(), c.clone());
        Some(c)
    }

    /// Resolve and cache the parents of `dirs` in parallel, so the lookups that follow
    /// cost no syscalls. Directories that cannot be resolved are left for `locate`.
    pub fn prefetch(&mut self, dirs: impl IntoIterator<Item = PathBuf>) {
        let missing: Vec<PathBuf> = dirs
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|d| !self.parents.contains_key(d))
            .collect();
        let found = par_map(&missing, |d| fs::canonicalize(d).ok());
        for (dir, canon) in missing.into_iter().zip(found) {
            if let Some(c) = canon {
                self.parents.insert(dir, c);
            }
        }
    }

    /// Where `raw` (absolute, possibly with `..` that the kernel resolves through symlinks)
    /// names its entry. None when it has no name, such as `/` or a path ending in `..`.
    pub fn locate(&mut self, raw: &Path) -> Option<Location> {
        // Pseudo filesystems describe the process that reads them. Resolved here they would
        // describe stoop rather than the traced command, so they have no physical location.
        if ["/proc", "/sys", "/dev"].iter().any(|p| raw.starts_with(p)) {
            return None;
        }
        let name = raw.file_name()?;
        let dir = raw.parent()?;
        match self.canonical_dir(dir) {
            Some(canon) => {
                let spelled = absolutize(Path::new("/"), dir);
                Some(Location {
                    path: canon.join(name),
                    redirected: canon != spelled,
                })
            }
            None => {
                let spelled = absolutize(Path::new("/"), raw);
                Some(match self.missing_location(dir, name) {
                    Some(path) => Location {
                        redirected: path != spelled,
                        path,
                    },
                    None => Location {
                        path: self.fallback(&spelled),
                        redirected: false,
                    },
                })
            }
        }
    }

    /// Resolve the existing prefix of a missing parent physically. If `..` follows
    /// a missing name, the missing name itself is what the call observed.
    fn missing_location(&mut self, dir: &Path, name: &std::ffi::OsStr) -> Option<PathBuf> {
        let parts: Vec<Component> = dir.components().collect();
        for cut in (1..parts.len()).rev() {
            let head: PathBuf = parts[..cut].iter().collect();
            let Some(mut out) = self.canonical_dir(&head) else {
                continue;
            };
            let mut first_missing = None;
            for part in &parts[cut..] {
                match part {
                    Component::Normal(n) => {
                        out.push(n);
                        first_missing.get_or_insert_with(|| out.clone());
                    }
                    Component::CurDir => {}
                    _ => return first_missing,
                }
            }
            out.push(name);
            return Some(out);
        }
        None
    }

    /// A parent that does not exist cannot be resolved. A path inside the root keeps its
    /// spelled location, re-rooted at the canonical root, so keys stay in one namespace.
    fn fallback(&self, lexical: &Path) -> PathBuf {
        match lexical.strip_prefix(&self.lexical) {
            Ok(rel) => self.real.join(rel),
            Err(_) => lexical.to_path_buf(),
        }
    }

    /// Drop cached parents at or below `p`: a write to `p` may change what they resolve to.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn forget(&mut self, p: &Path) {
        let descendants: Vec<PathBuf> = self
            .parents
            .range(p.to_path_buf()..)
            .take_while(|(key, _)| key.starts_with(p))
            .map(|(key, _)| key.clone())
            .collect();
        for key in descendants {
            self.parents.remove(&key);
        }
    }

    /// A topology change can invalidate aliases under unrelated spellings.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn clear(&mut self) {
        self.parents.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_dots_lexically() {
        let b = Path::new("/w/app");
        assert_eq!(
            absolutize(b, Path::new("../x/./y")),
            PathBuf::from("/w/x/y")
        );
        assert_eq!(
            absolutize(b, Path::new("/etc/../usr")),
            PathBuf::from("/usr")
        );
    }

    #[test]
    fn removes_dot_components_without_collapsing_parent_components() {
        assert_eq!(
            without_dots(Path::new("/repo/./link/../file")),
            PathBuf::from("/repo/link/../file")
        );
    }

    #[test]
    fn keys_round_trip() {
        let root = Path::new("/w");
        assert_eq!(to_key(root, Path::new("/w/a/b")), "a/b");
        assert_eq!(to_key(root, Path::new("/usr/lib/x")), "/usr/lib/x");
        assert_eq!(from_key(root, "a/b"), PathBuf::from("/w/a/b"));
        assert_eq!(from_key(root, "/usr/lib/x"), PathBuf::from("/usr/lib/x"));
    }

    #[test]
    fn proc_paths_never_get_a_physical_repository_key() {
        let root = scratch("proc-exclusion");
        let mut physical = Physical::new(&root, &root);
        assert!(physical.locate(Path::new("/proc/self/status")).is_none());
    }

    struct Scratch(PathBuf);
    impl std::ops::Deref for Scratch {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn scratch(name: &str) -> Scratch {
        let d = std::env::temp_dir().join(format!("stoop-pathutil-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        Scratch(fs::canonicalize(&d).unwrap())
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_resolves_to_its_target_and_is_flagged() {
        let root = scratch("redirect");
        fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink(root.join("sub"), root.join("link")).unwrap();
        let mut p = Physical::new(&root, &root);
        let loc = p.locate(&root.join("link/f")).unwrap();
        assert_eq!(loc.path, root.join("sub/f"));
        assert!(loc.redirected);
        let direct = p.locate(&root.join("sub/f")).unwrap();
        assert_eq!(direct.path, root.join("sub/f"));
        assert!(!direct.redirected);
    }

    #[cfg(unix)]
    #[test]
    fn the_final_name_is_not_resolved() {
        let root = scratch("final");
        fs::write(root.join("t"), "x").unwrap();
        std::os::unix::fs::symlink(root.join("t"), root.join("l")).unwrap();
        let mut p = Physical::new(&root, &root);
        assert_eq!(p.locate(&root.join("l")).unwrap().path, root.join("l"));
    }

    #[test]
    fn a_missing_parent_falls_back_to_the_spelled_path_under_the_real_root() {
        let root = scratch("missing");
        let mut p = Physical::new(&root, &root);
        let loc = p.locate(&root.join("nope/deeper/f")).unwrap();
        assert_eq!(loc.path, root.join("nope/deeper/f"));
        assert!(!loc.redirected);
    }

    #[cfg(unix)]
    #[test]
    fn missing_parents_follow_existing_links_and_stop_before_missing_dotdot() {
        let root = scratch("missing-link");
        fs::create_dir_all(root.join("sub/d1")).unwrap();
        std::os::unix::fs::symlink("sub/d1", root.join("link")).unwrap();
        let mut p = Physical::new(&root, &root);
        assert_eq!(
            p.locate(&root.join("link/../missing/file")).unwrap().path,
            root.join("sub/missing/file")
        );
        assert_eq!(
            p.locate(&root.join("link/missing/../file")).unwrap().path,
            root.join("sub/d1/missing")
        );
    }

    #[test]
    fn forget_drops_entries_at_and_below_the_path_only() {
        let root = scratch("forget");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::create_dir_all(root.join("c")).unwrap();
        let mut p = Physical::new(&root, &root);
        p.prefetch([root.join("a/b"), root.join("c")]);
        assert_eq!(p.parents.len(), 2);
        p.forget(&root.join("a"));
        assert!(p.parents.contains_key(&root.join("c")));
        assert!(!p.parents.contains_key(&root.join("a/b")));
    }

    #[test]
    fn pseudo_filesystems_have_no_physical_location() {
        let root = scratch("pseudo");
        let mut p = Physical::new(&root, &root);
        assert!(p.locate(Path::new("/proc/self/cwd/x")).is_none());
        assert!(p.locate(Path::new("/dev/stdout")).is_none());
        assert!(p.locate(&root.join("x")).is_some());
    }

    #[test]
    fn forgetting_a_prefix_visits_only_its_cached_descendants() {
        let root = scratch("range-count");
        let mut p = Physical::new(&root, &root);
        for i in 0..10_000 {
            let key = root.join(format!("entry-{i:05}"));
            p.parents.insert(key.clone(), key);
        }
        let prefix = root.join("entry-05000");
        let visited = p
            .parents
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .count();
        assert_eq!(visited, 1);
        p.forget(&prefix);
        assert_eq!(p.parents.len(), 9_999);
    }

    #[cfg(unix)]
    #[test]
    fn missing_parent_is_rerooted_when_lexical_root_is_a_symlink() {
        let root = scratch("reroot");
        let alias = root.join("alias");
        fs::create_dir(root.join("actual")).unwrap();
        std::os::unix::fs::symlink(root.join("actual"), &alias).unwrap();
        let real = root.join("actual");
        let mut p = Physical::new(&alias, &real);
        assert_eq!(
            p.locate(&alias.join("missing/child")).unwrap().path,
            real.join("missing/child")
        );
    }

    #[cfg(unix)]
    #[test]
    fn cwd_keys_do_not_fold_non_utf8() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = Path::new("/repo");
        let a = root.join(OsString::from_vec(b"dir-\x80".to_vec()));
        let b = root.join(OsString::from_vec(b"dir-\x81".to_vec()));
        assert_ne!(cwd_key(root, &a), cwd_key(root, &b));
        assert_ne!(cwd_key(root, &a), cwd_key(root, &root.join("dir-%80")));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    const ROOT: &str = r"C:\src\repo";

    fn key(p: &str) -> String {
        to_key(Path::new(ROOT), Path::new(p))
    }

    fn back(key: &str) -> PathBuf {
        from_key(Path::new(ROOT), key)
    }

    #[test]
    fn paths_in_the_root_use_forward_slashes_and_never_start_with_one() {
        assert_eq!(key(r"C:\src\repo\a\b.txt"), "a/b.txt");
        assert_eq!(key(r"C:\src\repo\a"), "a");
        assert!(!key(r"C:\src\repo\a\b").starts_with('/'));
        assert_eq!(back("a/b.txt"), Path::new(ROOT).join("a").join("b.txt"));
    }

    #[test]
    fn the_root_matches_without_regard_to_case_but_names_keep_theirs() {
        assert_eq!(
            key(r"c:\SRC\Repo\Dir\File.TXT"),
            "Dir/File.TXT",
            "the root prefix is case-insensitive, the names are not folded"
        );
    }

    #[test]
    fn a_verbatim_spelling_of_the_root_is_the_same_root() {
        assert_eq!(key(r"\\?\C:\src\repo\a\b"), "a/b");
    }

    #[test]
    fn outside_paths_get_absolute_keys_and_come_back() {
        for (path, expected, restored) in [
            (r"D:\tools\x.exe", "/D:/tools/x.exe", r"D:\tools\x.exe"),
            (r"d:\tools\x.exe", "/D:/tools/x.exe", r"D:\tools\x.exe"),
            (r"\\?\D:\tools\x.exe", "/D:/tools/x.exe", r"D:\tools\x.exe"),
            (
                r"\\server\share\dir\f.txt",
                "//server/share/dir/f.txt",
                r"\\server\share\dir\f.txt",
            ),
            (
                r"\\?\UNC\server\share\f.txt",
                "//server/share/f.txt",
                r"\\server\share\f.txt",
            ),
            (r"E:\", "/E:", r"E:\"),
        ] {
            assert_eq!(key(path), expected, "{path}");
            assert_eq!(back(expected), PathBuf::from(restored), "{expected}");
            assert!(key(path).starts_with('/'), "{path}");
        }
    }

    #[test]
    fn an_unpaired_surrogate_is_escaped_and_round_trips() {
        let name = OsString::from_wide(&[0x61, 0xD800, 0x62]);
        let path = Path::new(ROOT).join(&name);
        assert_eq!(to_key(Path::new(ROOT), &path), "a%uD800b");
        assert_eq!(from_key(Path::new(ROOT), "a%uD800b"), path);
    }

    #[test]
    fn cwd_keys_escape_percent_signs() {
        assert_eq!(
            cwd_key(Path::new(ROOT), Path::new(r"C:\src\repo\sub\100%")),
            "sub/100%25"
        );
        assert_eq!(cwd_key(Path::new(ROOT), Path::new(ROOT)), "");
    }

    #[test]
    fn the_git_directory_is_found_under_its_windows_spellings() {
        for name in [".git", ".GIT", ".git.", ".git ", "GIT~1", "git~1"] {
            assert!(is_git_name(std::ffi::OsStr::new(name)), "{name}");
        }
        for name in [".gitignore", "git", ".gi", "x.git"] {
            assert!(!is_git_name(std::ffi::OsStr::new(name)), "{name}");
        }
        assert!(key(r"C:\src\repo\.GIT\config")
            .split('/')
            .any(|part| is_git_name(std::ffi::OsStr::new(part))));
    }
}
