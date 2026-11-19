//! Lexical path handling shared by the tracer and the manifest, and the physical
//! location of a path: where it really lives once symlinks above its name are followed.

use crate::input::par_map;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
#[cfg(windows)]
use std::{borrow::Cow, ffi::OsString};

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

/// Root-relative text for paths under `root`, absolute text otherwise.
/// A relative result never starts with `/`, so the two cannot collide. Keys use `/` as their
/// separator on every platform.
pub fn to_key(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(rel) => key_text(rel),
        Err(_) => absolute_text(p),
    }
}

#[cfg(not(windows))]
fn key_text(rel: &Path) -> String {
    rel.to_string_lossy().into_owned()
}

#[cfg(not(windows))]
fn absolute_text(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

/// Windows relative key. `\` cannot occur inside a Windows name, so rewriting it as `/` is exact.
#[cfg(windows)]
fn key_text(rel: &Path) -> String {
    slashes(&escaped(rel.as_os_str()))
}

/// Windows absolute key (design section 4). A `\\?\` prefix is dropped first, so one file has one
/// key however it was spelled. A DOS path becomes `/C:/...` with the drive letter upper-cased, and
/// a UNC path becomes `//server/share/...`. Both start with `/`, which no relative key does.
#[cfg(windows)]
fn absolute_text(p: &Path) -> String {
    let unverbatim = unverbatim(p.as_os_str());
    let text = slashes(&escaped(&unverbatim));
    let bytes = text.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        return format!(
            "/{}{}",
            char::from(bytes[0]).to_ascii_uppercase(),
            &text[1..]
        );
    }
    text
}

#[cfg(windows)]
fn unverbatim(name: &OsStr) -> Cow<'_, OsStr> {
    let Some(text) = name.to_str() else {
        return Cow::Borrowed(name);
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return Cow::Owned(OsString::from(format!(r"\\{rest}")));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => Cow::Owned(OsString::from(rest)),
        None => Cow::Borrowed(name),
    }
}

#[cfg(windows)]
fn slashes(text: &str) -> String {
    text.replace('\\', "/")
}

#[cfg(not(windows))]
fn slashes(text: &str) -> String {
    text.to_owned()
}

/// Text for one path name. UTF-8 names keep their text, with each `%` doubled. Any other name
/// percent-escapes every byte that is not plain ASCII, and each `%`, so no two names share a key.
fn escaped(name: &OsStr) -> String {
    use std::fmt::Write;

    if let Some(text) = name.to_str() {
        return text.replace('%', "%25");
    }
    let mut key = String::new();
    for &byte in name.as_encoded_bytes() {
        if byte.is_ascii() && byte != b'%' {
            key.push(char::from(byte));
        } else {
            write!(key, "%{byte:02X}").unwrap();
        }
    }
    key
}

/// The relative working directory used to identify a command. Percent escapes
/// preserve non-UTF-8 bytes without colliding with literal percent signs.
pub fn cwd_key(root: &Path, cwd: &Path) -> String {
    let path = cwd.strip_prefix(root).unwrap_or(cwd);
    slashes(&escaped(path.as_os_str()))
}

/// The path a key names: the inverse of `to_key` for paths under `root`, and of its absolute text.
pub fn from_key(root: &Path, key: &str) -> PathBuf {
    #[cfg(windows)]
    if let Some(path) = windows_absolute(key) {
        return path;
    }
    if key.starts_with('/') {
        PathBuf::from(key)
    } else {
        #[cfg(windows)]
        return root.join(key.replace('/', "\\"));
        #[cfg(not(windows))]
        root.join(key)
    }
}

/// The Windows path an absolute key names: `/C:/x` is `C:\x`, `//server/share/x` is
/// `\\server\share\x`, and `/x` is `\x`.
#[cfg(windows)]
fn windows_absolute(key: &str) -> Option<PathBuf> {
    if let Some(unc) = key.strip_prefix("//") {
        return Some(PathBuf::from(format!(r"\\{}", unc.replace('/', "\\"))));
    }
    let rest = key.strip_prefix('/')?;
    let bytes = rest.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let tail = rest[2..].replace('/', "\\");
        return Some(PathBuf::from(format!("{}:{tail}", char::from(bytes[0]))));
    }
    Some(PathBuf::from(rest.replace('/', "\\")))
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
mod windows_keys {
    use super::*;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[test]
    fn in_root_keys_use_forward_slashes() {
        let root = Path::new(r"C:\repo");
        assert_eq!(
            to_key(root, Path::new(r"C:\repo\src\main.rs")),
            "src/main.rs"
        );
        assert_eq!(cwd_key(root, Path::new(r"C:\repo\src")), "src");
        assert_eq!(from_key(root, "src/main.rs"), root.join(r"src\main.rs"));
    }

    #[test]
    fn dos_paths_outside_the_root_get_an_upper_case_drive_key() {
        let root = Path::new(r"C:\repo");
        assert_eq!(
            to_key(root, Path::new(r"c:\tools\cargo.exe")),
            "/C:/tools/cargo.exe"
        );
        assert_eq!(
            from_key(root, "/C:/tools/cargo.exe"),
            PathBuf::from(r"C:\tools\cargo.exe")
        );
    }

    #[test]
    fn unc_paths_keep_their_server_and_share() {
        let root = Path::new(r"C:\repo");
        assert_eq!(
            to_key(root, Path::new(r"\\server\share\dir\f")),
            "//server/share/dir/f"
        );
        assert_eq!(
            from_key(root, "//server/share/dir/f"),
            PathBuf::from(r"\\server\share\dir\f")
        );
    }

    #[test]
    fn verbatim_spellings_give_the_plain_spelling_key() {
        let root = Path::new(r"C:\repo");
        assert_eq!(
            to_key(root, Path::new(r"\\?\C:\tools\x")),
            to_key(root, Path::new(r"C:\tools\x"))
        );
        assert_eq!(
            to_key(root, Path::new(r"\\?\UNC\server\share\f")),
            "//server/share/f"
        );
    }

    #[test]
    fn a_relative_key_never_starts_with_a_slash() {
        let root = Path::new(r"C:\repo");
        assert!(!to_key(root, Path::new(r"C:\repo\a\b")).starts_with('/'));
    }

    #[test]
    fn a_name_that_is_not_utf8_keeps_its_exact_bytes() {
        // An unpaired surrogate is not UTF-16 text, so it is escaped byte by byte, as cwd keys are.
        let root = Path::new(r"C:\repo");
        let lone = OsString::from_wide(&[0xD800, u16::from(b'a')]);
        assert_eq!(cwd_key(root, &root.join(lone)), "%ED%A0%80a");
    }
}
