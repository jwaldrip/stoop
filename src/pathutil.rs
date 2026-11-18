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

/// Root-relative text for paths under `root`, absolute text otherwise.
/// A relative result never starts with `/`, so the two cannot collide.
pub fn to_key(root: &Path, p: &Path) -> String {
    match p.strip_prefix(root) {
        Ok(rel) => rel.to_string_lossy().into_owned(),
        Err(_) => p.to_string_lossy().into_owned(),
    }
}

pub fn from_key(root: &Path, key: &str) -> PathBuf {
    if key.starts_with('/') {
        PathBuf::from(key)
    } else {
        root.join(key)
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
            None => Some(Location {
                path: self.fallback(&absolutize(Path::new("/"), raw)),
                redirected: false,
            }),
        }
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
    fn keys_round_trip() {
        let root = Path::new("/w");
        assert_eq!(to_key(root, Path::new("/w/a/b")), "a/b");
        assert_eq!(to_key(root, Path::new("/usr/lib/x")), "/usr/lib/x");
        assert_eq!(from_key(root, "a/b"), PathBuf::from("/w/a/b"));
        assert_eq!(from_key(root, "/usr/lib/x"), PathBuf::from("/usr/lib/x"));
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("stoop-pathutil-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        fs::canonicalize(&d).unwrap()
    }

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
}
