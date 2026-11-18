//! Lexical path handling shared by the tracer and the manifest.

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

/// The relative working directory used to identify a command. Percent escapes
/// preserve non-UTF-8 bytes without colliding with literal percent signs.
pub fn cwd_key(root: &Path, cwd: &Path) -> String {
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

pub fn from_key(root: &Path, key: &str) -> PathBuf {
    if key.starts_with('/') {
        PathBuf::from(key)
    } else {
        root.join(key)
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
