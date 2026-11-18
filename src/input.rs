//! What a command read, as comparable fingerprints.
//!
//! An input is a path plus an id describing its state:
//! - `f:<hash>`  regular file with no execute bit (hash of every byte)
//! - `x:<hash>`  regular file with an execute bit set (the same hash; the bit is part of the identity)
//! - `a`         does not exist (recorded only inside the root)
//! - `d`         directory that was looked at, not listed
//! - `dl:<hash>` directory whose entries were listed
//! - `l:<text>`  symbolic link (its target is recorded as a separate input)

use crate::pathutil::from_key;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub path: String,
    pub id: String,
}

/// Identity of a regular file: a hash of its bytes, and whether any execute bit is set.
/// The bit is part of the identity, so `chmod +x` changes the id of a file a run read.
pub fn file_id(exec: bool, hex: &str) -> String {
    format!("{}:{hex}", if exec { "x" } else { "f" })
}

#[derive(Debug)]
pub struct Mismatch {
    pub path: String,
    pub why: &'static str,
}

/// Current id for `path`, or `None` when the path is not worth recording
/// (outside the root and absent, or a device, socket or pipe).
pub fn identify(path: &Path, inside: bool, listed: bool) -> Option<String> {
    match fs::symlink_metadata(path) {
        Err(e) => match e.kind() {
            io::ErrorKind::NotFound => inside.then(|| "a".to_string()),
            _ => {
                if e.raw_os_error() == Some(libc::ENOTDIR) {
                    inside.then(|| "a".to_string())
                } else {
                    inside.then(|| "u".to_string())
                }
            }
        },
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_symlink() {
                let t = fs::read_link(path).ok()?;
                Some(format!("l:{}", t.to_string_lossy()))
            } else if ft.is_dir() {
                if listed {
                    Some(format!("dl:{}", list_hash(path)?))
                } else {
                    Some("d".to_string())
                }
            } else if ft.is_file() {
                match hash_file(path) {
                    Ok(h) => Some(file_id(m.mode() & 0o111 != 0, &h)),
                    Err(_) => inside.then(|| "u".to_string()),
                }
            } else {
                None
            }
        }
    }
}

fn list_hash(dir: &Path) -> Option<String> {
    let mut names: Vec<Vec<u8>> = Vec::new();
    for e in fs::read_dir(dir).ok()? {
        use std::os::unix::ffi::OsStrExt;
        names.push(e.ok()?.file_name().as_bytes().to_vec());
    }
    names.sort();
    let mut h = blake3::Hasher::new();
    for n in names {
        h.update(&(n.len() as u64).to_le_bytes());
        h.update(&n);
    }
    Some(h.finalize().to_hex().to_string())
}

/// Every byte counts, whatever the file is: source, binary, archive, model weights.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = blake3::Hasher::new();
    h.update_reader(&mut f)?;
    Ok(h.finalize().to_hex().to_string())
}

/// Run `f` over `items` on all cores, preserving order.
pub fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let n = items.len();
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(16);
    if n < 256 || threads == 1 {
        return items.iter().map(&f).collect();
    }
    let next = AtomicUsize::new(0);
    let mut out: Vec<Option<R>> = (0..n).map(|_| None).collect();
    let slots = std::sync::Mutex::new(&mut out);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                let mut local: Vec<(usize, R)> = Vec::new();
                loop {
                    let start = next.fetch_add(64, Ordering::Relaxed);
                    if start >= n {
                        break;
                    }
                    let end = (start + 64).min(n);
                    for (i, item) in items.iter().enumerate().take(end).skip(start) {
                        local.push((i, f(item)));
                    }
                }
                let mut g = slots.lock().unwrap();
                for (i, r) in local {
                    g[i] = Some(r);
                }
            });
        }
    });
    out.into_iter().map(|o| o.unwrap()).collect()
}

/// Compare recorded inputs with the tree as it is now.
/// With `all == false` the scan stops at the first difference.
pub fn verify(root: &Path, inputs: &[Input], all: bool) -> Vec<Mismatch> {
    let stop = AtomicBool::new(false);
    let results = par_map(inputs, |inp| {
        if !all && stop.load(Ordering::Relaxed) {
            return None;
        }
        let inside = !inp.path.starts_with('/');
        let listed = inp.id.starts_with("dl:");
        let now = identify(&from_key(root, &inp.path), inside, listed);
        if now.as_deref() == Some(inp.id.as_str()) {
            return None;
        }
        stop.store(true, Ordering::Relaxed);
        let why = match now.as_deref() {
            None => "unreadable",
            Some("a") => "removed",
            Some(_) if inp.id == "a" => "appeared",
            Some(_) => "changed",
        };
        Some(Mismatch {
            path: inp.path.clone(),
            why,
        })
    });
    results.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("stoop-input-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn file_ids_follow_content_not_mtime() {
        let d = tmp("content");
        let f = d.join("a.txt");
        fs::write(&f, "one").unwrap();
        let a = identify(&f, true, false).unwrap();
        fs::write(&f, "one").unwrap();
        assert_eq!(a, identify(&f, true, false).unwrap());
        fs::write(&f, "two").unwrap();
        assert_ne!(a, identify(&f, true, false).unwrap());
    }

    #[test]
    fn absence_is_recorded_inside_but_not_outside() {
        let d = tmp("absent");
        let f = d.join("nope");
        assert_eq!(identify(&f, true, false).as_deref(), Some("a"));
        assert_eq!(identify(&f, false, false), None);
    }

    #[test]
    fn listing_changes_when_an_entry_appears() {
        let d = tmp("list");
        fs::write(d.join("a"), "").unwrap();
        let before = identify(&d, true, true).unwrap();
        fs::write(d.join("b"), "").unwrap();
        assert_ne!(before, identify(&d, true, true).unwrap());
    }

    #[test]
    fn verify_names_what_changed() {
        let d = tmp("verify");
        fs::write(d.join("a"), "1").unwrap();
        let inputs = vec![
            Input {
                path: "a".into(),
                id: identify(&d.join("a"), true, false).unwrap(),
            },
            Input {
                path: "gone".into(),
                id: "a".into(),
            },
        ];
        assert!(verify(&d, &inputs, true).is_empty());
        fs::write(d.join("a"), "2").unwrap();
        fs::write(d.join("gone"), "").unwrap();
        let m = verify(&d, &inputs, true);
        assert_eq!(m.len(), 2);
        assert!(m.iter().any(|m| m.path == "a" && m.why == "changed"));
        assert!(m.iter().any(|m| m.path == "gone" && m.why == "appeared"));
    }

    #[test]
    fn one_changed_byte_anywhere_in_a_large_binary_changes_its_id() {
        let d = tmp("bigbin");
        let f = d.join("model.bin");
        let mut bytes: Vec<u8> = (0..(8u32 << 20))
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        bytes.extend_from_slice(&[0, 0, 0, 0, 255, 0]); // NULs and high bytes
        fs::write(&f, &bytes).unwrap();
        for inside in [true, false] {
            let base = identify(&f, inside, false).unwrap();
            // Positions chosen away from the head, middle and tail of the file.
            for pos in [100_000usize, 3_000_001, 6_999_999] {
                let mut b = bytes.clone();
                b[pos] ^= 1;
                fs::write(&f, &b).unwrap();
                assert_ne!(
                    base,
                    identify(&f, inside, false).unwrap(),
                    "byte {pos} (inside={inside})"
                );
            }
            fs::write(&f, &bytes).unwrap();
            assert_eq!(base, identify(&f, inside, false).unwrap());
        }
    }

    #[test]
    fn par_map_preserves_order() {
        let v: Vec<usize> = (0..1000).collect();
        let r = par_map(&v, |x| x * 2);
        assert!(r.iter().enumerate().all(|(i, x)| *x == i * 2));
    }

    #[test]
    fn file_identity_includes_executable_mode_without_changing_hash() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("exec-mode");
        let path = d.join("script");
        fs::write(&path, "same bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let plain = identify(&path, true, false).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).unwrap();
        let executable = identify(&path, true, false).unwrap();
        assert!(plain.starts_with("f:"));
        assert!(executable.starts_with("x:"));
        assert_eq!(&plain[2..], &executable[2..]);
        assert_ne!(plain, executable);
        fs::remove_dir_all(d).unwrap();
    }
}
