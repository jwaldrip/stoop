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
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Input {
    pub path: String,
    pub id: String,
    #[serde(default)]
    pub oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oid_basis: Option<crate::oid_attrs::OidBasis>,
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
    identify_recorded(path, inside, listed, false).map(|(id, _)| id)
}

/// Record a Git blob id only for regular files inside a Git worktree.
pub fn identify_recorded(
    path: &Path,
    inside: bool,
    listed: bool,
    oids: bool,
) -> Option<(String, Option<String>)> {
    match fs::symlink_metadata(path) {
        Err(e) => {
            let id = match e.kind() {
                io::ErrorKind::NotFound => "a",
                _ if e.raw_os_error() == Some(libc::ENOTDIR) => "a",
                _ => "u",
            };
            inside.then(|| (id.to_owned(), None))
        }
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_symlink() {
                let t = fs::read_link(path).ok()?;
                Some((format!("l:{}", t.to_string_lossy()), None))
            } else if ft.is_dir() {
                let id = if listed {
                    format!("dl:{}", list_hash(path)?)
                } else {
                    "d".to_owned()
                };
                Some((id, None))
            } else if ft.is_file() {
                let hash = if inside && oids {
                    hash_file_with_oid(path)
                } else {
                    hash_file(path).map(|hash| (hash, None))
                };
                match hash {
                    Ok((hash, oid)) => Some((file_id(m.mode() & 0o111 != 0, &hash), oid)),
                    Err(_) => inside.then(|| ("u".to_owned(), None)),
                }
            } else {
                None
            }
        }
    }
}

pub fn records_oids(root: &Path) -> bool {
    fs::symlink_metadata(root.join(".git")).is_ok_and(|m| m.is_file() || m.is_dir())
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

fn digest_hex(prefix: &str, digest: ring::digest::Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(prefix.len() + digest.as_ref().len() * 2);
    text.push_str(prefix);
    for &byte in digest.as_ref() {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 15) as usize] as char);
    }
    text
}

fn blob_header(digest: &mut ring::digest::Context, mut len: u64) {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (len % 10) as u8;
        len /= 10;
        if len == 0 {
            break;
        }
    }
    digest.update(b"blob ");
    digest.update(&digits[start..]);
    digest.update(b"\0");
}

/// Return the Git object id of these bytes using the selected object format.
#[allow(dead_code)]
pub fn blob_oid(bytes: &[u8], sha256: bool) -> String {
    let algorithm = if sha256 {
        &ring::digest::SHA256
    } else {
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY
    };
    let mut digest = ring::digest::Context::new(algorithm);
    blob_header(&mut digest, bytes.len() as u64);
    digest.update(bytes);
    digest_hex("", digest.finish())
}

fn hash_reader_with_oid(mut reader: impl Read, len: u64) -> io::Result<(String, Option<String>)> {
    let mut blake = blake3::Hasher::new();
    let mut git = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    blob_header(&mut git, len);
    let mut buffer = [0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        read = read.saturating_add(n as u64);
        blake.update(&buffer[..n]);
        git.update(&buffer[..n]);
    }
    let oid = (read == len).then(|| digest_hex("sha1:", git.finish()));
    Ok((blake.finalize().to_hex().to_string(), oid))
}

pub fn hash_file_with_oid(path: &Path) -> io::Result<(String, Option<String>)> {
    let file = fs::File::open(path)?;
    let len = file.metadata()?.len();
    hash_reader_with_oid(file, len)
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

    #[test]
    fn unavailable_oid_serializes_as_null_without_a_basis() {
        let input = Input {
            path: "file".into(),
            id: "f:hash".into(),
            oid: None,
            oid_basis: None,
        };
        let value = serde_json::to_value(&input).unwrap();
        assert_eq!(value.get("oid"), Some(&serde_json::Value::Null));
        assert!(value.get("oid_basis").is_none());
        let legacy: Input = serde_json::from_str(r#"{"path":"file","id":"f:hash"}"#).unwrap();
        assert_eq!(legacy, input);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("stoop-input-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_TEMPLATE_DIR")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678_9abc_def0u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    #[test]
    fn blob_ids_match_git() {
        let d = tmp("blob-sha1");
        git(&d, &["init", "--object-format=sha1", "-q"]);
        let file = d.join("sample.bin");
        for size in [0, 1, 65_537, 9 * 1024 * 1024] {
            let bytes = pseudo_random_bytes(size);
            fs::write(&file, &bytes).unwrap();
            let expected = git(&d, &["hash-object", "--no-filters", "sample.bin"]);
            let (hash, oid) = hash_file_with_oid(&file).unwrap();
            assert_eq!(oid, Some(format!("sha1:{expected}")), "size {size}");
            assert_eq!(blob_oid(&bytes, false), expected, "size {size}");
            assert_eq!(hash, hash_file(&file).unwrap(), "size {size}");
            assert_eq!(
                hash,
                blake3::hash(&bytes).to_hex().to_string(),
                "size {size}"
            );
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn blob_id_dropped_when_length_differs() {
        let bytes = b"\x00\xffreader contents";
        let expected_hash = blake3::hash(bytes).to_hex().to_string();
        for len in [bytes.len() - 1, bytes.len() + 1] {
            let (hash, oid) = hash_reader_with_oid(bytes.as_slice(), len as u64).unwrap();
            assert_eq!(hash, expected_hash, "declared length {len}");
            assert_eq!(oid, None, "declared length {len}");
        }
        let (hash, oid) = hash_reader_with_oid(bytes.as_slice(), bytes.len() as u64).unwrap();
        assert_eq!(hash, expected_hash);
        assert_eq!(oid, Some(format!("sha1:{}", blob_oid(bytes, false))));
    }

    #[test]
    fn blob_oid_sha256_matches_git() {
        let d = tmp("blob-sha256");
        git(&d, &["init", "--object-format=sha256", "-q"]);
        let file = d.join("sample.bin");
        for size in [0, 1, 65_537, 9 * 1024 * 1024] {
            let bytes = pseudo_random_bytes(size);
            fs::write(&file, &bytes).unwrap();
            let expected = git(&d, &["hash-object", "--no-filters", "sample.bin"]);
            assert_eq!(blob_oid(&bytes, true), expected, "size {size}");
            let (hash, oid) = hash_file_with_oid(&file).unwrap();
            assert_eq!(hash, hash_file(&file).unwrap(), "size {size}");
            assert_eq!(oid, Some(format!("sha1:{}", blob_oid(&bytes, false))));
        }
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn records_oids_requires_git_file_or_directory() {
        let d = tmp("git-entry");
        assert!(!records_oids(&d));
        fs::write(d.join(".git"), "gitdir: elsewhere\n").unwrap();
        assert!(records_oids(&d));
        fs::remove_file(d.join(".git")).unwrap();
        fs::create_dir(d.join(".git")).unwrap();
        assert!(records_oids(&d));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn recorded_oids_only_cover_in_root_regular_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let d = tmp("recorded-oids");
        let file = d.join("data");
        fs::write(&file, b"file contents").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        let (plain, oid) = identify_recorded(&file, true, false, true).unwrap();
        assert_eq!(plain, file_id(false, &hash_file(&file).unwrap()));
        assert_eq!(
            oid,
            Some(format!("sha1:{}", blob_oid(b"file contents", false)))
        );
        assert_eq!(
            identify_recorded(&file, true, false, false),
            Some((plain.clone(), None))
        );
        assert_eq!(
            identify_recorded(&file, false, false, true),
            Some((plain.clone(), None))
        );

        let input = Input {
            path: "data".into(),
            id: plain,
            oid: Some("sha1:0000000000000000000000000000000000000000".into()),
            oid_basis: Some(crate::oid_attrs::OidBasis {
                text: "unspecified".into(),
                eol: "unspecified".into(),
                crlf: "unspecified".into(),
                filter: "unspecified".into(),
                ident: "unspecified".into(),
                working_tree_encoding: "unspecified".into(),
                export_subst: "unspecified".into(),
                autocrlf: "unset".into(),
            }),
        };
        assert!(verify(&d, &[input], true).is_empty());

        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let (executable, executable_oid) = identify_recorded(&file, true, false, true).unwrap();
        assert_eq!(executable, file_id(true, &hash_file(&file).unwrap()));
        assert_eq!(executable_oid, oid);

        let link = d.join("link");
        symlink("data", &link).unwrap();
        assert_eq!(
            identify_recorded(&link, true, false, true),
            Some(("l:data".into(), None))
        );
        assert_eq!(
            identify_recorded(&d, true, false, true),
            Some(("d".into(), None))
        );
        let (listing, listing_oid) = identify_recorded(&d, true, true, true).unwrap();
        assert!(listing.starts_with("dl:"));
        assert_eq!(listing_oid, None);
        assert_eq!(
            identify_recorded(&d.join("missing"), true, false, true),
            Some(("a".into(), None))
        );
        assert_eq!(
            identify_recorded(&d.join("missing"), false, false, true),
            None
        );
        let socket = d.join("socket");
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        assert_eq!(identify_recorded(&socket, true, false, true), None);
        drop(listener);
        fs::remove_dir_all(d).unwrap();
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
                oid: None,
                oid_basis: None,
            },
            Input {
                path: "gone".into(),
                id: "a".into(),
                oid: None,
                oid_basis: None,
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
