//! Proofs: the inputs a command read the last time it passed.

use crate::input::Input;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

/// Proofs kept per key, newest first. Several are kept so that switching
/// between branches does not evict the proof the other branch still matches.
const MAX_PROOFS: usize = 8;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proof {
    pub created: u64,
    pub argv: Vec<String>,
    /// Hashes of the environment variables the user declared with `--env`.
    pub env: BTreeMap<String, String>,
    pub inputs: Vec<Input>,
    /// Files the run produced inside the repository. A skip needs them still in
    /// place, because skipping does not run the command that makes them.
    #[serde(default)]
    pub outputs: Vec<Input>,
    /// External state the user vouched for with `--probe`: command text to the hash
    /// of its output when the run happened. A skip needs every probe to match again.
    #[serde(default)]
    pub probes: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize)]
struct ProofFile {
    v: u32,
    key: String,
    proofs: Vec<Proof>,
}

pub struct Store {
    dir: PathBuf,
}

pub fn sanitize(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn same_proof(a: &Proof, b: &Proof) -> bool {
    a.inputs == b.inputs && a.env == b.env && a.outputs == b.outputs && a.probes == b.probes
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Store {
    pub fn new(dir: PathBuf) -> Store {
        Store { dir }
    }

    fn file(&self, key: &str) -> PathBuf {
        self.dir
            .join("proofs")
            .join(format!("{}.json", sanitize(key)))
    }

    /// Missing, unreadable or foreign-version files read as "no proof":
    /// the command then runs.
    pub fn load(&self, key: &str) -> Vec<Proof> {
        let Ok(bytes) = fs::read(self.file(key)) else {
            return Vec::new();
        };
        match serde_json::from_slice::<ProofFile>(&bytes) {
            Ok(f) if f.v == 1 && f.key == key => f.proofs,
            _ => Vec::new(),
        }
    }

    pub fn save(&self, key: &str, proof: Proof) -> io::Result<()> {
        let mut proofs = self.load(key);
        proofs.retain(|p| !same_proof(p, &proof));
        proofs.insert(0, proof);
        self.write_proofs(key, proofs)
    }

    fn write_proofs(&self, key: &str, mut proofs: Vec<Proof>) -> io::Result<()> {
        proofs.truncate(MAX_PROOFS);
        let path = self.file(key);
        fs::create_dir_all(path.parent().unwrap())?;
        let ignore = self.dir.join(".gitignore");
        if !ignore.exists() {
            let _ = fs::write(ignore, "*\n");
        }
        let body = serde_json::to_vec(&ProofFile {
            v: 1,
            key: key.to_string(),
            proofs,
        })
        .map_err(io::Error::other)?;
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&tmp, body)?;
        fs::rename(tmp, path)
    }

    /// The stored file, as published to a remote.
    pub fn export(&self, key: &str) -> Option<Vec<u8>> {
        fs::read(self.file(key)).ok()
    }

    /// Merge a published file into the local proofs, newest first. Returns how many
    /// proofs were new. A file for another key or an unknown version is refused.
    pub fn import(&self, key: &str, bytes: &[u8]) -> io::Result<usize> {
        let bad = || io::Error::new(io::ErrorKind::InvalidData, "not a proof file for this key");
        let theirs = serde_json::from_slice::<ProofFile>(bytes).map_err(|_| bad())?;
        if theirs.v != 1 || theirs.key != key {
            return Err(bad());
        }
        let mut proofs = self.load(key);
        let mut added = 0;
        for p in theirs.proofs {
            if !proofs.iter().any(|q| same_proof(q, &p)) {
                proofs.push(p);
                added += 1;
            }
        }
        if added > 0 {
            proofs.sort_by_key(|p| std::cmp::Reverse(p.created));
            self.write_proofs(key, proofs)?;
        }
        Ok(added)
    }

    pub fn key_of(bytes: &[u8]) -> Option<String> {
        serde_json::from_slice::<ProofFile>(bytes)
            .ok()
            .map(|f| f.key)
    }

    pub fn newest_created(bytes: &[u8]) -> Option<u64> {
        let f = serde_json::from_slice::<ProofFile>(bytes).ok()?;
        f.proofs.iter().map(|p| p.created).max()
    }

    pub fn forget(&self, key: &str) -> io::Result<bool> {
        match fs::remove_file(self.file(key)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// (key, proof count, newest created, newest input count)
    pub fn list(&self) -> Vec<(String, usize, u64, usize)> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(self.dir.join("proofs")) else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(bytes) = fs::read(e.path()) else {
                continue;
            };
            if let Ok(f) = serde_json::from_slice::<ProofFile>(&bytes) {
                if let Some(p) = f.proofs.first() {
                    out.push((f.key.clone(), f.proofs.len(), p.created, p.inputs.len()));
                }
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> Store {
        let d = std::env::temp_dir().join(format!("stoop-proof-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        Store::new(d)
    }

    fn proof(id: &str) -> Proof {
        Proof {
            created: 1,
            argv: vec!["x".into()],
            env: BTreeMap::new(),
            inputs: vec![Input {
                path: "a".into(),
                id: id.into(),
            }],
            outputs: vec![],
            probes: BTreeMap::new(),
        }
    }

    #[test]
    fn round_trips_and_keeps_newest_first() {
        let s = store("rt");
        s.save("k", proof("f:1")).unwrap();
        s.save("k", proof("f:2")).unwrap();
        let got = s.load("k");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].inputs[0].id, "f:2");
    }

    #[test]
    fn identical_proofs_are_not_duplicated_and_count_is_capped() {
        let s = store("cap");
        for i in 0..20 {
            s.save("k", proof(&format!("f:{i}"))).unwrap();
        }
        s.save("k", proof("f:19")).unwrap();
        assert_eq!(s.load("k").len(), MAX_PROOFS);
    }

    #[test]
    fn garbage_reads_as_no_proof() {
        let s = store("bad");
        s.save("k", proof("f:1")).unwrap();
        fs::write(s.file("k"), b"{not json").unwrap();
        assert!(s.load("k").is_empty());
    }

    #[test]
    fn forget_removes() {
        let s = store("forget");
        s.save("k", proof("f:1")).unwrap();
        assert!(s.forget("k").unwrap());
        assert!(!s.forget("k").unwrap());
    }
}
