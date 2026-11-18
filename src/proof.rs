//! Proofs: the inputs a command read the last time it passed.

use crate::input::Input;
use crate::trace::Provenance;
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
    /// Working directory relative to the selected root. Missing on old proofs.
    #[serde(default)]
    pub cwd: Option<String>,
    /// Repository identity when proofs can share a store across roots.
    #[serde(default)]
    pub scope: Option<String>,
    /// The operating system, architecture and tracer that made the observation.
    #[serde(default)]
    pub provenance: Option<Provenance>,
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

impl ProofFile {
    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut file: Self = serde_json::from_slice(bytes).ok()?;
        match file.v {
            1 => {
                for proof in &mut file.proofs {
                    proof.provenance = None;
                }
            }
            2 => {}
            _ => return None,
        }
        Some(file)
    }
}

pub struct ProofSummary {
    pub key: String,
    pub count: usize,
    pub created: u64,
    pub inputs: usize,
    pub dirs: Vec<String>,
    pub platforms: Vec<String>,
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
    a.cwd == b.cwd
        && a.scope == b.scope
        && a.provenance == b.provenance
        && a.inputs == b.inputs
        && a.env == b.env
        && a.outputs == b.outputs
        && a.probes == b.probes
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
        match ProofFile::decode(&bytes) {
            Some(f) if f.key == key => f.proofs,
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
            v: 2,
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
        let theirs = ProofFile::decode(bytes).ok_or_else(bad)?;
        if theirs.key != key {
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

    pub fn list(&self) -> Vec<ProofSummary> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(self.dir.join("proofs")) else {
            return out;
        };
        for e in rd.flatten() {
            let Ok(bytes) = fs::read(e.path()) else {
                continue;
            };
            if let Some(f) = ProofFile::decode(&bytes) {
                if let Some(p) = f.proofs.first() {
                    let dirs = f
                        .proofs
                        .iter()
                        .map(|proof| match proof.cwd.as_deref() {
                            Some("") => ".".to_string(),
                            Some(dir) => dir.to_string(),
                            None => "?".to_string(),
                        })
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    let platforms = f
                        .proofs
                        .iter()
                        .map(|proof| match &proof.provenance {
                            Some(p) => {
                                format!("{}/{} {}/v{}", p.os, p.arch, p.tracer, p.version)
                            }
                            None => "unknown".to_string(),
                        })
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    out.push(ProofSummary {
                        key: f.key.clone(),
                        count: f.proofs.len(),
                        created: p.created,
                        inputs: p.inputs.len(),
                        dirs,
                        platforms,
                    });
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
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
            cwd: Some(String::new()),
            scope: None,
            provenance: Some(Provenance::current()),
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
    fn syncing_keeps_identical_inputs_from_distinct_platforms() {
        let a = store("provenance-a");
        let b = store("provenance-b");
        let first = proof("f:1");
        let mut second = first.clone();
        second.provenance.as_mut().unwrap().arch = "other-arch".into();
        let mut legacy = first.clone();
        legacy.provenance = None;
        a.save("k", first).unwrap();
        a.save("k", second).unwrap();
        a.save("k", legacy).unwrap();
        assert_eq!(a.load("k").len(), 3);
        let bytes = a.export("k").unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(wire["v"], 2);
        assert_eq!(b.import("k", &bytes).unwrap(), 3);
        assert_eq!(b.import("k", &bytes).unwrap(), 0);
        let platforms = &b.list()[0].platforms;
        assert!(platforms.iter().any(|p| p.contains("other-arch")));
        assert!(platforms.iter().any(|p| p == "unknown"));
        assert_eq!(Store::key_of(&bytes).as_deref(), Some("k"));
        assert_eq!(Store::newest_created(&bytes), Some(1));
    }

    #[test]
    fn legacy_format_cannot_claim_provenance() {
        let a = store("legacy-platform-a");
        let b = store("legacy-platform-b");
        let file = ProofFile {
            v: 1,
            key: "k".into(),
            proofs: vec![proof("f:1")],
        };
        let bytes = serde_json::to_vec(&file).unwrap();
        fs::create_dir_all(a.file("k").parent().unwrap()).unwrap();
        fs::write(a.file("k"), &bytes).unwrap();
        assert!(a.load("k")[0].provenance.is_none());
        assert_eq!(a.list()[0].platforms, vec!["unknown"]);
        assert_eq!(b.import("k", &bytes).unwrap(), 1);
        assert_eq!(Store::newest_created(&bytes), Some(1));
        assert!(b.load("k")[0].provenance.is_none());
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
