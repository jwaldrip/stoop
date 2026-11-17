use crate::proof::sanitize;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io, path::PathBuf};

pub const MAX_RECORDS: usize = 8;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepHow {
    Ran,
    Skipped,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepRecord {
    pub key: String,
    pub proof: String,
    pub how: StepHow,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    pub created: u64,
    #[serde(default)]
    pub commit: Option<String>,
    #[serde(default)]
    pub host: BTreeMap<String, String>,
    #[serde(default)]
    pub event_path: Option<String>,
    #[serde(default)]
    pub run: Option<String>,
    pub steps: Vec<StepRecord>,
    /// Reserved for the signed job attestation payload; no trust is implied by its presence.
    #[serde(default)]
    pub attest: Option<String>,
}
#[derive(Serialize, Deserialize)]
struct JobFile {
    v: u32,
    kind: String,
    key: String,
    records: Vec<JobRecord>,
}
pub struct JobStore {
    dir: PathBuf,
}
impl JobStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    fn file(&self, key: &str) -> PathBuf {
        self.dir
            .join("jobs")
            .join(format!("{}.json", sanitize(key)))
    }
    fn parse(bytes: &[u8]) -> Option<JobFile> {
        let f: JobFile = serde_json::from_slice(bytes).ok()?;
        (f.v == 1 && f.kind == "job" && f.key.starts_with("job-")).then_some(f)
    }
    pub fn load(&self, key: &str) -> Vec<JobRecord> {
        fs::read(self.file(key))
            .ok()
            .and_then(|b| Self::parse(&b))
            .filter(|f| f.key == key)
            .map(|f| f.records)
            .unwrap_or_default()
    }
    fn same(a: &JobRecord, b: &JobRecord) -> bool {
        match (&a.run, &b.run) {
            (Some(a), Some(b)) => a == b,
            (None, None) => a.commit == b.commit && a.steps == b.steps,
            _ => false,
        }
    }
    fn write(&self, key: &str, mut records: Vec<JobRecord>) -> io::Result<()> {
        records.sort_by_key(|r| std::cmp::Reverse(r.created));
        records.truncate(MAX_RECORDS);
        let path = self.file(key);
        fs::create_dir_all(path.parent().unwrap())?;
        let ignore = self.dir.join(".gitignore");
        if !ignore.exists() {
            let _ = fs::write(ignore, "*\n");
        }
        let bytes = serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: key.into(),
            records,
        })
        .map_err(io::Error::other)?;
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        fs::write(&tmp, bytes)?;
        fs::rename(tmp, path)
    }
    pub fn save(&self, key: &str, record: JobRecord) -> io::Result<()> {
        if !key.starts_with("job-") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a job key"));
        }
        let mut records = self.load(key);
        records.retain(|r| !Self::same(r, &record));
        records.insert(0, record);
        self.write(key, records)
    }
    pub fn export(&self, key: &str) -> Option<Vec<u8>> {
        fs::read(self.file(key)).ok()
    }
    pub fn import(&self, key: &str, bytes: &[u8]) -> io::Result<usize> {
        let f = Self::parse(bytes).filter(|f| f.key == key).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "not a job file for this key")
        })?;
        let mut records = self.load(key);
        let mut added = 0;
        for r in f.records {
            if let Some(pos) = records.iter().position(|x| Self::same(x, &r)) {
                if r.created > records[pos].created {
                    records[pos] = r;
                    added += 1;
                }
            } else {
                records.push(r);
                added += 1;
            }
        }
        if added > 0 {
            self.write(key, records)?;
        }
        Ok(added)
    }
    pub fn key_of(bytes: &[u8]) -> Option<String> {
        Self::parse(bytes).map(|f| f.key)
    }
    pub fn newest_created(bytes: &[u8]) -> Option<u64> {
        Self::parse(bytes)?.records.iter().map(|r| r.created).max()
    }
    pub fn forget(&self, key: &str) -> io::Result<bool> {
        match fs::remove_file(self.file(key)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn list(&self) -> Vec<(String, usize, u64, usize)> {
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(self.dir.join("jobs")) {
            for e in rd.flatten() {
                if let Some(f) = fs::read(e.path()).ok().and_then(|b| Self::parse(&b)) {
                    if let Some(r) = f.records.first() {
                        out.push((f.key.clone(), f.records.len(), r.created, r.steps.len()));
                    }
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
    fn store(name: &str) -> JobStore {
        let d = std::env::temp_dir().join(format!("stoop-job-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        JobStore::new(d)
    }
    fn record(i: u64) -> JobRecord {
        JobRecord {
            created: i,
            commit: Some("sha".into()),
            host: BTreeMap::new(),
            event_path: None,
            run: Some(format!("{i}/1")),
            steps: vec![StepRecord {
                key: "sh-a".into(),
                proof: "p-a".into(),
                how: StepHow::Ran,
            }],
            attest: None,
        }
    }
    #[test]
    fn round_trip() {
        let s = store("round");
        let r = record(2);
        s.save("job-a", r.clone()).unwrap();
        assert_eq!(s.load("job-a"), vec![r]);
        let bytes = s.export("job-a").unwrap();
        assert_eq!(JobStore::key_of(&bytes).as_deref(), Some("job-a"));
        assert_eq!(JobStore::newest_created(&bytes), Some(2));
        let t = store("import");
        assert_eq!(t.import("job-a", &bytes).unwrap(), 1);
        assert_eq!(s.list().len(), 1);
        assert!(t.forget("job-a").unwrap());
    }
    #[test]
    fn same_run_replaces() {
        let s = store("same");
        let a = record(1);
        let mut b = a.clone();
        b.created = 2;
        b.steps.push(b.steps[0].clone());
        s.save("job-a", a).unwrap();
        s.save("job-a", b.clone()).unwrap();
        assert_eq!(s.load("job-a"), vec![b]);
    }
    #[test]
    fn cap_8() {
        let s = store("cap");
        for i in 0..12 {
            s.save("job-a", record(i)).unwrap();
        }
        let v = s.load("job-a");
        assert_eq!(v.len(), 8);
        assert_eq!(v[0].created, 11);
        assert_eq!(v[7].created, 4);
    }
    #[test]
    fn garbage_is_empty() {
        let s = store("garbage");
        s.save("job-a", record(1)).unwrap();
        fs::write(s.file("job-a"), b"bad").unwrap();
        assert!(s.load("job-a").is_empty());
    }
    #[test]
    fn kinds_do_not_cross() {
        let s = store("kinds");
        let p = crate::proof::Store::new(s.dir.clone());
        s.save("job-a", record(1)).unwrap();
        let job = s.export("job-a").unwrap();
        assert!(p.import("job-a", &job).is_err());
        let proof = br#"{"v":1,"key":"job-a","proofs":[]}"#;
        assert!(s.import("job-a", proof).is_err());
        assert_eq!(JobStore::key_of(proof), None);
    }
}
