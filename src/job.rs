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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordStatus {
    Running,
    Passed,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Unix seconds of the latest publication.
    pub created: u64,
    /// Unix milliseconds when the journal opened. Ordering key only, not an age.
    #[serde(default)]
    pub started: u64,
    #[serde(default)]
    pub status: Option<RecordStatus>,
    #[serde(default)]
    pub failed: Option<String>,
    #[serde(default)]
    pub actions: BTreeMap<String, String>,
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
    #[serde(default)]
    pub workflow_ref: Option<String>,
    #[serde(default)]
    pub job_workflow_ref: Option<String>,
}
impl JobRecord {
    /// Higher keys sort first. GitHub run identifiers and attempts are numeric.
    pub fn order_key(&self) -> (u64, u64, u64, u64, &str) {
        let raw = self.run.as_deref().unwrap_or("");
        let (id, attempt) = raw.split_once('/').unwrap_or(("", ""));
        (
            self.started,
            id.parse().unwrap_or(0),
            attempt.parse().unwrap_or(0),
            self.created,
            raw,
        )
    }
    fn retention_key(&self) -> (u64, bool, u64, u64, u64, &str) {
        let (started, run, attempt, created, raw) = self.order_key();
        (
            started,
            self.status == Some(RecordStatus::Failed),
            run,
            attempt,
            created,
            raw,
        )
    }
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
        records.sort_by(|a, b| b.retention_key().cmp(&a.retention_key()));
        records.truncate(MAX_RECORDS);
        records.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
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
    /// Build a publication from the remote snapshot and this run only.
    pub fn merge_remote(key: &str, bytes: Option<&[u8]>, record: JobRecord) -> io::Result<Vec<u8>> {
        let mut records = match bytes {
            Some(bytes) => {
                Self::parse(bytes)
                    .filter(|f| f.key == key)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "not a job file for this key")
                    })?
                    .records
            }
            None => Vec::new(),
        };
        records.retain(|old| !Self::same(old, &record));
        records.push(record);
        records.sort_by(|a, b| b.retention_key().cmp(&a.retention_key()));
        records.truncate(MAX_RECORDS);
        records.sort_by(|a, b| b.order_key().cmp(&a.order_key()));
        serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: key.into(),
            records,
        })
        .map_err(io::Error::other)
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
            started: 0,
            status: None,
            failed: None,
            actions: BTreeMap::new(),
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
            workflow_ref: None,
            job_workflow_ref: None,
        }
    }
    #[test]
    fn old_records_load_with_defaults() {
        let record: JobRecord = serde_json::from_str(r#"{"created":1,"steps":[]}"#).unwrap();
        assert_eq!(record.started, 0);
        assert_eq!(record.status, None);
        assert_eq!(record.failed, None);
        assert!(record.actions.is_empty());
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
    #[test]
    fn retention_uses_started_before_created() {
        let s = store("retention-started");
        let mut passed = record(500);
        passed.started = 100;
        let mut failed = record(210);
        failed.started = 200;
        failed.status = Some(RecordStatus::Failed);
        s.save("job-a", passed).unwrap();
        s.save("job-a", failed).unwrap();
        for i in 601..608 {
            let mut r = record(i);
            r.started = i;
            r.status = Some(RecordStatus::Running);
            s.save("job-a", r).unwrap();
        }
        let records = s.load("job-a");
        assert_eq!(records.len(), 8);
        assert!(records
            .iter()
            .any(|r| r.status == Some(RecordStatus::Failed)));
        assert!(!records.iter().any(|r| r.started == 100));
    }

    #[test]
    fn publish_merge_never_includes_local_records() {
        let s = store("remote-merge-only");
        let mut forged = record(999);
        forged.started = 999;
        s.save("job-a", forged).unwrap();
        let mut actual = record(2);
        actual.started = 2;
        let bytes = JobStore::merge_remote("job-a", None, actual.clone()).unwrap();
        let published = JobStore::parse(&bytes).unwrap();
        assert_eq!(published.records, vec![actual]);
    }
    #[test]
    fn equal_started_order_uses_numeric_run_then_attempt_before_created() {
        let s = store("equal-started");
        let mut older = record(500);
        older.started = 1000;
        older.run = Some("9/1".into());
        let mut newer = record(200);
        newer.started = 1000;
        newer.run = Some("10/1".into());
        let mut retry = newer.clone();
        retry.run = Some("10/2".into());
        retry.created = 100;
        s.save("job-a", older).unwrap();
        s.save("job-a", newer).unwrap();
        s.save("job-a", retry).unwrap();
        let runs: Vec<_> = s
            .load("job-a")
            .into_iter()
            .map(|r| r.run.unwrap())
            .collect();
        assert_eq!(runs, ["10/2", "10/1", "9/1"]);
    }
    #[test]
    fn merge_remote_caps_nine_records_by_order() {
        let mut records: Vec<_> = (1..=8).map(record).collect();
        for r in &mut records {
            r.started = r.created;
        }
        let snapshot = serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: "job-a".into(),
            records,
        })
        .unwrap();
        let mut newest = record(9);
        newest.started = 9;
        let bytes = JobStore::merge_remote("job-a", Some(&snapshot), newest).unwrap();
        let records = JobStore::parse(&bytes).unwrap().records;
        assert_eq!(records.len(), 8);
        assert!(records.iter().all(|r| r.started != 1));
        assert!(records.iter().any(|r| r.started == 9));
    }

    #[test]
    fn merge_remote_replaces_same_run() {
        let old = record(1);
        let snapshot = serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: "job-a".into(),
            records: vec![old.clone()],
        })
        .unwrap();
        let mut updated = old;
        updated.created = 2;
        let bytes = JobStore::merge_remote("job-a", Some(&snapshot), updated.clone()).unwrap();
        assert_eq!(JobStore::parse(&bytes).unwrap().records, vec![updated]);
    }

    #[test]
    fn retention_prefers_failure_at_equal_start() {
        let mut failed = record(9);
        failed.started = 1000;
        failed.run = Some("9/1".into());
        failed.status = Some(RecordStatus::Failed);
        let mut passed = record(10);
        passed.started = 1000;
        passed.run = Some("10/1".into());
        passed.status = Some(RecordStatus::Passed);
        let mut records = vec![failed, passed];
        for i in 2000..2007 {
            let mut r = record(i);
            r.started = i;
            r.status = Some(RecordStatus::Running);
            records.push(r);
        }
        let snapshot = serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: "job-a".into(),
            records,
        })
        .unwrap();
        let mut latest = record(2006);
        latest.started = 2006;
        let result = JobStore::merge_remote("job-a", Some(&snapshot), latest).unwrap();
        let records = JobStore::parse(&result).unwrap().records;
        assert_eq!(records.len(), 8);
        assert!(records
            .iter()
            .any(|r| r.run.as_deref() == Some("9/1") && r.status == Some(RecordStatus::Failed)));
        assert!(!records.iter().any(|r| r.run.as_deref() == Some("10/1")));
    }
    #[test]
    fn import_retains_failure_at_equal_start() {
        let store = store("import-equal-start");
        let mut failed = record(9);
        failed.started = 1000;
        failed.run = Some("9/1".into());
        failed.status = Some(RecordStatus::Failed);
        let mut passed = record(10);
        passed.started = 1000;
        passed.run = Some("10/1".into());
        passed.status = Some(RecordStatus::Passed);
        let mut records = vec![failed, passed];
        for i in 2000..2007 {
            let mut r = record(i);
            r.started = i;
            r.status = Some(RecordStatus::Running);
            records.push(r);
        }
        let snapshot = serde_json::to_vec(&JobFile {
            v: 1,
            kind: "job".into(),
            key: "job-a".into(),
            records,
        })
        .unwrap();
        store.import("job-a", &snapshot).unwrap();
        let records = store.load("job-a");
        assert_eq!(records.len(), 8);
        assert!(records
            .iter()
            .any(|r| r.run.as_deref() == Some("9/1") && r.status == Some(RecordStatus::Failed)));
        assert!(!records.iter().any(|r| r.run.as_deref() == Some("10/1")));
    }
}
