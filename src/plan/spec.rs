use crate::job::JobRecord;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct JobSpec {
    pub workflow: String,
    pub path: String,
    pub job: String,
    pub leg: Option<String>,
    pub key: Option<String>,
    pub runs_on: serde_json::Value,
    pub needs: Vec<String>,
    pub if_text: Option<String>,
    pub steps: Vec<StepSpec>,
    pub blocked: Option<Blocker>,
    /// `uses:` references of the steps the job runs, as written. Resolved by `gha::resolve`.
    pub actions: Vec<String>,
    /// Container and service image references of the job, as written.
    pub images: Vec<String>,
}
#[derive(Clone, Debug)]
pub enum StepSpec {
    Traced {
        index: usize,
        key: String,
        max_age: Option<u64>,
    },
    Neutral {
        index: usize,
        what: String,
    },
}
#[derive(Clone, Debug)]
pub struct Blocker {
    pub step: Option<usize>,
    pub detail: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Code {
    Proved,
    Full,
    Error,
    NotGated,
    Graph,
    Blocked,
    NoRecord,
    Incomplete,
    ProofMissing,
    OldProof,
    ProofPlatform,
    Expired,
    Probe,
    InputChanged,
    PriorChanged,
    Unplannable,
    EnvChanged,
    Stale,
    ImageChanged,
    RulesChanged,
    Unattested,
    UnresolvedAction,
    ActionMoved,
    ActionContentChanged,
    ActionUnverifiable,
}
#[derive(Clone, Debug)]
pub struct Decision {
    pub skip: bool,
    pub code: Code,
    pub detail: String,
    pub evidence: Option<Evidence>,
    pub mismatches: Vec<(usize, String, String)>,
}
#[derive(Clone, Debug)]
pub struct Evidence {
    pub run: Option<String>,
    pub created: u64,
    pub commit: Option<String>,
    pub record_digest: Option<String>,
    pub proofs: Vec<String>,
    pub steps: usize,
    pub inputs: usize,
    pub priors: usize,
    pub hashed: usize,
    /// Content comparisons decided by recorded and tree blob ids, with no blob read.
    pub by_oid: usize,
    /// Blob reads made while evaluating this record.
    pub blob_reads: usize,
    /// Comparisons that fell back to hashing, by stable reason.
    pub declined: BTreeMap<&'static str, usize>,
    pub overlay: usize,
    pub assumed_outside: usize,
    pub assumed_env: Vec<String>,
}

pub trait RecordCheck {
    fn check(&self, spec: &JobSpec, record: &JobRecord) -> Result<(), (Code, String)>;
}

pub struct Unverified;

impl RecordCheck for Unverified {
    fn check(&self, _spec: &JobSpec, _record: &JobRecord) -> Result<(), (Code, String)> {
        Err((
            Code::Unattested,
            "no attestation verifier is configured".into(),
        ))
    }
}

impl Evidence {
    /// Zeroed counters for one record.
    pub fn new(record: &JobRecord) -> Self {
        Self {
            run: record.run.clone(),
            created: record.created,
            commit: record.commit.clone(),
            record_digest: None,
            proofs: Vec::new(),
            steps: 0,
            inputs: 0,
            priors: 0,
            hashed: 0,
            by_oid: 0,
            blob_reads: 0,
            declined: BTreeMap::new(),
            overlay: 0,
            assumed_outside: 0,
            assumed_env: Vec::new(),
        }
    }
}
