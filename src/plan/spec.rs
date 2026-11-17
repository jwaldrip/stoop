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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    Expired,
    Probe,
    InputChanged,
    EnvChanged,
    Stale,
    ImageChanged,
    RulesChanged,
    Unattested,
    UnresolvedAction,
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
    pub steps: usize,
    pub inputs: usize,
    pub hashed: usize,
    pub by_diff: usize,
    pub overlay: usize,
    pub assumed_outside: usize,
    pub assumed_env: Vec<String>,
}
