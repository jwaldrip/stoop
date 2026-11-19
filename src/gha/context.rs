use std::collections::{BTreeMap, BTreeSet};

use super::expr::{Contexts, Unknowable, Value};
pub const VERIFIED_VARS: &[&str] = &[
    "GITHUB_REF",
    "GITHUB_REF_NAME",
    "GITHUB_REF_TYPE",
    "GITHUB_REF_PROTECTED",
    "GITHUB_SHA",
    "GITHUB_EVENT_NAME",
    "GITHUB_REPOSITORY",
    "GITHUB_REPOSITORY_ID",
    "GITHUB_REPOSITORY_OWNER",
    "GITHUB_REPOSITORY_OWNER_ID",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITHUB_TRIGGERING_ACTOR",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "GITHUB_WORKFLOW",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_NUMBER",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_SERVER_URL",
    "GITHUB_API_URL",
    "GITHUB_GRAPHQL_URL",
    "GITHUB_RETENTION_DAYS",
    "GITHUB_WORKSPACE",
    "CI",
];

#[derive(Clone, Debug)]
pub struct GhCtx {
    pub env: BTreeMap<String, String>,
    pub event: serde_json::Value,
    /// Names whose values are not UTF-8. Stoop cannot compare them, so they are unavailable.
    pub unreadable: BTreeSet<String>,
}

/// What the planner compares for a verified variable whose value is not UTF-8. It never
/// equals the recorded hash of a readable value, so the job runs.
pub const UNREADABLE: &str = "\u{fffd}unreadable";

impl GhCtx {
    pub fn from_env() -> Result<Self, String> {
        let mut env = BTreeMap::new();
        let mut unreadable = BTreeSet::new();
        // A variable whose name or value is not UTF-8 must not stop stoop. A name that is not
        // UTF-8 matches none of the names stoop reads, so it is skipped.
        for (name, value) in std::env::vars_os() {
            let Ok(name) = name.into_string() else {
                continue;
            };
            match value.into_string() {
                Ok(value) => {
                    env.insert(name, value);
                }
                Err(_) => {
                    unreadable.insert(name);
                }
            }
        }
        let event = match env.get("GITHUB_EVENT_PATH") {
            Some(path) if !path.is_empty() => {
                let bytes = std::fs::read(path).map_err(|e| format!("event payload: {e}"))?;
                serde_json::from_slice(&bytes).map_err(|e| format!("event payload: {e}"))?
            }
            _ => serde_json::Value::Null,
        };
        Ok(Self {
            env,
            event,
            unreadable,
        })
    }

    pub fn from_parts(env: BTreeMap<String, String>, event: serde_json::Value) -> Self {
        Self {
            env,
            event,
            unreadable: BTreeSet::new(),
        }
    }

    pub fn verified_vars(&self, job: &str) -> BTreeMap<String, String> {
        let mut vars = BTreeMap::new();
        for name in VERIFIED_VARS {
            if let Some(value) = self.env.get(*name) {
                vars.insert((*name).into(), value.clone());
            } else if self.unreadable.contains(*name) {
                vars.insert((*name).into(), UNREADABLE.into());
            }
        }
        vars.insert("GITHUB_JOB".into(), job.into());
        vars
    }

    pub fn event_id(&self) -> Option<String> {
        let path = self.env.get("GITHUB_EVENT_PATH")?;
        let bytes = std::fs::read(path).ok()?;
        Some(format!("f:{}", blake3::hash(&bytes).to_hex()))
    }
}

fn value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Num(n.as_f64().unwrap_or_default()),
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(a) => Value::Array(a.iter().map(value).collect()),
        serde_json::Value::Object(o) => {
            Value::Object(o.iter().map(|(k, v)| (k.clone(), value(v))).collect())
        }
    }
}

impl Contexts for GhCtx {
    fn get(&self, name: &str) -> Result<Value, Unknowable> {
        match name {
            "github" => {
                let mut fields: BTreeMap<String, Value> = self
                    .env
                    .iter()
                    .filter_map(|(key, v)| {
                        key.strip_prefix("GITHUB_")
                            .map(|k| (k.to_ascii_lowercase(), Value::Str(v.clone())))
                    })
                    .collect();
                fields.insert("event".into(), value(&self.event));
                Ok(Value::Object(fields))
            }
            "inputs" => Ok(value(
                self.event.get("inputs").unwrap_or(&serde_json::Value::Null),
            )),
            _ => Err(Unknowable(format!("unknown context {name}"))),
        }
    }
}
