use std::collections::BTreeMap;

use super::expr::{Contexts, Unknowable, Value};

#[derive(Clone, Debug)]
pub struct GhCtx {
    pub env: BTreeMap<String, String>,
    pub event: serde_json::Value,
}

impl GhCtx {
    pub fn from_env() -> Result<Self, String> {
        let env: BTreeMap<String, String> = std::env::vars().collect();
        let event = match env.get("GITHUB_EVENT_PATH") {
            Some(path) if !path.is_empty() => {
                let bytes = std::fs::read(path).map_err(|e| format!("event payload: {e}"))?;
                serde_json::from_slice(&bytes).map_err(|e| format!("event payload: {e}"))?
            }
            _ => serde_json::Value::Null,
        };
        Ok(Self::from_parts(env, event))
    }

    pub fn from_parts(env: BTreeMap<String, String>, event: serde_json::Value) -> Self {
        Self { env, event }
    }

    pub fn verified_vars(&self, job: &str) -> BTreeMap<String, String> {
        const NAMES: &[&str] = &[
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
        let mut vars = BTreeMap::new();
        for name in NAMES {
            if let Some(value) = self.env.get(*name) {
                vars.insert((*name).into(), value.clone());
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
