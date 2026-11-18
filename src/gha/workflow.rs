use std::path::{Component, Path};

use serde_json::{json, Map, Value};
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Default)]
struct ScalarCheck(Option<String>);
impl EventReceiver for ScalarCheck {
    fn on_event(&mut self, event: Event) {
        match event {
            Event::Alias(_) => self.0 = Some("YAML aliases are not supported".into()),
            Event::Scalar(value, yaml_rust2::scanner::TScalarStyle::Plain, _, _)
                if ["Null", "NULL"].contains(&value.as_str())
                    || value
                        .strip_prefix('-')
                        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b == b'0')) =>
            {
                self.0 = Some(format!("unsupported ambiguous YAML scalar {value}"));
            }
            _ => {}
        }
    }
}

use super::{context::GhCtx, matrix};
use crate::plan::spec::{Blocker, JobSpec, StepSpec};

#[derive(Clone, Debug)]
pub struct Workflow {
    pub path: String,
    pub name: String,
    pub root: Value,
}

fn convert(y: &Yaml) -> Result<Value, String> {
    match y {
        Yaml::Null => Ok(Value::Null),
        Yaml::Boolean(b) => Ok(json!(b)),
        Yaml::Integer(i) => Ok(json!(i)),
        Yaml::Real(s) => {
            let n: f64 = s.parse().map_err(|_| "invalid YAML number")?;
            serde_json::Number::from_f64(n)
                .map(Value::Number)
                .ok_or_else(|| "non-finite YAML number".into())
        }
        Yaml::String(s) => Ok(json!(s)),
        Yaml::Array(a) => a.iter().map(convert).collect(),
        Yaml::Hash(h) => {
            let mut m = Map::new();
            for (k, v) in h {
                let Yaml::String(k) = k else {
                    return Err("non-string YAML key".into());
                };
                if m.insert(k.clone(), convert(v)?).is_some() {
                    return Err("duplicate YAML key".into());
                }
            }
            Ok(Value::Object(m))
        }
        _ => Err("unsupported YAML value or alias".into()),
    }
}

pub fn parse(path: &str, text: &str) -> Result<Workflow, String> {
    let mut check = ScalarCheck::default();
    Parser::new_from_str(text)
        .load(&mut check, true)
        .map_err(|e| e.to_string())?;
    if let Some(error) = check.0 {
        return Err(error);
    }
    let docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    if docs.len() != 1 {
        return Err("workflow must contain one document".into());
    }
    let root = convert(&docs[0])?;
    let obj = root.as_object().ok_or("workflow must be an object")?;
    let name = match obj.get("name") {
        None => path.to_string(),
        Some(Value::String(s)) if !s.contains("${{") => s.clone(),
        _ => return Err("workflow name is not static".into()),
    };
    if !obj.get("jobs").is_some_and(Value::is_object) {
        return Err("workflow jobs must be an object".into());
    }
    Ok(Workflow {
        path: path.into(),
        name,
        root,
    })
}

fn object<'a>(v: Option<&'a Value>, label: &str) -> Result<&'a Map<String, Value>, String> {
    match v {
        Some(Value::Object(m)) => Ok(m),
        None => Ok(empty()),
        _ => Err(format!("{label} must be an object")),
    }
}
fn empty() -> &'static Map<String, Value> {
    static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);
    &EMPTY
}
fn static_value(v: &Value) -> Result<Value, String> {
    match v {
        Value::String(s) if s.contains("${{") => Err("expression in keyed field".into()),
        Value::Array(a) => Ok(Value::Array(
            a.iter().map(static_value).collect::<Result<_, _>>()?,
        )),
        Value::Object(o) => Ok(Value::Object(
            o.iter()
                .map(|(k, v)| {
                    if k.contains("${{") {
                        return Err("expression in keyed field".into());
                    }
                    Ok((k.clone(), static_value(v)?))
                })
                .collect::<Result<_, String>>()?,
        )),
        _ => Ok(v.clone()),
    }
}
fn env(v: Option<&Value>) -> Result<Map<String, Value>, String> {
    let mut out = Map::new();
    for (k, v) in object(v, "env")? {
        if !k.starts_with("STOOP_") {
            out.insert(k.clone(), static_value(v)?);
        }
    }
    Ok(out)
}

fn stoop_settings(layers: &[Option<&Value>]) -> Result<Option<u64>, String> {
    let mut effective = Map::new();
    for layer in layers {
        for (k, v) in object(*layer, "env")? {
            if ["STOOP_FULL", "STOOP_OFF", "STOOP_MAX_AGE"].contains(&k.as_str()) {
                effective.insert(k.clone(), v.clone());
            }
        }
    }
    for name in ["STOOP_FULL", "STOOP_OFF"] {
        if let Some(v) = effective.get(name) {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Bool(b) => b.to_string(),
                Value::Number(n) => n.to_string(),
                Value::Null => String::new(),
                _ => return Err(format!("{name} is not a scalar")),
            };
            if s.contains("${{") {
                return Err(format!("{name} is an expression"));
            }
            let lower = s.trim().to_ascii_lowercase();
            if !["", "0", "false", "no", "off"].contains(&lower.as_str()) {
                return Err(format!("{name} is enabled"));
            }
        }
    }
    match effective.get("STOOP_MAX_AGE") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let s = match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => return Err("STOOP_MAX_AGE is not a duration".into()),
            };
            if s.contains("${{") {
                return Err("STOOP_MAX_AGE is an expression".into());
            }
            if s.trim().is_empty() {
                return Ok(None);
            }
            crate::run::parse_age(&s)
                .map(Some)
                .map_err(|e| format!("STOOP_MAX_AGE: {e}"))
        }
    }
}

fn static_workflow_settings(w: &Workflow) -> Result<Value, String> {
    let mut settings = Map::new();
    for (name, value) in object(w.root.get("env"), "workflow env")? {
        if ["STOOP_FULL", "STOOP_OFF", "STOOP_MAX_AGE"].contains(&name.as_str())
            && !value.as_str().is_some_and(|s| s.contains("${{"))
        {
            settings.insert(name.clone(), value.clone());
        }
    }
    Ok(Value::Object(settings))
}

fn plan_job_override(w: &Workflow, plan_job: &str) -> Result<Option<String>, String> {
    let Some(job) = w.root["jobs"].get(plan_job) else {
        return Ok(None);
    };
    let job = job.as_object().ok_or("plan job must be an object")?;
    let mut envs = vec![job.get("env")];
    if let Some(steps) = job.get("steps") {
        for step in steps.as_array().ok_or("plan job steps must be an array")? {
            envs.push(
                step.as_object()
                    .ok_or("plan step must be an object")?
                    .get("env"),
            );
        }
    }
    for layer in envs {
        let map = object(layer, "plan job env")?;
        for name in ["STOOP_FULL", "STOOP_OFF", "STOOP_MAX_AGE"] {
            if map.contains_key(name) {
                return Ok(Some(format!("plan job overrides {name}")));
            }
        }
    }
    Ok(None)
}
fn run_defaults(v: Option<&Value>) -> Result<Map<String, Value>, String> {
    let outer = object(v, "defaults")?;
    if outer.keys().any(|k| k != "run") {
        return Err("unknown defaults field".into());
    }
    let run = object(outer.get("run"), "defaults.run")?;
    if run.keys().any(|k| k != "shell" && k != "working-directory") {
        return Err("unknown defaults.run field".into());
    }
    let mut out = Map::new();
    for (k, v) in run {
        out.insert(k.clone(), static_value(v)?);
    }
    Ok(out)
}
fn string<'a>(v: Option<&'a Value>, label: &str) -> Result<Option<&'a str>, String> {
    v.map(|v| {
        v.as_str()
            .ok_or_else(|| format!("{label} must be a string"))
    })
    .transpose()
}
fn cwd_key(s: &str) -> Result<String, String> {
    let mut parts = Vec::new();
    for c in Path::new(s).components() {
        match c {
            Component::CurDir => {}
            Component::Normal(p) => parts.push(p.to_str().ok_or("invalid working-directory")?),
            Component::ParentDir => {
                if parts.pop().is_none() {
                    return Err("working-directory escapes workspace".into());
                }
            }
            _ => return Err("absolute working-directory".into()),
        }
    }
    Ok(parts.join("/"))
}
fn shell(s: &str) -> Result<Option<u64>, String> {
    let words: Vec<_> = s.split_whitespace().collect();
    if words.len() < 3 || words[0] != "stoop" || words[1] != "sh" || words.last() != Some(&"{0}") {
        return Err("run step is not using stoop sh {0}".into());
    }
    let mut age = None;
    let mut i = 2;
    while i + 1 < words.len() {
        let opt = words[i];
        match opt {
            "--probe" | "--root" => return Err(format!("{opt} is not plannable")),
            "--sync-write" | "--no-record" | "--quiet" | "--allow-network" => i += 1,
            "--ignore" | "--ignore-env" | "--env" | "--max-age" | "--sync" | "--store"
            | "--key" => {
                if i + 2 >= words.len() || words[i + 1].contains(['\'', '"', '$', '`', '\\']) {
                    return Err(format!("invalid {opt} value"));
                }
                if opt == "--max-age" {
                    age = Some(crate::run::parse_age(words[i + 1])?);
                }
                i += 2;
            }
            _ => return Err(format!("unknown shell option {opt}")),
        }
    }
    Ok(age)
}
fn action_class(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    if n == "actions/checkout" {
        return Some("checkout");
    }
    if [
        "actions/cache",
        "actions/cache/restore",
        "actions/cache/save",
        "swatinem/rust-cache",
    ]
    .contains(&n.as_str())
    {
        return Some("cache");
    }
    if [
        "actions/setup-node",
        "actions/setup-python",
        "actions/setup-go",
        "actions/setup-java",
        "actions/setup-dotnet",
        "ruby/setup-ruby",
        "dtolnay/rust-toolchain",
        "actions-rust-lang/setup-rust-toolchain",
        "oven-sh/setup-bun",
        "pnpm/action-setup",
        "denoland/setup-deno",
        "erlef/setup-beam",
        "jdx/mise-action",
        "jwaldrip/stoop",
    ]
    .contains(&n.as_str())
    {
        return Some("setup");
    }
    None
}
fn check_setup(name: &str, fields: &Map<String, Value>) -> Result<(), String> {
    let n = name.to_ascii_lowercase();
    if n == "jdx/mise-action" || n == "pnpm/action-setup" {
        return Err(format!("{name} reads repository configuration"));
    }
    for field in [
        "node-version-file",
        "python-version-file",
        "go-version-file",
        "java-version-file",
        "jdk-file",
        "jdkfile",
        "global-json-file",
        "bun-version-file",
        "deno-version-file",
        "version-file",
        "package_json_file",
    ] {
        if fields.contains_key(field) {
            return Err(format!("{name} reads repository file via {field}"));
        }
    }
    let required = match n.as_str() {
        "actions/setup-python" => Some("python-version"),
        "ruby/setup-ruby" => Some("ruby-version"),
        "actions/setup-dotnet" => Some("dotnet-version"),
        "oven-sh/setup-bun" => Some("bun-version"),
        "actions-rust-lang/setup-rust-toolchain" => Some("toolchain"),
        _ => None,
    };
    if let Some(field) = required {
        match fields.get(field) {
            Some(Value::String(s))
                if !s.is_empty() && !s.eq_ignore_ascii_case("default") && !s.contains("${{") => {}
            _ => return Err(format!("{name} requires explicit {field}")),
        }
    }
    for field in ["bundler-cache", "run_install"] {
        if let Some(v) = fields.get(field) {
            if v != &Value::Bool(false) && v != "false" && v != "" {
                return Err(format!("{name} {field} can run repository code"));
            }
        }
    }
    Ok(())
}
fn action_with(class: &str, name: &str, fields: &Map<String, Value>) -> Result<Value, String> {
    let mut result = Map::new();
    for (k, v) in fields {
        if class == "checkout"
            && (["ref", "repository", "path", "sparse-checkout"].contains(&k.as_str())
                || (["submodules", "lfs"].contains(&k.as_str())
                    && v != &Value::Bool(false)
                    && v != "false")
                || (k == "clean"
                    && !matches!(v, Value::Null)
                    && !v
                        .as_str()
                        .is_some_and(|s| s.is_empty() || s.eq_ignore_ascii_case("true"))
                    && v != &Value::Bool(true)))
        {
            return Err(format!("checkout {k} is not supported"));
        }
        let excluded = match class {
            "checkout" => {
                [
                    "token",
                    "persist-credentials",
                    "fetch-depth",
                    "fetch-tags",
                    "filter",
                    "show-progress",
                    "set-safe-directory",
                    "github-server-url",
                ]
                .contains(&k.as_str())
                    || k.starts_with("ssh-")
            }
            "setup" => ["token", "cache", "cache-dependency-path"].contains(&k.as_str()),
            "cache" if name.eq_ignore_ascii_case("swatinem/rust-cache") => {
                !["workspaces", "cache-directories"].contains(&k.as_str())
            }
            "cache" => k != "path",
            _ => false,
        };
        if !excluded {
            result.insert(k.clone(), static_value(v)?);
        }
    }
    Ok(Value::Object(result))
}

pub fn job_specs(w: &Workflow, cx: &GhCtx, plan_job: &str) -> Vec<JobSpec> {
    let reason = match plan_job_override(w, plan_job) {
        Ok(reason) => reason,
        Err(error) => Some(error),
    };
    w.root["jobs"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
        .filter(|id| id.as_str() != plan_job)
        .map(|id| {
            let mut spec = job_spec(w, cx, id, None);
            if let Some(detail) = &reason {
                spec.key = None;
                spec.blocked = Some(Blocker {
                    step: None,
                    detail: detail.clone(),
                });
            }
            spec
        })
        .collect()
}

pub fn job_spec(w: &Workflow, cx: &GhCtx, job: &str, leg: Option<&str>) -> JobSpec {
    let mut spec = JobSpec {
        workflow: w.name.clone(),
        path: w.path.clone(),
        job: job.into(),
        leg: None,
        key: None,
        runs_on: Value::Null,
        needs: vec![],
        if_text: None,
        steps: vec![],
        blocked: None,
    };
    let result = build(w, cx, job, leg, &mut spec);
    if let Err((step, detail)) = result {
        spec.blocked = Some(Blocker { step, detail });
    }
    spec
}
fn build(
    w: &Workflow,
    cx: &GhCtx,
    job: &str,
    leg: Option<&str>,
    spec: &mut JobSpec,
) -> Result<(), (Option<usize>, String)> {
    let mut work = || -> Result<(), String> {
        let j = w.root["jobs"]
            .get(job)
            .and_then(Value::as_object)
            .ok_or("job missing or not an object")?;
        if let Some(k) = j.keys().find(|k| {
            ![
                "runs-on",
                "env",
                "defaults",
                "steps",
                "container",
                "services",
                "cache-mode",
                "name",
                "permissions",
                "needs",
                "if",
                "concurrency",
                "timeout-minutes",
                "continue-on-error",
                "strategy",
                "uses",
                "outputs",
                "environment",
            ]
            .contains(&k.as_str())
        }) {
            return Err(format!("unsupported job field {k}"));
        }
        if let Some(strategy) = j.get("strategy") {
            if let Some(k) = object(Some(strategy), "strategy")?
                .keys()
                .find(|k| !["matrix", "fail-fast", "max-parallel"].contains(&k.as_str()))
            {
                return Err(format!("unsupported strategy field {k}"));
            }
        }
        let workflow_settings = static_workflow_settings(w)?;
        stoop_settings(&[Some(&workflow_settings)])?;
        stoop_settings(&[Some(&workflow_settings), j.get("env")])?;
        let needs = match j.get("needs") {
            None => vec![],
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .ok_or("needs must contain strings".to_string())
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("invalid needs".into()),
        };
        spec.needs = needs;
        spec.if_text = j.get("if").map(|v| match v {
            Value::String(s) => s.clone(),
            _ => v.to_string(),
        });
        if j.contains_key("uses") {
            return Err("reusable uses is not supported".into());
        }
        if j.get("outputs")
            .is_some_and(|v| !v.is_null() && v.as_object().is_none_or(|m| !m.is_empty()))
        {
            return Err("job outputs are not supported".into());
        }
        if j.contains_key("environment") {
            return Err("job environment is not supported".into());
        }
        matrix::legs(j.get("strategy").unwrap_or(&Value::Null), cx).map_err(|e| e.0)?;
        let leg = match leg {
            Some(raw) => {
                crate::stepkey::canonical_matrix(raw).map_err(|e| format!("matrix: {e}"))?
            }
            None => None,
        };
        if leg.is_some() {
            return Err("matrix leg is not supported".into());
        }
        spec.leg = leg.clone();
        let runs = j.get("runs-on").ok_or("missing runs-on")?;
        spec.runs_on = static_value(runs)?;
        let mut all_env = env(w.root.get("env"))?;
        all_env.extend(env(j.get("env"))?);
        let mut defaults = run_defaults(w.root.get("defaults"))?;
        defaults.extend(run_defaults(j.get("defaults"))?);
        let mut keyed_steps = Vec::new();
        let steps = j
            .get("steps")
            .and_then(Value::as_array)
            .ok_or("steps must be an array")?;
        let mut seen_checkout = false;
        let mut seen_traced = false;
        for (n, step) in steps.iter().enumerate() {
            let idx = n + 1;
            let result = step_key(
                step,
                idx,
                &defaults,
                (&w.name, job),
                leg.as_deref(),
                &[Some(&workflow_settings), j.get("env")],
                seen_traced,
            );
            match result {
                Ok(Some((key, desc))) => {
                    if matches!(&desc, StepSpec::Neutral { what, .. } if action_name(what).is_some_and(|name| name.eq_ignore_ascii_case("actions/checkout")))
                    {
                        if seen_traced {
                            return Err("checkout after traced step".into());
                        }
                        seen_checkout = true;
                    }
                    if matches!(&desc, StepSpec::Traced { .. }) {
                        if !seen_checkout {
                            return Err("traced step requires preceding checkout".into());
                        }
                        seen_traced = true;
                    }
                    keyed_steps.push(key);
                    spec.steps.push(desc);
                }
                Ok(None) => {}
                Err(e) => {
                    spec.blocked = Some(Blocker {
                        step: Some(idx),
                        detail: e,
                    });
                    return Ok(());
                }
            }
        }
        if !spec
            .steps
            .iter()
            .any(|s| matches!(s, StepSpec::Traced { .. }))
        {
            return Err("no traced steps".into());
        }
        let key = json!({"schema": 1, "provider":"github", "workflow":w.name, "job":job, "matrix":leg, "runs_on":spec.runs_on, "container": static_value(j.get("container").unwrap_or(&Value::Null))?, "services": static_value(j.get("services").unwrap_or(&Value::Null))?, "env": all_env, "defaults":defaults, "workflow_cache_mode":static_value(w.root.get("cache-mode").unwrap_or(&Value::Null))?, "cache_mode":static_value(j.get("cache-mode").unwrap_or(&Value::Null))?, "steps":keyed_steps});
        let bytes = serde_json::to_vec(&key).map_err(|e| e.to_string())?;
        spec.key = Some(format!("job-{}", &blake3::hash(&bytes).to_hex()[..32]));
        Ok(())
    };
    work().map_err(|e| (None, e))
}
fn action_name(uses: &str) -> Option<String> {
    let (path, _) = uses.rsplit_once('@')?;
    Some(
        path.split(['/', '\\'])
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("/"),
    )
}
fn step_key(
    step: &Value,
    index: usize,
    defaults: &Map<String, Value>,
    identity: (&str, &str),
    leg: Option<&str>,
    env_layers: &[Option<&Value>],
    seen_traced: bool,
) -> Result<Option<(Value, StepSpec)>, String> {
    let s = step.as_object().ok_or("step must be an object")?;
    if let Some(k) = s.keys().find(|k| {
        ![
            "name",
            "id",
            "if",
            "run",
            "uses",
            "shell",
            "working-directory",
            "env",
            "with",
        ]
        .contains(&k.as_str())
    }) {
        return Err(format!("unsupported step field {k}"));
    }
    let cond = match s.get("if") {
        None | Some(Value::Bool(true)) => true,
        Some(Value::Bool(false)) => false,
        _ => return Err("step if is not a YAML boolean".into()),
    };
    if !cond {
        return Ok(None);
    }
    let e = env(s.get("env"))?;
    let raw_env = object(s.get("env"), "step env")?;
    let marker = raw_env.get("STOOP_PLAN") == Some(&Value::String("neutral".into()));
    let mut layers = env_layers.to_vec();
    layers.push(s.get("env"));
    let env_age = stoop_settings(&layers)?;
    let run = string(s.get("run"), "run")?;
    let uses = string(s.get("uses"), "uses")?;
    if run.is_some() == uses.is_some() {
        return Err("step must have exactly one of run or uses".into());
    }
    let shell_value = s.get("shell").or_else(|| defaults.get("shell"));
    let wd_value = s
        .get("working-directory")
        .or_else(|| defaults.get("working-directory"));
    let shell_text = string(shell_value, "shell")?.unwrap_or("");
    let wd = string(wd_value, "working-directory")?.unwrap_or("");
    static_value(&json!(shell_text))?;
    static_value(&json!(wd))?;
    if let Some(run) = run {
        static_value(&json!(run))?;
        if shell_text.split_whitespace().take(2).eq(["stoop", "sh"]) {
            let age = shell(shell_text)?.or(env_age);
            let key =
                crate::stepkey::sh_key(run.as_bytes(), identity.0, identity.1, &cwd_key(wd)?, leg);
            return Ok(Some((
                json!({"traced":{"key":key,"if":true,"env":e,"shell":shell_text,"working-directory":wd}}),
                StepSpec::Traced {
                    index,
                    key,
                    max_age: age,
                },
            )));
        }
        if !marker {
            return Err("run step is not traced and has no STOOP_PLAN neutral marker".into());
        }
        if seen_traced {
            return Err("neutral marker after traced step".into());
        }
        return Ok(Some((
            json!({"neutral":{"run":run,"env":e,"if":true,"shell":shell_text,"working-directory":wd}}),
            StepSpec::Neutral {
                index,
                what: "run".into(),
            },
        )));
    }
    let uses = uses.unwrap();
    static_value(&json!(uses))?;
    if uses.starts_with("./")
        || uses.starts_with(".\\")
        || uses.to_ascii_lowercase().starts_with("docker://")
    {
        return Err(format!("unsupported action {uses}"));
    }
    let (_, reference) = uses.rsplit_once('@').ok_or("action has no ref")?;
    let name = action_name(uses).ok_or("action has no ref")?;
    if name.is_empty() || reference.is_empty() {
        return Err("action has no ref".into());
    }
    let class = action_class(&name);
    if class.is_none() && !marker {
        return Err(format!("action {uses} is not allowlisted"));
    }
    if marker && seen_traced {
        return Err("neutral marker after traced step".into());
    }
    let mut normalized = Map::new();
    for (input, value) in object(s.get("with"), "with")? {
        if !input.is_ascii() {
            return Err(format!("non-ASCII action input {input}"));
        }
        let key = input.to_ascii_lowercase();
        if normalized.insert(key, value.clone()).is_some() {
            return Err(format!("duplicate action input {input}"));
        }
    }
    let with = &normalized;
    if class == Some("checkout") {
        action_with("checkout", &name, with)?;
    }
    if class == Some("setup") {
        check_setup(&name, with)?;
    }
    let fields = if marker {
        static_value(&Value::Object(with.clone()))?
    } else {
        action_with(class.unwrap(), &name, with)?
    };
    let is_cache = class == Some("cache") && !marker;
    let mut value = json!({"uses":uses,"with":fields,"env":e});
    if !is_cache {
        value["if"] = json!(true);
    }
    Ok(Some((
        json!({"neutral":value}),
        StepSpec::Neutral {
            index,
            what: uses.into(),
        },
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn fixture(extra: &str, steps: &str) -> String {
        format!("name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {{0}}\njobs:\n  test:\n    runs-on: ubuntu-latest\n{extra}    steps:\n      - uses: actions/checkout@v4\n{steps}")
    }
    fn spec(text: &str) -> JobSpec {
        let w = parse(".github/workflows/ci.yml", text).unwrap();
        job_spec(
            &w,
            &GhCtx::from_parts(BTreeMap::new(), Value::Null),
            "test",
            None,
        )
    }
    fn key(text: &str) -> String {
        let s = spec(text);
        assert!(s.blocked.is_none(), "{:?}", s.blocked);
        s.key.unwrap()
    }
    const RUN: &str = "      - run: cargo test\n";

    #[test]
    fn traced_key_matches_runtime_and_working_directory() {
        let s = spec(&fixture("", RUN));
        match &s.steps[1] {
            StepSpec::Traced { key, .. } => assert_eq!(
                *key,
                crate::stepkey::sh_key(b"cargo test", "fixture", "test", "", None)
            ),
            _ => panic!("not traced"),
        }
        let s = spec(&fixture(
            "",
            "      - run: cargo test\n        working-directory: ./app\n",
        ));
        match &s.steps[1] {
            StepSpec::Traced { key, .. } => assert_eq!(
                *key,
                crate::stepkey::sh_key(b"cargo test", "fixture", "test", "app", None)
            ),
            _ => panic!("not traced"),
        }
    }

    #[test]
    fn keys_cover_effects_and_exclude_non_keyed_fields() {
        let base = fixture("", RUN);
        let base_key = key(&base);
        assert_eq!(base_key, key(&fixture("    name: renamed\n    if: false\n    needs: other\n    env:\n      STOOP_SECRET: '${{ secrets.X }}'\n", "      - name: renamed\n        run: cargo test\n")));
        assert_ne!(
            base_key,
            key(&base.replace("ubuntu-latest", "macos-latest"))
        );
        assert_ne!(base_key, key(&base.replace("cargo test", "cargo build")));
        let action = fixture("", "      - uses: actions/setup-node@v4\n        with:\n          node-version: '20'\n      - run: cargo test\n");
        assert_ne!(key(&action), key(&action.replace("'20'", "'22'")));
        let cache = fixture("", "      - uses: actions/cache@v4\n        with:\n          key: old\n          path: target\n      - run: cargo test\n");
        assert_eq!(key(&cache), key(&cache.replace("key: old", "key: new")));
        assert_ne!(
            key(&cache),
            key(&cache.replace("path: target", "path: build"))
        );
    }

    #[test]
    fn unsafe_or_unknown_jobs_are_blocked() {
        let cases = [
            (fixture("", "      - uses: actions/upload-artifact@v4\n      - run: cargo test\n"), "upload-artifact"),
            (fixture("", "      - shell: bash\n        run: echo hi\n      - run: cargo test\n"), "not traced"),
            (fixture("", "      - run: '${{ github.ref }}'\n"), "expression"),
            (fixture("    strategy:\n      matrix:\n        os: [linux]\n", RUN), "matrix"),
            (fixture("    outputs: {result: value}\n", RUN), "outputs"),
            (fixture("    environment: production\n", RUN), "environment"),
            (fixture("    uses: owner/repo/.github/workflows/a.yml@v1\n", RUN), "reusable"),
            (fixture("", "      - uses: actions/checkout@v4\n        with: {ref: other}\n      - run: cargo test\n"), "checkout ref"),
            (fixture("", "      - shell: stoop sh --probe x {0}\n        run: cargo test\n"), "--probe"),
        ];
        for (text, expected) in cases {
            let s = spec(&text);
            let detail = s.blocked.expect(expected).detail;
            assert!(detail.contains(expected), "{detail:?} lacks {expected:?}");
            assert!(s.key.is_none());
        }
        let w = parse("ci.yml", &fixture("", RUN)).unwrap();
        let s = job_spec(
            &w,
            &GhCtx::from_parts(BTreeMap::new(), Value::Null),
            "test",
            Some("{"),
        );
        assert!(s.blocked.unwrap().detail.contains("matrix"));
    }

    #[test]
    fn unnamed_workflow_uses_path_and_aliases_are_blocked() {
        let t = fixture("", RUN).replace("name: fixture\n", "");
        let w = parse(".github/workflows/ci.yml", &t).unwrap();
        assert_eq!(w.name, ".github/workflows/ci.yml");
        assert!(parse("ci.yml", "jobs: &j {}\ncopy: *j\n").is_err());
    }
    #[test]
    fn neutral_marker_cannot_hide_a_traced_step_or_checkout_ref() {
        let s = spec(&fixture("", "      - shell: stoop  sh {0}\n        run: cargo test\n        env: {STOOP_PLAN: neutral}\n"));
        assert!(matches!(s.steps.get(1), Some(StepSpec::Traced { .. })));
        let s = spec(&fixture("", "      - uses: actions/checkout@v4\n        with: {ref: other}\n        env: {STOOP_PLAN: neutral}\n      - run: cargo test\n"));
        assert!(s.blocked.unwrap().detail.contains("checkout ref"));
    }
    #[test]
    fn review_blockers_and_checkout_safety() {
        let cases = [
            ("    snapshot: image\n", RUN, "snapshot"),
            ("    unknown: value\n", RUN, "unknown"),
            ("    env: {STOOP_FULL: '1'}\n", RUN, "STOOP_FULL"),
            ("    env: {STOOP_OFF: '${{ secrets.x }}'}\n", RUN, "STOOP_OFF"),
            ("", "      - run: x\n        env: {STOOP_OFF: '1'}\n", "STOOP_OFF"),
            ("", "      - uses: actions/setup-node@v4\n        with: {node-version-file: .nvmrc}\n      - run: x\n", "node-version-file"),
            ("", "      - uses: actions/setup-python@v5\n      - run: x\n", "python-version"),
            ("", "      - uses: ruby/setup-ruby@v1\n      - run: x\n", "ruby-version"),
            ("", "      - uses: actions/setup-dotnet@v4\n      - run: x\n", "dotnet-version"),
            ("", "      - uses: jdx/mise-action@v2\n      - run: x\n", "repository configuration"),
            ("", "      - uses: pnpm/action-setup@v4\n      - run: x\n", "repository configuration"),
            ("", "      - uses: ruby/setup-ruby@v1\n        with: {ruby-version: '3.3', bundler-cache: true}\n      - run: x\n", "bundler-cache"),
            ("", "      - uses: actions/checkout/@v4\n        with: {ref: other}\n        env: {STOOP_PLAN: neutral}\n      - run: x\n", "checkout ref"),
            ("", "      - uses: actions//checkout@v4\n        with: {path: other}\n        env: {STOOP_PLAN: neutral}\n      - run: x\n", "checkout path"),
            ("", "      - uses: actions/checkout@v4\n        with: {clean: 'False'}\n      - run: x\n", "checkout clean"),
            ("", "      - run: x\n      - shell: bash\n        run: npm test\n        env: {STOOP_PLAN: neutral}\n", "neutral marker after"),
            ("", "      - run: x\n      - uses: actions/checkout@v4\n", "checkout after"),
        ];
        for (extra, steps, expected) in cases {
            let detail = spec(&fixture(extra, steps)).blocked.expect(expected).detail;
            assert!(
                detail.contains(expected),
                "{detail} does not contain {expected}"
            );
        }
        let no_checkout = fixture("", RUN).replace("      - uses: actions/checkout@v4\n", "");
        assert!(spec(&no_checkout)
            .blocked
            .unwrap()
            .detail
            .contains("checkout"));
        for scalar in ["Null", "NULL", "-0"] {
            assert!(parse(
                "ci.yml",
                &fixture(&format!("    env: {{FOO: {scalar}}}\n"), RUN)
            )
            .is_err());
        }
    }

    #[test]
    fn max_age_precedence_and_marker_setup() {
        let text = fixture("    env: {STOOP_MAX_AGE: 1h}\n", "      - shell: bash\n        run: setup\n        env: {STOOP_PLAN: neutral}\n      - run: test\n        env: {STOOP_MAX_AGE: 60}\n");
        let s = spec(&text);
        assert!(s.blocked.is_none(), "{:?}", s.blocked);
        assert!(matches!(
            s.steps.last(),
            Some(StepSpec::Traced {
                max_age: Some(60),
                ..
            })
        ));
        let changed = text.replace(
            "      - run: test",
            "      - shell: stoop sh --max-age 2h {0}\n        run: test",
        );
        assert!(matches!(
            spec(&changed).steps.last(),
            Some(StepSpec::Traced {
                max_age: Some(7200),
                ..
            })
        ));
    }

    #[test]
    fn keyed_and_excluded_fields_table() {
        let base = fixture("", "      - shell: bash\n        run: prepare\n        env: {STOOP_PLAN: neutral}\n      - uses: actions/setup-node@v4\n        with: {node-version: '20', token: ignored}\n      - run: cargo test\n        env: {FOO: bar}\n");
        let key0 = key(&base);
        for (from, to) in [
            ("ubuntu-latest", "macos-latest"),
            ("    steps:", "    env: {VAR: new}\n    steps:"),
            ("    steps:", "    container: image\n    steps:"),
            (
                "    steps:",
                "    services: {db: {image: postgres}}\n    steps:",
            ),
            ("    steps:", "    cache-mode: read\n    steps:"),
            ("on: push", "on: push\ncache-mode: write"),
            ("FOO: bar", "FOO: other"),
            ("run: prepare", "run: other"),
            ("setup-node@v4", "setup-node@v5"),
            ("node-version: '20'", "node-version: '22'"),
            ("run: cargo test", "run: cargo build"),
            ("shell: stoop sh {0}", "shell: stoop sh --quiet {0}"),
        ] {
            assert_ne!(key0, key(&base.replace(from, to)), "{from}");
        }
        for (from, to) in [
            ("token: ignored", "token: changed"),
            ("    steps:", "    name: renamed\n    steps:"),
            ("    steps:", "    needs: other\n    steps:"),
            ("    steps:", "    if: false\n    steps:"),
        ] {
            assert_eq!(key0, key(&base.replace(from, to)), "{from}");
        }
    }
    #[test]
    fn action_inputs_are_case_insensitive_and_safe() {
        for (field, value) in [
            ("Ref", "other"),
            ("REPOSITORY", "other"),
            ("Path", "other"),
            ("Clean", "false"),
            ("Submodules", "true"),
            ("LFS", "true"),
            ("Sparse-Checkout", "other"),
        ] {
            let text = fixture("", &format!("      - uses: actions/checkout@v4\n        with: {{{field}: '{value}'}}\n      - run: test\n"));
            let detail = spec(&text).blocked.expect(field).detail;
            assert!(
                detail.contains(&format!("checkout {}", field.to_ascii_lowercase())),
                "{detail}"
            );
        }
        for (action, field, value) in [
            ("actions/setup-node", "Node-Version-File", ".nvmrc"),
            ("actions/setup-java", "jdkFile", "a"),
            ("erlef/setup-beam", "Version-File", "a"),
            ("ruby/setup-ruby", "Bundler-Cache", "true"),
        ] {
            let extra = if action == "ruby/setup-ruby" {
                ", ruby-version: '3.3'"
            } else {
                ""
            };
            let text = fixture("", &format!("      - uses: {action}@v1\n        with: {{{field}: '{value}'{extra}}}\n      - run: test\n"));
            let detail = spec(&text).blocked.expect(field).detail;
            assert!(
                detail
                    .to_ascii_lowercase()
                    .contains(&field.to_ascii_lowercase()),
                "{detail}"
            );
        }
        for action in [
            "oven-sh/setup-bun",
            "actions-rust-lang/setup-rust-toolchain",
        ] {
            let text = fixture(
                "",
                &format!("      - uses: {action}@v1\n      - run: test\n"),
            );
            assert!(spec(&text).blocked.is_some(), "{action}");
        }
        let cache = fixture("", "      - uses: actions/cache@v4\n        with: {Path: one, KEY: ignored}\n      - run: test\n");
        assert_ne!(key(&cache), key(&cache.replace("Path: one", "Path: two")));
        let bad = cache.replace("Path:", "Pıth:");
        assert!(spec(&bad).blocked.unwrap().detail.contains("non-ASCII"));
        let dup = cache.replace("Path: one", "Path: one, path: two");
        assert!(spec(&dup).blocked.unwrap().detail.contains("duplicate"));
    }

    #[test]
    fn workflow_flags_are_inherited_by_planner_not_rejected() {
        let text = fixture("", RUN).replace(
            "on: push\n",
            "on: push\nenv: {STOOP_FULL: \"${{ github.event_name }}\"}\n",
        );
        assert!(spec(&text).blocked.is_none());
        let text = fixture("    env: {STOOP_FULL: '${{ github.event_name }}'}\n", RUN);
        assert!(spec(&text).blocked.unwrap().detail.contains("STOOP_FULL"));
        for scalar in ["-0", "-00", "-000"] {
            assert!(parse(
                "ci.yml",
                &fixture(&format!("    env: {{X: {scalar}}}\n"), RUN)
            )
            .is_err());
        }
    }

    #[test]
    fn remaining_key_and_blocker_regressions() {
        let no_step = fixture("", "      - run: test\n        if: false\n");
        assert!(spec(&no_step).blocked.unwrap().detail.contains("no traced"));
        let with_step = fixture("", "      - run: test\n");
        let with_false = fixture(
            "",
            "      - run: ignored\n        if: false\n      - run: test\n",
        );
        assert_eq!(key(&with_step), key(&with_false));
        assert_ne!(
            key(&with_step),
            key(&fixture(
                "",
                "      - run: test\n        shell: stoop sh --quiet {0}\n"
            ))
        );
        let cases = [
            ("", "      - uses: actions/setup-node@v1\n        with: {node-version: '${{ x }}'}\n      - run: x\n", "expression"),
            ("", "      - run: x\n        shell: '${{ x }}'\n", "expression"),
            ("", "      - run: x\n        working-directory: '${{ x }}'\n", "expression"),
            ("", "      - uses: actions/checkout@v4\n        with: {repository: other}\n      - run: x\n", "repository"),
            ("", "      - uses: actions/checkout@v4\n        with: {submodules: true}\n      - run: x\n", "submodules"),
            ("", "      - uses: actions/checkout@v4\n        with: {lfs: true}\n      - run: x\n", "lfs"),
            ("", "      - shell: stoop sh --root x {0}\n        run: x\n", "--root"),
            ("", "      - run: x\n        timeout-minutes: 5\n", "timeout-minutes"),
            ("", "      - run: x\n        if: success()\n", "step if"),
            ("", "      - uses: docker://image\n      - run: x\n", "docker"),
            ("", "      - uses: '.\\\\local'\n      - run: x\n", "unsupported action"),
            ("    strategy: {unknown: value}\n", RUN, "strategy field"),
            ("", "      - uses: ruby/setup-ruby@v1\n        with: {ruby-version: default}\n      - run: x\n", "ruby-version"),
            ("", "      - run: x\n      - uses: actions/upload-artifact@v4\n        env: {STOOP_PLAN: neutral}\n", "neutral marker after"),
            ("", "      - run: x\n      - uses: actions//checkout@v4\n", "checkout after"),
        ];
        for (extra, steps, expected) in cases {
            let detail = spec(&fixture(extra, steps)).blocked.expect(expected).detail;
            assert!(detail.contains(expected), "{detail}: {expected}");
        }
        let checkout = fixture("", "      - uses: actions/checkout@v4\n        with: {fetch-depth: 1}\n      - run: test\n");
        assert_eq!(
            key(&checkout),
            key(&checkout.replace("fetch-depth: 1", "fetch-depth: 2"))
        );
        let age = spec(&fixture("    env: {STOOP_MAX_AGE: 1h}\n", RUN));
        assert!(matches!(
            age.steps.last(),
            Some(StepSpec::Traced {
                max_age: Some(3600),
                ..
            })
        ));
    }
    #[test]
    fn inherited_static_settings_and_plan_overrides_fail_wide() {
        let base = fixture("", RUN);
        let age = base.replace("on: push\n", "on: push\nenv: {STOOP_MAX_AGE: 1h}\n");
        assert!(matches!(
            spec(&age).steps.last(),
            Some(StepSpec::Traced {
                max_age: Some(3600),
                ..
            })
        ));
        for name in ["STOOP_FULL", "STOOP_OFF"] {
            let text = base.replace("on: push\n", &format!("on: push\nenv: {{{name}: '1'}}\n"));
            assert!(spec(&text).blocked.unwrap().detail.contains(name));
        }
        for name in ["STOOP_FULL", "STOOP_OFF", "STOOP_MAX_AGE"] {
            for location in ["job", "step"] {
                let plan = if location == "job" {
                    format!("  plan:\n    env: {{{name}: ''}}\n    runs-on: ubuntu-latest\n    steps: []\n")
                } else {
                    format!("  plan:\n    runs-on: ubuntu-latest\n    steps:\n      - run: stoop plan\n        env: {{{name}: '0'}}\n")
                };
                let text = base.replace("jobs:\n", &format!("jobs:\n{plan}"));
                let w = parse("ci.yml", &text).unwrap();
                let specs = job_specs(&w, &GhCtx::from_parts(BTreeMap::new(), Value::Null), "plan");
                assert_eq!(specs.len(), 1);
                assert!(specs[0].blocked.as_ref().unwrap().detail.contains(name));
                assert!(specs[0].key.is_none());
            }
        }
    }
}
