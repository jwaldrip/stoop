use std::path::{Component, Path};

use serde_json::{json, Map, Value};
use yaml_rust2::parser::{Event, EventReceiver, Parser};
use yaml_rust2::{Yaml, YamlLoader};

#[derive(Default)]
struct AliasCheck(bool);
impl EventReceiver for AliasCheck {
    fn on_event(&mut self, event: Event) {
        if matches!(event, Event::Alias(_)) {
            self.0 = true;
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
    let mut aliases = AliasCheck::default();
    Parser::new_from_str(text)
        .load(&mut aliases, true)
        .map_err(|e| e.to_string())?;
    if aliases.0 {
        return Err("YAML aliases are not supported".into());
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
fn action_with(class: &str, name: &str, fields: &Map<String, Value>) -> Result<Value, String> {
    let mut result = Map::new();
    for (k, v) in fields {
        if class == "checkout"
            && (["ref", "repository", "path", "sparse-checkout"].contains(&k.as_str())
                || (["submodules", "lfs"].contains(&k.as_str())
                    && v != &Value::Bool(false)
                    && v != "false")
                || (k == "clean" && (v == &Value::Bool(false) || v == "false")))
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
    w.root["jobs"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
        .filter(|id| id.as_str() != plan_job)
        .map(|id| job_spec(w, cx, id, None))
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
        for (n, step) in steps.iter().enumerate() {
            let idx = n + 1;
            let result = step_key(step, idx, &defaults, &w.name, job, leg.as_deref());
            match result {
                Ok(Some((key, desc))) => {
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
        let key = json!({"schema": 1, "provider":"github", "workflow":w.name, "job":job, "matrix":leg, "runs_on":spec.runs_on, "container": static_value(j.get("container").unwrap_or(&Value::Null))?, "services": static_value(j.get("services").unwrap_or(&Value::Null))?, "env": all_env, "defaults":defaults, "steps":keyed_steps});
        let bytes = serde_json::to_vec(&key).map_err(|e| e.to_string())?;
        spec.key = Some(format!("job-{}", &blake3::hash(&bytes).to_hex()[..32]));
        Ok(())
    };
    work().map_err(|e| (None, e))
}
fn step_key(
    step: &Value,
    index: usize,
    defaults: &Map<String, Value>,
    workflow: &str,
    job: &str,
    leg: Option<&str>,
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
            let age = shell(shell_text)?;
            let key = crate::stepkey::sh_key(run.as_bytes(), workflow, job, &cwd_key(wd)?, leg);
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
    if uses.starts_with("./") || uses.starts_with("docker://") {
        return Err(format!("unsupported action {uses}"));
    }
    let (name, reference) = uses.rsplit_once('@').ok_or("action has no ref")?;
    if name.is_empty() || reference.is_empty() {
        return Err("action has no ref".into());
    }
    let class = action_class(name);
    if class.is_none() && !marker {
        return Err(format!("action {uses} is not allowlisted"));
    }
    let with = object(s.get("with"), "with")?;
    if class == Some("checkout") {
        action_with("checkout", name, with)?;
    }
    let fields = if marker {
        static_value(&Value::Object(with.clone()))?
    } else {
        action_with(class.unwrap(), name, with)?
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
        format!("name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {{0}}\njobs:\n  test:\n    runs-on: ubuntu-latest\n{extra}    steps:\n{steps}")
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
        match &s.steps[0] {
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
        match &s.steps[0] {
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
        assert!(matches!(s.steps.first(), Some(StepSpec::Traced { .. })));
        let s = spec(&fixture("", "      - uses: actions/checkout@v4\n        with: {ref: other}\n        env: {STOOP_PLAN: neutral}\n      - run: cargo test\n"));
        assert!(s.blocked.unwrap().detail.contains("checkout ref"));
    }
}
