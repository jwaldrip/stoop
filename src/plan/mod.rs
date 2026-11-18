pub mod eval;
mod graph;
mod output;
pub mod spec;

use crate::{attest, gha, input, job, proof, run, sync};
use serde_json::{json, Value};
use spec::{Code, Decision, JobSpec, RecordCheck, StepSpec};
use std::path::{Path, PathBuf};
const HELP: &str = "stoop plan [--workflow PATH] [--rev REV] [--plan-job ID] [--format human|json|github] [--output FILE] [--root DIR] [--store DIR] [--sync git[:REMOTE]] [--max-age DUR] [--allow-uses OWNER/REPO[@REF]] [--explain] [--quiet]\nPlan-time skips are experimental. --max-age defaults to 7d and must be positive.\n";
struct Options {
    workflow: Option<String>,
    rev: String,
    plan_job: String,
    format: String,
    output: Option<String>,
    root: Option<PathBuf>,
    store: Option<PathBuf>,
    sync: Option<String>,
    max_age: u64,
    explain: bool,
    quiet: bool,
    allowed: Vec<String>,
}
fn parse(args: &[String]) -> Result<Option<Options>, String> {
    let mut o = Options {
        workflow: None,
        rev: "HEAD".into(),
        plan_job: std::env::var("GITHUB_JOB").unwrap_or_else(|_| "stoop-plan".into()),
        format: if std::env::var_os("GITHUB_OUTPUT").is_some() {
            "github"
        } else {
            "human"
        }
        .into(),
        output: None,
        root: None,
        store: None,
        sync: None,
        max_age: run::DEFAULT_MAX_AGE,
        explain: false,
        quiet: false,
        allowed: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        }
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--workflow" => o.workflow = Some(value()?),
            "--rev" => o.rev = value()?,
            "--plan-job" => o.plan_job = value()?,
            "--format" => o.format = value()?,
            "--output" => o.output = Some(value()?),
            "--root" => o.root = Some(value()?.into()),
            "--allow-uses" => {
                let entry = value()?;
                let parsed = gha::workflow::parse_allow_uses(&entry)?;
                if parsed.len() != 1 {
                    return Err(format!("invalid --allow-uses {entry}"));
                }
                o.allowed.extend(parsed);
            }
            "--store" => o.store = Some(value()?.into()),
            "--sync" => o.sync = Some(value()?),
            "--max-age" => o.max_age = run::parse_age(&value()?)?,
            "--explain" => o.explain = true,
            "--quiet" => o.quiet = true,
            _ => return Err(format!("unknown option {arg}")),
        }
    }
    if !["human", "json", "github"].contains(&o.format.as_str()) {
        return Err(format!("unknown format {}", o.format));
    }
    if !o.allowed.is_empty()
        && (std::env::var_os("GITHUB_OUTPUT").is_some()
            || (o.format == "github" && run::env_flag("GITHUB_ACTIONS")))
    {
        return Err("--allow-uses is only available for local dry runs".into());
    }
    if o.max_age == 0 {
        return Err("--max-age must be positive".into());
    }
    Ok(Some(o))
}

struct Composite<'a, S: attest::KeySource> {
    verifier: &'a attest::Verifier<S>,
    actions: &'a gha::resolve::ActionCheck<'a>,
    proofs: &'a proof::Store,
    now: u64,
    ceiling: u64,
}
impl<S: attest::KeySource> RecordCheck for Composite<'_, S> {
    fn check(&self, spec: &JobSpec, record: &job::JobRecord) -> Result<(), (Code, String)> {
        let verified = self.verifier.verify(spec, record)?;
        for (step, saved) in spec
            .steps
            .iter()
            .filter(|s| matches!(s, StepSpec::Traced { .. }))
            .zip(&record.steps)
        {
            if let StepSpec::Traced {
                index,
                key,
                max_age,
            } = step
            {
                let proof = self
                    .proofs
                    .load(key)
                    .into_iter()
                    .find(|p| p.digest() == saved.proof)
                    .ok_or((Code::ProofMissing, format!("step {index}: proof missing")))?;
                let age = max_age
                    .filter(|v| *v != 0)
                    .unwrap_or(self.ceiling)
                    .min(self.ceiling);
                if self.now.saturating_sub(proof.created.min(verified.iat())) > age {
                    return Err((
                        Code::Expired,
                        format!("step {index}: attested proof expired"),
                    ));
                }
            }
        }
        self.actions.check(spec, record)
    }
}
fn run_decision(code: Code, detail: impl Into<String>) -> Decision {
    Decision {
        skip: false,
        code,
        detail: detail.into(),
        evidence: None,
        mismatches: vec![],
    }
}
fn show(root: &Path, rev: &str, path: &str) -> Result<String, String> {
    if path.is_empty()
        || Path::new(path).is_absolute()
        || path.split('/').any(|p| p == ".." || p.is_empty())
    {
        return Err("invalid workflow path".into());
    }
    let out = std::process::Command::new("git")
        .current_dir(root)
        .env("GIT_NO_LAZY_FETCH", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .args(["show", &format!("{rev}:{path}")])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("cannot read workflow {path}"));
    }
    String::from_utf8(out.stdout).map_err(|_| "workflow is not UTF-8".into())
}
fn workflow_path(o: &Options) -> Result<String, String> {
    if let Some(path) = &o.workflow {
        return Ok(path.clone());
    }
    let repo = std::env::var("GITHUB_REPOSITORY").map_err(|_| "GITHUB_REPOSITORY is missing")?;
    let r = std::env::var("GITHUB_WORKFLOW_REF").map_err(|_| "GITHUB_WORKFLOW_REF is missing")?;
    r.strip_prefix(&format!("{repo}/"))
        .and_then(|s| s.rsplit_once('@').map(|(p, _)| p.to_string()))
        .ok_or_else(|| "invalid GITHUB_WORKFLOW_REF".into())
}
fn plan_override(w: &gha::workflow::Workflow, id: &str) -> Result<(), String> {
    let job = w.root["jobs"]
        .get(id)
        .and_then(Value::as_object)
        .ok_or("plan job does not exist")?;
    let mut layers = vec![
        job.get("env"),
        job.get("container").and_then(|c| c.get("env")),
    ];
    if let Some(steps) = job.get("steps") {
        for step in steps.as_array().ok_or("plan job steps must be an array")? {
            layers.push(step.get("env"));
        }
    }
    for layer in layers.into_iter().flatten() {
        let env = layer.as_object().ok_or("plan job env must be an object")?;
        for name in ["STOOP_FULL", "STOOP_OFF", "STOOP_MAX_AGE"] {
            if env.contains_key(name) {
                return Err(format!("plan job overrides {name}"));
            }
        }
    }
    Ok(())
}
pub fn cmd(args: &[String]) -> i32 {
    let o = match parse(args) {
        Ok(Some(o)) => o,
        Ok(None) => {
            print!("{HELP}");
            return 0;
        }
        Err(e) => {
            eprintln!("stoop: {e}\n{HELP}");
            return 2;
        }
    };
    let root = o
        .root
        .clone()
        .unwrap_or_else(|| run::find_root(&std::env::current_dir().unwrap_or_default()));
    let path = workflow_path(&o).unwrap_or_default();
    let mut plan = json!({"schema":"stoop.plan/1","workflow":"","path":path,"rev":"","plan_job":o.plan_job,"full":run::env_flag("STOOP_FULL"),"skip":[],"jobs":[]});
    let result = build(&o, &root, &path, &mut plan, attest::github);
    let warning = result.err();
    if let Err(e) = output::emit(
        &plan,
        &o.format,
        o.output.as_deref(),
        o.quiet,
        warning.as_deref(),
    ) {
        eprintln!("::warning::stoop plan: cannot write output: {e}");
    }
    0
}
fn build<S: attest::KeySource>(
    o: &Options,
    root: &Path,
    path: &str,
    out: &mut Value,
    verifier_factory: impl FnOnce(attest::Policy, u64, u64) -> attest::Verifier<S>,
) -> Result<(), String> {
    let mut tree = crate::gittree::GitTree::load(root, &o.rev).map_err(|e| e.0)?;
    out["rev"] = json!(tree.commit());
    let text = show(root, tree.commit(), path)?;
    let workflow = gha::workflow::parse(path, &text)?;
    out["workflow"] = json!(workflow.name);
    let cx = gha::context::GhCtx::from_env()?;
    let specs = gha::workflow::job_specs_with_allow(&workflow, &cx, &o.plan_job, &o.allowed);
    if o.explain {
        eprintln!("stoop: STOOP_ALLOW_USES actions are assumed side-effect free by the workflow author's assertion");
        if !o.allowed.is_empty() {
            eprintln!("stoop: --allow-uses is a local dry-run list and cannot match records made with different actions");
        }
    }
    let mut global_error = plan_override(&workflow, &o.plan_job).err();
    if std::env::var("GITHUB_JOB").ok().as_deref() != Some(o.plan_job.as_str()) {
        global_error = Some("plan job differs from GITHUB_JOB".into());
    }
    if run::env_flag("GITHUB_ACTIONS")
        && std::env::var("GITHUB_SHA").ok().as_deref() != Some(tree.commit())
    {
        global_error = Some("planned revision differs from GITHUB_SHA".into());
    }
    let dir = o
        .store
        .clone()
        .or_else(|| run::env_str("STOOP_STORE").map(PathBuf::from))
        .unwrap_or_else(|| root.join(".stoop"));
    let proofs = proof::Store::new(dir.clone());
    let jobs = job::JobStore::new(dir);
    if let Some(remote) = o.sync.clone().or_else(|| run::env_str("STOOP_SYNC")) {
        if let Err(e) = sync::Remote::from_spec(&remote, root, false)
            .and_then(|r| r.pull_all(&proofs, &jobs).map(|_| ()))
        {
            global_error = Some(format!("sync: {e}"));
        }
    }
    let now = proof::now();
    let branch = cx
        .event
        .pointer("/repository/default_branch")
        .and_then(Value::as_str)
        .unwrap_or("");
    let policy = attest::Policy::default_branch(
        &std::env::var("GITHUB_REPOSITORY").unwrap_or_default(),
        &std::env::var("GITHUB_REPOSITORY_ID").unwrap_or_default(),
        &std::env::var("GITHUB_REPOSITORY_OWNER_ID").unwrap_or_default(),
        branch,
    );
    let verifier = verifier_factory(policy, now, o.max_age);
    let resolver = gha::resolve::Git::from_env(root);
    let actions =
        gha::resolve::ActionCheck::with_strict(&resolver, run::env_flag("STOOP_STRICT_ACTIONS"));
    let check = Composite {
        verifier: &verifier,
        actions: &actions,
        proofs: &proofs,
        now,
        ceiling: o.max_age,
    };
    let event_path = run::env_str("GITHUB_EVENT_PATH");
    let event = event_path
        .as_ref()
        .and_then(|p| input::identify(Path::new(p), false, false));
    let mut ctx = eval::PlanCtx {
        tree: &mut tree,
        proofs: &proofs,
        jobs: &jobs,
        check: &check,
        now,
        max_age: o.max_age,
        github_vars: cx.verified_vars(&o.plan_job),
        salt: run::env_str("STOOP_ENV_SALT"),
        event_path,
        event,
        explain: o.explain,
    };
    let mut results = Vec::new();
    let mut skip = Vec::new();
    for spec in &specs {
        let gate = graph::check(&workflow, spec, &o.plan_job);
        let gated = gate.is_none();
        let decision = if run::env_flag("STOOP_FULL") {
            run_decision(Code::Full, "STOOP_FULL enabled")
        } else if let Some(error) = &global_error {
            run_decision(Code::Error, error.clone())
        } else if let Some((code, detail)) = gate {
            run_decision(code, detail)
        } else {
            eval::decide(spec, &mut ctx)
        };
        if o.explain {
            for (step, path, why) in &decision.mismatches {
                eprintln!("stoop: step {step}: {path}: {why}");
            }
        }
        if decision.skip {
            skip.push(spec.job.clone());
        }
        results.push(output::job(
            &spec.job,
            gated,
            &decision,
            spec.key.as_deref(),
        ));
    }
    out["skip"] = json!(skip);
    out["jobs"] = json!(results);
    if let Some(error) = global_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attest::tests as a;
    use crate::job::{RecordStatus, StepHow, StepRecord};
    use std::collections::BTreeMap;
    use std::process::Command;

    #[test]
    fn injected_planner_proves_an_attested_record() {
        if let Some(root) = std::env::var_os("STOOP_TEST_PLAN_CHILD") {
            let root = PathBuf::from(root);
            let args = vec![
                "--workflow".into(),
                ".github/workflows/ci.yml".into(),
                "--format".into(),
                "json".into(),
            ];
            let opts = parse(&args).unwrap().unwrap();
            let mut plan = json!({"skip": [], "jobs": []});
            build(
                &opts,
                &root,
                ".github/workflows/ci.yml",
                &mut plan,
                |policy, now, age| {
                    attest::Verifier::new(policy, a::Fixed(a::published()), now, age)
                },
            )
            .unwrap();
            assert_eq!(plan["skip"], json!(["a"]));
            assert_eq!(plan["jobs"][0]["code"], "proved");
            return;
        }
        let root = std::env::temp_dir().join(format!("stoop-injected-plan-{}", std::process::id()));
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        let workflow_text = "name: fixture\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: cat a.txt > /dev/null\n";
        let path = ".github/workflows/ci.yml";
        std::fs::write(root.join(path), workflow_text).unwrap();
        std::fs::write(root.join("a.txt"), "a\n").unwrap();
        for args in [
            &["init", "-q"][..],
            &["add", "."][..],
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ][..],
        ] {
            assert!(Command::new("git")
                .current_dir(&root)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        let sha = String::from_utf8(
            Command::new("git")
                .current_dir(&root)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let event = root.join("event.json");
        std::fs::write(&event, r#"{"repository":{"default_branch":"main"}}"#).unwrap();
        let workflow = gha::workflow::parse(path, workflow_text).unwrap();
        let cx = gha::context::GhCtx::from_parts(BTreeMap::new(), Value::Null);
        let spec = gha::workflow::job_spec(&workflow, &cx, "a", None);
        let key = spec.key.as_deref().unwrap();
        let step = match &spec.steps[1] {
            StepSpec::Traced { key, .. } => key,
            _ => panic!("expected traced step"),
        };
        let now = proof::now();
        let proof = proof::Proof {
            created: now,
            argv: vec![],
            env: BTreeMap::new(),
            inputs: vec![input::Input {
                path: "a.txt".into(),
                id: format!("f:{}", blake3::hash(b"a\n").to_hex()),
            }],
            outputs: vec![],
            removed: vec![],
            ignore: Some(vec![]),
            priors: Some(vec![]),
            unplannable: vec![],
            probes: BTreeMap::new(),
        };
        let store = root.join(".stoop");
        proof::Store::new(store.clone())
            .save(step, proof.clone())
            .unwrap();
        let mut record = a::record();
        record.created = now;
        record.started = now * 1000;
        record.status = Some(RecordStatus::Passed);
        record.commit = Some(sha.clone());
        record.event_path = Some(event.to_string_lossy().into_owned());
        record.actions = BTreeMap::from([(
            "actions/checkout@1111111111111111111111111111111111111111".into(),
            "1111111111111111111111111111111111111111".into(),
        )]);
        record.steps = vec![StepRecord {
            key: step.clone(),
            proof: proof.digest(),
            how: StepHow::Ran,
        }];
        let mut claims = a::claims(&record);
        claims["aud"] = json!(attest::audience(key, &record).unwrap());
        claims["sha"] = json!(sha);
        claims["iat"] = json!(now);
        claims["nbf"] = json!(now);
        record.attest = Some(a::token(
            &a::header("test-key-1"),
            &claims,
            &a::pair(a::KEY_1),
        ));
        job::JobStore::new(store).save(key, record).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "plan::tests::injected_planner_proves_an_attested_record",
                "--nocapture",
            ])
            .env("STOOP_TEST_PLAN_CHILD", &root)
            .env("GITHUB_JOB", "stoop-plan")
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_REPOSITORY", a::REPO)
            .env("GITHUB_REPOSITORY_ID", a::REPO_ID)
            .env("GITHUB_REPOSITORY_OWNER_ID", a::OWNER_ID)
            .env("GITHUB_SHA", &sha)
            .env("GITHUB_EVENT_PATH", &event)
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_ENV_SALT")
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
