//! Planner regression cases using local repositories and a test-only signing key.
use super::*;
use crate::attest::tests as a;
use crate::job::{JobRecord, RecordStatus, StepHow, StepRecord};
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
const DAY: u64 = 86_400;
const PIN: &str = "1111111111111111111111111111111111111111";
const CI: &str = ".github/workflows/ci.yml";

fn git(root: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

struct Repo {
    base: PathBuf,
    root: PathBuf,
    sha: String,
    event: PathBuf,
}

impl Repo {
    fn new(files: &[(&str, &str)]) -> Repo {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("s4probe-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("repo");
        for (p, text) in files {
            let path = root.join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        }
        git(&root, &["init", "-q", "-b", "main"]);
        git(&root, &["add", "."]);
        git(&root, &["commit", "-qm", "fixture"]);
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
        let event = base.join("event.json");
        std::fs::write(&event, r#"{"repository":{"default_branch":"main"}}"#).unwrap();
        Repo {
            base,
            root,
            sha,
            event,
        }
    }
    fn store(&self) -> PathBuf {
        self.root.join(".stoop")
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        if std::env::var_os("PROBE_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
}

fn file(path: &str, bytes: &[u8]) -> input::Input {
    input::Input {
        path: path.into(),
        id: format!("f:{}", blake3::hash(bytes).to_hex()),
    }
}

struct Rec<'a> {
    path: &'a str,
    text: &'a str,
    job: &'a str,
    created: u64,
    iat: u64,
    attested: bool,
    inputs: Vec<input::Input>,
}

/// Publish a passed record for `job` the way S2b/B5 would, attested with the test key.
/// Returns None when the planner's own spec is blocked (nothing could be recorded).
fn record(r: &Repo, x: Rec<'_>) -> Option<String> {
    let workflow = gha::workflow::parse(x.path, x.text).unwrap();
    let cx = gha::context::GhCtx::from_parts(BTreeMap::new(), Value::Null);
    let spec = gha::workflow::job_specs(&workflow, &cx, "stoop-plan")
        .into_iter()
        .find(|s| s.job == x.job)
        .unwrap();
    if spec.blocked.is_some() {
        return None;
    }
    let key = spec.key.clone().unwrap();
    let mut steps = Vec::new();
    for s in &spec.steps {
        if let StepSpec::Traced { key: step, .. } = s {
            let p = proof::Proof {
                created: x.created,
                argv: vec![],
                cwd: Some(String::new()),
                scope: None,
                provenance: Some(crate::trace::Provenance {
                    os: "linux".into(),
                    arch: "x86_64".into(),
                    tracer: "ptrace-seccomp".into(),
                    version: 4,
                }),
                env: BTreeMap::new(),
                inputs: x.inputs.clone(),
                outputs: vec![],
                removed: vec![],
                ignore: Some(vec![]),
                priors: Some(vec![]),
                unplannable: vec![],
                probes: BTreeMap::new(),
            };
            proof::Store::new(r.store()).save(step, p.clone()).unwrap();
            steps.push(StepRecord {
                key: step.clone(),
                proof: p.digest(),
                how: StepHow::Ran,
            });
        }
    }
    let workflow_ref = format!("{}/{}@refs/heads/main", a::REPO, x.path);
    let mut rec: JobRecord = a::record();
    rec.created = x.iat;
    rec.started = x.iat * 1000;
    rec.status = Some(RecordStatus::Passed);
    rec.commit = Some(r.sha.clone());
    rec.event_path = Some(r.event.to_string_lossy().into_owned());
    rec.workflow_ref = Some(workflow_ref.clone());
    rec.actions = spec
        .actions
        .iter()
        .map(|u| (u.clone(), u.rsplit_once('@').unwrap().1.to_string()))
        .collect();
    rec.steps = steps;
    if x.attested {
        let mut claims = a::claims(&rec);
        claims["aud"] = json!(attest::audience(&key, &rec).unwrap());
        claims["sha"] = json!(r.sha);
        claims["iat"] = json!(x.iat);
        claims["nbf"] = json!(x.iat);
        claims["workflow_ref"] = json!(workflow_ref);
        claims["job_workflow_ref"] = json!(workflow_ref);
        rec.attest = Some(a::token(
            &a::header("test-key-1"),
            &claims,
            &a::pair(a::KEY_1),
        ));
    }
    job::JobStore::new(r.store()).save(&key, rec).unwrap();
    Some(key)
}

/// The child: `cmd` with the test key injected.
#[test]
fn probe_child() {
    let Some(root) = std::env::var_os("PROBE_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let args: Vec<String> = serde_json::from_str(&std::env::var("PROBE_ARGS").unwrap()).unwrap();
    let o = match parse(&args) {
        Ok(Some(o)) => o,
        Ok(None) => panic!("help"),
        Err(e) => {
            println!("PLANUSAGE {e}");
            return;
        }
    };
    let path = workflow_path(&o).unwrap_or_default();
    let mut plan = json!({"schema":"stoop.plan/1","workflow":"","path":path,"rev":"","plan_job":o.plan_job,"full":run::env_flag("STOOP_FULL"),"skip":[],"jobs":[]});
    if let Ok(warning) = std::env::var("PROBE_WARNING") {
        output::emit(&plan, &o.format, None, false, Some(&warning)).unwrap();
        println!(
            "PLANJSON {}",
            serde_json::to_string(&plan)
                .unwrap()
                .replace("##[", "#\\u0023[")
                .replace("::", "\\u003a\\u003a")
        );
        return;
    }
    let result = build(&o, &root, &path, &mut plan, |policy, now, age| {
        attest::Verifier::new(policy, a::Fixed(a::published()), now, age)
    });
    let warning = result.err();
    output::emit(
        &plan,
        &o.format,
        o.output.as_deref(),
        o.quiet,
        warning.as_deref(),
    )
    .unwrap();
    println!(
        "PLANJSON {}",
        serde_json::to_string(&plan)
            .unwrap()
            .replace("##[", "#\\u0023[")
            .replace("::", "\\u003a\\u003a")
    );
}

struct Out {
    plan: Value,
    stdout: String,
    stderr: String,
}

fn plan(r: &Repo, args: &[&str], env: &[(&str, &str)]) -> Out {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args([
        "--exact",
        "plan::probes::probe_child",
        "--nocapture",
        "--test-threads=1",
    ])
    .current_dir(&r.root)
    .env("PROBE_ROOT", &r.root)
    .env("PROBE_ARGS", serde_json::to_string(args).unwrap())
    .env("GITHUB_JOB", "stoop-plan")
    .env("GITHUB_ACTIONS", "true")
    .env("GITHUB_REPOSITORY", a::REPO)
    .env("GITHUB_REPOSITORY_ID", a::REPO_ID)
    .env("GITHUB_REPOSITORY_OWNER_ID", a::OWNER_ID)
    .env("GITHUB_SHA", &r.sha)
    .env("GITHUB_EVENT_PATH", &r.event)
    .env(
        "GITHUB_WORKFLOW_REF",
        format!("{}/{CI}@refs/heads/main", a::REPO),
    )
    .env(
        "STOOP_JOB_WORKFLOW_REF",
        format!("{}/{CI}@refs/heads/main", a::REPO),
    );
    for k in [
        "GITHUB_OUTPUT",
        "GITHUB_STEP_SUMMARY",
        "STOOP_SYNC",
        "STOOP_FULL",
        "STOOP_OFF",
        "STOOP_MAX_AGE",
        "STOOP_ENV_SALT",
        "STOOP_STORE",
        "STOOP_STRICT_ACTIONS",
        "STOOP_ALLOW_USES",
    ] {
        c.env_remove(k);
    }
    for (k, v) in env {
        if *k == "GITHUB_WORKFLOW_REF" && v.is_empty() {
            c.env_remove(k);
        } else {
            c.env(k, v);
        }
    }
    let out = c.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let line = stdout
        .lines()
        .find_map(|l| l.find("PLANJSON ").map(|i| &l[i + 9..]))
        .unwrap_or_else(|| panic!("no plan\n{stdout}\n{stderr}"));
    Out {
        plan: serde_json::from_str(line).unwrap(),
        stdout,
        stderr,
    }
}

fn code(o: &Out, job: &str) -> String {
    o.plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|j| j["id"] == job)
        .map(|j| j["code"].as_str().unwrap().to_string())
        .unwrap_or_else(|| "absent".into())
}

fn report(name: &str, o: &Out) {
    let jobs = o.plan["jobs"]
        .as_array()
        .map(|js| {
            js.iter()
                .map(|j| {
                    format!(
                        "{}={} ({})",
                        j["id"].as_str().unwrap_or("?"),
                        j["code"].as_str().unwrap_or("?"),
                        j["detail"].as_str().unwrap_or("")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default();
    eprintln!(
        "OBS {}: skip={} {}",
        output::escape(name),
        o.plan["skip"],
        output::escape(&jobs)
    );
}

fn workflow(top: &str, a_extra: &str, more_jobs: &str) -> String {
    format!(
        "name: fixture\n{top}defaults:\n  run:\n    shell: stoop sh {{0}}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}}}\n    runs-on: ubuntu-latest\n{a_extra}    steps:\n      - uses: actions/checkout@{PIN}\n      - run: cat a.txt > /dev/null\n{more_jobs}"
    )
}

fn rec<'a>(text: &'a str, created: u64, iat: u64) -> Rec<'a> {
    Rec {
        path: CI,
        text,
        job: "a",
        created,
        iat,
        attested: true,
        inputs: vec![file("a.txt", b"a\n")],
    }
}

#[test]
fn control_baseline_proves() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[]);
    report("baseline", &o);
    assert_eq!(o.plan["skip"], json!(["a"]));
    let o = plan(&r, &["--format", "github"], &[]);
    assert!(o.stdout.contains("skip=,a,\n"), "{}", o.stdout);
}

#[test]
fn external_store_scoped_record_can_prove_a_plan_skip() {
    let workflow = workflow("", "", "");
    let repo = Repo::new(&[(CI, &workflow), ("a.txt", "a\n")]);
    let now = proof::now();
    let job_key = record(&repo, rec(&workflow, now, now)).unwrap();
    let local_proofs = proof::Store::new(repo.store());
    let local_jobs = job::JobStore::new(repo.store());
    let external = repo.base.join("shared-store");
    let scope = run::shared_scope(&std::fs::canonicalize(&repo.root).unwrap(), &external).unwrap();
    let proofs = proof::Store::new(external.clone());
    let jobs = job::JobStore::new(external.clone());
    let mut record = local_jobs.load(&job_key).remove(0);
    for step in &mut record.steps {
        let mut proof = local_proofs.load(&step.key).remove(0);
        proof.scope = Some(scope.clone());
        step.key = crate::stepkey::scoped(&step.key, Some(&scope));
        step.proof = proof.digest();
        proofs.save(&step.key, proof).unwrap();
    }
    let mut claims = a::claims(&record);
    claims["aud"] = json!(attest::audience(&job_key, &record).unwrap());
    claims["sha"] = json!(repo.sha);
    claims["iat"] = json!(now);
    claims["nbf"] = json!(now);
    claims["workflow_ref"] = json!(format!("{}/{CI}@refs/heads/main", a::REPO));
    claims["job_workflow_ref"] = claims["workflow_ref"].clone();
    record.attest = Some(a::token(
        &a::header("test-key-1"),
        &claims,
        &a::pair(a::KEY_1),
    ));
    jobs.save(&job_key, record).unwrap();
    let result = plan(
        &repo,
        &["--format", "json"],
        &[("STOOP_STORE", external.to_str().unwrap())],
    );
    assert_eq!(result.plan["skip"], json!(["a"]), "{}", result.stderr);
}

#[test]
fn warning_escapes_workflow_command_characters() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let o = plan(
        &r,
        &["--format", "github"],
        &[("PROBE_WARNING", "bad%\r\n::error::forged")],
    );
    assert!(o.stderr.contains("bad%25%0D%0A%3A%3Aerror%3A%3Aforged"));
    assert!(!o.stderr.lines().any(|line| line.starts_with("::error::")));
}

#[test]
fn two_attested_jobs_plan_only_the_unchanged_input() {
    let b = format!("  b:\n    needs: [stoop-plan]\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',b,') }}}}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{PIN}\n      - run: cat b.txt > /dev/null\n");
    let w = workflow("", "", &b);
    let r = Repo::new(&[
        (CI, &w),
        ("a.txt", include_str!("../../tests/fixtures/plan/a.txt")),
        ("b.txt", include_str!("../../tests/fixtures/plan/b.txt")),
    ]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let mut b_record = rec(&w, now, now);
    b_record.job = "b";
    b_record.inputs = vec![file(
        "b.txt",
        include_bytes!("../../tests/fixtures/plan/b.txt"),
    )];
    record(&r, b_record).unwrap();
    let baseline = plan(&r, &["--format", "json"], &[]);
    assert_eq!(baseline.plan["skip"], json!(["a", "b"]));
    std::fs::write(r.root.join("b.txt"), "changed\n").unwrap();
    git(&r.root, &["commit", "-qam", "change b"]);
    let sha = String::from_utf8(
        Command::new("git")
            .current_dir(&r.root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let github_output = r.base.join("github_output");
    let result = plan(
        &r,
        &["--format", "github"],
        &[
            ("GITHUB_SHA", sha.trim()),
            ("GITHUB_OUTPUT", github_output.to_str().unwrap()),
        ],
    );
    assert_eq!(result.plan["skip"], json!(["a"]));
    assert_eq!(code(&result, "b"), "input-changed");
    let lines = std::fs::read_to_string(github_output).unwrap();
    assert!(lines.lines().any(|line| line == "skip=,a,"));
    assert!(result.stderr.contains("skip a: proved"));
    assert!(result.stderr.contains("run b: b.txt changed"));
}

#[test]
fn ungated_job_never_enters_skip_output() {
    let w = workflow(
        "",
        "",
        "  free:\n    runs-on: ubuntu-latest\n    steps: []\n",
    );
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[]);
    assert_eq!(o.plan["skip"], json!(["a"]));
    assert_eq!(code(&o, "free"), "not-gated");
}

#[test]
fn plan_job_cannot_override_runtime_switches() {
    for name in [
        "STOOP_FULL",
        "STOOP_OFF",
        "STOOP_MAX_AGE",
        "STOOP_STRICT_ACTIONS",
    ] {
        let w = workflow("", "", "").replace(
            "    steps: []",
            &format!("    env: {{{name}: ''}}\n    steps: []"),
        );
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        let now = proof::now();
        // The record fixture is independent of the plan job override.
        let without = w.replace(&format!("    env: {{{name}: ''}}\n"), "");
        record(&r, rec(&without, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[]);
        assert_eq!(code(&o, "a"), "error", "{name}");
        assert!(o.plan["skip"].as_array().unwrap().is_empty());
    }
}

#[test]
fn sync_failure_refuses_a_provable_record() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    let o = plan(&r, &["--format", "json", "--sync", "git:missing"], &[]);
    assert_eq!(code(&o, "a"), "error");
}

#[test]
fn control_github_job_and_sha_mismatch_run() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(
        &r,
        &["--format", "json", "--plan-job", "stoop-plan"],
        &[("GITHUB_JOB", "other")],
    );
    report("GITHUB_JOB=other", &o);
    assert_eq!(code(&o, "a"), "error");
    let o = plan(
        &r,
        &["--format", "json"],
        &[("GITHUB_SHA", "2222222222222222222222222222222222222222")],
    );
    report("GITHUB_SHA mismatch", &o);
    assert_eq!(code(&o, "a"), "error");
}

#[test]
fn old_records_expire_under_default_ceiling() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let t = proof::now() - 10 * DAY;
    record(&r, rec(&w, t, t)).unwrap();
    let control = plan(&r, &["--format", "json"], &[]);
    report("10-day record, default ceiling", &control);
    assert_eq!(code(&control, "a"), "expired");
}

#[test]
fn dynamic_workflow_max_age_tightens_the_ceiling() {
    let dynamic = workflow(
        "env:\n  STOOP_MAX_AGE: ${{ github.event_name == 'push' && '1h' || '' }}\n",
        "",
        "",
    );
    let r = Repo::new(&[(CI, &dynamic), ("a.txt", "a\n")]);
    let t = proof::now() - 2 * DAY;
    record(&r, rec(&dynamic, t, t)).unwrap();
    // GitHub evaluates the workflow env for every job: on push, STOOP_MAX_AGE=1h in both
    // the plan job and job a, so stoop sh in job a would rerun a 2-day-old proof.
    let o = plan(
        &r,
        &["--format", "json"],
        &[("STOOP_MAX_AGE", "1h"), ("GITHUB_EVENT_NAME", "push")],
    );
    report("dynamic workflow STOOP_MAX_AGE=1h, 2-day record", &o);
    assert_eq!(code(&o, "a"), "expired");
    let fixed = workflow("env:\n  STOOP_MAX_AGE: 1h\n", "", "");
    let r2 = Repo::new(&[(CI, &fixed), ("a.txt", "a\n")]);
    record(&r2, rec(&fixed, t, t)).unwrap();
    let c = plan(&r2, &["--format", "json"], &[("STOOP_MAX_AGE", "1h")]);
    report("static workflow STOOP_MAX_AGE: 1h, 2-day record", &c);
    assert_eq!(code(&c, "a"), "expired");
}

#[test]
fn dynamic_workflow_off_forces_jobs_to_run() {
    let w = workflow(
        "env:\n  STOOP_OFF: ${{ inputs.off && '1' || '' }}\n",
        "",
        "",
    );
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[("STOOP_OFF", "1")]);
    report("dynamic workflow STOOP_OFF=1 (plan process env)", &o);
    assert_eq!(code(&o, "a"), "full");
    let fixed = workflow("env:\n  STOOP_OFF: '1'\n", "", "");
    let r2 = Repo::new(&[(CI, &fixed), ("a.txt", "a\n")]);
    let c = plan(&r2, &["--format", "json"], &[("STOOP_OFF", "1")]);
    report("static workflow STOOP_OFF: '1'", &c);
    assert_ne!(code(&c, "a"), "proved");
}

#[test]
fn container_env_stoop_age_is_honored() {
    let image = format!("alpine@sha256:{}", "a".repeat(64));
    for (name, value, age) in [
        ("STOOP_MAX_AGE", "1h", 2 * DAY),
        ("STOOP_MAX_AGE", "2h", 3 * DAY),
    ] {
        let w = workflow(
            "",
            &format!("    container:\n      image: {image}\n      env:\n        {name}: {value}\n"),
            "",
        );
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        let t = proof::now() - age;
        record(&r, rec(&w, t, t)).unwrap();
        let o = plan(&r, &["--format", "json"], &[]);
        report(&format!("container.env {name}={value}"), &o);
        assert_eq!(code(&o, "a"), "expired");
        let job_env = workflow("", &format!("    env:\n      {name}: {value}\n"), "");
        let r2 = Repo::new(&[(CI, &job_env), ("a.txt", "a\n")]);
        let _ = record(&r2, rec(&job_env, t, t));
        let c = plan(&r2, &["--format", "json"], &[]);
        report(&format!("job env {name}={value}"), &c);
        assert_ne!(code(&c, "a"), "proved");
    }
}

#[test]
fn workflow_flag_cannot_plan_a_different_workflow() {
    let ci = workflow("", "", "");
    let release = ci.replace("name: fixture", "name: release").replace(
        "cat a.txt > /dev/null",
        "cat a.txt > /dev/null && ./deploy.sh",
    );
    let r = Repo::new(&[
        (CI, &ci),
        (".github/workflows/release.yml", &release),
        ("a.txt", "a\n"),
    ]);
    let now = proof::now();
    record(&r, rec(&ci, now, now)).unwrap();
    let running = [
        (
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/release.yml@refs/heads/main",
        ),
        (
            "STOOP_JOB_WORKFLOW_REF",
            "owner/repo/.github/workflows/release.yml@refs/heads/main",
        ),
    ];
    let control = plan(&r, &["--format", "json"], &running);
    report("release.yml plans itself", &control);
    assert_eq!(code(&control, "a"), "no-record");
    let o = plan(&r, &["--format", "github", "--workflow", CI], &running);
    report("release.yml plan job with --workflow ci.yml", &o);
    assert_eq!(code(&o, "a"), "error");
    assert!(o.stdout.contains("skip=,\n"), "{}", o.stdout);
}

#[test]
fn copied_gate_cannot_skip_an_unproved_job() {
    let lint = format!("  lint:\n    needs: [stoop-plan]\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}}}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@{PIN}\n      - run: ./lint.sh\n");
    let w = workflow("", "", &lint);
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "github"], &[]);
    report("lint carries a's gate", &o);
    assert_eq!(code(&o, "lint"), "error");
    assert_eq!(code(&o, "a"), "error");
    assert!(o.stdout.contains("skip=,\n"), "{}", o.stdout);
}

#[test]
fn forged_proof_text_cannot_inject_workflow_commands() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    let mut x = rec(&w, now, now);
    x.attested = false;
    x.inputs = vec![input::Input {
        path: "a.txt\n::error title=stoop-injected::text from an unattested refs/stoop writer"
            .into(),
        id: format!("f:{}", "0".repeat(64)),
    }];
    record(&r, x).unwrap();
    let out = r.base.join("github_output");
    let o = plan(
        &r,
        &["--format", "github", "--explain"],
        &[("GITHUB_OUTPUT", out.to_str().unwrap())],
    );
    report("forged proof path", &o);
    let injected: Vec<_> = o
        .stderr
        .lines()
        .filter(|l| l.starts_with("::error title=stoop-injected::"))
        .collect();
    eprintln!("INJECTED LINES: {injected:#?}");
    for l in o
        .stderr
        .lines()
        .filter(|l| l.starts_with("stoop:") || l.starts_with("::"))
    {
        eprintln!("STDERR| {l}");
    }
    assert!(injected.is_empty(), "{}", o.stderr);
}

fn tamper(r: &Repo, key: &str, f: impl FnOnce(&mut JobRecord)) {
    let jobs = job::JobStore::new(r.store());
    let mut rec = jobs.load(key).remove(0);
    f(&mut rec);
    assert!(jobs.forget(key).unwrap());
    jobs.save(key, rec).unwrap();
}

#[test]
fn control_break_it_fixtures_all_run() {
    let now = proof::now();
    let w = workflow("", "", "");
    // Replayed token: an attested record re-pointed at a proof that reads nothing.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let key = record(&r, rec(&w, now, now)).unwrap();
    let step = job::JobStore::new(r.store()).load(&key)[0].steps[0]
        .key
        .clone();
    let weak = proof::Proof {
        created: now,
        argv: vec![],
        cwd: Some(String::new()),
        scope: None,
        provenance: Some(crate::trace::Provenance {
            os: "linux".into(),
            arch: "x86_64".into(),
            tracer: "ptrace-seccomp".into(),
            version: 4,
        }),
        env: BTreeMap::new(),
        inputs: vec![],
        outputs: vec![],
        removed: vec![],
        ignore: Some(vec![]),
        priors: Some(vec![]),
        unplannable: vec![],
        probes: BTreeMap::new(),
    };
    proof::Store::new(r.store())
        .save(&step, weak.clone())
        .unwrap();
    tamper(&r, &key, |rec| rec.steps[0].proof = weak.digest());
    let o = plan(&r, &["--format", "json"], &[]);
    report("replayed token on a weakened record", &o);
    assert_eq!(code(&o, "a"), "unattested");
    // Moved action: the record stored another commit for the pinned checkout.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let key = record(&r, rec(&w, now, now)).unwrap();
    tamper(&r, &key, |rec| {
        for v in rec.actions.values_mut() {
            *v = "2222222222222222222222222222222222222222".into();
        }
    });
    let o = plan(&r, &["--format", "json"], &[]);
    report(
        "record stored a different action commit (token now stale)",
        &o,
    );
    assert_eq!(code(&o, "a"), "unattested");
    // Event payload changed since the record.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let mut x = rec(&w, now, now);
    x.inputs.push(input::Input {
        path: r.event.to_string_lossy().into_owned(),
        id: format!("f:{}", blake3::hash(b"{\"old\":1}").to_hex()),
    });
    record(&r, x).unwrap();
    let o = plan(&r, &["--format", "json"], &[]);
    report("event payload changed", &o);
    assert_eq!(code(&o, "a"), "input-changed");
    // Workflow edited (a's run text changed) after the record.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    record(&r, rec(&w, now, now)).unwrap();
    let edited = w.replace("cat a.txt > /dev/null", "cat a.txt > /dev/null; true");
    std::fs::write(r.root.join(CI), &edited).unwrap();
    git(&r.root, &["commit", "-qam", "edit"]);
    let sha = String::from_utf8(
        Command::new("git")
            .current_dir(&r.root)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let o = plan(&r, &["--format", "json"], &[("GITHUB_SHA", sha.trim())]);
    report("workflow edited", &o);
    assert_eq!(code(&o, "a"), "no-record");
    // Repository ids unset in the plan job.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[("GITHUB_REPOSITORY_ID", "")]);
    report("GITHUB_REPOSITORY_ID empty", &o);
    assert_eq!(code(&o, "a"), "unattested");
    // Plan job tries to blank the nightly STOOP_FULL.
    let tampered = w.replace("    steps: []", "    env: {STOOP_FULL: ''}\n    steps: []");
    let r = Repo::new(&[(CI, &tampered), ("a.txt", "a\n")]);
    record(&r, rec(&tampered, now, now))
        .map(|_| ())
        .unwrap_or(());
    let o = plan(&r, &["--format", "json"], &[]);
    report("plan job env STOOP_FULL blanked", &o);
    assert_ne!(code(&o, "a"), "proved");
    // Token minted by an earlier record whose started is in the far future (R5 shape) is refused.
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let key = record(&r, rec(&w, now, now - 1000)).unwrap();
    let _ = key;
    let o = plan(&r, &["--format", "json"], &[]);
    report("record iat 1000s ago (honest)", &o);
    assert_eq!(code(&o, "a"), "proved");
}

/// The signed-age rule in a real job shape (checkout first). A writer refreshed the proof
/// (created = now) under a record whose token was minted 2 days ago; job env STOOP_MAX_AGE=1h.
#[test]
fn control_signed_age_with_leading_checkout() {
    let w = workflow("", "    env:\n      STOOP_MAX_AGE: 1h\n", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now - 2 * DAY)).unwrap();
    let o = plan(&r, &["--format", "json"], &[]);
    report("refreshed proof under a 2-day-old token, step age 1h", &o);
    assert_eq!(code(&o, "a"), "expired");
}

/// README: an allowlisted action "stays subject to STOOP_STRICT_ACTIONS". A floating
/// allowlisted ref under strict mode must not prove.
#[test]
fn control_allowlisted_floating_action_under_strict() {
    let w = workflow("", "    env:\n      STOOP_ALLOW_USES: example/tool\n", "").replace(
        "      - run: cat a.txt",
        "      - uses: example/tool@v1\n      - run: cat a.txt",
    );
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[("STOOP_STRICT_ACTIONS", "1")]);
    report(
        "allowlisted example/tool@v1 under STOOP_STRICT_ACTIONS=1",
        &o,
    );
    assert_eq!(code(&o, "a"), "unresolved-action");
}

#[test]
fn container_options_and_job_dependent_workflow_settings_fail_wide() {
    let now = proof::now();
    let control = workflow("", "    container:\n      image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", "");
    let r = Repo::new(&[(CI, &control), ("a.txt", "a\n")]);
    record(&r, rec(&control, now, now)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    for option in [
        "-e STOOP_FULL=1",
        "-eSTOOP_FULL=1",
        "--env STOOP_FULL=1",
        "--env=STOOP_FULL=1",
        "--env-file /tmp/env",
    ] {
        let w = workflow("", &format!("    container:\n      image: alpine@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n      options: {option}\n"), "");
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "blocked");
    }
    for expression in [
        "github.job",
        "github['job']",
        "github.action",
        "github.action_path",
    ] {
        for name in ["STOOP_FULL", "STOOP_SYNC", "STOOP_ENV_SALT"] {
            let w = workflow(
                &format!("env:\n  {name}: ${{{{ {expression} == 'a' && '1' || '' }}}}\n"),
                "",
                "",
            );
            let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
            let o = plan(&r, &["--format", "json"], &[]);
            assert_eq!(code(&o, "a"), "blocked", "{name} {expression}");
            assert!(o.plan["skip"].as_array().unwrap().is_empty());
        }
    }
}

#[test]
fn top_level_workflow_identity_is_required() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    for env in [
        vec![("STOOP_JOB_WORKFLOW_REF", "")],
        vec![(
            "STOOP_JOB_WORKFLOW_REF",
            "owner/repo/.github/workflows/called.yml@refs/heads/main",
        )],
        vec![("GITHUB_WORKFLOW_REF", "")],
    ] {
        let o = plan(&r, &["--format", "json", "--workflow", CI], &env);
        assert_eq!(code(&o, "a"), "error");
        if env[0].0 == "GITHUB_WORKFLOW_REF" {
            assert!(o.plan["jobs"][0]["detail"]
                .as_str()
                .unwrap()
                .contains("planned workflow differs from GITHUB_WORKFLOW_REF"));
        }
        assert!(o.plan["skip"].as_array().unwrap().is_empty());
    }
}

#[test]
fn differently_cased_and_string_needs_cannot_consume_another_gate() {
    let baseline = workflow("", "", "");
    let r = Repo::new(&[(CI, &baseline), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&baseline, now, now)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    for needs in ["[Stoop-Plan]", "stoop-plan"] {
        let lint = format!("  lint:\n    needs: {needs}\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}}}\n    runs-on: ubuntu-latest\n    steps: []\n");
        let w = workflow("", "", &lint);
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        record(&r, rec(&w, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[]);
        assert_eq!(code(&o, "a"), "error");
    }
}

#[test]
fn inherited_age_limits_signed_attestations() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now - 2 * DAY)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    let o = plan(&r, &["--format", "json"], &[("STOOP_MAX_AGE", "1h")]);
    assert_eq!(code(&o, "a"), "unattested");
}

#[test]
fn plan_output_relay_is_refused() {
    let relay = "  relay:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',relay,') }}\n    outputs: {skip: '${{ needs.stoop-plan.outputs.skip }}'}\n    runs-on: ubuntu-latest\n    steps: []\n";
    let w = workflow("", "", relay);
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    let o = plan(&r, &["--format", "json"], &[]);
    assert_eq!(code(&o, "a"), "error");
    assert_eq!(o.plan["skip"], json!([]));
}

#[test]
fn legacy_commands_and_markdown_are_inert_in_output() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    let mut x = rec(&w, now, now);
    x.inputs = vec![input::Input {
        path: "x##[error]message::warning::[link](https:/example.invalid)".into(),
        id: "f:000".into(),
    }];
    record(&r, x).unwrap();
    let summary = r.base.join("summary");
    let o = plan(
        &r,
        &["--format", "json", "--explain"],
        &[("GITHUB_STEP_SUMMARY", summary.to_str().unwrap())],
    );
    assert!(!o.stderr.contains("##["));
    assert!(!o.stdout.contains("##["));
    assert!(!o.stderr.contains("::warning::[link]"));
    let g = plan(
        &r,
        &["--format", "github"],
        &[("GITHUB_STEP_SUMMARY", summary.to_str().unwrap())],
    );
    assert!(!g.stderr.contains("##["));
    let rendered = std::fs::read_to_string(summary).unwrap();
    assert!(
        rendered.contains("`step 2: x##[error]message::warning::[link](https:/example.invalid)")
    );
}

#[test]
fn strict_actions_rejects_a_resolvable_floating_ref() {
    let w = workflow("", "    env:\n      STOOP_ALLOW_USES: example/tool\n", "").replace(
        "      - run: cat a.txt",
        "      - uses: example/tool@v1\n      - run: cat a.txt",
    );
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let source = r.base.join("action-source");
    let bare = r.base.join("server/example/tool.git");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::create_dir_all(&bare).unwrap();
    git(&source, &["init", "-q"]);
    std::fs::write(source.join("action.yml"), "name: test\n").unwrap();
    git(&source, &["add", "."]);
    git(&source, &["commit", "-qm", "fixture"]);
    git(&bare, &["init", "--bare", "-q"]);
    git(
        &source,
        &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/tags/v1"],
    );
    let sha = String::from_utf8(
        Command::new("git")
            .current_dir(&source)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let now = proof::now();
    let key = record(&r, rec(&w, now, now)).unwrap();
    let jobs = job::JobStore::new(r.store());
    let mut record = jobs.load(&key).remove(0);
    record.actions.insert("example/tool@v1".into(), sha);
    let mut claims = a::claims(&record);
    claims["aud"] = json!(attest::audience(&key, &record).unwrap());
    claims["sha"] = json!(r.sha);
    claims["iat"] = json!(now);
    claims["nbf"] = json!(now);
    record.attest = Some(a::token(
        &a::header("test-key-1"),
        &claims,
        &a::pair(a::KEY_1),
    ));
    assert!(jobs.forget(&key).unwrap());
    jobs.save(&key, record).unwrap();
    let server = format!("file://{}", r.base.join("server").display());
    let normal = plan(&r, &["--format", "json"], &[("GITHUB_SERVER_URL", &server)]);
    assert_eq!(code(&normal, "a"), "proved");
    let strict = plan(
        &r,
        &["--format", "json"],
        &[
            ("GITHUB_SERVER_URL", &server),
            ("STOOP_STRICT_ACTIONS", "1"),
        ],
    );
    assert_eq!(code(&strict, "a"), "unresolved-action");
}

#[test]
fn only_run_invariant_github_context_is_accepted() {
    let now = proof::now();
    let good = workflow(
        "env:\n  STOOP_FULL: ${{ github.event_name == 'push' && '1' || '' }}\n",
        "",
        "",
    );
    let r = Repo::new(&[(CI, &good), ("a.txt", "a\n")]);
    record(&r, rec(&good, now, now)).unwrap();
    assert_eq!(
        code(&plan(&r, &["--format", "json"], &[("STOOP_FULL", "")]), "a"),
        "proved"
    );
    for expr in [
        "contains(github.*, 'a')",
        "contains(toJSON(github), 'job')",
        "github['job'] == 'a'",
        "github.actor == 'a'",
        "GITHUB.JOB == 'a'",
        "GitHub.Job == 'a'",
        "github",
        "github.event_name == 'push' && github.job == 'a'",
    ] {
        let w = workflow(
            &format!("env:\n  STOOP_FULL: ${{{{ {expr} && '1' || '' }}}}\n"),
            "",
            "",
        );
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        record(&r, rec(&good, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[("STOOP_FULL", "")]);
        assert_ne!(code(&o, "a"), "proved", "{expr}");
        assert!(o.plan["skip"].as_array().unwrap().is_empty(), "{expr}");
    }
}

#[test]
fn plan_environment_cannot_shadow_workflow_vars_or_secrets() {
    let now = proof::now();
    for context in ["vars", "VARS", "Vars", "secrets", "SECRETS"] {
        let without_environment = workflow(
            &format!("env:\n  STOOP_FULL: ${{{{ {context}.FULL }}}}\n"),
            "",
            "",
        );
        let control = Repo::new(&[(CI, &without_environment), ("a.txt", "a\n")]);
        record(&control, rec(&without_environment, now, now)).unwrap();
        assert_eq!(
            code(
                &plan(&control, &["--format", "json"], &[("STOOP_FULL", "")]),
                "a"
            ),
            "proved",
            "{context}"
        );
        let w = workflow(
            &format!("env:\n  STOOP_FULL: ${{{{ {context}.FULL }}}}\n"),
            "",
            "",
        )
        .replace(
            "    steps: []",
            "    environment: production\n    steps: []",
        );
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        let safe = workflow("", "", "");
        record(&r, rec(&safe, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[("STOOP_FULL", "")]);
        assert_ne!(code(&o, "a"), "proved", "{context}");
        assert!(o.plan["skip"].as_array().unwrap().is_empty(), "{context}");
    }
}

#[test]
fn reusable_workflow_cannot_relay_plan_output() {
    let now = proof::now();
    let baseline = workflow("", "", "");
    let control = Repo::new(&[(CI, &baseline), ("a.txt", "a\n")]);
    record(&control, rec(&baseline, now, now)).unwrap();
    assert_eq!(
        code(&plan(&control, &["--format", "json"], &[]), "a"),
        "proved"
    );
    for relay in [
        "  relay:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',relay,') }}\n    uses: ./.github/workflows/called.yml\n",
        "  relay:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',relay,') }}\n    uses: ./.github/workflows/called.yml\n    with: {skip: '${{ needs.stoop-plan.outputs.skip }}'}\n",
        "  relay:\n    needs: [Stoop-Plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',relay,') }}\n    uses: ./.github/workflows/called.yml\n    secrets: inherit\n",
    ] {
        let w = workflow("", "", relay);
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        record(&r, rec(&w, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[]);
        assert_eq!(code(&o, "a"), "error", "{relay}");
        assert_eq!(o.plan["skip"], json!([]));
    }
}

#[test]
fn unrelated_reusable_calls_do_not_block_planning() {
    let build = "  build:\n    runs-on: ubuntu-latest\n    outputs: {v: '${{ steps.v.outputs.v }}'}\n    steps: []\n";
    let variants = [
        format!("{build}  deploy:\n    needs: [build]\n    uses: ./.github/workflows/deploy.yml\n    with: {{v: '${{{{ needs.build.outputs.v }}}}'}}\n"),
        "  deploy:\n    uses: ./.github/workflows/deploy.yml\n    with: {v: 'static'}\n".to_string(),
        "  deploy:\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n".to_string(),
        "  deploy:\n    uses: ./.github/workflows/deploy.yml\n    with: {sha: '${{ github.sha }}'}\n".to_string(),
    ];
    let now = proof::now();
    for extra in variants {
        let w = workflow("", "", &extra);
        let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
        record(&r, rec(&w, now, now)).unwrap();
        let o = plan(&r, &["--format", "json"], &[]);
        assert_eq!(code(&o, "a"), "proved", "{extra}");
        assert_eq!(o.plan["skip"], json!(["a"]));
    }
}

#[test]
fn malformed_workflow_ref_is_refused_even_when_both_refs_match() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    record(&r, rec(&w, now, now)).unwrap();
    assert_eq!(code(&plan(&r, &["--format", "json"], &[]), "a"), "proved");
    let mut failures = Vec::new();
    for value in [
        "other/repo/.github/workflows/ci.yml@refs/heads/main",
        "owner/repo/.github/workflows/ci.yml",
        "OWNER/REPO/.github/workflows/ci.yml@refs/heads/main",
    ] {
        let o = plan(
            &r,
            &["--format", "json", "--workflow", CI],
            &[
                ("GITHUB_WORKFLOW_REF", value),
                ("STOOP_JOB_WORKFLOW_REF", value),
            ],
        );
        if code(&o, "a") != "error" {
            failures.push(value);
        }
    }
    assert!(failures.is_empty(), "accepted malformed refs: {failures:?}");
}

#[test]
fn markdown_backtick_cannot_escape_summary_code_span() {
    let w = workflow("", "", "");
    let r = Repo::new(&[(CI, &w), ("a.txt", "a\n")]);
    let now = proof::now();
    let mut x = rec(&w, now, now);
    x.inputs = vec![file("x`[click](https:/example.invalid)", b"x")];
    record(&r, x).unwrap();
    let summary = r.base.join("summary");
    let _ = plan(
        &r,
        &["--format", "github"],
        &[("GITHUB_STEP_SUMMARY", summary.to_str().unwrap())],
    );
    let rendered = std::fs::read_to_string(summary).unwrap();
    assert!(rendered.contains("&#96;[click]"), "{rendered}");
    assert!(!rendered.contains("`[click]"), "{rendered}");
}
