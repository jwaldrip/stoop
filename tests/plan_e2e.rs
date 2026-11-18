use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Repo(PathBuf);
impl Repo {
    fn new(workflow: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "stoop-plan-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(p.join(".github/workflows")).unwrap();
        fs::write(p.join(".github/workflows/ci.yml"), workflow).unwrap();
        fs::write(p.join("a.txt"), "a\n").unwrap();
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
                .current_dir(&p)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        Self(p)
    }
    fn plan(&self, args: &[&str], full: bool) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .current_dir(&self.0)
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_MAX_AGE")
            .env("STOOP_FULL", if full { "1" } else { "" })
            .env("GITHUB_JOB", "stoop-plan")
            .env_remove("GITHUB_ACTIONS")
            .args(["plan", "--workflow", ".github/workflows/ci.yml"])
            .args(args)
            .output()
            .unwrap()
    }
}
impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
const WORKFLOW: &str = "name: fixture\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: cat a.txt > /dev/null\n";
#[test]
fn json_plan_has_the_documented_shape() {
    let repo = Repo::new(WORKFLOW);
    let output = repo.plan(&["--format", "json"], false);
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "stoop.plan/1");
    assert_eq!(value["skip"], serde_json::json!([]));
    assert_eq!(value["jobs"][0]["id"], "a");
    assert_eq!(value["jobs"][0]["code"], "no-record");
}
#[test]
fn full_forces_every_job_to_run() {
    let r = Repo::new(WORKFLOW);
    let o = r.plan(&["--format", "json"], true);
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["jobs"][0]["code"], "full");
    assert_eq!(v["skip"], serde_json::json!([]));
}
#[test]
fn ungated_job_and_dependent_run() {
    let r = Repo::new(&WORKFLOW.replace(
        "if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}",
        "if: true",
    ));
    let v: serde_json::Value =
        serde_json::from_slice(&r.plan(&["--format", "json"], false).stdout).unwrap();
    assert_eq!(v["jobs"][0]["code"], "not-gated");
    let text = format!("{WORKFLOW}  c:\n    needs: a\n    runs-on: ubuntu-latest\n    steps: []\n");
    let r = Repo::new(&text);
    let v: serde_json::Value =
        serde_json::from_slice(&r.plan(&["--format", "json"], false).stdout).unwrap();
    assert_eq!(v["jobs"][0]["code"], "graph");
    let text = format!("{WORKFLOW}  c:\n    needs: A\n    runs-on: ubuntu-latest\n    steps: []\n");
    let r = Repo::new(&text);
    let v: serde_json::Value =
        serde_json::from_slice(&r.plan(&["--format", "json"], false).stdout).unwrap();
    assert_eq!(v["jobs"][0]["code"], "graph");
}
#[test]
fn missing_workflow_fails_wide_and_bad_age_is_usage_error() {
    let r = Repo::new(WORKFLOW);
    let out = r.plan(&["--workflow", "missing.yml", "--format", "github"], false);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("skip=,"));
    assert!(String::from_utf8_lossy(&out.stderr).contains("::warning::"));
    assert_eq!(r.plan(&["--max-age", "0"], false).status.code(), Some(2));
}
#[test]
fn plan_job_container_override_fails_wide() {
    let r = Repo::new(&WORKFLOW.replace(
        "    steps: []",
        "    container:\n      image: image\n      env:\n        STOOP_MAX_AGE: 1h\n    steps: []",
    ));
    let v: serde_json::Value =
        serde_json::from_slice(&r.plan(&["--format", "json"], false).stdout).unwrap();
    assert_eq!(v["jobs"][0]["code"], "error");
    assert_eq!(v["skip"], serde_json::json!([]));
}

#[test]
fn flag_cannot_change_allowlist_in_github_output_mode() {
    let r = Repo::new(WORKFLOW);
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&r.0)
        .env("GITHUB_OUTPUT", r.0.join("output"))
        .args(["plan", "--allow-uses", "example/tool"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!r.0.join("output").exists());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "needs S2a"]
fn real_recorder_records_plannable_prior_states() {
    let r = Repo::new(WORKFLOW);
    let temp = r.0.join("runner");
    fs::create_dir(&temp).unwrap();
    let script = temp.join("script.sh");
    let event = temp.join("event.json");
    fs::write(&script, "cat a.txt > /dev/null").unwrap();
    fs::write(&event, "{}").unwrap();
    let sha = Command::new("git")
        .current_dir(&r.0)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&r.0)
        .args(["sh", script.to_str().unwrap()])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/ci.yml@refs/heads/main",
        )
        .env("GITHUB_WORKFLOW", "fixture")
        .env("GITHUB_JOB", "a")
        .env("GITHUB_SHA", String::from_utf8(sha.stdout).unwrap().trim())
        .env("GITHUB_RUN_ID", "123")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_EVENT_PATH", event)
        .env("RUNNER_TEMP", &temp)
        .env_remove("STOOP_SYNC")
        .env_remove("STOOP_FULL")
        .env_remove("STOOP_OFF")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proof = fs::read_dir(r.0.join(".stoop/proofs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let file: serde_json::Value = serde_json::from_slice(&fs::read(proof.path()).unwrap()).unwrap();
    assert!(file["proofs"][0]["ignore"].is_array());
    assert!(file["proofs"][0]["priors"].is_array());
}
