//! Non-UTF-8 environment bytes must never crash stoop, must not change an unrelated
//! decision, and must make a variable stoop needs unavailable so the job runs.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

const WORKFLOW: &str = "name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: cat a.txt > /dev/null\n";

fn raw(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "stoop-nonutf8-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
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

fn repo(dir: &Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let file = dir.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["add", "."]);
    git(dir, &["commit", "-qm", "fixture"]);
}

fn stoop(dir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
        .env("TMPDIR", dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    command
}

fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_panic(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "stoop panicked on a non-UTF-8 environment value:\n{}",
        text(output)
    );
}

#[test]
fn plan_survives_an_unrelated_non_utf8_variable() {
    let dir = Dir::new("plan");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = stoop(
        dir.path(),
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--format",
            "json",
        ],
    )
    .env("GITHUB_JOB", "stoop-plan")
    .env("NONUTF8_TEST", raw(b"raw-\xff"))
    .output()
    .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["schema"], "stoop.plan/1");
}

#[test]
fn a_non_utf8_needed_variable_makes_planning_fail_wide() {
    let dir = Dir::new("plan-sha");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = stoop(
        dir.path(),
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--format",
            "json",
        ],
    )
    .env("GITHUB_JOB", "stoop-plan")
    .env("GITHUB_ACTIONS", "true")
    .env("GITHUB_SHA", raw(b"\xff\xfe"))
    .output()
    .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["skip"], serde_json::json!([]), "{plan}");
}

#[test]
fn shell_mode_survives_an_unrelated_non_utf8_variable() {
    let dir = Dir::new("sh");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let runner = dir.path().join("runner");
    fs::create_dir_all(&runner).unwrap();
    fs::write(dir.path().join("step.sh"), "echo ok\n").unwrap();
    let output = stoop(dir.path(), &["sh", "step.sh"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/ci.yml@refs/heads/main",
        )
        .env("GITHUB_WORKFLOW", "fixture")
        .env("GITHUB_JOB", "a")
        .env("GITHUB_SHA", "1111111111111111111111111111111111111111")
        .env("GITHUB_RUN_ID", "1")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("RUNNER_TEMP", &runner)
        .env("NONUTF8_TEST", raw(b"raw-\xff"))
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ok"),
        "{}",
        text(&output)
    );
}

#[test]
fn pull_and_ls_survive_an_unrelated_non_utf8_variable() {
    let dir = Dir::new("pull-ls");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let remote = dir.path().join("remote.git");
    git(
        dir.path(),
        &["init", "-q", "--bare", remote.to_str().unwrap()],
    );
    git(
        dir.path(),
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    let ls = stoop(dir.path(), &["ls"])
        .env("NONUTF8_TEST", raw(b"raw-\xff"))
        .output()
        .unwrap();
    assert_no_panic(&ls);
    assert!(ls.status.success(), "{}", text(&ls));
    let pull = stoop(dir.path(), &["pull", "--sync", "git"])
        .env("NONUTF8_TEST", raw(b"raw-\xff"))
        .output()
        .unwrap();
    assert_no_panic(&pull);
    assert!(pull.status.success(), "{}", text(&pull));
}

#[cfg(target_os = "linux")]
#[test]
fn a_changed_non_utf8_variable_invalidates_a_proof() {
    let dir = Dir::new("run-changed");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let first = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("NONUTF8_TEST", raw(b"\xfe"))
        .output()
        .unwrap();
    assert_no_panic(&first);
    assert!(first.status.success(), "{}", text(&first));
    let second = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("NONUTF8_TEST", raw(b"\xff"))
        .output()
        .unwrap();
    assert_no_panic(&second);
    assert!(second.status.success(), "{}", text(&second));
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !stderr.contains("stoop: skip"),
        "a changed non-UTF-8 value must not skip:\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn explain_reports_a_changed_non_utf8_variable_as_a_run() {
    let dir = Dir::new("explain-changed");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let first = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("NONUTF8_TEST", raw(b"a-\xfe"))
        .output()
        .unwrap();
    assert!(first.status.success(), "{}", text(&first));
    let explain = stoop(dir.path(), &["explain", "--", "cat", "in.txt"])
        .env("NONUTF8_TEST", raw(b"b-\xfe"))
        .output()
        .unwrap();
    assert_no_panic(&explain);
    assert_eq!(explain.status.code(), Some(1), "{}", text(&explain));
}

#[cfg(target_os = "linux")]
#[test]
fn a_non_utf8_stoop_full_still_forces_a_run() {
    let dir = Dir::new("full-non-utf8");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let first = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .output()
        .unwrap();
    assert!(first.status.success(), "{}", text(&first));
    let second = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("STOOP_FULL", raw(b"\xff"))
        .output()
        .unwrap();
    assert_no_panic(&second);
    assert!(second.status.success(), "{}", text(&second));
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(
        !stderr.contains("stoop: skip"),
        "an unreadable STOOP_FULL must never skip:\n{stderr}"
    );
}

/// The fixture plan, with extra environment, as JSON.
fn plan_with(dir: &Path, env: &[(&str, OsString)]) -> Output {
    let mut command = stoop(
        dir,
        &["plan", "--workflow", ".github/workflows/ci.yml", "--format", "json"],
    );
    command.env("GITHUB_JOB", "stoop-plan");
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

#[test]
fn a_non_utf8_stoop_off_bypasses_stoop_and_prints_nothing() {
    let dir = Dir::new("stoop-off");
    repo(dir.path(), &[("a.txt", "a\n")]);
    let output = stoop(dir.path(), &["run", "--", "true"])
        .env("STOOP_OFF", raw(b"\xff"))
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains("stoop:"),
        "a non-UTF-8 STOOP_OFF must bypass stoop, which then prints nothing:\n{}",
        text(&output)
    );
}

#[test]
fn a_non_utf8_stoop_off_forces_the_planner_to_run_every_job() {
    let dir = Dir::new("plan-off");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = plan_with(dir.path(), &[("STOOP_OFF", raw(b"\xff"))]);
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["skip"], serde_json::json!([]), "{plan}");
    assert_eq!(
        plan["jobs"][0]["detail"],
        "STOOP_FULL or STOOP_OFF enabled",
        "{plan}"
    );
}

#[test]
fn a_non_utf8_stoop_full_marks_the_plan_full() {
    let dir = Dir::new("plan-full");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = plan_with(dir.path(), &[("STOOP_FULL", raw(b"\xff"))]);
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let plan: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["full"], true, "{plan}");
}

#[test]
fn a_non_utf8_github_actions_keeps_the_planner_guards() {
    let dir = Dir::new("plan-actions");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = stoop(
        dir.path(),
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--plan-job",
            "stoop-plan",
            "--format",
            "json",
        ],
    )
    .env("GITHUB_ACTIONS", raw(b"\xff"))
    .env("GITHUB_JOB", "other")
    .output()
    .unwrap();
    assert_no_panic(&output);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("plan job differs from GITHUB_JOB"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_non_utf8_github_actions_refuses_allow_uses_in_github_format() {
    let dir = Dir::new("plan-allow");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let output = stoop(
        dir.path(),
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--format",
            "github",
            "--allow-uses",
            "actions/checkout@v4",
        ],
    )
    .env("GITHUB_JOB", "stoop-plan")
    .env("GITHUB_ACTIONS", raw(b"\xff"))
    .output()
    .unwrap();
    assert_no_panic(&output);
    assert!(!output.status.success(), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("only available for local dry runs"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_non_utf8_variable_name_does_not_stop_plan_run_or_sh() {
    let dir = Dir::new("name");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let name = raw(b"\xffNAME");
    let plan = stoop(dir.path(), &["plan", "--workflow", ".github/workflows/ci.yml", "--format", "json"])
        .env("GITHUB_JOB", "stoop-plan")
        .env(&name, "1")
        .output()
        .unwrap();
    assert_no_panic(&plan);
    assert!(plan.status.success(), "{}", text(&plan));
    let run = stoop(dir.path(), &["run", "--", "true"])
        .env(&name, "1")
        .output()
        .unwrap();
    assert_no_panic(&run);
    assert!(run.status.success(), "{}", text(&run));
    fs::write(dir.path().join("step.sh"), "echo ok\n").unwrap();
    let sh = stoop(dir.path(), &["sh", "step.sh"])
        .env(&name, "1")
        .output()
        .unwrap();
    assert_no_panic(&sh);
    assert!(sh.status.success(), "{}", text(&sh));
}

#[cfg(target_os = "linux")]
#[test]
fn a_changed_non_utf8_variable_name_invalidates_a_proof() {
    let dir = Dir::new("name-changed");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let name = raw(b"\xffNAME");
    let first = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env(&name, raw(b"a"))
        .output()
        .unwrap();
    assert_no_panic(&first);
    assert!(first.status.success(), "{}", text(&first));
    let second = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env(&name, raw(b"b"))
        .output()
        .unwrap();
    assert_no_panic(&second);
    assert!(second.status.success(), "{}", text(&second));
    assert!(
        !String::from_utf8_lossy(&second.stderr).contains("stoop: skip"),
        "a changed non-UTF-8 variable name must not skip:\n{}",
        text(&second)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_non_utf8_salt_keys_every_recorded_environment_hash() {
    let dir = Dir::new("salt");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let output = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("STOOP_ENV_SALT", raw(b"\xff"))
        .env("NONUTF8_TEST", "one")
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let proof = fs::read_dir(dir.path().join(".stoop/proofs"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let file: serde_json::Value = serde_json::from_slice(&fs::read(proof.path()).unwrap()).unwrap();
    let env = file["proofs"][0]["env"].as_object().unwrap();
    assert!(!env.is_empty(), "{file}");
    for (name, hash) in env {
        assert!(
            hash.as_str().unwrap().starts_with("s:"),
            "{name} was recorded unsalted: {hash}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn a_recorded_plan_reports_a_non_utf8_github_sha_unavailable() {
    const SHA_WORKFLOW: &str = "name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: cat a.txt > /dev/null; echo \"$GITHUB_SHA\" > /dev/null\n";
    let dir = Dir::new("sha-sentinel");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", SHA_WORKFLOW), ("a.txt", "a\n")],
    );
    let head = Command::new("git")
        .current_dir(dir.path())
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let sha = String::from_utf8(head.stdout).unwrap().trim().to_string();
    let temp = dir.path().join("runner");
    fs::create_dir_all(&temp).unwrap();
    let script = temp.join("step.sh");
    fs::write(&script, "cat a.txt > /dev/null; echo \"$GITHUB_SHA\" > /dev/null").unwrap();
    let event = temp.join("event.json");
    fs::write(&event, "{}").unwrap();
    let recorded = stoop(dir.path(), &["sh", script.to_str().unwrap()])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/ci.yml@refs/heads/main",
        )
        .env("GITHUB_WORKFLOW", "fixture")
        .env("GITHUB_JOB", "a")
        .env("GITHUB_SHA", &sha)
        .env("GITHUB_RUN_ID", "123")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("GITHUB_EVENT_PATH", &event)
        .env("RUNNER_TEMP", &temp)
        .env("GITHUB_SERVER_URL", "http://127.0.0.1:1")
        .env("GITHUB_API_URL", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(recorded.status.success(), "{}", text(&recorded));
    let plan = plan_with(dir.path(), &[("GITHUB_SHA", raw(b"\xfe"))]);
    assert_no_panic(&plan);
    assert!(
        String::from_utf8_lossy(&plan.stdout).contains("GITHUB_SHA changed or unavailable"),
        "{}",
        text(&plan)
    );
}
