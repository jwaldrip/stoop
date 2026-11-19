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
        .args(["-c", "user.name=t", "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false"])
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
    repo(dir.path(), &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")]);
    let output = stoop(
        dir.path(),
        &["plan", "--workflow", ".github/workflows/ci.yml", "--format", "json"],
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
    repo(dir.path(), &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")]);
    let output = stoop(
        dir.path(),
        &["plan", "--workflow", ".github/workflows/ci.yml", "--format", "json"],
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
    repo(dir.path(), &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")]);
    let runner = dir.path().join("runner");
    fs::create_dir_all(&runner).unwrap();
    fs::write(dir.path().join("step.sh"), "echo ok\n").unwrap();
    let output = stoop(dir.path(), &["sh", "step.sh"])
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env("GITHUB_WORKFLOW_REF", "owner/repo/.github/workflows/ci.yml@refs/heads/main")
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
    assert!(String::from_utf8_lossy(&output.stdout).contains("ok"), "{}", text(&output));
}

#[test]
fn pull_and_ls_survive_an_unrelated_non_utf8_variable() {
    let dir = Dir::new("pull-ls");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let remote = dir.path().join("remote.git");
    git(dir.path(), &["init", "-q", "--bare", remote.to_str().unwrap()]);
    git(dir.path(), &["remote", "add", "origin", remote.to_str().unwrap()]);
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
        .env("NONUTF8_TEST", raw(b"a-\xfe"))
        .output()
        .unwrap();
    assert_no_panic(&first);
    assert!(first.status.success(), "{}", text(&first));
    let second = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("NONUTF8_TEST", raw(b"b-\xfe"))
        .output()
        .unwrap();
    assert_no_panic(&second);
    assert!(second.status.success(), "{}", text(&second));
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!stderr.contains("stoop: skip"), "a changed non-UTF-8 value must not skip:\n{stderr}");
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
    let first = stoop(dir.path(), &["run", "--", "cat", "in.txt"]).output().unwrap();
    assert!(first.status.success(), "{}", text(&first));
    let second = stoop(dir.path(), &["run", "--", "cat", "in.txt"])
        .env("STOOP_FULL", raw(b"\xff"))
        .output()
        .unwrap();
    assert_no_panic(&second);
    assert!(second.status.success(), "{}", text(&second));
    let stderr = String::from_utf8_lossy(&second.stderr);
    assert!(!stderr.contains("stoop: skip"), "an unreadable STOOP_FULL must never skip:\n{stderr}");
}
