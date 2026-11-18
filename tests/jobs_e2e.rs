#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

struct Ws {
    root: PathBuf,
    remote: PathBuf,
    temp: PathBuf,
    sha: String,
}
impl Ws {
    fn new(name: &str, steps: &[&str]) -> Self {
        let root =
            std::env::temp_dir().join(format!("stoop-job-e2e-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let remote = root.join("remote.git");
        fs::create_dir(&remote).unwrap();
        git(&remote, &["init", "--bare", "-q"]);
        let work = root.join("work");
        fs::create_dir(&work).unwrap();
        git(&work, &["init", "-q"]);
        git(
            &work,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        fs::create_dir_all(work.join(".github/workflows")).unwrap();
        let mut yaml = String::from("name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n");
        for step in steps {
            yaml.push_str(&format!("      - run: |\n          {}\n", step.trim_end()));
        }
        fs::write(work.join(".github/workflows/ci.yml"), yaml).unwrap();
        fs::write(work.join("in.txt"), "hello\n").unwrap();
        git(&work, &["add", "."]);
        git(
            &work,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ],
        );
        let sha = git(&work, &["rev-parse", "HEAD"]);
        let temp = root.join("runner");
        fs::create_dir(&temp).unwrap();
        fs::write(temp.join("event.json"), "{}").unwrap();
        Self {
            root: work,
            remote,
            temp,
            sha,
        }
    }
    fn run(&self, script: &str, write: &str) -> Output {
        let path = self.temp.join("script.sh");
        fs::write(&path, script).unwrap();
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .arg("sh")
            .arg(path)
            .current_dir(&self.root)
            .env("GITHUB_ACTIONS", "true")
            .env("GITHUB_REPOSITORY", "owner/repo")
            .env(
                "GITHUB_WORKFLOW_REF",
                "owner/repo/.github/workflows/ci.yml@refs/heads/main",
            )
            .env("GITHUB_WORKFLOW", "fixture")
            .env("GITHUB_JOB", "test")
            .env("GITHUB_SHA", &self.sha)
            .env("GITHUB_RUN_ID", "123")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("GITHUB_EVENT_PATH", self.temp.join("event.json"))
            .env("RUNNER_TEMP", &self.temp)
            .env("STOOP_SYNC", "git")
            .env("STOOP_SYNC_WRITE", write)
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_MATRIX")
            .env_remove("STOOP_STORE")
            .env_remove("STOOP_ENV_SALT")
            .output()
            .unwrap()
    }
    fn records(&self) -> Vec<Value> {
        let refs = git(
            &self.remote,
            &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
        );
        refs.lines()
            .filter(|s| s.starts_with("refs/stoop/job-"))
            .map(|r| serde_json::from_str(&git(&self.remote, &["cat-file", "blob", r])).unwrap())
            .collect()
    }
}
fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}
#[test]
fn a_trusted_job_publishes_a_passed_record() {
    let w = Ws::new("passed", &["cat in.txt > /dev/null\n", "true\n"]);
    let o = w.run("cat in.txt > /dev/null\n", "1");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let a = w.records();
    assert_eq!(a[0]["records"][0]["status"], "running");
    let started = a[0]["records"][0]["started"].as_u64().unwrap();
    let created = a[0]["records"][0]["created"].as_u64().unwrap();
    let o = w.run("true\n", "1");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let b = w.records();
    let record = &b[0]["records"][0];
    assert_eq!(record["status"], "passed");
    assert_eq!(record["steps"].as_array().unwrap().len(), 2);
    assert_eq!(record["started"], started);
    assert!(record["created"].as_u64().unwrap() > created);
    assert_eq!(record["commit"], w.sha);
    assert_eq!(
        record["event_path"],
        w.temp.join("event.json").to_str().unwrap()
    );
}
#[test]
fn a_failing_step_publishes_a_failed_record() {
    let w = Ws::new("failed", &["exit 1\n"]);
    assert!(!w.run("exit 1\n", "1").status.success());
    let r = w.records();
    let r = &r[0]["records"][0];
    assert_eq!(r["status"], "failed");
    assert!(r["failed"].as_str().unwrap().starts_with("sh-"));
    assert_eq!(r["steps"].as_array().unwrap().len(), 0);
}
#[test]
fn an_empty_sync_write_publishes_nothing() {
    let w = Ws::new("readonly", &["true\n"]);
    assert!(w.run("true\n", "").status.success());
    assert!(w.records().is_empty());
}
#[test]
fn a_script_that_differs_from_the_workflow_writes_no_job_record() {
    let w = Ws::new("diverged", &["true\n"]);
    let o = w.run("echo different\n", "1");
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("does not match the workflow"));
    assert!(w.records().is_empty());
}

#[test]
fn an_unrecordable_step_leaves_the_record_running() {
    let w = Ws::new(
        "unrecordable",
        &["cat in.txt > /dev/null\n", "cat .git/HEAD > /dev/null\n"],
    );
    assert!(w.run("cat in.txt > /dev/null\n", "1").status.success());
    assert!(w.run("cat .git/HEAD > /dev/null\n", "1").status.success());
    let records = w.records();
    assert_eq!(records[0]["records"][0]["status"], "running");
    assert_eq!(
        records[0]["records"][0]["steps"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn a_runtime_skip_references_the_existing_proof() {
    let w = Ws::new("skip", &["cat in.txt > /dev/null\n"]);
    let first = w.run("cat in.txt > /dev/null\n", "1");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before = w.records()[0]["records"][0]["steps"][0]["proof"].clone();
    fs::remove_file(w.temp.join("stoop/journal.json")).unwrap();
    let second = w.run("cat in.txt > /dev/null\n", "1");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let after = w.records();
    assert_eq!(after[0]["records"][0]["steps"][0]["how"], "skipped");
    assert_eq!(after[0]["records"][0]["steps"][0]["proof"], before);
}

#[test]
fn sync_failure_never_fails_the_step() {
    let w = Ws::new("sync-failure", &["true\n"]);
    git(
        &w.root,
        &["remote", "set-url", "origin", "/nonexistent/stoop.git"],
    );
    let o = w.run("true\n", "1");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn pull_imports_and_prune_expires_job_files() {
    let w = Ws::new("pull-prune", &["true\n"]);
    assert!(w.run("true\n", "1").status.success());
    let record = w.records().pop().unwrap();
    let key = record["key"].as_str().unwrap().to_string();
    let local = w.root.join(".stoop/jobs").join(format!("{key}.json"));
    fs::remove_file(&local).unwrap();
    let pull = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args(["pull", "--sync", "git"])
        .current_dir(&w.root)
        .env_remove("STOOP_STORE")
        .output()
        .unwrap();
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    assert!(local.exists());
    let mut old = record;
    old["records"][0]["created"] = 1.into();
    let blob_path = w.temp.join("old-job.json");
    fs::write(&blob_path, serde_json::to_vec(&old).unwrap()).unwrap();
    let hash = git(
        &w.remote,
        &["hash-object", "-w", blob_path.to_str().unwrap()],
    );
    git(
        &w.remote,
        &["update-ref", &format!("refs/stoop/{key}"), &hash],
    );
    let prune = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args(["prune", "--sync", "git", "--sync-write", "--max-age", "1"])
        .current_dir(&w.root)
        .output()
        .unwrap();
    assert!(
        prune.status.success(),
        "{}",
        String::from_utf8_lossy(&prune.stderr)
    );
    assert!(w.records().is_empty());
}

#[test]
fn import_keeps_the_latest_update_of_a_run() {
    let w = Ws::new("import-update", &["true\n"]);
    assert!(w.run("true\n", "1").status.success());
    let remote = w.records().pop().unwrap();
    let key = remote["key"].as_str().unwrap();
    let local = w.root.join(".stoop/jobs").join(format!("{key}.json"));
    let mut stale = remote.clone();
    stale["records"][0]["created"] = 1.into();
    stale["records"][0]["status"] = "running".into();
    fs::write(&local, serde_json::to_vec(&stale).unwrap()).unwrap();
    let pull = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args(["pull", "--sync", "git"])
        .current_dir(&w.root)
        .env_remove("STOOP_STORE")
        .output()
        .unwrap();
    assert!(
        pull.status.success(),
        "{}",
        String::from_utf8_lossy(&pull.stderr)
    );
    let updated: Value = serde_json::from_slice(&fs::read(local).unwrap()).unwrap();
    assert_eq!(updated["records"][0]["status"], "passed");
    assert_eq!(
        updated["records"][0]["created"],
        remote["records"][0]["created"]
    );
}
