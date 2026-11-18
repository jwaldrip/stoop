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
        self.command(script, write).output().unwrap()
    }
    fn command(&self, script: &str, write: &str) -> Command {
        let path = self.temp.join("script.sh");
        fs::write(&path, script).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
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
            .env_remove("STOOP_ENV_SALT");
        command
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

    fn second_runner(&self) -> Self {
        git(
            &self.root,
            &["push", "-q", "origin", "HEAD:refs/heads/main"],
        );
        let parent = self.root.parent().unwrap();
        let root = parent.join("second");
        git(
            parent,
            &[
                "clone",
                "-q",
                "-b",
                "main",
                self.remote.to_str().unwrap(),
                root.to_str().unwrap(),
            ],
        );
        let temp = parent.join("second-temp");
        fs::create_dir_all(&temp).unwrap();
        fs::write(temp.join("event.json"), "{}").unwrap();
        Self {
            root,
            remote: self.remote.clone(),
            temp,
            sha: self.sha.clone(),
        }
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
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let o = w.run("cat in.txt > /dev/null\n", "1");
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let a = w.records();
    assert_eq!(a[0]["records"][0]["status"], "running");
    let started = a[0]["records"][0]["started"].as_u64().unwrap();
    assert!((before..=after).contains(&started));
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
        record["workflow_ref"],
        "owner/repo/.github/workflows/ci.yml@refs/heads/main"
    );
    assert!(record["job_workflow_ref"].is_null());
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

#[test]
fn concurrent_older_push_cannot_erase_newer_failure() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    let old = Ws::new("race", &["test ! -e fail-flag\n", "true\n"]);
    let newer = old.second_runner();
    assert!(old
        .command("test ! -e fail-flag\n", "1")
        .env("GITHUB_RUN_ID", "100")
        .output()
        .unwrap()
        .status
        .success());
    let bin = old.temp.join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = old.temp.join("push-waiting");
    let release = old.temp.join("push-release");
    let wrapper = bin.join("git");
    fs::write(&wrapper, "#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = push ]; then touch \"$WAIT_MARKER\"; while [ ! -e \"$RELEASE_MARKER\" ]; do sleep 0.02; done; break; fi; done\nexec /usr/bin/git \"$@\"\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let mut child = old
        .command("true\n", "1")
        .env("GITHUB_RUN_ID", "100")
        .env("PATH", path)
        .env("WAIT_MARKER", &marker)
        .env("RELEASE_MARKER", &release)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !marker.exists() {
        let _ = child.kill();
        panic!("old push did not reach the barrier");
    }
    fs::write(newer.root.join("fail-flag"), "x").unwrap();
    let failure = newer
        .command("test ! -e fail-flag\n", "1")
        .env("GITHUB_RUN_ID", "200")
        .output()
        .unwrap();
    assert!(!failure.status.success());
    assert!(old.records()[0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["run"] == "200/1" && r["status"] == "failed"));
    fs::write(release, "go").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files = old.records();
    let records = files[0]["records"].as_array().unwrap();
    assert!(records
        .iter()
        .any(|r| r["run"] == "200/1" && r["status"] == "failed"));
    assert!(records
        .iter()
        .any(|r| r["run"] == "100/1" && r["status"] == "passed"));
}

#[test]
fn failing_untraced_command_publishes_failed_record() {
    let w = Ws::new("untraced-failure", &["exit 1\n"]);
    let out = w
        .command("exit 1\n", "1")
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(w.records()[0]["records"][0]["status"], "failed");
}

#[test]
fn forged_local_job_record_is_not_published() {
    let w = Ws::new("forged", &["true\n"]);
    assert!(w.run("true\n", "1").status.success());
    let file = w.records().pop().unwrap();
    let key = file["key"].as_str().unwrap();
    let local = w.root.join(".stoop/jobs").join(format!("{key}.json"));
    let mut forged = file;
    forged["records"][0]["run"] = "forged/1".into();
    forged["records"][0]["created"] = 4_102_444_800u64.into();
    forged["records"][0]["started"] = 4_102_444_800u64.into();
    fs::write(local, serde_json::to_vec(&forged).unwrap()).unwrap();
    fs::remove_file(w.temp.join("stoop/journal.json")).unwrap();
    let out = w
        .command("true\n", "1")
        .env("GITHUB_RUN_ID", "200")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let result = w.records();
    assert!(!result[0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["run"] == "forged/1"));
    assert!(result[0]["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["run"] == "200/1"));
}

#[test]
fn mismatched_head_is_not_recorded_as_commit() {
    let w = Ws::new("bad-sha", &["true\n"]);
    let out = w
        .command("true\n", "1")
        .env("GITHUB_SHA", "not-head")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(w.records()[0]["records"][0]["commit"].is_null());
}

#[test]
fn supplied_job_workflow_ref_mismatch_blocks_publication() {
    let w = Ws::new("reusable-ref", &["true\n"]);
    let out = w
        .command("true\n", "1")
        .env(
            "STOOP_JOB_WORKFLOW_REF",
            "owner/repo/.github/workflows/other.yml@refs/heads/main",
        )
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("job workflow ref differs"));
    assert!(w.records().is_empty());
}

#[test]
fn matrix_reaches_step_key() {
    let w = Ws::new("matrix", &["true\n"]);
    let out = w
        .command("true\n", "1")
        .env("STOOP_MATRIX", "{\"z\":2,\"a\":1}")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut h = blake3::Hasher::new();
    h.update(b"true\nfixture\0test\0\0matrix\0{\"a\":1,\"z\":2}");
    let expected = format!("sh-{}", &h.finalize().to_hex()[..20]);
    assert!(String::from_utf8_lossy(&out.stderr).contains(&expected));
    assert!(w.records().is_empty());
}

#[test]
fn failed_job_fetch_never_pushes() {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new("fetch-failure", &["true\n"]);
    let bin = w.temp.join("bin");
    fs::create_dir(&bin).unwrap();
    let wrapper = bin.join("git");
    fs::write(&wrapper, "#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = fetch ]; then echo blocked >&2; exit 1; fi; if [ \"$arg\" = push ]; then touch \"$PUSH_MARKER\"; fi; done\nexec /usr/bin/git \"$@\"\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let marker = w.temp.join("pushed");
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let out = w
        .command("true\n", "1")
        .env("PATH", path)
        .env("PUSH_MARKER", &marker)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!marker.exists());
    assert!(w.records().is_empty());
}

#[test]
fn recorded_step_keys_and_digests_resolve_on_remote() {
    use std::collections::BTreeMap;
    #[derive(serde::Deserialize, serde::Serialize)]
    struct Input {
        path: String,
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct Proof {
        inputs: Vec<Input>,
        outputs: Vec<Input>,
        removed: Vec<String>,
        env: BTreeMap<String, String>,
        probes: BTreeMap<String, String>,
        ignore: Option<Vec<String>>,
        priors: Option<Vec<Input>>,
        unplannable: Vec<String>,
    }
    let scripts = ["cat in.txt > /dev/null\n", "true\n"];
    let w = Ws::new("remote-digests", &scripts);
    for script in scripts {
        assert!(w.run(script, "1").status.success());
    }
    let files = w.records();
    let steps = files[0]["records"][0]["steps"].as_array().unwrap();
    assert_eq!(steps.len(), scripts.len());
    for (step, script) in steps.iter().zip(scripts) {
        let mut h = blake3::Hasher::new();
        h.update(script.as_bytes());
        h.update(b"fixture\0test\0");
        let key = format!("sh-{}", &h.finalize().to_hex()[..20]);
        assert_eq!(step["key"], key);
        let raw = git(
            &w.remote,
            &["cat-file", "blob", &format!("refs/stoop/{key}")],
        );
        let file: Value = serde_json::from_str(&raw).unwrap();
        let proofs: Vec<Proof> = serde_json::from_value(file["proofs"].clone()).unwrap();
        assert!(proofs.iter().any(|p| {
            let bytes = serde_json::to_vec(&(
                &p.inputs,
                &p.outputs,
                &p.removed,
                &p.env,
                &p.probes,
                &p.ignore,
                &p.priors,
                &p.unplannable,
            ))
            .unwrap();
            step["proof"] == format!("p-{}", &blake3::hash(&bytes).to_hex()[..32])
        }));
    }
}

#[test]
fn concurrent_same_step_publications_keep_both_proofs() {
    concurrent_proof_race(false);
}

#[test]
fn proof_only_writer_cannot_erase_a_concurrent_proof() {
    concurrent_proof_race(true);
}

fn concurrent_proof_race(proof_only: bool) {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};
    #[derive(serde::Deserialize, serde::Serialize)]
    struct Input {
        path: String,
        id: String,
    }
    #[derive(serde::Deserialize)]
    struct Proof {
        inputs: Vec<Input>,
        outputs: Vec<Input>,
        removed: Vec<String>,
        env: std::collections::BTreeMap<String, String>,
        probes: std::collections::BTreeMap<String, String>,
        ignore: Option<Vec<String>>,
        priors: Option<Vec<Input>>,
        unplannable: Vec<String>,
    }
    let script = "cat in.txt > /dev/null\n";
    let old = Ws::new(
        if proof_only {
            "proof-only-race"
        } else {
            "proof-race"
        },
        &[script],
    );
    let newer = old.second_runner();
    fs::write(newer.root.join("in.txt"), "different input\n").unwrap();
    let bin = old.temp.join("bin");
    fs::create_dir(&bin).unwrap();
    let marker = old.temp.join("push-waiting");
    let release = old.temp.join("push-release");
    let wrapper = bin.join("git");
    fs::write(&wrapper, "#!/bin/sh\nfor arg in \"$@\"; do if [ \"$arg\" = push ]; then touch \"$WAIT_MARKER\"; while [ ! -e \"$RELEASE_MARKER\" ]; do sleep 0.02; done; break; fi; done\nexec /usr/bin/git \"$@\"\n").unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap());
    let mut child = old
        .command(script, "1")
        .env("GITHUB_RUN_ID", "100")
        .env("PATH", path)
        .env("WAIT_MARKER", &marker)
        .env("RELEASE_MARKER", &release)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if !marker.exists() {
        let _ = child.kill();
        panic!("old push did not reach the barrier");
    }
    let mut competitor = newer.command(script, "1");
    competitor.env("GITHUB_RUN_ID", "200");
    if proof_only {
        competitor.env_remove("GITHUB_ACTIONS");
    }
    let out = competitor.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut hasher = blake3::Hasher::new();
    hasher.update(script.as_bytes());
    hasher.update(b"fixture\0test\0");
    let key = format!("sh-{}", &hasher.finalize().to_hex()[..20]);
    let competing_file: Value = serde_json::from_str(&git(
        &old.remote,
        &["cat-file", "blob", &format!("refs/stoop/{key}")],
    ))
    .unwrap();
    let competing_proofs: Vec<Proof> =
        serde_json::from_value(competing_file["proofs"].clone()).unwrap();
    assert!(!competing_proofs.is_empty());
    let digest = |p: &Proof| {
        let bytes = serde_json::to_vec(&(
            &p.inputs,
            &p.outputs,
            &p.removed,
            &p.env,
            &p.probes,
            &p.ignore,
            &p.priors,
            &p.unplannable,
        ))
        .unwrap();
        format!("p-{}", &blake3::hash(&bytes).to_hex()[..32])
    };
    let competing: Vec<_> = competing_proofs.iter().map(digest).collect();
    if proof_only {
        assert!(old.records().is_empty());
    }
    fs::write(release, "go").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let files = old.records();
    let records = files[0]["records"].as_array().unwrap();
    assert_eq!(records.len(), if proof_only { 1 } else { 2 });
    assert_eq!(records[0]["steps"][0]["key"], key);
    let raw = git(
        &old.remote,
        &["cat-file", "blob", &format!("refs/stoop/{key}")],
    );
    let file: Value = serde_json::from_str(&raw).unwrap();
    let proofs: Vec<Proof> = serde_json::from_value(file["proofs"].clone()).unwrap();
    let digests: Vec<String> = proofs.iter().map(digest).collect();
    let first = records[0]["steps"][0]["proof"].as_str().unwrap();
    assert!(digests.iter().any(|d| d == first));
    assert!(competing.iter().all(|d| digests.contains(d)));
    if proof_only {
        assert!(competing.iter().any(|d| d != first));
    }
    if !proof_only {
        let second = records[1]["steps"][0]["proof"].as_str().unwrap();
        assert_ne!(first, second);
        assert!(digests.iter().any(|d| d == second));
    }
}

#[test]
fn atomic_push_does_not_publish_job_if_proof_is_rejected() {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new("atomic-reject", &["true\n", "echo second\n"]);
    assert!(w.run("true\n", "1").status.success());
    let original = w.records();
    let hook = w.remote.join("hooks/update");
    fs::write(
        &hook,
        "#!/bin/sh\ncase \"$1\" in refs/stoop/sh-*) exit 1;; esac\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let out = w.run("echo second\n", "1");
    assert!(out.status.success());
    assert_eq!(w.records(), original);
}

#[test]
fn blocked_job_reports_initialization_error_only_once() {
    let w = Ws::new("blocked-once", &["true\n", "echo second\n"]);
    let mut errors = String::new();
    for script in ["true\n", "echo second\n"] {
        let out = w
            .command(script, "1")
            .env("STOOP_JOB_WORKFLOW_REF", "different")
            .output()
            .unwrap();
        assert!(out.status.success());
        errors.push_str(&String::from_utf8_lossy(&out.stderr));
    }
    assert_eq!(errors.matches("job record not written").count(), 1);
}

#[test]
fn rejected_push_retries_three_times_without_failing_step() {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new("bounded-push", &["true\n"]);
    let count = w.temp.join("attempts");
    let hook = w.remote.join("hooks/update");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\ncase \"$1\" in refs/stoop/job-*) echo x >> '{}'; exit 1;; esac\nexit 0\n",
            count.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let out = w.run("true\n", "1");
    assert!(out.status.success());
    assert_eq!(fs::read_to_string(count).unwrap().lines().count(), 3);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr)
            .matches("stoop: journal:")
            .count(),
        1
    );
    assert!(w.records().is_empty());
}
