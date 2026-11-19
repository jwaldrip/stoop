#![cfg(target_os = "linux")]
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(serde::Deserialize, serde::Serialize)]
struct RecordedProvenance {
    os: String,
    arch: String,
    tracer: String,
    version: u32,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct RecordedOidBasis {
    text: String,
    eol: String,
    filter: String,
    ident: String,
    working_tree_encoding: String,
    export_subst: String,
    crlf: String,
    autocrlf: String,
}

struct ActionApi {
    url: String,
    stop: Arc<AtomicBool>,
    unexpected: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ActionApi {
    fn new(sha: &str, archive: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let expected = format!("/repos/actions/checkout/tarball/{sha}");
        let stop = Arc::new(AtomicBool::new(false));
        let unexpected = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server_unexpected = unexpected.clone();
        let handle = thread::spawn(move || {
            while !server_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap_or(0);
                        let target = line.split_whitespace().nth(1).unwrap_or("");
                        let valid = target == expected;
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                                break;
                            }
                        }
                        if valid {
                            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", archive.len());
                            let _ = stream.write_all(&archive);
                        } else {
                            server_unexpected.store(true, Ordering::Relaxed);
                            let _ = write!(stream, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            url,
            stop,
            unexpected,
            thread: Some(handle),
        }
    }
}

impl Drop for ActionApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            handle.join().unwrap();
        }
        if !thread::panicking() {
            assert!(
                !self.unexpected.load(Ordering::Relaxed),
                "action test attempted a non-fixture network request"
            );
        }
    }
}

struct Ws {
    root: PathBuf,
    remote: PathBuf,
    temp: PathBuf,
    sha: String,
    api: Arc<ActionApi>,
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
        fs::write(
            work.join("action.yml"),
            "runs:\n  using: node20\n  main: index.js\n",
        )
        .unwrap();
        fs::write(work.join("index.js"), "fixture\n").unwrap();
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
        let action_dir = root.join("actions");
        fs::create_dir(&action_dir).unwrap();
        let action_remote = action_dir.join("checkout.git");
        git(
            &root,
            &[
                "clone",
                "--bare",
                "-q",
                work.to_str().unwrap(),
                action_remote.to_str().unwrap(),
            ],
        );
        git(&action_remote, &["update-ref", "refs/tags/v4", &sha]);
        let archive = Command::new("git")
            .current_dir(&work)
            .args(["archive", "--format=tar.gz", "--prefix=repo-sha/", &sha])
            .output()
            .unwrap();
        assert!(archive.status.success());
        let api = Arc::new(ActionApi::new(&sha, archive.stdout));
        let copy = root.join("runner-work/_actions/actions/checkout/v4");
        fs::create_dir_all(copy.join(".github/workflows")).unwrap();
        for path in [
            "action.yml",
            "index.js",
            "in.txt",
            ".github/workflows/ci.yml",
        ] {
            fs::copy(work.join(path), copy.join(path)).unwrap();
        }
        let temp = root.join("runner");
        fs::create_dir(&temp).unwrap();
        fs::write(temp.join("event.json"), "{}").unwrap();
        Self {
            root: work,
            remote,
            temp,
            sha,
            api,
        }
    }
    fn run(&self, script: &str, write: &str) -> Output {
        self.command(script, write).output().unwrap()
    }
    fn command(&self, script: &str, write: &str) -> Command {
        self.command_with_options(script, write, &[])
    }
    fn command_with_options(&self, script: &str, write: &str, options: &[&str]) -> Command {
        let path = self.temp.join("script.sh");
        fs::write(&path, script).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("GIT_") {
                command.env_remove(key);
            }
        }
        command
            .arg("sh")
            .args(options)
            .arg(path)
            .current_dir(&self.root)
            .env("GITHUB_ACTIONS", "true")
            .env(
                "GITHUB_SERVER_URL",
                format!("file://{}", self.root.parent().unwrap().display()),
            )
            .env("GITHUB_API_URL", &self.api.url)
            .env(
                "RUNNER_WORKSPACE",
                self.root.parent().unwrap().join("runner-work/repo"),
            )
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_URL")
            .env_remove("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
            .env_remove("STOOP_STRICT_ACTIONS")
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
            .env("HOME", self.root.parent().unwrap().join("home"))
            .env("XDG_CONFIG_HOME", self.root.parent().unwrap().join("xdg"))
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_GLOBAL")
            .env_remove("GIT_CONFIG_SYSTEM")
            .env_remove("GIT_CONFIG_NOSYSTEM")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_ATTR_SOURCE")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .env_remove("STOOP_ENV_SALT");
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(name, &self.api.url);
        }
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
            api: self.api.clone(),
        }
    }
}
fn git(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

fn shell_key(script: &str, matrix: Option<&str>) -> String {
    let mut h = blake3::Hasher::new();
    for field in [script.as_bytes(), b"fixture", b"test", b""] {
        h.update(&(field.len() as u64).to_le_bytes());
        h.update(field);
    }
    if let Some(matrix) = matrix {
        h.update(b"\0matrix\0");
        h.update(matrix.as_bytes());
    }
    format!("sh-{}", &h.finalize().to_hex()[..20])
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
    assert_eq!(record["actions"]["actions/checkout@v4"], w.sha);
    assert!(record["actions"]["!stoop-action-trees-v1"].is_string());
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
fn action_lookup_happens_at_open_before_the_first_step_moves_the_tag() {
    let step = "repo=${GITHUB_SERVER_URL#file://}/actions/checkout.git; other=$(git --git-dir=\"$repo\" -c user.name=Test -c user.email=test@example.org -c commit.gpgsign=false commit-tree HEAD^{tree} -m other); git --git-dir=\"$repo\" update-ref refs/tags/v4 \"$other\"\n";
    let w = Ws::new("action-open", &[step, "true\n"]);
    let first = w.run(step, "1");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = w.run("true\n", "1");
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let records = w.records();
    let record = &records[0]["records"][0];
    assert_eq!(record["status"], "passed");
    assert_eq!(record["actions"]["actions/checkout@v4"], w.sha);
    assert_ne!(
        git(
            &w.root.parent().unwrap().join("actions/checkout.git"),
            &["rev-parse", "refs/tags/v4"]
        ),
        w.sha
    );
}

#[test]
fn altered_runner_action_copy_never_produces_a_content_witness() {
    let w = Ws::new("action-copy-tampered", &["true\n"]);
    let copy = w
        .root
        .parent()
        .unwrap()
        .join("runner-work/_actions/actions/checkout/v4/index.js");
    fs::write(copy, "tampered\n").unwrap();
    let out = w.run("true\n", "1");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("runner action copy differs"));
    let records = w.records();
    assert_eq!(records[0]["records"][0]["status"], "passed");
    assert!(records[0]["records"][0]["actions"]["!stoop-action-trees-v1"].is_null());
}

#[test]
fn failed_action_lookup_does_not_block_job_publication() {
    let w = Ws::new("action-missing", &["true\n"]);
    let out = w
        .command("true\n", "1")
        .env(
            "GITHUB_SERVER_URL",
            format!("file://{}/missing", w.root.parent().unwrap().display()),
        )
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("action unverifiable at journal open"));
    let records = w.records();
    assert_eq!(records[0]["records"][0]["status"], "passed");
    assert!(records[0]["records"][0]["actions"]["actions/checkout@v4"].is_null());
}

#[test]
fn read_only_run_does_not_resolve_actions() {
    let w = Ws::new("action-readonly", &["true\n"]);
    let trace = w.temp.join("git-trace");
    let out = w
        .command("true\n", "0")
        .env(
            "GITHUB_SERVER_URL",
            format!("file://{}/missing", w.root.parent().unwrap().display()),
        )
        .env("GIT_TRACE", &trace)
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!String::from_utf8_lossy(&out.stderr).contains("action unverifiable at journal open"));
    let git_trace = fs::read_to_string(&trace).unwrap_or_default();
    assert!(
        !git_trace.contains("ls-remote"),
        "unexpected lookup: {git_trace}"
    );
    assert!(w.records().is_empty());
}

#[test]
fn strict_env_omits_floating_action_from_published_record() {
    let w = Ws::new("action-strict", &["true\n"]);
    let out = w
        .command("true\n", "1")
        .env("STOOP_STRICT_ACTIONS", "1")
        .output()
        .unwrap();
    assert!(out.status.success());
    let records = w.records();
    assert_eq!(records[0]["records"][0]["status"], "passed");
    assert!(records[0]["records"][0]["actions"]["actions/checkout@v4"].is_null());
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
    let expected = shell_key("true\n", Some("{\"a\":1,\"z\":2}"));
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
        #[serde(default)]
        oid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oid_basis: Option<RecordedOidBasis>,
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
        cwd: Option<String>,
        scope: Option<String>,
        provenance: Option<RecordedProvenance>,
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
        let key = shell_key(script, None);
        assert_eq!(step["key"], key);
        let raw = git(
            &w.remote,
            &["cat-file", "blob", &format!("refs/stoop/{key}")],
        );
        let file: Value = serde_json::from_str(&raw).unwrap();
        let proofs: Vec<Proof> = serde_json::from_value(file["proofs"].clone()).unwrap();
        if script == scripts[0] {
            let input = proofs
                .iter()
                .flat_map(|proof| &proof.inputs)
                .find(|input| input.path == "in.txt")
                .expect("the proof records in.txt");
            assert!(input
                .oid
                .as_deref()
                .is_some_and(|oid| oid.starts_with("sha1:")));
            assert!(input.oid_basis.is_some());
        }
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
                &p.cwd,
                &p.scope,
                &p.provenance,
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
        #[serde(default)]
        oid: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        oid_basis: Option<RecordedOidBasis>,
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
        cwd: Option<String>,
        scope: Option<String>,
        provenance: Option<RecordedProvenance>,
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
    let key = shell_key(script, None);
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
            &p.cwd,
            &p.scope,
            &p.provenance,
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

struct TokenApi {
    url: String,
    requests: Arc<std::sync::atomic::AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TokenApi {
    fn new(sha: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/token", listener.local_addr().unwrap());
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let seen = requests.clone();
        let stopping = stop.clone();
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        let target = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                        let mut bearer = false;
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                                break;
                            }
                            if let Some((name, value)) = line.trim_end().split_once(':') {
                                if name.eq_ignore_ascii_case("authorization")
                                    && value.trim() == "bearer fixture-bearer"
                                {
                                    bearer = true;
                                }
                            }
                        }
                        let audience = target.strip_prefix("/token?audience=").map(decode_query);
                        let body = if bearer && audience.is_some() {
                            seen.fetch_add(1, Ordering::Relaxed);
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            let claims = serde_json::json!({
                                "iss": "https://token.actions.githubusercontent.com",
                                "aud": audience.unwrap(),
                                "repository": "owner/repo",
                                "repository_id": "12345",
                                "repository_owner_id": "6789",
                                "runner_environment": "github-hosted",
                                "ref_protected": "true",
                                "ref": "refs/heads/main",
                                "event_name": "push",
                                "sha": sha,
                                "run_id": "123",
                                "run_attempt": "1",
                                "workflow_ref": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
                                "job_workflow_ref": "owner/repo/.github/workflows/ci.yml@refs/heads/main",
                                "iat": now,
                                "nbf": now,
                                "exp": now + 300,
                            });
                            let header = serde_json::json!({"alg": "RS256", "kid": "test-key-1", "typ": "JWT"});
                            let signed = format!(
                                "{}.{}",
                                jwt_b64(&serde_json::to_vec(&header).unwrap()),
                                jwt_b64(&serde_json::to_vec(&claims).unwrap())
                            );
                            let key = ring::signature::RsaKeyPair::from_pkcs8(include_bytes!(
                                "fixtures/attest/test-rsa-1.pkcs8.der"
                            ))
                            .unwrap();
                            let mut signature = vec![0; key.public().modulus_len()];
                            key.sign(
                                &ring::signature::RSA_PKCS1_SHA256,
                                &ring::rand::SystemRandom::new(),
                                signed.as_bytes(),
                                &mut signature,
                            )
                            .unwrap();
                            serde_json::json!({"value": format!("{signed}.{}", jwt_b64(&signature))}).to_string()
                        } else {
                            "{}".to_owned()
                        };
                        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(error) => panic!("token fixture: {error}"),
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for TokenApi {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn decode_query(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(u8::from_str_radix(&value[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

fn jwt_b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |v, (i, b)| v | (u32::from(*b) << (16 - i * 8)));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - i * 6)) & 63) as usize] as char);
        }
    }
    out
}

#[test]
fn clean_children_still_publish_an_attestation_the_planner_verifies() {
    use std::os::unix::fs::PermissionsExt;
    let script = "env > \"$RUNNER_TEMP/child.env\"\n";
    let mut w = Ws::new("oidc-filter", &[script]);
    let workflow = format!("name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {{0}}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  test:\n    needs: [stoop-plan]\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',test,') }}}}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: |\n          {}\n", script.trim_end());
    let runner = if cfg!(target_arch = "aarch64") {
        "ubuntu-24.04-arm"
    } else {
        "ubuntu-latest"
    };
    let workflow = workflow.replace("runs-on: ubuntu-latest", &format!("runs-on: {runner}"));
    fs::write(w.root.join(".github/workflows/ci.yml"), workflow).unwrap();
    git(&w.root, &["add", ".github/workflows/ci.yml"]);
    git(
        &w.root,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "gated fixture",
        ],
    );
    w.sha = git(&w.root, &["rev-parse", "HEAD"]);
    git(&w.root, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
    fs::write(
        w.temp.join("event.json"),
        r#"{"repository":{"default_branch":"main"}}"#,
    )
    .unwrap();
    let token = TokenApi::new(w.sha.clone());
    let bin = w.temp.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let curl = bin.join("curl");
    fs::write(&curl, "#!/bin/sh\n/usr/bin/env >> \"$STOOP_CURL_ENV\"\nif [ \"$1\" = -q ]; then\n  config=$(cat)\n  case \"$config\" in\n    *token.actions.githubusercontent.com/.well-known/jwks*) cat \"$STOOP_TEST_JWKS\" ;;\n    *\"$STOOP_TEST_TOKEN_URL\"*) printf '%s\\n' \"$config\" | /usr/bin/curl \"$@\" --noproxy '*' --proto '=http,https' ;;\n    *) exit 81 ;;\n  esac\nelse\n  case \"$*\" in\n    *\"$STOOP_TEST_ACTION_API/repos/actions/checkout/tarball/\"*) exec /usr/bin/curl \"$@\" --noproxy '*' ;;\n    *) exit 82 ;;\n  esac\nfi\n").unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
    let hook = w.root.join(".git/hooks/pre-push");
    fs::write(&hook, "#!/bin/sh\n/usr/bin/env > \"$STOOP_HOOK_ENV\"\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let jwks = w.temp.join("jwks.json");
    fs::write(&jwks, include_bytes!("fixtures/attest/test-jwks.json")).unwrap();
    let curl_env = w.temp.join("curl.env");
    let hook_env = w.temp.join("hook.env");
    let path = format!("{}:/usr/bin:/bin", bin.display());
    let configure = |command: &mut Command| {
        command
            .env("PATH", &path)
            .env("CI", "true")
            .env("ACTIONS_ID_TOKEN_REQUEST_URL", &token.url)
            .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fixture-bearer")
            .env("STOOP_TEST_TOKEN_URL", &token.url)
            .env("STOOP_TEST_ACTION_API", &w.api.url)
            .env("STOOP_TEST_JWKS", &jwks)
            .env("STOOP_CURL_ENV", &curl_env)
            .env("STOOP_HOOK_ENV", &hook_env)
            .env("GITHUB_REPOSITORY_ID", "12345")
            .env("GITHUB_REPOSITORY_OWNER_ID", "6789")
            .env(
                "STOOP_JOB_WORKFLOW_REF",
                "owner/repo/.github/workflows/ci.yml@refs/heads/main",
            )
            .env("RUNNER_OS", "Linux")
            .env_remove("STOOP_PASS_ENV");
    };
    let mut command = w.command(script, "1");
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        token.requests.load(Ordering::Relaxed) > 0,
        "journal never requested the token"
    );
    for path in [w.temp.join("child.env"), curl_env.clone(), hook_env.clone()] {
        let env = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        for value in [
            b"ACTIONS_ID_TOKEN_REQUEST_URL".as_slice(),
            b"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
            b"fixture-bearer",
        ] {
            assert!(
                !env.windows(value.len()).any(|window| window == value),
                "{} inherited a request credential",
                path.display()
            );
        }
    }
    let records = w.records();
    assert!(
        records[0]["records"][0]["attest"].as_str().is_some(),
        "record was not attested: {records:?}"
    );

    let mut plan = Command::new(env!("CARGO_BIN_EXE_stoop"));
    plan.args([
        "plan",
        "--workflow",
        ".github/workflows/ci.yml",
        "--format",
        "json",
    ])
    .current_dir(&w.root)
    .env_clear()
    .env("HOME", &w.temp)
    .env("GIT_CONFIG_GLOBAL", "/dev/null")
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GITHUB_ACTIONS", "true")
    .env("GITHUB_REPOSITORY", "owner/repo")
    .env("GITHUB_WORKFLOW", "fixture")
    .env(
        "GITHUB_WORKFLOW_REF",
        "owner/repo/.github/workflows/ci.yml@refs/heads/main",
    )
    .env("GITHUB_JOB", "stoop-plan")
    .env("GITHUB_SHA", &w.sha)
    .env("GITHUB_EVENT_PATH", w.temp.join("event.json"))
    .env(
        "GITHUB_SERVER_URL",
        format!("file://{}", w.root.parent().unwrap().display()),
    )
    .env("GITHUB_API_URL", &w.api.url)
    .env(
        "RUNNER_WORKSPACE",
        w.root.parent().unwrap().join("runner-work/repo"),
    )
    .env("STOOP_SYNC", "git");
    configure(&mut plan);
    let output = plan.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["jobs"][0]["code"], "proved", "{result}");
    fs::write(&jwks, r#"{"keys":[]}"#).unwrap();
    let output = plan.output().unwrap();
    assert!(output.status.success());
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["jobs"][0]["code"], "unattested", "{result}");
    assert_eq!(result["skip"], serde_json::json!([]));
}

#[test]
fn allowed_step_blocks_later_publication_after_an_attested_running_record() {
    use std::os::unix::fs::PermissionsExt;
    let first = "true\n";
    let allowed =
        "test -f \"$RUNNER_TEMP/stoop/journal.blocked\" && env > \"$RUNNER_TEMP/allowed.env\"\n";
    let last = "echo last\n";
    let w = Ws::new("oidc-opt-in", &[first, allowed, last]);
    let token = TokenApi::new(w.sha.clone());
    let bin = w.temp.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let curl = bin.join("curl");
    fs::write(&curl, "#!/bin/sh\nif [ \"$1\" = -q ]; then\n  config=$(cat)\n  case \"$config\" in\n    *\"$STOOP_TEST_TOKEN_URL\"*) printf '%s\\n' \"$config\" | /usr/bin/curl \"$@\" --noproxy '*' --proto '=http,https' ;;\n    *) exit 81 ;;\n  esac\nelse\n  case \"$*\" in\n    *\"$STOOP_TEST_ACTION_API/repos/actions/checkout/tarball/\"*) exec /usr/bin/curl \"$@\" --noproxy '*' ;;\n    *) exit 82 ;;\n  esac\nfi\n").unwrap();
    fs::set_permissions(&curl, fs::Permissions::from_mode(0o755)).unwrap();
    let configure = |command: &mut Command| {
        command
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("ACTIONS_ID_TOKEN_REQUEST_URL", &token.url)
            .env("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "fixture-bearer")
            .env("STOOP_TEST_TOKEN_URL", &token.url)
            .env("STOOP_TEST_ACTION_API", &w.api.url)
            .env_remove("STOOP_PASS_ENV");
    };
    let mut command = w.command(first, "1");
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let before = w.records();
    assert_eq!(before[0]["records"][0]["status"], "running");
    assert!(before[0]["records"][0]["attest"].as_str().is_some());
    let requests = token.requests.load(Ordering::Relaxed);
    assert!(requests > 0);

    let mut command = w.command_with_options(allowed, "1", &["--allow-id-token"]);
    configure(&mut command);
    command.env(
        "STOOP_PASS_ENV",
        "ACTIONS_ID_TOKEN_REQUEST_URL,ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    );
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let env = fs::read(w.temp.join("allowed.env")).unwrap();
    assert!(env
        .windows(b"ACTIONS_ID_TOKEN_REQUEST_TOKEN=fixture-bearer".len())
        .any(|v| v == b"ACTIONS_ID_TOKEN_REQUEST_TOKEN=fixture-bearer"));
    assert!(w.temp.join("stoop/journal.blocked").is_file());
    assert_eq!(w.records(), before);
    assert_eq!(token.requests.load(Ordering::Relaxed), requests);

    let mut command = w.command(last, "1");
    configure(&mut command);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(w.records(), before);
    assert_eq!(token.requests.load(Ordering::Relaxed), requests);
}
