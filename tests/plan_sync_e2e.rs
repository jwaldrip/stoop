use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn hermetic_git(command: &mut Command) {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("GIT_ATTR_SOURCE");
}
fn git(dir: &Path, args: &[&str]) -> String {
    let mut command = Command::new("git");
    hermetic_git(&mut command);
    let out = command
        .current_dir(dir)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}
fn put_ref(repo: &Path, key: &str, data: &Value) {
    let mut command = Command::new("git");
    hermetic_git(&mut command);
    let mut c = command
        .current_dir(repo)
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(data).unwrap().as_bytes())
        .unwrap();
    let out = c.wait_with_output().unwrap();
    assert!(out.status.success());
    let oid = String::from_utf8(out.stdout).unwrap();
    git(
        repo,
        &["update-ref", &format!("refs/stoop/{key}"), oid.trim()],
    );
}
fn sh_key(script: &str, job: &str) -> String {
    let mut h = blake3::Hasher::new();
    for part in [script.as_bytes(), b"fixture", job.as_bytes(), b""] {
        h.update(&(part.len() as u64).to_le_bytes());
        h.update(part);
    }
    format!("sh-{}", &h.finalize().to_hex()[..20])
}
struct Fixture {
    base: PathBuf,
    source: PathBuf,
    remote: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "stoop-b7-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let source = base.join("source");
        let remote = base.join("remote.git");
        fs::create_dir_all(source.join(".github/workflows")).unwrap();
        fs::create_dir_all(&remote).unwrap();
        git(&remote, &["init", "--bare", "-q"]);
        git(&source, &["init", "-q"]);
        git(
            &source,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let mut w = String::from("name: fixture\ndefaults: {run: {shell: 'stoop sh {0}'}}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n");
        for id in ["a", "b"] {
            w.push_str(&format!("  {id}:\n    needs: [stoop-plan]\n    if: ${{{{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',{id},') }}}}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: echo {id}1\n      - run: echo {id}2\n"));
        }
        fs::write(source.join(".github/workflows/ci.yml"), w).unwrap();
        git(&source, &["add", "."]);
        git(&source, &["commit", "-qm", "fixture"]);
        git(&source, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        git(&remote, &["symbolic-ref", "HEAD", "refs/heads/main"]);
        Self {
            base,
            source,
            remote,
        }
    }
    fn command(&self, cwd: &Path, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        hermetic_git(&mut command);
        command
            .current_dir(cwd)
            .env("GITHUB_JOB", "stoop-plan")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("GITHUB_OUTPUT")
            .env_remove("GITHUB_EVENT_PATH")
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_STORE")
            .env_remove("STOOP_ENV_SALT")
            .env_remove("STOOP_MAX_AGE")
            .args(args)
            .output()
            .unwrap()
    }
    fn clone_at(&self, name: &str) -> PathBuf {
        let dst = self.base.join(name);
        git(
            &self.base,
            &[
                "clone",
                "-q",
                self.remote.to_str().unwrap(),
                dst.to_str().unwrap(),
            ],
        );
        dst
    }
    fn populate(&self) -> Vec<String> {
        let out = self.command(
            &self.source,
            &[
                "plan",
                "--workflow",
                ".github/workflows/ci.yml",
                "--format",
                "json",
            ],
        );
        assert!(out.status.success());
        let plan: Value = serde_json::from_slice(&out.stdout).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sha = git(&self.source, &["rev-parse", "HEAD"]);
        let provenance =
            json!({"os":"linux", "arch":"x86_64", "tracer":"ptrace-seccomp", "version":4});
        let digest_bytes = b"[[],[],[],{},{},[],[],[],\"\",null,{\"os\":\"linux\",\"arch\":\"x86_64\",\"tracer\":\"ptrace-seccomp\",\"version\":4}]";
        let digest = format!("p-{}", &blake3::hash(digest_bytes).to_hex()[..32]);
        let mut selected = Vec::new();
        for j in plan["jobs"].as_array().unwrap() {
            let id = j["id"].as_str().unwrap();
            let job_key = j["legs"][0]["key"].as_str().unwrap();
            selected.push(format!("refs/stoop/{job_key}"));
            let mut steps = Vec::new();
            for n in 1..=2 {
                let key = sh_key(&format!("echo {id}{n}"), id);
                let proof = json!({"created":now,"argv":[],"cwd":"","scope":null,"provenance":provenance,"env":{},"inputs":[],"outputs":[],"removed":[],"ignore":[],"priors":[],"unplannable":[],"probes":{}});
                put_ref(
                    &self.remote,
                    &key,
                    &json!({"v":2,"key":key,"proofs":[proof]}),
                );
                selected.push(format!("refs/stoop/{key}"));
                steps.push(json!({"key":key,"proof":digest,"how":"ran"}));
            }
            let record = json!({"created":now,"started":now*1000,"status":"passed","commit":sha,"host":{"os":"Linux","arch":"X64"},"event_path":"/tmp/event.json","run":"1/1","steps":steps});
            put_ref(
                &self.remote,
                job_key,
                &json!({"v":1,"kind":"job","key":job_key,"records":[record]}),
            );
        }
        for n in 0..9 {
            let key = format!("{}-{n:032x}", if n < 3 { "job" } else { "sh" });
            put_ref(&self.remote, &key, &json!({"unrelated":n}));
        }
        selected.sort();
        selected
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn record_step_refs(record: &Value) -> Vec<String> {
    record["records"][0]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| {
            format!(
                "refs/stoop/{}",
                step["key"].as_str().unwrap().replace('.', "_")
            )
        })
        .collect()
}

fn assert_mismatch_matches_full_pull(
    f: &Fixture,
    checkout: &Path,
    result: &std::process::Output,
    selected: &[String],
    rejected_steps: &[String],
    expected_code: &str,
) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("fetched 4 of 15 stoop refs"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let plan: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(plan["skip"], json!([]));
    let jobs = plan["jobs"].as_array().unwrap();
    assert_eq!(jobs.len(), 2);
    assert!(
        jobs.iter().any(|job| job["code"] == expected_code),
        "{plan}"
    );
    assert!(jobs.iter().any(|job| job["code"] == "unattested"), "{plan}");
    let local = git(
        checkout,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    );
    let actual: Vec<_> = local.lines().collect();
    let expected: Vec<_> = selected
        .iter()
        .filter(|name| !rejected_steps.contains(name))
        .map(String::as_str)
        .collect();
    assert_eq!(actual, expected);
    let full = f.clone_at("full-mismatch");
    assert!(f
        .command(&full, &["pull", "--sync", "git"])
        .status
        .success());
    let full_plan = f.command(
        &full,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--format",
            "json",
        ],
    );
    assert!(full_plan.status.success());
    assert_eq!(
        plan,
        serde_json::from_slice::<Value>(&full_plan.stdout).unwrap()
    );
}
#[test]
fn plan_fetches_only_referenced_job_and_step_refs() {
    let f = Fixture::new();
    let selected = f.populate();
    let checkout = f.clone_at("targeted");
    let result = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
            "--explain",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("fetched 6 of 15 stoop refs"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let refs: Vec<_> = git(
        &checkout,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    )
    .lines()
    .map(str::to_owned)
    .collect();
    assert_eq!(refs, selected);
    let decisions: Value = serde_json::from_slice(&result.stdout).unwrap();
    for job in decisions["jobs"].as_array().unwrap() {
        assert_eq!(job["code"], "unattested", "{job}");
    }
    let full = f.clone_at("all");
    let pull = f.command(&full, &["pull", "--sync", "git"]);
    assert!(pull.status.success());
    let expected = f.command(
        &full,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--format",
            "json",
        ],
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stdout).unwrap(),
        serde_json::from_slice::<Value>(&expected.stdout).unwrap()
    );
}

#[cfg(unix)]
#[test]
fn plan_lists_once_and_fetches_jobs_then_proofs() {
    use std::os::unix::fs::PermissionsExt;

    let f = Fixture::new();
    f.populate();
    let checkout = f.clone_at("counted");
    let helper = f.base.join("count-upload-pack");
    let count = f.base.join("upload-count");
    let quote = |path: &Path| format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"));
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf '1\\n' >> {}\nexec git upload-pack \"$@\"\n",
            quote(&count)
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        &checkout,
        &["config", "remote.origin.uploadpack", &quote(&helper)],
    );
    let result = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
            "--explain",
        ],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stderr).contains("fetched 6 of 15 stoop refs"));
    let plan: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(plan["jobs"].as_array().unwrap().len(), 2);
    assert!(plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|job| job["code"] == "unattested"));
    assert_eq!(fs::read_to_string(count).unwrap().lines().count(), 3);
}

#[test]
fn missing_referenced_proof_is_reported_without_fetching_other_refs() {
    let f = Fixture::new();
    let refs = f.populate();
    let missing = refs
        .iter()
        .find(|r| r.starts_with("refs/stoop/sh-"))
        .unwrap();
    git(&f.remote, &["update-ref", "-d", missing]);
    let checkout = f.clone_at("missing");
    let result = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
            "--explain",
        ],
    );
    assert!(result.status.success());
    let plan: Value = serde_json::from_slice(&result.stdout).unwrap();
    let codes: Vec<_> = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|j| j["code"].as_str())
        .collect();
    assert!(codes.contains(&"proof-missing"), "{plan}");
    assert!(codes.contains(&"unattested"), "{plan}");
    assert!(String::from_utf8_lossy(&result.stderr).contains("fetched 5 of 14 stoop refs"));
}

#[test]
fn mismatched_dotted_step_key_is_not_fetched() {
    let f = Fixture::new();
    let refs = f.populate();
    let job_ref = refs
        .iter()
        .find(|r| r.starts_with("refs/stoop/job-"))
        .unwrap();
    let mut job: Value =
        serde_json::from_str(&git(&f.remote, &["cat-file", "blob", job_ref])).unwrap();
    let rejected_steps = record_step_refs(&job);
    let old_key = job["records"][0]["steps"][0]["key"]
        .as_str()
        .unwrap()
        .to_string();
    let new_key = format!("{old_key}.custom");
    let old_ref = format!("refs/stoop/{old_key}");
    let mut proof: Value =
        serde_json::from_str(&git(&f.remote, &["cat-file", "blob", &old_ref])).unwrap();
    proof["key"] = json!(new_key);
    put_ref(&f.remote, &new_key.replace('.', "_"), &proof);
    job["records"][0]["steps"][0]["key"] = json!(new_key);
    let job_key = job["key"].as_str().unwrap().to_string();
    put_ref(&f.remote, &job_key, &job);
    git(&f.remote, &["update-ref", "-d", &old_ref]);
    let checkout = f.clone_at("dotted");
    let result = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
            "--explain",
        ],
    );
    assert_mismatch_matches_full_pull(&f, &checkout, &result, &refs, &rejected_steps, "incomplete");
    assert!(result.status.success());
    let plan: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|job| job["code"] == "incomplete"));
    assert!(!checkout
        .join(".stoop/proofs")
        .join(format!("{new_key}.json"))
        .exists());
    let local_refs = git(
        &checkout,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    );
    assert!(!local_refs
        .lines()
        .any(|r| r == format!("refs/stoop/{}", new_key.replace('.', "_"))));
}

#[test]
fn mismatched_record_cannot_fetch_an_unrelated_job_ref() {
    let f = Fixture::new();
    let refs = f.populate();
    let planned = refs
        .iter()
        .find(|r| r.starts_with("refs/stoop/job-"))
        .unwrap();
    let unrelated_key = "job-00000000000000000000000000000000";
    let unrelated_ref = format!("refs/stoop/{unrelated_key}");
    let mut record: Value =
        serde_json::from_str(&git(&f.remote, &["cat-file", "blob", planned])).unwrap();
    let rejected_steps = record_step_refs(&record);
    record["records"][0]["steps"][0]["key"] = json!(unrelated_key);
    let key = record["key"].as_str().unwrap().to_string();
    put_ref(&f.remote, &key, &record);
    let checkout = f.clone_at("mismatch");
    let output = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
            "--explain",
        ],
    );
    assert_mismatch_matches_full_pull(&f, &checkout, &output, &refs, &rejected_steps, "incomplete");
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    let codes: Vec<_> = plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|j| j["code"].as_str())
        .collect();
    assert!(codes.contains(&"incomplete"), "{plan}");
    assert!(codes.contains(&"unattested"), "{plan}");
    let fetched = git(
        &checkout,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    );
    assert!(!fetched.lines().any(|r| r == unrelated_ref));
}

#[test]
fn ineligible_job_records_do_not_admit_their_proofs() {
    for (case, expected_code) in [
        ("failed", "stale"),
        ("legacy", "incomplete"),
        ("relative-event", "incomplete"),
    ] {
        let f = Fixture::new();
        let refs = f.populate();
        let planned = refs
            .iter()
            .find(|r| r.starts_with("refs/stoop/job-"))
            .unwrap();
        let mut record: Value =
            serde_json::from_str(&git(&f.remote, &["cat-file", "blob", planned])).unwrap();
        let rejected_steps = record_step_refs(&record);
        match case {
            "failed" => record["records"][0]["status"] = json!("failed"),
            "legacy" => record["records"][0]["started"] = json!(0),
            "relative-event" => record["records"][0]["event_path"] = json!("event.json"),
            _ => unreachable!(),
        }
        let key = record["key"].as_str().unwrap().to_string();
        put_ref(&f.remote, &key, &record);
        let checkout = f.clone_at(case);
        let output = f.command(
            &checkout,
            &[
                "plan",
                "--workflow",
                ".github/workflows/ci.yml",
                "--sync",
                "git",
                "--format",
                "json",
                "--explain",
            ],
        );
        assert_mismatch_matches_full_pull(
            &f,
            &checkout,
            &output,
            &refs,
            &rejected_steps,
            expected_code,
        );
    }
}

#[test]
fn wrong_embedded_proof_key_fails_every_job_wide() {
    let f = Fixture::new();
    let refs = f.populate();
    let name = refs
        .iter()
        .find(|r| r.starts_with("refs/stoop/sh-"))
        .unwrap();
    let key = name.strip_prefix("refs/stoop/").unwrap();
    let mut blob: Value =
        serde_json::from_str(&git(&f.remote, &["cat-file", "blob", name])).unwrap();
    let other = "sh-ffffffffffffffffffff";
    blob["key"] = json!(other);
    put_ref(&f.remote, key, &blob);
    let checkout = f.clone_at("wrong-key");
    let output = f.command(
        &checkout,
        &[
            "plan",
            "--workflow",
            ".github/workflows/ci.yml",
            "--sync",
            "git",
            "--format",
            "json",
        ],
    );
    let plan: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(plan["skip"], json!([]));
    assert!(plan["jobs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|j| j["code"] == "error"
            && j["detail"] == "sync: proof ref does not match a requested key"));
    assert!(!checkout
        .join(".stoop/proofs")
        .join(format!("{other}.json"))
        .exists());
    assert!(!checkout
        .join(".stoop/proofs")
        .join(format!("{key}.json"))
        .exists());
}

#[test]
fn sync_errors_do_not_expose_remote_url_credentials() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};
    let f = Fixture::new();
    for format in ["json", "github"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(10);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < until =>
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("local test server did not accept a request: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            stream
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
        });
        let remote =
            format!("git:http://dummyuser:dummypass@{address}/repo?token=dummyquerysecret");
        let output_file = f.base.join(format!("output-{format}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        hermetic_git(&mut command);
        command
            .current_dir(&f.source)
            .env("GITHUB_JOB", "stoop-plan")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("STOOP_SYNC")
            .env_remove("GITHUB_EVENT_PATH")
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ALLOW_PROTOCOL", "http")
            .env_remove("http_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("all_proxy")
            .env_remove("ALL_PROXY")
            .args([
                "plan",
                "--workflow",
                ".github/workflows/ci.yml",
                "--format",
                format,
                "--sync",
                &remote,
            ]);
        if format == "github" {
            command.env("GITHUB_OUTPUT", &output_file);
        } else {
            command.env_remove("GITHUB_OUTPUT");
        }
        let out = command.output().unwrap();
        server.join().unwrap();
        assert!(out.status.success());
        let mut text = String::from_utf8_lossy(&out.stdout).to_string();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        if format == "github" {
            text.push_str(&fs::read_to_string(output_file).unwrap());
        }
        for secret in ["dummyuser", "dummypass", "dummyquerysecret", &remote] {
            assert!(!text.contains(secret), "{format} exposed {secret}: {text}");
        }
    }
}

#[test]
fn sync_failure_details_are_fixed_in_json_and_github_outputs() {
    let f = Fixture::new();
    for (case, remote, detail) in [
        (
            "missing",
            "git:file:///nonexistent/stoop?token=STOOPMARK",
            "sync: git ls-remote failed with exit status 128",
        ),
        (
            "backend",
            "https://user:STOOPMARK@example.invalid/r?token=STOOPMARK",
            "sync: unknown sync backend; use `git` or `git:<remote>`",
        ),
    ] {
        for format in ["json", "github"] {
            let output_file = f.base.join(format!("redaction-output-{case}-{format}"));
            let summary_file = f.base.join(format!("redaction-summary-{case}-{format}"));
            fs::write(&output_file, "").unwrap();
            fs::write(&summary_file, "").unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
            hermetic_git(&mut command);
            let out = command
                .current_dir(&f.source)
                .env("GITHUB_JOB", "stoop-plan")
                .env("GITHUB_OUTPUT", &output_file)
                .env("GITHUB_STEP_SUMMARY", &summary_file)
                .env_remove("GITHUB_ACTIONS")
                .env_remove("GITHUB_EVENT_PATH")
                .env_remove("STOOP_SYNC")
                .env_remove("STOOP_FULL")
                .env_remove("STOOP_OFF")
                .env_remove("STOOP_STORE")
                .env_remove("STOOP_ENV_SALT")
                .env_remove("STOOP_MAX_AGE")
                .args([
                    "plan",
                    "--workflow",
                    ".github/workflows/ci.yml",
                    "--format",
                    format,
                    "--sync",
                    remote,
                ])
                .output()
                .unwrap();
            assert!(out.status.success());
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let github_output = fs::read_to_string(&output_file).unwrap();
            let summary = fs::read_to_string(&summary_file).unwrap();
            for (channel, text) in [
                ("stdout", stdout.as_ref()),
                ("stderr", stderr.as_ref()),
                ("GITHUB_OUTPUT", github_output.as_str()),
                ("GITHUB_STEP_SUMMARY", summary.as_str()),
            ] {
                assert!(
                    !text.contains("STOOPMARK"),
                    "{case} {format} {channel}: {text}"
                );
            }
            assert!(stderr.contains(detail), "{case} {format}: {stderr}");
            if format == "json" {
                let plan: Value = serde_json::from_str(&stdout).unwrap();
                assert_eq!(plan["skip"], json!([]));
                let jobs = plan["jobs"].as_array().unwrap();
                assert_eq!(jobs.len(), 2);
                assert!(jobs
                    .iter()
                    .all(|job| job["code"] == "error" && job["detail"] == detail));
            } else {
                assert!(github_output.starts_with("skip=,\n"), "{github_output}");
                assert_eq!(summary.matches("| `error` |").count(), 2, "{summary}");
            }
        }
    }
}
