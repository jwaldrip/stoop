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
fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
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
    let mut c = Command::new("git")
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
        Command::new(env!("CARGO_BIN_EXE_stoop"))
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
fn dotted_step_keys_are_mapped_forward_without_losing_identity() {
    let f = Fixture::new();
    let refs = f.populate();
    let job_ref = refs
        .iter()
        .find(|r| r.starts_with("refs/stoop/job-"))
        .unwrap();
    let mut job: Value =
        serde_json::from_str(&git(&f.remote, &["cat-file", "blob", job_ref])).unwrap();
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
        ],
    );
    assert!(result.status.success());
    assert!(checkout
        .join(".stoop/proofs")
        .join(format!("{new_key}.json"))
        .exists());
    let local_refs = git(
        &checkout,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    );
    assert!(local_refs
        .lines()
        .any(|r| r == format!("refs/stoop/{}", new_key.replace('.', "_"))));
}
