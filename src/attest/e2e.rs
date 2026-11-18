//! Recording and planning end to end, in one process. The journal publishes through the
//! real sync code to a bare remote, and a loopback server stands in for GitHub's OIDC
//! token endpoint and JWKS. Records are read back from the remote, and only the verifier
//! decides whether a record may skip a job. Nothing here calls GitHub.

use super::tests::{
    header, pair, token, CEILING, JWKS, KEY_1, OWNER_ID, PATH, REPO, REPO_ID, WORKFLOW,
};
use super::*;
use crate::gha::{context::GhCtx, workflow};
use crate::job::{JobRecord, JobStore, RecordStatus};
use crate::journal::Journal;
use crate::plan::spec::{JobSpec, StepSpec};
use crate::proof::Store;
use crate::run::{How, Outcome};
use crate::sync::Remote;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

const BEARER: &str = "test-request-bearer";
const WORKFLOW_TEXT: &str = "name: fixture
on: push
defaults:
  run:
    shell: stoop sh {0}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@1111111111111111111111111111111111111111
      - run: |
          true
";
const ENV: [&str; 17] = [
    "GITHUB_ACTIONS",
    "GITHUB_REPOSITORY",
    "GITHUB_WORKFLOW_REF",
    "GITHUB_WORKFLOW",
    "GITHUB_JOB",
    "GITHUB_SHA",
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "GITHUB_EVENT_PATH",
    "RUNNER_TEMP",
    "RUNNER_WORKSPACE",
    "GITHUB_API_URL",
    "GITHUB_SERVER_URL",
    "XDG_CACHE_HOME",
    "RUNNER_OS",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
];

/// What the fake GitHub serves: the claims of the next token, the key set it publishes,
/// and whether it refuses token requests.
#[derive(Clone)]
struct Github {
    claims: Value,
    jwks: Vec<u8>,
    failing: bool,
}

/// Serves `/token` and `/.well-known/jwks` on loopback and returns the base URL.
fn serve(state: Arc<Mutex<Github>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("address"));
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let github = state.lock().expect("state").clone();
            answer(stream, &github);
        }
    });
    base
}

fn answer(mut stream: TcpStream, github: &Github) {
    let Ok(copy) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(copy);
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return;
    }
    let mut authorization = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.trim_end().split_once(':') {
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_string());
            }
        }
    }
    let target = request.split_whitespace().nth(1).unwrap_or("/").to_string();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    if path == "/repos/actions/checkout/tarball/1111111111111111111111111111111111111111" {
        let body = crate::gha::actions::fixture_archive();
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(&body);
        return;
    }
    let expected = format!("bearer {BEARER}");
    let (status, body) = match path {
        "/token" if github.failing => (500, "{}".to_string()),
        "/token" if authorization.as_deref() != Some(expected.as_str()) => (401, "{}".into()),
        "/token" => {
            let mut claims = github.claims.clone();
            claims["aud"] = json!(query_param(query, "audience").unwrap_or_default());
            let issued = token(&header("test-key-1"), &claims, &pair(KEY_1));
            (200, json!({ "value": issued }).to_string())
        }
        "/.well-known/jwks" => (200, String::from_utf8_lossy(&github.jwks).into_owned()),
        _ => (404, "{}".to_string()),
    };
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        pair.split_once('=')
            .filter(|(key, _)| *key == name)
            .map(|(_, value)| percent_decode(value))
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The claims GitHub issues for one run. `job_workflow_ref` names the file that ran the job.
fn claims(sha: &str, run_id: &str, git_ref: &str, event: &str, job_workflow_ref: &str) -> Value {
    json!({
        "iss": ISSUER,
        "repository": REPO,
        "repository_id": REPO_ID,
        "repository_owner_id": OWNER_ID,
        "runner_environment": "github-hosted",
        "ref_protected": "true",
        "ref": git_ref,
        "event_name": event,
        "sha": sha,
        "run_id": run_id,
        "run_attempt": "1",
        "workflow_ref": WORKFLOW,
        "job_workflow_ref": job_workflow_ref,
        "iat": crate::proof::now(),
        "nbf": crate::proof::now(),
        "exp": 1_763_400_300u64,
    })
}

struct Repo {
    root: PathBuf,
    work: PathBuf,
    sha: String,
}

impl Repo {
    /// A bare remote and a work tree whose default branch carries the workflow.
    fn new(root: &Path) -> Self {
        let remote = root.join("remote.git");
        let work = root.join("work");
        fs::create_dir_all(&work).expect("work");
        let remote_text = remote.to_str().expect("utf8 path");
        git(root, &["init", "--bare", "-q", remote_text]);
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["remote", "add", "origin", remote_text]);
        fs::create_dir_all(work.join(".github/workflows")).expect("workflows");
        fs::write(work.join(PATH), WORKFLOW_TEXT).expect("workflow");
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
        git(&work, &["push", "-q", "origin", "HEAD:refs/heads/main"]);
        let sha = git(&work, &["rev-parse", "HEAD"]).trim().to_string();
        Self {
            root: root.to_path_buf(),
            work,
            sha,
        }
    }

    fn remote(&self) -> Remote {
        Remote::from_spec("git", &self.work, true).expect("remote")
    }

    /// Runs one traced step of job `test` as run `run_id` and publishes the record.
    /// `token_url` is the OIDC token request URL, or None for a job without
    /// `id-token: write`.
    fn publish(&self, run_id: &str, token_url: Option<&str>) -> Result<(), String> {
        let temp = self.root.join(format!("runner-{run_id}"));
        fs::create_dir_all(&temp).map_err(|e| e.to_string())?;
        fs::write(temp.join("event.json"), "{}").map_err(|e| e.to_string())?;
        let copy =
            temp.join("work/_actions/actions/checkout/1111111111111111111111111111111111111111");
        fs::create_dir_all(&copy).map_err(|e| e.to_string())?;
        fs::write(
            copy.join("action.yml"),
            "runs:\n  using: node20\n  main: index.js\n",
        )
        .map_err(|e| e.to_string())?;
        fs::write(copy.join("index.js"), "fixture\n").map_err(|e| e.to_string())?;
        let env = runner_env(&temp, &self.sha, run_id);
        for (name, value) in &env {
            std::env::set_var(name, value);
        }
        match token_url {
            Some(url) => {
                std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_URL", url);
                std::env::set_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN", BEARER);
            }
            None => {
                std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_URL");
                std::env::remove_var("ACTIONS_ID_TOKEN_REQUEST_TOKEN");
            }
        }
        let mut journal = Journal::open(&self.work, None, true)?.ok_or("journal is inactive")?;
        let key = traced_key(&planned(&env));
        journal.before(&key)?;
        let outcome = Outcome {
            status: 0,
            key,
            how: How::Skipped {
                proof: "p-0000000000000000000000000000000000000000".into(),
            },
        };
        let proofs = Store::new(self.root.join("proofs"));
        journal.after(
            &outcome,
            &JobStore::new(self.root.join("store")),
            &proofs,
            Some(&self.remote()),
        )
    }

    /// The job file on the remote, read back as a planner loads it. Returns the blob
    /// id it was read from, for a compare-and-swap push, and the records.
    fn read(&self, key: &str) -> (String, Vec<JobRecord>) {
        let (oid, blob) = self
            .remote()
            .pull_job(key)
            .expect("pull")
            .expect("the job has a file");
        let pulled = JobStore::new(self.root.join("pulled"));
        pulled.import(key, &blob).expect("import");
        (oid, pulled.load(key))
    }

    /// Pushes `record` into the job file the way a writer would, keeping every other record.
    fn forge(&self, key: &str, record: JobRecord) {
        let (oid, blob) = self
            .remote()
            .pull_job(key)
            .expect("pull")
            .expect("the job has a file");
        let bytes = JobStore::merge_remote(key, Some(&blob), record).expect("merge");
        self.remote()
            .push_job(key, &bytes, Some(&oid), None)
            .expect("forged push");
    }
}

/// The environment a runner gives the journal for one run of job `test`.
fn runner_env(temp: &Path, sha: &str, run_id: &str) -> BTreeMap<String, String> {
    [
        ("GITHUB_ACTIONS", "true".to_string()),
        ("GITHUB_REPOSITORY", REPO.to_string()),
        ("GITHUB_WORKFLOW_REF", WORKFLOW.to_string()),
        ("GITHUB_WORKFLOW", "fixture".to_string()),
        ("GITHUB_JOB", "test".to_string()),
        ("GITHUB_SHA", sha.to_string()),
        ("GITHUB_RUN_ID", run_id.to_string()),
        ("GITHUB_RUN_ATTEMPT", "1".to_string()),
        (
            "GITHUB_EVENT_PATH",
            temp.join("event.json").display().to_string(),
        ),
        ("RUNNER_TEMP", temp.display().to_string()),
        (
            "RUNNER_WORKSPACE",
            temp.join("work/repo").display().to_string(),
        ),
        ("RUNNER_OS", "Linux".to_string()),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect()
}

/// The job as the planner reads it from the committed workflow, under `env`.
fn planned(env: &BTreeMap<String, String>) -> JobSpec {
    let cx = GhCtx::from_parts(env.clone(), Value::Null);
    let parsed = workflow::parse(PATH, WORKFLOW_TEXT).expect("parse");
    workflow::job_spec(&parsed, &cx, "test", None)
}

fn traced_key(spec: &JobSpec) -> String {
    spec.steps
        .iter()
        .find_map(|step| match step {
            StepSpec::Traced { key, .. } => Some(key.clone()),
            _ => None,
        })
        .expect("a traced step")
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The planner's verdict on one record: `Ok` when it may skip the job.
fn judge(verifier: &Verifier<Jwks>, planned: &JobSpec, record: &JobRecord) -> Result<(), String> {
    verifier.check(planned, record).map_err(|(code, reason)| {
        assert_eq!(code, Code::Unattested, "{reason}");
        reason
    })
}

fn find<'a>(records: &'a [JobRecord], run: &str) -> &'a JobRecord {
    records
        .iter()
        .find(|record| record.run.as_deref() == Some(run))
        .unwrap_or_else(|| panic!("no record for run {run}"))
}

/// The verifier a planner builds against the fake GitHub's key set.
fn planner_for(base: &str) -> Verifier<Jwks> {
    Verifier::new(
        Policy::default_branch(REPO, REPO_ID, OWNER_ID, "main"),
        Jwks {
            url: format!("{base}/.well-known/jwks"),
        },
        crate::proof::now(),
        CEILING,
    )
}

/// The published key set with only the key for `kid` kept, as after a rotation.
fn jwks_with_only(kid: &str) -> Vec<u8> {
    let mut document: Value = serde_json::from_slice(JWKS).expect("fixture");
    let kept: Vec<Value> = document["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .filter(|key| key["kid"] == kid)
        .cloned()
        .collect();
    document["keys"] = Value::Array(kept);
    serde_json::to_vec(&document).expect("json")
}

#[test]
fn published_records_are_accepted_only_through_the_verifier() {
    let root = std::env::temp_dir().join(format!("stoop-attest-e2e-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let repo = Repo::new(&root);
    let github = Arc::new(Mutex::new(Github {
        claims: Value::Null,
        jwks: JWKS.to_vec(),
        failing: false,
    }));
    let base = serve(github.clone());
    std::env::set_var("GITHUB_API_URL", &base);
    std::env::set_var("GITHUB_SERVER_URL", &base);
    std::env::set_var("XDG_CACHE_HOME", root.join("cache"));
    let token_url = format!("{base}/token?api-version=2.0");
    let planned = planned(&runner_env(&root.join("runner-123"), &repo.sha, "123"));
    // The job file is keyed by the job key, not by a step key.
    let key = planned.key.clone().expect("job key");
    let sha = repo.sha.clone();
    let set_claims = |c: Value| github.lock().expect("state").claims = c;

    // Run 123 is the trusted publication: a push to the default branch, from the planned file.
    set_claims(claims(&sha, "123", "refs/heads/main", "push", WORKFLOW));
    repo.publish("123", Some(&token_url)).expect("publish 123");

    // Run 124: the job has no id-token permission. The step still succeeds.
    repo.publish("124", None)
        .expect("publish 124 without a token");

    // Run 125: the token endpoint refuses the request. The step still succeeds.
    github.lock().expect("state").failing = true;
    repo.publish("125", Some(&token_url))
        .expect("publish 125 with a failing token endpoint");
    github.lock().expect("state").failing = false;

    // Run 126: a valid token for a feature branch.
    set_claims(claims(&sha, "126", "refs/heads/feature", "push", WORKFLOW));
    repo.publish("126", Some(&token_url)).expect("publish 126");

    // Run 127: a pull request event.
    set_claims(claims(
        &sha,
        "127",
        "refs/heads/main",
        "pull_request",
        WORKFLOW,
    ));
    repo.publish("127", Some(&token_url)).expect("publish 127");

    // Run 128: the job ran in a called workflow that shares the planned job's id.
    let shared = "owner/repo/.github/workflows/shared.yml@refs/heads/main";
    set_claims(claims(&sha, "128", "refs/heads/main", "push", shared));
    repo.publish("128", Some(&token_url)).expect("publish 128");

    let verifier = planner_for(&base);
    let (_, records) = repo.read(&key);
    assert_eq!(records.len(), 6, "runs 123 to 128 are each kept");

    let trusted = find(&records, "123/1").clone();
    assert!(trusted.attest.is_some(), "run 123 must carry a token");
    assert_eq!(judge(&verifier, &planned, &trusted), Ok(()));

    // The same record without its token, or with one field changed, stays unattested.
    let mut stripped = trusted.clone();
    stripped.attest = None;
    assert_eq!(
        judge(&verifier, &planned, &stripped).unwrap_err(),
        NO_ATTESTATION
    );
    let mut edited = trusted.clone();
    edited.status = Some(RecordStatus::Failed);
    assert!(judge(&verifier, &planned, &edited)
        .unwrap_err()
        .contains("audience does not match"));

    let refusals = [
        ("124/1", NO_ATTESTATION),
        ("125/1", NO_ATTESTATION),
        ("126/1", "is not a trusted branch"),
        ("127/1", "may not publish job records"),
        ("128/1", "reusable workflow"),
    ];
    for (run, needle) in refusals {
        let reason = judge(&verifier, &planned, find(&records, run)).expect_err(run);
        assert!(reason.contains(needle), "{run}: {reason}");
    }

    // A writer replays run 123's token on a new record for run 129.
    let mut replay = trusted.clone();
    replay.run = Some("129/1".into());
    repo.forge(&key, replay);
    let (_, after_replay) = repo.read(&key);
    assert!(judge(&verifier, &planned, find(&after_replay, "129/1"))
        .unwrap_err()
        .contains("audience does not match"));

    // A writer pushes an edited copy of run 123 under run 131, keeping the token.
    let mut forged = trusted.clone();
    forged.run = Some("131/1".into());
    forged.status = Some(RecordStatus::Failed);
    forged.failed = Some("sh-cccccccccccccccccccc".into());
    repo.forge(&key, forged);
    let (_, after_edit) = repo.read(&key);
    assert!(judge(&verifier, &planned, find(&after_edit, "131/1"))
        .unwrap_err()
        .contains("audience does not match"));

    // Of everything on the remote, only the trusted record may skip the job.
    let accepted: Vec<String> = after_edit
        .iter()
        .filter(|record| judge(&verifier, &planned, record).is_ok())
        .filter_map(|record| record.run.clone())
        .collect();
    assert_eq!(accepted, vec!["123/1".to_string()]);

    // GitHub rotates away the key that signed run 123: the record stays unattested.
    github.lock().expect("state").jwks = jwks_with_only("test-key-2");
    let rotated = planner_for(&base);
    assert!(judge(&rotated, &planned, &trusted)
        .unwrap_err()
        .contains("no longer published"));

    for name in ENV {
        std::env::remove_var(name);
    }
}
