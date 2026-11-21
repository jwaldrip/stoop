//! Planner regressions using proof files captured by the real Linux recorder.
//! Regenerate with `STOOP_REGENERATE_RECORDER_FIXTURES=1 cargo test --test record_e2e
//! regenerate_planner_recorder_fixtures -- --ignored` on Linux.

use super::eval::{decide, PlanCtx, Prefilter};
use super::spec::{Code, JobSpec, RecordCheck, StepSpec};
use crate::gittree::GitTree;
use crate::input::Input;
use crate::job::{JobRecord, JobStore, RecordStatus, StepHow, StepRecord};
use crate::oid_attrs::OidBasis;
use crate::proof::{Proof, Store};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Accept;
impl RecordCheck for Accept {
    fn check(&self, _: &JobSpec, _: &JobRecord) -> Result<(), (Code, String)> {
        Ok(())
    }
}

fn git(root: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(root)
        .env("HOME", root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn put(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, value).unwrap();
}

struct Fixture {
    root: PathBuf,
    store: Store,
    jobs: JobStore,
    spec: JobSpec,
    proof_key: &'static str,
    created: u64,
}
impl Fixture {
    fn new(case: &str) -> Self {
        Self::build(case, false)
    }
    /// The case as the recorder writes it inside a git worktree, with git blob ids.
    fn with_blob_ids(case: &str) -> Self {
        Self::build(case, true)
    }
    fn build(case: &str, with_ids: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "stoop-recorded-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        put(&root, "in.txt", "one");
        match case {
            "sed" | "sed-exec" => put(&root, "config.txt", "foo\n"),
            "mkdir" => put(&root, "src/keep", "keep"),
            "rename" => put(&root, "d/file", "keep"),
            "eol" | "failed" => {}
            "chmod" => {
                put(&root, "s.sh", "echo hi\n");
                fs::set_permissions(root.join("s.sh"), fs::Permissions::from_mode(0o755)).unwrap();
            }
            "parent" => put(&root, "build/.keep", "keep"),
            "symlink" => {
                put(&root, "sub/inner/keep", "keep");
                std::os::unix::fs::symlink("sub/inner", root.join("link")).unwrap();
            }
            "proc" => put(&root, "config.txt", "old content"),
            "app" => {
                put(
                    &root,
                    "app/build.sh",
                    "#!/bin/sh\ncat input.txt >/dev/null\n",
                );
                put(&root, "app/input.txt", "app input");
                fs::set_permissions(root.join("app/build.sh"), fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
            _ => panic!("unknown case"),
        }
        git(&root, &["init", "-q"]);
        git(&root, &["add", "."]);
        git(
            &root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "base",
            ],
        );
        let proof_file = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/recorder")
            .join(case)
            .join("proof.json");
        let proof_key = if case == "sed-exec" { "sed-exec" } else { "t" };
        let store = Store::new(root.join("store"));
        store
            .import(proof_key, &fs::read(proof_file).unwrap())
            .unwrap();
        let proof = store.load(proof_key).remove(0);
        let proof = if with_ids {
            let patched = with_blob_ids(&root, proof);
            store.save(proof_key, patched.clone()).unwrap();
            patched
        } else {
            proof
        };
        let created = proof.created;
        let runner = match proof.provenance.as_ref().map(|p| p.arch.as_str()) {
            Some("aarch64") => "ubuntu-24.04-arm",
            _ => "ubuntu-latest",
        };
        let jobs = JobStore::new(root.join("store"));
        jobs.save(
            "job-test",
            JobRecord {
                created,
                started: created,
                status: Some(RecordStatus::Passed),
                failed: None,
                actions: BTreeMap::new(),
                commit: None,
                host: BTreeMap::new(),
                event_path: Some("/tmp/event.json".into()),
                run: Some("1/1".into()),
                steps: vec![StepRecord {
                    key: proof_key.into(),
                    proof: proof.digest(),
                    how: StepHow::Ran,
                }],
                attest: None,
                workflow_ref: None,
                job_workflow_ref: None,
            },
        )
        .unwrap();
        let spec = JobSpec {
            workflow: "ci".into(),
            path: "ci.yml".into(),
            job: "test".into(),
            leg: None,
            key: Some("job-test".into()),
            runs_on: serde_json::json!(runner),
            needs: vec![],
            if_text: None,
            steps: vec![StepSpec::Traced {
                index: 1,
                key: proof_key.into(),
                max_age: None,
            }],
            blocked: None,
            actions: vec![],
            images: vec![],
        };
        Self {
            root,
            store,
            jobs,
            spec,
            proof_key,
            created,
        }
    }
    fn commit(&self) {
        git(&self.root, &["add", "-A", "--", ".", ":(exclude)store"]);
        git(
            &self.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "change",
            ],
        );
    }
    fn decision(&self) -> super::spec::Decision {
        self.decision_mode(Prefilter::On)
    }
    fn decision_mode(&self, prefilter: Prefilter) -> super::spec::Decision {
        let mut tree = GitTree::load(&self.root, "HEAD").unwrap();
        decide(
            &self.spec,
            &mut PlanCtx {
                tree: &mut tree,
                proofs: &self.store,
                jobs: &self.jobs,
                check: &Accept,
                now: self.created + 1,
                max_age: 86400,
                github_vars: BTreeMap::from([("CI".into(), "true".into())]),
                salt: None,
                event_path: None,
                event: None,
                explain: false,
                prefilter,
            },
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// The change each real recording was made for, committed by the caller.
fn change(f: &Fixture, case: &str) {
    use std::os::unix::fs::PermissionsExt;
    match case {
        "sed" | "sed-exec" | "proc" => put(&f.root, "config.txt", "changed\n"),
        "mkdir" => {
            fs::remove_dir_all(f.root.join("src")).unwrap();
            put(&f.root, "src", "not a directory");
        }
        "eol" => put(&f.root, ".gitattributes", "in.txt text eol=crlf\n"),
        "chmod" => {
            fs::set_permissions(f.root.join("s.sh"), fs::Permissions::from_mode(0o644)).unwrap()
        }
        "parent" => fs::remove_file(f.root.join("build/.keep")).unwrap(),
        "failed" => put(&f.root, "missing/.keep", "keep"),
        "app" => put(&f.root, "app/input.txt", "changed"),
        _ => unreachable!(),
    }
}

const CASES: [&str; 9] = [
    "sed", "sed-exec", "mkdir", "eol", "chmod", "parent", "failed", "proc", "app",
];

fn expected_change(case: &str) -> Code {
    match case {
        "mkdir" | "app" => Code::InputChanged,
        "eol" => Code::Unplannable,
        _ => Code::PriorChanged,
    }
}

/// The fields that decide what a plan says. Evidence counters are compared separately.
fn plan_key(d: &super::spec::Decision) -> (bool, Code, String, Vec<(usize, String, String)>) {
    (
        d.skip,
        d.code.clone(),
        d.detail.clone(),
        d.mismatches.clone(),
    )
}

#[test]
fn real_recorded_proofs_reject_changed_input_and_prior_states() {
    for case in CASES {
        let f = Fixture::new(case);
        let control = f.decision();
        assert_eq!(control.code, Code::Proved, "{case}: {}", control.detail);
        change(&f, case);
        f.commit();
        let changed = f.decision();
        assert_eq!(
            changed.code,
            expected_change(case),
            "{case}: {}",
            changed.detail
        );
    }
}

/// The same recordings with git blob ids, as a recorder inside a worktree writes them. Every
/// prefilter mode must plan them the same way, before and after the change, and the shortcut must
/// decide at least one comparison on the control.
#[test]
fn real_recorded_proofs_plan_the_same_with_blob_ids_in_every_mode() {
    for case in CASES {
        let f = Fixture::with_blob_ids(case);
        let control = f.decision_mode(Prefilter::On);
        assert_eq!(control.code, Code::Proved, "{case}: {}", control.detail);
        let tagged = f.store.load(f.proof_key).iter().any(|p| {
            p.inputs
                .iter()
                .chain(p.priors.iter().flatten())
                .any(|input| input.oid.is_some())
        });
        let by_oid = control.evidence.as_ref().unwrap().by_oid;
        assert_eq!(by_oid > 0, tagged, "{case}: blob ids decided {by_oid}");
        for mode in [Prefilter::Off, Prefilter::Check] {
            assert_eq!(
                plan_key(&f.decision_mode(mode)),
                plan_key(&control),
                "{case}: {mode:?}"
            );
        }
        change(&f, case);
        f.commit();
        let changed = f.decision_mode(Prefilter::On);
        assert_eq!(
            changed.code,
            expected_change(case),
            "{case}: {}",
            changed.detail
        );
        for mode in [Prefilter::Off, Prefilter::Check] {
            assert_eq!(
                plan_key(&f.decision_mode(mode)),
                plan_key(&changed),
                "{case}: {mode:?}"
            );
        }
    }
}

/// The proof a recorder inside a worktree writes: every in-repository regular file input and
/// prior gets its git blob id and a clean basis, but only where the recorded content id hashes
/// the file's committed bytes. Anything else keeps no id, as before.
fn with_blob_ids(root: &Path, mut proof: Proof) -> Proof {
    tag_blob_ids(root, &mut proof.inputs);
    if let Some(priors) = proof.priors.as_mut() {
        tag_blob_ids(root, priors);
    }
    proof
}

fn tag_blob_ids(root: &Path, inputs: &mut [Input]) {
    for input in inputs {
        let exec = input.id.starts_with("x:");
        if !(exec || input.id.starts_with("f:")) {
            continue;
        }
        let object = format!("HEAD:{}", input.path);
        let object = object.as_str();
        let Some(bytes) = git_bytes(root, &["cat-file", "blob", object]) else {
            continue;
        };
        let hash = blake3::hash(&bytes).to_hex().to_string();
        if input.id != crate::input::file_id(exec, &hash) {
            continue;
        }
        let Some(oid) = git_bytes(root, &["rev-parse", object]) else {
            continue;
        };
        input.oid = Some(format!("sha1:{}", String::from_utf8_lossy(&oid).trim()));
        input.oid_basis = Some(OidBasis {
            text: "unspecified".into(),
            eol: "unspecified".into(),
            filter: "unspecified".into(),
            ident: "unspecified".into(),
            working_tree_encoding: "unspecified".into(),
            export_subst: "unspecified".into(),
            crlf: "unspecified".into(),
            autocrlf: "unset".into(),
        });
    }
}

fn git_bytes(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .current_dir(root)
        .env("HOME", root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(output.stdout)
}

#[test]
fn real_recorded_directory_rename_and_symlink_write_are_unplannable() {
    for case in ["rename", "symlink"] {
        let f = Fixture::new(case);
        let result = f.decision();
        assert_eq!(result.code, Code::Unplannable, "{case}: {}", result.detail);
    }
}

/// The single-tracee `exec sed -i` recording must carry the promoted input that the shell-wrapped
/// sed recording lacks: `config.txt` is an input equal to its prior. Finding P2-6.
#[test]
fn single_tracee_sed_records_the_promoted_config_input() {
    let f = Fixture::new("sed-exec");
    let proof = f.store.load(f.proof_key).remove(0);
    let prior = proof
        .priors
        .as_ref()
        .and_then(|priors| priors.iter().find(|input| input.path == "config.txt"))
        .expect("config.txt prior");
    let input = proof
        .inputs
        .iter()
        .find(|input| input.path == "config.txt")
        .expect("config.txt promoted input");
    assert_eq!(input.id, prior.id);
}
