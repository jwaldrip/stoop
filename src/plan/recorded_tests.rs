//! Planner regressions using proof files captured by the real Linux recorder.
//! Regenerate with `STOOP_REGENERATE_RECORDER_FIXTURES=1 cargo test --test record_e2e
//! regenerate_planner_recorder_fixtures -- --ignored` on Linux.

use super::eval::{decide, PlanCtx};
use super::spec::{Code, JobSpec, RecordCheck, StepSpec};
use crate::gittree::GitTree;
use crate::job::{JobRecord, JobStore, RecordStatus, StepHow, StepRecord};
use crate::proof::Store;
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
    created: u64,
}
impl Fixture {
    fn new(case: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!(
            "stoop-recorded-plan-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        put(&root, "in.txt", "one");
        match case {
            "sed" => put(&root, "config.txt", "foo\n"),
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
        let store = Store::new(root.join("store"));
        store.import("t", &fs::read(proof_file).unwrap()).unwrap();
        let proof = store.load("t").remove(0);
        let created = proof.created;
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
                    key: "t".into(),
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
            runs_on: serde_json::Value::Null,
            needs: vec![],
            if_text: None,
            steps: vec![StepSpec::Traced {
                index: 1,
                key: "t".into(),
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
            },
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn real_recorded_proofs_reject_changed_input_and_prior_states() {
    use std::os::unix::fs::PermissionsExt;
    for case in ["sed", "mkdir", "eol", "chmod", "parent", "failed", "proc"] {
        let f = Fixture::new(case);
        let control = f.decision();
        assert_eq!(control.code, Code::Proved, "{case}: {}", control.detail);
        match case {
            "sed" | "proc" => put(&f.root, "config.txt", "changed\n"),
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
            _ => unreachable!(),
        }
        f.commit();
        let changed = f.decision();
        let expected = match case {
            "mkdir" => Code::InputChanged,
            "eol" => Code::Unplannable,
            _ => Code::PriorChanged,
        };
        assert_eq!(changed.code, expected, "{case}: {}", changed.detail);
    }
}

#[test]
fn real_recorded_directory_rename_and_symlink_write_are_unplannable() {
    for case in ["rename", "symlink"] {
        let f = Fixture::new(case);
        let result = f.decision();
        assert_eq!(result.code, Code::Unplannable, "{case}: {}", result.detail);
    }
}
