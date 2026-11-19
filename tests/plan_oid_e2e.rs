#![cfg(unix)]
//! `stoop plan --prefilter` at the command line: other values are a usage error (exit 2), and
//! the three modes give the same plan for a repository without records.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

const WORKFLOW: &str = "name: fixture\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: cat a.txt > /dev/null\n";

struct Repo(PathBuf);

impl Repo {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-prefilter-e2e-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), WORKFLOW).unwrap();
        fs::write(root.join("a.txt"), "a\n").unwrap();
        for args in [
            &["init", "-q"][..],
            &["add", "."][..],
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-qm",
                "fixture",
            ][..],
        ] {
            assert!(Command::new("git")
                .current_dir(&root)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(args)
                .status()
                .unwrap()
                .success());
        }
        Self(root)
    }

    fn plan(&self, args: &[&str]) -> std::process::Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .current_dir(&self.0)
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_MAX_AGE")
            .env_remove("STOOP_FULL")
            .env("GITHUB_JOB", "stoop-plan")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("GITHUB_OUTPUT")
            .env_remove("GITHUB_STEP_SUMMARY")
            .env_remove("GITHUB_EVENT_PATH")
            .env_remove("STOOP_STORE")
            .env_remove("STOOP_ENV_SALT")
            .args(["plan", "--workflow", ".github/workflows/ci.yml"])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn prefilter_rejects_other_values_with_usage_exit_two() {
    let repo = Repo::new();
    for bad in ["bogus", "ON", ""] {
        let output = repo.plan(&["--prefilter", bad, "--format", "json"]);
        assert_eq!(output.status.code(), Some(2), "{bad:?}");
    }
}

#[test]
fn every_prefilter_mode_gives_the_same_plan_without_records() {
    let repo = Repo::new();
    let plans: Vec<serde_json::Value> = ["on", "off", "check"]
        .into_iter()
        .map(|mode| {
            let output = repo.plan(&["--prefilter", mode, "--format", "json"]);
            assert!(
                output.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            serde_json::from_slice(&output.stdout).unwrap()
        })
        .collect();
    assert_eq!(plans[0]["jobs"][0]["code"], "no-record");
    assert_eq!(plans[0], plans[1]);
    assert_eq!(plans[0], plans[2]);
}
