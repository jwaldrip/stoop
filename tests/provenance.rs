//! Proof portability must never cross incompatible tracing platforms.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
#[path = "../src/trace/version.rs"]
mod tracer_version;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
const SCRIPT: &str = "printf x >> marker; exit 7";

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "stoop-platform-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(dir.join(".git")).unwrap();
        Self(fs::canonicalize(dir).unwrap())
    }

    fn proof(&self, key: &str, provenance: Option<serde_json::Value>) -> PathBuf {
        let dir = self.0.join(".stoop/proofs");
        fs::create_dir_all(&dir).unwrap();
        let mut proof = serde_json::json!({
            "created": 4_000_000_000u64,
            "argv": ["sh", "-c", SCRIPT],
            "cwd": "",
            "scope": null,
            "env": {"PATH": blake3::hash(b"/usr/bin:/bin").to_hex().to_string()},
            "inputs": [],
            "outputs": [],
            "probes": {}
        });
        let version = if provenance.is_some() { 2 } else { 1 };
        if let Some(provenance) = provenance {
            proof["provenance"] = provenance;
        }
        let file = dir.join(format!("{key}.json"));
        fs::write(
            &file,
            serde_json::to_vec(&serde_json::json!({"v": version, "key": key, "proofs": [proof]}))
                .unwrap(),
        )
        .unwrap();
        file
    }

    fn stoop(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn current() -> serde_json::Value {
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "tracer": "ptrace-seccomp",
        "version": tracer_version::TRACER_VERSION
    })
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn explanation(w: &Workspace) -> Output {
    w.stoop(&["explain", "--key", "spike", "--", "sh", "-c", SCRIPT])
}

fn run(w: &Workspace) -> Output {
    w.stoop(&["run", "--key", "spike", "--", "sh", "-c", SCRIPT])
}

fn assert_cold(provenance: Option<serde_json::Value>, linux_reason: &str) {
    let w = Workspace::new();
    w.proof("spike", provenance);
    let out = explanation(&w);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let reason = if cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )) {
        linux_reason
    } else {
        "not traced"
    };
    assert!(stderr(&out).contains(reason), "{}", stderr(&out));
    assert!(
        !w.0.join("marker").exists(),
        "explain must not run the command"
    );
    let result = run(&w);
    assert_eq!(result.status.code(), Some(7), "{}", stderr(&result));
    assert_eq!(fs::read_to_string(w.0.join("marker")).unwrap(), "x");
    assert!(
        !stderr(&result).contains("stoop: skip"),
        "{}",
        stderr(&result)
    );
}

#[test]
fn a_different_os_cannot_use_the_proof() {
    let mut p = current();
    p["os"] = if std::env::consts::OS == "linux" {
        "macos"
    } else {
        "linux"
    }
    .into();
    assert_cold(Some(p), "provenance changed");
}

#[test]
fn a_different_architecture_cannot_use_the_proof() {
    let mut p = current();
    p["arch"] = if std::env::consts::ARCH == "x86_64" {
        "aarch64"
    } else {
        "x86_64"
    }
    .into();
    assert_cold(Some(p), "provenance changed");
}

#[test]
fn a_different_tracer_or_version_cannot_use_the_proof() {
    let mut p = current();
    p["tracer"] = "another-tracer".into();
    assert_cold(Some(p), "provenance changed");
    let mut p = current();
    p["version"] = (tracer_version::TRACER_VERSION + 1).into();
    assert_cold(Some(p), "provenance changed");
}

#[test]
fn legacy_proofs_without_provenance_are_cold() {
    assert_cold(None, "provenance missing");
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn no_tracer_runs_once_even_with_a_matching_proof() {
    let w = Workspace::new();
    let proof = w.proof("spike", Some(current()));
    let before = fs::read(&proof).unwrap();
    let result = run(&w);
    assert_eq!(result.status.code(), Some(7), "{}", stderr(&result));
    assert_eq!(fs::read_to_string(w.0.join("marker")).unwrap(), "x");
    assert!(
        stderr(&result).contains("not traced"),
        "{}",
        stderr(&result)
    );
    assert_eq!(
        fs::read(proof).unwrap(),
        before,
        "unsupported hosts must not record"
    );
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn no_tracer_explains_that_it_would_run() {
    let w = Workspace::new();
    w.proof("spike", Some(current()));
    let result = explanation(&w);
    assert_eq!(result.status.code(), Some(1), "{}", stderr(&result));
    assert!(
        stderr(&result).contains("not traced"),
        "{}",
        stderr(&result)
    );
    assert!(!w.0.join("marker").exists());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn matching_platform_still_uses_a_proof() {
    let w = Workspace::new();
    w.proof("spike", Some(current()));
    let out = explanation(&w);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("stoop: skip"), "{}", stderr(&out));
    assert!(!w.0.join("marker").exists());
}

#[test]
fn ls_identifies_platforms_and_old_proofs() {
    let w = Workspace::new();
    w.proof("current", Some(current()));
    w.proof("legacy", None);
    let out = w.stoop(&["ls"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains(std::env::consts::OS), "{text}");
    assert!(text.contains(std::env::consts::ARCH), "{text}");
    assert!(text.contains("ptrace-seccomp"), "{text}");
    assert!(text.contains("unknown"), "{text}");
}
