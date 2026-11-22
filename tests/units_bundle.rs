//! The first whole-command proof records a suite roster, but no unit proofs.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    runner: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(root.join("tests/a.t"), "a\n").unwrap();
        fs::write(root.join("tests/b.t"), "b\n").unwrap();
        let runner = root.join("runner");
        fs::write(
            &runner,
            "#!/bin/sh\nprintf 'suite-run\\n'\nif [ -n \"${MAKE_UNIT:-}\" ]; then : > \"$MAKE_UNIT\"; fi\n[ \"${FAIL:-0}\" != 1 ]\n",
        )
        .unwrap();
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, runner }
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .current_dir(cwd)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("STOOP_LEARN_VOLATILE", "0")
            .env("STOOP_FULL", "1");
        command
    }

    fn run_at(
        &self,
        cwd: &Path,
        options: &[&str],
        hook: Option<&str>,
        env: &[(&str, &str)],
    ) -> Output {
        let mut command = self.command(cwd);
        command.args(["run", "--quiet", "--root"]).arg(&self.root);
        command.args(options).arg("--").arg(&self.runner);
        if let Some(hook) = hook {
            command.arg(hook);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn run(&self, options: &[&str], hook: Option<&str>, env: &[(&str, &str)]) -> Output {
        self.run_at(&self.root, options, hook, env)
    }

    fn verbose_run(&self) -> Output {
        self.command(&self.root)
            .args(["run", "--root"])
            .arg(&self.root)
            .arg("--")
            .arg(&self.runner)
            .arg("{changed:*.t}")
            .output()
            .unwrap()
    }

    fn cli(&self, command: &str, args: &[&str]) -> Output {
        self.command(&self.root)
            .arg(command)
            .args(args)
            .output()
            .unwrap()
    }

    fn bundles(&self) -> Vec<PathBuf> {
        let dir = self.root.join(".stoop/units/v1");
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut paths: Vec<_> = entries
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension() == Some(OsStr::new("json")))
            .collect();
        paths.sort();
        paths
    }

    fn one_bundle(&self) -> (PathBuf, Value) {
        let paths = self.bundles();
        assert_eq!(paths.len(), 1, "expected a single suite bundle: {paths:?}");
        let value = serde_json::from_slice(&fs::read(&paths[0]).unwrap()).unwrap();
        (paths[0].clone(), value)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn success(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn suite_id(scope: &str, cwd: &str, argv: &[&OsStr], label: &str) -> String {
    let mut hash = blake3::Hasher::new_derive_key("stoop suite id v1");
    for field in [b"hook".as_slice(), scope.as_bytes(), cwd.as_bytes()] {
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    for word in argv {
        let field = word.as_bytes();
        hash.update(&(field.len() as u64).to_le_bytes());
        hash.update(field);
    }
    hash.update(&(label.len() as u64).to_le_bytes());
    hash.update(label.as_bytes());
    hash.finalize().to_hex()[..32].to_string()
}

#[derive(Deserialize, Serialize)]
struct SavedInput {
    path: String,
    id: String,
    oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oid_basis: Option<Value>,
}

#[derive(Deserialize, Serialize)]
struct SavedProvenance {
    os: String,
    arch: String,
    tracer: String,
    version: u32,
}

#[derive(Deserialize)]
struct SavedProof {
    inputs: Vec<SavedInput>,
    outputs: Vec<SavedInput>,
    removed: Vec<String>,
    env: BTreeMap<String, String>,
    probes: BTreeMap<String, String>,
    env_excluded: Vec<String>,
    ignore: Option<Vec<String>>,
    priors: Option<Vec<SavedInput>>,
    unplannable: Vec<String>,
    cwd: Option<String>,
    scope: Option<String>,
    provenance: Option<SavedProvenance>,
}

fn digest_saved_proof(path: &Path) -> String {
    let file: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let proof: SavedProof = serde_json::from_value(file["proofs"][0].clone()).unwrap();
    let bytes = serde_json::to_vec(&(
        proof.inputs,
        proof.outputs,
        proof.removed,
        proof.env,
        proof.probes,
        proof.env_excluded,
        proof.ignore,
        proof.priors,
        proof.unplannable,
        proof.cwd,
        proof.scope,
        proof.provenance,
    ))
    .unwrap();
    format!("p-{}", &blake3::hash(&bytes).to_hex()[..32])
}

#[test]
fn a_passing_hook_records_the_roster_and_saved_whole_proof_digest() {
    let f = Fixture::new();
    let out = f.run(&[], Some("{changed:*.t}"), &[]);
    success(&out);
    let (path, bundle) = f.one_bundle();
    let id = path.file_stem().unwrap().to_str().unwrap();
    assert_eq!(
        id,
        suite_id(
            "",
            "",
            &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
            ""
        )
    );
    assert_eq!(bundle["v"], 1);
    assert_eq!(bundle["generation"], 1);
    assert_eq!(bundle["suite"], id);
    assert_eq!(bundle["roster"]["filter"], "*.t");
    assert_eq!(
        bundle["roster"]["units"],
        serde_json::json!(["tests/a.t", "tests/b.t"])
    );
    assert!(bundle["roster"].get("inputs").is_none());
    assert_eq!(bundle["table"], serde_json::json!([]));
    assert_eq!(bundle["units"], serde_json::json!({}));
    assert!(bundle.get("state").is_some());
    assert!(bundle.get("residue").is_some());
    let key = bundle["whole_key"].as_str().unwrap();
    let proof = f.root.join(".stoop/proofs").join(format!("{key}.json"));
    assert_eq!(bundle["whole"], digest_saved_proof(&proof));
}

#[test]
fn explain_never_creates_a_suite_bundle_or_lock() {
    let f = Fixture::new();
    let out = f
        .command(&f.root)
        .args(["explain", "--root"])
        .arg(&f.root)
        .arg("--")
        .arg(&f.runner)
        .arg("{changed:*.t}")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!f.root.join(".stoop/units").exists());
}

#[test]
fn failed_hook_never_creates_a_suite_bundle_or_lock() {
    let f = Fixture::new();
    let out = f.run(&[], Some("{changed:*.t}"), &[("FAIL", "1")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!f.root.join(".stoop/units").exists());
}

#[test]
fn plain_commands_never_create_a_suite_bundle_or_lock() {
    let f = Fixture::new();
    success(&f.run(&[], None, &[]));
    assert!(!f.root.join(".stoop/units").exists());
}

#[test]
fn zero_units_never_create_a_suite_bundle_or_lock() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.none}"), &[]));
    assert!(!f.root.join(".stoop/units").exists());
}

#[test]
fn ineligible_hooks_never_create_a_suite_bundle_or_lock() {
    for options in [
        vec!["--no-record"],
        vec!["--allow-network"],
        vec!["--ignore", "irrelevant"],
        vec!["--ignore-env", "IRRELEVANT"],
        vec!["--probe", "printf ok"],
        vec!["--literal"],
    ] {
        let f = Fixture::new();
        success(&f.run(&options, Some("{changed:*.t}"), &[]));
        assert!(!f.root.join(".stoop/units").exists(), "options={options:?}");
    }
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[("STOOP_OFF", "1")]));
    assert!(!f.root.join(".stoop/units").exists());
}

#[test]
fn the_roster_is_captured_before_the_command_runs() {
    let f = Fixture::new();
    let path = f.root.join("tests/new.t");
    success(&f.run(
        &[],
        Some("{changed:*.t}"),
        &[("MAKE_UNIT", path.to_str().unwrap())],
    ));
    assert!(path.exists());
    let (_, bundle) = f.one_bundle();
    assert_eq!(
        bundle["roster"]["units"],
        serde_json::json!(["tests/a.t", "tests/b.t"])
    );
}

#[test]
fn ls_lists_the_suite_without_argv_text() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (_, bundle) = f.one_bundle();
    let id = bundle["suite"].as_str().unwrap();
    let out = f.cli("ls", &[]);
    success(&out);
    let stdout = String::from_utf8(out.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.starts_with("suite\t") && line.contains(id))
        .unwrap();
    assert!(line.contains("dir ."), "{line}");
    assert!(line.contains("ready"), "{line}");
    assert!(line.contains("linux"), "{line}");
    assert!(line.contains("2 units"), "{line}");
    assert!(line.contains("0 proven"), "{line}");
    assert!(!line.contains("runner"), "{line}");
    assert!(!line.contains("{changed"), "{line}");
}

#[test]
fn forget_units_removes_the_bundle_and_its_lock_but_not_the_whole_proof() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, bundle) = f.one_bundle();
    let id = bundle["suite"].as_str().unwrap();
    let proof = f
        .root
        .join(".stoop/proofs")
        .join(format!("{}.json", bundle["whole_key"].as_str().unwrap()));
    let lock = path.with_extension("lock");
    assert!(lock.exists());
    success(&f.cli("forget", &["--units", id]));
    assert!(!path.exists());
    assert!(!lock.exists());
    assert!(proof.exists());
}

#[test]
fn a_busy_suite_lock_leaves_the_bundle_and_output_unchanged() {
    let f = Fixture::new();
    let first = f.run(&[], Some("{changed:*.t}"), &[]);
    success(&first);
    let (path, _) = f.one_bundle();
    let before = fs::read(&path).unwrap();
    let lock = File::options()
        .read(true)
        .write(true)
        .open(path.with_extension("lock"))
        .unwrap();
    lock.lock().unwrap();
    let new_unit = f.root.join("tests/new.t");
    let busy = f.run(
        &[],
        Some("{changed:*.t}"),
        &[("MAKE_UNIT", new_unit.to_str().unwrap())],
    );
    assert_eq!(busy.status.code(), first.status.code());
    assert_eq!(busy.stdout, first.stdout);
    assert_eq!(busy.stderr, first.stderr);
    assert!(new_unit.exists());
    assert_eq!(fs::read(path).unwrap(), before);
}

#[test]
fn a_newer_bundle_version_is_never_overwritten_and_ls_identifies_it() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, mut bundle) = f.one_bundle();
    bundle["v"] = 2.into();
    let newer = serde_json::to_vec(&bundle).unwrap();
    fs::write(&path, &newer).unwrap();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    assert_eq!(fs::read(&path).unwrap(), newer);
    let listing = f.cli("ls", &[]);
    success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("newer format"));
}

#[test]
fn corrupt_bundle_is_reported_once_by_ls_and_replaced_silently_by_a_run() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let baseline = f.verbose_run();
    success(&baseline);
    let (path, _) = f.one_bundle();
    let id = path.file_stem().unwrap().to_str().unwrap();
    fs::write(&path, b"not json").unwrap();
    let listing = f.cli("ls", &[]);
    success(&listing);
    let warning = format!("stoop: ignoring a corrupt suite bundle: {id}");
    let stderr = String::from_utf8(listing.stderr).unwrap();
    assert_eq!(
        stderr.lines().filter(|line| *line == warning).count(),
        1,
        "{stderr}"
    );
    let stdout = String::from_utf8(listing.stdout).unwrap();
    assert!(stdout
        .lines()
        .any(|line| line.contains(id) && line.contains("unreadable")));
    let out = f.verbose_run();
    success(&out);
    assert_eq!(out.stdout, baseline.stdout);
    assert_eq!(out.stderr, baseline.stderr);
    let repaired: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(repaired["suite"], id);
    assert_eq!(repaired["v"], 1);
}

#[test]
fn suite_id_binds_cwd_scope_label_and_original_arguments() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (_, first) = f.one_bundle();
    let id = first["suite"].as_str().unwrap().to_owned();
    success(&f.run(&["--key", "named"], Some("{changed:*.t}"), &[]));
    fs::create_dir(f.root.join("sub")).unwrap();
    success(&f.run_at(&f.root.join("sub"), &[], Some("{changed:*.t}"), &[]));
    success(&f.run(&[], Some("{changed:tests/*.t}"), &[]));
    let ids: Vec<_> = f
        .bundles()
        .into_iter()
        .map(|path| path.file_stem().unwrap().to_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 4, "{ids:?}");
    assert!(ids.contains(&id));
    assert!(ids.contains(&suite_id(
        "",
        "",
        &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
        "named"
    )));
    assert!(ids.contains(&suite_id(
        "",
        "sub",
        &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
        ""
    )));
    let store = f.root.join("other-store");
    success(&f.run(
        &["--store", store.to_str().unwrap()],
        Some("{changed:*.t}"),
        &[],
    ));
    let path = fs::read_dir(store.join("units/v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension() == Some(OsStr::new("json")))
        .unwrap();
    let other: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let scope = other["origin"]["scope"].as_str().unwrap();
    assert_ne!(other["suite"], id);
    assert_eq!(
        other["suite"],
        suite_id(
            scope,
            "",
            &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
            ""
        )
    );
}
