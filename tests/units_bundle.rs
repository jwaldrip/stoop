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
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
        let _ = fs::remove_dir_all(self.outside());
        let _ = fs::remove_dir_all(self.root.with_extension("stray"));
    }
}

fn success(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn suite_id(scope: Option<&str>, cwd: &str, argv: &[&OsStr], label: Option<&str>) -> String {
    fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    fn optional(hash: &mut blake3::Hasher, value: Option<&str>) {
        match value {
            None => {
                hash.update(&[0]);
            }
            Some(value) => {
                hash.update(&[1]);
                field(hash, value.as_bytes());
            }
        }
    }
    let mut hash = blake3::Hasher::new_derive_key("stoop suite id v1");
    field(&mut hash, b"hook");
    optional(&mut hash, scope);
    field(&mut hash, cwd.as_bytes());
    for word in argv {
        field(&mut hash, word.as_bytes());
    }
    optional(&mut hash, label);
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

fn only_file(dir: &Path) -> PathBuf {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension() == Some(OsStr::new("json")))
        .collect();
    assert_eq!(files.len(), 1, "{files:?}");
    files.remove(0)
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
            None,
            "",
            &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
            None,
        )
    );
    assert_eq!(bundle["v"], 1);
    assert_eq!(bundle["generation"], 1);
    assert_eq!(bundle["suite"], id);
    assert_eq!(
        bundle["roster"]["units"],
        serde_json::json!(["tests/a.t", "tests/b.t"])
    );
    assert!(bundle["roster"].get("inputs").is_none());
    assert_eq!(bundle["table"], serde_json::json!([]));
    assert_eq!(bundle["units"], serde_json::json!({}));
    assert!(bundle.get("state").is_some());
    assert!(bundle.get("residue").is_some());
    assert!(bundle["roster"].get("filter").is_none());
    assert!(bundle["origin"].get("argv").is_none());
    assert!(bundle["origin"].get("label").is_none());
    let proof = only_file(&f.root.join(".stoop/proofs"));
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
    let proof = only_file(&f.root.join(".stoop/proofs"));
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
    bundle["generation"] = "a future schema".into();
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
        None,
        "",
        &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
        Some("named")
    )));
    assert!(ids.contains(&suite_id(
        None,
        "sub",
        &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
        None
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
            Some(scope),
            "",
            &[f.runner.as_os_str(), OsStr::new("{changed:*.t}")],
            None,
        )
    );
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let key = path.strip_prefix(base).unwrap().to_path_buf();
            let kind = entry.file_type().unwrap();
            if kind.is_symlink() {
                let target = fs::read_link(&path).unwrap();
                out.insert(key, target.as_os_str().as_bytes().to_vec());
            } else if kind.is_dir() {
                out.insert(key, Vec::new());
                walk(base, &path, out);
            } else {
                out.insert(key, fs::read(&path).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

type Observed = (
    BTreeMap<PathBuf, Vec<u8>>,
    BTreeMap<PathBuf, Vec<u8>>,
    Option<Vec<u8>>,
);

fn observe(f: &Fixture, outside: &Path, units: &Path, id: &str) -> Observed {
    let bundle = f.root.join(".stoop/units/v1").join(format!("{id}.json"));
    (snapshot(outside), snapshot(units), fs::read(bundle).ok())
}

fn symlink_case(component: &str, action: &str) {
    use std::os::unix::fs::symlink;

    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (bundle, value) = f.one_bundle();
    let id = value["suite"].as_str().unwrap().to_owned();
    // A roster that differs from the stored one makes any write through the link visible.
    fs::write(f.root.join("tests/c.t"), "c\n").unwrap();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let units = f.root.join(".stoop/units");
    let (link, target) = match component {
        "units" => (units.clone(), outside.join("units")),
        "version" => (units.join("v1"), outside.join("v1")),
        "lock" => (bundle.with_extension("lock"), outside.join("lock")),
        "bundle" => (bundle.clone(), outside.join("bundle.json")),
        _ => unreachable!("unknown component {component}"),
    };
    fs::rename(&link, &target).unwrap();
    symlink(&target, &link).unwrap();
    let before = observe(&f, &outside, &units, &id);
    match action {
        "run" => {
            let out = f.run(&[], Some("{changed:*.t}"), &[]);
            success(&out);
            assert!(
                out.stderr.is_empty(),
                "{component}: run printed {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        "ls" => {
            let out = f.cli("ls", &[]);
            success(&out);
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(text.contains("unreadable"), "{component}: {text}");
        }
        "forget" => {
            let out = f.cli("forget", &["--units", id.as_str()]);
            assert!(!out.status.success(), "{component}: forget followed a link");
            assert!(!out.stderr.is_empty(), "{component}: forget gave no reason");
        }
        _ => unreachable!("unknown action {action}"),
    }
    let still_link = fs::symlink_metadata(&link).is_ok_and(|meta| meta.file_type().is_symlink());
    assert!(still_link, "{component}: {action} replaced the link");
    assert_eq!(
        observe(&f, &outside, &units, &id),
        before,
        "{component}: {action} changed a file through the link"
    );
}

#[test]
fn a_symlinked_units_directory_is_never_followed() {
    for action in ["run", "ls", "forget"] {
        symlink_case("units", action);
    }
}

#[test]
fn a_symlinked_version_directory_is_never_followed() {
    for action in ["run", "ls", "forget"] {
        symlink_case("version", action);
    }
}

#[test]
fn a_symlinked_lock_file_is_never_followed() {
    for action in ["run", "ls", "forget"] {
        symlink_case("lock", action);
    }
}

#[test]
fn a_symlinked_bundle_file_is_never_followed() {
    for action in ["run", "ls", "forget"] {
        symlink_case("bundle", action);
    }
}

fn assert_tree_omits(path: &Path, secret: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            assert_tree_omits(&entry.path(), secret);
        } else {
            let bytes = fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(secret.len()).any(|window| window == secret));
        }
    }
}

#[test]
fn argument_text_is_not_persisted_under_the_suite_store() {
    let f = Fixture::new();
    let secret = "W5A-SENTINEL-argument-9f2c";
    let out = f
        .command(&f.root)
        .args(["run", "--quiet", "--root"])
        .arg(&f.root)
        .arg("--")
        .arg(&f.runner)
        .arg(secret)
        .arg("{changed:*.t}")
        .output()
        .unwrap();
    success(&out);
    f.one_bundle();
    assert_tree_omits(&f.root.join(".stoop/units"), secret.as_bytes());
    let listing = f.cli("ls", &[]);
    success(&listing);
    assert!(!String::from_utf8_lossy(&listing.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&listing.stderr).contains(secret));
}

#[test]
fn units_flag_outside_forget_is_refused_before_anything_runs() {
    let f = Fixture::new();
    let marker = f.root.join("ran");
    let out = f
        .command(&f.root)
        .args(["run", "--units", "--", "sh", "-c"])
        .arg(format!("touch '{}'", marker.display()))
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!marker.exists());
    let listing = f.command(&f.root).args(["ls", "--units"]).output().unwrap();
    assert_eq!(listing.status.code(), Some(2));
}

#[test]
fn a_bundle_that_cannot_be_read_is_never_replaced() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, _) = f.one_bundle();
    let before = fs::read(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    let listing = f.cli("ls", &[]);
    success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("unreadable"));
    fs::write(f.root.join("tests/c.t"), "c\n").unwrap();
    let out = f.run(&[], Some("{changed:*.t}"), &[]);
    success(&out);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn an_explicit_empty_key_has_its_own_suite() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    success(&f.run(&["--key", ""], Some("{changed:*.t}"), &[]));
    assert_eq!(f.bundles().len(), 2);
}

#[test]
fn duplicate_unit_keys_make_a_bundle_unreadable() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, _) = f.one_bundle();
    let original = fs::read_to_string(&path).unwrap();
    assert_eq!(original.matches("\"units\":{}").count(), 1, "{original}");
    let duplicated = original.replace(
        "\"units\":{}",
        "\"units\":{\"tests/a.t\":[],\"tests/a.t\":[]}",
    );
    fs::write(&path, duplicated).unwrap();
    let listing = f.cli("ls", &[]);
    success(&listing);
    assert!(String::from_utf8_lossy(&listing.stdout).contains("unreadable"));
    let warnings = String::from_utf8_lossy(&listing.stderr)
        .matches("ignoring a corrupt suite bundle")
        .count();
    assert_eq!(warnings, 1);
}

impl Fixture {
    /// Where a symlink test points its link. It sits beside the repository, never inside it.
    fn outside(&self) -> PathBuf {
        self.root.with_extension("outside")
    }

    /// The `stoop run` command for the fixture, left open for the caller to adjust.
    fn run_command(&self, options: &[&str], hook: Option<&str>, env: &[(&str, &str)]) -> Command {
        let mut command = self.command(&self.root);
        command.args(["run", "--quiet", "--root"]).arg(&self.root);
        command.args(options).arg("--").arg(&self.runner);
        if let Some(hook) = hook {
            command.arg(hook);
        }
        for (name, value) in env {
            command.env(name, value);
        }
        command
    }
}

/// The arguments stoop's unit inventory passes to Git. Each probe also passes its `-C` and `-c`
/// options first, so a logged line matches by its end.
const INVENTORY: [&str; 2] = [
    "ls-files -z --cached --others --exclude-standard",
    "ls-files -z --others --ignored --exclude-standard --directory",
];

/// A directory holding a `git` that logs its arguments to `$STOOP_TEST_GIT_LOG`, then runs the
/// real one. Returns the `PATH` that finds it first.
fn git_shim(dir: &Path) -> String {
    fs::create_dir_all(dir).unwrap();
    let shim = dir.join("git");
    fs::write(
        &shim,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$STOOP_TEST_GIT_LOG\"\nexec /usr/bin/git \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    format!("{}:/usr/bin:/bin", dir.display())
}

fn identity(path: &Path) -> (u64, u64) {
    let meta = fs::metadata(path).unwrap();
    (meta.dev(), meta.ino())
}

fn make_fifo(path: &Path) {
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success(), "mkfifo failed");
}

/// Runs a command to completion, and panics if it is still running after `limit`. A lock that
/// blocked the run would otherwise hang the suite.
fn output_within(command: &mut Command, limit: Duration) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + limit;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("the command was still running after {limit:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Records one suite, then replaces its lock with what `make` creates. Returns the bundle path
/// and the suite ID.
fn suite_with_lock(f: &Fixture, make: impl FnOnce(&Path)) -> (PathBuf, String) {
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, bundle) = f.one_bundle();
    let id = bundle["suite"].as_str().unwrap().to_owned();
    let lock = path.with_extension("lock");
    fs::remove_file(&lock).unwrap();
    make(&lock);
    (path, id)
}

#[test]
fn an_implicit_store_that_is_a_link_is_never_written() {
    let f = Fixture::new();
    let outside = f.outside();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, f.root.join(".stoop")).unwrap();
    // The run is unaffected: the command runs and suite bookkeeping is skipped.
    let out = f.run(&[], Some("{changed:*.t}"), &[]);
    success(&out);
    assert_eq!(out.stdout, b"suite-run\n");
    assert!(!outside.join("units").exists());
    let listing = f.cli("ls", &[]);
    success(&listing);
    let stdout = String::from_utf8(listing.stdout).unwrap();
    assert!(
        stdout.lines().any(|line| line == "suite\t-\tunavailable"),
        "{stdout}"
    );
    let mut forget = f.command(&f.root);
    forget.args(["forget", "--units", "0123456789abcdef0123456789abcdef"]);
    assert_eq!(forget.output().unwrap().status.code(), Some(1));
    assert!(!outside.join("units").exists());
}

#[test]
fn an_explicit_store_through_a_link_is_trusted() {
    for via_env in [false, true] {
        let f = Fixture::new();
        let outside = f.outside();
        fs::create_dir_all(&outside).unwrap();
        // The repository's own .stoop is a link to a stray directory. The explicit store must be
        // the only place suites go.
        let stray = f.root.with_extension("stray");
        fs::create_dir_all(&stray).unwrap();
        std::os::unix::fs::symlink(&stray, f.root.join(".stoop")).unwrap();
        let link_path = f.root.join("linked");
        std::os::unix::fs::symlink(&outside, &link_path).unwrap();
        let link = link_path.to_str().unwrap();
        let (options, env): (Vec<&str>, Vec<(&str, &str)>) = if via_env {
            (Vec::new(), vec![("STOOP_STORE", link)])
        } else {
            (vec!["--store", link], Vec::new())
        };
        success(&f.run(&options, Some("{changed:*.t}"), &env));
        assert!(!stray.join("units").exists());
        let bundle = only_file(&outside.join("units/v1"));
        let id = bundle.file_stem().unwrap().to_str().unwrap().to_owned();
        let mut ls = f.command(&f.root);
        ls.arg("ls");
        if via_env {
            ls.env("STOOP_STORE", link);
        } else {
            ls.args(["--store", link]);
        }
        let listing = ls.output().unwrap();
        success(&listing);
        let stdout = String::from_utf8(listing.stdout).unwrap();
        let prefix = format!("suite\t{id}\t");
        assert!(
            stdout.lines().any(|line| line.starts_with(prefix.as_str())),
            "{stdout}"
        );
    }
}

#[test]
fn an_implicit_store_that_is_a_file_lists_as_unavailable() {
    let f = Fixture::new();
    fs::write(f.root.join(".stoop"), b"not a store\n").unwrap();
    let listing = f.cli("ls", &[]);
    success(&listing);
    let stdout = String::from_utf8(listing.stdout).unwrap();
    assert!(
        stdout.lines().any(|line| line == "suite\t-\tunavailable"),
        "{stdout}"
    );
    assert_eq!(fs::read(f.root.join(".stoop")).unwrap(), b"not a store\n");
}

#[test]
fn a_fifo_suite_lock_never_blocks_a_run_or_replaces_the_bundle() {
    let f = Fixture::new();
    let (path, id) = suite_with_lock(&f, make_fifo);
    let before = (identity(&path), fs::read(&path).unwrap());
    // The run is forced, so it tries to record. A blocking open of the FIFO would never return.
    let run = output_within(
        &mut f.run_command(&[], Some("{changed:*.t}"), &[]),
        Duration::from_secs(60),
    );
    success(&run);
    assert_eq!((identity(&path), fs::read(&path).unwrap()), before);
    let lock = path.with_extension("lock");
    assert!(fs::symlink_metadata(&lock).unwrap().file_type().is_fifo());
    let mut forget = f.command(&f.root);
    forget.args(["forget", "--units", id.as_str()]);
    let forgot = output_within(&mut forget, Duration::from_secs(60));
    assert_eq!(forgot.status.code(), Some(1));
}

#[test]
fn a_directory_suite_lock_never_replaces_the_bundle() {
    let f = Fixture::new();
    let (path, id) = suite_with_lock(&f, |lock| fs::create_dir(lock).unwrap());
    let before = (identity(&path), fs::read(&path).unwrap());
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    assert_eq!((identity(&path), fs::read(&path).unwrap()), before);
    let mut forget = f.command(&f.root);
    forget.args(["forget", "--units", id.as_str()]);
    assert_eq!(forget.output().unwrap().status.code(), Some(1));
    assert!(path.with_extension("lock").is_dir());
}

#[test]
fn a_hard_linked_suite_lock_is_never_taken() {
    let f = Fixture::new();
    let (path, id) = suite_with_lock(&f, |lock| {
        let spare = lock.with_file_name("spare");
        fs::write(&spare, b"").unwrap();
        fs::hard_link(&spare, lock).unwrap();
    });
    assert_eq!(
        fs::metadata(path.with_extension("lock")).unwrap().nlink(),
        2
    );
    let before = (identity(&path), fs::read(&path).unwrap());
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    assert_eq!((identity(&path), fs::read(&path).unwrap()), before);
    let mut forget = f.command(&f.root);
    forget.args(["forget", "--units", id.as_str()]);
    assert_eq!(forget.output().unwrap().status.code(), Some(1));
}

#[test]
fn a_warm_whole_command_hit_never_runs_the_suite_inventory() {
    let f = Fixture::new();
    // Inputs are committed, as in a real repository. An untracked input has no basis, so a run
    // that reads one is never recorded. The policy forces every hook run to launch when the
    // default branch is unknown or HEAD is on it, so a default is configured and HEAD is elsewhere.
    fs::write(
        f.root.join(".stoop.toml"),
        "[units]\ndefault_branch = \"main\"\n",
    )
    .unwrap();
    git(&f.root, &["init", "-q"]);
    git(&f.root, &["symbolic-ref", "HEAD", "refs/heads/work"]);
    git(&f.root, &["add", "-A"]);
    git(
        &f.root,
        &[
            "-c",
            "user.name=stoop",
            "-c",
            "user.email=stoop@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
    );
    let path = git_shim(&f.root.with_extension("shims"));
    let log = f.root.with_extension("git.log");
    let log_text = log.to_str().unwrap();
    let env = [("PATH", path.as_str()), ("STOOP_TEST_GIT_LOG", log_text)];
    // The first run records a suite, so the inventory runs and the shim logs it.
    success(&f.run(&[], Some("{changed:*.t}"), &env));
    f.one_bundle();
    let recorded = fs::read_to_string(&log).unwrap();
    assert!(
        INVENTORY
            .iter()
            .any(|argv| recorded.lines().any(|line| line.ends_with(*argv))),
        "{recorded}"
    );
    fs::remove_file(&log).unwrap();
    // Without STOOP_FULL the second run is a whole-command hit: it skips the command and takes
    // no roster.
    let mut command = f.run_command(&[], Some("{changed:*.t}"), &env);
    command.env_remove("STOOP_FULL");
    let warm = command.output().unwrap();
    success(&warm);
    assert!(warm.stdout.is_empty(), "the warm run launched the command");
    let inventory = fs::read_to_string(&log).unwrap_or_default();
    assert!(
        !inventory
            .lines()
            .any(|line| INVENTORY.iter().any(|argv| line.ends_with(*argv))),
        "{inventory}"
    );
}

#[test]
fn a_forced_full_hit_still_records_the_suite() {
    let f = Fixture::new();
    success(&f.run(&[], Some("{changed:*.t}"), &[]));
    let (path, _) = f.one_bundle();
    fs::remove_file(&path).unwrap();
    // STOOP_FULL keeps the whole-command proof but still launches the command, so the suite is
    // recorded again.
    let out = f.run(&[], Some("{changed:*.t}"), &[]);
    success(&out);
    assert_eq!(out.stdout, b"suite-run\n");
    let (_, bundle) = f.one_bundle();
    assert_eq!(
        bundle["roster"]["units"],
        serde_json::json!(["tests/a.t", "tests/b.t"])
    );
}

/// Runs Git in a fixture repository and requires it to succeed.
fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?} failed");
}
