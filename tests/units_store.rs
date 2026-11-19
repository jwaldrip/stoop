//! The hook record catalog is a cache. Damage to it warns and never changes the command's
//! own status, and concurrent first recordings leave one valid file holding every record.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("runner"),
            "#!/bin/sh\n: > \"$LOG\"\nfor arg do printf 'arg=<%s>\\n' \"$arg\" >> \"$LOG\"; done\nprintf 'changed=<%s>\\n' \"${STOOP_CHANGED-UNSET}\" >> \"$LOG\"\n[ \"${FAIL:-0}\" != 1 ]\n",
        )
        .unwrap();
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
        Self { root }
    }

    fn store(&self) -> PathBuf {
        self.root.join("store")
    }

    fn catalog(&self) -> PathBuf {
        self.store().join("hooks-v1.json")
    }

    fn stoop(&self, log: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("LOG", self.root.join(log))
            .env("STOOP_STORE", self.store())
            .current_dir(&self.root);
        command
    }

    /// The first recording of a placeholder argv, which is a hook.
    fn hook(&self, log: &str, fail: bool) -> Output {
        let mut command = self.stoop(log);
        if fail {
            command.env("FAIL", "1");
        }
        command
            .args(["run", "--", "./runner", "{changed}"])
            .output()
            .unwrap()
    }

    fn log(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::set_permissions(self.store(), fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The command's own status survives, and exactly one line reports the hook records.
fn one_warning(output: &Output, status: i32) {
    assert_eq!(output.status.code(), Some(status), "{}", err(output));
    assert_eq!(
        err(output).matches("hook records").count(),
        1,
        "{}",
        err(output)
    );
}

fn damaged(bytes: &[u8]) -> Fixture {
    let f = Fixture::new();
    fs::create_dir_all(f.store()).unwrap();
    fs::write(f.catalog(), bytes).unwrap();
    f
}

#[test]
fn corrupted_catalog_is_replaced_with_one_warning() {
    let f = damaged(b"{not json");
    let out = f.hook("log", false);
    one_warning(&out, 0);
    assert_eq!(f.log("log"), "changed=<>\n");
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(f.catalog()).unwrap()).unwrap();
    assert_eq!(catalog["version"], 1);
}

#[test]
fn a_newer_catalog_version_is_left_untouched_and_the_hook_still_runs() {
    let bytes = br#"{"version":9,"records":[]}"#;
    let f = damaged(bytes);
    let out = f.hook("log", false);
    one_warning(&out, 0);
    assert_eq!(f.log("log"), "changed=<>\n");
    assert_eq!(fs::read(f.catalog()).unwrap(), bytes);
}

#[test]
fn an_oversized_catalog_is_replaced_and_the_hook_still_runs() {
    let f = damaged(&vec![b' '; 2 * 1024 * 1024]);
    let out = f.hook("log", false);
    one_warning(&out, 0);
    assert_eq!(f.log("log"), "changed=<>\n");
}

#[test]
fn an_unreadable_catalog_warns_and_the_command_runs_as_typed() {
    let f = damaged(br#"{"version":1,"records":[]}"#);
    fs::set_permissions(f.catalog(), fs::Permissions::from_mode(0o000)).unwrap();
    let out = f
        .stoop("log")
        .env("FAIL", "1")
        .args(["run", "--", "./runner", "--only", ""])
        .output()
        .unwrap();
    one_warning(&out, 1);
    assert_eq!(f.log("log"), "arg=<--only>\narg=<>\nchanged=<UNSET>\n");
}

#[test]
fn a_read_only_store_runs_the_hook_and_keeps_its_status() {
    let f = Fixture::new();
    fs::create_dir_all(f.store()).unwrap();
    fs::set_permissions(f.store(), fs::Permissions::from_mode(0o500)).unwrap();
    let out = f.hook("log", false);
    one_warning(&out, 0);
    assert_eq!(f.log("log"), "changed=<>\n");
}

#[test]
fn concurrent_first_recordings_leave_one_valid_catalog_with_every_record() {
    let f = Fixture::new();
    let children: Vec<_> = (0..8)
        .map(|i| {
            f.stoop(&format!("log{i}"))
                .args(["run", "--", "./runner", &format!("--tag{i}"), "{changed}"])
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{}", err(&out));
    }
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(f.catalog()).unwrap()).unwrap();
    assert_eq!(catalog["version"], 1);
    assert_eq!(catalog["records"].as_array().unwrap().len(), 8);
}
