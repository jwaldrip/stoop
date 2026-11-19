//! The explicit hook remains a full-command execution until unit proofs exist.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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
            "stoop-hook-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let runner = root.join("runner");
        fs::write(
            &runner,
            "#!/bin/sh\n: > \"$LOG\"\nfor arg do printf 'arg=<%s>\\n' \"$arg\" >> \"$LOG\"; done\nprintf 'changed=<%s>\\n' \"${STOOP_CHANGED-UNSET}\" >> \"$LOG\"\n[ \"${FAIL:-0}\" != 1 ]\n",
        )
        .unwrap();
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, runner }
    }

    fn command(&self, off: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("LOG", self.root.join("log"))
            .env("STOOP_STORE", self.root.join(".stoop"))
            .current_dir(&self.root);
        if off {
            command.env("STOOP_OFF", "1");
        }
        command
    }

    fn invoke(&self, opts: &[&str], args: &[&str], off: bool) -> Output {
        self.command(off)
            .arg("run")
            .args(opts)
            .arg("--")
            .arg(&self.runner)
            .args(args)
            .output()
            .unwrap()
    }

    fn log(&self) -> String {
        fs::read_to_string(self.root.join("log")).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn err(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn full_form_removes_the_placeholder_and_its_option() {
    for args in [
        vec!["--files", "{changed}"],
        vec!["--files={changed}"],
        vec!["-f", "{changed}"],
        vec!["-f={changed}"],
        vec!["-f{changed}"],
        vec!["--files", "base.t", "--files", "{changed:*.t|!slow/**}"],
        vec!["--files=base.t", "--files={changed:*.t}"],
        vec!["{changed:*.t}"],
        vec!["--files", "$STOOP_CHANGED"],
        vec!["--files=${STOOP_CHANGED:*.t}"],
        vec!["@{changed:file}"],
    ] {
        let f = Fixture::new();
        let out = f.invoke(&[], &args, true);
        assert!(out.status.success(), "args={args:?} stderr={}", err(&out));
        assert_eq!(f.log(), "changed=<>\n", "args={args:?}");
    }
}

#[test]
fn terminator_and_unrelated_options_survive_full_form() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-v", "--", "{changed}"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "arg=<-v>\nchanged=<>\n");
}

#[test]
fn ambiguous_option_arity_fails_before_the_runner() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "one", "two", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("--files"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn malformed_and_shell_mangled_placeholders_fail_before_launch() {
    for bad in [
        "{changed:}",
        "{changed:*.t|}",
        "{changed:*.t,*.u}",
        "{changed:*.t:*.u}",
        "{changed:{a,b}}",
        "{changed:!slow/**}",
        "{changed:*.t",
        "changed:*.t",
        "--files=changed:*.t",
    ] {
        let f = Fixture::new();
        let out = f.invoke(&[], &[bad], true);
        assert_eq!(
            out.status.code(),
            Some(2),
            "bad={bad:?} stderr={}",
            err(&out)
        );
        assert!(!f.root.join("log").exists(), "bad={bad:?}");
    }
}

#[test]
fn a_placeholder_embedded_in_a_word_with_spaces_is_refused_before_launch() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["echo {changed} now"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("embedded"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_hook_run_prints_the_words_it_removed_without_tracing() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("removed [\"--files\", \"{changed}\"]"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn inherited_changed_value_is_cleared_only_for_a_hook() {
    let f = Fixture::new();
    let out = f
        .command(true)
        .env("STOOP_CHANGED", "old-value")
        .args(["run", "--"])
        .arg(&f.runner)
        .arg("{changed}")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("STOOP_CHANGED"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn literal_mode_and_ordinary_empty_values_do_not_rewrite_argv() {
    let f = Fixture::new();
    let out = f.invoke(&["--literal"], &["--files", "{changed}"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "arg=<--files>\narg=<{changed}>\nchanged=<UNSET>\n");

    let f = Fixture::new();
    let out = f.invoke(&[], &["--only", ""], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("quote"), "{}", err(&out));
    assert_eq!(f.log(), "arg=<--only>\narg=<>\nchanged=<UNSET>\n");
}

#[test]
fn no_split_keeps_explicit_hooks_and_explain_never_launches() {
    let f = Fixture::new();
    let out = f.invoke(&["--no-split"], &["--files", "{changed}"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
    fs::remove_file(f.root.join("log")).unwrap();
    let out = f
        .command(false)
        .args(["explain", "--"])
        .arg(&f.runner)
        .arg("{changed}")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    assert!(err(&out).contains("{changed}"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn failed_hook_still_detects_erased_forms_without_skipping() {
    for (hook, erased) in [
        (vec!["--files", "{changed:*.t}"], vec!["--files", ""]),
        (vec!["--files", "{changed:*.t}"], vec!["--files"]),
        (vec!["--files={changed:*.t}"], vec!["--files="]),
    ] {
        let f = Fixture::new();
        let before = f.invoke(&[], &erased, false);
        assert!(before.status.success(), "{}", err(&before));
        let before_log = f.log();
        let failed = f
            .command(false)
            .env("FAIL", "1")
            .arg("run")
            .arg("--")
            .arg(&f.runner)
            .args(&hook)
            .output()
            .unwrap();
        assert_eq!(failed.status.code(), Some(1), "{}", err(&failed));
        fs::write(f.root.join("log"), before_log).unwrap();
        let after = f.invoke(&[], &erased, false);
        assert!(after.status.success(), "{}", err(&after));
        assert!(err(&after).contains("quote"), "{}", err(&after));
        assert!(!err(&after).contains("stoop: skip"), "{}", err(&after));
        assert_eq!(f.log(), "changed=<>\n");
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn explicit_keys_cannot_share_hook_and_ordinary_proofs() {
    let f = Fixture::new();
    let first = f.invoke(&["--key", "same"], &["--files", "one.t"], false);
    assert!(first.status.success(), "{}", err(&first));
    let hook = f.invoke(&["--key", "same"], &["--files", "{changed}"], false);
    assert!(hook.status.success(), "{}", err(&hook));
    assert!(!err(&hook).contains("stoop: skip"), "{}", err(&hook));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn a_placeholder_cannot_be_the_executable() {
    let f = Fixture::new();
    let out = f
        .command(true)
        .args(["run", "--", "{changed}"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_placeholder_takes_only_one_filter() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed:*.t:*.u}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_first_sighting_records_the_template_before_the_run_outcome() {
    let f = Fixture::new();
    let failed = f
        .command(false)
        .env("FAIL", "1")
        .args(["run", "--", "./runner", "--files", "{changed}"])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1), "{}", err(&failed));
    let catalog = fs::read_to_string(f.root.join(".stoop/hooks-v1.json")).unwrap();
    assert!(catalog.contains("{changed}"), "{catalog}");
}

#[test]
fn several_values_before_the_placeholder_are_refused_with_the_documented_fix() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "a", "b", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        err(&out).contains("cannot tell where values"),
        "{}",
        err(&out)
    );
    assert!(
        err(&out).contains("option arity configuration"),
        "{}",
        err(&out)
    );
    assert!(!f.root.join("log").exists());
}
