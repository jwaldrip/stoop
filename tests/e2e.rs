//! End to end: the real binary, real processes, a real tree.
//! Tracing needs Linux, so these only run there.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Ws {
    root: PathBuf,
}

impl Ws {
    fn new(name: &str) -> Ws {
        let root = std::env::temp_dir().join(format!("stoop-e2e-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("in.txt"), "one").unwrap();
        Ws { root }
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    /// Run `stoop <args>` in the workspace. Returns (exit code, stderr).
    fn stoop(&self, args: &[&str]) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
            .args(args)
            .current_dir(&self.root)
            .env(
                "STOOP_STORE",
                self.root.join("..").join(format!(
                    "{}-store",
                    self.root.file_name().unwrap().to_string_lossy()
                )),
            )
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn sh(&self, script: &str) -> (i32, String) {
        self.stoop(&["run", "--root", ".", "--key", "t", "--", "sh", "-c", script])
    }
}

fn skipped(s: &str) -> bool {
    s.contains("stoop: skip")
}

#[test]
fn unchanged_inputs_skip_and_a_changed_input_runs() {
    let w = Ws::new("basic");
    let (c, e) = w.sh("cat in.txt > /dev/null");
    assert_eq!(c, 0, "{e}");
    assert!(e.contains("recorded"), "{e}");
    let (c, e) = w.sh("cat in.txt > /dev/null");
    assert_eq!(c, 0);
    assert!(skipped(&e), "second run should skip: {e}");
    w.write("in.txt", "two");
    let (_, e) = w.sh("cat in.txt > /dev/null");
    assert!(!skipped(&e) && e.contains("in.txt changed"), "{e}");
}

#[test]
fn a_file_the_command_never_read_does_not_matter() {
    let w = Ws::new("unrelated");
    w.sh("cat in.txt > /dev/null");
    w.write("other.txt", "x");
    w.write("sub/more.txt", "y");
    let (_, e) = w.sh("cat in.txt > /dev/null");
    assert!(skipped(&e), "{e}");
}

#[test]
fn a_file_that_was_absent_and_appears_runs_the_command() {
    let w = Ws::new("appears");
    let script = "[ -f config.json ] && cat config.json; cat in.txt > /dev/null; true";
    w.sh(script);
    assert!(skipped(&w.sh(script).1));
    w.write("config.json", "{}");
    let (_, e) = w.sh(script);
    assert!(!skipped(&e) && e.contains("config.json appeared"), "{e}");
}

#[test]
fn a_changed_binary_file_the_command_reads_runs_it_again() {
    let w = Ws::new("binary");
    let mut blob: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    blob.extend_from_slice(&[0, 255, 0, 0]);
    fs::write(w.root.join("data.bin"), &blob).unwrap();
    let script = "wc -c data.bin > /dev/null";
    w.sh(script);
    assert!(skipped(&w.sh(script).1));
    blob[150_000] ^= 1; // same size, one bit different, far from either end
    fs::write(w.root.join("data.bin"), &blob).unwrap();
    let (_, e) = w.sh(script);
    assert!(!skipped(&e) && e.contains("data.bin changed"), "{e}");
}

#[test]
fn a_new_entry_in_a_listed_directory_runs_the_command() {
    let w = Ws::new("listing");
    w.write("tests/a.txt", "a");
    let script = "ls tests > /dev/null";
    w.sh(script);
    assert!(skipped(&w.sh(script).1));
    w.write("tests/b.txt", "b");
    let (_, e) = w.sh(script);
    assert!(!skipped(&e), "{e}");
}

#[test]
fn a_failed_run_leaves_no_proof() {
    let w = Ws::new("fail");
    let (c, e) = w.sh("cat in.txt > /dev/null; exit 3");
    assert_eq!(c, 3, "exit code passes through: {e}");
    let (c, e) = w.sh("cat in.txt > /dev/null; exit 3");
    assert_eq!(c, 3);
    assert!(!skipped(&e), "{e}");
}

#[test]
fn a_file_the_run_wrote_is_not_an_input() {
    let w = Ws::new("outputs");
    let script = "cat in.txt > out.txt; cat out.txt > /dev/null";
    w.sh(script);
    let (_, e) = w.sh(script);
    assert!(
        skipped(&e),
        "a generated file that is still there must not block the skip: {e}"
    );
}

#[test]
fn a_skip_needs_the_outputs_still_in_place() {
    let w = Ws::new("outputs-missing");
    let script = "cat in.txt > built.bin";
    w.sh(script);
    fs::remove_file(w.root.join("built.bin")).unwrap();
    let (_, e) = w.sh(script);
    assert!(
        !skipped(&e) && e.contains("output built.bin missing"),
        "{e}"
    );
    assert!(
        w.root.join("built.bin").exists(),
        "the command must have run again"
    );
}

#[test]
fn a_changed_output_runs_the_command_again() {
    let w = Ws::new("outputs-changed");
    let script = "cat in.txt > built.bin";
    w.sh(script);
    w.write("built.bin", "tampered");
    let (_, e) = w.sh(script);
    assert!(
        !skipped(&e) && e.contains("output built.bin changed"),
        "{e}"
    );
}

#[test]
fn ignored_outputs_do_not_block_a_skip() {
    let w = Ws::new("outputs-ignored");
    w.write(".stoopignore", "report.xml\n");
    let script = "cat in.txt > report.xml";
    w.sh(script);
    fs::remove_file(w.root.join("report.xml")).unwrap();
    let (_, e) = w.sh(script);
    assert!(skipped(&e), "{e}");
}

#[test]
fn temp_files_the_run_removes_are_not_outputs() {
    let w = Ws::new("outputs-temp");
    let script = "cat in.txt > scratch.tmp; rm scratch.tmp";
    w.sh(script);
    let (_, e) = w.sh(script);
    assert!(skipped(&e), "{e}");
}

#[test]
fn children_and_grandchildren_are_traced() {
    let w = Ws::new("children");
    w.write("deep.txt", "d");
    let script = "sh -c 'sh -c \"cat deep.txt > /dev/null\"'";
    w.sh(script);
    w.write("deep.txt", "changed");
    let (_, e) = w.sh(script);
    assert!(!skipped(&e) && e.contains("deep.txt changed"), "{e}");
}

#[test]
fn reading_git_state_is_never_recorded() {
    let w = Ws::new("git");
    w.write(".git/HEAD", "ref: refs/heads/main");
    let script = "cat .git/HEAD > /dev/null";
    let (_, e) = w.sh(script);
    assert!(e.contains("not recorded") && e.contains(".git"), "{e}");
    assert!(!skipped(&w.sh(script).1));
}

#[test]
fn ignoring_git_makes_it_skippable() {
    let w = Ws::new("gitignore");
    w.write(".git/HEAD", "ref: refs/heads/main");
    w.write(".stoopignore", ".git\n");
    let script = "cat .git/HEAD in.txt > /dev/null";
    w.sh(script);
    assert!(skipped(&w.sh(script).1));
}

/// Run with FOO set to `v` and extra args before `--`.
fn run_with_foo(w: &Ws, v: &str, extra: &[&str]) -> String {
    let mut args = vec!["run", "--root", ".", "--key", "e"];
    args.extend(extra);
    args.extend(["--", "sh", "-c", "cat in.txt > /dev/null"]);
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args(args)
        .current_dir(&w.root)
        .env("STOOP_STORE", w.root.join("../env-store"))
        .env("FOO", v)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn the_whole_environment_is_an_input() {
    let w = Ws::new("env");
    run_with_foo(&w, "a", &[]);
    assert!(skipped(&run_with_foo(&w, "a", &[])));
    let e = run_with_foo(&w, "b", &[]);
    assert!(!skipped(&e) && e.contains("env changed"), "{e}");
}

#[test]
fn an_ignored_variable_may_change_freely() {
    let w = Ws::new("env-ignore");
    run_with_foo(&w, "a", &["--ignore-env", "FOO"]);
    assert!(skipped(&run_with_foo(&w, "b", &["--ignore-env", "FOO"])));
}

const NET: &str =
    "cat in.txt > /dev/null; bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null; true";

fn with_probe(w: &Ws, probe: &str, script: &str) -> (i32, String) {
    w.stoop(&[
        "run", "--root", ".", "--key", "p", "--probe", probe, "--", "sh", "-c", script,
    ])
}

#[test]
fn a_declared_probe_lets_a_networked_step_be_recorded_and_skipped() {
    let w = Ws::new("probe");
    w.write("probe.txt", "v1");
    let (_, e) = with_probe(&w, "cat probe.txt", NET);
    assert!(e.contains("recorded"), "{e}");
    assert!(skipped(&with_probe(&w, "cat probe.txt", NET).1));
}

#[test]
fn a_changed_probe_runs_the_command_again() {
    let w = Ws::new("probe-changed");
    w.write("probe.txt", "v1");
    with_probe(&w, "cat probe.txt", NET);
    w.write("probe.txt", "v2");
    let (_, e) = with_probe(&w, "cat probe.txt", NET);
    assert!(
        !skipped(&e) && e.contains("probe `cat probe.txt` changed"),
        "{e}"
    );
}

#[test]
fn a_failing_probe_is_never_assumed_unchanged() {
    let w = Ws::new("probe-fails");
    let (_, e) = with_probe(&w, "false", NET);
    assert!(e.contains("not recorded") && e.contains("probe"), "{e}");
    assert!(!skipped(&with_probe(&w, "false", NET).1));
}

#[test]
fn dropping_a_probe_invalidates_the_proof() {
    let w = Ws::new("probe-dropped");
    w.write("probe.txt", "v1");
    with_probe(&w, "cat probe.txt", NET);
    let (_, e) = w.stoop(&[
        "run",
        "--allow-network",
        "--root",
        ".",
        "--key",
        "p",
        "--",
        "sh",
        "-c",
        NET,
    ]);
    assert!(!skipped(&e), "{e}");
}

#[test]
fn a_probe_that_changes_during_the_run_blocks_recording() {
    let w = Ws::new("probe-midrun");
    w.write("probe.txt", "v1");
    let script = "cat in.txt > /dev/null; echo changed > probe.txt";
    let (_, e) = with_probe(&w, "cat probe.txt", script);
    assert!(
        e.contains("not recorded") && e.contains("changed while the command ran"),
        "{e}"
    );
}

#[test]
fn using_the_network_is_never_recorded() {
    let w = Ws::new("net");
    let script = "cat in.txt > /dev/null; bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null; true";
    let (_, e) = w.sh(script);
    assert!(e.contains("not recorded") && e.contains("network"), "{e}");
    assert!(!skipped(&w.sh(script).1));
}

#[test]
fn allow_network_records_it_anyway() {
    let w = Ws::new("net-allowed");
    let script = "cat in.txt > /dev/null; bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null; true";
    let run = || {
        w.stoop(&[
            "run",
            "--allow-network",
            "--root",
            ".",
            "--key",
            "n",
            "--",
            "sh",
            "-c",
            script,
        ])
        .1
    };
    run();
    assert!(skipped(&run()));
}

#[test]
fn full_mode_never_skips_but_still_records() {
    let w = Ws::new("full");
    w.sh("cat in.txt > /dev/null");
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args([
            "run",
            "--root",
            ".",
            "--key",
            "t",
            "--",
            "sh",
            "-c",
            "cat in.txt > /dev/null",
        ])
        .current_dir(&w.root)
        .env(
            "STOOP_STORE",
            w.root.join("..").join(format!(
                "{}-store",
                w.root.file_name().unwrap().to_string_lossy()
            )),
        )
        .env("STOOP_FULL", "1")
        .output()
        .unwrap();
    let e = String::from_utf8_lossy(&out.stderr);
    assert!(e.contains("stoop: run") && !skipped(&e), "{e}");
}

#[test]
fn explain_reports_without_running() {
    let w = Ws::new("explain");
    w.sh("cat in.txt > /dev/null; touch ran");
    fs::remove_file(w.root.join("ran")).ok();
    w.write("in.txt", "new");
    let (c, e) = w.stoop(&[
        "explain", "--root", ".", "--key", "t", "--", "sh", "-c", "x",
    ]);
    assert_eq!(c, 1, "{e}");
    assert!(e.contains("in.txt"), "{e}");
    assert!(!w.root.join("ran").exists());
}

#[test]
fn shell_mode_keys_on_script_content_not_its_file_name() {
    let w = Ws::new("shellmode");
    let a = w.root.join("step-aaa.sh");
    let b = w.root.join("step-bbb.sh");
    let body = "cat in.txt > /dev/null\n";
    fs::write(&a, body).unwrap();
    fs::write(&b, body).unwrap();
    let first = w.stoop(&["sh", a.to_str().unwrap()]);
    assert_eq!(first.0, 0, "{}", first.1);
    let (_, e) = w.stoop(&["sh", b.to_str().unwrap()]);
    assert!(skipped(&e), "{e}");
}

#[test]
fn an_expired_proof_no_longer_skips() {
    let w = Ws::new("expiry");
    let run = |age: &str| {
        w.stoop(&[
            "run",
            "--max-age",
            age,
            "--root",
            ".",
            "--key",
            "x",
            "--",
            "sh",
            "-c",
            "cat in.txt > /dev/null",
        ])
        .1
    };
    run("1h");
    assert!(skipped(&run("1h")));
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let e = run("1s");
    assert!(!skipped(&e) && e.contains("proof expired"), "{e}");
}

#[test]
fn no_record_checks_but_never_writes() {
    let w = Ws::new("norecord");
    w.stoop(&[
        "run",
        "--no-record",
        "--root",
        ".",
        "--key",
        "n",
        "--",
        "sh",
        "-c",
        "cat in.txt > /dev/null",
    ]);
    let (_, e) = w.stoop(&[
        "run",
        "--no-record",
        "--root",
        ".",
        "--key",
        "n",
        "--",
        "sh",
        "-c",
        "cat in.txt > /dev/null",
    ]);
    assert!(!skipped(&e), "{e}");
}

#[allow(dead_code)]
fn _unused(_: &Path) {}
