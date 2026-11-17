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
fn mkdir_over_existing_ancestors_does_not_hide_the_inputs() {
    // `mkdir -p` (and Rust's create_dir_all, and so cargo) calls mkdir on every ancestor
    // of the target, top down. Those calls fail with EEXIST. They once turned the whole
    // repository into "output" and an edit to a read file went unnoticed.
    let w = Ws::new("mkdirp");
    let script = "mkdir -p \"$PWD/out/deep\"; cat in.txt > /dev/null";
    let (c, e) = w.sh(script);
    assert_eq!(c, 0, "{e}");
    w.write("in.txt", "edited");
    let (_, e) = w.sh(script);
    assert!(
        !skipped(&e) && e.contains("in.txt changed"),
        "an edit to a file the command read must be seen: {e}"
    );
}

// ---- sharing proofs through a git remote --------------------------------------------

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A bare repository standing in for GitHub, GitLab or any other remote.
fn bare(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "stoop-e2e-{}-{name}-remote.git",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    git(&p, &["init", "--bare", "-q", "."]);
    p
}

impl Ws {
    /// Make the workspace a git checkout whose `origin` is `remote`.
    fn with_remote(self, remote: &Path) -> Ws {
        git(&self.root, &["init", "-q", "."]);
        git(
            &self.root,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        self
    }
}

fn published(remote: &Path) -> Vec<String> {
    git(
        remote,
        &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
    )
    .lines()
    .map(String::from)
    .collect()
}

const SCRIPT: &str = "cat in.txt > /dev/null";

fn run_sync(w: &Ws, extra: &[&str]) -> (i32, String) {
    let mut args = vec!["run", "--root", ".", "--key", "s"];
    args.extend(extra);
    args.extend(["--", "sh", "-c", SCRIPT]);
    w.stoop(&args)
}

#[test]
fn a_proof_published_by_one_checkout_lets_another_skip() {
    let remote = bare("share");
    let a = Ws::new("sync-a").with_remote(&remote);
    let b = Ws::new("sync-b").with_remote(&remote);
    let (_, e) = run_sync(&a, &["--sync", "git", "--sync-write"]);
    assert!(e.contains("published"), "{e}");
    assert_eq!(published(&remote), vec!["refs/stoop/s".to_string()]);
    // B has no local proof and does not write; it reads A's.
    let (c, e) = run_sync(&b, &["--sync", "git"]);
    assert_eq!(c, 0, "{e}");
    assert!(skipped(&e), "B should skip on A's proof: {e}");
}

#[test]
fn a_published_proof_does_not_hide_a_changed_input() {
    let remote = bare("changed");
    let a = Ws::new("syncc-a").with_remote(&remote);
    let b = Ws::new("syncc-b").with_remote(&remote);
    run_sync(&a, &["--sync", "git", "--sync-write"]);
    b.write("in.txt", "different");
    let (_, e) = run_sync(&b, &["--sync", "git"]);
    assert!(!skipped(&e) && e.contains("in.txt changed"), "{e}");
}

#[test]
fn sync_only_reads_unless_write_is_asked_for() {
    let remote = bare("readonly");
    let a = Ws::new("syncr-a").with_remote(&remote);
    let (_, e) = run_sync(&a, &["--sync", "git"]);
    assert!(e.contains("recorded") && !e.contains("published"), "{e}");
    assert!(
        published(&remote).is_empty(),
        "nothing may be published without --sync-write"
    );
}

#[test]
fn an_unreachable_remote_never_fails_the_step() {
    let a = Ws::new("syncu-a").with_remote(Path::new("/nonexistent/remote.git"));
    let (c, e) = run_sync(&a, &["--sync", "git", "--sync-write"]);
    assert_eq!(c, 0, "the command's own exit status must pass through: {e}");
    assert!(e.contains("sync:") && e.contains("continuing"), "{e}");
    assert!(
        e.contains("recorded"),
        "the local proof is still recorded: {e}"
    );
    // and the local proof works
    assert!(skipped(&run_sync(&a, &[]).1));
}

#[test]
fn pull_fetches_every_published_proof_so_steps_never_wait_on_the_network() {
    let remote = bare("pull");
    let a = Ws::new("syncp-a").with_remote(&remote);
    let b = Ws::new("syncp-b").with_remote(&remote);
    run_sync(&a, &["--sync", "git", "--sync-write"]);
    let (c, e) = b.stoop(&["pull", "--sync", "git", "--root", "."]);
    assert_eq!(c, 0, "{e}");
    assert!(e.contains("pulled 1"), "{e}");
    // No --sync here: the proof is already in B's local store.
    assert!(skipped(&run_sync(&b, &[]).1));
}

#[test]
fn prune_removes_expired_published_proofs() {
    let remote = bare("prune");
    let a = Ws::new("syncx-a").with_remote(&remote);
    run_sync(&a, &["--sync", "git", "--sync-write"]);
    assert_eq!(published(&remote).len(), 1);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let (c, e) = a.stoop(&[
        "prune",
        "--sync",
        "git",
        "--sync-write",
        "--max-age",
        "1s",
        "--root",
        ".",
    ]);
    assert_eq!(c, 0, "{e}");
    assert!(published(&remote).is_empty(), "{e}");
    // Without write it refuses rather than deleting.
    a.stoop(&["forget", "s", "--root", "."]);
    run_sync(&a, &["--sync", "git", "--sync-write"]);
    assert_eq!(
        published(&remote).len(),
        1,
        "republished after forgetting the local proof"
    );
    let (c, _) = a.stoop(&["prune", "--sync", "git", "--max-age", "0", "--root", "."]);
    assert_ne!(c, 0);
    assert_eq!(published(&remote).len(), 1);
}

#[test]
fn republishing_keeps_proofs_other_runs_published() {
    let remote = bare("merge");
    let a = Ws::new("syncm-a").with_remote(&remote);
    let b = Ws::new("syncm-b").with_remote(&remote);
    run_sync(&a, &["--sync", "git", "--sync-write"]);
    b.write("in.txt", "variant");
    run_sync(&b, &["--sync", "git", "--sync-write"]); // proof for a different input state
                                                      // A third checkout sees both: it can skip for either variant.
    let c = Ws::new("syncm-c").with_remote(&remote);
    assert!(skipped(&run_sync(&c, &["--sync", "git"]).1), "variant one");
    c.write("in.txt", "variant");
    assert!(skipped(&run_sync(&c, &["--sync", "git"]).1), "variant two");
}

#[test]
fn io_uring_is_refused_inside_a_traced_command_so_runtimes_fall_back() {
    let w = Ws::new("iouring");
    // syscall 425 is io_uring_setup on x86-64 and arm64. Entries = 0 is EINVAL natively;
    // under stoop the kernel answers ENOSYS (38) before the call is looked at.
    let probe = "perl -e 'syscall(425, 0, 0); exit(($!+0) == 38 ? 0 : 7)'; cat in.txt > /dev/null";
    let (code, e) = w.sh(probe);
    assert_eq!(
        code, 0,
        "io_uring_setup should have been refused with ENOSYS: {e}"
    );
    assert!(
        e.contains("recorded"),
        "refusing io_uring must not make the run unrecordable: {e}"
    );
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
