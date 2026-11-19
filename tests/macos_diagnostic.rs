//! The macOS DTrace diagnostic, end to end. It needs passwordless `sudo` and DTrace, which
//! hosted macOS runners have. Elsewhere each test says why it skipped, unless
//! `STOOP_REQUIRE_DTRACE` is set, which makes a missing tracer a failure.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tracer_usable() -> bool {
    Command::new("sudo")
        .args(["-n", "/usr/sbin/dtrace", "-V"])
        .output()
        .is_ok_and(|out| out.status.success())
}

fn skip(test: &str) -> bool {
    if tracer_usable() {
        return false;
    }
    assert!(
        std::env::var_os("STOOP_REQUIRE_DTRACE").is_none(),
        "{test}: STOOP_REQUIRE_DTRACE is set but `sudo -n dtrace` does not work here"
    );
    eprintln!("{test}: skipped, `sudo -n dtrace` is not usable on this machine");
    true
}

struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("stoop-dtrace-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        // The tracer reports the paths the command used; the kernel's working directory is
        // the canonical one.
        let dir = fs::canonicalize(dir).unwrap();
        fs::write(dir.join("in.txt"), "in").unwrap();
        fs::write(dir.join("nested.txt"), "nested").unwrap();
        Self { dir }
    }

    fn stoop(&self, script: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .args([
                "run", "--root", ".", "--key", "t", "--", "/bin/sh", "-c", script,
            ])
            .current_dir(&self.dir)
            .env("STOOP_STORE", self.dir.join("store"))
            .env("STOOP_DTRACE_DIAGNOSTIC", "list")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_FULL")
            .output()
            .unwrap()
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn listed(stderr: &str, verb: &str) -> Vec<String> {
    let prefix = format!("stoop: dtrace {verb} ");
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_tree_its_lookups_and_its_status_are_observed_and_never_recorded() {
    if skip("the_tree_its_lookups_and_its_status_are_observed_and_never_recorded") {
        return;
    }
    let w = Work::new("tree");
    let script = "cat in.txt >/dev/null; \
        i=0; while [ $i -lt 2000 ]; do test -e \"missing/$i\"; i=$((i+1)); done; \
        /bin/sh -c 'cat nested.txt >/dev/null; printf built > built.txt'; \
        printf run >> runs.log; exit 3";
    let out = w.stoop(script);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert_eq!(fs::read_to_string(w.dir.join("runs.log")).unwrap(), "run");
    assert!(stderr.contains("stoop: DTrace diagnostic:"), "{stderr}");
    assert!(stderr.contains("not recorded"), "{stderr}");
    // DTrace cannot always read a path, and it cannot place a path relative to a descriptor
    // here, so a run may be reported incomplete. It must never be incomplete for a structural
    // reason: the tracer armed, saw the command exit, stopped cleanly, and every pid it saw
    // belongs to the tree.
    for line in stderr.lines().filter(|l| l.contains("is incomplete")) {
        assert!(
            line.contains("directory descriptor") || line.contains("loss or error"),
            "structural reason: {line}\n{stderr}"
        );
    }

    let read = listed(&stderr, "read");
    for name in ["in.txt", "nested.txt"] {
        assert!(read.contains(&w.path(name)), "{name} missing from {read:?}");
    }
    let missing = read
        .iter()
        .filter(|path| path.starts_with(&w.path("missing/")))
        .count();
    // A failed lookup is never lost silently: either all 2000 were seen, or the tracer said it
    // could not read some path.
    assert!(
        missing == 2000 || stderr.contains("loss or error"),
        "failed lookups seen: {missing}\n{stderr}"
    );
    assert!(missing >= 1900, "failed lookups seen: {missing}");
    assert!(
        listed(&stderr, "wrote").contains(&w.path("built.txt")),
        "{stderr}"
    );
    assert!(!Path::new(&w.path("store")).join("proofs").exists());
}

#[test]
fn a_tracer_killed_mid_run_returns_the_status_and_says_the_trace_is_incomplete() {
    if skip("a_tracer_killed_mid_run_returns_the_status_and_says_the_trace_is_incomplete") {
        return;
    }
    let w = Work::new("killed");
    let out = w.stoop("cat in.txt >/dev/null; sudo -n pkill -INT -x dtrace; sleep 2; printf run >> runs.log; exit 5");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert_eq!(fs::read_to_string(w.dir.join("runs.log")).unwrap(), "run");
    assert!(
        stderr.contains("DTrace diagnostic is incomplete"),
        "{stderr}"
    );
}

#[test]
fn without_the_switch_the_command_runs_untraced_as_before() {
    let w = Work::new("off");
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args([
            "run", "--root", ".", "--key", "t", "--", "/bin/sh", "-c", "exit 4",
        ])
        .current_dir(&w.dir)
        .env("STOOP_STORE", w.dir.join("store"))
        .env_remove("STOOP_DTRACE_DIAGNOSTIC")
        .env_remove("STOOP_OFF")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(!stderr.contains("DTrace"), "{stderr}");
}
