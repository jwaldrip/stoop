//! The macOS DTrace diagnostic, end to end. It needs passwordless `sudo` and DTrace, which
//! hosted macOS runners have. Where they are missing, each test says why it skipped, unless
//! `STOOP_REQUIRE_DTRACE` is set, which makes a missing tracer a failure.
#![cfg(target_os = "macos")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn tracer_usable() -> bool {
    Command::new("sudo")
        .args(["-n", "/usr/sbin/dtrace", "-V"])
        .output()
        .is_ok_and(|out| out.status.success())
}

/// True when the test should be skipped. It never skips on a runner that has the tracer.
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

    fn stoop(&self, script: &str, mode: &str) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .args([
                "run", "--root", ".", "--key", "t", "--", "/bin/sh", "-c", script,
            ])
            .current_dir(&self.dir)
            .env("STOOP_STORE", self.dir.join("store"))
            .env("STOOP_DTRACE_DIAGNOSTIC", mode)
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_FULL")
            .output()
            .unwrap()
    }

    fn path(&self, name: &str) -> String {
        self.dir.join(name).display().to_string()
    }

    /// Stoop wrote no proof: its store holds no proof files.
    fn no_proof_written(&self) {
        let store = self.dir.join("store");
        let proofs = fs::read_dir(&store)
            .map(|entries| entries.count())
            .unwrap_or(0);
        assert_eq!(proofs, 0, "a diagnostic run wrote into {}", store.display());
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// The report lines of one kind: `stoop: dtrace <verb> <rest>` gives `<rest>`.
fn listed(stderr: &str, verb: &str) -> Vec<String> {
    let prefix = format!("stoop: dtrace {verb} ");
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_fixture_with_a_tree_and_failed_lookups_is_observed_in_full_and_never_recorded() {
    let name = "a_fixture_with_a_tree_and_failed_lookups_is_observed_in_full_and_never_recorded";
    if skip(name) {
        return;
    }
    let w = Work::new("fixture");
    // 2000 lookups that fail, 1000 that succeed, 300 processes spawned and exec'd (so pids are
    // reused), a grandchild, and writes into the repository.
    let script = "cat in.txt >/dev/null; \
        i=0; while [ $i -lt 2000 ]; do test -e \"missing/$i\"; i=$((i+1)); done; \
        i=0; while [ $i -lt 1000 ]; do test -e in.txt; i=$((i+1)); done; \
        i=0; while [ $i -lt 300 ]; do /usr/bin/true; i=$((i+1)); done; \
        /bin/sh -c 'cat nested.txt >/dev/null; printf built > built.txt'; \
        mkdir out; printf run >> runs.log; exit 3";
    let out = w.stoop(script, "list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert_eq!(fs::read_to_string(w.dir.join("runs.log")).unwrap(), "run");
    assert!(stderr.contains("stoop: DTrace diagnostic: "), "{stderr}");
    assert!(stderr.contains("not recorded"), "{stderr}");
    // The known result: DTrace saw the whole fixture and reported no loss or error.
    assert!(
        stderr.contains("DTrace diagnostic verdict: no loss seen"),
        "{stderr}"
    );
    w.no_proof_written();

    let read = listed(&stderr, "read");
    let failed = listed(&stderr, "failed");
    let wrote = listed(&stderr, "wrote");
    let spawned = listed(&stderr, "spawn");
    let execed = listed(&stderr, "exec");

    assert!(read.contains(&w.path("in.txt")), "{read:?}");
    assert!(read.contains(&w.path("nested.txt")), "{read:?}");
    let missing = failed
        .iter()
        .filter(|path| path.starts_with(&w.path("missing/")))
        .count();
    assert_eq!(missing, 2000, "failed lookups seen: {failed:?}");
    assert!(
        !read
            .iter()
            .any(|path| path.starts_with(&w.path("missing/"))),
        "a failed lookup was also listed as read"
    );
    assert!(wrote.contains(&w.path("built.txt")), "{wrote:?}");
    assert!(wrote.contains(&w.path("runs.log")), "{wrote:?}");
    assert!(wrote.contains(&w.path("out")), "{wrote:?}");

    let trues = execed
        .iter()
        .filter(|line| line.ends_with(" /usr/bin/true"))
        .count();
    assert_eq!(trues, 300, "exec attempts seen: {execed:?}");
    assert!(
        execed.iter().any(|line| line.ends_with(" /bin/sh")),
        "{execed:?}"
    );
    assert!(
        execed.iter().any(|line| line.ends_with(" /bin/cat")),
        "{execed:?}"
    );
    assert!(spawned.len() >= 300, "spawn edges seen: {}", spawned.len());
}

#[test]
fn a_tracer_killed_mid_run_returns_the_status_and_says_the_report_is_unsound() {
    let name = "a_tracer_killed_mid_run_returns_the_status_and_says_the_report_is_unsound";
    if skip(name) {
        return;
    }
    let w = Work::new("killed");
    // The command is a child of stoop, and so is the tracer's `sudo`. Only that tracer is
    // signalled, never another process with the same name.
    let out = w.stoop(
        "cat in.txt >/dev/null; \
         tracer=$(pgrep -P $PPID -x sudo); sudo -n kill -INT $tracer; sleep 2; \
         printf run >> runs.log; exit 5",
        "1",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert_eq!(fs::read_to_string(w.dir.join("runs.log")).unwrap(), "run");
    assert!(
        stderr.contains("DTrace diagnostic verdict: UNSOUND"),
        "{stderr}"
    );
    w.no_proof_written();
}

#[test]
fn an_opt_in_without_passwordless_sudo_says_unknown_and_runs_the_command_once() {
    if tracer_usable() {
        eprintln!("skipped: `sudo -n dtrace` works here, so the no-sudo path cannot run");
        return;
    }
    let w = Work::new("nosudo");
    let out = w.stoop("printf run >> runs.log; exit 4", "1");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert_eq!(fs::read_to_string(w.dir.join("runs.log")).unwrap(), "run");
    assert!(
        stderr.contains("DTrace diagnostic verdict: UNKNOWN"),
        "{stderr}"
    );
    w.no_proof_written();
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
