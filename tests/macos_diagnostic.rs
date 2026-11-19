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
    // 2000 lookups that fail, 1000 that succeed, 300 processes spawned and exec'd, a grandchild,
    // and writes into the repository. Pids are not reused here; the pid-reuse rule is a unit test.
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
    // The known result: DTrace reported no loss or error at all. The run is unsound for one
    // reason only: the system's loader looks files up through directory descriptors, which the
    // tracer does not follow yet (the spike's gap two). Nothing else makes it unsound.
    assert!(
        stderr.contains("DTrace diagnostic verdict: UNSOUND ("),
        "{stderr}"
    );
    assert!(
        stderr.contains(" 0 tracer loss or error line(s)"),
        "{stderr}"
    );
    for line in stderr
        .lines()
        .filter(|line| line.starts_with("stoop: DTrace diagnostic UNSOUND: "))
    {
        assert!(line.contains("directory descriptor"), "{line}");
    }
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
    // Both structural reasons are asserted, not just the verdict: the tracer died before the
    // command's exit and never reported a clean stop. The dyld reasons cannot explain either.
    assert!(
        stderr.contains("stoop: DTrace diagnostic UNSOUND: the tracer did not report a clean stop"),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "stoop: DTrace diagnostic UNSOUND: the command's exit was not seen by the tracer"
        ),
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

#[test]
fn a_switch_value_that_is_not_utf8_is_not_an_opt_in() {
    use std::os::unix::ffi::OsStrExt;
    let w = Work::new("nonutf8");
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args([
            "run", "--root", ".", "--key", "t", "--", "/bin/sh", "-c", "exit 4",
        ])
        .current_dir(&w.dir)
        .env("STOOP_STORE", w.dir.join("store"))
        .env(
            "STOOP_DTRACE_DIAGNOSTIC",
            std::ffi::OsStr::from_bytes(b"\xff"),
        )
        .env_remove("STOOP_OFF")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(!stderr.contains("DTrace"), "{stderr}");
}

/// A program that starts `/bin/cat in.txt` with posix_spawn in the directory it is given. The
/// child changes directory through a file action, so no chdir call shows the change.
const POSIX_CHDIR: &str = r#"#include <spawn.h>
#include <sys/wait.h>
extern char **environ;
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) return 3;
    if (posix_spawn_file_actions_addchdir_np(&actions, argv[1]) != 0) return 4;
    char *child_argv[] = {"cat", "in.txt", NULL};
    pid_t pid;
    if (posix_spawn(&pid, "/bin/cat", &actions, NULL, child_argv, environ) != 0) return 5;
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return 6;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 7;
}
"#;

#[test]
fn a_child_started_by_posix_spawn_in_another_directory_makes_the_run_unsound() {
    let name = "a_child_started_by_posix_spawn_in_another_directory_makes_the_run_unsound";
    if skip(name) {
        return;
    }
    let w = Work::new("posixcwd");
    fs::create_dir(w.dir.join("sub")).unwrap();
    fs::write(w.dir.join("sub").join("in.txt"), "inner").unwrap();
    fs::write(w.dir.join("spawn.c"), POSIX_CHDIR).unwrap();
    let built = Command::new("cc")
        .arg(w.dir.join("spawn.c"))
        .arg("-o")
        .arg(w.dir.join("spawn"))
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let out = w.stoop("./spawn sub", "list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("stoop: DTrace diagnostic verdict: UNSOUND ("),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "stoop: DTrace diagnostic UNSOUND: a relative path was used where the working directory is unknown"
        ),
        "{stderr}"
    );
    w.no_proof_written();
}

#[test]
fn a_newline_in_a_file_name_makes_the_run_unsound_and_lists_no_half_of_it() {
    let name = "a_newline_in_a_file_name_makes_the_run_unsound_and_lists_no_half_of_it";
    if skip(name) {
        return;
    }
    let w = Work::new("newline");
    let out = w.stoop("printf x > \"$(printf 'a\\nb')\"; exit 6", "list");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(6), "{stderr}");
    assert!(
        w.dir.join("a\nb").exists(),
        "the command did not create its file"
    );
    assert!(
        stderr.contains("stoop: DTrace diagnostic verdict: UNSOUND ("),
        "{stderr}"
    );
    assert!(
        stderr.contains(
            "stoop: DTrace diagnostic UNSOUND: a path did not match the length the tracer gave it"
        ),
        "{stderr}"
    );
    assert!(
        !listed(&stderr, "wrote").contains(&w.path("a")),
        "the first half of a split path was listed as written: {stderr}"
    );
    w.no_proof_written();
}
