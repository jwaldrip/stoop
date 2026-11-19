//! Windows runs a command untraced: stoop never records, never skips, and passes the command's
//! exit code, working directory, environment and output through.
#![cfg(windows)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

struct Work {
    dir: PathBuf,
}

impl Work {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("stoop-win-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        Self { dir }
    }

    fn stoop(&self, args: &[&str]) -> Output {
        self.stoop_in(&self.dir, args)
    }

    fn stoop_in(&self, cwd: &std::path::Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .args(args)
            .current_dir(cwd)
            .env("STOOP_STORE", self.dir.join("store"))
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_FULL")
            .env_remove("GITHUB_ACTIONS")
            .output()
            .unwrap()
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn the_exit_code_comes_through_and_the_run_says_it_was_not_traced() {
    let w = Work::new("exit");
    let out = w.stoop(&["run", "--root", ".", "--", "cmd", "/c", "exit", "3"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{stderr}");
    assert!(stderr.contains("no compatible tracer"), "{stderr}");
    assert!(stderr.contains("not traced"), "{stderr}");
    assert!(
        !w.dir.join("store").join("proofs").exists(),
        "a proof was written"
    );
}

#[test]
fn an_ntstatus_exit_code_is_the_code_stoop_exits_with() {
    let w = Work::new("ntstatus");
    // 0xC0000005, an access violation, as a signed 32-bit exit code.
    let out = w.stoop(&[
        "run",
        "--root",
        ".",
        "--",
        "cmd",
        "/c",
        "exit",
        "-1073741819",
    ]);
    assert_eq!(
        out.status.code(),
        Some(0xC000_0005_u32 as i32),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_run_that_passes_is_run_again_because_nothing_was_recorded() {
    let w = Work::new("again");
    let counter = w.dir.join("count.txt");
    let script = format!("echo x>> \"{}\"", counter.display());
    for _ in 0..2 {
        let out = w.stoop(&["run", "--root", ".", "--", "cmd", "/c", &script]);
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    }
    let lines = fs::read_to_string(&counter).unwrap().lines().count();
    assert_eq!(lines, 2, "the second run was skipped");
}

#[test]
fn explain_exits_1_and_says_the_command_is_not_traced() {
    let w = Work::new("explain");
    let out = w.stoop(&["explain", "--root", ".", "--", "cmd", "/c", "echo", "hi"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("not traced"), "{stderr}");
}

#[test]
fn the_working_directory_environment_and_output_pass_through() {
    let w = Work::new("stdio");
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args([
            "run",
            "--root",
            ".",
            "--",
            "cmd",
            "/c",
            "echo %STOOP_WIN_VAR%& cd",
        ])
        .current_dir(w.dir.join("sub"))
        .env("STOOP_STORE", w.dir.join("store"))
        .env("STOOP_WIN_VAR", "hello-from-env")
        .env_remove("STOOP_OFF")
        .output()
        .unwrap();
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(stdout.contains("hello-from-env"), "{stdout}");
    assert!(stdout.to_lowercase().contains("sub"), "{stdout}");
}

#[test]
fn a_missing_command_exits_127() {
    let w = Work::new("missing");
    let out = w.stoop(&["run", "--root", ".", "--", "stoop-no-such-command-anywhere"]);
    assert_eq!(out.status.code(), Some(127), "{}", text(&out.stderr));
}

#[test]
fn stoop_sh_runs_the_script_under_bash_and_returns_its_status() {
    if Command::new("bash").arg("--version").output().is_err() {
        eprintln!("skipped: bash is not on PATH here");
        return;
    }
    let w = Work::new("sh");
    let script = w.dir.join("step.sh");
    fs::write(&script, "echo ran-under-bash\nexit 4\n").unwrap();
    let out = w.stoop(&["sh", script.to_str().unwrap()]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{stderr}");
    assert!(text(&out.stdout).contains("ran-under-bash"), "{stderr}");
}

#[test]
fn mcp_and_the_status_descriptor_are_refused_plainly() {
    let w = Work::new("mcp");
    let out = w.stoop(&["mcp"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(text(&out.stderr).contains("not available on Windows"));
    let out = w.stoop(&[
        "run",
        "--root",
        ".",
        "--status-fd",
        "3",
        "--",
        "cmd",
        "/c",
        "exit",
        "0",
    ]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("not available on Windows"));
}
