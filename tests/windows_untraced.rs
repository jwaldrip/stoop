//! The Windows run path without tracing. A command run by `stoop run` keeps its exit code (a crash
//! code included), its standard streams, its working directory and its environment. `explain` says
//! the command is not traced, and a stoop that dies takes its command's processes with it.

#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A scratch directory, removed when the test ends.
struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "stoop-winrun-{}-{}-{name}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Dir(path)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stoop(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn a_root_exit_code_is_returned_unchanged() {
    let dir = Dir::new("exit");
    let out = stoop(&dir.0, &["run", "--", "cmd", "/c", "exit 3"]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not traced"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_crash_code_is_returned_unchanged() {
    // 0xC0000005 is an access violation. Windows reports it as a 32-bit status, which stoop passes on.
    let dir = Dir::new("crash");
    let out = stoop(
        &dir.0,
        &[
            "run",
            "--",
            "powershell",
            "-NoProfile",
            "-Command",
            "exit -1073741819",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(-1073741819),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn the_command_writes_to_the_inherited_standard_streams() {
    let dir = Dir::new("streams");
    let out = stoop(
        &dir.0,
        &["run", "--", "cmd", "/c", "echo to-out & echo to-err 1>&2"],
    );
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("to-out"),
        "{}",
        text(&out.stdout)
    );
    assert!(
        text(&out.stderr).contains("to-err"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn the_command_starts_in_the_callers_directory() {
    let dir = Dir::new("cwd");
    let sub = dir.0.join("sub");
    fs::create_dir_all(&sub).unwrap();
    let out = stoop(&sub, &["run", "--", "cmd", "/c", "cd"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).trim_end().ends_with("sub"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn the_callers_environment_reaches_the_command() {
    let dir = Dir::new("env");
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&dir.0)
        .env("WINSLICE_VALUE", "from-the-caller")
        .args(["run", "--", "cmd", "/c", "echo %WINSLICE_VALUE%"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("from-the-caller"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn explain_says_the_command_is_not_traced() {
    let dir = Dir::new("explain");
    let out = stoop(&dir.0, &["explain", "--", "cmd", "/c", "echo hi"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("not traced"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn sh_mode_returns_the_script_status() {
    let dir = Dir::new("sh");
    let script = dir.0.join("step.sh");
    fs::write(&script, "exit 4\n").unwrap();
    let out = stoop(&dir.0, &["sh", script.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out.stderr));
}

#[test]
fn killing_stoop_ends_the_command_tree() {
    let dir = Dir::new("kill");
    let pid_file = dir.0.join("pid");
    let script = format!(
        "[System.IO.File]::WriteAllText('{}', $PID); Start-Sleep -Seconds 300",
        pid_file.display()
    );
    let mut stoop_child = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&dir.0)
        .args(["run", "--", "powershell", "-NoProfile", "-Command", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = wait_for_pid(&pid_file);
    stoop_child.kill().unwrap();
    stoop_child.wait().unwrap();
    assert!(
        wait_until_gone(pid, Duration::from_secs(30)),
        "process {pid} survived the stoop that started it"
    );
}

/// The PID the command wrote, once it has started.
fn wait_for_pid(path: &Path) -> u32 {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(pid) = fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse().ok())
        {
            return pid;
        }
        assert!(Instant::now() < deadline, "the command never started");
        thread::sleep(Duration::from_millis(100));
    }
}

/// Whether a process with this PID is still running.
fn wait_until_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        let listed = Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .unwrap();
        if !text(&listed.stdout).contains(&pid.to_string()) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(250));
    }
}
