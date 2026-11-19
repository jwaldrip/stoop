//! Helpers for the MCP tests: drive the real `stoop mcp` over stdio, build throwaway
//! repositories, and inspect processes. Each test file includes this module with `mod common;`.
#![allow(dead_code)]

use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The newest revision the server speaks. It is stateless: every request carries its version.
pub const MODERN: &str = "2026-07-28";

/// Variables that would change what stoop does. Tests start from none of them.
const CLEARED: [&str; 11] = [
    "STOOP_STORE",
    "STOOP_SYNC",
    "STOOP_SYNC_WRITE",
    "STOOP_FULL",
    "STOOP_OFF",
    "STOOP_MAX_AGE",
    "STOOP_PASS_ENV",
    "STOOP_ENV_SALT",
    "STOOP_MATRIX",
    "GITHUB_ACTIONS",
    "RUNNER_TEMP",
];

pub fn clear_env(cmd: &mut Command) {
    for name in CLEARED {
        cmd.env_remove(name);
    }
}

/// A fresh, empty directory under the system temp folder.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("stoop-mcp-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=stoop-test",
            "-c",
            "user.email=stoop-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

/// The standard output of a git command in `dir`.
pub fn git_output(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("git runs");
    assert!(out.status.success(), "git {args:?} failed");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A git repository whose first commit holds `files` (relative path, body).
pub fn repo(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = temp_dir(name);
    git(&dir, &["init", "-q"]);
    for (path, body) in files {
        let p = dir.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }
    git(&dir, &["add", "-A"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "fixture"]);
    dir
}

/// Run the stoop CLI in `dir`. Returns (exit code, stderr).
pub fn stoop(dir: &Path, args: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.args(args).current_dir(dir).stdin(Stdio::null());
    clear_env(&mut cmd);
    let out = cmd.output().expect("stoop runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The `_meta` block every modern request carries.
pub fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientInfo": {"name": "stoop-test", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    })
}

/// Params for a modern request: `params` with the required `_meta` added.
pub fn modern(mut params: Value) -> Value {
    params["_meta"] = meta();
    params
}

/// `tools/call` params.
pub fn tool_call(name: &str, arguments: Value) -> Value {
    json!({"name": name, "arguments": arguments})
}

/// The `result` of a response, or a panic that shows the whole error.
pub fn result(response: &Value) -> &Value {
    response
        .get("result")
        .unwrap_or_else(|| panic!("expected a result, got {response}"))
}

pub fn error_code(response: &Value) -> i64 {
    response["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("expected an error, got {response}"))
}

/// The first text content item of a tool result.
pub fn text_of(tool_result: &Value) -> String {
    tool_result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content in {tool_result}"))
        .to_string()
}

/// Whether `dir` or one of its ancestors is a repository.
pub fn has_git_ancestor(dir: &Path) -> bool {
    dir.ancestors().any(|d| d.join(".git").exists())
}

/// The state letters `ps` reports for a process, or None when it does not exist.
pub fn process_state(pid: u32) -> Option<String> {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if state.is_empty() {
        None
    } else {
        Some(state)
    }
}

/// True once a process is gone or a zombie: nothing runs for it any more.
pub fn process_gone(pid: u32) -> bool {
    match process_state(pid) {
        None => true,
        Some(state) => state.starts_with('Z'),
    }
}

/// Wait up to `within` for a process to stop running. Returns whether it did.
pub fn wait_gone(pid: u32, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if process_gone(pid) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait up to `within` for a file to appear, and return its text.
pub fn wait_for_file(path: &Path, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    loop {
        if let Ok(text) = fs::read_to_string(path) {
            if !text.trim().is_empty() {
                return Some(text);
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Send a signal to a process.
#[cfg(unix)]
pub fn signal(pid: u32, sig: i32) {
    // SAFETY: kill only sends a signal to a process the test started.
    unsafe {
        libc::kill(pid as i32, sig);
    }
}

/// A running `stoop mcp` with its stdio attached.
pub struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Arc<Mutex<String>>,
    /// Every line the server wrote to stdout, verbatim.
    pub seen: Vec<String>,
    queued: VecDeque<Value>,
}

impl Mcp {
    /// Start `stoop mcp <args>` in `dir`. When `dir` has no repository above it and no `--root`
    /// is given, `--root dir` is added, so a plain temp folder can still be used.
    pub fn spawn(args: &[&str], dir: &Path) -> Mcp {
        Self::spawn_env(args, dir, &[])
    }

    /// As `spawn`, with extra environment variables for the server.
    pub fn spawn_env(args: &[&str], dir: &Path, env: &[(&str, &str)]) -> Mcp {
        let mut all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        if !all.iter().any(|a| a == "--root") && !has_git_ancestor(dir) {
            all.push("--root".into());
            all.push(dir.display().to_string());
        }
        Self::start(&all, dir, env)
    }

    /// Start with exactly `args`: the server's own rules apply, including refusing to start
    /// outside a repository without `--root`.
    pub fn spawn_raw(args: &[&str], dir: &Path) -> Mcp {
        let all: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        Self::start(&all, dir, &[])
    }

    fn start(all: &[String], dir: &Path, env: &[(&str, &str)]) -> Mcp {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
        cmd.arg("mcp")
            .args(all)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        clear_env(&mut cmd);
        for (name, value) in env {
            cmd.env(name, value);
        }
        let mut child = cmd.spawn().expect("stoop mcp starts");
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        let mut err = child.stderr.take().unwrap();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = err.read_to_end(&mut bytes);
            *sink.lock().unwrap() = String::from_utf8_lossy(&bytes).into_owned();
        });
        let stdin = child.stdin.take();
        Mcp {
            child,
            stdin,
            lines,
            stderr,
            seen: Vec::new(),
            queued: VecDeque::new(),
        }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn stderr(&self) -> String {
        self.stderr.lock().unwrap().clone()
    }

    /// Write one message as one line.
    pub fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_vec(message).unwrap();
        line.push(b'\n');
        self.write(&line);
    }

    /// Write raw bytes followed by a newline, for malformed input.
    pub fn send_raw(&mut self, bytes: &[u8]) {
        let mut line = bytes.to_vec();
        line.push(b'\n');
        self.write(&line);
    }

    fn write(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin is still open");
        stdin.write_all(bytes).expect("write to stoop mcp");
        stdin.flush().expect("flush to stoop mcp");
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}));
    }

    /// Send a request and wait for its response.
    pub fn call(&mut self, id: Value, method: &str, params: Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        self.response(&id)
    }

    fn record(&mut self, line: String) {
        self.seen.push(line.clone());
        let message = serde_json::from_str(&line).unwrap_or_else(|_| json!({"__not_json": line}));
        self.queued.push_back(message);
    }

    /// The response to request `id`. Other messages stay queued for `next_message`.
    pub fn response(&mut self, id: &Value) -> Value {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let found = self.queued.iter().position(|m| {
                m.get("id") == Some(id) && (m.get("result").is_some() || m.get("error").is_some())
            });
            if let Some(pos) = found {
                return self.queued.remove(pos).unwrap();
            }
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "no response to {id}; stdout so far:\n{}",
                self.seen.join("\n")
            );
            match self
                .lines
                .recv_timeout(left.min(Duration::from_millis(100)))
            {
                Ok(line) => self.record(line),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => panic!(
                    "stoop mcp exited before answering {id}; stdout:\n{}",
                    self.seen.join("\n")
                ),
            }
        }
    }

    /// The next message the server writes, or `None` after `within`.
    pub fn next_message(&mut self, within: Duration) -> Option<Value> {
        if let Some(m) = self.queued.pop_front() {
            return Some(m);
        }
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.record(line);
                    if let Some(m) = self.queued.pop_front() {
                        return Some(m);
                    }
                }
                Err(_) => return None,
            }
        }
    }

    /// Close stdin, wait for the server to exit and return its exit code and every stdout line.
    pub fn finish(mut self) -> (Option<i32>, Vec<String>) {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match self.lines.recv_timeout(Duration::from_millis(50)) {
                Ok(line) => self.record(line),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() > deadline {
                break;
            }
        }
        let code = loop {
            match self.child.try_wait().unwrap() {
                Some(status) => break status.code(),
                None if Instant::now() > deadline => {
                    let _ = self.child.kill();
                    break None;
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        (code, self.seen)
    }
}

/// Every stdout line must be one JSON-RPC 2.0 object. Returns the parsed messages.
pub fn assert_protocol_only(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .map(|line| {
            let value: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {line:?}"));
            assert_eq!(value["jsonrpc"], "2.0", "not a JSON-RPC message: {line:?}");
            value
        })
        .collect()
}
