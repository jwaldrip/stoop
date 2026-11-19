#![cfg(unix)]
//! The server's lifetime and its argument contract. A run never outlives the server: end of
//! input, SIGTERM, SIGINT, SIGHUP and SIGKILL all stop the command. A cancelled request that is
//! still queued is never answered. Argument mistakes follow the protocol's error rules, and
//! error text is escaped exactly once.

mod common;

use common::*;
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Start a run that writes its pid to `pidfile` and then sleeps for a minute. `exec` keeps the pid.
/// Returns the pid once the command has started.
fn start_sleeping_run(m: &mut Mcp, id: i64, pidfile: &Path) -> u32 {
    let script = format!("echo $$ > {}; exec sleep 60", pidfile.display());
    m.send(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": modern(tool_call(
            "run",
            json!({"argv": ["sh", "-c", script], "timeout_s": 120}),
        )),
    }));
    let text = wait_for_file(pidfile, Duration::from_secs(20)).expect("the command started");
    text.trim().parse().expect("the command wrote its pid")
}

#[test]
fn stdin_ending_mid_call_cancels_it_and_leaves_nothing_running() {
    let dir = temp_dir("life-eof");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    let started = Instant::now();
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0), "stdin ended: the server exits 0");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the exit took {:?}",
        started.elapsed()
    );
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "the command outlived the server"
    );
    let answered = assert_protocol_only(&lines)
        .iter()
        .any(|message| message["id"] == json!(1));
    assert!(!answered, "a cancelled call was answered: {lines:?}");
}

#[test]
fn sigterm_stops_the_command_and_exits() {
    let dir = temp_dir("life-term");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    signal(m.pid(), libc::SIGTERM);
    let (code, _) = m.finish();
    assert_eq!(
        code,
        Some(128 + libc::SIGTERM),
        "the server exits with the signal status"
    );
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "SIGTERM left the command running"
    );
}

#[test]
fn sighup_stops_the_command_and_exits() {
    let dir = temp_dir("life-hup");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    signal(m.pid(), libc::SIGHUP);
    let (code, _) = m.finish();
    assert_eq!(code, Some(128 + libc::SIGHUP));
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "SIGHUP left the command running"
    );
}

#[test]
fn sigkill_of_the_server_still_stops_the_command() {
    // SIGKILL cannot be caught. The watchdog sees the heartbeat close and kills the group.
    let dir = temp_dir("life-kill");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    signal(m.pid(), libc::SIGKILL);
    let (code, _) = m.finish();
    assert_eq!(code, None, "the server was killed by a signal");
    assert!(
        wait_gone(pid, Duration::from_secs(10)),
        "SIGKILL of the server left the command running"
    );
}

#[test]
fn cancelling_a_run_kills_the_commands_whole_process_group() {
    let dir = temp_dir("life-group");
    let childfile = dir.join("child.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    // The command starts a background sleep in its own group and waits for it.
    let script = format!("sleep 60 & echo $! > {}; wait", childfile.display());
    m.send(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": modern(tool_call(
            "run",
            json!({"argv": ["sh", "-c", script], "timeout_s": 120}),
        )),
    }));
    let child: u32 = wait_for_file(&childfile, Duration::from_secs(20))
        .expect("the background process started")
        .trim()
        .parse()
        .expect("its pid");
    m.notify(
        "notifications/cancelled",
        json!({"requestId": 1, "reason": "test"}),
    );
    assert!(
        wait_gone(child, Duration::from_secs(5)),
        "the background process survived the cancellation"
    );
    let (code, _) = m.finish();
    assert_eq!(code, Some(0));
}

#[test]
fn a_queued_request_cancelled_before_its_turn_is_never_answered() {
    let dir = temp_dir("life-queued");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    // Queued behind the run, then cancelled before its turn.
    m.send(
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": modern(json!({}))}),
    );
    std::thread::sleep(Duration::from_millis(200));
    m.notify(
        "notifications/cancelled",
        json!({"requestId": 2, "reason": "test"}),
    );
    m.notify(
        "notifications/cancelled",
        json!({"requestId": 1, "reason": "test"}),
    );
    let pong = m.call(json!(3), "ping", json!({}));
    assert_eq!(pong["id"], json!(3), "{pong}");
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0));
    let messages = assert_protocol_only(&lines);
    assert!(
        !messages.iter().any(|message| message["id"] == json!(2)),
        "the cancelled queued request was answered: {lines:?}"
    );
    assert!(wait_gone(pid, Duration::from_secs(5)));
}

#[test]
fn stdin_closing_mid_call_answers_nothing_queued() {
    // A request queued behind a run is dropped when stdin ends. After the run is cancelled,
    // nothing is answered.
    let dir = temp_dir("life-eof-queued");
    let pidfile = dir.join("pid.txt");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let pid = start_sleeping_run(&mut m, 1, &pidfile);
    m.send(
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": modern(json!({}))}),
    );
    let (code, lines) = m.finish();
    assert_eq!(code, Some(0), "stdin ended: the server exits 0");
    assert!(
        wait_gone(pid, Duration::from_secs(5)),
        "the command outlived the server"
    );
    let messages = assert_protocol_only(&lines);
    let answered: Vec<&Value> = messages
        .iter()
        .filter(|message| message.get("id").is_some())
        .collect();
    assert!(
        answered.is_empty(),
        "a request was answered after stdin ended: {lines:?}"
    );
}

#[test]
fn a_command_cannot_read_the_protocol_stream() {
    // The command reads stdin. It gets an empty stream, so the next protocol message is still
    // answered, and the output carries only what the command printed.
    let dir = temp_dir("life-stdin");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call(
            "run",
            json!({"argv": ["sh", "-c", "cat; echo done"], "timeout_s": 30}),
        )),
    );
    assert_eq!(
        result(&r)["structuredContent"]["stdout"]["text"],
        "done\n",
        "{r}"
    );
    let pong = m.call(json!(2), "ping", json!({}));
    assert_eq!(pong["id"], json!(2), "{pong}");
    m.finish();
}

#[test]
fn outside_a_repository_without_root_the_server_refuses_to_start() {
    let dir = temp_dir("life-no-git");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.arg("mcp").current_dir(&dir).stdin(Stdio::null());
    clear_env(&mut cmd);
    let out = cmd.output().expect("stoop runs");
    assert_eq!(
        out.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--root"), "{err}");
    assert!(out.stdout.is_empty(), "a refused start wrote to stdout");
}

#[test]
fn a_non_object_params_value_is_invalid_params_with_the_request_id() {
    let dir = temp_dir("life-params");
    let mut m = Mcp::spawn(&[], &dir);
    m.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": "hello"}));
    let r = m.next_message(Duration::from_secs(10)).expect("an error");
    assert_eq!(error_code(&r), -32602, "{r}");
    assert_eq!(r["id"], json!(1));
    m.finish();
}

#[test]
fn an_unknown_argument_name_is_invalid_params() {
    let dir = temp_dir("life-unknown-arg");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("guide", json!({"topik": "run"}))),
    );
    assert_eq!(error_code(&r), -32602, "{r}");
    assert!(
        r["error"]["message"].as_str().unwrap().contains("topik"),
        "{r}"
    );
    m.finish();
}

#[test]
fn a_tool_error_is_escaped_once() {
    // The topic holds a literal "%0A" and a workflow-command separator. The text shows each
    // escaped once: "%250A" for the literal percent sequence, never "%25250A".
    let dir = temp_dir("life-escape-once");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("guide", json!({"topic": "x::error::y%0A"}))),
    );
    let res = result(&r);
    assert_eq!(res["isError"], true, "{r}");
    let text = text_of(res);
    assert!(
        text.contains("named x%3A%3Aerror%3A%3Ay%250A;"),
        "the topic was not escaped exactly once: {text}"
    );
    assert!(
        !text.contains("%25250A"),
        "the text was escaped twice: {text}"
    );
    m.finish();
}

#[test]
fn a_bidirectional_character_in_an_error_is_escaped() {
    let dir = temp_dir("life-bidi");
    let mut m = Mcp::spawn(&[], &dir);
    let r = m.call(
        json!(1),
        "tools/call",
        modern(tool_call("guide", json!({"topic": "\u{202e}reversed"}))),
    );
    let text = text_of(result(&r));
    assert!(
        !text.contains('\u{202e}'),
        "a raw bidi character reached the text: {text}"
    );
    assert!(text.contains("\\u{202e}"), "{text}");
    m.finish();
}

#[cfg(target_os = "linux")]
#[test]
fn a_root_that_is_not_utf8_is_refused_at_start() {
    use std::os::unix::ffi::OsStrExt;
    // APFS refuses a directory name that is not UTF-8, so this runs on Linux only.
    let base = temp_dir("life-utf8-root");
    let root = base.join(std::ffi::OsStr::from_bytes(b"root-\xff"));
    std::fs::create_dir(&root).expect("a directory whose name is not UTF-8");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.args(["mcp", "--root"]).arg(&root).stdin(Stdio::null());
    clear_env(&mut cmd);
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("not valid UTF-8"), "{err}");
}

#[cfg(target_os = "linux")]
#[test]
fn a_git_root_whose_path_is_not_utf8_is_refused_at_start() {
    use std::os::unix::ffi::OsStrExt;
    let base = temp_dir("life-utf8-git");
    let project = base.join(std::ffi::OsStr::from_bytes(b"repo-\xff"));
    std::fs::create_dir_all(project.join("sub")).expect("a directory whose name is not UTF-8");
    git(&project, &["init", "-q"]);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.arg("mcp")
        .current_dir(project.join("sub"))
        .stdin(Stdio::null());
    clear_env(&mut cmd);
    let out = cmd.output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{err}");
    assert!(err.contains("not valid UTF-8"), "{err}");
}
