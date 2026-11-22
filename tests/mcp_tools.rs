#![cfg(unix)]
//! The MCP tools on real repositories, through the real `stoop mcp` binary.
//! Recorded-proof behaviour needs tracing, so those cases only run on Linux.

mod common;

use common::*;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const WORKFLOW: &str = "name: ci\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n";

/// Every file under `dir` (except `.git`) with its size and modification time.
fn snapshot(dir: &Path) -> Vec<(PathBuf, u64, std::time::SystemTime)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(PathBuf, u64, std::time::SystemTime)>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|n| n == ".git") {
                continue;
            }
            let meta = entry.metadata().unwrap();
            out.push((
                path.strip_prefix(root).unwrap().to_path_buf(),
                meta.len(),
                meta.modified().unwrap(),
            ));
            if meta.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

fn call(m: &mut Mcp, id: i64, name: &str, arguments: Value) -> Value {
    m.call(json!(id), "tools/call", modern(tool_call(name, arguments)))
}

fn sc(tool_result: &Value) -> &Value {
    &tool_result["structuredContent"]
}

#[test]
fn explain_on_a_fresh_repo_says_run_and_creates_nothing() {
    let dir = repo("tools-explain-fresh", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let before = snapshot(&dir);
    let r = call(
        &mut m,
        1,
        "explain",
        json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
    );
    let res = result(&r);
    assert_eq!(res["isError"], false, "{r}");
    assert_eq!(sc(res)["decision"], "run");
    assert_eq!(sc(res)["exit_code"], 1);
    assert!(sc(res)["key"].as_str().unwrap().starts_with("sh-"));
    assert!(!dir.join(".stoop").exists(), "explain created a store");
    assert_eq!(snapshot(&dir), before, "explain changed the repository");
    m.finish();
}

#[test]
fn explain_reports_whether_tracing_is_available_on_this_platform() {
    let dir = repo("tools-explain-traced", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(&mut m, 1, "explain", json!({"argv": ["sh", "-c", "true"]}));
    let traced = sc(result(&r))["traced"].as_bool().unwrap();
    assert_eq!(traced, cfg!(target_os = "linux"), "{r}");
    if !traced {
        assert!(
            sc(result(&r))["reason"]
                .as_str()
                .unwrap()
                .contains("not traced"),
            "{r}"
        );
    }
    m.finish();
}

#[test]
fn list_proofs_on_a_fresh_repo_is_empty() {
    let dir = repo("tools-list-empty", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(&mut m, 1, "list_proofs", json!({}));
    assert_eq!(result(&r)["isError"], false, "{r}");
    assert_eq!(sc(result(&r))["proofs"], json!([]));
    assert_eq!(sc(result(&r))["jobs"], json!([]));
    m.finish();
}

#[test]
fn forget_of_an_unknown_key_is_idempotent_and_not_an_error() {
    let dir = repo("tools-forget-unknown", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(&mut m, 1, "forget", json!({"key": "no-such-proof"}));
    assert_eq!(result(&r)["isError"], false, "{r}");
    assert_eq!(sc(result(&r))["removed"], false);
    m.finish();
}

#[test]
fn plan_reads_the_workflow_at_the_revision() {
    let dir = repo("tools-plan", &[(".github/workflows/ci.yml", WORKFLOW)]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(
        &mut m,
        1,
        "plan",
        json!({"workflow": ".github/workflows/ci.yml"}),
    );
    assert_eq!(result(&r)["isError"], false, "{r}");
    assert_eq!(sc(result(&r))["schema"], "stoop.plan/1");
    assert_eq!(sc(result(&r))["path"], ".github/workflows/ci.yml");
    assert!(sc(result(&r))["jobs"].is_array());
    m.finish();
}

#[test]
fn plan_refuses_a_revision_that_starts_with_a_dash() {
    // git would read such a revision as an option (--output= writes a file), so the server
    // refuses it before any process starts. The plan command refuses it too.
    let dir = repo("tools-plan-rev", &[(".github/workflows/ci.yml", WORKFLOW)]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(
        &mut m,
        1,
        "plan",
        json!({"workflow": ".github/workflows/ci.yml", "rev": "--output=pwned.txt"}),
    );
    assert_eq!(result(&r)["isError"], true, "{r}");
    assert!(text_of(result(&r)).contains("rev"), "{r}");
    m.finish();
}

#[test]
fn plan_refuses_a_workflow_path_that_leaves_the_repository() {
    let dir = repo("tools-plan-path", &[(".github/workflows/ci.yml", WORKFLOW)]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(&mut m, 1, "plan", json!({"workflow": "../ci.yml"}));
    assert_eq!(result(&r)["isError"], true, "{r}");
    let absolute = call(&mut m, 2, "plan", json!({"workflow": "/etc/passwd"}));
    assert_eq!(result(&absolute)["isError"], true, "{absolute}");
    m.finish();
}

#[test]
fn guide_returns_every_section_and_one_section_by_topic() {
    let dir = repo("tools-guide", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let all = call(&mut m, 1, "guide", json!({}));
    let sections = sc(result(&all))["sections"].as_array().unwrap().clone();
    assert!(sections.len() >= 6, "{sections:?}");
    for s in &sections {
        assert!(!s["markdown"].as_str().unwrap().is_empty());
        assert!(s["id"]
            .as_str()
            .unwrap()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));
    }
    let first = sections[0]["id"].as_str().unwrap().to_string();
    let one = call(&mut m, 2, "guide", json!({"topic": first.clone()}));
    let picked = sc(result(&one))["sections"].as_array().unwrap();
    assert_eq!(picked.len(), 1, "{one}");
    assert_eq!(picked[0]["id"], first.as_str());
    let unknown = call(&mut m, 3, "guide", json!({"topic": "no-such-section-xyz"}));
    assert_eq!(result(&unknown)["isError"], true, "{unknown}");
    assert!(
        text_of(result(&unknown)).contains(&first),
        "the error lists the valid topics"
    );
    m.finish();
}

#[test]
fn run_is_absent_without_allow_run_and_returns_exit_code_and_both_streams_with_it() {
    let dir = repo("tools-run-streams", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let r = call(
        &mut m,
        1,
        "run",
        json!({"argv": ["sh", "-c", "echo out; echo err >&2; exit 3"]}),
    );
    let res = result(&r);
    assert_eq!(
        res["isError"], true,
        "a failing command is a tool error: {r}"
    );
    assert_eq!(sc(res)["exit_code"], 3);
    assert!(sc(res)["stdout"]["text"].as_str().unwrap().contains("out"));
    assert!(sc(res)["stderr"]["text"].as_str().unwrap().contains("err"));
    assert_eq!(sc(res)["timed_out"], false);
    m.finish();
}

#[test]
fn run_truncates_large_output_and_reports_the_true_total() {
    let dir = repo("tools-run-cap", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let r = call(
        &mut m,
        1,
        "run",
        json!({"argv": ["sh", "-c", "head -c 300000 /dev/zero | tr '\\0' a"]}),
    );
    let out = &sc(result(&r))["stdout"];
    assert_eq!(out["bytes"], 300_000, "{r}");
    assert_eq!(out["truncated"], true);
    assert!(
        out["text"].as_str().unwrap().len() < 300_000,
        "the text was not capped"
    );
    m.finish();
}

#[test]
fn run_times_out_kills_the_command_and_says_so() {
    let dir = repo("tools-run-timeout", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let started = Instant::now();
    let r = call(
        &mut m,
        1,
        "run",
        json!({"argv": ["sleep", "30"], "timeout_s": 1}),
    );
    assert_eq!(result(&r)["isError"], true, "{r}");
    assert_eq!(sc(result(&r))["timed_out"], true);
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "the timeout did not stop the command"
    );
    m.finish();
}

#[test]
fn run_rejects_a_timeout_outside_its_range() {
    let dir = repo("tools-run-range", &[("in.txt", "one\n")]);
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let r = call(&mut m, 1, "run", json!({"argv": ["true"], "timeout_s": 0}));
    assert_eq!(result(&r)["isError"], true, "{r}");
    let big = call(
        &mut m,
        2,
        "run",
        json!({"argv": ["true"], "timeout_s": 99999}),
    );
    assert_eq!(result(&big)["isError"], true, "{big}");
    m.finish();
}

#[test]
fn read_only_tools_do_not_write_the_repository() {
    let dir = repo(
        "tools-readonly",
        &[("in.txt", "one\n"), (".github/workflows/ci.yml", WORKFLOW)],
    );
    let mut m = Mcp::spawn(&[], &dir);
    let before = snapshot(&dir);
    call(
        &mut m,
        1,
        "explain",
        json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
    );
    call(&mut m, 2, "list_proofs", json!({}));
    call(
        &mut m,
        3,
        "plan",
        json!({"workflow": ".github/workflows/ci.yml"}),
    );
    call(&mut m, 4, "guide", json!({}));
    m.finish();
    assert_eq!(
        snapshot(&dir),
        before,
        "a read-only tool changed the repository"
    );
}

#[test]
fn a_cwd_that_is_a_symlink_out_of_the_root_is_refused() {
    let dir = repo("tools-symlink", &[("in.txt", "one\n")]);
    let outside = temp_dir("tools-symlink-outside");
    std::os::unix::fs::symlink(&outside, dir.join("link")).unwrap();
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(
        &mut m,
        1,
        "explain",
        json!({"argv": ["true"], "cwd": "link"}),
    );
    assert_eq!(result(&r)["isError"], true, "{r}");
    assert!(
        text_of(result(&r)).contains("outside"),
        "{}",
        text_of(result(&r))
    );
    m.finish();
}

#[test]
fn a_cwd_inside_the_root_is_accepted_and_reported_relative_to_it() {
    let dir = repo("tools-subdir", &[("sub/in.txt", "one\n")]);
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(
        &mut m,
        1,
        "explain",
        json!({"argv": ["sh", "-c", "true"], "cwd": "sub"}),
    );
    assert_eq!(result(&r)["isError"], false, "{r}");
    assert!(
        sc(result(&r))["lines"].to_string().contains("stoop: dir"),
        "{r}"
    );
    m.finish();
}

#[test]
fn the_default_root_is_the_nearest_git_ancestor_of_the_start_directory() {
    let dir = repo("tools-default-root", &[("sub/in.txt", "one\n")]);
    // Started inside sub/ with no --root: the root is the repository, so "sub" is inside it and
    // stoop reports the directory relative to that root.
    let mut m = Mcp::spawn(&[], &dir.join("sub"));
    let r = call(
        &mut m,
        1,
        "explain",
        json!({"argv": ["true"], "cwd": "sub"}),
    );
    assert_eq!(result(&r)["isError"], false, "{r}");
    assert!(
        sc(result(&r))["lines"].to_string().contains("stoop: dir"),
        "{r}"
    );
    m.finish();
}

#[test]
fn an_explicit_root_confines_every_call_to_it() {
    let dir = repo(
        "tools-explicit-root",
        &[("sub/in.txt", "one\n"), ("other.txt", "x")],
    );
    let mut m = Mcp::spawn(&["--root", "sub"], &dir);
    let inside = call(&mut m, 1, "explain", json!({"argv": ["true"]}));
    assert_eq!(result(&inside)["isError"], false, "{inside}");
    let outside = call(&mut m, 2, "explain", json!({"argv": ["true"], "cwd": ".."}));
    assert_eq!(result(&outside)["isError"], true, "{outside}");
    m.finish();
}

#[test]
fn every_tool_declares_its_annotations_explicitly_and_truthfully() {
    let dir = temp_dir("tools-annotations");
    let mut m = Mcp::spawn(&["--allow-run"], &dir);
    let r = m.call(json!(1), "tools/list", modern(json!({})));
    // name: readOnly, destructive, idempotent, openWorld
    let expected = [
        ("explain", true, false, true, false),
        ("list_proofs", true, false, true, false),
        ("plan", true, false, true, false),
        ("forget", false, true, true, false),
        ("guide", true, false, true, false),
        ("run", false, true, false, true),
    ];
    let tools = result(&r)["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), expected.len());
    for (name, read_only, destructive, idempotent, open_world) in expected {
        let tool = tools
            .iter()
            .find(|t| t["name"] == name)
            .unwrap_or_else(|| panic!("no {name}"));
        let a = &tool["annotations"];
        assert_eq!(a["readOnlyHint"], read_only, "{name}");
        assert_eq!(a["destructiveHint"], destructive, "{name}");
        assert_eq!(a["idempotentHint"], idempotent, "{name}");
        assert_eq!(a["openWorldHint"], open_world, "{name}");
        assert!(tool["inputSchema"]["type"] == "object", "{name}");
        assert!(tool["outputSchema"]["type"] == "object", "{name}");
        let description = tool["description"].as_str().unwrap();
        assert!(
            !description.is_empty() && !description.contains('\u{2014}'),
            "{name}"
        );
        assert!(!description.contains('\u{2013}'), "{name}");
    }
    m.finish();
}

#[cfg(target_os = "linux")]
mod recorded {
    use super::*;

    fn record(dir: &Path) {
        let (code, err) = stoop(
            dir,
            &[
                "run",
                "--root",
                ".",
                "--",
                "sh",
                "-c",
                "cat in.txt > /dev/null",
            ],
        );
        assert_eq!(code, 0, "{err}");
        assert!(err.contains("recorded"), "{err}");
    }

    #[test]
    fn a_recorded_run_is_skipped_by_explain_then_listed_then_forgotten() {
        let dir = repo("tools-recorded-cycle", &[("in.txt", "one\n")]);
        record(&dir);
        let mut m = Mcp::spawn(&[], &dir);
        let skip = call(
            &mut m,
            1,
            "explain",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        assert_eq!(sc(result(&skip))["decision"], "skip", "{skip}");
        assert_eq!(sc(result(&skip))["exit_code"], 0);
        let key = sc(result(&skip))["key"].as_str().unwrap().to_string();
        let listed = call(&mut m, 2, "list_proofs", json!({}));
        let proofs = sc(result(&listed))["proofs"].as_array().unwrap();
        assert_eq!(proofs.len(), 1, "{listed}");
        assert_eq!(proofs[0]["key"], key.as_str());
        let forgot = call(&mut m, 3, "forget", json!({"key": key.clone()}));
        assert_eq!(sc(result(&forgot))["removed"], true, "{forgot}");
        let again = call(&mut m, 4, "forget", json!({"key": key}));
        assert_eq!(sc(result(&again))["removed"], false);
        let run_again = call(
            &mut m,
            5,
            "explain",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        assert_eq!(sc(result(&run_again))["decision"], "run", "{run_again}");
        m.finish();
    }

    #[test]
    fn explain_names_the_input_that_changed() {
        let dir = repo("tools-recorded-changed", &[("in.txt", "one\n")]);
        record(&dir);
        fs::write(dir.join("in.txt"), "two\n").unwrap();
        let mut m = Mcp::spawn(&[], &dir);
        let r = call(
            &mut m,
            1,
            "explain",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        assert_eq!(sc(result(&r))["decision"], "run", "{r}");
        let changed = sc(result(&r))["changed"].as_array().unwrap();
        assert!(changed.iter().any(|c| c["path"] == "in.txt"), "{r}");
        m.finish();
    }

    #[test]
    fn run_skips_the_second_time_and_says_so() {
        let dir = repo("tools-recorded-run", &[("in.txt", "one\n")]);
        let mut m = Mcp::spawn(&["--allow-run"], &dir);
        let first = call(
            &mut m,
            1,
            "run",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        assert_eq!(sc(result(&first))["decision"], "ran", "{first}");
        assert_eq!(sc(result(&first))["traced"], true);
        let second = call(
            &mut m,
            2,
            "run",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        assert_eq!(sc(result(&second))["decision"], "skipped", "{second}");
        assert_eq!(sc(result(&second))["exit_code"], 0);
        m.finish();
    }

    #[test]
    fn read_only_tools_leave_the_proof_store_alone_and_forget_changes_it() {
        let dir = repo("tools-recorded-store", &[("in.txt", "one\n")]);
        record(&dir);
        let store_before = snapshot(&dir.join(".stoop"));
        assert!(!store_before.is_empty());
        let mut m = Mcp::spawn(&[], &dir);
        call(
            &mut m,
            1,
            "explain",
            json!({"argv": ["sh", "-c", "cat in.txt > /dev/null"]}),
        );
        call(&mut m, 2, "list_proofs", json!({}));
        call(&mut m, 3, "guide", json!({}));
        assert_eq!(
            snapshot(&dir.join(".stoop")),
            store_before,
            "a read-only tool changed the store"
        );
        let key = sc(result(&call(&mut m, 4, "list_proofs", json!({}))))["proofs"][0]["key"]
            .as_str()
            .unwrap()
            .to_string();
        call(&mut m, 5, "forget", json!({"key": key}));
        assert_ne!(
            snapshot(&dir.join(".stoop")),
            store_before,
            "forget did not change the store"
        );
        m.finish();
    }
}

/// A hooked suite after a change: the MCP `explain` tool reports the proof key of the legacy decision,
/// not the first word of the attribution pass line that follows it (spec 4.16). Linux only, because
/// the pass needs the tracer.
#[cfg(target_os = "linux")]
#[test]
fn explain_of_a_hooked_suite_after_a_change_reports_the_proof_key() {
    let dir = temp_dir("suite-key");
    fs::create_dir_all(dir.join("tests")).unwrap();
    fs::write(dir.join("tests/a.t"), "one\n").unwrap();
    fs::write(dir.join("tests/b.t"), "two\n").unwrap();
    let words = [
        "sh",
        "-c",
        "for f in \"$@\"; do cat \"$f\" > /dev/null; done",
        "sh",
        "{changed:**/*.t}",
    ];
    let run = std::process::Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &dir)
        .env("STOOP_LEARN_VOLATILE", "0")
        .args(["run", "--root"])
        .arg(&dir)
        .arg("--")
        .args(words)
        .output()
        .unwrap();
    assert_eq!(
        run.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let proofs: Vec<PathBuf> = fs::read_dir(dir.join(".stoop/proofs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(proofs.len(), 1, "{proofs:?}");
    let proof: Value = serde_json::from_slice(&fs::read(&proofs[0]).unwrap()).unwrap();
    let key = proof["key"].as_str().unwrap().to_owned();
    fs::write(dir.join("tests/a.t"), "one, edited\n").unwrap();
    let mut m = Mcp::spawn(&[], &dir);
    let r = call(&mut m, 1, "explain", json!({ "argv": words }));
    let res = result(&r);
    assert_eq!(res["isError"], false, "{r}");
    assert_eq!(sc(res)["decision"], "run", "{r}");
    assert!(
        sc(res)["lines"]
            .to_string()
            .contains("stoop: would run an attribution pass"),
        "the pass line is printed: {r}"
    );
    assert_eq!(sc(res)["key"], key.as_str(), "{r}");
    m.finish();
    fs::remove_dir_all(&dir).unwrap();
}
