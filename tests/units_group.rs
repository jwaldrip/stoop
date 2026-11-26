//! Grouped subset launches, inexact member proofs and fail-closed attribution (W7-4b).
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::fs;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Output, Stdio};
use units_common::*;

const A: &str = "tests/a.t";
const B: &str = "tests/b.t";
const C: &str = "tests/c.t";
const GROUP: [(&str, &str); 2] = [("STOOP_SPLIT", "1"), ("STOOP_SPLIT_GROUP", "1")];

fn run(s: &Suite, extra: &[(&str, &str)]) -> Output {
    let env: Vec<_> = GROUP.into_iter().chain(extra.iter().copied()).collect();
    s.hook(&env)
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

fn warm(s: &Suite, extra: &[(&str, &str)]) {
    s.clear_log();
    let out = run(s, extra);
    success(&out);
    assert_eq!(launched(s), ["", A, B, C], "{}", text(&out.stderr));
    s.clear_log();
}

fn edit_shared(s: &Suite) {
    s.write("src/shared.src", "shared changed\n");
}
fn held_group(s: &Suite, extra: &[(&str, &str)]) -> Child {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .envs(GROUP)
        .envs(extra.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    spawning(|| command.spawn()).unwrap()
}

#[test]
fn s2_an_edit_to_shared_runs_a_and_b_in_one_launch() {
    let s = Suite::new();
    warm(&s, &[]);
    let before = s.bundle().unwrap();
    edit_shared(&s);
    let out = run(&s, &[]);
    success(&out);
    assert!(text(&out.stderr).contains("; run 2 (src/shared.src changed): tests/a.t, tests/b.t"));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    let bundle = s.bundle().unwrap();
    let a = &bundle["units"][A][0];
    let b = &bundle["units"][B][0];
    assert_eq!(a["exact"], false);
    assert_eq!(b["exact"], false);
    for field in ["inputs", "outputs", "created", "guard"] {
        assert_eq!(a[field], b[field], "{field}");
    }
    // Table compaction can change c's serialized indexes without replacing its version.
    assert_eq!(
        bundle["units"][C][0]["created"],
        before["units"][C][0]["created"]
    );
    assert_eq!(bundle["units"][C][0]["exact"], true);
    s.clear_log();
    success(&run(&s, &[]));
    assert!(s.launches().is_empty());
    s.write(A, "src/shared.src\n\n");
    s.clear_log();
    success(&run(&s, &[]));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
}

#[test]
fn s10_a_grouped_launch_names_only_units_and_their_changed_inputs() {
    for from_tests in [false, true] {
        let s = Suite::new();
        let cwd = if from_tests {
            s.root.join("tests")
        } else {
            s.root.clone()
        };
        let runner = if from_tests { "../t" } else { "./t" };
        let launch = |s: &Suite| s.run(&cwd, &[], &[runner, HOOK], &GROUP);
        success(&launch(&s));
        edit_shared(&s);
        s.clear_log();
        let out = launch(&s);
        success(&out);
        let calls = s.launches();
        assert_eq!(calls.len(), 1, "{}", text(&out.stderr));
        let (args, units, changed) = if from_tests {
            (vec!["a.t", "b.t"], "a.t|b.t", "../src/shared.src")
        } else {
            (vec![A, B], "tests/a.t|tests/b.t", "src/shared.src")
        };
        assert_eq!(calls[0].args, args);
        assert_eq!(calls[0].env("changed"), units);
        assert_eq!(calls[0].env("units"), units);
        assert_eq!(calls[0].env("changed_inputs"), changed);
    }
}

#[test]
fn s24_a_member_the_launch_did_not_read_disables_and_has_no_verdict() {
    let s = Suite::new();
    let toggle = s.outside.join("toggle");
    let toggle = toggle.to_str().unwrap();
    let extra = [("T_WRITE_EACH", "1"), ("T_SKIP_TEST", B), ("T_IF", toggle)];
    warm(&s, &extra);
    let before = s.bundle().unwrap();
    let id = before["suite"].as_str().unwrap();
    // Removing an output would change the listing of `tests/`, which the whole proof holds, so it takes the full form.
    edit_shared(&s);
    fs::write(toggle, "on").unwrap();
    let out = run(&s, &extra);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("stoop: no proof for tests/b.t: the launch never read it"),
        "{stderr}"
    );
    assert!(stderr.contains(&format!("stoop: suite {id} disabled: tests/b.t exited 0 without reading it; run 'stoop forget --units {id}' after fixing it")), "{stderr}");
    assert!(
        stderr.contains(
            "stoop: this run has no verdict (exit 125): tests/b.t did not run in its launch"
        ),
        "{stderr}"
    );
    let after = s.bundle().unwrap();
    assert_eq!(after["units"][A], before["units"][A]);
    assert_eq!(after["units"][B], before["units"][B]);
}

#[test]
fn s25_a_failing_group_launch_leaves_every_member_affected() {
    let s = Suite::new();
    let toggle = s.outside.join("toggle");
    let toggle = toggle.to_str().unwrap();
    let extra = [("T_FAIL_ALONE", A), ("T_IF", toggle)];
    warm(&s, &extra);
    let before = s.bundle().unwrap();
    edit_shared(&s);
    fs::write(toggle, "on").unwrap();
    let out = run(&s, &extra);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    let after = s.bundle().unwrap();
    assert_eq!(after["units"][A], before["units"][A]);
    assert_eq!(after["units"][B], before["units"][B]);
    fs::remove_file(toggle).unwrap();
    s.clear_log();
    success(&run(&s, &extra));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
}
#[test]
fn s14_a_kill_during_the_group_launch_leaves_both_affected() {
    let s = Suite::new();
    let fifo = s.fifo();
    let gate = s.outside.join("hold");
    let extra = [
        ("T_FIFO", fifo.to_str().unwrap()),
        ("T_FIFO_AT", B),
        ("T_FIFO_IF", gate.to_str().unwrap()),
    ];
    warm(&s, &extra);
    let before = s.bundle_bytes().unwrap();
    edit_shared(&s);
    fs::write(&gate, "hold").unwrap();
    let mut child = held_group(&s, &extra);
    let writer = meet(&fifo);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    drop(writer);
    fs::remove_file(&gate).unwrap();
    assert_eq!(s.bundle_bytes().unwrap(), before);
    let prediction = explain_words(&s, &["./t", HOOK], &extra);
    let explained = all_output(&prediction);
    assert!(
        explained.contains("stoop: affected tests/a.t: src/shared.src changed"),
        "{explained}"
    );
    assert!(
        explained.contains("stoop: affected tests/b.t: src/shared.src changed"),
        "{explained}"
    );
    s.clear_log();
    success(&run(&s, &extra));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
}

#[test]
fn s17_an_edit_during_the_group_launch_leaves_both_affected() {
    let s = Suite::new();
    let fifo = s.fifo();
    let gate = s.outside.join("hold");
    let extra = [
        ("T_FIFO", fifo.to_str().unwrap()),
        ("T_FIFO_AT", B),
        ("T_FIFO_IF", gate.to_str().unwrap()),
    ];
    warm(&s, &extra);
    let before = s.bundle().unwrap();
    edit_shared(&s);
    s.age("src/shared.src");
    fs::write(&gate, "hold").unwrap();
    let child = held_group(&s, &extra);
    let writer = meet(&fifo);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    s.write("src/shared.src", "shared changed while running\n");
    release(writer);
    let out = finish(child);
    fs::remove_file(&gate).unwrap();
    let stderr = text(&out.stderr);
    assert_eq!(code(&out), 125, "{stderr}");
    assert!(
        stderr.contains("stoop: not recorded for tests/a.t (+1 more): src/shared.src changed while the command ran"),
        "{stderr}"
    );
    assert!(
        stderr.contains("stoop: this run has no verdict (exit 125): src/shared.src changed, and no unit's new proof reads it"),
        "{stderr}"
    );
    let after = s.bundle().unwrap();
    assert_eq!(after["units"][A], before["units"][A]);
    assert_eq!(after["units"][B], before["units"][B]);
    s.clear_log();
    success(&run(&s, &extra));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
}

#[test]
fn g_r2_completion_reproves_inexact_units_one_launch_each() {
    let s = Suite::new();
    let extra = [("T_WRITE_EACH", "1")];
    warm(&s, &extra);
    edit_shared(&s);
    success(&run(&s, &extra));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = run(&s, &extra);
    success(&out);
    assert_eq!(launched(&s), ["", A, B, "tests/d.t"]);
    let bundle = s.bundle().unwrap();
    for unit in [A, B, C, "tests/d.t"] {
        assert_eq!(bundle["units"][unit][0]["exact"], true, "{unit}");
    }
    assert_eq!(bundle["residue"]["state"], "confirmed");
}

#[test]
fn g_h2_a_group_writing_a_skipped_units_input_disables() {
    let s = Suite::new();
    let toggle = s.outside.join("toggle");
    let toggle = toggle.to_str().unwrap();
    let extra = [
        ("T_WRITE", "src/c.src"),
        ("T_WRITE_AT", A),
        ("T_IF", toggle),
    ];
    warm(&s, &extra);
    edit_shared(&s);
    fs::write(toggle, "on").unwrap();
    let out = run(&s, &extra);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("tests/a.t (+1 more) wrote src/c.src, which tests/c.t reads"),
        "{stderr}"
    );
}

/// The argument wrapper of these tests: an argument that starts with `@` names a list file, and each line of the file
/// becomes an argument. The runner gets the rest as they are, so a launch's words show what the hook gave it.
const ARGV: &str = r#"#!/bin/sh
ROOT=$(cd "$(dirname "$0")" && pwd -P) || exit 2
list=
for word in "$@"; do
	case $word in
		@*) list="$list$(cat "${word#@}")
" ;;
		*) list="$list$word
" ;;
	esac
done
old=$IFS
IFS='
'
set -f
set -- $list
IFS=$old
set +f
exec "$ROOT/t" "$@"
"#;

/// `stoop explain` with `words` as the hook, under `env`. Its decision may print on either stream.
fn explain_words(s: &Suite, words: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .arg("--")
        .args(words);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

fn all_output(out: &Output) -> String {
    format!("{}{}", text(&out.stdout), text(&out.stderr))
}

/// One hundred and three units with the three of the suite: one hundred whose paths are about 700 bytes long, so 101 of
/// them as one join word overflow 64 KiB (S20). The first 99 read the shared source, and the last reads the centre
/// source only. The full command runs every `*.t`, so the roster must cover them all.
fn long_units(s: &Suite) -> Vec<String> {
    let dir = format!("long/{}", format!("{}/", "d".repeat(45)).repeat(15));
    (0..100)
        .map(|n| {
            let unit = format!("{dir}u{n:03}.t");
            let source = if n == 99 {
                "src/c.src"
            } else {
                "src/shared.src"
            };
            s.write(&unit, &format!("{source}\n"));
            unit
        })
        .collect()
}

#[test]
fn explain_names_the_grouped_argv() {
    let s = Suite::new();
    success(&s.run(&s.root, &[], &["./t", HOOK], &GROUP));
    edit_shared(&s);
    let out = explain_words(&s, &["./t", HOOK], &GROUP);
    assert!(
        all_output(&out).contains("(2 of 3 units affected): argv ./t tests/a.t tests/b.t"),
        "{}",
        all_output(&out)
    );
}

#[test]
fn a_grouped_launch_writes_one_list_holding_every_member() {
    let s = Suite::new();
    s.executable("argv", ARGV);
    let words = ["./argv", "@{changed:**/*.t|!slow/**:file}"];
    success(&s.run(&s.root, &[], &words, &GROUP));
    edit_shared(&s);
    s.clear_log();
    let out = s.run(&s.root, &[], &words, &GROUP);
    success(&out);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn s20_a_join_word_over_64_kib_runs_the_full_form() {
    let s = Suite::new();
    long_units(&s);
    let words = ["./t", "{changed:**/*.t|!slow/**:comma}"];
    success(&s.run(&s.root, &[], &words, &GROUP));
    edit_shared(&s);
    let reason = "the 101 affected units do not fit on the command line";
    let explained = explain_words(&s, &words, &GROUP);
    assert!(
        all_output(&explained).contains(reason),
        "{}",
        all_output(&explained)
    );
    s.clear_log();
    let out = s.run(&s.root, &[], &words, &GROUP);
    assert!(text(&out.stderr).contains(reason), "{}", text(&out.stderr));
    assert_eq!(
        launched(&s).first().map(String::as_str),
        Some(""),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn s20b_a_list_over_64_kib_leaves_the_variables_unset_and_uses_the_file() {
    let s = Suite::new();
    s.executable("argv", ARGV);
    let units = long_units(&s);
    let words = ["./argv", "@{changed:**/*.t|!slow/**:file}"];
    success(&s.run(&s.root, &[], &words, &GROUP));
    edit_shared(&s);
    s.clear_log();
    let out = s.run(&s.root, &[], &words, &GROUP);
    success(&out);
    let calls = s.launches();
    assert_eq!(calls.len(), 1, "{}", text(&out.stderr));
    assert_eq!(calls[0].args.len(), 101, "{}", text(&out.stderr));
    assert!(calls[0].lines.contains(&"changed_set=".to_string()));
    assert!(calls[0].lines.contains(&"units_set=".to_string()));
    assert_eq!(s.bundle().unwrap()["units"][&units[0]][0]["exact"], false);
}

#[test]
fn s20e_argv_and_environment_over_half_of_arg_max_run_the_full_form() {
    let s = Suite::new();
    // SAFETY: sysconf reads no pointers.
    let arg_max = unsafe { libc::sysconf(libc::_SC_ARG_MAX) } as usize;
    let value = "b".repeat(100 * 1024);
    let names: Vec<String> = (0..arg_max / 2 / value.len() + 1)
        .map(|n| format!("STOOP_TEST_BALLAST_{n}"))
        .collect();
    let mut env: Vec<(&str, &str)> = GROUP.to_vec();
    for name in &names {
        env.push((name.as_str(), value.as_str()));
    }
    let reason = "the 2 affected units do not fit on the command line";
    success(&s.run(&s.root, &[], &["./t", HOOK], &env));
    edit_shared(&s);
    assert!(all_output(&explain_words(&s, &["./t", HOOK], &env)).contains(reason));
    s.clear_log();
    let out = s.run(&s.root, &[], &["./t", HOOK], &env);
    assert!(text(&out.stderr).contains(reason), "{}", text(&out.stderr));
    assert_eq!(
        launched(&s).first().map(String::as_str),
        Some(""),
        "{}",
        text(&out.stderr)
    );
}
