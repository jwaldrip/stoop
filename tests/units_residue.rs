//! The residue of a suite (spec 3.8, W6-2): the paths the whole command reads that no unit's own run reads. A
//! passing attribution pass stores it as provisional, a forced full run measures it again, and `stoop explain` names
//! it when it is not empty. These tests drive the stoop binary and the fake runner under the tracer, so they run on
//! Linux x86-64 and arm64 only. Each one says what it fails on a tree without the residue it checks.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::{json, Value};
use std::fs;
use std::process::Output;
use units_common::*;

/// A source edit that is a change for certain: the file's length follows `n`.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// The suite's bundle, as JSON.
fn bundle(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")
}

/// The residue the suite's bundle stores (spec 3.8).
fn residue(s: &Suite) -> Value {
    bundle(s)["residue"].clone()
}

/// The paths a stored residue names, in stored order.
fn paths(residue: &Value) -> Vec<String> {
    residue["paths"]
        .as_array()
        .expect("the residue's paths")
        .iter()
        .map(|path| path.as_str().unwrap().to_owned())
        .collect()
}

/// `stoop explain` of `hook` with `env`, from the root.
fn explain_with(s: &Suite, hook: &str, env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t", hook]);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

/// The residue line `stoop explain` prints for `count` paths, of which `shown` are named (spec 3.8).
fn residue_line(count: usize, shown: &str) -> String {
    let noun = if count == 1 { "file" } else { "files" };
    format!(
        "stoop: the full command reads {count} {noun} no unit's own run reads, such as {shown}; widen the filter or narrow the command"
    )
}

/// I9: a file that only `lint` reads is residue, and explain names it. The pass that follows prints nothing new.
#[test]
fn i9_explain_names_a_lint_the_full_command_runs() {
    let s = Suite::new();
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    s.clear_log();
    let pass = s.hook(&[("T_LINT", "1")]);
    success(&pass);
    assert_eq!(s.launches().len(), 3, "the change runs an attribution pass");
    assert!(
        !stderr(&pass).contains("no unit's own run reads"),
        "{}",
        stderr(&pass)
    );
    let explained = explain_with(&s, HOOK, &[("T_LINT", "1")]);
    assert!(
        stderr(&explained).contains(&residue_line(1, "lint")),
        "{}",
        stderr(&explained)
    );
}

/// I10: a unit file that the full command runs and no unit reads is residue, until a filter makes it a unit. The
/// runner also probes that file's `.flag`, which only the full command probes, so the residue holds the probe too.
/// Then the residue of the second suite, whose filter makes the file a unit, is empty.
#[test]
fn i10_a_file_the_full_command_runs_is_residue_until_a_filter_takes_it() {
    let s = Suite::new();
    success(&s.hook(&[("T_U", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_U", "1")]));
    let r = residue(&s);
    assert_eq!(r["state"], "provisional", "{r}");
    assert_eq!(r["count"], 2, "{r}");
    assert_eq!(paths(&r), ["e2e/x.flag", "e2e/x.u"], "{r}");

    let wide = "{changed:**/*.t|**/*.u|!slow/**}";
    let t = Suite::new();
    success(&t.run(&t.root, &[], &["./t", wide], &[("T_U", "1")]));
    edit(&t, 2);
    success(&t.run(&t.root, &[], &["./t", wide], &[("T_U", "1")]));
    let r = residue(&t);
    assert_eq!(r["state"], "provisional", "{r}");
    assert_eq!(r["count"], 0, "{r}");
    assert!(paths(&r).is_empty(), "{r}");
}

/// I16b: the pinned fixture's full command reads nothing that its units do not read, so after a pass its residue is
/// empty and provisional, and explain prints no residue line.
#[test]
fn i16b_the_pinned_fixture_has_an_empty_residue_after_a_pass() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    success(&s.hook(&[]));
    let r = residue(&s);
    assert_eq!(r["state"], "provisional", "{r}");
    assert_eq!(r["count"], 0, "{r}");
    assert!(paths(&r).is_empty(), "{r}");
    assert_eq!(r["whole"], bundle(&s)["whole"], "{r}");
    let explained = explain_with(&s, HOOK, &[]);
    assert!(
        !stderr(&explained).contains("no unit's own run reads"),
        "{}",
        stderr(&explained)
    );
}

/// I17: a forced full run records its own proof and leaves the residue unknown for a passing run to measure (PR 86 review
/// round 2).
#[test]
fn i17_a_forced_full_run_records_its_proof_and_leaves_the_residue_unknown() {
    let s = Suite::new();
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    let before = bundle(&s)["whole"].clone();
    success(&s.hook(&[("T_LINT", "1"), ("STOOP_FULL", "1")]));
    let b = bundle(&s);
    assert_ne!(b["whole"], before, "the forced run records a new proof");
    assert_eq!(b["residue"]["state"], "none", "{}", b["residue"]);
}

/// I18: a unit that fails in a pass has no version, so the pass leaves the residue unknown. It passes on a tree that
/// never stores a residue; it is a guard against a residue measured from a partial roster.
#[test]
fn i18_a_pass_with_a_failing_unit_leaves_the_residue_unknown() {
    let s = Suite::new();
    success(&s.hook(&[]));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 2);
    let out = s.hook(&[]);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let r = residue(&s);
    assert_eq!(r["state"], "none", "{r}");
    assert!(paths(&r).is_empty(), "{r}");
}

/// I19: explain names the first five residue paths in sorted order, and the count of every path.
#[test]
fn i19_explain_names_five_residue_paths_and_counts_them_all() {
    let s = Suite::new();
    let misc: Vec<String> = (1..=7).map(|n| format!("misc/{n}.txt")).collect();
    for file in &misc {
        s.write(file, "x\n");
    }
    let reads: String = misc.iter().map(|file| format!(" {file}")).collect();
    s.executable("lint", &format!("#!/bin/sh\ncat{reads} >/dev/null\n"));
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    // `lint` is an input as well: the full command executes it, so its seven files and the script make eight.
    let r = residue(&s);
    assert_eq!(r["count"], 8, "{r}");
    let first: Vec<String> = paths(&r).into_iter().take(5).collect();
    assert_eq!(
        first,
        [
            "lint",
            "misc/1.txt",
            "misc/2.txt",
            "misc/3.txt",
            "misc/4.txt"
        ]
    );
    let explained = explain_with(&s, HOOK, &[("T_LINT", "1")]);
    assert!(
        stderr(&explained).contains(&residue_line(
            8,
            "lint, misc/1.txt, misc/2.txt, misc/3.txt, misc/4.txt"
        )),
        "{}",
        stderr(&explained)
    );
}

/// I21: a program that only the full command runs is residue, and it is stored by its absolute path.
#[test]
fn i21_a_program_only_the_full_command_runs_is_residue_by_absolute_path() {
    let s = Suite::new();
    s.executable("lint", "#!/bin/sh\nod -An -c src/c.src >/dev/null\n");
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    let r = residue(&s);
    assert!(paths(&r).contains(&"/usr/bin/od".to_owned()), "{r}");
}

/// I22: a unit that leaves the roster is no longer a version, so its reads stop being covered. A forced run that drops it
/// leaves the residue unknown, never known and empty; a passing run measures it (PR 86 review round 2).
#[test]
fn i22_a_unit_that_leaves_the_roster_stops_covering_its_reads() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    success(&s.hook(&[]));
    s.write(".stoopignore", "tests/c.t\n");
    success(&s.hook(&[("STOOP_FULL", "1")]));
    let units = bundle(&s)["units"].clone();
    assert!(units.get("tests/c.t").is_none(), "{units}");
    let r = residue(&s);
    assert_eq!(r["state"], "none", "{r}");
}

/// I23: explain prints the residue line directly before the tracked line, so the residue reads with the counts it
/// qualifies (spec 3.12).
#[test]
fn i23_the_residue_line_comes_directly_before_the_tracked_line() {
    let s = Suite::new();
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    let explained = explain_with(&s, HOOK, &[("T_LINT", "1")]);
    let text = stderr(&explained);
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.starts_with("stoop: the full command reads "))
        .unwrap_or_else(|| panic!("no residue line in:\n{text}"));
    assert!(
        lines
            .get(at + 1)
            .is_some_and(|next| next.starts_with("stoop: tracked ")),
        "{text}"
    );
}

/// I24: explain counts every path of the residue, not only the first 32 that a bundle stores (spec 3.8).
#[test]
fn i24_explain_counts_every_residue_path_not_only_the_stored_ones() {
    let s = Suite::new();
    let misc: Vec<String> = (1..=39).map(|n| format!("misc/{n:02}.txt")).collect();
    for file in &misc {
        s.write(file, "x\n");
    }
    let reads: String = misc.iter().map(|file| format!(" {file}")).collect();
    s.executable("lint", &format!("#!/bin/sh\ncat{reads} >/dev/null\n"));
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    let r = residue(&s);
    assert_eq!(r["count"], 40, "{r}");
    assert_eq!(paths(&r).len(), 32, "{r}");
    let explained = explain_with(&s, HOOK, &[("T_LINT", "1")]);
    assert!(
        stderr(&explained).contains(&residue_line(
            40,
            "lint, misc/01.txt, misc/02.txt, misc/03.txt, misc/04.txt"
        )),
        "{}",
        stderr(&explained)
    );
}

/// I25: a disabled suite names no residue and counts no proofs (spec 3.6, 3.12). Its roster units keep their
/// versions, and a forced run records a residue for its whole proof while the suite stays disabled.
#[test]
fn i25_a_disabled_suite_names_no_residue_in_explain() {
    let s = Suite::new();
    success(&s.hook(&[("T_LINT", "1")]));
    edit(&s, 2);
    success(&s.hook(&[("T_LINT", "1")]));
    // The state a breach stores, written by hand: the unit proofs and the residue are kept.
    let path = s.bundle_path().unwrap();
    let mut bundle: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    bundle["state"] = json!({
        "status": "disabled",
        "code": "wrote_unit",
        "phase": "attribution",
        "label": "tests/a.t wrote tests/b.t",
        "at": 1
    });
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    success(&s.hook(&[("T_LINT", "1"), ("STOOP_FULL", "1")]));
    edit(&s, 3);
    let explained = explain_with(&s, HOOK, &[("T_LINT", "1")]);
    let text = stderr(&explained);
    assert!(!text.contains("the full command reads"), "{text}");
    assert!(
        text.contains("stoop: tracked 3 units, 0 inputs; 0 proven, 3 without a proof"),
        "{text}"
    );
    assert!(
        text.contains(" disabled: tests/a.t wrote tests/b.t; run 'stoop forget --units "),
        "{text}"
    );
}
