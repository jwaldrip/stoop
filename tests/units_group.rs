//! Grouped subset launches, inexact member proofs and fail-closed attribution.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::fs;
use std::process::Output;
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
    success(&run(s, extra));
    assert_eq!(launched(s), ["", A, B, C]);
    s.clear_log();
}

fn edit_shared(s: &Suite) {
    s.write("src/shared.src", "shared changed\n");
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
    for field in ["inputs", "outputs", "created", "guard"] {
        assert_eq!(a[field], b[field], "{field}");
    }
    assert_eq!(bundle["units"][C], before["units"][C]);
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
    s.remove("tests/a.out");
    s.remove("tests/b.out");
    fs::write(toggle, "on").unwrap();
    let out = run(&s, &extra);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
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
