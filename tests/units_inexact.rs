//! Injected grouped versions exercise ownership while the grouped producer is still absent.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::process::Output;
use units_common::*;

const A: &str = "tests/a.t";
const B: &str = "tests/b.t";
const C: &str = "tests/c.t";
const ENV: [(&str, &str); 2] = [("STOOP_SPLIT", "1"), ("T_WRITE_EACH", "1")];

fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|item| item.args.join(" "))
        .collect()
}

fn warm(s: &Suite, env: &[(&str, &str)]) {
    s.clear_log();
    let out = s.hook(env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(launched(s), ["", A, B, C]);
}

fn inject_union(s: &Suite) {
    let path = s.bundle_path().unwrap();
    let mut bundle = s.bundle().unwrap();
    let a = bundle["units"][A][0].clone();
    let b = bundle["units"][B][0].clone();
    assert_eq!(a["exact"], true);
    assert_eq!(b["exact"], true);
    let mut group = a.clone();
    group["exact"] = json!(false);
    for kind in ["inputs", "outputs"] {
        let mut indices = BTreeSet::new();
        for version in [&a, &b] {
            let mut index = 0u64;
            for value in version[kind].as_array().unwrap() {
                index += value.as_u64().unwrap();
                indices.insert(index);
            }
        }
        let mut last = 0u64;
        let deltas: Vec<u64> = indices
            .into_iter()
            .map(|index| {
                let delta = index - last;
                last = index;
                delta
            })
            .collect();
        group[kind] = json!(deltas);
    }
    bundle["units"][A] = json!([group.clone()]);
    bundle["units"][B] = json!([group]);
    fs::write(path, serde_json::to_vec(&bundle).unwrap()).unwrap();
}

fn direct(s: &Suite, env: &[(&str, &str)]) -> i32 {
    code(&s.direct(&s.root, &[], env))
}

fn explain(s: &Suite, env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

fn assert_ready(bundle: &Value) {
    assert_eq!(bundle["state"]["status"], "ready", "{bundle}");
}

#[test]
fn test_rvw_r4_private_outputs_do_not_make_completion_coupled() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    let before = s.bundle().unwrap()["whole"].clone();
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = s.hook(&ENV);
    let calls = launched(&s);
    let bundle = s.bundle().unwrap();
    assert_eq!(code(&out), direct(&s, &ENV), "{}", text(&out.stderr));
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(calls, ["", A, B, "tests/d.t"]);
    assert_ready(&bundle);
    assert_ne!(bundle["whole"], before);
    for unit in [A, B, C, "tests/d.t"] {
        assert_eq!(bundle["units"][unit][0]["exact"], true);
    }
    assert_eq!(bundle["residue"]["state"], "confirmed");
}

#[test]
fn test_rvw_subset_private_outputs_do_not_stop_before_failing_member() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.write(B, "src/shared.src\nfail\n");
    s.clear_log();
    let out = s.hook(&ENV);
    let calls = launched(&s);
    let bundle = s.bundle().unwrap();
    assert_eq!(direct(&s, &ENV), 1);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    assert_eq!(calls, [A, B]);
    assert_ready(&bundle);
    assert_eq!(bundle["units"][A][0]["exact"], true);
    assert_eq!(bundle["units"][B][0]["exact"], false);
}

#[test]
fn a_skipped_inexact_member_is_protected_without_false_disabling() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.write(B, "src/shared.src\nfail\n");
    s.write("src/shared.src", "shared changed\n");
    let failed = s.hook(&ENV);
    assert_eq!(code(&failed), 1, "{}", text(&failed.stderr));
    s.write(B, "src/shared.src\n");
    s.write("src/shared.src", "shared\n");
    // Keep the whole proof invalid while b's grouped proof becomes valid again.
    s.write("src/c.src", "c changed\n");
    s.clear_log();
    let out = s.hook(&ENV);
    let calls = launched(&s);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    assert_eq!(calls, [A, C]);
    assert!(text(&out.stderr).contains("which skipped unit tests/b.t reads"));
    let bundle = s.bundle().unwrap();
    assert_ready(&bundle);
    assert_eq!(bundle["residue"]["state"], "none");
    assert_eq!(direct(&s, &ENV), 0);
    s.clear_log();
    let retry = s.hook(&ENV);
    assert_eq!(code(&retry), 0, "{}", text(&retry.stderr));
    assert_eq!(launched(&s), ["", B]);
    assert_ready(&s.bundle().unwrap());
}

#[test]
fn an_exact_skipped_unit_still_disables_a_writer_of_its_input() {
    let s = Suite::new();
    let marker = s.outside.join("go");
    let env = [
        ("STOOP_SPLIT", "1"),
        ("T_WRITE_EACH", "1"),
        ("T_IF", marker.to_str().unwrap()),
        ("T_WRITE", "src/c.src"),
        ("T_WRITE_AT", A),
    ];
    warm(&s, &env);
    inject_union(&s);
    fs::write(&marker, "go").unwrap();
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = s.hook(&env);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    assert_eq!(launched(&s), [A]);
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["state"]["code"], "wrote_input");
    assert!(text(&out.stderr).contains("tests/a.t wrote src/c.src, which tests/c.t reads"));
}

#[test]
fn a_member_writing_another_members_output_is_still_disabled() {
    let s = Suite::new();
    let marker = s.outside.join("go");
    let env = [
        ("STOOP_SPLIT", "1"),
        ("T_WRITE_EACH", "1"),
        ("T_IF", marker.to_str().unwrap()),
        ("T_WRITE", "tests/a.out"),
        ("T_WRITE_AT", B),
    ];
    warm(&s, &env);
    inject_union(&s);
    fs::write(&marker, "go").unwrap();
    s.write("src/shared.src", "changed\n");
    s.write("src/c.src", "changed\n");
    s.clear_log();
    let out = s.hook(&env);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    assert_eq!(launched(&s), [A, B]);
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["state"]["code"], "wrote_output");
    assert!(text(&out.stderr).contains("tests/b.t and tests/a.t both write tests/a.out"));
}

#[test]
fn a_member_reading_another_members_output_is_still_disabled() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.write(B, "src/shared.src\ntests/a.out\n");
    s.clear_log();
    let out = s.hook(&ENV);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    assert_eq!(launched(&s), [A, B]);
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["state"]["code"], "wrote_input");
    assert!(text(&out.stderr).contains("tests/a.t wrote tests/a.out, which tests/b.t reads"));
}

#[test]
fn rvw_explain_counts_inexact_and_new_units() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = explain(&s, &ENV);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    assert!(launched(&s).is_empty());
    assert!(
        text(&out.stderr)
            .contains("would launch 3 units without a current exact proof, one launch each"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_deleted_grouped_member_that_the_full_run_read_takes_the_full_form() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.remove(A);
    s.clear_log();
    let out = s.hook(&ENV);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert!(
        text(&out.stderr).contains("tests/a.t was removed after the full command read it"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_deleted_input_read_by_grouped_members_takes_the_full_form() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.remove("src/shared.src");
    s.clear_log();
    let out = s.hook(&ENV);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert!(
        text(&out.stderr)
            .contains("src/shared.src was removed, and a unit's stored proof reads it"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_nonmember_writing_a_skipped_inexact_output_has_no_verdict() {
    let s = Suite::new();
    let marker = s.outside.join("go");
    let env = [
        ("STOOP_SPLIT", "1"),
        ("T_WRITE_EACH", "1"),
        ("T_IF", marker.to_str().unwrap()),
        ("T_WRITE", "tests/a.out"),
        ("T_WRITE_AT", C),
    ];
    warm(&s, &env);
    inject_union(&s);
    fs::write(&marker, "go").unwrap();
    s.write("src/c.src", "changed\n");
    s.clear_log();
    let out = s.hook(&env);
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
    assert_eq!(launched(&s), [C]);
    assert_ready(&s.bundle().unwrap());
    assert!(text(&out.stderr).contains("which skipped unit tests/a.t reads"));
    s.clear_log();
    let retry = s.hook(&env);
    assert_eq!(code(&retry), 0, "{}", text(&retry.stderr));
    assert_eq!(launched(&s), ["", A]);
    assert_eq!(s.bundle().unwrap()["state"]["code"], "wrote_output");
}

#[test]
fn completion_names_a_grouped_member_that_fails_alone() {
    let s = Suite::new();
    let marker = s.outside.join("go");
    let env = [
        ("STOOP_SPLIT", "1"),
        ("T_WRITE_EACH", "1"),
        ("T_IF", marker.to_str().unwrap()),
        ("T_FAIL_ALONE", A),
    ];
    warm(&s, &env);
    inject_union(&s);
    fs::write(&marker, "go").unwrap();
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = s.hook(&env);
    let calls = launched(&s);
    assert_eq!(code(&out), direct(&s, &env), "{}", text(&out.stderr));
    assert_eq!(code(&out), 0);
    assert_eq!(calls, ["", A, B, "tests/d.t"]);
    let state = s.bundle().unwrap()["state"].clone();
    assert_eq!(state["code"], "disagreement");
    assert!(text(&out.stderr).contains("tests/a.t failed alone while the full command passed"));
}

#[test]
fn a_failing_grouped_member_is_retried_until_it_passes() {
    let s = Suite::new();
    warm(&s, &ENV);
    inject_union(&s);
    s.write(B, "src/shared.src\nfail\n");
    let first = s.hook(&ENV);
    assert_eq!(code(&first), 1, "{}", text(&first.stderr));
    s.clear_log();
    let retry = s.hook(&ENV);
    assert_eq!(code(&retry), 1, "{}", text(&retry.stderr));
    assert_eq!(launched(&s), [B]);
    assert_ready(&s.bundle().unwrap());
    s.write(B, "src/shared.src\n\n");
    s.clear_log();
    let fixed = s.hook(&ENV);
    assert_eq!(code(&fixed), 0, "{}", text(&fixed.stderr));
    assert_eq!(launched(&s), [B]);
    let bundle = s.bundle().unwrap();
    assert_ready(&bundle);
    assert_eq!(bundle["units"][A][0]["exact"], true);
    assert_eq!(bundle["units"][B][0]["exact"], true);
}

#[test]
fn a_coupling_found_at_the_last_launch_keeps_the_launches_status() {
    let s = Suite::new();
    let marker = s.outside.join("go");
    let env = [
        ("STOOP_SPLIT", "1"),
        ("T_WRITE_EACH", "1"),
        ("T_IF", marker.to_str().unwrap()),
        ("T_WRITE", "tests/a.out"),
        ("T_WRITE_AT", B),
    ];
    warm(&s, &env);
    inject_union(&s);
    fs::write(&marker, "go").unwrap();
    s.write("src/shared.src", "changed\n");
    s.clear_log();
    let out = s.hook(&env);
    let calls = launched(&s);
    let state = s.bundle().unwrap()["state"].clone();
    assert_eq!(code(&out), direct(&s, &env), "{}", text(&out.stderr));
    assert_eq!(code(&out), 0);
    assert_eq!(calls, [A, B]);
    assert_eq!(state["code"], "wrote_output");
}
