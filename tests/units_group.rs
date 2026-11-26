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
fn make_group(s: &Suite, extra: &[(&str, &str)]) {
    edit_shared(s);
    let out = run(s, extra);
    success(&out);
    assert_eq!(
        launched(s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
    s.clear_log();
}

fn assert_full(s: &Suite, out: &Output, reason: &str) {
    assert_eq!(launched(s).first().map(String::as_str), Some(""));
    assert!(text(&out.stderr).contains(reason), "{}", text(&out.stderr));
}
#[test]
fn g_v5_a_missing_output_reruns_the_group() {
    let s = Suite::new();
    fs::create_dir(s.path(".outputs")).unwrap();
    let extra = [("T_WRITE_EACH", "1"), ("T_OUTPUT_DIR", ".outputs")];
    warm(&s, &extra);
    make_group(&s, &extra);
    s.remove(".outputs/a.t.out");
    let out = run(&s, &extra);
    success(&out);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
    assert!(s.path(".outputs/a.t.out").is_file());
}

#[test]
fn g_v6_listing_link_and_unreadable_identities_rerun_the_group() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let s = Suite::new();
    fs::create_dir_all(s.path(".inputs/dir")).unwrap();
    let runner = include_str!("fixtures/hook/t");
    let anchor = "cat \"$ROOT/$line\"";
    assert_eq!(runner.matches(anchor).count(), 1);
    s.executable(
        "t",
        &runner.replace(
            anchor,
            "case $line in\nls:*) ls -a \"$ROOT/${line#ls:}\" >/dev/null ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
        ),
    );
    s.write(A, "src/shared.src\nls:.inputs/dir\n.inputs/dir/added\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(".inputs/dir/added", "now present\n");
    let listed = run(&s, &[]);
    success(&listed);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "listing: {}",
        text(&listed.stderr)
    );

    let s = Suite::new();
    s.write(".inputs/one", "one\n");
    s.write(".inputs/two", "two\n");
    symlink("one", s.path(".inputs/link")).unwrap();
    s.write(A, "src/shared.src\n.inputs/link\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.remove(".inputs/link");
    symlink("two", s.path(".inputs/link")).unwrap();
    let linked = run(&s, &[]);
    success(&linked);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "link: {}",
        text(&linked.stderr)
    );

    let s = Suite::new();
    s.write(".inputs/secret", "secret\n");
    fs::set_permissions(s.path(".inputs/secret"), fs::Permissions::from_mode(0o000)).unwrap();
    s.write(A, "src/shared.src\n.inputs/secret\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    let bundle = s.bundle().unwrap();
    assert!(
        bundle["table"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["path"] == ".inputs/secret" && entry["id"] == "u" }),
        "the grouped proof must record an unreadable identity: {bundle}"
    );
    fs::set_permissions(s.path(".inputs/secret"), fs::Permissions::from_mode(0o600)).unwrap();
    let readable = run(&s, &[]);
    success(&readable);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "unreadable: {}",
        text(&readable.stderr)
    );
}

#[test]
fn g_g1_over_claimed_reads_can_make_a_change_global() {
    let s = Suite::new();
    s.write("src/x.src", "old\n");
    s.write(A, "src/shared.src\nsrc/x.src\n");
    s.write(C, "src/c.src\nsrc/x.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(B, "src/shared.src\n\n");
    let per_unit = s.hook(&[("STOOP_SPLIT", "1")]);
    success(&per_unit);
    assert_eq!(launched(&s), [A, B], "{}", text(&per_unit.stderr));
    s.clear_log();
    s.write(B, "src/shared.src\n\n\n");
    s.write(C, "src/c.src\nsrc/x.src\n\n");
    let second = run(&s, &[]);
    success(&second);
    assert_eq!(
        launched(&s),
        ["tests/b.t tests/c.t"],
        "{}",
        text(&second.stderr)
    );
    s.clear_log();
    s.write("src/x.src", "changed\n");
    let out = run(&s, &[]);
    success(&out);
    assert_full(&s, &out, "src/x.src changed and every unit reads it");
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_x2_an_excused_name_read_by_another_member_is_covered() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    s.write(A, "src/shared.src\ntests/z.u\n");
    let extra = [("T_U", "1")];
    warm(&s, &extra);
    make_group(&s, &extra);
    s.write(A, "src/shared.src\n");
    s.write(B, "src/shared.src\ntests/z.u\n");
    s.write("tests/z.u", "src/c.src\n");
    let out = run(&s, &extra);
    success(&out);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &extra)));
}

#[test]
fn g_e_a_missing_group_member_disables_without_recording_any_member() {
    let s = Suite::new();
    let gate = s.outside.join("skip");
    let extra = [("T_IF", gate.to_str().unwrap()), ("T_SKIP_TEST", B)];
    warm(&s, &extra);
    make_group(&s, &extra);
    let before = s.bundle().unwrap();
    s.write(A, "src/shared.src\n\n");
    fs::write(&gate, "skip").unwrap();
    let out = run(&s, &extra);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), 125, "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    let after = s.bundle().unwrap();
    assert_eq!(after["state"]["status"], "disabled", "{after}");
    assert_eq!(after["units"][A], before["units"][A]);
    assert_eq!(after["units"][B], before["units"][B]);
}

#[test]
fn g_h1_coupling_inside_a_group_is_caught_by_the_next_exact_launch() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(A, "src/shared.src\ntests/b.t\n");
    let grouped = run(&s, &[]);
    success(&grouped);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(s.bundle().unwrap()["state"]["status"], "ready");
    s.clear_log();
    s.write("tests/d.t", "src/c.src\n");
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert!(launched(&s).iter().any(|call| call == A));
    let stderr = text(&out.stderr);
    assert!(stderr.contains("tests/a.t read tests/b.t"), "{stderr}");
    assert_eq!(s.bundle().unwrap()["state"]["code"], "read_unit");
}

#[test]
fn g_h3_a_group_changing_a_skipped_listing_has_no_verdict() {
    let s = Suite::new();
    let gate = s.outside.join("write");
    let extra = [
        ("T_IF", gate.to_str().unwrap()),
        ("T_LS_ROOT", "1"),
        ("T_WRITE", "new.top"),
        ("T_WRITE_AT", A),
    ];
    warm(&s, &extra);
    edit_shared(&s);
    fs::write(&gate, "write").unwrap();
    let out = run(&s, &extra);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), 125, "{stderr}");
    assert!(
        stderr.contains("which skipped unit tests/c.t lists"),
        "{stderr}"
    );
}

fn premise_violation(s: &Suite, extra: &[(&str, &str)]) {
    s.write("gate", "ok\n");
    // Every unit must execute grep too; otherwise the full form's gate check is residue.
    for flag in ["tests/a.flag", "tests/b.flag", "tests/c.flag"] {
        s.write(flag, "ok\n");
    }
    s.write(A, "src/shared.src\ngate\n");
    warm(s, extra);
    make_group(s, extra);
    s.write(A, "src/shared.src\n");
    s.write("src/shared.src", "changed again\n");
    let dropped = run(s, extra);
    success(&dropped);
    assert_eq!(
        launched(s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&dropped.stderr)
    );
    s.clear_log();
    s.write("gate", "fail\n");
    let grouped = run(s, extra);
    assert_eq!(
        launched(s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&grouped.stderr)
    );
    // Premise G is deliberately violated: only a multi-unit invocation reads gate.
    assert_eq!(code(&grouped), 0, "{}", text(&grouped.stderr));
    assert_eq!(code(&s.direct(&s.root, &[], extra)), 1);
    s.clear_log();
}

#[test]
fn g_p1_a_group_only_read_is_the_documented_premise() {
    let extra = [("T_GATE", "gate"), ("T_GROUP_READ", "gate")];

    let s = Suite::new();
    premise_violation(&s, &extra);
    let forced = [
        ("T_GATE", "gate"),
        ("T_GROUP_READ", "gate"),
        ("STOOP_FULL", "1"),
    ];
    let failed = run(&s, &forced);
    assert_eq!(code(&failed), 1, "{}", text(&failed.stderr));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert_eq!(s.bundle().unwrap()["state"]["code"], "disagreement");

    let s = Suite::new();
    premise_violation(&s, &extra);
    s.write("gate", "ok\n");
    let repaired = run(&s, &forced);
    success(&repaired);
    assert_eq!(launched(&s), ["", A, B], "{}", text(&repaired.stderr));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["units"][A][0]["exact"], true);
    assert_eq!(bundle["units"][B][0]["exact"], true);
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    assert_eq!(bundle["residue"]["count"], 1, "{bundle}");
    s.clear_log();
    s.write("gate", "fail\n");
    let out = run(&s, &extra);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &extra)));
}

#[test]
fn g_v1_a_file_one_member_read_reruns_the_group() {
    let s = Suite::new();
    s.write("src/private.src", "private\n");
    s.write(A, "src/shared.src\nsrc/private.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write("src/private.src", "private changed\n");
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_v3_a_stat_only_read_reruns_the_group() {
    let s = Suite::new();
    let runner = include_str!("fixtures/hook/t");
    let anchor = "cat \"$ROOT/$line\"";
    assert_eq!(runner.matches(anchor).count(), 1);
    s.executable(
        "t",
        &runner.replace(
            anchor,
            "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
        ),
    );
    s.write("src/stat.src", "old\n");
    s.write(A, "src/shared.src\nstat:src/stat.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write("src/stat.src", "changed size\n");
    let out = run(&s, &[]);
    let stderr = text(&out.stderr);
    assert_eq!(code(&out), 125, "{stderr}");
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert!(
        stderr.contains("src/stat.src changed, and no unit's new proof reads it"),
        "{stderr}"
    );
    assert_eq!(code(&s.direct(&s.root, &[], &[])), 0);
}

#[test]
fn g_v4_an_appeared_flag_is_excused_and_read_by_the_group() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write("tests/a.flag", "ok\n");
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(
        launched(&s),
        ["tests/a.t tests/b.t"],
        "{}",
        text(&out.stderr)
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_v7_an_outside_root_change_takes_the_full_form() {
    let s = Suite::new();
    // If every unit reads the input, the earlier global-change rule supplies the full reason.
    let runner = include_str!("fixtures/hook/t");
    let anchor = "if [ -n \"${T_READ_OTHER:-}\" ] && armed; then";
    assert_eq!(runner.matches(anchor).count(), 1);
    s.executable(
        "t",
        &runner.replace(
            anchor,
            "if [ -n \"${T_READ_OTHER:-}\" ] && armed && { [ \"$TESTS\" = 0 ] || [ \"$COUNT\" -ge 2 ] || [ \"${1:-}\" = tests/a.t ]; }; then",
        ),
    );
    struct Outside(std::path::PathBuf);
    impl Drop for Outside {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    // /tmp is ignored outside the root. Runner and Cargo test temp directories are not.
    let dir = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")));
    fs::create_dir_all(&dir).unwrap();
    let dir = fs::canonicalize(dir).unwrap();
    assert!(!dir.starts_with("/tmp") && !dir.starts_with("/var/tmp") && !dir.starts_with("/run"));
    let outside = Outside(dir.join(format!("stoop-v7-{}", std::process::id())));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&outside.0)
        .unwrap();
    fs::write(&outside.0, "old\n").unwrap();
    let extra = [("T_READ_OTHER", outside.0.to_str().unwrap())];
    warm(&s, &extra);
    assert!(
        s.proofs()
            .iter()
            .any(|proof| proof["inputs"].as_array().is_some_and(|inputs| {
                inputs
                    .iter()
                    .any(|input| input["path"].as_str() == outside.0.to_str())
            })),
        "the whole proof must track the external input"
    );
    make_group(&s, &extra);
    fs::write(&outside.0, "outside changed\n").unwrap();
    let out = run(&s, &extra);
    success(&out);
    assert_full(&s, &out, "changed outside the repository");
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &extra)));
}

#[test]
fn g_u1_a_changed_shared_source_is_covered_by_the_group() {
    let s = Suite::new();
    warm(&s, &[]);
    edit_shared(&s);
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
    for unit in [A, B] {
        assert_eq!(s.bundle().unwrap()["units"][unit][0]["exact"], false);
    }
}

#[test]
fn g_u2_another_member_covers_a_dropped_read() {
    let s = Suite::new();
    s.write("src/extra.src", "old\n");
    s.write(A, "src/shared.src\nsrc/extra.src\n");
    s.write(B, "src/shared.src\nsrc/extra.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(A, "src/shared.src\n");
    s.write("src/extra.src", "changed\n");
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

fn dropped_private_read(s: &Suite) -> Output {
    s.write("src/private.src", "old\n");
    s.write(A, "src/shared.src\nsrc/private.src\n");
    warm(s, &[]);
    make_group(s, &[]);
    s.write(A, "src/shared.src\n");
    s.write("src/private.src", "changed\n");
    run(s, &[])
}

#[test]
fn g_u3_a_sole_reader_dropping_its_read_has_no_verdict() {
    let s = Suite::new();
    let out = dropped_private_read(&s);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(code(&out), 125, "{stderr}");
    assert!(
        stderr.contains("stoop: this run has no verdict (exit 125): src/private.src changed, and no unit's new proof reads it"),
        "{stderr}"
    );
}

#[test]
fn g_t1_an_unchanged_retry_after_a_grouped_125_takes_the_full_form() {
    let s = Suite::new();
    let first = dropped_private_read(&s);
    assert_eq!(code(&first), 125, "{}", text(&first.stderr));
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    s.clear_log();
    let retry = run(&s, &[]);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert_eq!(code(&retry), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_d1_a_removed_member_takes_the_full_form() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.remove(A);
    let out = run(&s, &[]);
    success(&out);
    assert_full(
        &s,
        &out,
        "tests/a.t was removed after the full command read it",
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_d2_a_removed_private_input_takes_the_full_form() {
    let s = Suite::new();
    s.write("src/private.src", "private\n");
    s.write(A, "src/shared.src\nsrc/private.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.remove("src/private.src");
    let out = run(&s, &[]);
    assert_full(
        &s,
        &out,
        "src/private.src was removed, and a unit's stored proof reads it",
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
}

#[test]
fn g_d3_the_full_run_after_a_removal_reproves_the_group() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.remove(A);
    let out = run(&s, &[]);
    success(&out);
    assert_full(
        &s,
        &out,
        "tests/a.t was removed after the full command read it",
    );
    assert!(launched(&s).iter().any(|call| call == B));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["units"][B][0]["exact"], true, "{bundle}");
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
}

#[test]
fn g_r1_a_reset_residue_waits_for_the_next_full_run() {
    let s = Suite::new();
    s.write("src/private.src", "private\n");
    s.write(A, "src/shared.src\nsrc/private.src\n");
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(A, "src/shared.src\n");
    let out = run(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t tests/b.t"]);
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "none");
    s.clear_log();
    let next = run(&s, &[]);
    success(&next);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["residue"]["state"], "confirmed", "{bundle}");
    for unit in [A, B] {
        assert_eq!(bundle["units"][unit][0]["exact"], true, "{unit}: {bundle}");
    }
}

#[test]
fn g_r3_explain_counts_inexact_units_for_completion() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write("tests/d.t", "src/c.src\n");
    let out = explain_words(&s, &["./t", HOOK], &GROUP);
    assert!(s.launches().is_empty());
    let message = all_output(&out);
    assert!(
        message.contains("would launch 3 units without a current exact proof, one launch each"),
        "{message}"
    );
    let run = run(&s, &[]);
    success(&run);
    assert_eq!(launched(&s), ["", A, B, "tests/d.t"]);
}

#[test]
fn g_a1_a_failing_forced_full_run_with_inexact_proofs_disables() {
    let s = Suite::new();
    let gate = s.outside.join("fail-full");
    let extra = [("T_IF", gate.to_str().unwrap()), ("T_FAIL_FULL", "1")];
    warm(&s, &extra);
    make_group(&s, &extra);
    fs::write(&gate, "fail").unwrap();
    let forced = [
        ("T_IF", gate.to_str().unwrap()),
        ("T_FAIL_FULL", "1"),
        ("STOOP_FULL", "1"),
    ];
    let out = run(&s, &forced);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    let bundle = s.bundle().unwrap();
    assert_eq!(bundle["state"]["status"], "disabled", "{bundle}");
    assert_eq!(bundle["state"]["code"], "disagreement", "{bundle}");
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &extra)));
}

#[test]
fn g_k1_inexact_proofs_stay_valid_with_grouping_off() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    let no_group = [("STOOP_SPLIT", "1")];
    success(&s.hook(&no_group));
    assert!(s.launches().is_empty());
    s.write(A, "src/shared.src\n\n");
    let out = s.hook(&no_group);
    success(&out);
    assert_eq!(launched(&s), [A, B], "{}", text(&out.stderr));
    for unit in [A, B] {
        assert_eq!(s.bundle().unwrap()["units"][unit][0]["exact"], true);
    }
}

#[test]
fn g_o1_a_new_unit_beside_a_grouped_edit_takes_the_full_form() {
    let s = Suite::new();
    warm(&s, &[]);
    make_group(&s, &[]);
    s.write(A, "src/shared.src\n\n");
    s.write("tests/d.t", "src/c.src\n");
    let out = run(&s, &[]);
    success(&out);
    assert_full(
        &s,
        &out,
        "tests/d.t was not on the roster of the last full run",
    );
    assert_eq!(code(&out), code(&s.direct(&s.root, &[], &[])));
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
    let env: Vec<_> = GROUP.into_iter().chain(extra.iter().copied()).collect();
    let prediction = explain_words(&s, &["./t", HOOK], &env);
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
// Record the original argv, then adapt option and list forms to the fixture runner.
const ARGV_413: &str = r#"#!/bin/sh
ROOT=$(cd "$(dirname "$0")" && pwd -P) || exit 2
cat "$ROOT/.stoop.toml" >/dev/null
printf 'launch\n' >> "$LOG.argv"
entries=
add() {
	old_ifs=$IFS
	IFS=',
 '
	set -f
	for part in $1; do
		case "$part" in
			tests/*.t|tests/*.u) entries="$entries$part
" ;;
		esac
	done
	set +f
	IFS=$old_ifs
}
for word in "$@"; do
	printf 'arg=%s\n' "$word" >> "$LOG.argv"
	case "$word" in
		@*) add "$(cat "${word#@}")" ;;
		--files=*) add "${word#--files=}" ;;
		-f=*) add "${word#-f=}" ;;
		-f?*) add "${word#-f}" ;;
		*) add "$word" ;;
	esac
done
old=$IFS
IFS='
'
set -f
set -- $entries
IFS=$old
set +f
exec "$ROOT/t" "$@"
"#;

#[test]
fn a10n_the_4_13_rows_run_end_to_end() {
    struct Row {
        words: &'static [&'static str],
        expected: &'static [&'static str],
        many: bool,
        mixed: bool,
    }
    let rows = [
        Row {
            words: &["./argv", "--files", "{changed}"],
            expected: &["launch", "arg=--files", "arg=tests/a.t", "arg=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files={changed}"],
            expected: &["launch", "arg=--files=tests/a.t", "arg=--files=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "-f", "{changed}"],
            expected: &["launch", "arg=-f", "arg=tests/a.t", "arg=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "-f={changed}"],
            expected: &["launch", "arg=-f=tests/a.t", "arg=-f=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "-f{changed}"],
            expected: &["launch", "arg=-ftests/a.t", "arg=-ftests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "-f", "{changed:each}"],
            expected: &[
                "launch",
                "arg=-f",
                "arg=tests/a.t",
                "arg=-f",
                "arg=tests/b.t",
            ],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files={changed:comma}"],
            expected: &["launch", "arg=--files=tests/a.t,tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files=base,{changed:comma}"],
            expected: &["launch", "arg=--files=base,tests/a.t,tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files", "base", "--files", "{changed}"],
            expected: &[
                "launch",
                "arg=--files",
                "arg=base",
                "arg=--files",
                "arg=tests/a.t",
                "arg=tests/b.t",
            ],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files", "base", "more", "{changed}"],
            expected: &[
                "launch",
                "arg=--files",
                "arg=base",
                "arg=more",
                "arg=tests/a.t",
                "arg=tests/b.t",
            ],
            many: true,
            mixed: false,
        },
        Row {
            words: &["./argv", "-v", "--", "{changed}"],
            expected: &[
                "launch",
                "arg=-v",
                "arg=--",
                "arg=tests/a.t",
                "arg=tests/b.t",
            ],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "{changed:**/*.t}"],
            expected: &["launch", "arg=tests/a.t", "arg=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files", "{changed:**/*.t|**/*.u}"],
            expected: &["launch", "arg=--files", "arg=tests/a.t", "arg=tests/b.u"],
            many: false,
            mixed: true,
        },
        Row {
            words: &["./argv", "{unit:**/*.t}"],
            expected: &["launch", "arg=tests/a.t", "launch", "arg=tests/b.t"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "@{changed:file}"],
            expected: &["launch", "arg=@<list>"],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./npm", "test", "--", "--files", "{changed}"],
            expected: &[
                "launch",
                "arg=test",
                "arg=--",
                "arg=--files",
                "arg=tests/a.t",
                "arg=tests/b.t",
            ],
            many: false,
            mixed: false,
        },
        Row {
            words: &["./argv", "--files", "$STOOP_CHANGED"],
            expected: &["launch", "arg=--files", "arg=tests/a.t", "arg=tests/b.t"],
            many: false,
            mixed: false,
        },
    ];
    for row in rows {
        let s = Suite::new();
        s.remove("slow/s.t");
        s.remove("e2e/x.u");
        if row.mixed {
            s.remove(B);
            s.write("tests/b.u", "src/shared.src\n");
        }
        s.executable("argv", ARGV_413);
        s.executable("npm", ARGV_413);
        let options = if row.many {
            "options = [{ names = [\"--files\"], values = \"many\" }]\n"
        } else {
            ""
        };
        s.config(&format!(
            "[[units.suite]]\nid = \"args\"\nmatch = {}\nunits = [\"tests/*.t\", \"tests/*.u\"]\n{options}",
            serde_json::to_string(row.words).unwrap()
        ));
        let mut env = GROUP.to_vec();
        if row.mixed {
            env.push(("T_U", "1"));
        }
        let warm = s.run(&s.root, &[], row.words, &env);
        success(&warm);
        let log = s.log.with_extension("argv");
        fs::remove_file(&log).unwrap();
        s.clear_log();
        edit_shared(&s);
        let out = s.run(&s.root, &[], row.words, &env);
        success(&out);
        let raw = fs::read_to_string(&log).unwrap();
        let actual: Vec<_> = raw
            .lines()
            .map(|line| {
                if line.starts_with("arg=@") {
                    "arg=@<list>"
                } else {
                    line
                }
            })
            .collect();
        assert_eq!(
            actual,
            row.expected,
            "{:?}: {}",
            row.words,
            text(&out.stderr)
        );
        let expected_units = if row.mixed {
            vec![A, "tests/b.u"]
        } else {
            vec![A, B]
        };
        let ran: Vec<_> = s
            .launches()
            .iter()
            .flat_map(|launch| {
                launch
                    .ran()
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .collect();
        assert_eq!(ran, expected_units, "{:?}", row.words);
    }
}

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
