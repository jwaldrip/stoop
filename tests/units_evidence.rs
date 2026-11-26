//! A per-unit run cannot exit 0 on a launch that left no member evidence, and a launch that could not be traced has no
//! evidence at all (W7-4c, issue #91). Each test is one row of the class table in the pull request: the branch the
//! launch takes, its position among the launches, the evidence its own unit leaves, its exit status and whether it was
//! traced. Linux only, as the tracer and the fork shim are.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::fs;
use std::process::{Command, Output};
use units_common::*;

const A: &str = "tests/a.t";
const B: &str = "tests/b.t";
const C: &str = "tests/c.t";
const SPLIT: [(&str, &str); 1] = [("STOOP_SPLIT", "1")];

const FORK_SHIM: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
pid_t fork(void) {
    static pid_t (*real_fork)(void);
    if (!real_fork) real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
    const char *gate = getenv("STOOP_TEST_FORK_MARKER");
    struct stat st;
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (gate && n > 0 && stat(gate, &st) == 0) {
        exe[n] = 0;
        const char *name = strrchr(exe, '/');
        if (name && strcmp(name + 1, "stoop") == 0) {
            errno = EAGAIN;
            return -1;
        }
    }
    return real_fork();
}
"#;

/// The fixture runner with five seams. `RVW_ACTION` acts in the launch of `tests/b.t` alone, and only while `RVW_GATE`
/// exists: `read_c` reads `tests/c.t`, `write_own` writes `tests/b.t`, `write_input` writes `src/shared.src` (an input
/// of `tests/a.t`), `write_output` writes `.outputs/a.t.out` (an output of `tests/a.t`), and `fail` exits 1.
/// `RVW_DROP_GATE` removes the gate in the launch of `tests/a.t`, after that launch's trace was refused, so the next
/// launch is traced. `RVW_FULL_FAIL` fails `tests/b.t` in the full form only. `RVW_CREATE_GATE` creates the gate as
/// the full form ends, so the learning launches that follow it are untraced.
fn runner() -> String {
    let runner = include_str!("fixtures/hook/t");
    assert_eq!(runner.matches("STATUS=0\n").count(), 1);
    assert_eq!(runner.matches("note \"ran=$1\"").count(), 1);
    assert_eq!(runner.matches("exit \"$STATUS\"").count(), 1);
    let seams = r#"
if [ "$#" -eq 1 ] && [ "$1" = tests/b.t ] && [ -e "$RVW_GATE" ]; then
    case "$RVW_ACTION" in
        read_c) cat "$ROOT/tests/c.t" > /dev/null ;;
        write_own) printf 'written\n' > "$ROOT/tests/b.t" ;;
        write_input) printf 'written\n' > "$ROOT/src/shared.src" ;;
        write_output) printf 'written\n' > "$ROOT/.outputs/a.t.out" ;;
        fail) STATUS=1 ;;
    esac
fi
if [ "$#" -eq 1 ] && [ "$1" = tests/a.t ] && [ "${RVW_DROP_GATE:-}" = 1 ] && [ -e "$RVW_GATE" ]; then
    rm -f "$RVW_GATE"
fi
"#;
    runner
        .replace("STATUS=0\n", &format!("STATUS=0\n{seams}"))
        .replace(
            "note \"ran=$1\"",
            r#"note "ran=$1"
    if [ "$TESTS" = 0 ] && [ "$1" = tests/b.t ] && [ -n "${RVW_FULL_FAIL:-}" ]; then STATUS=1; fi"#,
        )
        .replace(
            "exit \"$STATUS\"",
            "if [ \"$TESTS\" = 0 ] && [ -n \"${RVW_CREATE_GATE:-}\" ]; then : > \"$RVW_CREATE_GATE\"; fi\nexit \"$STATUS\"",
        )
}

fn suite() -> Suite {
    let s = Suite::new();
    s.executable("t", &runner());
    fs::create_dir(s.path(".outputs")).unwrap();
    s
}

fn gate(s: &Suite) -> String {
    s.outside.join("gate").to_str().unwrap().to_owned()
}

fn arm(gate: &str) {
    fs::write(gate, "on").unwrap();
}

fn hook(s: &Suite, extra: &[(&str, &str)]) -> Output {
    let env: Vec<_> = SPLIT.into_iter().chain(extra.iter().copied()).collect();
    s.hook(&env)
}

fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

/// The unit proofs the bundle holds, counted across every unit.
fn unit_proofs(s: &Suite) -> usize {
    let bundle = s.bundle().unwrap();
    bundle["units"].as_object().map_or(0, |units| {
        units
            .values()
            .map(|versions| versions.as_array().map_or(0, Vec::len))
            .sum()
    })
}

/// The full form learns every unit's proof, as a suite does before a subset run.
fn warm(s: &Suite, extra: &[(&str, &str)]) {
    s.clear_log();
    let out = hook(s, extra);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(launched(s), ["", A, B, C], "{}", text(&out.stderr));
    s.clear_log();
}

/// Changes `src/shared.src`, which `tests/a.t` and `tests/b.t` both read: both are affected, and `a` launches first.
fn edit_shared(s: &Suite) {
    s.write("src/shared.src", "shared changed\n");
}

/// Changes only `tests/b.t`: the one affected unit, so its launch is both the first and the last.
fn edit_b_only(s: &Suite) {
    s.write(B, "src/shared.src\n\n");
}

fn fork_shim(s: &Suite) -> String {
    let source = s.outside.join("fork-shim.c");
    let library = s.outside.join("fork-shim.so");
    fs::write(&source, FORK_SHIM).unwrap();
    let built = spawning(|| {
        Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .arg("-ldl")
            .output()
    })
    .unwrap();
    assert!(built.status.success(), "{}", text(&built.stderr));
    library.to_str().unwrap().to_owned()
}

/// Runs the full command traced, so it records a whole proof, and creates the gate as it ends. The completion launches
/// that follow it are untraced, so the suite holds a whole proof and no unit proof. Returns the shim library, the gate
/// and the run's output.
fn whole_proof_without_unit_proofs(s: &Suite) -> (String, String, Output) {
    let library = fork_shim(s);
    let gate = gate(s);
    let out = {
        let env = [
            ("LD_PRELOAD", library.as_str()),
            ("STOOP_TEST_FORK_MARKER", gate.as_str()),
            ("RVW_CREATE_GATE", gate.as_str()),
        ];
        hook(s, &env)
    };
    (library, gate, out)
}

#[test]
fn a_last_launch_that_skips_its_unit_cannot_exit_zero() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[]);
    arm(&gate);
    edit_shared(&s);
    let env = [("T_SKIP_TEST", B), ("T_IF", gate.as_str())];
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
    // The full command fails tests/b.t, so an exit 0 here would be a false pass.
    let truth = s.direct(&s.root, &[], &[("RVW_FULL_FAIL", "1")]);
    assert_eq!(code(&truth), 1, "{}", text(&truth.stderr));
}

#[test]
fn a_last_stat_only_launch_cannot_exit_zero() {
    let s = suite();
    warm(&s, &[]);
    edit_b_only(&s);
    s.clear_log();
    let out = hook(&s, &[("T_STAT_UNIT", "1")]);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [B], "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_last_launch_coupling_with_only_a_stat_of_its_unit_cannot_exit_zero() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_b_only(&s);
    s.clear_log();
    let out = hook(
        &s,
        &[
            ("RVW_GATE", gate.as_str()),
            ("RVW_ACTION", "read_c"),
            ("T_STAT_UNIT", "1"),
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [B], "{stderr}");
    assert!(stderr.contains("tests/b.t read tests/c.t"), "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_last_launch_that_writes_its_own_unit_without_reading_it_cannot_exit_zero() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_shared(&s);
    let env = [
        ("T_SKIP_TEST", B),
        ("T_IF", gate.as_str()),
        ("RVW_GATE", gate.as_str()),
        ("RVW_ACTION", "write_own"),
    ];
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_last_launch_that_writes_a_named_input_without_reading_its_unit_cannot_exit_zero() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_shared(&s);
    let env = [
        ("T_SKIP_TEST", B),
        ("T_IF", gate.as_str()),
        ("RVW_GATE", gate.as_str()),
        ("RVW_ACTION", "write_input"),
    ];
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_last_launch_that_writes_a_named_output_without_reading_its_unit_cannot_exit_zero() {
    let s = suite();
    let gate = gate(&s);
    let mut extra = vec![
        ("T_WRITE_EACH", "1"),
        ("T_OUTPUT_DIR", ".outputs"),
        ("RVW_GATE", gate.as_str()),
    ];
    warm(&s, &extra);
    arm(&gate);
    edit_shared(&s);
    extra.extend([
        ("T_SKIP_TEST", B),
        ("T_IF", gate.as_str()),
        ("RVW_ACTION", "write_output"),
    ]);
    s.clear_log();
    let out = hook(&s, &extra);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        stderr.contains("tests/b.t did not run in its launch"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_last_launch_that_fails_without_reading_its_unit_keeps_its_status() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_shared(&s);
    let env = [
        ("T_SKIP_TEST", B),
        ("T_IF", gate.as_str()),
        ("RVW_GATE", gate.as_str()),
        ("RVW_ACTION", "fail"),
    ];
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(!stderr.contains("did not run in its launch"), "{stderr}");
    assert_eq!(code(&out), 1, "{stderr}");
}

#[test]
fn a_last_launch_that_reads_its_unit_keeps_its_verdict() {
    let s = suite();
    warm(&s, &[]);
    edit_shared(&s);
    s.clear_log();
    let out = hook(&s, &[]);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(!stderr.contains("did not run in its launch"), "{stderr}");
    assert_eq!(code(&out), 0, "{stderr}");
    assert_eq!(s.bundle().unwrap()["state"]["status"], "ready", "{stderr}");
}

#[test]
fn a_last_launch_coupling_with_its_own_read_keeps_its_verdict() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_shared(&s);
    s.clear_log();
    let out = hook(&s, &[("RVW_GATE", gate.as_str()), ("RVW_ACTION", "read_c")]);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(stderr.contains("tests/b.t read tests/c.t"), "{stderr}");
    assert!(!stderr.contains("did not run in its launch"), "{stderr}");
    assert_eq!(
        s.bundle().unwrap()["state"]["code"],
        "read_unit",
        "{stderr}"
    );
    assert_eq!(code(&out), 0, "{stderr}");
}

#[test]
fn a_last_launch_writing_a_named_input_with_its_own_read_keeps_its_verdict() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[("RVW_GATE", gate.as_str())]);
    arm(&gate);
    edit_shared(&s);
    s.clear_log();
    let out = hook(
        &s,
        &[("RVW_GATE", gate.as_str()), ("RVW_ACTION", "write_input")],
    );
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(!stderr.contains("did not run in its launch"), "{stderr}");
    assert_eq!(
        s.bundle().unwrap()["state"]["code"],
        "wrote_input",
        "{stderr}"
    );
    assert_eq!(code(&out), 0, "{stderr}");
}

#[test]
fn a_non_last_launch_that_skips_its_unit_keeps_its_stop_message() {
    let s = suite();
    let gate = gate(&s);
    warm(&s, &[]);
    arm(&gate);
    edit_shared(&s);
    s.clear_log();
    let out = hook(&s, &[("T_SKIP_TEST", A), ("T_IF", gate.as_str())]);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A], "{stderr}");
    assert!(stderr.contains("only 1 of 2 launches ran"), "{stderr}");
    assert!(!stderr.contains("did not run in its launch"), "{stderr}");
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn an_untraced_launch_that_exits_zero_before_a_traced_pass_has_no_verdict() {
    let s = suite();
    let library = fork_shim(&s);
    let gate = gate(&s);
    let shim = [
        ("LD_PRELOAD", library.as_str()),
        ("STOOP_TEST_FORK_MARKER", gate.as_str()),
    ];
    warm(&s, &shim);
    let before = s.bundle().unwrap();
    arm(&gate);
    edit_shared(&s);
    let mut env = shim.to_vec();
    env.extend([("RVW_GATE", gate.as_str()), ("RVW_DROP_GATE", "1")]);
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        stderr
            .contains("the launch of tests/a.t could not be traced, so it has no member evidence"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
    let after = s.bundle().unwrap();
    assert_eq!(after["state"]["status"], "ready", "{stderr}");
    // The untraced launch recorded no version, so a keeps the one it had.
    assert_eq!(
        after["units"][A].as_array().unwrap().len(),
        before["units"][A].as_array().unwrap().len(),
        "{stderr}"
    );
    assert_eq!(
        after["units"][A][0]["created"], before["units"][A][0]["created"],
        "{stderr}"
    );
}

#[test]
fn an_untraced_launch_that_fails_keeps_its_status_without_a_mark() {
    let s = suite();
    let library = fork_shim(&s);
    let gate = gate(&s);
    let shim = [
        ("LD_PRELOAD", library.as_str()),
        ("STOOP_TEST_FORK_MARKER", gate.as_str()),
    ];
    warm(&s, &shim);
    arm(&gate);
    edit_shared(&s);
    let mut env = shim.to_vec();
    env.extend([
        ("RVW_GATE", gate.as_str()),
        ("RVW_DROP_GATE", "1"),
        ("T_FAIL_ALONE", A),
    ]);
    s.clear_log();
    let out = hook(&s, &env);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [A, B], "{stderr}");
    assert!(
        !stderr.contains("could not be traced, so it has no member evidence"),
        "{stderr}"
    );
    assert_eq!(code(&out), 1, "{stderr}");
}

#[test]
fn a_completion_launch_that_cannot_be_traced_keeps_the_full_commands_status() {
    let s = suite();
    let (_library, _gate, out) = whole_proof_without_unit_proofs(&s);
    let stderr = text(&out.stderr);
    // Completion after a full run keeps the full command's status. Its untraced launches record nothing and say so.
    assert_eq!(code(&out), 0, "{stderr}");
    assert_eq!(launched(&s), ["", A, B, C], "{stderr}");
    assert!(
        stderr.contains("running tests/a.t without a proof"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("could not be traced, so it has no member evidence"),
        "{stderr}"
    );
    assert_eq!(unit_proofs(&s), 0, "{stderr}");
}

#[test]
fn an_attribution_pass_of_a_suite_with_a_whole_proof_and_no_unit_proof_has_no_verdict_when_untraced(
) {
    let s = suite();
    let (library, gate, first) = whole_proof_without_unit_proofs(&s);
    assert_eq!(code(&first), 0, "{}", text(&first.stderr));
    let shim = [
        ("LD_PRELOAD", library.as_str()),
        ("STOOP_TEST_FORK_MARKER", gate.as_str()),
    ];
    // A changed run that starts an attribution pass takes its verdict from its launches: `attribution::pass` returns
    // their status as the run's exit, so an untraced exit 0 there is no verdict (decision A). Completion, in the first
    // run above, is different: `subset::learn` keeps the full command's status and never calls `finish`.
    edit_shared(&s);
    s.clear_log();
    let out = hook(&s, &shim);
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("stoop: attribution pass: 3 units, one launch each"),
        "{stderr}"
    );
    assert_eq!(launched(&s), [A, B, C], "{stderr}");
    assert!(
        stderr
            .contains("the launch of tests/a.t could not be traced, so it has no member evidence"),
        "{stderr}"
    );
    assert_eq!(code(&out), 125, "{stderr}");
}

#[test]
fn a_suite_with_no_recorded_proof_takes_the_full_form_when_tracing_fails() {
    let s = suite();
    let library = fork_shim(&s);
    let gate = gate(&s);
    arm(&gate);
    let shim = [
        ("LD_PRELOAD", library.as_str()),
        ("STOOP_TEST_FORK_MARKER", gate.as_str()),
        ("T_FAIL_FULL", "1"),
    ];
    let out = hook(&s, &shim);
    let stderr = text(&out.stderr);
    assert_eq!(launched(&s), [""], "{stderr}");
    assert!(
        !stderr.contains("could not be traced, so it has no member evidence"),
        "{stderr}"
    );
    assert!(!stderr.contains("attribution pass"), "{stderr}");
    let truth = s.direct(&s.root, &[], &shim);
    assert_eq!(code(&truth), 1, "{}", text(&truth.stderr));
    assert_eq!(code(&out), 1, "{stderr}");
}
