//! Completion (spec 3.10, W7-3) and the first changed run (issue #84). With `STOOP_SPLIT=1`, a passing, recorded
//! first-run form learns the unit proofs that it leaves without a valid version, one launch each, after its own
//! verdict is settled. Until a suite holds every unit's proof, a changed run takes the full form, so no attribution pass
//! decides the verdict. The suite is the pinned fixture.
//! These tests drive the stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and arm64
//! only, as `units_split.rs` does.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod units_common;

use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::process::Output;
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");

/// The line a learning run prints before its launches (spec 3.12).
const COMPLETION_HEADER: &str =
    "stoop: attribution pass after the full run: 3 units, one launch each";

/// The line `stoop explain` prints for a full command whose passing run would learn the units (spec 3.12).
const COMPLETION_LINE: &str =
    "stoop: if the full command passes, would launch 3 units without a current proof, one launch each";

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// `env` followed by `extra`.
fn with<'a>(env: &[(&'a str, &'a str)], extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    env.iter().chain(extra).copied().collect()
}

/// The pinned hook under `env`, with the engine on.
fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    s.hook(&with(&[SPLIT], env))
}

/// `stoop explain` of the pinned hook under `env`, with the engine on.
fn explain(s: &Suite, env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    command.env(SPLIT.0, SPLIT.1);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

/// The argument words of each launch the runner logged since the log was cleared, joined by spaces. A full run has
/// one launch with no words, which reads as the empty string.
fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

/// A change to the source that units `a` and `b` read. The file's length follows `n`, so the change is certain.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

/// The stored state of the suite's bundle.
fn state(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")["state"].clone()
}

/// Holds the suite's lock, as another stoop run would, until the returned file is dropped.
fn hold_lock(s: &Suite) -> File {
    let lock = s
        .bundle_path()
        .expect("a suite bundle")
        .with_extension("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap();
    // SAFETY: the descriptor is an open file, and flock takes no pointers.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "the test could not hold the suite lock");
    file
}

/// C1: a full run that fails learns nothing. The fixed full run learns every unit, the unchanged run is a legacy skip,
/// and the next change to one unit is a subset of one launch.
#[test]
fn c1_a_failing_full_run_learns_nothing_and_the_fixed_one_learns_every_unit() {
    let s = Suite::new();
    s.write("tests/b.flag", "fail\n");
    let failed = split(&s, &[]);
    assert_eq!(code(&failed), 1, "{}", stderr(&failed));
    assert!(s.bundle().is_none(), "a failing full run records nothing");
    s.write("tests/b.flag", "ok\n");
    s.clear_log();
    let learned = split(&s, &[]);
    success(&learned);
    assert!(
        stderr(&learned).contains(COMPLETION_HEADER),
        "{}",
        stderr(&learned)
    );
    assert_eq!(launched(&s), ["", "tests/a.t", "tests/b.t", "tests/c.t"]);
    s.clear_log();
    let unchanged = split(&s, &[]);
    success(&unchanged);
    assert!(
        stderr(&unchanged).contains("stoop: skip "),
        "{}",
        stderr(&unchanged)
    );
    assert!(launched(&s).is_empty(), "{:?}", launched(&s));
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let changed = split(&s, &[]);
    success(&changed);
    assert_eq!(launched(&s), ["tests/c.t"]);
}

/// C2: a unit that fails when launched alone, while the full command passes, disables the suite with the completion
/// phase. The run keeps the full command's status, which is zero.
#[test]
fn c2_a_unit_that_fails_alone_while_the_full_command_passes_disables_the_suite() {
    let s = Suite::new();
    let go = s.outside.join("go");
    fs::write(&go, "").unwrap();
    let go = go.to_str().unwrap().to_owned();
    let out = split(&s, &[("T_FAIL_ALONE", "tests/b.t"), ("T_IF", &go)]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let state = state(&s);
    assert_eq!(state["status"], "disabled", "{state}");
    assert_eq!(state["code"], "disagreement", "{state}");
    assert_eq!(state["phase"], "completion", "{state}");
    assert!(
        state["label"]
            .as_str()
            .is_some_and(|label| label.contains("tests/b.t")),
        "{state}"
    );
}

/// C3: explain names the units that the passing run would learn, and the run launches exactly those, one each.
#[test]
fn c3_explain_predicts_the_completion_launches_and_the_run_makes_them() {
    let s = Suite::new();
    let before = explain(&s, &[]);
    assert!(
        stderr(&before).contains(COMPLETION_LINE),
        "{}",
        stderr(&before)
    );
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["", "tests/a.t", "tests/b.t", "tests/c.t"]);
}

/// C4 (issue #84): a suite whose bundle holds no unit proof takes the full form on its first changed run. A runner-only
/// test that fails is then the verdict, where an attribution pass over the units would exit 0.
#[test]
fn c4_the_first_changed_run_takes_the_full_form_when_no_unit_holds_a_proof() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    // The switch is off for the cold run, so the bundle holds the whole proof and no unit proof.
    success(&s.hook(&env));
    s.write("tests/z.flag", "fail\n");
    edit(&s, 2);
    let out = split(&s, &env);
    assert_eq!(
        code(&out),
        1,
        "the full form runs tests/z.u, which fails: {}",
        stderr(&out)
    );
    assert!(
        !stderr(&out).contains("stoop: attribution pass: "),
        "{}",
        stderr(&out)
    );
}

/// C5: a CI run learns nothing, and a changed CI run takes the full form.
#[test]
fn c5_a_ci_run_never_completes() {
    let s = Suite::new();
    let env = [("CI", "true")];
    s.clear_log();
    let cold = split(&s, &env);
    success(&cold);
    assert!(
        !stderr(&cold).contains("attribution pass after the full run"),
        "{}",
        stderr(&cold)
    );
    assert_eq!(launched(&s), [""]);
    edit(&s, 2);
    s.clear_log();
    let changed = split(&s, &env);
    success(&changed);
    assert_eq!(launched(&s), [""], "{}", stderr(&changed));
}

/// C6: a suite lock that another run holds stops the learning silently. The bundle is left as it was.
#[test]
fn c6_a_busy_suite_lock_stops_completion_silently() {
    let s = Suite::new();
    success(&split(&s, &[]));
    let before = s.bundle();
    // Every unit reads `setup.src`, so this run is a full run. The lock is held, so nothing is recorded or learned.
    s.write("setup.src", "setup changed\n");
    let lock = hold_lock(&s);
    s.clear_log();
    let out = split(&s, &[]);
    drop(lock);
    success(&out);
    assert!(
        !stderr(&out).contains("attribution pass after the full run"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("busy"), "{}", stderr(&out));
    assert_eq!(s.bundle(), before);
}

/// C7: while the full command leaves a residue that no unit names, every changed run is a full run, and its completion
/// relaunches only the units whose proof no longer holds. Here `c` changes, and `a` and `b` keep their proofs.
#[test]
fn c7_a_completion_relaunches_only_the_units_without_a_valid_proof() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    success(&split(&s, &env));
    s.write("tests/c.t", "src/c.src\n\n");
    let predicted = explain(&s, &env);
    assert!(
        stderr(&predicted).contains(
            "stoop: if the full command passes, would launch 1 units without a current proof, one launch each"
        ),
        "{}",
        stderr(&predicted)
    );
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert!(
        stderr(&out).contains("stoop: run full "),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), ["", "tests/c.t"], "{}", stderr(&out));
}

/// C8: a unit whose launch writes the input of another unit breaks the independence check at completion. The suite is
/// disabled with that violation in the completion phase, and the status is the full command's.
#[test]
fn c8_a_completion_violation_disables_the_suite() {
    let s = Suite::new();
    let out = split(&s, &[("T_WRITE", "src/c.src"), ("T_WRITE_AT", "tests/a.t")]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let state = state(&s);
    assert_eq!(state["status"], "disabled", "{state}");
    assert_eq!(state["code"], "wrote_input", "{state}");
    assert_eq!(state["phase"], "completion", "{state}");
}

/// C9: with the switch off, a passing full run learns nothing. The cold run launches the full command only, and the next
/// changed run is the switch-off attribution pass, as it was before the engine.
#[test]
fn c9_the_switch_off_learns_nothing_after_a_full_run() {
    let s = Suite::new();
    s.clear_log();
    success(&s.hook(&[]));
    assert_eq!(launched(&s), [""]);
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[]);
    success(&out);
    assert!(
        stderr(&out).contains("stoop: attribution pass: "),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t", "tests/c.t"]);
}

/// C10: the documented root-listing gap, pinned so that it is not read as a guarantee. A whole-command proof does not
/// record the entry list of the repository root, so a unit added at the top level, with no other change, is skipped by the
/// legacy hit. That holds with the switch off and with it on, after a passing full run. The test asserts the skip, and the
/// runner's own status on the same tree shows the false pass.
#[test]
fn c10_a_top_level_unit_added_after_a_passing_full_run_is_skipped_by_the_documented_root_gap() {
    for on in [false, true] {
        let s = Suite::new();
        let run = |s: &Suite| {
            if on {
                split(s, &[])
            } else {
                s.hook(&[])
            }
        };
        success(&run(&s));
        s.write("top.t", "src/c.src\n");
        s.write("top.flag", "fail\n");
        s.clear_log();
        let out = run(&s);
        assert_eq!(code(&out), 0, "switch on {on}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("stoop: skip "),
            "switch on {on}: {}",
            stderr(&out)
        );
        assert!(
            launched(&s).is_empty(),
            "switch on {on}: {:?}",
            launched(&s)
        );
        assert_ne!(
            code(&s.direct(&s.root, &[], &[])),
            0,
            "switch on {on}: the runner fails on top.t"
        );
    }
}
