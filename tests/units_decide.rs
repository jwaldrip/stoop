//! The decision engine (spec 3.9 and 3.10, W7-1). With `STOOP_SPLIT` set, a changed run of a hooked suite skips when no
//! unit is affected, and every other decision takes the full form with the reason the spec gives. These tests drive the
//! stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and arm64 only. Each one says what it
//! fails on the base, which has no engine. They are named T1 to T17 after the W7-1 table (its D1 to D17), because the
//! harness keeps the D numbers for its base-versus-head scenarios.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// A change to a source that units read: the file's length follows `n`, so the change is certain.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

/// `env` followed by `extra`.
fn with<'a>(env: &[(&'a str, &'a str)], extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    env.iter().chain(extra).copied().collect()
}

/// The pinned hook under `env`, with the engine on.
fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    s.hook(&with(&[SPLIT], env))
}

/// A suite whose units hold proofs: a cold run under `env` with the switch off, then a change and a run under `env` and
/// `switch`. With the switch on, that run is the full form, and its completion learns every unit's proof. Returns the
/// run's output.
fn passed(s: &Suite, env: &[(&str, &str)], switch: &[(&str, &str)]) -> Output {
    success(&s.hook(env));
    edit(s, 2);
    s.hook(&with(env, switch))
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

/// The decision a run or an explain prints, as one word. Explain's lines name the same decisions as the run's.
fn decision(out: &Output) -> &'static str {
    let log = stderr(out);
    if log.contains("stoop: skip ") {
        "skip"
    } else if log.contains("stoop: attribution pass: ")
        || log.contains("would run an attribution pass: ")
        || log.contains("(attribution pass): ")
    {
        "pass"
    } else if log.contains("inputs; run ") || log.contains(" units affected, one launch each)") {
        "subset"
    } else if log.contains("run full ") {
        "full"
    } else {
        "none"
    }
}

/// Explains the hook under `env`, then runs it, and checks that both make the decision `expect`. A skip exits 0.
fn agree(s: &Suite, env: &[(&str, &str)], expect: &str) {
    let explained = explain(s, env);
    let ran = split(s, env);
    assert_eq!(
        decision(&explained),
        expect,
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), expect, "run: {}", stderr(&ran));
    if expect == "skip" {
        success(&ran);
    }
}

/// The hook with `STOOP_SPLIT` set to `value`, or unset when `value` is `None`, so a test can name a value that is
/// not text.
fn hook_with_switch(s: &Suite, value: Option<&OsStr>) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    if let Some(value) = value {
        command.env(SPLIT.0, value);
    }
    spawning(|| command.output()).unwrap()
}

/// Runs `git` in the root with the fixture's environment.
fn git(s: &Suite, args: &[&str]) {
    let status = spawning(|| {
        Command::new("git")
            .current_dir(&s.root)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &s.outside)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .args(args)
            .status()
    })
    .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// The lock file of the suite's bundle, which every write takes.
fn lock_path(s: &Suite) -> PathBuf {
    s.bundle_path()
        .expect("a suite bundle")
        .with_extension("lock")
}

/// Holds the suite's lock, as another stoop run would, until the returned file is dropped.
fn hold_lock(s: &Suite) -> File {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path(s))
        .unwrap();
    // SAFETY: the descriptor is an open file, and flock takes no pointers.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(rc, 0, "the test could not hold the suite lock");
    file
}

/// The stored state of the suite's bundle.
fn state(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")["state"].clone()
}

/// T1 (D1): a run that changes nothing after a pass skips. It launches nothing and exits 0. The base has no engine, so
/// it runs the full form.
#[test]
fn t1_an_unchanged_run_after_a_pass_skips() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    // The skip line keeps the whole command's key, which the MCP explain parser reads (spec 3.12).
    assert!(
        stderr(&out).contains("stoop: skip hook-t-"),
        "{}",
        stderr(&out)
    );
    // The full run after the pass recorded the whole proof, so this run is a whole-command hit. It prints the legacy
    // skip line, which keeps the same key.
    assert!(
        stderr(&out).contains("inputs unchanged since"),
        "{}",
        stderr(&out)
    );
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// T2 (D2): an edit to a file that no unit reads is not a change to any unit, so the run skips.
#[test]
fn t2_an_edit_no_unit_reads_skips() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("docs/readme.md", "edited\n");
    s.write("src/dead.src", "edited\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// T3 (D3): with `STOOP_SPLIT` unset, `0`, empty, `off` or not UTF-8, the unchanged run after a pass takes the full
/// form, as it does without the engine.
#[test]
fn t3_the_switch_off_keeps_the_full_form() {
    let values: [Option<&OsStr>; 5] = [
        None,
        Some(OsStr::new("0")),
        Some(OsStr::new("")),
        Some(OsStr::new("off")),
        Some(OsStr::from_bytes(b"\xff")),
    ];
    for value in values {
        let s = Suite::new();
        success(&passed(&s, &[], &[]));
        s.clear_log();
        let out = hook_with_switch(&s, value);
        success(&out);
        assert_eq!(decision(&out), "full", "{value:?}: {}", stderr(&out));
        assert_eq!(
            s.launches().len(),
            1,
            "{value:?}: the full form launches once"
        );
    }
}

/// T4 (D4): a file that only `lint` reads is residue. The next change takes the full form, and the reason names it.
#[test]
fn t4_residue_takes_the_full_form_and_names_it() {
    let s = Suite::new();
    let env = [("T_LINT", "1")];
    success(&passed(&s, &env, &[SPLIT]));
    // `lint` is read only by the full command, so a change to it is residue and takes the full form.
    s.write("lint", "#!/bin/sh\nexit 0\n# changed\n");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out)
            .contains("the full command reads 1 file no unit's own run reads, such as lint"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T5 (D5), replaced for W7-3. On the base, a unit that fails in the pass keeps no proof, so the residue is not matched
/// to the units, and the next change takes the full form with the reason "not matched yet". With the switch on there is
/// no pass, and a failing full run records nothing (C1 and C2 in units_completion.rs pin the failing cases). This test
/// reaches the same reason another way: a recorded run in CI learns nothing, and a unit that joined the roster after the
/// last proof has no proof to measure the residue with.
#[test]
fn t5_a_recorded_run_that_learns_nothing_leaves_the_residue_unmatched() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    // A unit joins the roster, and the change leaves the whole proof behind. The CI run takes the full form and records
    // the whole proof, but learns no unit proof, so the new unit has none.
    s.write("tests/d.t", "src/c.src\n");
    edit(&s, 3);
    success(&split(&s, &[("CI", "true")]));
    // Another change leaves the recorded whole proof behind, and its residue is unknown. The run takes the full form and
    // says so. Its completion then learns a, b and d, the units with no current proof.
    edit(&s, 4);
    s.clear_log();
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the full command has not been matched to its units yet"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        s.launches().len(),
        4,
        "the full form, then a, b and d, which hold no current proof"
    );
}

/// T6 (D6): a change to a file that every unit reads is a change to the whole suite. The full form runs, and the
/// reason names the file.
#[test]
fn t6_a_change_every_unit_reads_takes_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("setup.src", "changed\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("setup.src changed and every unit reads it"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        s.launches().len(),
        4,
        "the full form launches once, then completion relaunches the three units"
    );
}

/// T7 (D7): a new environment variable changes every unit's environment. The full form runs, and the reason says so.
#[test]
fn t7_a_new_environment_variable_takes_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.clear_log();
    let out = split(&s, &[("FOO", "1")]);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the environment changed since the last full run"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        s.launches().len(),
        4,
        "the full form launches once, then completion relaunches the three units"
    );
}

/// T8 (D8): a unit's own output that a later run deletes is not kept, so the next run is not a skip.
#[test]
fn t8_a_deleted_unit_output_is_not_a_skip() {
    let s = Suite::new();
    let env = [("T_WRITE_EACH", "1")];
    success(&passed(&s, &env, &[SPLIT]));
    s.remove("tests/a.out");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert_ne!(decision(&out), "skip", "{}", stderr(&out));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T9 (D9): an output that only the full form writes is part of the whole proof. Deleting it is a change, and the
/// reason names it.
#[test]
fn t9_an_output_only_the_full_form_writes_is_checked() {
    let s = Suite::new();
    let env = [("T_WRITE_FULL", "full.out")];
    success(&passed(&s, &env, &[SPLIT]));
    s.remove("full.out");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("output full.out is missing"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T10 (D10): a new unit has no proof, so the run is not a skip.
#[test]
fn t10_a_new_unit_is_not_skipped() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "subset", "{}", stderr(&out));
    assert_eq!(
        s.launches().len(),
        1,
        "the subset launches the new unit alone"
    );
}

/// T11 (D11): a unit that Git ignores after its pass leaves the roster while its file stays. The next run takes the
/// full form and names the unit.
#[test]
fn t11_a_unit_that_leaves_the_roster_while_its_file_stays_is_named() {
    let s = Suite::new();
    s.git("feature");
    // A repository's own `.git` is read by every run, and a run that reads it records nothing (the message says
    // to ignore it when that read cannot change the result).
    s.write(".stoopignore", ".git\n");
    // The repository is on `feature`, which is not the default branch. With no default named, the context is unknown
    // and every run is forced to the full form (spec 3.10, E1), so the default is named here.
    let branch = [("STOOP_DEFAULT_BRANCH", "main")];
    success(&passed(&s, &branch, &[SPLIT]));
    git(&s, &["rm", "--cached", "-q", "tests/c.t"]);
    s.write(".gitignore", "tests/c.t\n");
    // The whole proof still matches, so the legacy lookup would hit. A tracked input changes in the same step, so the
    // engine judges the roster and names the unit that left it.
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &branch);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/c.t is no longer one of the units but still exists"),
        "{}",
        stderr(&out)
    );
    // The full form launches once. Its passing run then learns the two units that remain: the change made their proofs
    // stale, and `tests/c.t` is no longer a unit. So the run makes three launches in all.
    assert_eq!(
        s.launches().len(),
        3,
        "the full form, then the two remaining units, which hold no current proof"
    );
}

/// T12 (D12): a disabled suite takes the full form, and the reason names the suite and its state.
#[test]
fn t12_a_disabled_suite_takes_the_full_form_and_names_it() {
    let s = Suite::new();
    let env = [("T_READ_OTHER", "tests/b.t")];
    // The pass disables the suite: its first unit reads another unit's file (spec 3.3, check b).
    passed(&s, &env, &[SPLIT]);
    assert_eq!(state(&s)["status"], "disabled", "{}", state(&s));
    // The whole proof still matches, so the legacy lookup would hit. A tracked input changes in the same step, so the
    // engine judges the disabled suite at step E8.
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("is disabled: tests/a.t read tests/b.t"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T13 (D13): in each state, explain and the run make the same decision. A skip exits 0.
#[test]
fn t13_explain_and_the_run_agree_in_every_state() {
    // Cold: no bundle yet.
    let s = Suite::new();
    agree(&s, &[], "full");
    // The first change is a subset: a and b read it, and the cold run proved every unit. The unchanged run
    // after it skips.
    edit(&s, 2);
    agree(&s, &[], "subset");
    agree(&s, &[], "skip");
    // Residue: the next change takes the full form.
    let t = Suite::new();
    let env = [("T_LINT", "1")];
    success(&passed(&t, &env, &[SPLIT]));
    // Only the full command reads `lint`, so a change to it is residue and takes the full form.
    t.write("lint", "#!/bin/sh\nexit 0\n# changed\n");
    agree(&t, &env, "full");
    // A change every unit reads.
    let u = Suite::new();
    success(&passed(&u, &[], &[SPLIT]));
    u.write("setup.src", "changed\n");
    agree(&u, &[], "full");
}

/// T14 (D14): explain changes nothing in the store, launches nothing, and takes no lock. A busy suite does not stop it.
#[test]
fn t14_explain_writes_nothing_launches_nothing_and_takes_no_lock() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let before = s.store_snapshot();
    s.clear_log();
    let held = hold_lock(&s);
    let out = explain(&s, &[]);
    drop(held);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert!(s.launches().is_empty(), "explain launches nothing");
    assert_eq!(s.store_snapshot(), before, "explain writes nothing");
}

/// The forced-failure setup of T15 and T16: a suite whose units hold proofs, and a full form that fails once the
/// file at `flag` exists. Returns the environment that names the file.
fn armed_full_failure(s: &Suite, flag: &str) -> Vec<(&'static str, String)> {
    let env = vec![("T_FAIL_FULL", "1".to_owned()), ("T_IF", flag.to_owned())];
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    success(&passed(s, &borrowed, &[SPLIT]));
    env
}

/// T15 (D15): a forced full run that fails while every unit's proof holds disables the suite as a disagreement.
#[test]
fn t15_a_failing_full_run_against_held_proofs_disables_the_suite() {
    let s = Suite::new();
    let flag = s.outside.join("fail-full");
    let env = armed_full_failure(&s, flag.to_str().unwrap());
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    fs::write(&flag, b"").unwrap();
    let out = split(&s, &with(&borrowed, &[("STOOP_FULL", "1")]));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("disabled: the full command failed while every unit's proof held"),
        "{}",
        stderr(&out)
    );
    let state = state(&s);
    assert_eq!(state["status"], "disabled", "{state}");
    assert_eq!(state["code"], "disagreement", "{state}");
    assert_eq!(state["phase"], "full", "{state}");
}

/// T22 (D15, the covered condition): a failing forced run is not a disagreement while the residue holds files that no
/// unit reads. The disagreement check arms only for a covered residue (spec 3.10, E1).
#[test]
fn t22_a_failing_forced_run_with_a_residue_does_not_disable() {
    let s = Suite::new();
    let flag = s.outside.join("fail-full");
    let flag_text = flag.to_str().unwrap().to_owned();
    // T_LINT adds a file that only the full command reads, so the residue is not empty after the pass.
    let env = [
        ("T_FAIL_FULL", "1"),
        ("T_IF", flag_text.as_str()),
        ("T_LINT", "1"),
    ];
    success(&passed(&s, &env, &[SPLIT]));
    fs::write(&flag, b"").unwrap();
    let out = split(&s, &with(&env, &[("STOOP_FULL", "1")]));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(state(&s)["status"], "ready", "{}", state(&s));
}

/// T16 (D16): the same failure with a unit affected by a change is not a disagreement. The suite stays enabled.
#[test]
fn t16_a_failing_forced_run_with_an_affected_unit_does_not_disable() {
    let s = Suite::new();
    let flag = s.outside.join("fail-full");
    let env = armed_full_failure(&s, flag.to_str().unwrap());
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    fs::write(&flag, b"").unwrap();
    edit(&s, 3);
    let out = split(&s, &with(&borrowed, &[("STOOP_FULL", "1")]));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(state(&s)["status"], "ready", "{}", state(&s));
}

/// The stoop run with a status descriptor, which it reports its decision on as one JSON line. Returns the run's output
/// and that line.
fn run_with_status(s: &Suite) -> (Output, String) {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "{}", io::Error::last_os_error());
    let (read, write) = (fds[0], fds[1]);
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--status-fd", "3", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    command.env(SPLIT.0, SPLIT.1);
    // SAFETY: the closure only duplicates one descriptor, which is async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(write, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = spawning(|| command.output()).unwrap();
    // SAFETY: this process owns both ends. Closing the write end lets the read see its end of file.
    unsafe { libc::close(write) };
    // SAFETY: `read` is an open descriptor that only this function uses from here on.
    let mut file = unsafe { File::from_raw_fd(read) };
    let mut report = String::new();
    file.read_to_string(&mut report).unwrap();
    (out, report)
}

/// T17 (D17): the skip after a removal's full form reports `skipped` on the status descriptor, with exit 0.
#[test]
fn t17_a_skip_after_the_full_form_reports_on_the_status_descriptor() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    // Removing a unit's file takes the full form on the first run, since its reads were the last readers (spec 3.8, item 1
    // of PR 86 review round 1). The next run is the skip, and it reports on the status descriptor.
    s.remove("tests/c.t");
    success(&split(&s, &[]));
    let (out, report) = run_with_status(&s);
    success(&out);
    let decided: Value = serde_json::from_str(report.trim())
        .unwrap_or_else(|error| panic!("the status line is not JSON ({error}): {report:?}"));
    assert_eq!(decided["decision"], "skipped", "{decided}");
    assert_eq!(decided["exit"], 0, "{decided}");
}

/// A unit whose proof is older than the maximum age is affected. Explain names the expiry, and the next run is not a skip.
#[test]
fn an_expired_unit_proof_is_affected() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    for versions in bundle["units"].as_object_mut().unwrap().values_mut() {
        for version in versions.as_array_mut().unwrap() {
            version["created"] = Value::from(1);
        }
    }
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    // The whole proof still matches, so an expired proof alone is a legacy hit. A tracked input changes in the same step.
    // Every unit is then affected (by its age, and a and b also by the input), so the run is the attribution pass.
    edit(&s, 3);
    let explained = explain(&s, &[]);
    assert!(
        stderr(&explained).contains("stoop: affected tests/a.t: proof expired"),
        "{}",
        stderr(&explained)
    );
    s.clear_log();
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "pass", "{}", stderr(&out));
    assert_eq!(
        s.launches().len(),
        3,
        "the attribution pass launches each unit once"
    );
}

/// The cost of an engine skip against a legacy hit at `STOOP_BENCH_UNITS` roster units (256, 1024 or 4096). It prints
/// the median of five runs of each and their ratio. Spec S7 stops W7-1 when a skip costs more than three legacy hits at
/// 1024 units.
#[test]
#[ignore = "a measurement: STOOP_BENCH_UNITS sets the roster size (256, 1024 or 4096)"]
fn decide_cost() {
    let units: usize = std::env::var("STOOP_BENCH_UNITS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256);
    let s = Suite::new();
    // `Suite::new` writes three units, so these fill the rest and the roster is `units` in all.
    for n in 0..units.saturating_sub(3) {
        s.write(&format!("tests/u{n:05}.t"), "src/c.src\n");
    }
    success(&passed(&s, &[], &[SPLIT]));
    // A forced full run records the whole proof for the tree as it is now.
    success(&s.hook(&[("STOOP_FULL", "1")]));
    let hit_ms = median_ms(|| {
        let started = Instant::now();
        let hit = split(&s, &[]);
        let ms = started.elapsed().as_secs_f64() * 1e3;
        success(&hit);
        assert!(stderr(&hit).contains("stoop: skip "), "{}", stderr(&hit));
        assert!(
            !stderr(&hit).contains("no tracked input changed"),
            "{}",
            stderr(&hit)
        );
        ms
    });
    // Removing a unit's file changes its directory's listing, which the legacy proof refuses. The engine skips through the
    // bundle's excuse for that name (E16), and the first skip drops the unit's versions under the lock.
    s.remove("tests/u00000.t");
    let skip_ms = median_ms(|| {
        let started = Instant::now();
        let skip = split(&s, &[]);
        let ms = started.elapsed().as_secs_f64() * 1e3;
        success(&skip);
        assert!(
            stderr(&skip).contains("no tracked input changed"),
            "{}",
            stderr(&skip)
        );
        ms
    });
    eprintln!(
        "decide_cost units={units} legacy_hit_ms={hit_ms:.1} engine_skip_ms={skip_ms:.1} ratio={:.2}",
        skip_ms / hit_ms
    );
}

/// The median of five runs of `run`, in milliseconds. One run on a shared runner is too noisy to compare two paths that
/// differ by a few milliseconds.
fn median_ms(mut run: impl FnMut() -> f64) -> f64 {
    let mut samples: Vec<f64> = (0..5).map(|_| run()).collect();
    samples.sort_by(f64::total_cmp);
    samples[2]
}

/// T18: a unit proof made under another environment is affected, even when the whole proof's environment matches. The
/// run takes the attribution pass over every unit the environment changed, and explain names the environment for each.
#[test]
fn t18_a_unit_proof_made_under_another_environment_is_affected() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    // The passing full run recorded the whole proof and every unit's proof under no environment. Each unit's guard is
    // rewritten so its proof reads as made under another environment, while the whole proof still matches this one.
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    for versions in bundle["units"].as_object_mut().unwrap().values_mut() {
        for version in versions.as_array_mut().unwrap() {
            version["guard"] = Value::from("another environment");
        }
    }
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    // c reads its own file, so this change leaves the whole proof behind and the engine decides the run.
    s.write("src/c.src", "edited\n");
    s.clear_log();
    let explained = explain(&s, &[]);
    assert!(
        stderr(&explained).contains("stoop: affected tests/a.t: the environment changed"),
        "{}",
        stderr(&explained)
    );
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "pass", "{}", stderr(&out));
    assert_eq!(
        s.launches().len(),
        3,
        "the attribution pass launches each unit once"
    );
}

/// T19: a unit that left the roster and no longer exists keeps no proof once the run after its removal has taken the full
/// form. That full run records the roster's units only, and the run after it skips.
#[test]
fn t19_the_full_form_after_a_removal_drops_the_proof_of_a_unit_that_was_removed() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("tests/c.t");
    // The first run after the removal is the full form, since its reads were the last readers (spec 3.8, item 1 of PR 86
    // review round 1). That run records the whole proof without c, so the run after it skips and launches nothing.
    let first = split(&s, &[]);
    success(&first);
    assert_eq!(decision(&first), "full", "{}", stderr(&first));
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
    let units = s.bundle().expect("a suite bundle")["units"].clone();
    assert!(units.get("tests/c.t").is_none(), "{units}");
    assert!(units.get("tests/a.t").is_some(), "{units}");
}

/// T20: a change that not every unit reads is not a change to the whole suite. Its reason is the legacy one.
#[test]
fn t20_a_change_that_not_every_unit_reads_is_not_global() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    // Units a and b read the shared source, and c does not.
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "subset", "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("every unit reads it"),
        "{}",
        stderr(&out)
    );
    assert_eq!(
        s.launches().len(),
        2,
        "the subset launches a and b, each once"
    );
}

/// T21: explain names the units a change affects and no others: the two that read the changed source, not the third.
#[test]
fn t21_explain_names_only_the_affected_units() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    edit(&s, 3);
    let log = stderr(&explain(&s, &[]));
    assert!(
        log.contains("stoop: affected tests/a.t: src/shared.src changed"),
        "{log}"
    );
    assert!(
        log.contains("stoop: affected tests/b.t: src/shared.src changed"),
        "{log}"
    );
    assert!(!log.contains("stoop: affected tests/c.t"), "{log}");
}

/// The units and inputs a skip line names, `(N units, M inputs)`.
fn skip_counts(text: &str) -> (usize, usize) {
    let line = text
        .lines()
        .find(|line| line.contains("no tracked input changed"))
        .expect("a skip line");
    let inside = line.rsplit('(').next().unwrap().trim_end_matches(')');
    let mut parts = inside.split(", ");
    let count = |part: Option<&str>| -> usize {
        part.and_then(|part| part.split(' ').next())
            .and_then(|number| number.parse().ok())
            .expect("a count")
    };
    (count(parts.next()), count(parts.next()))
}

/// E14 (g2) for a path the whole proof does not list. The cold run's proof lacks `src/x.src`. Once a pass has recorded
/// every unit under its content, a change to it is a change every unit reads, so the full command runs for that reason.
#[test]
fn t_e14_lacking_path_is_global() {
    let s = Suite::new();
    success(&s.hook(&[]));
    s.write("src/x.src", "one\n");
    s.write("tests/a.t", "src/shared.src\nsrc/x.src\n");
    s.write("tests/b.t", "src/shared.src\nsrc/x.src\n");
    s.write("tests/c.t", "src/c.src\nsrc/x.src\n");
    success(&split(&s, &[]));
    s.write("src/x.src", "two\n");
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("src/x.src changed and every unit reads it"),
        "{}",
        stderr(&out)
    );
}

/// E15 for an output that a unit lists. The full run writes `tests/a.out` and the units list it, so it is a unit's output
/// and not one only the full form writes. A changed `tests/a.out` affects `a`, and E15 does not name it.
#[test]
fn t_e15_listed_output_is_affected_not_global() {
    let env = [("T_WRITE_EACH", "1")];
    let s = Suite::new();
    success(&s.hook(&env));
    edit(&s, 2);
    success(&s.hook(&with(&env, &[SPLIT])));
    success(&s.hook(&with(&env, &[SPLIT, ("STOOP_FULL", "1")])));
    s.write("tests/a.out", "changed\n");
    let out = s.hook(&with(&env, &[SPLIT]));
    assert_eq!(decision(&out), "subset", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("output tests/a.out changed"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("is changed"), "{}", stderr(&out));
}

/// Every launch lists the root (`T_LS_ROOT`), so the root listing is an input of each unit. Its identity is its own:
/// an edit inside a directory the root lists leaves the root's listing as it was, so the run still skips.
#[test]
fn t_listed_identity_is_its_own() {
    let env = [("T_LS_ROOT", "1")];
    let s = Suite::new();
    s.write("docs/readme.md", "x\n");
    success(&passed(&s, &env, &[SPLIT]));
    s.write("docs/readme.md", "edited\n");
    let out = s.hook(&with(&env, &[SPLIT]));
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("inputs unchanged since"),
        "{}",
        stderr(&out)
    );
}

/// The skip line counts each input once: its count is the number of distinct inputs the bundle's table holds, however
/// many versions list each one.
#[test]
fn t_skip_line_counts_distinct_inputs() {
    let s = Suite::new();
    s.write("tests/d.t", "src/c.src\n");
    success(&passed(&s, &[], &[SPLIT]));
    // A change to a shared input launches a and b and leaves the whole proof behind, so the engine decides the
    // next run. A whole-command hit would skip before it.
    edit(&s, 3);
    success(&split(&s, &[]));
    s.write("docs/readme.md", "edited\n");
    let out = split(&s, &[]);
    success(&out);
    let (units, inputs) = skip_counts(&stderr(&out));
    let table = s.bundle().expect("a suite bundle")["table"]
        .as_array()
        .expect("a table")
        .len();
    assert_eq!((units, inputs), (4, table), "{}", stderr(&out));
}

/// A change that every unit reads is global only while a unit holds the old content. Once a pass has recorded every unit
/// under the new content, an unchanged run skips.
#[test]
fn t_g2_a_recorded_change_is_not_global() {
    let s = Suite::new();
    s.write("tests/c.t", "src/shared.src\n");
    success(&passed(&s, &[], &[SPLIT]));
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("inputs unchanged since"),
        "{}",
        stderr(&out)
    );
}

/// A proof recorded for another command is not a view, so the run does not skip on it.
#[test]
fn t_view_refuses_another_command_bundle() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    bundle["whole_key_digest"] = Value::from("recorded for another command");
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    s.write("docs/readme.md", "edited\n");
    let out = split(&s, &[]);
    assert!(
        !stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
}

/// A bundle of a later generation is not a view either, so the run does not skip on it.
#[test]
fn t_later_generation_is_another_version() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    bundle["generation"] = Value::from(3);
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    s.write("docs/readme.md", "edited\n");
    let out = split(&s, &[]);
    assert!(
        !stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
}

/// A busy suite lock does not change the decision: the removed reads were the last readers, so the run takes the full form
/// (spec 3.8, item 1 of PR 86 review round 1).
#[test]
fn t_busy_lock_does_not_change_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    fs::remove_file(s.root.join("tests/c.t")).unwrap();
    let lock = fs::read_dir(s.root.join(".stoop/units/v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "lock"))
        .expect("a suite lock");
    let held = File::open(&lock).unwrap();
    // SAFETY: `held` is an open descriptor until the end of this test.
    let locked = unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    assert_eq!(locked, 0, "the test takes the suite lock");
    let out = split(&s, &[]);
    drop(held);
    success(&out);
    // The removed reads were the last readers, so this run takes the full form even while the lock is busy (spec 3.8, item 1
    // of PR 86 review round 1). The busy lock bounds only what the run stores.
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
}

/// E15 for an output that only the full form writes: a changed one is named as changed, not as missing.
#[test]
fn t_e15_a_changed_output_is_named_changed() {
    let env = [("T_WRITE_FULL", "full.out")];
    let s = Suite::new();
    success(&s.hook(&env));
    edit(&s, 2);
    success(&s.hook(&with(&env, &[SPLIT])));
    s.write("full.out", "changed\n");
    let out = s.hook(&with(&env, &[SPLIT]));
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("output full.out is changed"),
        "{}",
        stderr(&out)
    );
}

/// Explains the pinned hook under `env`, with `STOOP_SPLIT` on or off.
fn explain_switch(s: &Suite, env: &[(&str, &str)], on: bool) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    if on {
        command.env(SPLIT.0, SPLIT.1);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

/// The stderr with proof ages and durations replaced, so two explains taken a moment apart compare equal.
fn aged(out: &Output) -> String {
    let text = stderr(out);
    let mut result = String::new();
    let mut rest = text.as_str();
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let after = &rest[digits..];
        let is_age = ["s ago", "m ago", "h ago", "d ago"]
            .iter()
            .any(|suffix| after.starts_with(*suffix));
        // A legacy skip line also prints how long its lookup took, which differs between two explains.
        let is_ms = after.starts_with("ms)");
        if digits > 0 && is_age {
            result.push_str("<age>");
            rest = &after[5..];
        } else if digits > 0 && is_ms {
            result.push_str("<ms>");
            rest = &after[2..];
        } else {
            let step = if digits > 0 {
                digits
            } else {
                rest.chars().next().map_or(0, char::len_utf8)
            };
            result.push_str(&rest[..step]);
            rest = &rest[step..];
        }
    }
    result
}

/// The line a switch-on explain prints last when a passing full run would launch units (spec 3.12).
const COMPLETION_LINE: &str =
    "stoop: if the full command passes, would launch 3 units without a current proof, one launch each";

/// `text` without its completion line.
fn without_completion(text: &str) -> String {
    text.lines()
        .filter(|line| *line != COMPLETION_LINE)
        .map(|line| format!("{line}\n"))
        .collect()
}

/// Explains and runs the pinned hook under `env`: both make a full decision, and the run fails as the full command
/// does. The full form launches once.
fn full_and_failing(s: &Suite, env: &[(&str, &str)]) {
    let explained = explain(s, env);
    s.clear_log();
    let ran = split(s, env);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert_eq!(code(&ran), 1, "{}", stderr(&ran));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// E8 (spec 3.12): explain of a disabled suite prints what the switch-off path prints, not the engine's lines.
#[test]
fn explain_of_a_disabled_suite_prints_what_the_switch_off_prints() {
    let s = Suite::new();
    let env = [("T_READ_OTHER", "tests/b.t")];
    // The pass finds that a unit reads another unit's file, which disables the suite (spec 3.3, check b).
    passed(&s, &env, &[SPLIT]);
    assert_eq!(state(&s)["status"], "disabled", "{}", state(&s));
    let off = explain_switch(&s, &env, false);
    let on = explain_switch(&s, &env, true);
    assert_eq!(
        aged(&on),
        aged(&off),
        "E8 prints what the switch off prints"
    );
    assert_eq!(code(&on), code(&off));
}

/// E9 (spec 3.12): explain before any unit proof, and while a pass is due, prints the switch-off lines apart from its
/// decision and its last line. With the switch on, E9 is the full command, so the decision line differs by design: the
/// switch-off explain names the attribution pass that the switch-on explain no longer runs. The last line says what a
/// passing full run would launch, and only the switch-on explain prints it.
#[test]
fn explain_before_any_unit_proof_prints_what_the_switch_off_prints() {
    let s = Suite::new();
    let on = aged(&explain_switch(&s, &[], true));
    assert_eq!(on.lines().last(), Some(COMPLETION_LINE), "cold: {on}");
    assert_eq!(
        without_completion(&on),
        aged(&explain_switch(&s, &[], false)),
        "cold"
    );
    success(&s.hook(&[]));
    edit(&s, 2);
    let off = aged(&explain_switch(&s, &[], false));
    let on = aged(&explain_switch(&s, &[], true));
    assert_eq!(on.lines().last(), Some(COMPLETION_LINE), "{on}");
    assert!(on.contains("stoop: would run full "), "{on}");
    assert!(
        off.contains("stoop: would run an attribution pass: 3 launches"),
        "{off}"
    );
    let rest = |text: &str| -> String {
        text.lines()
            .filter(|line| !line.starts_with("stoop: would run"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        rest(&without_completion(&on)),
        rest(&off),
        "apart from the decision, the switch-on explain prints what the switch-off explain prints"
    );
}

/// STOOP_MAX_AGE=0 means no expiry, as for legacy proofs: a version created long ago still holds.
#[test]
fn a_maximum_age_of_zero_never_expires_a_version() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    for versions in bundle["units"].as_object_mut().unwrap().values_mut() {
        for version in versions.as_array_mut().unwrap() {
            version["created"] = Value::from(1);
        }
    }
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    agree(&s, &[("STOOP_MAX_AGE", "0")], "skip");
}

/// A skip with nothing to drop takes no lock and writes no bundle: its bytes and its inode are the same afterwards.
#[test]
fn a_skip_with_nothing_to_drop_writes_nothing() {
    use std::os::unix::fs::MetadataExt;
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let inode = |path: &PathBuf| fs::metadata(path).unwrap().ino();
    let before = (s.bundle_bytes(), inode(&path));
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "skip", "{}", stderr(&out));
    assert_eq!(
        (s.bundle_bytes(), inode(&path)),
        before,
        "a skip with nothing to drop writes no bundle"
    );
}

/// E10 (spec 3.10): when the whole proof is gone, another stored proof does not stand in for it.
#[test]
fn a_whole_proof_that_is_gone_is_not_replaced_by_another() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    // A forced full run stores a second whole proof, which becomes the bundle's and the newest in the store.
    std::thread::sleep(Duration::from_millis(1100));
    success(&split(&s, &[("STOOP_FULL", "1")]));
    let file = fs::read_dir(s.root.join(".stoop/proofs"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "json"))
        .expect("a proof file");
    let mut stored: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let proofs = stored["proofs"].as_array_mut().unwrap();
    assert!(proofs.len() >= 2, "two proofs: {}", proofs.len());
    proofs.remove(0);
    fs::write(&file, serde_json::to_vec(&stored).unwrap()).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the last full run's proof is gone"),
        "{}",
        stderr(&out)
    );
}

/// A new file that the full command runs and no unit names is not a skip. The runner's full form also runs `*.u`
/// files, which the filter does not name. `tests/z.u` is new and fails, so the full command fails. Only the listing of
/// `tests` shows the change, since the residue leaves the listings of the catalog walk out (spec 3.8).
#[test]
fn a_new_file_the_full_command_runs_in_a_listed_directory_is_not_a_skip() {
    let s = Suite::new();
    // No `*.u` file exists when the whole proof is recorded, so the residue is empty.
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env, &[SPLIT]));
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    assert_eq!(
        code(&s.direct(&s.root, &[], &env)),
        1,
        "the full command fails on the new file"
    );
    full_and_failing(&s, &env);
}

/// As above, with a file that Git ignores, so the catalog never names it, and with the root's dot files out of stoop's
/// view, so the residue is empty as in the pinned fixture. The stock runner's full form runs the file.
#[test]
fn a_new_git_ignored_file_the_full_command_runs_is_not_a_skip() {
    let s = Suite::new();
    s.write(".gitignore", "tests/z.t\ntests/z.flag\n");
    s.write(".stoopignore", ".git\n.stoopignore\n.gitignore\n");
    s.git("feature");
    let branch = [("STOOP_DEFAULT_BRANCH", "main")];
    success(&passed(&s, &branch, &[SPLIT]));
    s.write("tests/z.t", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    assert_eq!(
        code(&s.direct(&s.root, &[], &branch)),
        1,
        "the full command fails on the new file"
    );
    full_and_failing(&s, &branch);
}

/// A new file in a directory the full command never lists is not a change to any listing the proof holds. The runner
/// prunes `slow/`, so the run skips.
#[test]
fn a_new_file_in_a_directory_the_full_command_never_lists_is_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("slow/extra.t", "src/c.src\n");
    agree(&s, &[], "skip");
}

/// A deleted file that no unit names, in a directory the full command lists, changes that listing. The run takes the
/// full form, and the reason names the directory.
#[test]
fn a_deleted_non_unit_file_in_a_listed_directory_runs_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("docs/readme.md");
    let explained = explain(&s, &[]);
    s.clear_log();
    let ran = split(&s, &[]);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert!(stderr(&ran).contains("(docs changed)"), "{}", stderr(&ran));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// A removed unit's file leaves its directory's listing, which the whole proof read. Its reads were the last readers, so the
/// first run takes the full form and records the whole proof without it. Each later run skips (spec 3.10, E16).
#[test]
fn a_removed_unit_file_is_still_a_skip_on_each_later_run() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("tests/c.t");
    agree(&s, &[], "full");
    agree(&s, &[], "skip");
    agree(&s, &[], "skip");
}

/// A disagreement that cannot take the suite lock says so and stores nothing. The lock stays held for the whole forced
/// run, so the bounded wait gives up (spec 3.10, E1).
#[test]
fn a_disagreement_that_cannot_take_the_suite_lock_says_so() {
    let s = Suite::new();
    let flag = s.outside.join("fail-full");
    let env = armed_full_failure(&s, flag.to_str().unwrap());
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    fs::write(&flag, b"").unwrap();
    let id = s
        .bundle_path()
        .expect("a suite bundle")
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let held = hold_lock(&s);
    let out = split(&s, &with(&borrowed, &[("STOOP_FULL", "1")]));
    drop(held);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    let line = format!(
        "stoop: could not record that the full command failed while every unit held (the suite is busy); run 'stoop forget --units {id}' to be safe"
    );
    assert!(stderr(&out).contains(&line), "{}", stderr(&out));
    assert_eq!(state(&s)["status"], "ready", "{}", state(&s));
}

/// The bounded wait takes the suite lock when another run releases it shortly after, and then the disagreement is
/// stored (spec 3.10, E1).
#[test]
fn a_disagreement_waits_for_a_suite_lock_that_is_released_soon() {
    let s = Suite::new();
    let flag = s.outside.join("fail-full");
    let env = armed_full_failure(&s, flag.to_str().unwrap());
    let borrowed: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
    fs::write(&flag, b"").unwrap();
    let held = hold_lock(&s);
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    for (name, value) in with(&borrowed, &[SPLIT, ("STOOP_FULL", "1")]) {
        command.env(name, value);
    }
    let child = spawning(|| {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    drop(held);
    let out = child.wait_with_output().unwrap();
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(state(&s)["status"], "disabled", "{}", state(&s));
    assert_eq!(state(&s)["code"], "disagreement", "{}", state(&s));
}

/// A runner whose full form reads every `*.t` outside `slow/` but `tests/skip.t`, so the whole proof lists that file
/// without reading it. A unit run reads the programs the full form reads, as the pinned runner does (the purity rule),
/// and cats the words it is given, so a unit proof reads its own file and the residue stays empty.
const SKIPS_ONE: &str = r#"#!/bin/sh
if [ $# -eq 0 ]; then
	for f in $(find . \( -name '.?*' -o -path ./slow \) -prune -o -type f -name '*.t' -print | sed 's|^\./||' | LC_ALL=C sort); do
		if [ "$f" != tests/skip.t ]; then cat "$f" > /dev/null; fi
	done
	exit 0
fi
find /dev/null -prune >/dev/null
sed -n q </dev/null
LC_ALL=C sort </dev/null >/dev/null
for f in "$@"; do
	cat "$f" > /dev/null
done
"#;

/// The bundle excuses a unit's file that the whole proof listed and never read. The deleted unit's version held the last
/// reader of a path that no unit reads now, so the first run takes the full form, and the run after it skips.
#[test]
fn a_unit_the_whole_proof_never_read_is_excused_by_its_bundle() {
    let s = Suite::new();
    s.executable("t", SKIPS_ONE);
    s.write("tests/skip.t", "src/c.src\n");
    success(&s.hook(&[]));
    // The runner's units never read src/shared.src, so the change that starts the pass is a unit's own file.
    s.write("tests/a.t", "src/shared.src\nedited\n");
    success(&s.hook(&[SPLIT]));
    let units = s.bundle().expect("a suite bundle")["units"].clone();
    assert!(
        units.get("tests/skip.t").is_some(),
        "the pass proves skip.t: {units}"
    );
    s.remove("tests/skip.t");
    // The removed unit's reads were the last readers of files the whole command reads, so the first run after the removal
    // is the full form (spec 3.8, item 1 of PR 86 review round 1). That run records the whole proof without it.
    agree(&s, &[], "full");
    agree(&s, &[], "skip");
}

/// A removed directory of units is a change: its parent's listing loses a name that is not a file, and no proof
/// excuses that name (E16).
#[test]
fn a_removed_directory_is_a_change() {
    let s = Suite::new();
    s.write("tests/sub/d.t", "src/c.src\n");
    success(&passed(&s, &[], &[SPLIT]));
    fs::remove_dir_all(s.path("tests/sub")).unwrap();
    let explained = explain(&s, &[]);
    s.clear_log();
    let ran = split(&s, &[]);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert!(stderr(&ran).contains("(tests changed)"), "{}", stderr(&ran));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// A unit renamed to a name that no unit has is a change: the old name is lost, and the new name appeared, which is
/// never excused.
#[test]
fn a_rename_of_a_unit_to_a_non_unit_name_is_a_change() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    fs::rename(s.path("tests/c.t"), s.path("tests/c.txt")).unwrap();
    let explained = explain(&s, &[]);
    s.clear_log();
    let ran = split(&s, &[]);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert!(stderr(&ran).contains("(tests changed)"), "{}", stderr(&ran));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// An added name is never excused as a lost one, even when a unit leaves the same directory in the same change.
#[test]
fn an_added_name_is_never_excused_as_lost() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("tests/new.txt", "x\n");
    s.remove("tests/c.t");
    let explained = explain(&s, &[]);
    s.clear_log();
    let ran = split(&s, &[]);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert!(stderr(&ran).contains("(tests changed)"), "{}", stderr(&ran));
}

/// A deleted input that a unit reads affects that unit, so the run takes the full form and names the input.
#[test]
fn a_deleted_input_that_a_unit_reads_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("src/c.src");
    let explained = explain(&s, &[]);
    s.clear_log();
    let ran = split(&s, &[]);
    assert_eq!(
        decision(&explained),
        "full",
        "explain: {}",
        stderr(&explained)
    );
    assert_eq!(decision(&ran), "full", "run: {}", stderr(&ran));
    assert!(
        stderr(&explained).contains("src/c.src was removed"),
        "{}",
        stderr(&explained)
    );
}

/// m07 (spec 3.9, `new`): a new unit in a new top-level directory. A whole proof drops the root listing and never listed
/// the new directory, so the legacy lookup hits unless a tracked input changes. This test changes one in the same step,
/// so the engine judges the new unit, which keeps the run from a skip. The full command runs the unit, and it fails.
#[test]
fn a_new_unit_in_a_new_top_level_directory_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("extra/z.t", "src/c.src\n");
    s.write("extra/z.flag", "fail\n");
    // As above, a new top-level directory alone is a legacy hit. A tracked input changes in the same step.
    edit(&s, 3);
    let direct = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&direct), 1, "{}", stderr(&direct));
    let explained = explain(&s, &[]);
    assert!(
        stderr(&explained).contains("stoop: affected extra/z.t: new"),
        "{}",
        stderr(&explained)
    );
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "subset", "{}", stderr(&out));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
}

/// m07, the root variant: a new unit at the top level. The whole proof has no root listing that shows the new name, so
/// the legacy lookup hits unless a tracked input changes. This test changes one in the same step, so the engine judges
/// the new unit, and that keeps the run from a skip.
#[test]
fn a_new_unit_at_the_top_level_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.write("z.t", "src/c.src\n");
    s.write("z.flag", "fail\n");
    // A top-level name added alone is a legacy hit, since the whole proof does not list the root. A tracked input
    // changes in the same step, so the engine judges the new unit.
    edit(&s, 3);
    let direct = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&direct), 1, "{}", stderr(&direct));
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "subset", "{}", stderr(&out));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
}

/// m07 (r27): a unit's file replaced by a directory that holds a new, failing unit. The parent's listing keeps the same
/// names, and the whole proof never listed the new directory, so the new-unit reason sees the change.
#[test]
fn a_unit_replaced_by_a_directory_holding_a_failing_unit_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("tests/c.t");
    s.write("tests/c.t/x.t", "src/c.src\n");
    s.write("tests/c.t/x.flag", "fail\n");
    let direct = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&direct), 1, "{}", stderr(&direct));
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
}

/// z02 (spec 3.10, the generation check): a bundle of an earlier generation is not a view. `read_bundle` keeps earlier
/// generations, so only the view's check on the generation stops a skip on this bundle.
#[test]
fn an_earlier_generation_bundle_is_not_a_view() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    bundle["generation"] = Value::from(1);
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    s.write("docs/readme.md", "edited\n");
    // The docs edit alone is a legacy hit. A tracked input changes in the same step, so the bundle's generation decides:
    // the view refuses it, and the legacy path runs the full command.
    edit(&s, 3);
    let explained = explain(&s, &[]);
    assert_ne!(decision(&explained), "skip", "{}", stderr(&explained));
    assert_eq!(decision(&explained), "full", "{}", stderr(&explained));
    let out = split(&s, &[]);
    assert_ne!(decision(&out), "skip", "{}", stderr(&out));
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
}

/// E11 (spec 3.10), for a unit file that became a directory. The name still exists, so the unit has left the roster while
/// its path stays, and the run takes the full form. T_U runs every *.u, so the full command runs the failing x.u inside the
/// directory and exits 1.
#[test]
fn a_unit_file_replaced_by_a_directory_takes_the_full_form() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env, &[SPLIT]));
    s.remove("tests/c.t");
    s.write("tests/c.t/x.u", "src/c.src\n");
    s.write("tests/c.t/x.flag", "fail\n");
    let direct = s.direct(&s.root, &[], &env);
    assert_eq!(code(&direct), 1, "{}", stderr(&direct));
    let explained = explain(&s, &env);
    assert_eq!(decision(&explained), "full", "{}", stderr(&explained));
    let out = split(&s, &env);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/c.t is no longer one of the units but still exists"),
        "{}",
        stderr(&out)
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
}
