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
use std::process::{Command, Output};
use std::time::Instant;
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

/// A suite whose units hold proofs: a cold full run under `env`, then a change that starts the attribution pass,
/// run under `env` and `switch`. Returns the pass's output.
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
    {
        "pass"
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
    assert!(
        stderr(&out).contains("no tracked input changed (3 units,"),
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

/// T5 (D5): a unit that fails in the pass keeps no proof, so the residue is not matched to the units. The next change
/// takes the full form.
#[test]
fn t5_a_failing_unit_leaves_the_residue_unmatched() {
    let s = Suite::new();
    success(&s.hook(&[]));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 2);
    let pass = split(&s, &[]);
    assert_eq!(code(&pass), 1, "{}", stderr(&pass));
    s.clear_log();
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("the full command has not been matched to its units yet"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
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
    assert_eq!(s.launches().len(), 1, "the full form launches once");
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
    assert_eq!(s.launches().len(), 1, "the full form launches once");
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
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
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
    s.clear_log();
    let out = split(&s, &branch);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/c.t is no longer one of the units but still exists"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T12 (D12): a disabled suite takes the full form, and the reason names the suite and its state.
#[test]
fn t12_a_disabled_suite_takes_the_full_form_and_names_it() {
    let s = Suite::new();
    let env = [("T_READ_OTHER", "tests/b.t")];
    // The pass disables the suite: its first unit reads another unit's file (spec 3.3, check b).
    passed(&s, &env, &[SPLIT]);
    assert_eq!(state(&s)["status"], "disabled", "{}", state(&s));
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
    // The first change starts the pass, and the unchanged run after it skips.
    edit(&s, 2);
    agree(&s, &[], "pass");
    agree(&s, &[], "skip");
    // Residue: the next change takes the full form.
    let t = Suite::new();
    let env = [("T_LINT", "1")];
    success(&passed(&t, &env, &[SPLIT]));
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

/// T17 (D17): a skip reports `skipped` with the `units` outcome on the status descriptor.
#[test]
fn t17_a_skip_reports_units_on_the_status_descriptor() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    let (out, report) = run_with_status(&s);
    success(&out);
    let decided: Value = serde_json::from_str(report.trim())
        .unwrap_or_else(|error| panic!("the status line is not JSON ({error}): {report:?}"));
    assert_eq!(decided["decision"], "skipped", "{decided}");
    assert_eq!(decided["how"], "units", "{decided}");
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
    let explained = explain(&s, &[]);
    assert!(
        stderr(&explained).contains("stoop: affected tests/a.t: proof expired"),
        "{}",
        stderr(&explained)
    );
    s.clear_log();
    let out = split(&s, &[]);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
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
    // A new file in a directory that the full command lists changes the whole proof, and no unit reads it.
    s.write("docs/extra.md", "x\n");
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
/// run takes the full form, and explain names the environment for each unit.
#[test]
fn t18_a_unit_proof_made_under_another_environment_is_affected() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    // The pass runs under FOO=1, so every unit's proof is made under that environment.
    success(&split(&s, &[("FOO", "1")]));
    s.clear_log();
    // Back to no FOO: the whole proof was made without it, so only the units' proofs can see the change.
    let explained = explain(&s, &[]);
    assert!(
        stderr(&explained).contains("stoop: affected tests/a.t: the environment changed"),
        "{}",
        stderr(&explained)
    );
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert_eq!(s.launches().len(), 1, "the full form launches once");
}

/// T19: a unit that left the roster and no longer exists keeps no proof after a skip. The skip drops its versions, and
/// the bundle names only the roster's units.
#[test]
fn t19_a_skip_drops_the_proof_of_a_unit_that_was_removed() {
    let s = Suite::new();
    success(&passed(&s, &[], &[SPLIT]));
    s.remove("tests/c.t");
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
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        !stderr(&out).contains("every unit reads it"),
        "{}",
        stderr(&out)
    );
    assert_eq!(s.launches().len(), 1, "the full form launches once");
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
    assert_eq!(decision(&out), "full", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("output tests/a.out changed"),
        "{}",
        stderr(&out)
    );
    assert!(!stderr(&out).contains("is changed"), "{}", stderr(&out));
}

/// Every launch lists the root (`T_LS_ROOT`), so the root listing is an input of each unit. Its identity is its own:
/// a change that only the whole proof sees, in a directory the root lists, skips on the units' unchanged listing.
#[test]
fn t_listed_identity_is_its_own() {
    let env = [("T_LS_ROOT", "1")];
    let s = Suite::new();
    s.write("docs/readme.md", "x\n");
    success(&passed(&s, &env, &[SPLIT]));
    s.write("docs/extra.md", "x\n");
    let out = s.hook(&with(&env, &[SPLIT]));
    success(&out);
    assert!(
        stderr(&out).contains("no tracked input changed"),
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
    s.write("docs/extra.md", "x\n");
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
    assert!(
        stderr(&out).contains("no tracked input changed"),
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
    s.write("docs/extra.md", "x\n");
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
    s.write("docs/extra.md", "x\n");
    let out = split(&s, &[]);
    assert!(
        !stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
}

/// A busy suite lock keeps a skip whose settle would drop a removed unit's versions: the skip stands and nothing is
/// written. The next run that gets the lock drops them.
#[test]
fn t_busy_lock_keeps_the_skip() {
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
    assert!(
        stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
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
