//! Adopted from the PR 86 review (W7-3): round 1 at 424cf9e and round 2 at f1b8213. The reviewer's test names (w01 to
//! w22) are kept so the review can be traced. Each test prints REVIEW lines so a failure names the decision. Linux only.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::process::{Child, Output, Stdio};
use units_common::*;

const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");
const COMPLETION: &str = "stoop: attribution pass after the full run: ";
const LEARN_LINE: &str = "stoop: if the full command passes, would launch ";

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", stderr(out));
}

fn with<'a>(env: &[(&'a str, &'a str)], extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    env.iter().chain(extra).copied().collect()
}

fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    s.hook(&with(&[SPLIT], env))
}

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

fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

fn direct(s: &Suite, env: &[(&str, &str)]) -> i32 {
    let out = code(&s.direct(&s.root, &[], env));
    s.clear_log();
    out
}

fn bundle(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")
}

fn state(s: &Suite) -> Value {
    bundle(s)["state"].clone()
}

/// The units that hold at least one version.
fn proven(s: &Suite) -> Vec<String> {
    let bundle = bundle(s);
    bundle["units"]
        .as_object()
        .map(|units| {
            units
                .iter()
                .filter(|(_, versions)| versions.as_array().is_some_and(|v| !v.is_empty()))
                .map(|(unit, _)| unit.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The count that a line starting with `prefix` names right after it.
fn count_after(out: &Output, prefix: &str) -> Option<usize> {
    stderr(out).lines().find_map(|line| {
        line.strip_prefix(prefix)
            .and_then(|rest| rest.split(' ').next())
            .and_then(|n| n.parse().ok())
    })
}

fn completion(out: &Output) -> Option<usize> {
    count_after(out, COMPLETION)
}

fn predicted(out: &Output) -> Option<usize> {
    count_after(out, LEARN_LINE)
}

fn spawn_split(s: &Suite, env: &[(&str, &str)]) -> Child {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.env(SPLIT.0, SPLIT.1);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.spawn()).unwrap()
}

/// Waits until no process holds the suite lock, for up to 10 s.
fn lock_free(s: &Suite) {
    let lock = s
        .bundle_path()
        .expect("a suite bundle")
        .with_extension("lock");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock)
            .unwrap();
        // SAFETY: the descriptor is an open file, and flock takes no pointers.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the suite lock stayed held"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Explains (writing nothing, launching nothing), runs, and compares with the direct full form when `compare` is set.
/// Returns (explain output, run output, launches, direct status or -1).
fn judge(
    name: &str,
    s: &Suite,
    env: &[(&str, &str)],
    compare: bool,
) -> (Output, Output, Vec<String>, i32) {
    let before = s.store_snapshot();
    s.clear_log();
    let explained = explain(s, env);
    assert_eq!(
        s.store_snapshot(),
        before,
        "{name}: explain changed the store"
    );
    assert!(s.launches().is_empty(), "{name}: explain launched");
    let direct_code = if compare { direct(s, env) } else { -1 };
    s.clear_log();
    let ran = split(s, env);
    let launches = launched(s);
    eprintln!(
        "REVIEW {name}: exit={} direct={direct_code} launches={launches:?} predicted={:?} completion={:?}\n--- explain\n{}--- run\n{}",
        code(&ran),
        predicted(&explained),
        completion(&ran),
        stderr(&explained),
        stderr(&ran)
    );
    (explained, ran, launches, direct_code)
}

fn same_verdict(name: &str, ran: &Output, direct_code: i32) {
    assert_eq!(
        code(ran) == 0,
        direct_code == 0,
        "{name}: WRONG VERDICT: run exit {} against direct {direct_code}\n{}",
        code(ran),
        stderr(ran)
    );
}

/// The explain prediction agrees with what the run did: a learning line exactly when the run completes, same count.
fn prediction_matches(name: &str, explained: &Output, ran: &Output) {
    assert_eq!(
        predicted(explained),
        completion(ran),
        "{name}: explain predicted {:?} completion launches, the run made {:?}",
        predicted(explained),
        completion(ran)
    );
}

/// The cold run with the switch on: the full form, then completion learns every unit.
fn learned(s: &Suite, env: &[(&str, &str)]) {
    let (explained, ran, _, _) = judge("cold", s, env, false);
    success(&ran);
    assert_eq!(completion(&ran), Some(3), "{}", stderr(&ran));
    prediction_matches("cold", &explained, &ran);
}

#[test]
fn w01_a_completion_disagreement_disables_and_the_next_change_is_full() {
    let s = Suite::new();
    let go = s.outside.join("go").display().to_string();
    fs::write(&go, "").unwrap();
    let env = [("T_FAIL_ALONE", "tests/b.t"), ("T_IF", go.as_str())];
    let (_, cold, _, _) = judge("w01-cold", &s, &env, false);
    assert_eq!(code(&cold), 0, "the status is the full command's");
    assert_eq!(state(&s)["status"], "disabled");
    assert_eq!(state(&s)["code"], "disagreement");
    assert_eq!(state(&s)["phase"], "completion");
    edit(&s, 3);
    let (explained, next, launches, direct_code) = judge("w01-next", &s, &env, true);
    same_verdict("w01-next", &next, direct_code);
    assert_eq!(
        launches,
        [""],
        "a disabled suite takes the full form and learns nothing"
    );
    assert_eq!(
        predicted(&explained),
        None,
        "explain must not predict learning for a disabled suite"
    );
}

#[test]
fn w02_a_completion_launch_that_never_reads_its_unit_disables() {
    let s = Suite::new();
    let env = [("T_IGNORE", "1")];
    let (_, cold, launches, _) = judge("w02", &s, &env, false);
    assert_eq!(code(&cold), 0, "{}", stderr(&cold));
    assert_eq!(launches, ["", "tests/a.t"]);
    assert_eq!(state(&s)["status"], "disabled");
    assert_eq!(state(&s)["code"], "never_ran");
    assert_eq!(state(&s)["phase"], "completion");
}

/// `b`'s completion launch is held after it read the shared source, which is edited then: `b` is not recorded, so not
/// every unit holds a proof, the residue is not confirmed, and the next run takes the full form and learns again.
#[test]
fn w03_a_unit_unrecorded_at_completion_leaves_the_residue_unmatched() {
    let s = Suite::new();
    let fifo = s.fifo();
    let fifo_text = fifo.to_str().unwrap().to_owned();
    let env = [("T_FIFO", fifo_text.as_str()), ("T_FIFO_AT", "tests/b.t")];
    let child = spawn_split(&s, &env);
    release(meet(&fifo));
    let writer = meet(&fifo);
    edit(&s, 5);
    release(writer);
    let cold = finish(child);
    eprintln!("REVIEW w03 cold:\n{}", stderr(&cold));
    success(&cold);
    assert!(
        stderr(&cold).contains("not recorded for tests/b.t"),
        "{}",
        stderr(&cold)
    );
    assert!(
        !proven(&s).contains(&"tests/b.t".to_owned()),
        "{:?}",
        proven(&s)
    );
    assert_ne!(
        bundle(&s)["residue"]["state"],
        "confirmed",
        "{}",
        bundle(&s)["residue"]
    );
    let child = spawn_split(&s, &env);
    release(meet(&fifo));
    release(meet(&fifo));
    let next = finish(child);
    eprintln!("REVIEW w03 next:\n{}", stderr(&next));
    success(&next);
    assert!(
        stderr(&next).contains("has not been matched to its units yet"),
        "{}",
        stderr(&next)
    );
    assert_eq!(
        bundle(&s)["residue"]["state"],
        "confirmed",
        "{}",
        bundle(&s)["residue"]
    );
}

/// As w03 when every unit already holds a (stale) proof: `T_LINT` keeps a residue, so every change is a full run whose
/// completion relaunches the stale units. `b` is not recorded, so it keeps its stale proof, and the residue that the
/// completion leaves must not be labelled confirmed.
#[test]
fn w03b_a_stale_unit_unrecorded_at_completion_leaves_the_residue_unconfirmed() {
    let s = Suite::new();
    let fifo = s.fifo();
    let fifo_text = fifo.to_str().unwrap().to_owned();
    let env = [
        ("T_LINT", "1"),
        ("T_FIFO", fifo_text.as_str()),
        ("T_FIFO_AT", "tests/b.t"),
    ];
    let child = spawn_split(&s, &env);
    release(meet(&fifo));
    release(meet(&fifo));
    let cold = finish(child);
    eprintln!(
        "REVIEW w03b cold:\n{}\nresidue={}",
        stderr(&cold),
        bundle(&s)["residue"]
    );
    success(&cold);
    assert_eq!(
        bundle(&s)["residue"]["state"],
        "confirmed",
        "{}",
        bundle(&s)["residue"]
    );
    edit(&s, 3);
    let child = spawn_split(&s, &env);
    release(meet(&fifo));
    let writer = meet(&fifo);
    edit(&s, 6);
    release(writer);
    let out = finish(child);
    eprintln!(
        "REVIEW w03b:\n{}\nresidue={}",
        stderr(&out),
        bundle(&s)["residue"]
    );
    success(&out);
    assert!(
        stderr(&out).contains("not recorded for tests/b.t"),
        "{}",
        stderr(&out)
    );
    assert_ne!(
        bundle(&s)["residue"]["state"],
        "confirmed",
        "{}",
        bundle(&s)["residue"]
    );
}

/// SIGKILL while `b`'s completion launch is held: `b` gets no proof, nothing is labelled confirmed, and the next change
/// takes the full form.
#[test]
fn w04_sigkill_during_completion_leaves_no_wrongly_fresh_unit() {
    let s = Suite::new();
    let fifo = s.fifo();
    let fifo_text = fifo.to_str().unwrap().to_owned();
    let env = [("T_FIFO", fifo_text.as_str()), ("T_FIFO_AT", "tests/b.t")];
    let mut child = spawn_split(&s, &env);
    release(meet(&fifo));
    let writer = meet(&fifo);
    child.kill().unwrap();
    child.wait().unwrap();
    drop(writer);
    lock_free(&s);
    let units = proven(&s);
    eprintln!(
        "REVIEW w04 proven after the kill: {units:?} residue={}",
        bundle(&s)["residue"]
    );
    assert!(!units.contains(&"tests/b.t".to_owned()));
    assert!(!units.contains(&"tests/c.t".to_owned()));
    assert_ne!(bundle(&s)["residue"]["state"], "confirmed");
    edit(&s, 3);
    let child = spawn_split(&s, &env);
    release(meet(&fifo));
    release(meet(&fifo));
    let next = finish(child);
    let launches = launched(&s);
    let direct_code = direct(&s, &[]);
    eprintln!("REVIEW w04 next: launches={launches:?}\n{}", stderr(&next));
    same_verdict("w04-next", &next, direct_code);
    assert_eq!(
        launches.first().map(String::as_str),
        Some(""),
        "the full form runs first"
    );
}

#[test]
fn w07_ci_one_never_learns_and_explain_agrees() {
    let s = Suite::new();
    let (explained, cold, launches, _) = judge("w07", &s, &[("CI", "1")], false);
    success(&cold);
    assert_eq!(launches, [""]);
    assert!(proven(&s).is_empty(), "{:?}", proven(&s));
    prediction_matches("w07", &explained, &cold);
}

/// After a CI cold run (no unit proof) the unchanged run is a whole-command hit: explain predicts no learning and the run
/// skips without launching.
#[test]
fn w11_a_whole_command_hit_predicts_no_learning() {
    let s = Suite::new();
    success(&s.hook(&[]));
    assert!(
        bundle(&s)["units"]
            .as_object()
            .is_none_or(|units| units.is_empty()),
        "{}",
        bundle(&s)
    );
    let (explained, ran, launches, _) = judge("w11", &s, &[], false);
    success(&ran);
    assert!(launches.is_empty(), "{launches:?}");
    prediction_matches("w11", &explained, &ran);
}

/// Explain's learning line against the run, in states that reach the full form after learning.
#[test]
fn w08_explain_predicts_the_completion_in_every_full_state() {
    let s = Suite::new();
    learned(&s, &[]);
    s.write("tests/c.t", "src/c.src\n\n");
    let (explained, ran, launches, _) = judge("w08-subset", &s, &[], false);
    success(&ran);
    assert_eq!(launches, ["tests/c.t"]);
    prediction_matches("w08-subset", &explained, &ran);
    let env = [("FOO", "1")];
    edit(&s, 3);
    let (explained, ran, _, _) = judge("w08-env", &s, &env, false);
    success(&ran);
    prediction_matches("w08-env", &explained, &ran);
    s.write("setup.src", "setup changed\n");
    let (explained, ran, _, _) = judge("w08-global", &s, &env, false);
    success(&ran);
    prediction_matches("w08-global", &explained, &ran);
    s.write("tests/c.t", "src/c.src\n\n\n");
    let forced = [("FOO", "1"), ("STOOP_FULL", "1")];
    let (explained, ran, _, _) = judge("w08-forced", &s, &forced, false);
    success(&ran);
    prediction_matches("w08-forced", &explained, &ran);
}

/// Deviation 4 probe: a full run (environment change) that also gains work no unit does (a runner-only test, `T_U`).
/// The residue before the run is known and empty, but the run records a new proof, so explain names what completion learns.
#[test]
fn w08e_explain_when_the_full_run_gains_runner_only_work() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    learned(&s, &env);
    s.write("tests/z.u", "src/c.src\n");
    let changed = [("T_U", "1"), ("FOO", "1")];
    let (explained, ran, _, direct_code) = judge("w08e", &s, &changed, true);
    same_verdict("w08e", &ran, direct_code);
    eprintln!(
        "REVIEW w08e informational: predicted={:?} completion={:?}",
        predicted(&explained),
        completion(&ran)
    );
    // The run records a new proof, which leaves the residue unknown, so explain names the three units that completion
    // learns, as the run does (PR 86 review round 2, cc0cf08).
    assert_eq!(predicted(&explained), Some(3), "{}", stderr(&explained));
    assert_eq!(completion(&ran), Some(3), "{}", stderr(&ran));
}

/// A completion launch writes an input of a VALID unit that the completion does not relaunch (`c`). `src/c.src` already
/// holds what the write writes, so `c`'s proof stays valid and only the writer-side check sees the coupling.
#[test]
fn w12_a_completion_write_into_a_valid_units_input_disables() {
    let s = Suite::new();
    s.write("src/c.src", "written\n");
    let go = s.outside.join("go").display().to_string();
    let env = [
        ("T_LINT", "1"),
        ("T_WRITE", "src/c.src"),
        ("T_WRITE_AT", "tests/a.t"),
        ("T_IF", go.as_str()),
    ];
    let cold = split(&s, &env);
    success(&cold);
    assert_eq!(completion(&cold), Some(3), "{}", stderr(&cold));
    fs::write(&go, "").unwrap();
    edit(&s, 3);
    let (_, ran, launches, _) = judge("w12", &s, &env, false);
    assert_eq!(code(&ran), 0, "the status is the full command's");
    eprintln!("REVIEW w12 launches={launches:?} state={}", state(&s));
    assert!(
        !launches.contains(&"tests/c.t".to_owned()),
        "c is valid and not relaunched: {launches:?}"
    );
    assert_eq!(state(&s)["status"], "disabled", "{}", stderr(&ran));
    assert_eq!(state(&s)["code"], "wrote_input", "{}", stderr(&ran));
}

/// The residue across states (pre-existing since W7-2): unit `c` reads a runner-only test and its flag as data when the
/// suite learns, so the residue counts them as unit work. Then `c` stops reading them (a subset), and the flag turns to
/// `fail`. The full command still runs the runner-only test.
#[test]
fn w20_a_runner_only_test_that_a_unit_stopped_reading_keeps_the_full_verdict() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    learned(&s, &env);
    eprintln!(
        "REVIEW w20 residue after learning: {}",
        bundle(&s)["residue"]
    );
    s.write("tests/c.t", "src/c.src\n");
    let (_, first, _, direct_first) = judge("w20-first", &s, &env, true);
    same_verdict("w20-first", &first, direct_first);
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("w20", &s, &env, true);
    same_verdict("w20", &second, direct_second);
}

/// As w20, with `c` deleted instead of changed (its former reads stay attributed, spec 3.8).
#[test]
fn w21_a_runner_only_test_a_deleted_unit_read_keeps_the_full_verdict() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    learned(&s, &env);
    eprintln!(
        "REVIEW w21 residue after learning: {}",
        bundle(&s)["residue"]
    );
    s.remove("tests/c.t");
    s.remove("tests/c.flag");
    let (_, first, _, direct_first) = judge("w21-first", &s, &env, true);
    same_verdict("w21-first", &first, direct_first);
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("w21", &s, &env, true);
    same_verdict("w21", &second, direct_second);
}

/// The documented covered-file gap, for comparison with w20 and w21: `c` still reads the runner-only test.
#[test]
fn w22_informational_the_documented_covered_file_gap() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    learned(&s, &env);
    eprintln!(
        "REVIEW w22 residue after learning: {}",
        bundle(&s)["residue"]
    );
    s.write("tests/z.flag", "fail\n");
    let (_, ran, launches, direct_code) = judge("w22", &s, &env, true);
    eprintln!(
        "REVIEW w22 informational: exit={} direct={direct_code} launches={launches:?}",
        code(&ran)
    );
}
