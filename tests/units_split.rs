//! The subset run (spec 3.10, E17 and E18; 3.11 and 3.12, W7-2). With `STOOP_SPLIT=1`, a changed run of a hooked
//! suite launches only the units whose proof no longer holds, one launch per unit, and keeps every other unit's
//! proof. A unit whose proof holds is never launched, and a launch that writes another unit's input disables the
//! suite or gives the run no verdict (125). These tests drive the stoop binary and the fake runner under the
//! tracer, so they run on Linux x86-64 and arm64 only. They are named after the plan's table (S1 to S22, G1), the
//! mutant it names, and the seeded model test M1. On the base, which has no subset, every changed run that the
//! engine does not skip takes the full form, so the tests that expect a subset or a pass fail there.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Output;
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");

/// The hook the unit form of the pinned runner takes: one launch per affected unit.
const UNIT: &str = "{unit:**/*.t|!slow/**}";

/// A hook whose roster also holds the `*.u` file that `T_U` makes the full form run.
const COVERING: &str = "{changed:**/*.t|**/*.u|!slow/**}";

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

/// A change to the source that units `a` and `b` read. The file's length follows `n`, so the change is certain.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

/// The pinned hook under `env`, with the engine on.
fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    s.hook(&with(&[SPLIT], env))
}

/// A cold full run, then a change to the shared source and a run under `env`. That run is the attribution pass,
/// which launches every unit once. Returns the pass's output.
fn passed(s: &Suite, env: &[(&str, &str)]) -> Output {
    success(&split(s, env));
    edit(s, 2);
    split(s, env)
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

/// The subset header a run prints (spec 3.12), when it prints one.
fn header(out: &Output) -> Option<String> {
    stderr(out)
        .lines()
        .find(|line| line.starts_with("stoop: tracked "))
        .map(str::to_owned)
}

/// Asserts that the run printed a subset header that ends with `tail`.
fn assert_header(out: &Output, tail: &str) {
    let line = header(out).unwrap_or_else(|| panic!("no subset header: {}", stderr(out)));
    assert!(line.ends_with(tail), "{line}");
}

fn full(out: &Output) -> bool {
    stderr(out).contains("stoop: run full ")
}

fn pass_line(out: &Output) -> bool {
    stderr(out).contains("stoop: attribution pass: ")
}

fn skipped(out: &Output) -> bool {
    stderr(out).contains("stoop: skip ")
}

/// The stored state of the suite's bundle.
fn state(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")["state"].clone()
}

/// The suite's stored unit names, from its bundle.
fn stored_units(s: &Suite) -> Vec<String> {
    let bundle = s.bundle().expect("a suite bundle");
    bundle["units"]
        .as_object()
        .expect("a units object")
        .keys()
        .cloned()
        .collect()
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

/// S1: a cold full run, then the first change is an attribution pass that launches every unit once.
#[test]
fn s1_cold_then_the_first_change_is_a_pass() {
    let s = Suite::new();
    success(&split(&s, &[]));
    edit(&s, 2);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t", "tests/c.t"]);
}

/// S2b: after a pass, an edit to the shared source runs `a` and then `b`, one launch each, under the subset header.
#[test]
fn s2b_an_edit_to_shared_runs_a_then_b_under_the_header() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    assert!(
        header(&out).is_some_and(|line| line.starts_with("stoop: tracked 3 units, ")),
        "{}",
        stderr(&out)
    );
    assert_header(
        &out,
        "; run 2 (src/shared.src changed): tests/a.t, tests/b.t",
    );
}

/// S3: appending an empty line to `tests/c.t` changes only that unit's own file, so only `c` runs.
#[test]
fn s3_appending_an_empty_line_to_c_runs_c_only() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/c.t"]);
    assert_header(&out, "; run 1 (tests/c.t changed): tests/c.t");
}

/// S5: a changed `setup.src` is read by every unit, so the run is full. The proof then holds the new `setup.src`,
/// and the next change is an attribution pass, not a full run (C13).
#[test]
fn s5_a_setup_change_runs_full_and_the_next_change_is_a_pass() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("setup.src", "setup changed\n");
    let out = split(&s, &[]);
    success(&out);
    assert!(full(&out), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("setup.src changed and every unit reads it"),
        "{}",
        stderr(&out)
    );
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t", "tests/c.t"]);
}

/// S6: a new unit has no proof, so it runs alone.
#[test]
fn s6_a_new_unit_runs_alone() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/d.t"]);
    assert_header(&out, "; run 1 (new): tests/d.t");
}

/// S7: deleting `c`, then editing `a` and `b` through their own files. Both remaining units are affected, so the whole
/// roster is affected and the attribution pass runs both, one launch each. The proof of `c` is dropped with the write
/// (spec 3.10, E17). The next test pins the case where the shared source changes instead.
#[test]
fn s7_deleting_c_then_an_edit_runs_a_and_b() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.remove("tests/c.t");
    s.write("tests/a.t", "src/shared.src\n\n");
    s.write("tests/b.t", "src/shared.src\n\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    assert!(pass_line(&out), "{}", stderr(&out));
    assert!(
        !stored_units(&s).iter().any(|unit| unit == "tests/c.t"),
        "the proof of a deleted unit was kept: {:?}",
        stored_units(&s)
    );
}

/// S7, the plan's literal scenario: deleting `c`, then editing the shared source. `a` and `b` both read that source, so
/// the change is global and the full command runs for it (spec 3.10, E14 g2). The full command's record drops `c`.
#[test]
fn s7_literal_deleting_c_then_an_edit_to_shared_is_global() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.remove("tests/c.t");
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(
        stderr(&out).contains("(src/shared.src changed and every unit reads it)"),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), [""]);
    assert!(
        !stored_units(&s).iter().any(|unit| unit == "tests/c.t"),
        "the proof of a deleted unit was kept: {:?}",
        stored_units(&s)
    );
}

/// S8: renaming `c` to `d` runs `d` alone.
#[test]
fn s8_renaming_c_to_d_runs_d_alone() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    fs::rename(s.path("tests/c.t"), s.path("tests/d.t")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/d.t"]);
    assert_header(&out, "; run 1 (new): tests/d.t");
}

/// S9: `c.t` lists a file that does not exist yet. Creating it changes only the proof of `c`, so `c` runs alone.
#[test]
fn s9_a_listed_file_that_appears_reruns_only_the_unit_that_lists_it() {
    let s = Suite::new();
    s.write("tests/c.t", "src/missing.src\nsrc/c.src\n");
    success(&passed(&s, &[]));
    s.write("src/missing.src", "appeared\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/c.t"]);
    assert_header(&out, "; run 1 (src/missing.src changed): tests/c.t");
}

/// S9b: with `T_LS_ROOT`, every unit lists the root, so a new top-level entry changes a listing that every unit's proof
/// names. That is a change every unit reads, so the full command runs for it (spec 3.10, E14 g2).
#[test]
fn s9b_with_t_ls_root_a_new_top_level_entry_is_global() {
    let s = Suite::new();
    let env = [("T_LS_ROOT", "1")];
    success(&passed(&s, &env));
    s.write("new.top", "new\n");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert!(
        stderr(&out).contains("(. changed and every unit reads it)"),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), [""]);
}

/// S10b: a launch's unit variables name only the unit, and `STOOP_CHANGED_INPUTS` names the changed input it has.
#[test]
fn s10b_the_unit_variables_name_units_and_the_changed_inputs_name_the_input() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 2, "{}", stderr(&out));
    for (launch, unit) in launches.iter().zip(["tests/a.t", "tests/b.t"]) {
        assert_eq!(launch.env("changed"), unit);
        assert_eq!(launch.env("units"), unit);
        assert_eq!(launch.env("changed_inputs"), "src/shared.src");
    }
}

/// S11: `T_U` makes the full form run a `*.u` file that no unit covers, so every change is a full run.
#[test]
fn s11_t_u_makes_every_change_a_full_run() {
    let s = Suite::new();
    let env = [("T_U", "1")];
    success(&passed(&s, &env));
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert!(full(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// S12: a filter that covers the `*.u` file the full form runs allows subsets, so an edit to `src/c.src` runs `c`.
#[test]
fn s12_the_covering_filter_allows_subsets() {
    let s = Suite::new();
    let env = [("T_U", "1")];
    let covering = |s: &Suite, env: &[(&str, &str)]| {
        s.run(&s.root, &[], &["./t", COVERING], &with(&[SPLIT], env))
    };
    success(&covering(&s, &env));
    edit(&s, 2);
    success(&covering(&s, &env));
    s.write("src/c.src", "c changed\n");
    s.clear_log();
    let out = covering(&s, &env);
    success(&out);
    assert_eq!(launched(&s), ["tests/c.t"]);
    assert_header(&out, "; run 1 (src/c.src changed): tests/c.t");
}

/// S13: `T_LINT` makes the full form run a script that no unit covers, so every change is a full run.
#[test]
fn s13_t_lint_makes_every_change_a_full_run() {
    let s = Suite::new();
    let env = [("T_LINT", "1")];
    success(&passed(&s, &env));
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert!(full(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// S15: a `{unit}` run whose unit `b` fails keeps `b` affected, so the next run launches it again.
#[test]
fn a_failing_unit_stays_affected_until_it_passes() {
    let s = Suite::new();
    let run = |s: &Suite| s.run(&s.root, &[], &["./t", UNIT], &[SPLIT]);
    success(&run(&s));
    edit(&s, 2);
    success(&run(&s));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 3);
    s.clear_log();
    let out = run(&s);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    s.write("tests/b.flag", "ok\n");
    s.clear_log();
    let out = run(&s);
    success(&out);
    assert_eq!(launched(&s), ["tests/b.t"]);
}

/// S16: three partial runs, each changing one unit's inputs, lose nothing. The next unchanged run skips.
#[test]
fn s16_three_partial_runs_lose_nothing() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/c.t"]);
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    s.write("tests/b.t", "src/shared.src\n\n");
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/b.t"]);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// S18: `a` writes `src/c.src`, which the proof of the skipped unit `c` names. The suite is disabled and the run
/// has no verdict. The write happens only once `go` exists, so the earlier runs are unaffected.
#[test]
fn s18_a_write_into_a_skipped_units_input_disables_the_suite() {
    let s = Suite::new();
    let go = s.outside.join("go").display().to_string();
    let env = [
        ("T_WRITE", "src/c.src"),
        ("T_WRITE_AT", "tests/a.t"),
        ("T_IF", go.as_str()),
    ];
    success(&passed(&s, &env));
    fs::write(&go, "").unwrap();
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 125, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t"]);
    assert_eq!(state(&s)["status"], "disabled", "{}", stderr(&out));
    assert_eq!(state(&s)["code"], "wrote_input", "{}", stderr(&out));
}

/// S18b: `a` creates a top-level entry, which the proof of the skipped unit `c` lists through the root. The run has
/// no verdict, but the suite stays enabled.
#[test]
fn s18b_a_new_top_level_entry_from_a_launch_is_125_not_disabled() {
    let s = Suite::new();
    let go = s.outside.join("go").display().to_string();
    let top = s.root.join("new.top").display().to_string();
    let env = [
        ("T_LS_ROOT", "1"),
        ("T_WRITE", top.as_str()),
        ("T_WRITE_AT", "tests/a.t"),
        ("T_IF", go.as_str()),
    ];
    success(&passed(&s, &env));
    fs::write(&go, "").unwrap();
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 125, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    assert_eq!(state(&s)["status"], "ready", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("which skipped unit tests/c.t lists"),
        "{}",
        stderr(&out)
    );
}

/// S18c: the write of S18 made by the last launch. Nothing stops early, so the run has no verdict because the write
/// broke a skipped unit's proof (spec 3.7, file level), and the suite is disabled.
#[test]
fn s18c_a_write_into_a_skipped_units_input_by_the_last_launch_is_125() {
    let s = Suite::new();
    let go = s.outside.join("go").display().to_string();
    let env = [
        ("T_WRITE", "src/c.src"),
        ("T_WRITE_AT", "tests/b.t"),
        ("T_IF", go.as_str()),
    ];
    success(&passed(&s, &env));
    fs::write(&go, "").unwrap();
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 125, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    assert_eq!(state(&s)["status"], "disabled", "{}", stderr(&out));
    assert_eq!(state(&s)["code"], "wrote_input", "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/b.t changed src/c.src, which skipped unit tests/c.t reads"),
        "{}",
        stderr(&out)
    );
}

/// S19: a run that cannot take the suite lock runs the full command and says so (spec 3.10).
#[test]
fn s19_a_busy_suite_runs_the_full_command_and_says_so() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    edit(&s, 3);
    let lock = hold_lock(&s);
    s.clear_log();
    let out = split(&s, &[]);
    drop(lock);
    success(&out);
    assert!(
        stderr(&out).contains("is busy in another stoop; running the full command"),
        "{}",
        stderr(&out)
    );
    assert!(full(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// S21: `CI` is set, so the run keeps the full form, which launches once with no units.
#[test]
fn s21_ci_keeps_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[("CI", "true")]);
    success(&out);
    assert!(full(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// S22: explain names the launches the next run makes, and writes nothing. Its argv is the first launch's argv.
#[test]
fn s22_explain_predicts_the_launches_the_next_run_makes() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    edit(&s, 3);
    let before = s.store_snapshot();
    s.clear_log();
    let explained = explain(&s, &[]);
    assert_eq!(s.store_snapshot(), before, "explain changed the store");
    assert!(s.launches().is_empty(), "explain launched a unit");
    let line = stderr(&explained)
        .lines()
        .find(|line| line.starts_with("stoop: would run "))
        .unwrap_or_else(|| panic!("no decision line: {}", stderr(&explained)))
        .to_owned();
    assert!(
        line.ends_with("(2 of 3 units affected, one launch each): argv ./t tests/a.t (+1 more)"),
        "{line}"
    );
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
}

/// S22b: when every unit is affected, explain names the attribution pass, with one launch for each unit.
#[test]
fn s22b_explain_names_the_attribution_pass_when_every_unit_is_affected() {
    let s = Suite::new();
    let env = [("FOO", "1")];
    success(&passed(&s, &[]));
    success(&split(&s, &env));
    edit(&s, 3);
    let explained = explain(&s, &env);
    assert!(
        stderr(&explained).contains("(attribution pass): 3 launches, one unit each"),
        "{}",
        stderr(&explained)
    );
}

/// G1: an environment change that a full run sees makes the next change an attribution pass, because every unit's
/// proof was made under the old environment.
#[test]
fn g1_an_environment_change_seen_by_a_full_run_makes_the_next_change_a_pass() {
    let s = Suite::new();
    let env = [("FOO", "1")];
    success(&passed(&s, &[]));
    let out = split(&s, &env);
    success(&out);
    assert!(
        stderr(&out).contains("the environment changed since the last full run"),
        "{}",
        stderr(&out)
    );
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert!(pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t", "tests/c.t"]);
}

/// The model test's random generator. A seed names one sequence on every platform.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn draw(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.draw() % n as u64) as usize
    }
}

/// One operation of the model, as a failure names it.
#[derive(Clone, Copy, Debug)]
enum Flag {
    Fail,
    Ok,
    Removed,
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Flag(usize, Flag),
    Source(usize),
    Rewrite(usize),
    Add,
    Delete(usize),
    Rename(usize),
    Readd(usize),
    Runner,
    RunnerDelete(usize),
    Setup,
    Docs,
    Noop,
}

/// The model's state: which units and runner-only tests exist, how many edits have been made, and what the model knows of
/// each file's history. A removed name is in `deleted` or `deleted_runners`. `listed` and `runner_listed` hold every source
/// index that a file ever listed, and `sources` and `runner_sources` hold the indices that a file lists now. `full` holds
/// the sources that the units and runners listed when the last full run passed, which is what the whole proof records.
struct Model {
    units: Vec<usize>,
    next: usize,
    revision: usize,
    deleted: std::collections::BTreeSet<usize>,
    listed: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>>,
    sources: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>>,
    runners: Vec<usize>,
    deleted_runners: std::collections::BTreeSet<usize>,
    next_runner: usize,
    runner_listed: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>>,
    runner_sources: std::collections::BTreeMap<usize, std::collections::BTreeSet<usize>>,
    full: std::collections::BTreeSet<usize>,
    runners_at_full: std::collections::BTreeSet<usize>,
}

impl Model {
    /// The first state: six units, each listing one to three of four sources. The default tree's units are removed.
    fn start(s: &Suite, rng: &mut Rng) -> Model {
        for unit in ["tests/a.t", "tests/b.t", "tests/c.t", "e2e/x.u"] {
            s.remove(unit);
        }
        for source in 0..4 {
            s.write(&format!("src/s{source}"), "source\n");
        }
        let mut model = Model {
            units: Vec::new(),
            next: 0,
            revision: 0,
            deleted: Default::default(),
            listed: Default::default(),
            sources: Default::default(),
            runners: Vec::new(),
            deleted_runners: Default::default(),
            next_runner: 0,
            runner_listed: Default::default(),
            runner_sources: Default::default(),
            full: Default::default(),
            runners_at_full: Default::default(),
        };
        for _ in 0..6 {
            model.add(s, rng);
        }
        s.write("setup.src", "setup\n");
        s.write("docs/readme.md", "docs\n");
        model
    }

    fn add(&mut self, s: &Suite, rng: &mut Rng) {
        let id = self.next;
        self.next += 1;
        self.units.push(id);
        self.rewrite(s, rng, id);
    }

    /// Writes unit `id`'s file, and records the sources that it lists.
    fn rewrite(&mut self, s: &Suite, rng: &mut Rng, id: usize) {
        let listed = write_unit(s, rng, id);
        self.listed
            .entry(id)
            .or_default()
            .extend(listed.iter().copied());
        self.sources.insert(id, listed.into_iter().collect());
    }

    fn roster(&self) -> Vec<String> {
        self.units.iter().map(|id| unit_path(*id)).collect()
    }

    /// The sources that the units and the runner-only tests list now.
    fn listing_now(&self) -> std::collections::BTreeSet<usize> {
        self.sources
            .values()
            .chain(self.runner_sources.values())
            .flatten()
            .copied()
            .collect()
    }

    /// The next operation. A unit is added only up to nine, and deleted only while two remain. Names are renamed or
    /// re-added, and runner-only tests come and go, so that a step can carry several operations at once.
    fn pick(&self, rng: &mut Rng) -> Op {
        let units = self.units.len();
        match rng.below(18) {
            0 => Op::Flag(rng.below(units), Flag::Fail),
            1 => Op::Flag(rng.below(units), Flag::Ok),
            2 => Op::Flag(rng.below(units), Flag::Removed),
            3 | 4 => Op::Source(rng.below(4)),
            5 | 6 => Op::Rewrite(rng.below(units)),
            7 if units < 9 => Op::Add,
            8 if units > 2 => Op::Delete(rng.below(units)),
            9 => Op::Setup,
            10 => Op::Docs,
            11 => Op::Rename(rng.below(units)),
            12 if !self.deleted.is_empty() => {
                let index = rng.below(self.deleted.len());
                Op::Readd(*self.deleted.iter().nth(index).expect("a deleted unit"))
            }
            13 | 14 => Op::Runner,
            15 if !self.runners.is_empty() => Op::RunnerDelete(rng.below(self.runners.len())),
            _ => Op::Noop,
        }
    }

    fn apply(&mut self, s: &Suite, rng: &mut Rng, op: Op) {
        match op {
            Op::Flag(k, flag) => {
                let path = flag_path(self.units[k]);
                match flag {
                    Flag::Fail => s.write(&path, "fail\n"),
                    Flag::Ok => s.write(&path, "ok\n"),
                    Flag::Removed => {
                        if s.path(&path).exists() {
                            s.remove(&path);
                        }
                    }
                }
            }
            Op::Source(source) => {
                self.revision += 1;
                s.write(
                    &format!("src/s{source}"),
                    &format!("revision {}\n", self.revision),
                );
            }
            Op::Rewrite(k) => {
                let id = self.units[k];
                self.rewrite(s, rng, id);
            }
            Op::Add => self.add(s, rng),
            Op::Delete(k) => {
                let id = self.units.remove(k);
                self.deleted.insert(id);
                self.sources.remove(&id);
                s.remove(&unit_path(id));
                if s.path(&flag_path(id)).exists() {
                    s.remove(&flag_path(id));
                }
            }
            Op::Setup => {
                self.revision += 1;
                s.write("setup.src", &format!("setup {}\n", self.revision));
            }
            Op::Docs => {
                self.revision += 1;
                s.write("docs/readme.md", &format!("docs {}\n", self.revision));
            }
            Op::Rename(k) => {
                let old = self.units[k];
                let new = self.next;
                self.next += 1;
                self.units[k] = new;
                self.deleted.insert(old);
                fs::rename(s.path(&unit_path(old)), s.path(&unit_path(new))).unwrap();
                if s.path(&flag_path(old)).exists() {
                    fs::rename(s.path(&flag_path(old)), s.path(&flag_path(new))).unwrap();
                }
                let listed = self.listed.get(&old).cloned().unwrap_or_default();
                self.listed.insert(new, listed);
                if let Some(sources) = self.sources.remove(&old) {
                    self.sources.insert(new, sources);
                }
            }
            Op::Readd(id) => {
                self.deleted.remove(&id);
                self.units.push(id);
                self.rewrite(s, rng, id);
            }
            Op::Runner => {
                let id = self.next_runner;
                self.next_runner += 1;
                self.runners.push(id);
                let listed = write_listing(s, rng, &runner_path(id));
                self.runner_listed
                    .entry(id)
                    .or_default()
                    .extend(listed.iter().copied());
                self.runner_sources.insert(id, listed.into_iter().collect());
            }
            Op::RunnerDelete(k) => {
                let id = self.runners.remove(k);
                self.deleted_runners.insert(id);
                self.runner_sources.remove(&id);
                s.remove(&runner_path(id));
            }
            Op::Noop => {}
        }
    }
}

fn unit_path(id: usize) -> String {
    format!("tests/m{id}.t")
}

fn flag_path(id: usize) -> String {
    format!("tests/m{id}.flag")
}

/// Writes unit `id`'s file, with one to three distinct sources, and returns those sources.
fn write_unit(s: &Suite, rng: &mut Rng, id: usize) -> Vec<usize> {
    write_listing(s, rng, &unit_path(id))
}

/// A runner-only test's file: a `*.u` file that the full form runs under `T_U`, and that no unit covers.
fn runner_path(id: usize) -> String {
    format!("tests/r{id}.u")
}

/// Writes the file at `rel` with one to three distinct sources, each on its own line, and returns those sources.
fn write_listing(s: &Suite, rng: &mut Rng, rel: &str) -> Vec<usize> {
    let count = 1 + rng.below(3);
    let mut sources: Vec<usize> = Vec::new();
    while sources.len() < count {
        let source = rng.below(4);
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
    let body: String = sources
        .iter()
        .map(|source| format!("src/s{source}\n"))
        .collect();
    s.write(rel, &body);
    sources
}

fn count_from_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// M1: over seeded sequences of edits, the subject's verdict (with `STOOP_SPLIT=1`) equals the verdict of the runner run
/// directly, with `T_U=1`, so the full form also runs the runner-only tests. Its status is never 125 or 2, and every
/// launched argument is a roster unit. A no-op after a passing run launches nothing, unless the stored residue refuses it.
/// Then the full form runs once, its residue names only what `residue_owner` allows, and the next no-op must skip.
/// Seeds come from `STOOP_MODEL_FIRST` (1 by default) for `STOOP_MODEL_SEEDS` (4 by default), and steps from
/// `STOOP_MODEL_STEPS` (30). A step applies one operation, or two in about three steps in ten, before its run.
#[test]
fn model_split_runs_give_the_full_runs_verdict() {
    let first = count_from_env("STOOP_MODEL_FIRST", 1);
    let seeds = count_from_env("STOOP_MODEL_SEEDS", 4);
    let steps = count_from_env("STOOP_MODEL_STEPS", 30);
    for seed in first..first + seeds {
        run_model(seed as u64, steps);
    }
}

/// The residue the engine stored, when it is known for the proof it belongs to and counts paths above zero. That residue
/// refuses a no-op with the residue reason (spec 3.8, E12). The paths are the first ones the bundle stores.
fn stored_residue(s: &Suite) -> Option<(usize, Vec<String>)> {
    let bundle = s.bundle()?;
    let residue = &bundle["residue"];
    let known = residue["state"] != "none"
        && !bundle["whole"].is_null()
        && residue["whole"] == bundle["whole"];
    let count = residue["count"].as_u64()? as usize;
    if !known || count == 0 {
        return None;
    }
    let paths: Vec<String> = residue["paths"]
        .as_array()?
        .iter()
        .filter_map(|path| path.as_str().map(str::to_owned))
        .collect();
    Some((count, paths))
}

/// Whether the model's own history allows the stored residue to name `path` (spec 3.8). A file of a live unit, or a
/// source that a live unit lists now, is a defect. A file of a deleted unit or runner-only test is allowed, and so is a
/// file of a live runner-only test, which the full command reads and no unit does. A source is allowed when a deleted
/// unit or a runner-only test ever listed it, or when the last full pass listed it and no unit lists it now.
fn residue_owner(model: &Model, path: &str) -> Result<(), String> {
    let live_unit_file = model
        .units
        .iter()
        .any(|id| path == unit_path(*id) || path == flag_path(*id));
    if live_unit_file {
        return Err("it is a file of a live unit".to_owned());
    }
    let deleted_unit_file = model
        .deleted
        .iter()
        .any(|id| path == unit_path(*id) || path == flag_path(*id));
    let runner_file = model.runners.iter().any(|id| path == runner_path(*id))
        || model
            .deleted_runners
            .iter()
            .any(|id| path == runner_path(*id));
    if deleted_unit_file || runner_file {
        return Ok(());
    }
    let Some(source) = path
        .strip_prefix("src/s")
        .and_then(|n| n.parse::<usize>().ok())
    else {
        return Err("no deleted unit or runner-only test read it".to_owned());
    };
    if model
        .sources
        .values()
        .any(|listed| listed.contains(&source))
    {
        return Err("a live unit lists that source now".to_owned());
    }
    let deleted_listed = model.deleted.iter().any(|id| {
        model
            .listed
            .get(id)
            .is_some_and(|listed| listed.contains(&source))
    });
    let runner_listed = model
        .runner_listed
        .values()
        .any(|listed| listed.contains(&source));
    if deleted_listed || runner_listed || model.full.contains(&source) {
        return Ok(());
    }
    Err("no deleted unit listed it, and the last full pass did not list it".to_owned())
}

fn run_model(seed: u64, steps: usize) {
    let s = Suite::new();
    let mut rng = Rng::new(seed);
    let mut model = Model::start(&s, &mut rng);
    let env = [("T_U", "1")];
    let cold = split(&s, &env);
    assert_eq!(
        code(&cold),
        0,
        "seed {seed}: the cold run failed: {}",
        stderr(&cold)
    );
    model.full = model.listing_now();
    let mut passing = true;
    // Set by a refused no-op whose full form ran: the next step, when it is a no-op, must skip.
    let mut owed = false;
    let mut operations: Vec<String> = Vec::new();
    for step in 1..=steps {
        let count = if rng.below(10) < 3 { 2 } else { 1 };
        let mut ops = Vec::new();
        for _ in 0..count {
            let op = model.pick(&mut rng);
            model.apply(&s, &mut rng, op);
            ops.push(op);
        }
        let noop = ops.iter().all(|op| matches!(op, Op::Noop));
        operations.push(format!("step {step}: {ops:?}"));
        let roster = model.roster();
        // The residue the engine stored before this step's run: the decision that the run makes reads it.
        let stored = if noop && passing {
            stored_residue(&s)
        } else {
            None
        };
        let owed_now = std::mem::take(&mut owed);
        let runner_new = model
            .runners
            .iter()
            .any(|id| !model.runners_at_full.contains(id));
        s.clear_log();
        let subject = split(&s, &env);
        let launches = launched(&s);
        s.clear_log();
        let oracle = s.direct(&s.root, &[], &env);
        let report = || {
            let mut listing: Vec<String> = std::fs::read_dir(s.path("tests"))
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            listing.sort();
            format!(
                "seed {seed}, step {step}\noperations:\n  {}\nsubject exit {}, oracle exit {}\ntests/ now: {}\nsubject stderr:\n{}",
                operations.join("\n  "),
                code(&subject),
                code(&oracle),
                listing.join(" "),
                stderr(&subject)
            )
        };
        let subject_code = code(&subject);
        assert!(subject_code != 2 && subject_code != 125, "{}", report());
        assert_eq!(subject_code == 0, code(&oracle) == 0, "{}", report());
        for launch in launches.iter().filter(|launch| !launch.is_empty()) {
            assert!(roster.contains(launch), "a non-unit argument: {}", report());
        }
        if noop && passing {
            match &stored {
                _ if owed_now => assert!(
                    launches.is_empty(),
                    "a no-op right after a full run must skip: {}",
                    report()
                ),
                None if !runner_new => assert!(
                    launches.is_empty(),
                    "a no-op after a passing run launched: {}",
                    report()
                ),
                // A refused no-op may run the full form once. So may a no-op after a runner-only test was added since the
                // last full pass: its name is no unit, so the listing of `tests` no longer matches the whole proof's.
                _ => {
                    if launches.is_empty() {
                        assert!(
                            stored.is_some(),
                            "a no-op skipped a runner-only test added since the last full pass: {}",
                            report()
                        );
                    } else {
                        assert_eq!(
                            launches,
                            [""],
                            "a refused no-op must run the full form once: {}",
                            report()
                        );
                        match &stored {
                            Some((count, paths)) => {
                                assert!(
                                    stderr(&subject).contains("the full command reads "),
                                    "{}",
                                    report()
                                );
                                for path in paths {
                                    if let Err(why) = residue_owner(&model, path) {
                                        panic!(
                                            "the residue of {count} files names {path}, and {why}: {}",
                                            report()
                                        );
                                    }
                                }
                                println!(
                                    "M1 exemption: seed {seed}, step {step}: a residue of {count} files; the full form runs once"
                                );
                            }
                            None => assert!(
                                stderr(&subject).contains("tests changed"),
                                "a runner-only test added since the last full pass must change the listing: {}",
                                report()
                            ),
                        }
                        owed = true;
                    }
                }
            }
        }
        if subject_code == 0 && launches == [""] {
            model.full = model.listing_now();
            model.runners_at_full = model.runners.iter().copied().collect();
        }
        passing = subject_code == 0;
    }
}

/// STOP 4 (spec 3.10, E16 as amended): a no-op after a subset that added a unit skips. The subset launched only the new
/// unit and proved it, so its own version covers it, and the whole proof's listing of `tests` gained only that name. The
/// no-op is the engine's skip (`no tracked input changed`), not the legacy hit. This is M1 seed 1, step 15.
#[test]
fn m1_seed1_step15_a_no_op_after_a_subset_that_added_a_unit_skips() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    s.clear_log();
    let added = split(&s, &[]);
    success(&added);
    assert_eq!(launched(&s), ["tests/d.t"], "{}", stderr(&added));
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(
        stderr(&explained).contains("no tracked input changed"),
        "{}",
        stderr(&explained)
    );
    assert!(
        stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// STOP 4: an added unit is excused, but a non-unit file added to the same listing is not, so the full command runs.
#[test]
fn an_added_unit_next_to_an_added_non_unit_is_a_change() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    success(&split(&s, &[]));
    s.write("tests/notes.txt", "not a unit\n");
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(
        stderr(&explained).contains("(tests changed)"),
        "{}",
        stderr(&explained)
    );
    assert!(stderr(&out).contains("(tests changed)"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// STOP 4: a non-unit file renamed inside a listed directory is a change, because its new name is not a unit.
#[test]
fn a_non_unit_file_renamed_in_a_listed_directory_is_a_change() {
    let s = Suite::new();
    s.write("tests/notes.txt", "not a unit\n");
    success(&passed(&s, &[]));
    fs::rename(s.path("tests/notes.txt"), s.path("tests/notes2.txt")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(stderr(&out).contains("(tests changed)"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// STOP 4: a top-level unit added since the full run is covered by its own proof, and the next run skips. The whole proof
/// records no root listing, so no root excuse is needed: the subset proves the unit, and the skip then consults only the
/// unit's proof (spec 3.10).
#[test]
fn a_top_level_unit_added_since_the_full_run_is_covered_by_its_own_proof() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("z.t", "src/c.src\n");
    success(&split(&s, &[]));
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// STOP 4 guard: an added unit whose proof has expired is affected, so it launches. The excuse never reaches it.
#[test]
fn an_added_unit_whose_proof_expired_is_affected_not_excused() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    success(&split(&s, &[]));
    let path = s.bundle_path().expect("a suite bundle");
    let mut bundle = s.bundle().expect("a suite bundle");
    for (unit, versions) in bundle["units"].as_object_mut().unwrap().iter_mut() {
        if unit == "tests/d.t" {
            for version in versions.as_array_mut().unwrap() {
                version["created"] = Value::from(1);
            }
        }
    }
    fs::write(&path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(
        stderr(&out).contains("run 1 (proof expired): tests/d.t"),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), ["tests/d.t"]);
}

/// STOP 4, files a unit reads: a file that a unit reads and that appears after the full run is covered by that unit's
/// own proof, so the next run skips. The whole proof never held the file.
#[test]
fn a_file_a_unit_reads_that_appears_after_the_full_run_is_covered_by_that_unit() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/a.flag", "ok\n");
    s.clear_log();
    success(&split(&s, &[]));
    assert_eq!(launched(&s), ["tests/a.t"]);
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// STOP 4, files a unit reads: a file that no unit reads and that appears after the full run is a change, so the full
/// command runs.
#[test]
fn a_file_no_unit_reads_that_appears_after_the_full_run_is_a_change() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/notes.txt", "read by no unit\n");
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(
        stderr(&explained).contains("(tests changed)"),
        "{}",
        stderr(&explained)
    );
    assert!(stderr(&out).contains("(tests changed)"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// STOP 4, files a unit reads: editing such a file makes that unit affected, so it launches and the run does not skip.
#[test]
fn an_edited_file_a_unit_reads_makes_that_unit_affected() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/a.flag", "ok\n");
    success(&split(&s, &[]));
    s.write("tests/a.flag", "fail\n");
    s.clear_log();
    let out = split(&s, &[]);
    assert!(!skipped(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t"]);
}

/// STOP 4, files a unit reads: removing such a file makes that unit affected, so it launches and the run does not skip.
#[test]
fn a_removed_file_a_unit_reads_makes_that_unit_affected() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/a.flag", "ok\n");
    success(&split(&s, &[]));
    fs::remove_file(s.path("tests/a.flag")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(!skipped(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t"]);
}

/// STOP 4, files a unit reads: a file that only a removed unit's version reads is not covered, because that unit is no
/// longer on the roster. The flag appears after the unit's first proof, so the unit's own run covers it. The full command
/// runs once the unit is removed.
#[test]
fn a_file_read_only_by_a_removed_units_version_is_a_change() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    success(&split(&s, &[]));
    s.write("tests/d.flag", "ok\n");
    success(&split(&s, &[]));
    fs::remove_file(s.path("tests/d.t")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(stderr(&out).contains("(tests changed)"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// STOP 4: a unit added after the full run and removed again leaves its version in the bundle, and the listing check reads
/// that version as a name the listing lost. The whole proof never held the name, so the run takes the full form once, which
/// records the listing as it is now. The next run skips.
#[test]
fn an_added_unit_removed_again_takes_one_full_run_then_skips() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/a.flag", "ok\n");
    success(&split(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    success(&split(&s, &[]));
    fs::remove_file(s.path("tests/d.t")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(full(&out), "{}", stderr(&out));
    assert!(stderr(&out).contains("(tests changed)"), "{}", stderr(&out));
    s.clear_log();
    let explained = explain(&s, &[]);
    let next = split(&s, &[]);
    success(&next);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&next), "{}", stderr(&next));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// STOP 4, reviewer r25: a new top-level unit that fails has no proof, so it is affected and runs alone. A skip would hide it.
#[test]
fn a_new_top_level_unit_that_fails_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("z.t", "src/c.src\n");
    s.write("z.flag", "fail\n");
    s.clear_log();
    let out = split(&s, &[]);
    assert!(!skipped(&out), "{}", stderr(&out));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(launched(&s), ["z.t"]);
}

/// STOP 4, reviewer r25b: a failing unit in a new top-level directory is affected and runs alone.
#[test]
fn a_new_unit_in_a_new_top_level_directory_that_fails_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("extra/z.t", "src/c.src\n");
    s.write("extra/z.flag", "fail\n");
    s.clear_log();
    let out = split(&s, &[]);
    assert!(!skipped(&out), "{}", stderr(&out));
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(launched(&s), ["extra/z.t"]);
}

/// STOP 4, reviewer r27: a unit file replaced by a directory that holds a failing unit. The path still exists, so E11 takes
/// the full form, which runs the new unit and fails. A skip would hide it.
#[test]
fn a_unit_file_replaced_by_a_directory_holding_a_failing_unit_is_not_a_skip() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.remove("tests/c.t");
    s.write("tests/c.t/x.t", "src/c.src\n");
    s.write("tests/c.t/x.flag", "fail\n");
    s.clear_log();
    let out = split(&s, &[]);
    assert!(!skipped(&out), "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/c.t is no longer one of the units but still exists"),
        "{}",
        stderr(&out)
    );
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// A unit deleted before it has a proof leaves reads in the whole proof that no unit can attribute (spec 3.8). The pass
/// after the deletion measures the residue, so the next no-op is refused on it and runs the full form once, with the
/// residue reason. That full run records the whole proof again, so the no-op after it skips.
#[test]
fn a_unit_deleted_before_it_had_a_proof_takes_one_full_run_then_skips() {
    let s = Suite::new();
    success(&split(&s, &[]));
    fs::remove_file(s.path("tests/c.t")).unwrap();
    s.clear_log();
    let pass = split(&s, &[]);
    success(&pass);
    assert!(pass_line(&pass), "{}", stderr(&pass));
    s.clear_log();
    let refused = split(&s, &[]);
    success(&refused);
    assert!(full(&refused), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("the full command reads ")
            && stderr(&refused).contains("tests/c.t"),
        "{}",
        stderr(&refused)
    );
    assert_eq!(launched(&s), [""]);
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// A unit deleted after it had a proof leaves its reads attributed: the residue was measured while the unit existed, and
/// it is not measured again while the whole proof is current. So the run skips.
#[test]
fn a_unit_deleted_after_it_had_a_proof_stays_attributed_and_skips() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    fs::remove_file(s.path("tests/c.t")).unwrap();
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&out), "{}", stderr(&out));
    assert!(s.launches().is_empty(), "a skip launches nothing");
}

/// E11, reviewer r37 (issue #81, item 2): a dangling link still exists, so the unit has not been removed. Its
/// symlink_metadata is what says so, and `metadata` would say it is gone. The full command takes the full form.
#[test]
fn a_unit_file_replaced_by_a_dangling_link_takes_the_full_form() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.remove("tests/c.t");
    std::os::unix::fs::symlink("gone.t", s.path("tests/c.t")).unwrap();
    s.clear_log();
    let out = split(&s, &[]);
    assert!(full(&out), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("tests/c.t is no longer one of the units but still exists"),
        "{}",
        stderr(&out)
    );
    assert_eq!(launched(&s), [""]);
}

/// A new runner-only test (a `*.u` file that the full form runs under `T_U`) that fails, beside an edit to a unit. The
/// new name is no unit, so no excuse covers it: the full form runs and reports the failure a subset would not run.
fn fail_runner_only(s: &Suite, rel: &str) {
    s.write(rel, "src/c.src\n");
    s.write(&format!("{}.flag", rel.trim_end_matches(".u")), "fail\n");
}

#[test]
fn a_new_failing_runner_only_test_beside_a_unit_edit_is_a_full_run() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env));
    fail_runner_only(&s, "tests/z.u");
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert!(stderr(&out).contains("tests changed"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

#[test]
fn a_new_failing_runner_only_test_in_src_beside_a_unit_edit_is_a_full_run() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env));
    fail_runner_only(&s, "src/z.u");
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert!(stderr(&out).contains("src changed"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

#[test]
fn a_new_failing_runner_only_test_beside_every_unit_edited_is_a_full_run() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env));
    fail_runner_only(&s, "tests/z.u");
    s.write("tests/c.t", "src/c.src\n\n");
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert!(!pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

#[test]
fn a_new_failing_runner_only_test_in_src_beside_every_unit_edited_is_a_full_run() {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let env = [("T_U", "1")];
    success(&passed(&s, &env));
    fail_runner_only(&s, "src/z.u");
    s.write("tests/c.t", "src/c.src\n\n");
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert!(!pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// An ignored test (`tests/z.t` is in `.stoopignore`, so it is no unit) that the full form runs, and that fails once
/// `T_IF` names it, beside an edit to a unit. A subset of the unit would pass. The catalog reads `.stoopignore`, which no
/// unit reads, so the residue refuses the subset before the listing is looked at; the test pins that the full form runs.
#[test]
fn an_ignored_test_beside_a_unit_edit_is_a_full_run() {
    let s = Suite::new();
    s.write(".stoopignore", "tests/z.t\n");
    let z = s.path("tests/z.t").display().to_string();
    let env = [("T_FAIL_FULL", "1"), ("T_IF", z.as_str())];
    success(&passed(&s, &env));
    s.write("tests/z.t", "src/c.src\n");
    s.write("tests/c.t", "src/c.src\n\n");
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(full(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
}

/// A failing unit keeps the proof it held until it passes. `b` fails in a run that replaces `a`'s proof, and its old
/// proof still holds when the shared source is back as it was: `b` is not launched, while `a` is. A dropped or a stored
/// failing proof would launch `b` as well.
#[test]
fn a_failing_unit_keeps_its_previous_proof_until_it_passes() {
    let s = Suite::new();
    let run = |s: &Suite| s.run(&s.root, &[], &["./t", UNIT], &[SPLIT]);
    s.write("tests/b.flag", "ok\n");
    success(&run(&s));
    edit(&s, 2);
    success(&run(&s));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 3);
    s.clear_log();
    let out = run(&s);
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    s.write("tests/b.flag", "ok\n");
    edit(&s, 2);
    s.clear_log();
    let out = run(&s);
    success(&out);
    assert_eq!(launched(&s), ["tests/a.t"], "{}", stderr(&out));
}

/// A launch that writes a top-level entry, which the proof of a skipped unit lists through the root, is a 125 when it is
/// the last launch. S18b covers the first launch; the listing level must not skip the last one.
#[test]
fn a_top_level_entry_written_by_the_last_launch_is_125_not_disabled() {
    let s = Suite::new();
    let go = s.outside.join("go").display().to_string();
    let top = s.root.join("new.top").display().to_string();
    let env = [
        ("T_LS_ROOT", "1"),
        ("T_WRITE", top.as_str()),
        ("T_WRITE_AT", "tests/c.t"),
        ("T_IF", go.as_str()),
    ];
    success(&passed(&s, &env));
    fs::write(&go, "").unwrap();
    s.write("src/c.src", "c changed\n");
    s.clear_log();
    let out = split(&s, &env);
    assert_eq!(code(&out), 125, "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/c.t"]);
    assert_eq!(state(&s)["status"], "ready", "{}", stderr(&out));
}

/// The attribution pass exports no changed inputs, to any launch, in the variable (spec 3.11). Every unit is affected
/// here and each holds a stored version, so this is an attribution pass that keeps its versions.
#[test]
fn the_attribution_pass_exports_no_changed_inputs() {
    let s = Suite::new();
    success(&split(&s, &[]));
    edit(&s, 2);
    success(&split(&s, &[]));
    s.write("src/c.src", "c changed\n");
    edit(&s, 3);
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(pass_line(&out), "{}", stderr(&out));
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t", "tests/c.t"]);
    for launch in s.launches() {
        assert_eq!(launch.env("changed_inputs"), "", "{}", stderr(&out));
    }
}
