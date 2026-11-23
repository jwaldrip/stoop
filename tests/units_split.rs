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

/// S7: deleting `c`, then editing `a` and `b` through their own files, runs `a` and `b`. Each reads its own file alone, so
/// neither change is global, and the proof of `c` is dropped with the write (spec 3.10, E18; E14 g2 does not apply).
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
    assert_header(&out, "; run 2 (tests/a.t changed): tests/a.t, tests/b.t");
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

/// S15: a `{unit}` run whose unit `b` fails keeps `b` affected. Its previous proof stays until `b` passes.
#[test]
fn a_failing_unit_keeps_its_previous_proof_until_it_passes() {
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
    Setup,
    Docs,
    Noop,
}

/// The model's state: which units exist, and how many edits have been made.
struct Model {
    units: Vec<usize>,
    next: usize,
    revision: usize,
}

impl Model {
    /// The first state: six units, each listing one to three of four sources. The default tree's units are removed.
    fn start(s: &Suite, rng: &mut Rng) -> Model {
        for unit in ["tests/a.t", "tests/b.t", "tests/c.t"] {
            s.remove(unit);
        }
        for source in 0..4 {
            s.write(&format!("src/s{source}"), "source\n");
        }
        let mut model = Model {
            units: Vec::new(),
            next: 0,
            revision: 0,
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
        write_unit(s, rng, id);
    }

    fn roster(&self) -> Vec<String> {
        self.units.iter().map(|id| unit_path(*id)).collect()
    }

    /// The next operation. A unit is added only up to nine, and deleted only while two remain.
    fn pick(&self, rng: &mut Rng) -> Op {
        let units = self.units.len();
        match rng.below(12) {
            0 => Op::Flag(rng.below(units), Flag::Fail),
            1 => Op::Flag(rng.below(units), Flag::Ok),
            2 => Op::Flag(rng.below(units), Flag::Removed),
            3 | 4 => Op::Source(rng.below(4)),
            5 | 6 => Op::Rewrite(rng.below(units)),
            7 if units < 9 => Op::Add,
            8 if units > 2 => Op::Delete(rng.below(units)),
            9 => Op::Setup,
            10 => Op::Docs,
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
            Op::Rewrite(k) => write_unit(s, rng, self.units[k]),
            Op::Add => self.add(s, rng),
            Op::Delete(k) => {
                let id = self.units.remove(k);
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

/// Writes unit `id`'s file with one to three distinct sources, each on its own line.
fn write_unit(s: &Suite, rng: &mut Rng, id: usize) {
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
    s.write(&unit_path(id), &body);
}

fn count_from_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// M1: over seeded sequences of edits, the subject's verdict (with `STOOP_SPLIT=1`) equals the verdict of the runner
/// run directly. Its status is never 125 or 2, every launched argument is a roster unit, and a no-op after a passing
/// run launches nothing. Seeds come from `STOOP_MODEL_SEEDS` (4 by default) and steps from `STOOP_MODEL_STEPS` (30).
#[test]
fn model_split_runs_give_the_full_runs_verdict() {
    let seeds = count_from_env("STOOP_MODEL_SEEDS", 4);
    let steps = count_from_env("STOOP_MODEL_STEPS", 30);
    for seed in 1..=seeds {
        run_model(seed as u64, steps);
    }
}

fn run_model(seed: u64, steps: usize) {
    let s = Suite::new();
    let mut rng = Rng::new(seed);
    let mut model = Model::start(&s, &mut rng);
    let cold = split(&s, &[]);
    assert_eq!(
        code(&cold),
        0,
        "seed {seed}: the cold run failed: {}",
        stderr(&cold)
    );
    let mut passing = true;
    let mut operations: Vec<String> = Vec::new();
    for step in 1..=steps {
        let op = model.pick(&mut rng);
        model.apply(&s, &mut rng, op);
        operations.push(format!("step {step}: {op:?}"));
        let roster = model.roster();
        s.clear_log();
        let subject = split(&s, &[]);
        let launches = launched(&s);
        s.clear_log();
        let oracle = s.direct(&s.root, &[], &[]);
        let report = || {
            format!(
                "seed {seed}, step {step}\noperations:\n  {}\nsubject exit {}, oracle exit {}\nsubject stderr:\n{}",
                operations.join("\n  "),
                code(&subject),
                code(&oracle),
                stderr(&subject)
            )
        };
        let subject_code = code(&subject);
        assert!(subject_code != 2 && subject_code != 125, "{}", report());
        assert_eq!(subject_code == 0, code(&oracle) == 0, "{}", report());
        for launch in launches.iter().filter(|launch| !launch.is_empty()) {
            assert!(roster.contains(launch), "a non-unit argument: {}", report());
        }
        if matches!(op, Op::Noop) && passing {
            assert!(
                launches.is_empty(),
                "a no-op after a passing run launched: {}",
                report()
            );
        }
        passing = subject_code == 0;
    }
}

/// STOP 4 (spec 3.10, E16 as amended): a no-op after a subset that added a unit skips. The subset proved the new unit, so
/// its own version covers it, and the whole proof's listing of `tests` gained only that name. This is M1 seed 1, step 15.
#[test]
fn m1_seed1_step15_a_no_op_after_a_subset_that_added_a_unit_skips() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("tests/d.t", "src/c.src\n");
    success(&split(&s, &[]));
    s.clear_log();
    let explained = explain(&s, &[]);
    let out = split(&s, &[]);
    success(&out);
    assert!(skipped(&explained), "{}", stderr(&explained));
    assert!(skipped(&out), "{}", stderr(&out));
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

/// STOP 4: the root listing never excuses an added unit. A top-level unit added since the full run is a change to the
/// root, so the full command runs for it, even though the unit's own version covers it.
#[test]
fn a_top_level_unit_added_since_the_full_run_is_never_excused() {
    let s = Suite::new();
    success(&passed(&s, &[]));
    s.write("z.t", "src/c.src\n");
    success(&split(&s, &[]));
    s.clear_log();
    let out = split(&s, &[]);
    success(&out);
    assert!(stderr(&out).contains("(. changed)"), "{}", stderr(&out));
    assert_eq!(launched(&s), [""]);
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
