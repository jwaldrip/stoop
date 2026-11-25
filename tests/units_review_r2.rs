//! PR 86 review round 2 (W7-3). Wrong-verdict scenarios the subset rule must answer without a false pass: a unit that
//! departs or stops reading a runner-only test's flag in the step the flag fails (x01, x01c, x02), and a full run that
//! the engine takes for another reason, after which the flag fails (x03a to x03d). Two pins: explain creates nothing in
//! the suite store (c3), and an engine skip reports its outcome on the status descriptor (c5). Linux only.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::FromRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Output;
use std::time::Duration;
use units_common::*;

const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");
const COMPLETION: &str = "stoop: attribution pass after the full run: ";
const LEARN_LINE: &str = "stoop: if the full command passes, would launch ";
const TU: [(&str, &str); 1] = [("T_U", "1")];

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

fn explain_with(s: &Suite, options: &[&str], env: &[(&str, &str)], on: bool) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(options)
        .args(["--", "./t", HOOK]);
    if on {
        command.env(SPLIT.0, SPLIT.1);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

fn explain(s: &Suite, env: &[(&str, &str)]) -> Output {
    explain_with(s, &[], env, true)
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

fn residue(s: &Suite) -> Value {
    s.bundle()
        .map(|bundle| bundle["residue"].clone())
        .unwrap_or(Value::Null)
}

/// The residue's count when it is known for the bundle's whole proof (any state but `none`).
fn known(s: &Suite) -> Option<u64> {
    let bundle = bundle(s);
    let residue = &bundle["residue"];
    (residue["state"] != "none"
        && !bundle["whole"].is_null()
        && residue["whole"] == bundle["whole"])
        .then(|| residue["count"].as_u64().unwrap_or(0))
}

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

/// Explains (the store must not change and nothing launches), runs the direct full form when `compare` is set, then
/// runs the subject. Returns (explain, run, launches, direct status or -1).
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
        "REVIEW {name}: exit={} direct={direct_code} launches={launches:?} predicted={:?} completion={:?} residue={}\n--- explain\n{}--- run\n{}",
        code(&ran),
        predicted(&explained),
        completion(&ran),
        residue(s),
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

fn prediction_matches(name: &str, explained: &Output, ran: &Output) {
    assert_eq!(
        predicted(explained),
        completion(ran),
        "{name}: explain predicted {:?} completion launches, the run made {:?}\n--- explain\n{}--- run\n{}",
        predicted(explained),
        completion(ran),
        stderr(explained),
        stderr(ran)
    );
}

fn learned(s: &Suite, env: &[(&str, &str)]) {
    let (explained, ran, _, _) = judge("cold", s, env, false);
    success(&ran);
    assert_eq!(completion(&ran), Some(3), "{}", stderr(&ran));
    prediction_matches("cold", &explained, &ran);
}

/// The w20 fixture: `tests/z.u` is a runner-only test (the full form runs it under `T_U=1`, no unit does), whose flag
/// is `tests/z.flag`. Unit `c` reads both as data, so the residue counts them as unit work.
fn zsuite() -> Suite {
    let s = Suite::new();
    s.remove("e2e/x.u");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    s
}

fn zlearned() -> Suite {
    let s = zsuite();
    learned(&s, &TU);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s
}

/// A run without a verdict exits 125, and its line names the changed input that no kept proof and no new proof reads
/// (PR 86 review round 2). The x01, x01c and x02 runs must print it.
fn no_verdict_names(ran: &Output, path: &str) {
    assert_eq!(code(ran), 125, "{}", stderr(ran));
    let line = format!(
        "stoop: this run has no verdict (exit 125): {path} changed, and no unit's new proof reads it"
    );
    assert!(stderr(ran).contains(&line), "{}", stderr(ran));
}

/// The full command takes the decision, because a changed input is read only by units that left the roster (PR 86
/// review round 2). Its exit is the verdict, and the reason names the input.
fn full_form(name: &str, ran: &Output, launches: &[String], direct_code: i32, path: &str) {
    assert_eq!(code(ran), direct_code, "{name}: {}", stderr(ran));
    assert_eq!(
        launches.first().map(String::as_str),
        Some(""),
        "{name}: {launches:?}"
    );
    let reason = format!("{path} changed and only units that left the roster read it");
    assert!(stderr(ran).contains(&reason), "{name}: {}", stderr(ran));
}

// ---- Wrong verdicts: the reader goes in the same step as the flag fails ----

/// x01: `c`, the only unit that reads the runner-only test's file and flag, is deleted while `a` changes and the flag
/// turns to `fail`, in one step. The full command runs `z.u`, which fails.
#[test]
fn r2_x01_a_deleted_reader_and_a_subset_in_one_step() {
    let s = zlearned();
    s.remove("tests/c.t");
    s.remove("tests/c.flag");
    s.write("tests/a.t", "src/shared.src\n\n");
    s.write("tests/z.flag", "fail\n");
    let (_, ran, launches, direct_code) = judge("x01", &s, &TU, true);
    same_verdict("x01", &ran, direct_code);
    full_form("x01", &ran, &launches, direct_code, "tests/z.flag");
}

/// x01c: `c.t` is renamed to `d.t`, whose listing drops the runner-only test, while the flag turns to `fail`.
#[test]
fn r2_x01c_a_renamed_reader_in_one_step() {
    let s = zlearned();
    s.remove("tests/c.t");
    s.write("tests/d.t", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let (_, ran, launches, direct_code) = judge("x01c", &s, &TU, true);
    same_verdict("x01c", &ran, direct_code);
    full_form("x01c", &ran, &launches, direct_code, "tests/z.flag");
}

/// x02: `c` stops reading the runner-only test in the same step as its flag turns to `fail`.
#[test]
fn r2_x02_a_unit_that_stops_reading_in_the_step_its_flag_fails() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let (_, ran, _, direct_code) = judge("x02", &s, &TU, true);
    same_verdict("x02", &ran, direct_code);
    no_verdict_names(&ran, "tests/z.flag");
}

/// x03a: a full run that the engine takes for another reason (here `setup.src`, which every unit reads, changed) records
/// the whole proof while `c`'s stale version still names the runner-only test. The residue is measured against that
/// stale version, so it is known and empty, and completion learns nothing. The next change trusts the stale reads.
#[test]
fn r2_x03a_a_global_full_run_leaves_a_stale_reader_counted() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "setup changed\n");
    let (_, first, launches, direct_first) = judge("x03a-first", &s, &TU, true);
    same_verdict("x03a-first", &first, direct_first);
    eprintln!(
        "REVIEW x03a after the full run: launches={launches:?} residue={}",
        residue(&s)
    );
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("x03a", &s, &TU, true);
    same_verdict("x03a", &second, direct_second);
}

/// x03b: as x03a, with an environment change as the reason for the full run.
#[test]
fn r2_x03b_an_environment_full_run_leaves_a_stale_reader_counted() {
    let s = zlearned();
    let env = [("T_U", "1"), ("FOO", "1")];
    s.write("tests/c.t", "src/c.src\n");
    let (_, first, launches, direct_first) = judge("x03b-first", &s, &env, true);
    same_verdict("x03b-first", &first, direct_first);
    eprintln!(
        "REVIEW x03b after the full run: launches={launches:?} residue={}",
        residue(&s)
    );
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("x03b", &s, &env, true);
    same_verdict("x03b", &second, direct_second);
}

/// x03c: as x03a, with a new file that is not a unit in `tests` as the reason for the full run (its listing changed).
#[test]
fn r2_x03c_a_listing_full_run_leaves_a_stale_reader_counted() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/notes.txt", "notes\n");
    let (_, first, launches, direct_first) = judge("x03c-first", &s, &TU, true);
    same_verdict("x03c-first", &first, direct_first);
    eprintln!(
        "REVIEW x03c after the full run: launches={launches:?} residue={}",
        residue(&s)
    );
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("x03c", &s, &TU, true);
    same_verdict("x03c", &second, direct_second);
}

/// x03d: as x03a, with `STOOP_FULL=1` as the reason for the full run.
#[test]
fn r2_x03d_a_forced_full_run_leaves_a_stale_reader_counted() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\n");
    let forced = [("T_U", "1"), ("STOOP_FULL", "1")];
    let (_, first, launches, direct_first) = judge("x03d-first", &s, &forced, true);
    same_verdict("x03d-first", &first, direct_first);
    eprintln!(
        "REVIEW x03d after the full run: launches={launches:?} residue={}",
        residue(&s)
    );
    s.write("tests/z.flag", "fail\n");
    let (_, second, _, direct_second) = judge("x03d", &s, &TU, true);
    same_verdict("x03d", &second, direct_second);
}

/// The stoop run with a status descriptor (fd 3). Returns the run's output and the JSON line it reported.
fn run_with_status(s: &Suite) -> (Output, String) {
    let mut fds = [0i32; 2];
    // SAFETY: `fds` has room for the two descriptors pipe2 writes.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
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
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = spawning(|| command.output()).unwrap();
    // SAFETY: this process owns both ends.
    unsafe { libc::close(write) };
    // SAFETY: `read` is an open descriptor that only this function uses from here on.
    let mut file = unsafe { File::from_raw_fd(read) };
    let mut report = String::new();
    file.read_to_string(&mut report).unwrap();
    (out, report)
}

fn stamp(dir: &Path) -> (std::time::SystemTime, i64, i64, u64) {
    let metadata = fs::metadata(dir).unwrap();
    (
        metadata.modified().unwrap(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        metadata.nlink(),
    )
}

/// c3: explain creates nothing in the suite store, with the switch off and on (spec 3.12, 4.16). A created and removed
/// entry changes the directory's modification time.
#[test]
fn r2_c3_explain_creates_nothing_in_the_suite_store() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let dir = s
        .bundle_path()
        .expect("a suite bundle")
        .parent()
        .unwrap()
        .to_path_buf();
    let before = stamp(&dir);
    std::thread::sleep(Duration::from_millis(50));
    let off = explain_with(&s, &[], &[], false);
    assert_eq!(
        stamp(&dir),
        before,
        "the switch-off explain changed the suite store directory\n{}",
        stderr(&off)
    );
    std::thread::sleep(Duration::from_millis(50));
    let on = explain(&s, &[]);
    eprintln!("REVIEW c3 switch-on explain:\n{}", stderr(&on));
    assert!(stderr(&on).contains(LEARN_LINE), "{}", stderr(&on));
    assert_eq!(
        stamp(&dir),
        before,
        "the switch-on explain created or removed an entry in the suite store directory\n{}",
        stderr(&on)
    );
}

/// c5: an engine skip reports the `units` outcome on the status descriptor (D17 at the base). The skip comes after a
/// subset, so the whole-command lookup misses and the engine decides it.
#[test]
fn r2_c5_an_engine_skip_reports_units_on_the_status_descriptor() {
    let s = Suite::new();
    learned(&s, &[]);
    edit(&s, 2);
    success(&split(&s, &[]));
    s.write("docs/readme.md", "edited\n");
    let (out, report) = run_with_status(&s);
    eprintln!("REVIEW c5: {report}\n{}", stderr(&out));
    success(&out);
    assert!(
        stderr(&out).contains("no tracked input changed"),
        "{}",
        stderr(&out)
    );
    let decided: Value = serde_json::from_str(report.trim())
        .unwrap_or_else(|error| panic!("the status line is not JSON ({error}): {report:?}"));
    assert_eq!(decided["decision"], "skipped", "{decided}");
    assert_eq!(decided["how"], "units", "{decided}");
}

/// The seed 33 shape: a unit is added, and the only reader of a changed source is deleted, in one step. The full command
/// decides, so the run exits as the full command does.
#[test]
fn r2_departed_only_reader_of_a_changed_source_takes_the_full_form() {
    let s = zlearned();
    s.write("tests/n.t", "src/shared.src\n");
    s.remove("tests/c.t");
    s.write("src/c.src", "changed\n");
    let (_, ran, launches, direct_code) = judge("seed33", &s, &TU, true);
    full_form("seed33", &ran, &launches, direct_code, "src/c.src");
}

/// The seed 11089 shape with another source: a unit that reads it alone is deleted while a unit is added.
#[test]
fn r2_departed_only_reader_of_a_second_source_takes_the_full_form() {
    let s = zsuite();
    s.write("src/d.src", "original\n");
    s.write(
        "tests/c.t",
        "src/c.src\ntests/z.u\ntests/z.flag\nsrc/d.src\n",
    );
    learned(&s, &TU);
    s.write("tests/n.t", "src/shared.src\n");
    s.remove("tests/c.t");
    s.write("src/d.src", "changed\n");
    s.write("tests/z.flag", "fail\n");
    let (_, ran, launches, direct_code) = judge("seed11089", &s, &TU, true);
    assert_eq!(direct_code, 1, "the runner-only test must fail");
    full_form("seed11089", &ran, &launches, direct_code, "src/d.src");
}

/// The whole roster is affected in the same step, and the only reader of the failing flag is a departed unit: the whole
/// roster pass takes the full form too, because no launch reads the flag.
#[test]
fn r2_e17_departed_only_reader_of_a_failing_flag_takes_the_full_form() {
    let s = zlearned();
    s.remove("tests/c.t");
    s.remove("tests/c.flag");
    s.write("tests/a.t", "src/shared.src\n\n");
    s.write("tests/b.t", "src/shared.src\n\n\n");
    s.write("tests/z.flag", "fail\n");
    let (_, ran, launches, direct_code) = judge("e17", &s, &TU, true);
    full_form("e17", &ran, &launches, direct_code, "tests/z.flag");
}

/// A departed unit's own file can matter to the runner even if a live unit shares its changed source.
#[test]
fn r2_a_departed_reader_shared_with_a_live_unit_takes_the_full_form() {
    let s = zsuite();
    s.write("tests/a.t", "src/shared.src\nsrc/both.src\n");
    s.write(
        "tests/c.t",
        "src/c.src\ntests/z.u\ntests/z.flag\nsrc/both.src\n",
    );
    learned(&s, &TU);
    s.remove("tests/c.t");
    s.write("src/both.src", "changed\n");
    let (_, ran, launches, direct_code) = judge("shared-live", &s, &TU, true);
    same_verdict("shared-live", &ran, direct_code);
    assert_eq!(
        launches.first().map(String::as_str),
        Some(""),
        "{}",
        stderr(&ran)
    );
    assert!(stderr(&ran).contains("tests/c.t was removed after the full command read it"));
}

/// A departed unit's own file still takes the full form when its other inputs are unchanged.
#[test]
fn r2_an_unchanged_input_of_a_departed_reader_takes_the_full_form() {
    let s = zlearned();
    s.remove("tests/c.t");
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, ran, launches, direct_code) = judge("unchanged", &s, &TU, true);
    same_verdict("unchanged", &ran, direct_code);
    assert_eq!(
        launches.first().map(String::as_str),
        Some(""),
        "{}",
        stderr(&ran)
    );
    assert!(stderr(&ran).contains("tests/c.t was removed after the full command read it"));
}

/// The D19 shape with the switch off (PR 86 review round 2, switch-off parity): a cold run, then a changed run that
/// passes by the attribution pass, store the residue as main measures it, provisional against the held versions. The
/// bundle that the switch off writes must be the one main writes.
#[test]
fn r2_switch_off_record_stores_main_residue_measurement() {
    let s = Suite::new();
    s.remove("tests/c.t");
    success(&s.hook(&[]));
    edit(&s, 2);
    success(&s.hook(&[]));
    let stored = residue(&s);
    assert_eq!(stored["state"], "provisional", "{stored}");
    assert_eq!(stored["whole"], bundle(&s)["whole"], "{stored}");
}

// ---- E3: units that read other tests' flags, and runner-only test files, as data ----

fn count_from_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

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
        (self.draw() % n.max(1) as u64) as usize
    }
}

fn flag_of(path: &str) -> String {
    format!("{}.flag", path.rsplit_once('.').unwrap().0)
}

/// A flag line that a unit lists: read by content, or stat-only (`stat:flag`) one time in three (PR 86 review round 3).
fn flag_line(rng: &mut Rng, flag: &str) -> String {
    if rng.below(3) == 0 {
        format!("stat:{flag}")
    } else {
        flag.to_owned()
    }
}

/// The fake runner with the round three readings (PR 86 review round 3): a listed line `stat:P` stats `P`, and a
/// runner-only test (`*.u`) fails when its flag is absent, so that a removed flag can change the full command.
fn e3_runner() -> String {
    let stat = "cat \"$ROOT/$line\"";
    let flag = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
    let fixture = include_str!("fixtures/hook/t");
    assert_eq!(fixture.matches(stat).count(), 1);
    assert_eq!(fixture.matches(flag).count(), 1);
    fixture
        .replace(
            stat,
            "case $line in\nunit-only:*) if [ \"$TESTS\" = 1 ]; then cat \"$ROOT/${line#unit-only:}\"; fi ;;\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
        )
        .replace(
            flag,
            "if { case \"$1\" in *.u) [ ! -f \"$flag\" ] ;; *) false ;; esac; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then",
        )
}

#[derive(Clone, Debug)]
enum Step {
    Flag(String, &'static str),
    Source(usize),
    Rewrite(String),
    Add(String),
    Delete(String),
    Readd(String),
    Rename(String, String),
    Runner(String),
    RunnerDelete(String),
    Setup,
    /// `FOO` takes this value for the subject and the runner from this step on.
    Env(usize),
    /// The subject runs with `STOOP_FULL=1` in this step.
    Forced,
    /// A runner-only test's flag is removed, and each unit that lists it stops listing it in the same step (PR 86 review
    /// round 3).
    RemoveAndDrop(String),
    SelfFail(String),
    SelfPass(String),
    StageRunner(String, String),
    StatStaged(String, String),
    PublishStaged(String),
    ListedDirectory(usize),
    Noop,
}

struct World {
    units: Vec<String>,
    runners: Vec<String>,
    deleted: Vec<String>,
    staged: Vec<String>,
    next: usize,
    revision: usize,
    foo: usize,
    forced: bool,
}

impl World {
    fn fresh(&mut self, ext: &str) -> String {
        let name = format!("tests/m{}.{ext}", self.next);
        self.next += 1;
        name
    }

    /// One or two sources. Then, two times in three when a runner-only test exists, that test's file and flag; or one
    /// time in three, another unit's flag. All read as data, by `cat`.
    fn listing(&self, rng: &mut Rng, own: &str) -> String {
        let mut lines: Vec<String> = Vec::new();
        let count = 1 + rng.below(2);
        while lines.len() < count {
            let source = format!("src/s{}", rng.below(4));
            if !lines.contains(&source) {
                lines.push(source);
            }
        }
        match rng.below(3) {
            0 | 1 if !self.runners.is_empty() => {
                let runner = self.runners[rng.below(self.runners.len())].clone();
                lines.push(flag_line(rng, &flag_of(&runner)));
                lines.push(runner);
            }
            2 => {
                let others: Vec<&String> = self.units.iter().filter(|unit| *unit != own).collect();
                if !others.is_empty() {
                    let pick = rng.below(others.len());
                    lines.push(flag_line(rng, &flag_of(others[pick])));
                }
            }
            _ => {}
        }
        lines.iter().map(|line| format!("{line}\n")).collect()
    }

    fn sources(rng: &mut Rng) -> String {
        format!("src/s{}\n", rng.below(4))
    }

    fn pick(&mut self, rng: &mut Rng) -> Step {
        let units = self.units.len();
        let choice = rng.below(26);
        match choice {
            0..=2 => {
                let kind = ["fail", "ok", "removed"][choice];
                let pool: Vec<String> = self.units.iter().chain(&self.runners).cloned().collect();
                Step::Flag(pool[rng.below(pool.len())].clone(), kind)
            }
            3 | 4 => Step::Source(rng.below(4)),
            5..=7 => Step::Rewrite(self.units[rng.below(units)].clone()),
            8 if units < 8 => Step::Add(self.fresh("t")),
            9 if units > 2 => Step::Delete(self.units[rng.below(units)].clone()),
            10 if !self.deleted.is_empty() && units < 8 => {
                Step::Readd(self.deleted[rng.below(self.deleted.len())].clone())
            }
            11 if units > 2 => {
                let from = self.units[rng.below(units)].clone();
                Step::Rename(from, self.fresh("t"))
            }
            12 | 13 if self.runners.len() < 2 => Step::Runner(self.fresh("u")),
            14 if !self.runners.is_empty() => {
                Step::RunnerDelete(self.runners[rng.below(self.runners.len())].clone())
            }
            15 => Step::Setup,
            16 if !self.runners.is_empty() => {
                Step::RemoveAndDrop(self.runners[rng.below(self.runners.len())].clone())
            }
            17 => Step::Env(rng.below(3)),
            18 => Step::Forced,
            19 => Step::SelfFail(self.units[rng.below(units)].clone()),
            20 => Step::SelfPass(self.units[rng.below(units)].clone()),
            21 if self.staged.len() < 2 => {
                let unit = self.units[rng.below(units)].clone();
                Step::StageRunner(unit, self.fresh("u"))
            }
            22 if !self.staged.is_empty() => Step::StatStaged(
                self.units[rng.below(units)].clone(),
                self.staged[rng.below(self.staged.len())].clone(),
            ),
            23 if !self.staged.is_empty() && self.runners.len() < 2 => {
                Step::PublishStaged(self.staged[rng.below(self.staged.len())].clone())
            }
            24 => Step::ListedDirectory(rng.below(4)),
            _ => Step::Noop,
        }
    }

    fn apply(&mut self, s: &Suite, rng: &mut Rng, step: &Step) {
        match step {
            Step::Flag(path, kind) => {
                let flag = flag_of(path);
                match *kind {
                    "fail" => s.write(&flag, "fail\n"),
                    "ok" => s.write(&flag, "ok\n"),
                    _ => {
                        if s.path(&flag).exists() {
                            s.remove(&flag);
                        }
                    }
                }
            }
            Step::Source(n) => {
                self.revision += 1;
                s.write(
                    &format!("src/s{n}"),
                    &format!("revision {}\n", self.revision),
                );
            }
            Step::Rewrite(path) => {
                let body = self.listing(rng, path);
                s.write(path, &body);
            }
            Step::Add(path) | Step::Readd(path) => {
                let body = self.listing(rng, path);
                s.write(path, &body);
                self.deleted.retain(|gone| gone != path);
                self.units.push(path.clone());
                self.units.sort();
            }
            Step::Delete(path) => {
                s.remove(path);
                self.units.retain(|unit| unit != path);
                self.deleted.push(path.clone());
            }
            Step::Rename(from, to) => {
                fs::rename(s.path(from), s.path(to)).unwrap();
                self.units.retain(|unit| unit != from);
                self.deleted.push(from.clone());
                self.units.push(to.clone());
                self.units.sort();
                // Half the time the new name lists its own reads, so a rename can also drop the old name's data reads.
                if rng.below(2) == 0 {
                    let body = self.listing(rng, to);
                    s.write(to, &body);
                }
            }
            Step::Runner(path) => {
                let body = World::sources(rng);
                s.write(path, &body);
                self.runners.push(path.clone());
                s.write(&flag_of(path), "ok\n");
            }
            Step::RunnerDelete(path) => {
                s.remove(path);
                if s.path(&flag_of(path)).exists() {
                    s.remove(&flag_of(path));
                }
                self.runners.retain(|other| other != path);
            }
            Step::Setup => {
                self.revision += 1;
                s.write("setup.src", &format!("setup {}\n", self.revision));
            }
            Step::Env(value) => self.foo = *value,
            Step::Forced => self.forced = true,
            Step::RemoveAndDrop(path) => {
                let flag = flag_of(path);
                let stated = format!("stat:{flag}");
                for unit in &self.units {
                    let body = fs::read_to_string(s.path(unit)).unwrap_or_default();
                    if body.lines().any(|line| line == flag || line == stated) {
                        let kept: String = body
                            .lines()
                            .filter(|line| *line != flag && *line != stated)
                            .map(|line| format!("{line}\n"))
                            .collect();
                        s.write(unit, &kept);
                    }
                }
                if s.path(&flag).exists() {
                    s.remove(&flag);
                }
            }
            Step::SelfFail(path) | Step::SelfPass(path) => {
                let text = fs::read_to_string(s.path(path)).unwrap();
                let mut body: String = text
                    .lines()
                    .filter(|line| *line != "fail")
                    .map(|line| format!("{line}\n"))
                    .collect();
                if matches!(step, Step::SelfFail(_)) {
                    body.push_str("fail\n");
                }
                s.write(path, &body);
            }
            Step::StageRunner(unit, path) => {
                let body = fs::read_to_string(s.path(unit)).unwrap();
                s.write(
                    unit,
                    &format!("{body}unit-only:{path}\nunit-only:{}\n", flag_of(path)),
                );
                self.staged.push(path.clone());
            }
            Step::StatStaged(unit, path) => {
                let body = fs::read_to_string(s.path(unit)).unwrap();
                s.write(
                    unit,
                    &format!("{body}stat:{path}\nstat:{}\n", flag_of(path)),
                );
            }
            Step::PublishStaged(path) => {
                s.write(path, &World::sources(rng));
                s.write(
                    &flag_of(path),
                    if rng.below(2) == 0 { "ok\n" } else { "fail\n" },
                );
                self.staged.retain(|staged| staged != path);
                self.runners.push(path.clone());
            }
            Step::ListedDirectory(kind) => listed_policy_replace(s, *kind),
            Step::Noop => {}
        }
    }
}

/// Each roster unit's listed data inputs, captured before and after a model step.
fn e3_listings(
    s: &Suite,
    units: &[String],
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    units
        .iter()
        .filter_map(|unit| {
            let text = fs::read_to_string(s.path(unit)).ok()?;
            Some((
                unit.clone(),
                text.lines()
                    .filter(|line| !line.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ))
        })
        .collect()
}

/// An appeared runner-only test must be read by content by a unit launched in this step.
fn e3_launched_content_path(listings: &ModelListings, launches: &[String], path: &str) -> bool {
    let unit_only = format!("unit-only:{path}");
    launches.iter().any(|unit| {
        listings
            .get(unit)
            .is_some_and(|lines| lines.contains(path) || lines.contains(&unit_only))
    })
}

#[test]
fn r7_e5_requires_a_launched_unit_to_read_the_appeared_test() {
    let mut listings = ModelListings::new();
    listings.insert(
        "tests/a.t".into(),
        ["tests/z.u".into()].into_iter().collect(),
    );
    listings.insert(
        "tests/c.t".into(),
        ["stat:tests/z.u".into()].into_iter().collect(),
    );
    let launches = vec!["tests/c.t".to_owned()];
    assert!(!e3_launched_content_path(&listings, &launches, "tests/z.u"));
    listings
        .get_mut("tests/c.t")
        .unwrap()
        .insert("unit-only:tests/z.u".into());
    assert!(e3_launched_content_path(&listings, &launches, "tests/z.u"));
}

/// The paths that the stored versions of `units` read, by the bundle's table (`stored` is the bundle before the run).
fn stored_reads(stored: &Value, units: &[String]) -> Vec<String> {
    let table = stored["table"].as_array().cloned().unwrap_or_default();
    let mut out = Vec::new();
    for unit in units {
        for version in stored["units"][unit.as_str()]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let mut index: u64 = 0;
            for (at, step) in version["inputs"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                let step = step.as_u64().unwrap_or(0);
                index = if at == 0 { step } else { index + step };
                if let Some(path) = table
                    .get(index as usize)
                    .and_then(|entry| entry["path"].as_str())
                {
                    out.push(path.to_owned());
                }
            }
        }
    }
    out
}

/// A stat and a content read share an identity. Check the unit's recorded own-file bytes and its runner line too.
fn e3_stored_content_flag(
    stored: &Value,
    s: &Suite,
    units: &[String],
    flag: &str,
    previous: &str,
) -> bool {
    let Some(table) = stored["table"].as_array() else {
        return false;
    };
    let flag_hash = blake3::hash(previous.as_bytes()).to_hex().to_string();
    for unit in units {
        let Ok(body) = fs::read_to_string(s.path(unit)) else {
            continue;
        };
        if !body
            .lines()
            .any(|line| line == flag || line.strip_prefix("unit-only:") == Some(flag))
        {
            continue;
        }
        let unit_hash = blake3::hash(body.as_bytes()).to_hex().to_string();
        let Some(versions) = stored["units"][unit.as_str()].as_array() else {
            continue;
        };
        for version in versions {
            let Some(inputs) = version["inputs"].as_array() else {
                continue;
            };
            let mut index = 0u64;
            let mut has_unit = false;
            let mut has_flag = false;
            for (at, delta) in inputs.iter().enumerate() {
                let Some(delta) = delta.as_u64() else {
                    break;
                };
                index = if at == 0 { delta } else { index + delta };
                let Some(entry) = table.get(index as usize) else {
                    break;
                };
                let id = entry["id"].as_str().unwrap_or_default();
                let Some(hash) = id.strip_prefix("f:").or_else(|| id.strip_prefix("x:")) else {
                    continue;
                };
                let path = entry["path"].as_str().unwrap_or_default();
                has_unit |= path == unit && hash == unit_hash;
                has_flag |= path == flag && hash == flag_hash;
            }
            if has_unit && has_flag {
                return true;
            }
        }
    }
    false
}

#[test]
fn e3_stored_content_requires_a_content_line_and_matching_proof() {
    let s = Suite::new();
    let flag = "tests/z.flag";
    let units = vec!["tests/a.t".to_owned()];
    let content = "ok\n";
    s.write(flag, content);
    let stat_body = format!("stat:{flag}\n");
    s.write("tests/a.t", &stat_body);
    let mut stored = serde_json::json!({
        "table": [
            {"path": "tests/a.t", "id": format!("f:{}", blake3::hash(stat_body.as_bytes()))},
            {"path": flag, "id": format!("f:{}", blake3::hash(content.as_bytes()))}
        ],
        "units": {"tests/a.t": [{"inputs": [0, 1]}]}
    });
    assert!(!e3_stored_content_flag(&stored, &s, &units, flag, content));
    let read_body = format!("{flag}\n");
    s.write("tests/a.t", &read_body);
    stored["table"][0]["id"] = Value::String(format!("f:{}", blake3::hash(read_body.as_bytes())));
    assert!(e3_stored_content_flag(&stored, &s, &units, flag, content));
    assert!(!e3_stored_content_flag(&stored, &s, &[], flag, content));
    s.write("tests/b.t", &read_body);
    assert!(!e3_stored_content_flag(
        &stored,
        &s,
        &["tests/b.t".to_owned()],
        flag,
        content
    ));
    assert!(!e3_stored_content_flag(
        &stored,
        &s,
        &units,
        flag,
        "different\n"
    ));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum E3Gap {
    W22,
    E5,
}

#[derive(Clone, Copy, Default)]
struct E3GapEvidence {
    runner_only: bool,
    appeared_now: bool,
    flag_flipped: bool,
    stored_content: bool,
    launched_stored_content: bool,
    current_content: bool,
    appeared_test_content: bool,
}

fn e3_gap(evidence: E3GapEvidence) -> Option<E3Gap> {
    if !evidence.runner_only || !evidence.current_content {
        return None;
    }
    if evidence.appeared_now {
        evidence.appeared_test_content.then_some(E3Gap::E5)
    } else if evidence.flag_flipped && evidence.stored_content && evidence.launched_stored_content {
        Some(E3Gap::W22)
    } else {
        None
    }
}

#[test]
fn e3_gap_accepts_only_the_two_owner_approved_shapes() {
    let w22 = E3GapEvidence {
        runner_only: true,
        flag_flipped: true,
        stored_content: true,
        launched_stored_content: true,
        current_content: true,
        ..E3GapEvidence::default()
    };
    let e5 = E3GapEvidence {
        runner_only: true,
        appeared_now: true,
        current_content: true,
        appeared_test_content: true,
        ..E3GapEvidence::default()
    };
    assert_eq!(e3_gap(w22), Some(E3Gap::W22));
    assert_eq!(e3_gap(e5), Some(E3Gap::E5));
    for rejected in [
        E3GapEvidence {
            runner_only: false,
            ..w22
        },
        E3GapEvidence {
            current_content: false,
            ..w22
        },
        E3GapEvidence {
            flag_flipped: false,
            ..w22
        },
        E3GapEvidence {
            stored_content: false,
            ..w22
        },
        E3GapEvidence {
            launched_stored_content: false,
            ..w22
        },
        E3GapEvidence {
            runner_only: false,
            ..e5
        },
        E3GapEvidence {
            current_content: false,
            ..e5
        },
        E3GapEvidence {
            appeared_test_content: false,
            ..e5
        },
        E3GapEvidence {
            appeared_now: false,
            ..e5
        },
    ] {
        assert_eq!(e3_gap(rejected), None);
    }
}

struct E3Diverged {
    origin: usize,
    failing: std::collections::BTreeSet<String>,
    changed: std::collections::BTreeSet<String>,
    shapes: Vec<E3Gap>,
}

fn e3_changes_runner(step: &Step, test: &str) -> bool {
    match step {
        Step::Flag(path, _)
        | Step::Runner(path)
        | Step::RunnerDelete(path)
        | Step::RemoveAndDrop(path)
        | Step::PublishStaged(path) => path == test,
        _ => false,
    }
}

fn e3_changes_full_policy(step: &Step) -> bool {
    matches!(step, Step::ListedDirectory(_))
}

fn e3_empty_policy_directory(s: &Suite) -> bool {
    let path = s.path("policy-r6/zone");
    fs::symlink_metadata(&path).is_ok_and(|meta| meta.file_type().is_dir())
        && fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

fn e3_same_empty_policy_recreation(s: &Suite, before_empty: bool, ops: &[Step]) -> bool {
    before_empty && matches!(ops, [Step::ListedDirectory(1)]) && e3_empty_policy_directory(s)
}

fn e3_policy_changed(s: &Suite, before_empty: bool, ops: &[Step]) -> bool {
    ops.iter().any(e3_changes_full_policy) && !e3_same_empty_policy_recreation(s, before_empty, ops)
}

fn e3_sticky(
    divergence: &E3Diverged,
    failed: &[String],
    policy_failures: &[String],
    runners: &[String],
    units: &[String],
    launches: &[String],
) -> bool {
    !failed.is_empty()
        && failed.len() == divergence.failing.len()
        && divergence.changed.is_empty()
        && policy_failures.is_empty()
        && !launches.iter().any(String::is_empty)
        && failed.iter().all(|test| {
            divergence.failing.contains(test)
                && runners.contains(test)
                && !units.contains(test)
                && !launches.contains(test)
        })
}

#[test]
fn e3_sticky_retry_requires_the_original_unchanged_runner_only_failures() {
    let test = "tests/m0.u".to_owned();
    let mut divergence = E3Diverged {
        origin: 8,
        failing: [test.clone()].into_iter().collect(),
        changed: Default::default(),
        shapes: vec![E3Gap::W22],
    };
    let failed = vec![test.clone()];
    let runners = vec![test.clone()];
    assert!(e3_sticky(&divergence, &failed, &[], &runners, &[], &[]));
    divergence.failing.insert("tests/m1.u".to_owned());
    assert!(!e3_sticky(&divergence, &failed, &[], &runners, &[], &[]));
    divergence.failing.remove("tests/m1.u");
    assert!(!e3_sticky(&divergence, &[], &[], &runners, &[], &[]));
    assert!(!e3_sticky(
        &divergence,
        &["tests/new.u".to_owned()],
        &[],
        &runners,
        &[],
        &[]
    ));
    assert!(!e3_sticky(
        &divergence,
        &failed,
        &["policy-r6/zone".to_owned()],
        &runners,
        &[],
        &[]
    ));
    assert!(!e3_sticky(
        &divergence,
        &failed,
        &[],
        &runners,
        &failed,
        &[]
    ));
    assert!(!e3_sticky(
        &divergence,
        &failed,
        &[],
        &runners,
        &[],
        &failed
    ));
    assert!(!e3_sticky(
        &divergence,
        &failed,
        &[],
        &runners,
        &[],
        &[String::new()]
    ));
    assert!(e3_changes_runner(&Step::Flag(test.clone(), "fail"), &test));
    assert!(e3_changes_runner(&Step::RunnerDelete(test.clone()), &test));
    assert!(!e3_changes_runner(&Step::Source(0), &test));
    divergence.changed.insert("tests/m1.u".to_owned());
    assert!(!e3_sticky(&divergence, &failed, &[], &runners, &[], &[]));
    divergence.changed.clear();
    divergence.changed.insert(test);
    assert!(!e3_sticky(&divergence, &failed, &[], &runners, &[], &[]));
}

#[derive(Default)]
struct E3Tally {
    steps: usize,
    gap_current: usize,
    gap_w22: usize,
    gap_e5: usize,
    gap_sticky: usize,
    gap_stored: usize,
    no_verdict: usize,
    no_verdict_failing: usize,
    no_verdict_no_reader: usize,
}

/// E3 accepts only w22 and E5, plus retries of the same unchanged runner-only failures. Each category is bounded to a
/// third of a sequence, as are the designed no-verdicts.
fn run_e3(seed: u64, steps: usize, tally: &mut E3Tally) -> Result<(), String> {
    run_e3_with_directory_recreation(seed, steps, tally, None)
}

fn run_e3_with_directory_recreation(
    seed: u64,
    steps: usize,
    tally: &mut E3Tally,
    recreate_step: Option<usize>,
) -> Result<(), String> {
    let s = Suite::new();
    let mut rng = Rng::new(seed);
    for unit in ["tests/a.t", "tests/b.t", "tests/c.t"] {
        s.remove(unit);
    }
    s.remove("e2e/x.u");
    for n in 0..4 {
        s.write(&format!("src/s{n}"), "source\n");
    }
    let mut world = World {
        units: Vec::new(),
        runners: Vec::new(),
        deleted: Vec::new(),
        staged: Vec::new(),
        next: 0,
        revision: 0,
        foo: 0,
        forced: false,
    };
    for _ in 0..2 {
        let runner = world.fresh("u");
        let body = World::sources(&mut rng);
        s.write(&runner, &body);
        s.write(&flag_of(&runner), "ok\n");
        world.runners.push(runner);
    }
    for _ in 0..5 {
        let unit = world.fresh("t");
        world.units.push(unit);
    }
    world.units.sort();
    for unit in world.units.clone() {
        let body = world.listing(&mut rng, &unit);
        s.write(&unit, &body);
    }
    listed_policy_setup(&s);
    s.executable("t", &listed_policy_runner(&e3_runner()));
    let cold = split(&s, &[("T_U", "1"), ("FOO", "0")]);
    if code(&cold) != 0 {
        return Err(format!(
            "seed {seed}: the cold run failed: {}",
            stderr(&cold)
        ));
    }
    let mut log: Vec<String> = Vec::new();
    let mut no_verdicts = 0usize;
    let mut failing_refusals = 0usize;
    let mut no_reader_refusals = 0usize;
    let mut whole_inputs = ModelWholeInputs::default();
    whole_inputs.record(&s, &world.units, &world.runners);
    let mut divergence: Option<E3Diverged> = None;
    let mut gap_fires = 0usize;
    let mut sticky_retries = 0usize;
    // An unchanged retry after a 125 (PR 86 review round 3): half the time, the step after a 125 applies nothing.
    let mut last_125 = false;
    for step in 1..=steps {
        let before = e3_listings(&s, &world.units);
        let empty_policy_before = divergence.is_some() && e3_empty_policy_directory(&s);
        let before_flags: std::collections::BTreeMap<String, Option<String>> = world
            .runners
            .iter()
            .map(|runner| {
                (
                    runner.clone(),
                    fs::read_to_string(s.path(&flag_of(runner))).ok(),
                )
            })
            .collect();
        let forced_noop = last_125 && rng.below(2) == 0;
        let recreate_empty = recreate_step == Some(step);
        if recreate_empty {
            assert!(
                empty_policy_before,
                "the retry must start with an empty directory"
            );
        }
        let count = if forced_noop || recreate_empty {
            1
        } else {
            1 + rng.below(3)
        };
        let mut ops = Vec::new();
        world.forced = false;
        for _ in 0..count {
            let op = if recreate_empty {
                Step::ListedDirectory(1)
            } else if forced_noop {
                Step::Noop
            } else {
                world.pick(&mut rng)
            };
            world.apply(&s, &mut rng, &op);
            ops.push(op);
        }
        log.push(format!("step {step}: {ops:?}"));
        let foo_value = world.foo.to_string();
        let env: Vec<(&str, &str)> = vec![("T_U", "1"), ("FOO", foo_value.as_str())];
        let mut subject_env = env.clone();
        if world.forced {
            subject_env.push(("STOOP_FULL", "1"));
        }
        let stored = s.bundle().unwrap_or(Value::Null);
        s.clear_log();
        let subject = split(&s, &subject_env);
        let launches = launched(&s);
        s.clear_log();
        let oracle = s.direct(&s.root, &[], &env);
        let failed = oracle_failed_tests(&s);
        let policy_failures = oracle_policy_failures(&s);
        s.clear_log();
        tally.steps += 1;
        let report = |why: &str| {
            let files: Vec<String> = world
                .units
                .iter()
                .chain(&world.runners)
                .map(|test| {
                    format!(
                        "{test} = {:?}, flag {:?}",
                        fs::read_to_string(s.path(test)).unwrap_or_default(),
                        fs::read_to_string(s.path(&flag_of(test))).ok()
                    )
                })
                .collect();
            format!(
                "{why}\nseed {seed}, step {step}\noperations:\n  {}\nfiles now:\n  {}\nsubject exit {}, oracle exit {}, oracle failed {failed:?}, policy failures {policy_failures:?}, launches {launches:?}\nsubject stderr:\n{}",
                log.join("\n  "),
                files.join("\n  "),
                code(&subject),
                code(&oracle),
                stderr(&subject)
            )
        };
        let subject_code = code(&subject);
        let after = e3_listings(&s, &world.units);
        if subject_code == 0 && launches.iter().any(String::is_empty) {
            whole_inputs.record(&s, &world.units, &world.runners);
        }
        let noop = ops.iter().all(|op| matches!(op, Step::Noop));
        if false_pass_after_125(last_125, noop, subject_code, code(&oracle)) {
            return Err(report(
                "WRONG VERDICT: an unchanged retry after exit 125 passed",
            ));
        }
        let changed_full_policy =
            divergence.is_some() && e3_policy_changed(&s, empty_policy_before, &ops);
        if changed_full_policy && subject_code == 0 && !launches.iter().any(String::is_empty) {
            return Err(report(
                "WRONG VERDICT: a full-run policy change requires a fresh full run after a gap",
            ));
        }
        if subject_code != 0
            || code(&oracle) == 0
            || launches.iter().any(String::is_empty)
            || changed_full_policy
        {
            divergence = None;
        } else if let Some(previous) = &mut divergence {
            for test in &previous.failing {
                if ops.iter().any(|op| e3_changes_runner(op, test)) {
                    previous.changed.insert(test.clone());
                }
            }
        }
        last_125 = subject_code == 125;
        if subject_code == 2 {
            return Err(report("a status of 2"));
        }
        if let Some(bad) = launches
            .iter()
            .find(|launch| !launch.is_empty() && !world.units.contains(launch))
        {
            return Err(report(&format!("a launch named {bad}, not a roster unit")));
        }
        if subject_code == 125 {
            let Some(path) = no_verdict_changed(&subject) else {
                return Err(report("a status of 125 without the no-verdict line"));
            };
            let stopped = world.units.iter().any(|unit| {
                launches.contains(unit)
                    && before
                        .get(unit)
                        .zip(after.get(unit))
                        .is_some_and(|(old, new)| content_read_dropped(old, new, &path))
            });
            let failing_oracle =
                code(&oracle) != 0 && failing_runner_depends_on(&failed, &world.runners, &path);
            let no_reader = code(&oracle) == 0 && no_content_reader(&s, &after, &path);
            if failing_oracle {
                failing_refusals += 1;
                tally.no_verdict_failing += 1;
                if failing_refusals * 3 > steps {
                    return Err(report("too many refusals on a failing oracle"));
                }
                println!(
                    "REFUSAL ON FAILING ORACLE (E3): seed {seed}, step {step}, {path}, failed {failed:?}"
                );
            } else if no_reader && stopped {
                println!("NO VERDICT ACCEPTED (E3): seed {seed}, step {step}, {path}");
            } else if no_reader && whole_inputs.contains(&s, &path) {
                no_reader_refusals += 1;
                tally.no_verdict_no_reader += 1;
                if no_reader_refusals * 3 > steps {
                    return Err(report("too many no-content-reader refusals"));
                }
                println!("NO CONTENT READER REFUSAL (E3): seed {seed}, step {step}, {path}");
            } else {
                return Err(report(&format!("unaccepted 125 for {path}")));
            }
            no_verdicts += 1;
            tally.no_verdict += 1;
            if no_verdicts * 3 > steps {
                return Err(report("too many no-verdicts in one sequence"));
            }
            continue;
        }
        if (subject_code == 0) == (code(&oracle) == 0) {
            continue;
        }
        if subject_code != 0 {
            return Err(report(
                "WRONG VERDICT: the subject failed and the runner passed",
            ));
        }
        if !policy_failures.is_empty() {
            return Err(report(
                "WRONG VERDICT: the full runner has an independent policy failure",
            ));
        }
        if let Some(previous) = divergence.as_ref().filter(|previous| {
            e3_sticky(
                previous,
                &failed,
                &policy_failures,
                &world.runners,
                &world.units,
                &launches,
            )
        }) {
            sticky_retries += 1;
            if sticky_retries * 3 > steps {
                return Err(report(
                    "too many sticky covered-file retries in one sequence",
                ));
            }
            tally.gap_sticky += 1;
            println!(
                "E3 sticky gap: seed {seed}, step {step}, origin {}, shapes {:?}, failed {failed:?}",
                previous.origin, previous.shapes
            );
            continue;
        }
        if failed.iter().any(|test| {
            world.units.contains(test)
                && fs::read_to_string(s.path(test))
                    .is_ok_and(|body| body.lines().any(|line| line == "fail"))
        }) {
            return Err(report(
                "WRONG VERDICT: a unit with a failing own file passed",
            ));
        }
        let listed_now = |flag: &str| {
            world.units.iter().any(|unit| {
                fs::read_to_string(s.path(unit))
                    .map(|body| {
                        body.lines().any(|line| {
                            line == flag || line.strip_prefix("unit-only:") == Some(flag)
                        })
                    })
                    .unwrap_or(false)
            })
        };
        let reads = stored_reads(&stored, &world.units);
        let current = !failed.is_empty() && failed.iter().all(|test| listed_now(&flag_of(test)));
        let stored_gap = !failed.is_empty()
            && failed.iter().all(|test| {
                let flag = flag_of(test);
                listed_now(&flag) || reads.contains(&flag)
            });
        if current {
            let mut kinds = Vec::new();
            for test in &failed {
                let flag = flag_of(test);
                let previous_flag = before_flags.get(test).and_then(|value| value.as_deref());
                let appeared_now = !before_flags.contains_key(test)
                    && ops.iter().any(|op| match op {
                        Step::Runner(path) | Step::PublishStaged(path) => path == test,
                        _ => false,
                    });
                let flag_flipped = ops
                    .iter()
                    .any(|op| matches!(op, Step::Flag(path, _) if path == test))
                    && previous_flag.is_some_and(|value| !value.contains("fail"))
                    && fs::read_to_string(s.path(test))
                        .is_ok_and(|body| !body.lines().any(|line| line == "fail"))
                    && match fs::read_to_string(s.path(&flag)) {
                        Ok(value) => value.contains("fail"),
                        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                    };
                let evidence = E3GapEvidence {
                    runner_only: world.runners.contains(test)
                        && !world.units.contains(test)
                        && !launches.contains(test)
                        && !launches.iter().any(String::is_empty),
                    appeared_now,
                    flag_flipped,
                    stored_content: previous_flag.is_some_and(|value| {
                        e3_stored_content_flag(&stored, &s, &world.units, &flag, value)
                    }),
                    launched_stored_content: previous_flag.is_some_and(|value| {
                        e3_stored_content_flag(&stored, &s, &launches, &flag, value)
                    }),
                    current_content: listed_now(&flag),
                    appeared_test_content: e3_launched_content_path(&after, &launches, test),
                };
                let Some(kind) = e3_gap(evidence) else {
                    return Err(report(
                        "WRONG VERDICT: the covered-file mismatch is outside w22 and E5",
                    ));
                };
                kinds.push(kind);
            }
            gap_fires += 1;
            if gap_fires * 3 > steps {
                return Err(report("too many covered-file exemptions in one sequence"));
            }
            tally.gap_current += 1;
            tally.gap_w22 += usize::from(kinds.contains(&E3Gap::W22));
            tally.gap_e5 += usize::from(kinds.contains(&E3Gap::E5));
            println!("E3 covered-file gap: seed {seed}, step {step}, shapes {kinds:?}");
            divergence = Some(E3Diverged {
                origin: step,
                failing: failed.iter().cloned().collect(),
                changed: Default::default(),
                shapes: kinds,
            });
            continue;
        }
        if stored_gap {
            tally.gap_stored += 1;
            return Err(report(
                "WRONG VERDICT beyond the current reading: only a roster unit's stored version read the flag",
            ));
        }
        return Err(report(
            "WRONG VERDICT beyond the covered-file gap: no roster unit reads the failed test's flag",
        ));
    }
    Ok(())
}

/// E3. Seeds from `STOOP_R2_FIRST` (1) for `STOOP_R2_SEEDS` (4), steps from `STOOP_R2_STEPS` (30). Every failing seed
/// is reported in full with operations and stderr.
#[test]
fn r2_e3_flag_readers_model() {
    let first = count_from_env("STOOP_R2_FIRST", 1) as u64;
    let seeds = count_from_env("STOOP_R2_SEEDS", 4) as u64;
    let steps = count_from_env("STOOP_R2_STEPS", 30);
    let mut tally = E3Tally::default();
    let mut failures = Vec::new();
    for seed in first..first + seeds {
        if let Err(why) = run_e3(seed, steps, &mut tally) {
            println!("E3 FAILING SEED {seed}:\n{why}");
            failures.push(why);
        }
    }
    println!(
        "E3 sweep: seeds {first}..{}: {} steps, {} covered-file gap steps (w22={}, E5={}), {} sticky retries, {} steps beyond the current reading, {} accepted no-verdicts ({} on failing oracle, {} with no content reader), {} failing seeds",
        first + seeds - 1,
        tally.steps,
        tally.gap_current,
        tally.gap_w22,
        tally.gap_e5,
        tally.gap_sticky,
        tally.gap_stored,
        tally.no_verdict,
        tally.no_verdict_failing,
        tally.no_verdict_no_reader,
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} failing seeds; first:\n{}",
        failures.len(),
        failures.first().cloned().unwrap_or_default()
    );
}

#[test]
fn e3_reported_seeds_match_the_owner_approved_shapes() {
    let mut appeared = E3Tally::default();
    if let Err(why) = run_e3(14039, 5, &mut appeared) {
        panic!("{why}");
    }
    assert_eq!((appeared.gap_e5, appeared.gap_w22), (1, 0));

    let mut changed_flag = E3Tally::default();
    if let Err(why) = run_e3(10037, 9, &mut changed_flag) {
        panic!("{why}");
    }
    assert_eq!((changed_flag.gap_e5, changed_flag.gap_w22), (0, 1));
    assert_eq!(changed_flag.gap_sticky, 1);
}

#[test]
fn r9_identical_recreated_listing_preserves_the_sticky_retry() {
    let mut tally = E3Tally::default();
    if let Err(why) = run_e3_with_directory_recreation(10037, 9, &mut tally, Some(9)) {
        panic!("{why}");
    }
    assert_eq!((tally.gap_w22, tally.gap_sticky), (1, 1));
}

#[test]
fn r9_sticky_listing_requires_the_same_empty_directory() {
    let s = Suite::new();
    listed_policy_setup(&s);
    let ops = [Step::ListedDirectory(1)];
    assert!(e3_empty_policy_directory(&s));
    listed_policy_replace(&s, 1);
    assert!(!e3_policy_changed(&s, true, &ops));
    assert!(
        e3_policy_changed(&s, false, &ops),
        "a directory that appeared cannot be an identical recreation"
    );
    s.write("policy-r6/zone/extra", "different listing\n");
    assert!(
        e3_policy_changed(&s, true, &ops),
        "a changed listing cannot retain the sticky exemption"
    );
    s.remove("policy-r6/zone/extra");
    listed_policy_replace(&s, 3);
    assert!(
        e3_policy_changed(&s, true, &ops),
        "a symlink cannot be an identical directory recreation"
    );
    assert!(e3_policy_changed(&s, true, &[Step::ListedDirectory(3)]));
    listed_policy_replace(&s, 1);
    assert!(e3_policy_changed(
        &s,
        true,
        &[Step::ListedDirectory(1), Step::Noop]
    ));
}

#[test]
fn e3_refusal_requires_an_exact_line_and_a_failing_runner_dependency() {
    use std::os::unix::process::ExitStatusExt;
    let output = |message: &str| Output {
        status: std::process::ExitStatus::from_raw(125 << 8),
        stdout: Vec::new(),
        stderr: message.as_bytes().to_vec(),
    };
    let exact = "stoop: this run has no verdict (exit 125): tests/m10.flag changed, and no unit's new proof reads it";
    assert_eq!(
        no_verdict_changed(&output(exact)).as_deref(),
        Some("tests/m10.flag")
    );
    for bad in [
        "stoop: this run has no verdict (exit 125)",
        "stoop: this run has no verdict (exit 125): tests/m10.flag appeared, and no unit's new proof reads it",
        "stoop: this run has no verdict (exit 125): tests/m10.flag changed, and no unit's new proof reads it extra",
    ] {
        assert_eq!(no_verdict_changed(&output(bad)), None);
    }
    let failed = vec!["tests/m10.u".to_owned()];
    let runners = vec!["tests/m10.u".to_owned()];
    assert!(failing_runner_depends_on(
        &failed,
        &runners,
        "tests/m10.flag"
    ));
    assert!(failing_runner_depends_on(&failed, &runners, "tests/m10.u"));
    assert!(!failing_runner_depends_on(
        &failed,
        &runners,
        "tests/other.flag"
    ));
    assert!(!failing_runner_depends_on(&failed, &[], "tests/m10.flag"));
    assert!(false_pass_after_125(true, true, 0, 1));
    assert!(!false_pass_after_125(true, true, 1, 1));
    assert!(!false_pass_after_125(true, false, 0, 1));
}

#[test]
fn e3_seed_10077_refuses_a_failing_runner_without_claiming_a_pass() {
    let mut tally = E3Tally::default();
    if let Err(why) = run_e3(10077, 15, &mut tally) {
        panic!("{why}");
    }
    assert_eq!(tally.no_verdict_failing, 1);
}

// Independent delta-review probes. The runner is a disposable fixture in each test.
fn r3_spec_runner(s: &Suite, body: &str) {
    s.executable("t", body);
    learned(s, &TU);
    assert_eq!(known(s), Some(0), "{}", residue(s));
}

#[test]
fn r3_retry_after_a_stat_only_no_verdict_cannot_be_a_skip() {
    let s = zsuite();
    let fixture = include_str!("fixtures/hook/t");
    let old = "cat \"$ROOT/$line\"";
    assert_eq!(fixture.matches(old).count(), 1);
    let body = fixture.replace(old, "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac");
    r3_spec_runner(&s, &body);
    s.write("tests/c.t", "src/c.src\ntests/z.u\nstat:tests/z.flag\n");
    s.write("tests/z.flag", "fail\n");
    let (_, first, launches, oracle) = judge("r3-stat-first", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(launches, ["tests/c.t"]);
    no_verdict_names(&first, "tests/z.flag");
    let facts = bundle(&s);
    eprintln!(
        "r3-stat new inputs for c: {:?}",
        stored_reads(&facts, &["tests/c.t".to_owned()])
    );
    for input in facts["table"].as_array().unwrap() {
        if input["path"] == "tests/z.flag" {
            eprintln!("r3-stat stored identity: {input}");
        }
    }
    let (_, retry, _, oracle) = judge("r3-stat-retry", &s, &TU, true);
    same_verdict("r3-stat-retry", &retry, oracle);
}

#[test]
fn r3_retry_after_an_actual_lost_read_cannot_be_a_skip() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    s.write("tests/z.flag", "fail\n");
    let (_, first, launches, oracle) = judge("r3-drop-first", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(launches, ["tests/c.t"]);
    no_verdict_names(&first, "tests/z.flag");
    assert_eq!(known(&s), None, "{}", residue(&s));
    let (_, retry, launches, oracle) = judge("r3-drop-retry", &s, &TU, true);
    same_verdict("r3-drop-retry", &retry, oracle);
    assert_eq!(launches, [""]);
}

#[test]
fn r3_removing_the_file_and_its_last_reader_cannot_pass() {
    let s = zsuite();
    let fixture = include_str!("fixtures/hook/t");
    let anchor = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
    assert_eq!(fixture.matches(anchor).count(), 1);
    let body = fixture.replace(anchor, "if { [ \"$1\" = tests/z.u ] && [ ! -f \"$flag\" ]; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then");
    r3_spec_runner(&s, &body);
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    s.remove("tests/z.flag");
    let (_, run, _, oracle) = judge("r3-file-removal", &s, &TU, true);
    assert_eq!(oracle, 1);
    same_verdict("r3-file-removal", &run, oracle);
}

#[test]
fn r3_off_record_then_on_checks_the_dropped_content() {
    let s = zlearned();
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "setup changed\n");
    s.clear_log();
    success(&s.hook(&TU));
    assert_eq!(launched(&s), [""]);
    assert_eq!(residue(&s)["state"], "provisional");
    assert_eq!(known(&s), Some(0));
    s.write("tests/z.flag", "fail\n");
    let (_, run, launches, oracle) = judge("r3-off-on-stale", &s, &TU, true);
    assert_eq!(oracle, 1);
    same_verdict("r3-off-on-stale", &run, oracle);
    // A switch-off record stores no roster (PR 86 review round 5), so this first switch-on decision is the full form. The
    // full form runs the runner's check of the flag, where a subset would stop at a 125.
    assert_eq!(launches, [""], "{}", stderr(&run));
    let (_, retry, launches, oracle) = judge("r3-off-on-retry", &s, &TU, true);
    same_verdict("r3-off-on-retry", &retry, oracle);
    assert_eq!(launches, [""]);
}

#[test]
fn r3_switch_on_after_off_full_with_no_unit_proofs() {
    let s = zsuite();
    success(&s.hook(&TU));
    assert!(bundle(&s)["units"].as_object().unwrap().is_empty());
    s.write("tests/z.flag", "fail\n");
    let (_, run, launches, oracle) = judge("r3-off-on-e9", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 1);
    assert_eq!(launches, [""]);
    s.write("tests/z.flag", "ok\n");
    s.write("setup.src", "setup changed\n");
    let (_, learned, launches, oracle) = judge("r3-off-on-learn", &s, &TU, true);
    same_verdict("r3-off-on-learn", &learned, oracle);
    assert_eq!(launches, ["", "tests/a.t", "tests/b.t", "tests/c.t"]);
    assert_eq!(residue(&s)["state"], "confirmed");
}

#[test]
fn r3_completion_blocked_by_ci_lock_or_read_only_store_fails_safe() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    for mode in ["ci", "busy", "read-only"] {
        let s = zlearned();
        let path = s.bundle_path().unwrap();
        let parent = path.parent().unwrap();
        let before = s.bundle_bytes();
        s.write("tests/c.t", "src/c.src\n");
        s.write("setup.src", "setup changed\n");
        let lock = (mode == "busy").then(|| {
            let lock = File::open(path.with_extension("lock")).unwrap();
            assert_eq!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            lock
        });
        let env = if mode == "ci" {
            with(&TU, &[("CI", "1")])
        } else {
            TU.to_vec()
        };
        if mode == "read-only" {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o555)).unwrap();
        }
        s.clear_log();
        let first = split(&s, &env);
        if mode == "read-only" {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
        }
        drop(lock);
        success(&first);
        assert_eq!(launched(&s), [""], "{mode}: {}", stderr(&first));
        assert!(
            stderr(&first).contains("stoop: recorded "),
            "{mode}: {}",
            stderr(&first)
        );
        assert!(
            !stderr(&first).contains("busy"),
            "{mode}: {}",
            stderr(&first)
        );
        if mode == "ci" {
            assert_eq!(known(&s), None, "{mode}: {}", residue(&s));
        } else {
            assert_eq!(s.bundle_bytes(), before, "{mode}: suite bundle changed");
        }
        s.write("tests/z.flag", "fail\n");
        let (_, retry, launches, oracle) = judge(mode, &s, &env, true);
        assert_eq!(oracle, 1, "{mode}");
        assert_eq!(code(&retry), 1, "{mode}: {}", stderr(&retry));
        assert_eq!(launches, [""], "{mode}: {}", stderr(&retry));
    }
}

#[test]
fn r3_killed_completion_leaves_the_new_whole_proof_unmatched() {
    let s = zlearned();
    let whole = bundle(&s)["whole"].clone();
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "setup changed\n");
    let fifo = s.fifo();
    let env = with(
        &TU,
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/c.t"),
        ],
    );
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    command.env(SPLIT.0, SPLIT.1).envs(env.iter().copied());
    command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = spawning(|| command.spawn()).unwrap();
    release(meet(&fifo)); // full form
    let writer = meet(&fifo); // c in completion, after the whole proof is saved
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    drop(writer);
    assert_ne!(bundle(&s)["whole"], whole);
    assert_eq!(known(&s), None, "{}", residue(&s));
    assert!(
        stored_reads(&bundle(&s), &["tests/c.t".to_owned()]).contains(&"tests/z.flag".to_owned())
    );
    s.write("tests/z.flag", "fail\n");
    let (_, retry, launches, oracle) = judge("r3-sigkill", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&retry), 1, "{}", stderr(&retry));
    assert_eq!(launches, [""]);
}

fn r3_control_run(s: &Suite, binary: &Path) -> Output {
    let mut command = std::process::Command::new(binary);
    command
        .current_dir(&s.root)
        .stdin(std::process::Stdio::null())
        .env_clear();
    command
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &s.outside)
        .env("LOG", &s.log);
    command
        .env("STOOP_LEARN_VOLATILE", "0")
        .env(SPLIT.0, SPLIT.1)
        .envs(TU);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    s.clear_log();
    spawning(|| command.output()).unwrap()
}

/// The same warmed state on each binary. Start with a measured, non-empty residue. A later passing full run is
/// what learns the newly added cross-read on the PR, while the merge base still has the non-empty residue.
fn r3_control_case(binary: &Path, replace_with_stat: bool) -> ((i32, i32), (i32, i32)) {
    let s = zsuite();
    let fixture = include_str!("fixtures/hook/t");
    let stat_anchor = "cat \"$ROOT/$line\"";
    let missing_anchor = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
    assert_eq!(fixture.matches(stat_anchor).count(), 1);
    assert_eq!(fixture.matches(missing_anchor).count(), 1);
    let fixture = fixture
        .replace(stat_anchor, "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac")
        .replace(missing_anchor, "if { [ \"$1\" = tests/z.u ] && [ ! -f \"$flag\" ]; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then");
    s.executable("t", &fixture);
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    success(&r3_control_run(&s, binary));
    edit(&s, 2);
    let warm = r3_control_run(&s, binary);
    success(&warm);
    assert!(known(&s).is_some_and(|count| count > 0), "{}", residue(&s));
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    s.write("setup.src", "force a changed full command\n");
    let full = r3_control_run(&s, binary);
    success(&full);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    eprintln!("R3 CONTROL after full: binary={binary:?} stat={replace_with_stat} launches={:?} residue={}", launched(&s), residue(&s));
    if replace_with_stat {
        s.write("tests/c.t", "src/c.src\ntests/z.u\nstat:tests/z.flag\n");
        s.write("tests/z.flag", "fail\n");
    } else {
        s.write("tests/c.t", "src/c.src\ntests/z.u\n");
        s.remove("tests/z.flag");
    }
    let mut results = [(0, 0); 2];
    for (attempt, result) in results.iter_mut().enumerate() {
        let run = r3_control_run(&s, binary);
        let launches = launched(&s);
        let oracle = direct(&s, &TU);
        assert_eq!(oracle, 1);
        if code(&run) == 125 {
            no_verdict_names(&run, "tests/z.flag");
        }
        *result = (code(&run), oracle);
        eprintln!("R3 CONTROL verdict: binary={binary:?} stat={replace_with_stat} try={attempt} exit={} direct={oracle} launches={launches:?} residue={}\n{}", code(&run), residue(&s), stderr(&run));
    }
    (results[0], results[1])
}

#[test]
#[ignore = "requires STOOP_REVIEW_BASE_BIN"]
fn r3_merge_base_control_for_both_wrong_verdicts() {
    let base = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("set the merge-base binary");
    let base = Path::new(&base);
    let head = Path::new(env!("CARGO_BIN_EXE_stoop"));
    let mut wrong = Vec::new();
    for replace_with_stat in [false, true] {
        assert_eq!(r3_control_case(base, replace_with_stat), ((1, 1), (1, 1)));
        let result = r3_control_case(head, replace_with_stat);
        if result.0 .0 == 0 || result.1 .0 == 0 {
            wrong.push((replace_with_stat, result));
        }
    }
    assert!(
        wrong.is_empty(),
        "R3 REGRESSION: head false pass where the merge base fails correctly: {wrong:?}"
    );
}

/// PR 86 review round 3, the stat-only reader of a deleted flag. `c` keeps listing the flag, but only stats it, and the
/// runner-only test requires the flag to exist. Deleting the flag changes `c`'s input, so the subset launches `c`. Its
/// new proof stats the absence and reads no content, so nothing vouches for the flag: the run gives no verdict, and its
/// retry takes the full form. Neither may pass.
#[test]
fn r3_a_stat_only_reader_of_a_deleted_flag_cannot_pass() {
    let s = zsuite();
    let fixture = include_str!("fixtures/hook/t");
    let stat_anchor = "cat \"$ROOT/$line\"";
    let missing_anchor = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
    assert_eq!(fixture.matches(stat_anchor).count(), 1);
    assert_eq!(fixture.matches(missing_anchor).count(), 1);
    let body = fixture
        .replace(stat_anchor, "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac")
        .replace(missing_anchor, "if { [ \"$1\" = tests/z.u ] && [ ! -f \"$flag\" ]; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then");
    s.write("tests/c.t", "src/c.src\ntests/z.u\nstat:tests/z.flag\n");
    r3_spec_runner(&s, &body);
    s.remove("tests/z.flag");
    let (_, run, _, oracle) = judge("r3-stat-deleted", &s, &TU, true);
    assert_eq!(oracle, 1);
    same_verdict("r3-stat-deleted", &run, oracle);
    let (_, retry, _, oracle) = judge("r3-stat-deleted-retry", &s, &TU, true);
    same_verdict("r3-stat-deleted-retry", &retry, oracle);
}

// PR 86 review round 4 (W7-3). The reviewer's controls (probe 45542542956, adopted from 463b822a), adapted where the
// listing and whole-proof rules decide the case, and the derived holes of the same class. Their files and hold gates
// are local disposable fixtures.
fn r4_script(missing_fails: bool, held: bool) -> String {
    let mut body = include_str!("fixtures/hook/t").to_owned();
    let stat = "cat \"$ROOT/$line\"";
    assert_eq!(body.matches(stat).count(), 1);
    body = body.replace(stat, "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac");
    if missing_fails {
        let anchor = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
        assert_eq!(body.matches(anchor).count(), 1);
        body = body.replace(anchor, "if { [ \"$1\" = tests/z.u ] && [ ! -f \"$flag\" ]; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then");
    }
    if held {
        let anchor = "\thold \"$1\"\n";
        assert_eq!(body.matches(anchor).count(), 1);
        body = body.replace(
            anchor,
            "\tif [ \"$TESTS\" = 1 ] && [ -e \"${R4_HOLD_GATE:-}\" ]; then hold \"$1\"; fi\n",
        );
    }
    body
}

fn r4_version_id(stored: &Value, unit: &str, path: &str) -> String {
    let version = &stored["units"][unit][0];
    let mut index = 0;
    for step in version["inputs"].as_array().unwrap() {
        index += step.as_u64().unwrap() as usize;
        let input = &stored["table"][index];
        if input["path"] == path {
            return input["id"].as_str().unwrap().to_owned();
        }
    }
    panic!("the proof of {unit} has no {path}");
}

#[test]
fn r4_kill_after_the_stat_proof_is_durable_and_before_finish() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    let s = zsuite();
    s.executable("t", &r4_script(false, true));
    s.write("tests/a.t", "src/shared.src\ntests/z.u\ntests/z.flag\n");
    s.write("tests/c.t", "src/c.src\n");
    let fifo = s.fifo();
    let gate = s.outside.join("hold-trigger");
    // Keep every environment value equal across cold, warmed, interrupted, retry and oracle runs.
    let env = with(
        &TU,
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/b.t"),
            ("R4_HOLD_GATE", gate.to_str().unwrap()),
        ],
    );
    learned(&s, &env);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    let before = bundle(&s);
    s.write(
        "tests/a.t",
        "src/shared.src\ntests/z.u\nstat:tests/z.flag\n",
    );
    s.write("tests/b.t", "src/shared.src\n\n");
    s.write("tests/z.flag", "fail\n");
    fs::write(&gate, "hold").unwrap();
    s.clear_log();
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    command.env(SPLIT.0, SPLIT.1).envs(env.iter().copied());
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let mut child = spawning(|| command.spawn()).unwrap();
    let writer = meet(&fifo);
    let held_launches = launched(&s);
    let at_hold = bundle(&s);
    child.kill().unwrap();
    assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    drop(writer);
    fs::remove_file(&gate).unwrap();
    assert_eq!(
        held_launches,
        ["tests/a.t", "tests/b.t"],
        "the hold must be in the subset, not the full form or completion"
    );
    assert_eq!(
        at_hold["whole"], before["whole"],
        "the whole proof was replaced before the hold"
    );
    let old_flag = r4_version_id(&before, "tests/a.t", "tests/z.flag");
    let new_flag = r4_version_id(&at_hold, "tests/a.t", "tests/z.flag");
    assert!(
        new_flag.starts_with("f:") && new_flag != old_flag,
        "the stat-only version was not yet durable: old={old_flag}, new={new_flag}"
    );
    assert_ne!(
        r4_version_id(&at_hold, "tests/a.t", "tests/a.t"),
        r4_version_id(&before, "tests/a.t", "tests/a.t")
    );
    assert_eq!(
        r4_version_id(&at_hold, "tests/b.t", "tests/b.t"),
        r4_version_id(&before, "tests/b.t", "tests/b.t"),
        "the second launch was already recorded"
    );
    eprintln!(
        "R4 KILL AT DURABLE A: launches={held_launches:?} a.flag={new_flag} residue={}",
        at_hold["residue"]
    );
    let (_, retry, run, oracle) = judge("r4-kill-retry", &s, &env, true);
    assert_eq!(oracle, 1);
    assert_eq!(
        code(&retry),
        1,
        "R4 KILL WRONG VERDICT: exit={} direct={oracle} launches={run:?}\n{}",
        code(&retry),
        stderr(&retry)
    );
    assert_eq!(run, [""]);
    assert_eq!(at_hold["residue"]["state"], "none");
    let (_, retry, run, oracle) = judge("r4-kill-retry-again", &s, &env, true);
    assert_eq!(
        (code(&retry), oracle, run.as_slice()),
        (1, 1, [String::new()].as_slice())
    );
}

#[test]
fn r4_failed_due_write_still_carries_content_proof_to_the_next_write() {
    use std::process::Stdio;
    let s = zsuite();
    s.executable("t", &r4_script(false, true));
    s.write("tests/a.t", "src/shared.src\ntests/z.u\ntests/z.flag\n");
    s.write("tests/c.t", "src/c.src\n");
    let fifo = s.fifo();
    let gate = s.outside.join("hold-trigger");
    let env = with(
        &TU,
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("R4_HOLD_GATE", gate.to_str().unwrap()),
        ],
    );
    learned(&s, &env);
    assert_eq!(known(&s), Some(0));
    let path = s.bundle_path().unwrap();
    let backup = path.with_extension("probe-backup");
    let before = bundle(&s);
    let old_flag = r4_version_id(&before, "tests/a.t", "tests/z.flag");
    s.write("tests/z.flag", "still ok, different bytes\n");
    s.write("tests/b.t", "src/shared.src\n\n");
    fs::write(&gate, "hold").unwrap();
    s.clear_log();
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    command.env(SPLIT.0, SPLIT.1).envs(env.iter().copied());
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = spawning(|| command.spawn()).unwrap();
    let first = meet(&fifo);
    assert_eq!(launched(&s), ["tests/a.t"]);
    fs::rename(&path, &backup).unwrap();
    // A cannot rename an encoded bundle over this directory. The suite's scratch folder still works for B.
    fs::create_dir(&path).unwrap();
    release(first);
    let second = meet(&fifo);
    assert_eq!(launched(&s), ["tests/a.t", "tests/b.t"]);
    assert!(
        path.is_dir(),
        "unexpected successful bundle replace while A was recording"
    );
    fs::remove_dir(&path).unwrap();
    fs::rename(&backup, &path).unwrap();
    release(second);
    let run = finish(child);
    fs::remove_file(&gate).unwrap();
    let oracle = direct(&s, &env);
    let flag = r4_version_id(&bundle(&s), "tests/a.t", "tests/z.flag");
    assert_ne!(flag, old_flag, "B's write did not carry A's held proof");
    eprintln!(
        "R4 DUE WRITE: exit={} direct={oracle}, A flag updated at B's write\n{}",
        code(&run),
        stderr(&run)
    );
    assert_eq!(oracle, 0);
    assert_eq!(
        code(&run),
        0,
        "R4 DUE WRITE false no-verdict:\n{}",
        stderr(&run)
    );
    let (_, retry, _, oracle) = judge("r4-due-write-retry", &s, &env, true);
    assert_eq!((code(&retry), oracle), (0, 0));
}

/// The fixture runner with two more line forms. `abs:P` reads the absolute path P by content, and a `fail` line fails
/// the unit that lists it. The full form also runs `check`, a shell condition, before its tests, and fails when it holds.
/// That is a runner-only check of a path outside any unit (PR 86 review round 4, B11 and D2).
fn ow_script(check: &str) -> String {
    let mut body = include_str!("fixtures/hook/t").to_owned();
    let stat = "cat \"$ROOT/$line\"";
    assert_eq!(body.matches(stat).count(), 1);
    body = body.replace(
        stat,
        "case $line in\nabs:*) cat \"${line#abs:}\" ;;\nfail) note failed=$1; STATUS=1 ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
    );
    let anchor = "\tset -f\n";
    assert_eq!(body.matches(anchor).count(), 1);
    body = body.replace(
        anchor,
        &format!("\tif {check}; then\n\t\tnote runner-check\n\t\tSTATUS=1\n\tfi\n{anchor}"),
    );
    body
}

fn r4_new_names_case(binary: &Path, head: bool) {
    let s = zsuite();
    s.remove("tests/z.u");
    s.remove("tests/z.flag");
    s.write("tests/c.t", "src/c.src\n");
    let body = r4_script(false, false);
    let anchor = "case $line in\nstat:";
    assert_eq!(body.matches(anchor).count(), 1);
    let body = body.replace(anchor, "case $line in\nunit-only:*) if [ \"$TESTS\" = 1 ]; then cat \"$ROOT/${line#unit-only:}\"; fi ;;\nstat:");
    s.executable("t", &body);
    success(&r3_control_run(&s, binary));
    edit(&s, 2);
    success(&r3_control_run(&s, binary));
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s.write(
        "tests/c.t",
        "src/c.src\nunit-only:tests/z.u\nunit-only:tests/z.flag\n",
    );
    s.write("setup.src", "a changed global input\n");
    success(&r3_control_run(&s, binary));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    for proof in s.proofs() {
        assert!(!proof["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| matches!(input["path"].as_str(), Some("tests/z.u" | "tests/z.flag"))));
    }
    s.write(
        "tests/a.t",
        "src/shared.src\nstat:tests/z.u\nstat:tests/z.flag\n",
    );
    s.write("tests/c.t", "src/c.src\nunit-only:tests/z.u\n");
    s.write("tests/c.flag", "fail\n");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let first = r3_control_run(&s, binary);
    let run = launched(&s);
    eprintln!(
        "R4 APPEARED FIRST: head={head} exit={} launches={run:?} residue={}\n{}",
        code(&first),
        residue(&s),
        stderr(&first)
    );
    assert_eq!(code(&first), 1);
    if run != [""] {
        assert!(head, "the merge base should take the full form: {run:?}");
        assert_eq!(run, ["tests/a.t", "tests/c.t"]);
        assert_eq!(known(&s), None, "{}", residue(&s));
    }
    s.write("tests/c.flag", "ok\n");
    let mut verdicts = Vec::new();
    for attempt in 0..2 {
        let retry = r3_control_run(&s, binary);
        let run = launched(&s);
        let oracle = direct(&s, &TU);
        assert_eq!(oracle, 1);
        assert_eq!(
            code(&retry),
            1,
            "R4 APPEARED WRONG VERDICT on attempt {attempt}: {run:?}\n{}",
            stderr(&retry)
        );
        eprintln!("R4 APPEARED RETRY: head={head} attempt={attempt} exit={} direct={oracle} launches={run:?} residue={}\n{}", code(&retry), residue(&s), stderr(&retry));
        verdicts.push(code(&retry));
    }
    assert!(
        verdicts.iter().all(|&exit| exit != 0),
        "R4 APPEARED WRONG VERDICT: {verdicts:?} with direct 1 on both attempts"
    );
}

#[test]
#[ignore = "requires frozen merge-base binary"]
fn r4_a_failing_excuser_must_not_promote_another_units_stat() {
    let base = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("set the merge-base binary");
    r4_new_names_case(Path::new(&base), false);
    r4_new_names_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

/// Review round 4, R4a on the head binary alone, so ordinary CI catches a regression without the merge-base binary. A
/// failing unit's stale proof must not excuse the listing of an appeared runner-only test.
#[test]
fn r4_a_head_failing_excuser_takes_the_full_form() {
    r4_new_names_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

fn r4_departed_own_file_case(binary: &Path, head: bool) {
    let s = Suite::new();
    s.remove("e2e/x.u");
    s.remove("tests/c.t");
    let fixture = include_str!("fixtures/hook/t");
    let anchor = "\tset -f\n";
    assert_eq!(fixture.matches(anchor).count(), 1);
    let fixture = fixture.replace(anchor, "\tif IFS= read -r policy < \"$ROOT/setup.src\" && [ \"$policy\" = 'requires c' ] && [ ! -f \"$ROOT/tests/c.t\" ]; then\n\t\tnote missing-required-test=tests/c.t\n\t\tSTATUS=1\n\tfi\n\tset -f\n");
    s.executable("t", &fixture);
    success(&r3_control_run(&s, binary));
    edit(&s, 2);
    success(&r3_control_run(&s, binary));
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "requires c\n");
    success(&r3_control_run(&s, binary));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    eprintln!(
        "R4 DEPARTED BEFORE: head={head} launches={:?} residue={}",
        launched(&s),
        residue(&s)
    );
    assert_eq!(known(&s), if head { Some(0) } else { None });
    s.remove("tests/c.t");
    s.write("tests/a.t", "src/shared.src\n\n");
    let mut verdicts = Vec::new();
    for attempt in 0..2 {
        let retry = r3_control_run(&s, binary);
        let run = launched(&s);
        let oracle = direct(&s, &TU);
        assert_eq!(oracle, 1);
        assert_eq!(
            code(&retry),
            1,
            "R4 DEPARTED WRONG VERDICT on attempt {attempt}: {run:?}\n{}",
            stderr(&retry)
        );
        eprintln!("R4 DEPARTED RETRY: head={head} attempt={attempt} exit={} direct={oracle} launches={run:?} residue={}\n{}", code(&retry), residue(&s), stderr(&retry));
        verdicts.push(code(&retry));
    }
    assert!(
        verdicts.iter().all(|&exit| exit != 0),
        "R4 DEPARTED WRONG VERDICT: {verdicts:?} with direct 1 on both attempts"
    );
}

#[test]
#[ignore = "requires frozen merge-base binary"]
fn r4_departed_unit_path_used_by_the_full_runner_is_not_optional() {
    let base = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("set the merge-base binary");
    r4_departed_own_file_case(Path::new(&base), false);
    r4_departed_own_file_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

/// Review round 4, R4b on the head binary alone. A departed unit's own file that the full command requires takes the
/// full form, and the subset's exit is not trusted.
#[test]
fn r4_b_head_departed_unit_required_by_the_runner_takes_the_full_form() {
    r4_departed_own_file_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

#[test]
fn r4_retry_after_each_input_refusal_and_round_trip_switch() {
    for mode in ["actual-drop", "stat", "appeared-stat", "removed"] {
        let s = zsuite();
        s.executable("t", &r4_script(mode == "removed", false));
        if mode == "appeared-stat" {
            s.remove("tests/z.flag");
        }
        learned(&s, &TU);
        assert_eq!(known(&s), Some(0), "{mode}: {}", residue(&s));
        s.write(
            "tests/c.t",
            if mode.contains("stat") {
                "src/c.src\ntests/z.u\nstat:tests/z.flag\n"
            } else {
                "src/c.src\ntests/z.u\n"
            },
        );
        if mode == "removed" {
            s.remove("tests/z.flag");
        } else {
            s.write("tests/z.flag", "fail\n");
        }
        let (_, initial, run, oracle) = judge(mode, &s, &TU, true);
        assert_eq!(oracle, 1);
        if mode == "removed" {
            assert_eq!(code(&initial), 1);
            assert_eq!(run, [""]);
        } else {
            assert_eq!(code(&initial), 125, "{mode}: {}", stderr(&initial));
            assert_eq!(run, ["tests/c.t"]);
            assert!(stderr(&initial).contains("tests/z.flag"));
        }
        for off in [false, false, true, false] {
            s.clear_log();
            let run = if off { s.hook(&TU) } else { split(&s, &TU) };
            eprintln!(
                "R4 RETRY {mode}: off={off} exit={} launches={:?}\n{}",
                code(&run),
                launched(&s),
                stderr(&run)
            );
            assert_eq!(code(&run), 1, "{mode}, off={off}: {}", stderr(&run));
            assert_eq!(launched(&s), [""]);
        }
    }
}

#[test]
fn r4_retry_while_fallback_store_unavailable_and_after_unlock() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    for mode in ["busy", "read-only"] {
        let s = zlearned();
        let bundle_path = s.bundle_path().unwrap();
        let dir = bundle_path.parent().unwrap();
        let before = s.bundle_bytes();
        s.write("tests/c.t", "src/c.src\ntests/z.u\n");
        s.write("tests/z.flag", "fail\n");
        let lock = (mode == "busy").then(|| {
            let lock = File::open(bundle_path.with_extension("lock")).unwrap();
            assert_eq!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            lock
        });
        if mode == "read-only" {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();
        }
        let mut outcomes = Vec::new();
        for _ in 0..2 {
            s.clear_log();
            let run = split(&s, &TU);
            outcomes.push((code(&run), launched(&s), stderr(&run)));
        }
        if mode == "read-only" {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        drop(lock);
        assert_eq!(s.bundle_bytes(), before);
        for (code, launches, log) in outcomes {
            eprintln!("R4 FALLBACK {mode}: exit={code} launches={launches:?}\n{log}");
            assert_eq!((code, launches.as_slice()), (1, [String::new()].as_slice()));
        }
        let (_, refusal, run, oracle) = judge("r4-restored-refusal", &s, &TU, true);
        no_verdict_names(&refusal, "tests/z.flag");
        assert_eq!(run, ["tests/c.t"]);
        assert_eq!(oracle, 1);
        let (_, retry, run, oracle) = judge("r4-restored-retry", &s, &TU, true);
        assert_eq!(
            (code(&retry), oracle, run.as_slice()),
            (1, 1, [String::new()].as_slice())
        );
    }
}

/// Review round 4, B11 (derived, reproduced by the same reading of the excuses). An input outside the root that the
/// whole command reads changes beside an edit to a roster unit's own file. The unit that reads it passes alone, while
/// the runner's own check fails. The whole proof's input takes the full form.
#[test]
fn t1_an_outside_root_input_change_beside_an_own_file_edit_takes_the_full_form() {
    let s = Suite::new();
    struct OutsideFile(std::path::PathBuf);
    impl Drop for OutsideFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
    let home = fs::canonicalize(std::env::var_os("HOME").expect("HOME")).unwrap();
    assert!(
        !home.starts_with("/tmp") && !home.starts_with("/var/tmp") && !home.starts_with("/run")
    );
    let path = home.join(format!(".stoop-r4-b11-{}.flag", std::process::id()));
    File::options()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let file = OutsideFile(path);
    fs::write(&file.0, "ok\n").unwrap();
    let flag = file.0.display().to_string();
    s.executable(
        "t",
        &ow_script(&format!("read -r v < '{flag}' && [ \"$v\" = fail ]")),
    );
    s.write("tests/c.t", &format!("src/c.src\nabs:{flag}\n"));
    learned(&s, &[]);
    assert!(
        s.proofs().iter().any(|proof| {
            proof["inputs"].as_array().is_some_and(|inputs| {
                inputs.iter().any(|input| {
                    input["path"].as_str() == Some(flag.as_str())
                        && input["id"]
                            .as_str()
                            .is_some_and(|id| id.starts_with("f:") || id.starts_with("x:"))
                })
            })
        }),
        "the whole proof did not record the outside input"
    );
    assert!(
        stored_reads(&bundle(&s), &["tests/c.t".to_owned()]).contains(&flag),
        "unit c did not record the outside input"
    );
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    fs::write(&flag, "fail\n").unwrap();
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, run, launches, oracle) = judge("t1-b11", &s, &[], true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 1, "{}", stderr(&run));
    assert_eq!(launches, [""]);
    let (_, retry, launches, oracle) = judge("t1-b11-retry", &s, &[], true);
    assert_eq!(
        (code(&retry), oracle, launches.as_slice()),
        (1, 1, [String::new()].as_slice())
    );
}

/// Review round 4, D2 (derived). A path in a dot directory, which the catalog walk does not list, appears. A unit reads it
/// by content and passes, while the runner's own check of the same path fails beside an edit to a unit's own file.
#[test]
fn t1_an_absent_input_that_appears_in_an_unlisted_directory_takes_the_full_form() {
    let s = Suite::new();
    s.executable("t", &ow_script("[ -f \"$ROOT/.cfg/x\" ]"));
    s.write("tests/c.t", "src/c.src\n.cfg/x\n");
    learned(&s, &[]);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s.write(".cfg/x", "ok\n");
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, run, launches, oracle) = judge("t1-d2", &s, &[], true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 1, "{}", stderr(&run));
    assert_eq!(launches, [""]);
    let (_, retry, launches, oracle) = judge("t1-d2-retry", &s, &[], true);
    assert_eq!(
        (code(&retry), oracle, launches.as_slice()),
        (1, 1, [String::new()].as_slice())
    );
}

/// Review round 4, E2 (derived). A new unit that the runner's own policy rejects. The new unit passes alone, so a subset
/// would pass where the full command fails. A new unit is not a subset's to decide.
#[test]
fn r5c_a_new_unit_that_the_runner_policy_rejects_takes_the_full_form() {
    let s = Suite::new();
    s.executable("t", &ow_script("[ -f \"$ROOT/tests/d.t\" ]"));
    s.write("tests/c.t", "src/c.src\ntests/d.t\n");
    learned(&s, &[]);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s.write("tests/d.t", "src/c.src\n");
    let (_, run, launches, oracle) = judge("r5c", &s, &[], true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 1, "{}", stderr(&run));
    assert_eq!(launches, [""]);
    let (_, retry, launches, oracle) = judge("r5c-retry", &s, &[], true);
    assert_eq!(
        (code(&retry), oracle, launches.as_slice()),
        (1, 1, [String::new()].as_slice())
    );
}

/// The runner counts its catalog without probing the future unit by name. Its old proof has no input for d.t, and the
/// new unit passes alone, but adding it violates the full runner's policy.
#[test]
fn r4_e2_an_unseen_new_unit_rejected_by_runner_policy_takes_the_full_form() {
    let s = Suite::new();
    s.executable(
        "t",
        &ow_script("set -- \"$ROOT\"/tests/*.t; [ \"$#\" -gt 3 ]"),
    );
    learned(&s, &[]);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    let proofs = s.proofs();
    assert!(
        !proofs.is_empty()
            && proofs.iter().all(|proof| {
                proof["inputs"].as_array().is_some_and(|inputs| {
                    inputs
                        .iter()
                        .all(|input| input["path"].as_str() != Some("tests/d.t"))
                })
            }),
        "the full proof already named the future unit"
    );
    s.write("tests/d.t", "src/c.src\n");
    let (_, run, launches, oracle) = judge("r4-e2-unseen", &s, &[], true);
    assert_eq!(
        (code(&run), oracle, launches.as_slice()),
        (1, 1, [String::new()].as_slice()),
        "{}",
        stderr(&run)
    );
    let (_, retry, launches, oracle) = judge("r4-e2-unseen-retry", &s, &[], true);
    assert_eq!(
        (code(&retry), oracle, launches.as_slice()),
        (1, 1, [String::new()].as_slice()),
        "{}",
        stderr(&retry)
    );
}

/// The accepted covered-file gap also applies when a runner-only test appears: a unit reads the file by content, but
/// the runner executes it separately and fails on its existing flag. The traces cannot distinguish that from unit data.
#[test]
fn r4c_informational_an_appeared_runner_only_test_read_as_data() {
    let s = zsuite();
    s.remove("tests/z.u");
    s.write("tests/z.flag", "fail\n");
    learned(&s, &TU);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, run, launches, oracle) = judge("r4c-appeared", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 0, "{}", stderr(&run));
    assert_eq!(launches, ["tests/a.t", "tests/c.t"]);
    let (_, retry, launches, oracle) = judge("r4c-appeared-retry", &s, &TU, true);
    assert_eq!((code(&retry), oracle), (0, 1), "{}", stderr(&retry));
    assert!(launches.is_empty(), "{launches:?}");
}

/// Benefit kept (owner-accepted): own-file content edits accumulate between full runs, and the next unchanged run skips.
#[test]
fn t1_own_file_edits_accumulate_between_full_runs() {
    let s = Suite::new();
    learned(&s, &[]);
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, run, launches, oracle) = judge("t1-a2-a", &s, &[], true);
    assert_eq!((code(&run), oracle), (0, 0), "{}", stderr(&run));
    assert_eq!(launches, ["tests/a.t"]);
    s.write("tests/b.t", "src/shared.src\n\n");
    let (_, run, launches, oracle) = judge("t1-a2-b", &s, &[], true);
    assert_eq!((code(&run), oracle), (0, 0), "{}", stderr(&run));
    assert_eq!(launches, ["tests/b.t"]);
    let (_, run, launches, oracle) = judge("t1-a2-skip", &s, &[], true);
    assert_eq!((code(&run), oracle), (0, 0), "{}", stderr(&run));
    assert!(launches.is_empty(), "{launches:?}");
}

/// Benefit kept (owner-accepted): an own-file edit that makes its unit fail is a failing subset, with the direct exit.
#[test]
fn t1_an_own_file_edit_that_fails_its_unit_is_a_failing_subset() {
    let s = Suite::new();
    s.executable("t", &ow_script("false"));
    learned(&s, &[]);
    s.write("tests/a.t", "src/shared.src\nfail\n");
    let (_, run, launches, oracle) = judge("t1-a3", &s, &[], true);
    assert_eq!(oracle, 1);
    assert_eq!(code(&run), 1, "{}", stderr(&run));
    assert_eq!(launches, ["tests/a.t"]);
}

fn r5_run_control(s: &Suite, binary: &Path, label: &str) {
    let oracle = direct(s, &TU);
    assert_eq!(oracle, 1, "{label}");
    let mut exits = Vec::new();
    for n in 0..2 {
        let run = r3_control_run(s, binary);
        eprintln!(
            "R5 CONTROL {label} attempt={n}: exit={} direct={oracle} launches={:?} residue={}\n{}",
            code(&run),
            launched(s),
            residue(s),
            stderr(&run)
        );
        exits.push(code(&run));
    }
    assert_eq!(
        exits,
        [1, 1],
        "{label}: the full command returned 1 on the same tree"
    );
}

fn r5_dir_control(binary: &Path, head: bool, edit_unit: bool) {
    let s = Suite::new();
    s.remove("e2e/x.u");
    s.remove("tests/c.t");
    fs::create_dir_all(s.path("policy/zone")).unwrap();
    let body = ow_script("[ ! -d \"$ROOT/policy/zone\" ]");
    let old = "-o -path ./slow ";
    assert_eq!(body.matches(old).count(), 2);
    s.executable(
        "t",
        &body.replace(old, "-o -path ./slow -o -path ./policy "),
    );
    success(&r3_control_run(&s, binary));
    edit(&s, 2);
    success(&r3_control_run(&s, binary));
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "refresh the whole proof for the new roster\n");
    success(&r3_control_run(&s, binary));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert_eq!(known(&s), if head { Some(0) } else { None });
    assert!(
        s.proofs().iter().all(|p| p["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["path"] == "policy/zone" && i["id"] == "d")),
        "the whole proof must record the directory as an input, not a listing"
    );
    for unit in ["tests/a.t", "tests/b.t", "tests/c.t"] {
        assert!(!stored_reads(&bundle(&s), &[unit.to_owned()]).contains(&"policy/zone".to_owned()));
    }
    fs::remove_dir(s.path("policy/zone")).unwrap();
    if edit_unit {
        s.write("tests/a.t", "src/shared.src\n\n");
    }
    r5_run_control(
        &s,
        binary,
        &format!("removed-observed-directory head={head} edit={edit_unit}"),
    );
}

#[test]
#[ignore = "requires frozen merge-base binary"]
fn r5_a_removed_catalog_directory_that_the_full_runner_statted_is_not_optional() {
    let base = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("set the merge-base binary");
    for edit in [false, true] {
        r5_dir_control(Path::new(&base), false, edit);
    }
    for edit in [true, false] {
        r5_dir_control(Path::new(env!("CARGO_BIN_EXE_stoop")), true, edit);
    }
}

fn r5_statted_unit_control(binary: &Path, head: bool) {
    use std::os::unix::fs::PermissionsExt;
    let s = Suite::new();
    s.remove("e2e/x.u");
    s.config("[units]\ndefault_branch = 'main'\n");
    s.write(
        ".stoopignore",
        ".git\n.stoopignore\n.gitignore\n.stoop.toml\n",
    );
    s.write(".gitignore", "tests/d.t\n");
    s.write("tests/d.t", "src/c.src\n");
    let body = ow_script("[ -x \"$ROOT/tests/d.t\" ]");
    let anchor = "case $line in\nabs:";
    assert_eq!(body.matches(anchor).count(), 1);
    let body = body.replace(
        anchor,
        "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\nabs:",
    );
    let iter = "\tfor P in $(list_tests); do\n";
    assert_eq!(body.matches(iter).count(), 1);
    s.executable(
        "t",
        &body.replace(
            iter,
            "\tfor P in $(list_tests); do\n\t\t[ \"$P\" = tests/d.t ] && continue\n",
        ),
    );
    s.git("review-feature");
    let cold = r3_control_run(&s, binary);
    eprintln!(
        "R5 GIT COLD head={head}: launches={:?} bundles={}\n{}",
        launched(&s),
        s.bundle().is_some(),
        stderr(&cold)
    );
    success(&cold);
    edit(&s, 2);
    let warm = r3_control_run(&s, binary);
    eprintln!(
        "R5 GIT WARM head={head}: launches={:?} bundles={}\n{}",
        launched(&s),
        s.bundle().is_some(),
        stderr(&warm)
    );
    success(&warm);
    assert!(known(&s).is_some_and(|n| n > 0), "{}", residue(&s));
    s.write("tests/c.t", "src/c.src\nstat:tests/d.t\n");
    s.write("setup.src", "refresh the cached roster\n");
    success(&r3_control_run(&s, binary));
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    assert!(bundle(&s)["units"].get("tests/d.t").is_none());
    assert!(
        s.proofs().iter().all(|p| p["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["path"] == "tests/d.t" && i["id"].as_str().unwrap().starts_with("f:"))),
        "the old whole command only statted d.t"
    );
    if head {
        assert_eq!(known(&s), Some(0), "{}", residue(&s));
    } else {
        assert!(known(&s).is_some_and(|n| n > 0), "{}", residue(&s));
    }
    let staged = spawning(|| {
        std::process::Command::new("git")
            .current_dir(&s.root)
            .args(["add", "-f", "--", "tests/d.t"])
            .output()
    })
    .unwrap();
    assert!(staged.status.success(), "{}", text(&staged.stderr));
    fs::set_permissions(s.path("tests/d.t"), fs::Permissions::from_mode(0o755)).unwrap();
    r5_run_control(
        &s,
        binary,
        &format!("previously-statted-new-roster-unit head={head}"),
    );
}

#[test]
#[ignore = "requires frozen merge-base binary"]
fn r5_e2_a_formerly_ignored_unit_that_the_full_runner_only_statted_needs_full() {
    let base = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("set the merge-base binary");
    r5_statted_unit_control(Path::new(&base), false);
    r5_statted_unit_control(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

#[test]
fn r5_a_head_removed_catalog_directory_is_not_optional() {
    for edit in [true, false] {
        r5_dir_control(Path::new(env!("CARGO_BIN_EXE_stoop")), true, edit);
    }
}

#[test]
fn r5_e2_head_formerly_ignored_statted_unit_needs_full() {
    r5_statted_unit_control(Path::new(env!("CARGO_BIN_EXE_stoop")), true);
}

#[test]
fn r5_a_unit_file_that_gains_an_execute_bit_takes_the_full_form() {
    use std::os::unix::fs::PermissionsExt;
    let s = Suite::new();
    s.executable("t", &ow_script("[ -x \"$ROOT/tests/a.t\" ]"));
    learned(&s, &[]);
    fs::set_permissions(s.path("tests/a.t"), fs::Permissions::from_mode(0o755)).unwrap();
    let (_, run, launches, oracle) = judge("r5-own-execute-bit", &s, &[], true);
    assert_eq!(
        oracle, 1,
        "the runner's policy rejects an executable unit file"
    );
    assert_eq!(code(&run), 1, "{}", stderr(&run));
    assert_eq!(
        launches,
        [""],
        "a changed execute bit is not a content change"
    );
}

#[rustfmt::skip]
fn r6_directory_fixture(check: &str) -> Suite {
    let s = Suite::new();
    s.remove("e2e/x.u");
    let body = ow_script(check);
    let old = "-o -path ./slow ";
    assert_eq!(body.matches(old).count(), 2);
    s.executable("t", &body.replace(old, "-o -path ./slow -o -path ./policy "));
    s.write("policy/zone/item", "payload\n");
    s
}

#[rustfmt::skip]
fn r6_directory_id(s: &Suite, prefix: &str) {
    let proof = bundle(s)["whole"].as_str().unwrap().to_owned();
    let proofs = s.proofs();
    assert!(!proofs.is_empty(), "no whole proof for {proof}");
    assert!(proofs.iter().all(|p| p["inputs"].as_array().unwrap().iter()
        .any(|input| input["path"] == "policy/zone" && input["id"].as_str().unwrap().starts_with(prefix))),
        "{proof}: the observed directory must use {prefix:?}");
    for unit in ["tests/a.t", "tests/b.t", "tests/c.t"] {
        assert!(!stored_reads(&bundle(s), &[unit.to_owned()]).contains(&"policy/zone".to_owned()),
            "a unit should not own the full runner's directory check");
    }
}

#[rustfmt::skip]
fn r6_empty_listed_directory_case(binary: &Path, head: bool, change_unit: bool) {
    // The shell lists this empty directory during the passing full form. None of its launches own that dependency.
    let s = r6_directory_fixture("for item in \"$ROOT\"/policy/zone/*; do :; done; [ ! -d \"$ROOT/policy/zone\" ]");
    s.remove("policy/zone/item");
    s.remove("tests/c.t");
    success(&r3_control_run(&s, binary));
    edit(&s, 2);
    success(&r3_control_run(&s, binary));
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "force a passing whole run for the new roster\n");
    let full = r3_control_run(&s, binary);
    success(&full);
    assert_eq!(launched(&s).first().map(String::as_str), Some(""));
    r6_directory_id(&s, "dl:");
    assert_eq!(known(&s), if head { Some(0) } else { None });
    fs::remove_dir(s.path("policy/zone")).unwrap();
    if change_unit { s.write("tests/a.t", "src/shared.src\n\n"); }
    let mut exits = Vec::new();
    for attempt in 0..2 {
        let run = r3_control_run(&s, binary);
        let launched = launched(&s);
        let oracle = direct(&s, &TU);
        assert_eq!(oracle, 1);
        eprintln!("R6 EMPTY DIR head={head} changed_unit={change_unit} attempt={attempt} exit={} direct={oracle} launches={launched:?} residue={}\n{}", code(&run), residue(&s), stderr(&run));
        exits.push(code(&run));
    }
    assert_eq!(exits, [1, 1], "R6 LISTED EMPTY DIR false verdict: no names does not prove a directory exists");
}

#[test]
#[ignore = "requires the pinned comparison binary"]
fn r6_deleting_an_empty_listed_directory_is_not_an_unchanged_listing() {
    let path = std::env::var_os("STOOP_REVIEW_BASE_BIN").expect("pinned comparison binary");
    for change_unit in [false, true] {
        r6_empty_listed_directory_case(Path::new(&path), false, change_unit);
    }
    r6_empty_listed_directory_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true, true);
}

#[test]
fn r6_head_deleting_an_empty_listed_directory_takes_the_full_form() {
    for change_unit in [false, true] {
        r6_empty_listed_directory_case(Path::new(env!("CARGO_BIN_EXE_stoop")), true, change_unit);
    }
}

fn r7_oracle(s: &Suite, env: &[(&str, &str)]) -> (i32, Vec<String>, Vec<String>) {
    s.clear_log();
    let out = s.direct(&s.root, &[], env);
    let failures = oracle_failed_tests(s);
    let policy_failures = oracle_policy_failures(s);
    s.clear_log();
    (code(&out), failures, policy_failures)
}

fn r7_policy_fixture() -> Suite {
    let s = zsuite();
    listed_policy_setup(&s);
    s.executable("t", &listed_policy_runner(&e3_runner()));
    learned(&s, &TU);
    assert_eq!(known(&s), Some(0), "{}", residue(&s));
    assert!(s.proofs().iter().any(|p| p["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["path"] == "policy-r6/zone" && i["id"].as_str().unwrap().starts_with("dl:"))));
    s
}

#[test]
#[rustfmt::skip]
fn r7_sticky_classifier_cannot_see_an_independent_full_policy_failure() {
    let s = r7_policy_fixture();
    let stored = bundle(&s);
    let world_units: Vec<String> = ROSTER.iter().map(|unit| (*unit).to_owned()).collect();
    let runners = vec!["tests/z.u".to_owned()];
    assert!(e3_stored_content_flag(&stored, &s, &world_units, "tests/z.flag", "ok\n"));
    s.write("tests/z.flag", "fail\n");
    let (_, first, launches, oracle) = judge("r7-first-accepted-w22", &s, &TU, true);
    assert_eq!((code(&first), oracle), (0, 1));
    assert_eq!(launches, ["tests/c.t"]);
    let (before, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!((before, failed.as_slice()), (1, runners.as_slice()));
    assert!(policy.is_empty());
    assert_eq!(r7_oracle(&s, &[("T_U", "0")]), (0, Vec::new(), Vec::new()));
    let event = Step::ListedDirectory(0);
    let mut divergence = E3Diverged {
        origin: 1,
        failing: failed.iter().cloned().collect(),
        changed: Default::default(),
        shapes: vec![E3Gap::W22],
    };
    assert!(e3_sticky(&divergence, &failed, &policy, &runners, &world_units, &[]));
    for test in &divergence.failing {
        if e3_changes_runner(&event, test) { divergence.changed.insert(test.clone()); }
    }
    assert!(divergence.changed.is_empty());
    assert!(e3_changes_full_policy(&event));
    listed_policy_replace(&s, 0);
    let (direct, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!((direct, failed.as_slice()), (1, runners.as_slice()));
    assert_eq!(policy, ["policy-r6/zone"]);
    assert_eq!(r7_oracle(&s, &[("T_U", "0")]), (1, Vec::new(), policy.clone()));
    let (_, outcome, actual, direct) = judge("r7-sticky-after-distinct-policy-failure", &s, &TU, true);
    assert_eq!(direct, 1);
    let mutant = std::env::var_os("STOOP_R7_LISTED_MUTANT").is_some();
    if mutant {
        assert_eq!(code(&outcome), 0, "expected the actual stale skip in the negative control");
        assert!(actual.is_empty());
    } else {
        assert_eq!(code(&outcome), 1, "{}", stderr(&outcome));
        assert_eq!(actual, [""]);
    }
    let proposed_launches: &[String] = if mutant { &actual } else { &[] };
    let accepted = e3_sticky(&divergence, &failed, &policy, &runners, &world_units, proposed_launches);
    eprintln!("R7 STICKY mutant={mutant} subject={} direct={direct} independent_policy_exit=1 failed={failed:?} policy={policy:?} classifier_accepts_skip={accepted}", code(&outcome));
    assert!(!accepted, "an independent full-run policy failure must reject the sticky exemption");
}

#[test]
#[rustfmt::skip]
fn r7_e5_classifier_credits_a_flag_read_without_a_read_of_the_test() {
    let s = zsuite();
    s.remove("tests/z.u");
    s.remove("tests/z.flag");
    s.executable("t", &e3_runner());
    s.write("tests/c.t", "src/c.src\nunit-only:tests/z.u\nunit-only:tests/z.flag\n");
    learned(&s, &TU);
    assert_eq!(known(&s), Some(0));
    let world_units: Vec<String> = ROSTER.iter().map(|unit| (*unit).to_owned()).collect();
    let admitted = "tests/z.u";
    let flag = "tests/z.flag";
    assert!(!s.path(admitted).exists());
    assert!(!s.path(flag).exists());
    assert_eq!(r4_version_id(&bundle(&s), "tests/c.t", admitted), "a");
    s.write("tests/c.t", "src/c.src\nstat:tests/z.u\nunit-only:tests/z.flag\n");
    s.write(admitted, "src/c.src\n");
    s.write(flag, "fail\n");
    let runners = vec![admitted.to_owned()];
    let (direct, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!((direct, failed.as_slice()), (1, runners.as_slice()));
    assert!(policy.is_empty());
    let (_, outcome, launches, oracle) = judge("r7-e5-stats-test-and-reads-flag", &s, &TU, true);
    assert_eq!(oracle, 1);
    assert_eq!(launches, ["tests/c.t"]);
    let mutant = std::env::var_os("STOOP_R7_E5_MUTANT").is_some();
    if mutant {
        assert_eq!(code(&outcome), 0, "expected false pass when the test path's refusal is suppressed");
    } else {
        assert_eq!(code(&outcome), 125, "{}", stderr(&outcome));
        assert!(stderr(&outcome).contains("tests/z.u appeared"), "{}", stderr(&outcome));
    }
    let after = e3_listings(&s, &world_units);
    assert!(no_content_reader(&s, &after, admitted));
    assert!(!no_content_reader(&s, &after, flag));
    let shape = e3_gap(E3GapEvidence {
        runner_only: runners.contains(&admitted.to_owned()) && !world_units.contains(&admitted.to_owned()) && !launches.contains(&admitted.to_owned()),
        appeared_now: true,
        current_content: !no_content_reader(&s, &after, flag),
        appeared_test_content: e3_launched_content_path(&after, &launches, admitted),
        ..E3GapEvidence::default()
    });
    eprintln!("R7 E5 mutant={mutant} subject={} direct=1 test_content_reader=false flag_content_reader=true classifier={shape:?}", code(&outcome));
    assert_eq!(shape, None, "a flag read without a content read of the appeared test must not receive E5");
}

// Independent round-eight controls. The runner and all paths are disposable fixtures.
#[test]
#[rustfmt::skip]
fn r8_sticky_rejects_independent_policy_and_runner_edits() {
    use std::os::unix::fs::PermissionsExt;
    let s = zsuite();
    listed_policy_setup(&s);
    s.write("policy-r6/required", "required\n");
    s.write("policy-r6/mode", "must not be executable\n");
    s.write("tests/y.u", "src/c.src\n");
    s.write("tests/y.flag", "ok\n");
    let anchor = "\tset -f\n";
    let script = listed_policy_runner(&e3_runner());
    assert_eq!(script.matches(anchor).count(), 1);
    let checks = concat!(
        "\tif [ ! -f \"$ROOT/policy-r6/required\" ]; then note 'failed-policy=required-file'; STATUS=1; fi\n",
        "\tif [ -x \"$ROOT/policy-r6/mode\" ]; then note 'failed-policy=mode'; STATUS=1; fi\n",
        "\tif [ \"${FOO:-}\" = reject ]; then note 'failed-policy=environment'; STATUS=1; fi\n",
        "\tset -f\n",
    );
    s.executable("t", &script.replace(anchor, checks));
    assert_eq!(r7_oracle(&s, &TU), (0, vec![], vec![]));
    s.write("tests/z.flag", "fail\n");
    let (status, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!(status, 1);
    assert_eq!(failed, ["tests/z.u"]);
    assert!(policy.is_empty());
    let runners = vec!["tests/y.u".to_owned(), "tests/z.u".to_owned()];
    let units: Vec<String> = ROSTER.iter().map(|u| (*u).to_owned()).collect();
    let mut divergence = E3Diverged {
        origin: 1,
        failing: failed.iter().cloned().collect(),
        changed: Default::default(),
        shapes: vec![E3Gap::W22],
    };
    assert!(e3_sticky(&divergence, &failed, &policy, &runners, &units, &[]));
    for mode in ["required-file", "policy-r6/zone", "mode", "environment", "second-runner"] {
        let mut env = TU.to_vec();
        match mode {
            "required-file" => s.remove("policy-r6/required"),
            "policy-r6/zone" => listed_policy_replace(&s, 0),
            "mode" => fs::set_permissions(s.path("policy-r6/mode"), fs::Permissions::from_mode(0o755)).unwrap(),
            "environment" => env.push(("FOO", "reject")),
            "second-runner" => s.remove("tests/y.flag"),
            _ => unreachable!(),
        }
        let (status, failed, policy) = r7_oracle(&s, &env);
        assert_eq!(status, 1, "{mode}");
        if mode == "second-runner" {
            assert_eq!(failed, ["tests/y.u", "tests/z.u"]);
            assert!(policy.is_empty());
        } else {
            assert_eq!(failed, ["tests/z.u"]);
            assert_eq!(policy, [mode]);
        }
        let accepted = e3_sticky(&divergence, &failed, &policy, &runners, &units, &[]);
        eprintln!("R8 POLICY {mode}: sticky={accepted} failed={failed:?} policy={policy:?}");
        assert!(!accepted);
        match mode {
            "required-file" => s.write("policy-r6/required", "required\n"),
            "policy-r6/zone" => listed_policy_replace(&s, 1),
            "mode" => fs::set_permissions(s.path("policy-r6/mode"), fs::Permissions::from_mode(0o644)).unwrap(),
            "second-runner" => s.write("tests/y.flag", "ok\n"),
            _ => (),
        }
    }
    for value in ["ok", "fail"] {
        s.write("tests/z.flag", &format!("{value}\n"));
        let op = Step::Flag("tests/z.u".to_owned(), value);
        for test in &divergence.failing {
            if e3_changes_runner(&op, test) { divergence.changed.insert(test.clone()); }
        }
    }
    let (status, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!((status, failed.as_slice()), (1, ["tests/z.u".to_owned()].as_slice()));
    assert!(policy.is_empty());
    let accepted = e3_sticky(&divergence, &failed, &policy, &runners, &units, &[]);
    eprintln!("R8 FLAG ROUNDTRIP sticky={accepted} changed={:?}", divergence.changed);
    assert!(!accepted);
}

#[test]
#[rustfmt::skip]
fn r8_reading_a_different_appeared_test_does_not_earn_e5_or_a_sticky_pass() {
    let s = zsuite();
    s.executable("t", &e3_runner());
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\nunit-only:tests/y.u\nunit-only:tests/y.flag\nunit-only:tests/w.u\nunit-only:tests/w.flag\n");
    learned(&s, &TU);
    assert_eq!(known(&s), Some(0));
    s.write("tests/z.flag", "fail\n");
    let (_, origin, origins, oracle) = judge("r8-origin-w22", &s, &TU, true);
    assert_eq!((code(&origin), oracle, origins.as_slice()), (0, 1, ["tests/c.t".to_owned()].as_slice()));
    let (_, sticky, launches, oracle) = judge("r8-sticky-w22", &s, &TU, true);
    assert_eq!((code(&sticky), oracle), (0, 1));
    assert!(launches.is_empty());
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\nstat:tests/y.u\nunit-only:tests/y.flag\nunit-only:tests/w.u\nunit-only:tests/w.flag\n");
    s.write("tests/y.u", "src/c.src\n");
    s.write("tests/y.flag", "fail\n");
    s.write("tests/w.u", "src/c.src\n");
    s.write("tests/w.flag", "ok\n");
    let (direct, failed, policy) = r7_oracle(&s, &TU);
    assert!(policy.is_empty());
    assert_eq!((direct, failed.as_slice()), (1, ["tests/y.u".to_owned(), "tests/z.u".to_owned()].as_slice()));
    let (_, refused, launched, oracle) = judge("r8-different-content-path", &s, &TU, true);
    assert_eq!((code(&refused), oracle), (125, 1), "{}", stderr(&refused));
    assert_eq!(launched, ["tests/c.t"]);
    assert!(stderr(&refused).contains("tests/y.u appeared"));
    let units: Vec<String> = ROSTER.iter().map(|u| (*u).to_owned()).collect();
    let listings = e3_listings(&s, &units);
    assert!(e3_launched_content_path(&listings, &launched, "tests/w.u"));
    assert!(e3_launched_content_path(&listings, &launched, "tests/y.flag"));
    let e5 = e3_gap(E3GapEvidence {
        runner_only: true,
        appeared_now: true,
        current_content: true,
        appeared_test_content: e3_launched_content_path(&listings, &launched, "tests/y.u"),
        ..E3GapEvidence::default()
    });
    eprintln!("R8 WRONG PATH refused={} e5={e5:?}", code(&refused));
    assert_eq!(e5, None);
    for attempt in 0..2 {
        let (_, retry, launches, oracle) = judge(&format!("r8-retry-after-refusal-{attempt}"), &s, &TU, true);
        assert_eq!((code(&retry), oracle), (1, 1), "{}", stderr(&retry));
        assert_eq!(launches, [""]);
    }
}

#[test]
#[rustfmt::skip]
fn r8_fresh_w22_requires_a_unit_to_run_against_the_changed_flag() {
    let s = r7_policy_fixture();
    let unit_names: Vec<String> = ROSTER.iter().map(|name| (*name).to_owned()).collect();
    let before = bundle(&s);
    let failure = "tests/z.u";
    let flag = "tests/z.flag";
    let old_flag = fs::read_to_string(s.path(flag)).unwrap();
    assert_eq!(r7_oracle(&s, &TU), (0, vec![], vec![]));
    s.write(flag, "fail\n");
    let (_, run, launches, oracle) = judge("r8-fresh-w22", &s, &TU, true);
    assert_eq!((code(&run), oracle), (0, 1));
    let (status, failed, policy) = r7_oracle(&s, &TU);
    assert_eq!(status, 1);
    assert_eq!(failed, [failure]);
    assert!(policy.is_empty());
    let after = e3_listings(&s, &unit_names);
    let op = Step::Flag(failure.to_owned(), "fail");
    let evidence = E3GapEvidence {
        runner_only: !unit_names.contains(&failure.to_owned())
            && !launches.contains(&failure.to_owned())
            && !launches.iter().any(String::is_empty),
        flag_flipped: e3_changes_runner(&op, failure)
            && !old_flag.contains("fail")
            && fs::read_to_string(s.path(flag)).unwrap().contains("fail"),
        stored_content: e3_stored_content_flag(&before, &s, &unit_names, flag, &old_flag),
        launched_stored_content: e3_stored_content_flag(&before, &s, &launches, flag, &old_flag),
        current_content: !no_content_reader(&s, &after, flag),
        appeared_test_content: e3_launched_content_path(&after, &launches, failure),
        ..E3GapEvidence::default()
    };
    let actual_flag_reader = e3_launched_content_path(&after, &launches, flag);
    let shape = e3_gap(evidence);
    let mutant = std::env::var_os("STOOP_R8_W22_MUTANT").is_some();
    eprintln!("R8 FRESH W22 mutant={mutant} exit={} direct={oracle} launches={launches:?} flag_reader_launched={actual_flag_reader} granted={shape:?}", code(&run));
    if mutant {
        assert!(launches.is_empty(), "the control must actually skip the first changed run");
        assert!(!actual_flag_reader);
        assert_eq!(shape, None, "a skip on the first flag change falls outside the accepted subset and sticky shapes");
    } else {
        assert_eq!(launches, ["tests/c.t"]);
        assert!(actual_flag_reader);
        assert_eq!(shape, Some(E3Gap::W22));
        let no_launched_reader = E3GapEvidence {
            launched_stored_content: e3_stored_content_flag(&before, &s, &[], flag, &old_flag),
            ..evidence
        };
        assert_eq!(e3_gap(no_launched_reader), None, "a fresh W22 requires the launched stored flag reader");
    }
}
