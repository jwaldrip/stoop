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

/// A departed unit that shares a changed source with a live unit leaves the live unit's new proof to read it, so the
/// run stays a subset.
#[test]
fn r2_a_departed_reader_shared_with_a_live_unit_stays_a_subset() {
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
    assert_eq!(launches, ["tests/a.t"], "{}", stderr(&ran));
}

/// A departed unit whose inputs did not change does not take the full form: the change is to a live unit alone.
#[test]
fn r2_an_unchanged_input_of_a_departed_reader_stays_a_subset() {
    let s = zlearned();
    s.remove("tests/c.t");
    s.write("tests/a.t", "src/shared.src\n\n");
    let (_, ran, launches, direct_code) = judge("unchanged", &s, &TU, true);
    same_verdict("unchanged", &ran, direct_code);
    assert_eq!(launches, ["tests/a.t"], "{}", stderr(&ran));
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
            "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
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
    Noop,
}

struct World {
    units: Vec<String>,
    runners: Vec<String>,
    deleted: Vec<String>,
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
        let choice = rng.below(19);
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

fn e3_no_verdict_path(out: &Output) -> Option<String> {
    stderr(out).lines().find_map(|line| {
        let rest = line.strip_prefix("stoop: this run has no verdict (exit 125): ")?;
        let named = rest.strip_suffix(", and no unit's new proof reads it")?;
        named.strip_suffix(" changed").map(str::to_owned)
    })
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

#[derive(Default)]
struct E3Tally {
    steps: usize,
    gap_current: usize,
    gap_stored: usize,
    no_verdict: usize,
}

/// One E3 sequence. The documented covered-file gap permits a pass only when each failed test's flag is listed by a
/// current unit. A flag read only by a stale version is a wrong verdict. Exit 125 is accepted only with the exact
/// no-verdict line and a launched unit that stopped listing the named path in this step.
fn run_e3(seed: u64, steps: usize, tally: &mut E3Tally) -> Result<(), String> {
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
    s.executable("t", &e3_runner());
    let cold = split(&s, &[("T_U", "1"), ("FOO", "0")]);
    if code(&cold) != 0 {
        return Err(format!(
            "seed {seed}: the cold run failed: {}",
            stderr(&cold)
        ));
    }
    let mut log: Vec<String> = Vec::new();
    let mut no_verdicts = 0usize;
    // An unchanged retry after a 125 (PR 86 review round 3): half the time, the step after a 125 applies nothing.
    let mut last_125 = false;
    for step in 1..=steps {
        let before = e3_listings(&s, &world.units);
        let forced_noop = last_125 && rng.below(2) == 0;
        let count = if forced_noop { 1 } else { 1 + rng.below(3) };
        let mut ops = Vec::new();
        world.forced = false;
        for _ in 0..count {
            let op = if forced_noop {
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
        let failed: Vec<String> = s
            .launches()
            .iter()
            .flat_map(|launch| {
                launch
                    .lines
                    .iter()
                    .filter_map(|line| line.strip_prefix("failed=").map(str::to_owned))
                    .collect::<Vec<_>>()
            })
            .collect();
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
                "{why}\nseed {seed}, step {step}\noperations:\n  {}\nfiles now:\n  {}\nsubject exit {}, oracle exit {}, oracle failed {failed:?}, launches {launches:?}\nsubject stderr:\n{}",
                log.join("\n  "),
                files.join("\n  "),
                code(&subject),
                code(&oracle),
                stderr(&subject)
            )
        };
        let subject_code = code(&subject);
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
            let Some(path) = e3_no_verdict_path(&subject) else {
                return Err(report("a status of 125 without the no-verdict line"));
            };
            let after = e3_listings(&s, &world.units);
            let stopped = world.units.iter().any(|unit| {
                launches.contains(unit)
                    && after.get(unit).is_some_and(|new| {
                        // A launched unit that reads the path by stat only now, or that stopped listing it (PR 86 round 3).
                        new.contains(&format!("stat:{path}"))
                            || (before.get(unit).is_some_and(|old| old.contains(&path))
                                && !new.contains(&path))
                    })
            });
            if !stopped {
                return Err(report(&format!(
                    "the no-verdict line names {path}, which no launched unit stopped reading"
                )));
            }
            no_verdicts += 1;
            tally.no_verdict += 1;
            println!("NO VERDICT ACCEPTED (E3): seed {seed}, step {step}, {path}");
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
        let listed_now = |flag: &str| {
            world.units.iter().any(|unit| {
                fs::read_to_string(s.path(unit))
                    .map(|body| body.lines().any(|line| line == flag))
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
            tally.gap_current += 1;
            println!(
                "E3 covered-file gap (a current unit lists the flag): seed {seed}, step {step}"
            );
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
/// is reported, and the first one in full.
#[test]
fn r2_e3_flag_readers_model() {
    let first = count_from_env("STOOP_R2_FIRST", 1) as u64;
    let seeds = count_from_env("STOOP_R2_SEEDS", 4) as u64;
    let steps = count_from_env("STOOP_R2_STEPS", 30);
    let mut tally = E3Tally::default();
    let mut failures = Vec::new();
    for seed in first..first + seeds {
        if let Err(why) = run_e3(seed, steps, &mut tally) {
            println!("E3 FAILING SEED {seed}");
            failures.push(why);
        }
    }
    println!(
        "E3 sweep: seeds {first}..{}: {} steps, {} covered-file gap steps, {} steps beyond the current reading, {} accepted no-verdicts, {} failing seeds",
        first + seeds - 1,
        tally.steps,
        tally.gap_current,
        tally.gap_stored,
        tally.no_verdict,
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} failing seeds; first:\n{}",
        failures.len(),
        failures.first().cloned().unwrap_or_default()
    );
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
    let (_, run, _, oracle) = judge("r3-off-on-stale", &s, &TU, true);
    assert_eq!(oracle, 1);
    same_verdict("r3-off-on-stale", &run, oracle);
    no_verdict_names(&run, "tests/z.flag");
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
