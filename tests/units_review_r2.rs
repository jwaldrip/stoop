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
