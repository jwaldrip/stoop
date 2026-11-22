//! Independence checks of one traced unit launch (spec 3.3 to 3.6, W6-1). A launch that reads another
//! unit's file, writes a unit's file or a path another unit's proof names, or exits 0 without reading
//! its own file, breaks the suite's independence. The pass stops at that launch, the suite is stored as
//! disabled, and its changed runs take the first-run form until `stoop forget --units`. These tests drive
//! the stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and arm64 only.
//! Each one states what it fails on a tree without the check it exercises.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs;
use std::process::{Child, Output, Stdio};
use units_common::*;

/// A source edit that is a change for certain: the file's length follows `n`.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

/// One launch per unit, in roster order, each with exactly that unit as its only test argument.
fn one_per_unit(launches: &[Launch], units: &[&str]) {
    assert_eq!(launches.len(), units.len(), "{launches:?}");
    for (launch, unit) in launches.iter().zip(units) {
        assert_eq!(launch.args, [*unit], "{launch:?}");
    }
}

/// The one launch of the full form: no test argument, and the whole roster runs.
fn full_form(launches: &[Launch]) {
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
    assert_eq!(launches[0].ran(), ROSTER);
}

fn bundle(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")
}

/// The suite's ID, which names its bundle.
fn suite_id(s: &Suite) -> String {
    let path = s.bundle_path().expect("a suite bundle");
    path.file_stem().unwrap().to_str().unwrap().to_owned()
}

/// The `state` of the suite's bundle, as the store writes it.
fn state(s: &Suite) -> Value {
    bundle(s)["state"].clone()
}

/// The code and label of a suite that is disabled by an attribution pass.
fn disabled(s: &Suite) -> (String, String) {
    let state = state(s);
    assert_eq!(state["status"], "disabled", "{state}");
    assert_eq!(state["phase"], "attribution", "{state}");
    (
        state["code"].as_str().unwrap().to_owned(),
        state["label"].as_str().unwrap().to_owned(),
    )
}

/// The line a run prints when it disables a suite (spec 3.12).
fn disabled_line(id: &str, label: &str) -> String {
    format!("stoop: suite {id} disabled: {label}; run 'stoop forget --units {id}' after fixing it")
}

/// The units whose proof the bundle holds, in name order.
fn proven(s: &Suite) -> Vec<String> {
    bundle(s)["units"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}

/// `stoop forget --units <id>` for one suite, from the root.
fn forget_units(s: &Suite, id: &str) {
    let mut command = s.stoop(&s.root);
    command
        .args(["forget", "--root"])
        .arg(&s.root)
        .args(["--units", id]);
    success(&spawning(|| command.output()).unwrap());
}

/// `stoop explain` of the pinned hook with `env`, from the root.
fn explain_with(s: &Suite, env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK]);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

/// The pinned hook started without waiting, for a test that must act while it runs.
fn spawn_hook(s: &Suite, env: &[(&str, &str)]) -> Child {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.spawn()).unwrap()
}

/// A runner that honours `--files=PATH`. It logs its launch the way the fixture does, and reads only
/// the file it is given, so no launch of it reads another unit.
const FILES_RUNNER: &str = "#!/bin/sh
note() {
	if [ -n \"${LOG:-}\" ]; then
		printf '%s\\n' \"$1\" >> \"$LOG\"
	fi
}
note launch
for word in \"$@\"; do
	note \"arg=$word\"
done
note \"changed=${STOOP_CHANGED:-}\"
for word in \"$@\"; do
	case $word in
		--files=*)
			if [ -f \"${word#--files=}\" ]; then cat \"${word#--files=}\" > /dev/null; fi
			;;
	esac
done
cat setup.src > /dev/null
";

// I0 (guard, passes on the base and on this tree): the glued value form expands to one launch per unit,
// each launch carries `--files=<unit>` as its argument, and each unit keeps its proof. The fixture
// cannot show this, because it ignores a `-` word and reads every test, so this runner honours the flag.
// A10i's first check pins the same expansion with the fixture.
#[test]
fn i0_the_glued_value_form_launches_each_unit_on_its_own() {
    let s = Suite::new();
    s.executable("files", FILES_RUNNER);
    let words = ["./files", "--files={changed:**/*.t|!slow/**}"];
    success(&s.run(&s.root, &[], &words, &[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.run(&s.root, &[], &words, &[]));
    let launches = s.launches();
    assert_eq!(launches.len(), 3, "{launches:?}");
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.args, [format!("--files={unit}")], "{launch:?}");
        assert_eq!(launch.env("changed"), unit);
    }
    assert_eq!(proven(&s), ROSTER);
    assert_eq!(state(&s)["status"], "ready");
}

// I1a: unit a writes a path that c's proof reads. The reader-side check catches it at c, the last
// launch: every unit launches, the run exits 0, a and b keep their proofs, and the suite is disabled at
// c. Fails on a tree without the reader-side check: c's proof is stored and the suite stays ready.
#[test]
fn i1a_a_unit_writing_what_a_later_unit_reads_disables_the_suite_at_the_reader() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_WRITE", "src/c.src"), ("T_WRITE_AT", "tests/a.t")]);
    success(&out);
    one_per_unit(&s.launches(), &ROSTER);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "wrote_input");
    assert_eq!(label, "tests/a.t wrote src/c.src, which tests/c.t reads");
    let err = text(&out.stderr);
    assert!(err.contains(&disabled_line(&suite_id(&s), &label)), "{err}");
    assert_eq!(proven(&s), ["tests/a.t", "tests/b.t"]);
}

// I1b: unit c writes a path that the proofs of a and b read. The writer-side check catches it at c, the
// last launch: the run exits 0, a and b keep their proofs, and the suite is disabled at the writer.
// Fails on a tree without the writer-side check: c's write is not seen and the suite stays ready.
#[test]
fn i1b_a_unit_writing_an_input_of_an_earlier_proof_disables_the_suite_at_the_writer() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_WRITE", "src/shared.src"), ("T_WRITE_AT", "tests/c.t")]);
    success(&out);
    one_per_unit(&s.launches(), &ROSTER);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "wrote_input");
    assert_eq!(
        label,
        "tests/c.t wrote src/shared.src, which tests/a.t reads"
    );
    let err = text(&out.stderr);
    assert!(err.contains(&disabled_line(&suite_id(&s), &label)), "{err}");
    assert_eq!(proven(&s), ["tests/a.t", "tests/b.t"]);
}

// I2: unit a reads unit b's file. The launch of a is coupled, so the pass stops after it: one launch,
// no verdict (exit 125), and the suite is disabled with the read as its label. Fails on a tree without
// check (b): all three units launch and the status is 0.
#[test]
fn i2_a_unit_reading_another_units_file_stops_the_pass_with_no_verdict() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_READ_OTHER", "tests/b.t")]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 125, "{err}");
    one_per_unit(&s.launches(), &["tests/a.t"]);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "read_unit");
    assert_eq!(label, "tests/a.t read tests/b.t");
    assert!(err.contains(&disabled_line(&suite_id(&s), &label)), "{err}");
    assert!(
        err.contains("stoop: this run has no verdict (exit 125): only 1 of 3 launches ran"),
        "{err}"
    );
    assert!(bundle(&s)["units"].as_object().unwrap().is_empty());
}

// I3: unit a only stats unit b's file. A stat is not a read, so no unit is coupled: all three proofs
// are stored and the suite stays ready. Fails on a tree that counts a stat: a is disabled instead.
#[test]
fn i3_a_stat_of_another_units_file_is_not_a_read() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_STAT_OTHER", "tests/b.t")]);
    success(&out);
    one_per_unit(&s.launches(), &ROSTER);
    assert_eq!(state(&s)["status"], "ready", "{}", bundle(&s));
    assert_eq!(proven(&s), ROSTER);
}

// I4: a disabled suite is not used. Its changed runs take the first-run form and print nothing a pass
// would print. Explain names the state, and adding a unit keeps it disabled. `forget --units` clears it:
// the first changed run after that is the full form, which records the suite again, and the next one
// starts a pass, as A12 shows. Fails on a tree without a persisted state: the second change starts a
// pass again.
#[test]
fn i4_a_disabled_suite_takes_the_full_form_until_forget() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let knob = [("T_READ_OTHER", "tests/b.t")];
    edit(&s, 2);
    s.clear_log();
    assert_eq!(code(&s.hook(&knob)), 125);
    let id = suite_id(&s);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "read_unit");

    edit(&s, 3);
    s.clear_log();
    let out = s.hook(&knob);
    success(&out);
    full_form(&s.launches());
    let err = text(&out.stderr);
    assert!(
        !err.contains("attribution pass") && !err.contains("disabled") && !err.contains("verdict"),
        "{err}"
    );

    let explained = explain_with(&s, &knob);
    assert_eq!(code(&explained), 1, "{}", text(&explained.stderr));
    let explained_err = text(&explained.stderr);
    let last = explained_err.lines().last().unwrap();
    assert_eq!(
        last,
        format!(
            "stoop: no attribution pass: suite {id} disabled: {label}; run 'stoop forget --units {id}' after fixing it"
        )
    );

    s.write("tests/d.t", "src/shared.src\n");
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&knob));
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert_eq!(launches[0].ran().len(), 4, "{launches:?}");
    assert_eq!(disabled(&s), (reason.clone(), label.clone()));

    forget_units(&s, &id);
    edit(&s, 5);
    s.clear_log();
    success(&s.hook(&knob));
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{launches:?}");
    edit(&s, 6);
    s.clear_log();
    let out = s.hook(&knob);
    assert!(
        text(&out.stderr).contains("stoop: attribution pass: 4 units, one launch each"),
        "{}",
        text(&out.stderr)
    );
    one_per_unit(
        &s.launches(),
        &["tests/a.t", "tests/b.t", "tests/c.t", "tests/d.t"],
    );
}

// I5: unit a writes unit b's file. That is violation (a) on the writer side, as a write to a unit's own
// file. The pass stops at a: one launch, and no verdict. Fails on a tree without wrote_unit: all three
// units launch, and b's proof is stored after a's write.
#[test]
fn i5_a_unit_writing_another_units_file_stops_at_the_writer() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_WRITE", "tests/b.t"), ("T_WRITE_AT", "tests/a.t")]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 125, "{err}");
    one_per_unit(&s.launches(), &["tests/a.t"]);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "wrote_unit");
    assert_eq!(label, "tests/a.t wrote tests/b.t");
    assert!(err.contains(&disabled_line(&suite_id(&s), &label)), "{err}");
}

// I6: units a and b both write out.txt, which a's proof names as an output. The writer-side check
// catches it at b, the second launch, so the pass stops with two launches and no verdict. Fails on a
// tree without wrote_output: all three units launch and both proofs name the file.
#[test]
fn i6_two_units_writing_one_output_stops_at_the_second() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_WRITE", "out.txt")]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 125, "{err}");
    one_per_unit(&s.launches(), &["tests/a.t", "tests/b.t"]);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "wrote_output");
    assert_eq!(label, "tests/b.t and tests/a.t both write out.txt");
    assert!(err.contains(&disabled_line(&suite_id(&s), &label)), "{err}");
}

// I7 (replaces A24): unit a's launch exits 0 without reading its own file. Check (c) disables the
// suite at a, the line for the unit still prints, and the run has no verdict. Fails on a tree without
// check (c): the silent launch is not a violation, and the pass goes on to all three units.
#[test]
fn i7_a_launch_that_exits_zero_without_reading_its_unit_disables_the_suite() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_IGNORE", "1")]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 125, "{err}");
    assert!(
        err.contains("stoop: no proof for tests/a.t: the launch never read it"),
        "{err}"
    );
    one_per_unit(&s.launches(), &["tests/a.t"]);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "never_ran");
    assert_eq!(label, "tests/a.t exited 0 without reading it");
    assert!(bundle(&s)["units"].as_object().unwrap().is_empty());
}

// I8: unit a fails, and it also reads unit b's file. The read is a coupling, and a failure is a verdict
// of its own: the run's status is the failure's, 1, and the suite is disabled. Fails on a tree where the
// failure gives 125, or where the coupling goes unseen and the suite stays ready.
#[test]
fn i8_a_failing_unit_that_reads_another_fails_the_run_and_disables_the_suite() {
    let s = Suite::new();
    success(&s.hook(&[]));
    s.write("tests/a.flag", "fail\n");
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_READ_OTHER", "tests/b.t")]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 1, "{err}");
    one_per_unit(&s.launches(), &["tests/a.t"]);
    let (reason, label) = disabled(&s);
    assert_eq!(reason, "read_unit");
    assert_eq!(label, "tests/a.t read tests/b.t");
}

// I11: a bundle of an earlier generation is not used. Its generation is set to 1 after a pass: the next
// changed run takes the full form, and the one after starts a new pass. Fails on a tree whose generation
// stays 1: the old bundle is used, so the changed run starts a pass.
#[test]
fn i11_a_bundle_of_an_earlier_generation_is_not_used() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
    let path = s.bundle_path().expect("a suite bundle");
    let mut stored: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    stored["generation"] = Value::from(1);
    fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
    edit(&s, 3);
    s.clear_log();
    success(&s.hook(&[]));
    full_form(&s.launches());
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
}

// I12: a top-level name created during a's launch refuses a, even though a's launch wrote a top-level
// entry itself. That case is the one the identity check does not compare (the OwnEntries gap), so only
// the root guard refuses it. Fails on a tree without the root guard: a's proof is stored with a root
// listing that includes the new name.
#[test]
fn i12_a_top_level_name_created_during_a_launch_refuses_that_unit_even_when_the_launch_wrote_one() {
    let s = Suite::new();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    let top = s.root.join("top.out");
    let fifo = s.fifo();
    let child = spawn_hook(
        &s,
        &[
            ("T_LS_ROOT", "1"),
            ("T_WRITE", top.to_str().unwrap()),
            ("T_WRITE_AT", "tests/a.t"),
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/a.t"),
        ],
    );
    let writer = meet(&fifo);
    s.write("new.txt", "new\n");
    release(writer);
    let out = finish(child);
    success(&out);
    let err = text(&out.stderr);
    assert!(
        err.contains("stoop: not recorded for tests/a.t: . changed while the command ran"),
        "{err}"
    );
    assert!(
        bundle(&s)["units"].get("tests/a.t").is_none(),
        "{}",
        bundle(&s)
    );
    assert_eq!(state(&s)["status"], "ready");
}

// I14 (replaces E6): a disabled suite explains itself. Explain prints the tracked counts, then the
// decision that names the state and its label, in place of the refusal a silent roster gave before.
// Fails on a tree without the state: explain names the silent marker of this roster.
#[test]
fn i14_explain_names_a_disabled_suite_after_the_tracked_line() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    assert_eq!(code(&s.hook(&[("T_IGNORE", "1")])), 125);
    let id = suite_id(&s);
    edit(&s, 3);
    let out = explain_with(&s, &[]);
    let err = text(&out.stderr);
    assert_eq!(code(&out), 1, "{err}");
    let lines: Vec<&str> = err.lines().collect();
    let count = lines.len();
    assert!(
        lines[count - 2]
            .starts_with("stoop: tracked 3 units, 0 inputs; 0 proven, 3 without a proof (suite "),
        "{err}"
    );
    assert_eq!(
        lines[count - 1],
        format!(
            "stoop: no attribution pass: suite {id} disabled: tests/a.t exited 0 without reading it; run 'stoop forget --units {id}' after fixing it"
        ),
        "{err}"
    );
}
