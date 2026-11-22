//! Root listing in unit proofs (spec W5b PR-2). An attribution pass stores a listed repository root
//! as the input `.` with a `dl:` id. Whole-command proofs never do (pin P10). These tests drive the
//! stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and arm64 only.
//! Each one states why it fails on a tree without the switch, or that it is a guard.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::path::Path;
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

/// The suite's one bundle, which every test here reads after a run.
fn bundle(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")
}

/// The inputs of a unit's first stored version, decoded through the bundle's table.
fn inputs_of(bundle: &Value, unit: &str) -> Vec<Value> {
    assert!(
        bundle["units"].get(unit).is_some(),
        "no proof for {unit}: {bundle}"
    );
    let table = bundle["table"].as_array().unwrap();
    let mut index = 0;
    bundle["units"][unit][0]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
        .map(|(at, step)| {
            let step = step.as_u64().unwrap() as usize;
            index = if at == 0 { step } else { index + step };
            table[index].clone()
        })
        .collect()
}

/// The id of the root input (`.`) in a unit's first stored version, if it has one.
fn root_id(bundle: &Value, unit: &str) -> Option<String> {
    inputs_of(bundle, unit)
        .iter()
        .find(|input| input["path"] == ".")
        .map(|input| input["id"].as_str().unwrap().to_owned())
}

/// The id the recorder gives the root's listing right now: `dl:` and the BLAKE3 of its entry names,
/// each preceded by its length, in byte order.
fn root_listing_id(root: &Path) -> String {
    let mut names: Vec<Vec<u8>> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().as_bytes().to_vec())
        .collect();
    names.sort();
    let mut hash = blake3::Hasher::new();
    for name in &names {
        hash.update(&(name.len() as u64).to_le_bytes());
        hash.update(name);
    }
    format!("dl:{}", hash.finalize().to_hex())
}

/// Every legacy proof of the suite lacks the root input.
fn legacy_proofs_have_no_root(s: &Suite) {
    let proofs = s.proofs();
    assert!(!proofs.is_empty());
    for proof in proofs {
        let inputs = proof["inputs"].as_array().unwrap();
        assert!(inputs.iter().all(|input| input["path"] != "."), "{proof}");
    }
}

/// `stoop forget --units <id>` for the suite's bundle, as A12 runs it.
fn forget_units(s: &Suite) {
    let id = s
        .bundle_path()
        .unwrap()
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut command = s.stoop(&s.root);
    command
        .args(["forget", "--root"])
        .arg(&s.root)
        .args(["--units", id.as_str()]);
    success(&spawning(|| command.output()).unwrap());
    assert!(s.bundle_path().is_none(), "the suite bundle is gone");
}

/// The pinned hook run through `root` rather than the suite's own path, from the suite's root.
fn run_at(s: &Suite, root: &Path, env: &[(&str, &str)]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(root)
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

// R1u: a listed root is recorded as `.` with the `dl:` id of its listing. A top-level name that
// appears, and then a new pass, give a different id, and each id is the listing the root has. Fails
// on a tree without the switch: no unit input is `.`.
#[test]
fn r1u_a_listed_root_is_recorded_as_dot_and_follows_the_top_level_names() {
    let s = Suite::new();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    let recorded = bundle(&s);
    let first = root_id(&recorded, "tests/a.t").expect("a root input");
    assert!(first.starts_with("dl:"), "{first}");
    assert_eq!(first, root_listing_id(&s.root));
    for unit in ROSTER {
        assert_eq!(
            root_id(&recorded, unit).as_deref(),
            Some(first.as_str()),
            "{unit}"
        );
    }
    legacy_proofs_have_no_root(&s);
    forget_units(&s);
    s.write("new.txt", "new\n");
    edit(&s, 3);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    full_form(&s.launches());
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    let second = root_id(&bundle(&s), "tests/a.t").expect("a root input");
    assert_ne!(second, first);
    assert_eq!(second, root_listing_id(&s.root));
}

// R2u: store activity between two passes leaves the root's listing unchanged. The store directory
// is already in the root when a pass runs, and only its contents change after that. Fails on a tree
// without the switch: no unit input is `.`.
#[test]
fn r2u_store_activity_between_passes_leaves_the_root_listing_unchanged() {
    let s = Suite::new();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    let first = root_id(&bundle(&s), "tests/a.t").expect("a root input");
    let before = s.store_snapshot();
    forget_units(&s);
    edit(&s, 3);
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    assert_ne!(
        s.store_snapshot(),
        before,
        "the store changed between the passes"
    );
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    let second = root_id(&bundle(&s), "tests/a.t").expect("a root input");
    assert_eq!(second, first);
    assert_eq!(second, root_listing_id(&s.root));
}

// R3u: a launch that only stats the root records no root input. T_STAT_ROOT stats the root and never
// lists it. This is a guard: it passes on a tree without the switch, and fails if a stat records `.`.
#[test]
fn r3u_a_stat_of_the_root_records_no_root_input() {
    let s = Suite::new();
    success(&s.hook(&[("T_STAT_ROOT", "1")]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_STAT_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    let bundle = bundle(&s);
    for unit in ROSTER {
        assert_eq!(root_id(&bundle, unit), None, "{unit}");
    }
    assert!(inputs_of(&bundle, "tests/a.t")
        .iter()
        .any(|input| input["path"] == "src/shared.src"));
}

// R5u: a root given through a symlink is canonical before the run, so its listing is `.`, as when
// the root is named directly. Fails on a tree without the switch: no unit input is `.`.
#[test]
fn r5u_a_root_given_through_a_symlink_records_dot() {
    let s = Suite::new();
    let link = s.root.parent().unwrap().join("root-link");
    symlink(&s.root, &link).unwrap();
    success(&run_at(&s, &link, &[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    s.clear_log();
    success(&run_at(&s, &link, &[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    assert_eq!(
        root_id(&bundle(&s), "tests/a.t"),
        Some(root_listing_id(&s.root))
    );
}

// R6u: a top-level name that appears during a's launch refuses a with the root as the changed key.
// That holds when the launch wrote no top-level entry itself (R7u covers that case). b and c launch
// after it, keep their proofs, and their `.` is the listing that includes the new name. Fails on a
// tree without the switch: a keeps its proof and the refusal line is missing.
#[test]
fn r6u_a_top_level_name_created_during_a_launch_refuses_that_unit() {
    let s = Suite::new();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    let fifo = s.fifo();
    let child = spawn_hook(
        &s,
        &[
            ("T_LS_ROOT", "1"),
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
    let bundle = bundle(&s);
    assert!(bundle["units"].get("tests/a.t").is_none(), "{bundle}");
    for unit in ["tests/b.t", "tests/c.t"] {
        assert_eq!(
            root_id(&bundle, unit),
            Some(root_listing_id(&s.root)),
            "{unit}"
        );
    }
}

// R7u: a launch that creates its own top-level name is not refused by that name. Every unit keeps a
// proof whose `.` is the listing the root has after the run, and a later pass that finds the name
// already there keeps the same id. Fails on a tree without the switch: no unit input is `.`.
#[test]
fn r7u_a_launch_that_creates_its_own_root_entry_keeps_a_stable_proof() {
    let s = Suite::new();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    let written = s.root.join("launch.out");
    let written = written.to_str().unwrap();
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1"), ("T_WRITE", written)]));
    one_per_unit(&s.launches(), &ROSTER);
    let recorded = bundle(&s);
    let first = root_id(&recorded, "tests/a.t").expect("a root input");
    assert_eq!(first, root_listing_id(&s.root));
    for unit in ROSTER {
        assert_eq!(
            root_id(&recorded, unit).as_deref(),
            Some(first.as_str()),
            "{unit}"
        );
    }
    forget_units(&s);
    edit(&s, 3);
    success(&s.hook(&[("T_LS_ROOT", "1"), ("T_WRITE", written)]));
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1"), ("T_WRITE", written)]));
    one_per_unit(&s.launches(), &ROSTER);
    assert_eq!(
        root_id(&bundle(&s), "tests/a.t").as_deref(),
        Some(first.as_str())
    );
}

// R8u: a `.stoopignore` pattern that matches the name `.` does not hide the root. The tracer keys the
// root as "" and drops it only when that key is ignored, and the recorder applies the same test. Fails
// on a tree without the switch: no unit input is `.`. Fails on a mutant that tests `.` instead: the
// root is then dropped.
#[test]
fn r8u_a_pattern_that_matches_dot_does_not_hide_the_root() {
    let s = Suite::new();
    s.write(".stoopignore", ".*\n");
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_LS_ROOT", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    assert_eq!(
        root_id(&bundle(&s), "tests/a.t"),
        Some(root_listing_id(&s.root))
    );
}
