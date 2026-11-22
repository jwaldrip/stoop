//! Attribution passes (spec PR-1). A changed run of a hooked suite launches each unit of its roster
//! once, and a launch that exits 0 and read its own file stores that unit's proof. These tests
//! drive the stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and
//! arm64 only. Each one fails on a tree without the pass, for the reason its comment states.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use units_common::*;

/// A source edit that is a change for certain: the file's length follows `n`, so no two edits of
/// different `n` have the same size. The fixture's file starts as one copy, so `n` is at least 2.
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

/// The one launch of the full form: no test argument, an empty `changed=`, the whole roster.
fn full_form(launches: &[Launch]) {
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
    assert_eq!(launches[0].env("changed"), "");
    assert_eq!(launches[0].ran(), ROSTER);
}

/// The suite's one bundle, which every test here reads after a run.
fn bundle(s: &Suite) -> Value {
    s.bundle().expect("a suite bundle")
}

/// The suite's lock file, named by the bundle's suite id.
fn lock_file(s: &Suite) -> PathBuf {
    let bundle = s.bundle_path().expect("a suite bundle");
    let id = bundle.file_stem().unwrap().to_str().unwrap().to_owned();
    bundle.with_file_name(format!("{id}.lock"))
}

/// The input paths of a unit's first stored version, decoded through the bundle's table.
fn inputs_of(bundle: &Value, unit: &str) -> Vec<String> {
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
            table[index]["path"].as_str().unwrap().to_owned()
        })
        .collect()
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|word| (*word).to_owned()).collect()
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

/// A preload library whose `fork` fails once the marker holds data. Only the process named
/// `stoop` is affected, so the traced command and its shells run as they would without it.
const FORK_SHIM: &str = r#"
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

pid_t fork(void) {
    static pid_t (*real_fork)(void);
    if (!real_fork) real_fork = (pid_t (*)(void))dlsym(RTLD_NEXT, "fork");
    const char *marker = getenv("STOOP_TEST_FORK_MARKER");
    if (marker) {
        char exe[4096];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        struct stat st;
        if (n > 0) {
            exe[n] = 0;
            const char *name = strrchr(exe, '/');
            if (name && strcmp(name + 1, "stoop") == 0 && stat(marker, &st) == 0 && st.st_size > 0) {
                errno = EAGAIN;
                return -1;
            }
        }
    }
    return real_fork();
}
"#;

// A2: after an edit, a changed run launches each unit once, in roster order. Each launch that
// exits 0 and read its own file stores that unit's exact proof, and the legacy proofs stay as they
// were. Fails on a tree without the pass: the changed run is the full form, with no pass header.
#[test]
fn the_next_change_runs_one_launch_per_unit() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let proofs = s.proofs();
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[]);
    success(&out);
    assert!(
        text(&out.stderr).contains("stoop: attribution pass: 3 units, one launch each"),
        "{}",
        text(&out.stderr)
    );
    one_per_unit(&s.launches(), &ROSTER);
    let bundle = bundle(&s);
    assert_eq!(bundle["units"].as_object().unwrap().len(), 3, "{bundle}");
    for unit in ROSTER {
        assert_eq!(bundle["units"][unit].as_array().unwrap().len(), 1, "{unit}");
        assert_eq!(bundle["units"][unit][0]["exact"], true, "{unit}");
        assert_eq!(bundle["units"][unit][0]["source"]["kind"], "exit", "{unit}");
    }
    let a = inputs_of(&bundle, "tests/a.t");
    assert!(a.iter().any(|p| p == "src/shared.src"), "{a:?}");
    assert!(a.iter().any(|p| p == "setup.src"), "{a:?}");
    let c = inputs_of(&bundle, "tests/c.t");
    assert!(c.iter().any(|p| p == "src/c.src"), "{c:?}");
    assert!(!c.iter().any(|p| p == "src/shared.src"), "{c:?}");
    assert_eq!(s.proofs(), proofs, "the legacy proofs are unchanged");
}

// A3c: the unchanged run after a pass is the full form. W7 replaces this test by name. Fails on a
// tree without the pass: the changed run is one full launch, not one per unit.
#[test]
fn the_unchanged_run_after_a_pass_is_the_full_form() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
    s.clear_log();
    success(&s.hook(&[]));
    full_form(&s.launches());
}

// A4p: a Git feature-branch checkout without CI runs a pass. Only CI keeps the full form, so this
// is the same suite as the pinned P3 without its CI variable. Fails on a tree without the pass.
#[test]
fn a_feature_branch_checkout_without_ci_runs_a_pass() {
    let s = Suite::new();
    s.config("[units]\ndefault_branch = \"main\"\n");
    // Without this, stoop refuses every legacy proof in a repository, as the pins do.
    s.write(".stoopignore", ".git\n");
    s.git("work");
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
}

// A5: a unit whose launch fails gets no proof, the others keep theirs, every unit is launched,
// and the invocation fails. Fails on a tree without the pass: one full launch, not one per unit.
#[test]
fn a_failing_unit_gets_no_proof_and_the_invocation_fails() {
    let s = Suite::new();
    success(&s.hook(&[]));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[]);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    one_per_unit(&s.launches(), &ROSTER);
    let bundle = bundle(&s);
    assert!(bundle["units"]["tests/a.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"]["tests/c.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"].get("tests/b.t").is_none(), "{bundle}");
}

// A6: a SIGKILL during b's launch leaves a's proof on disk and no proof for b or c, and the suite
// lock is free once the process is gone. Fails on a tree without the pass: there is no unit proof.
#[test]
fn sigkill_during_a_launch_leaves_that_unit_unproven() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let fifo = s.fifo();
    let mut child = spawn_hook(
        &s,
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/b.t"),
        ],
    );
    let writer = meet(&fifo);
    child.kill().unwrap();
    child.wait().unwrap();
    drop(writer);
    let bundle = bundle(&s);
    assert!(bundle["units"]["tests/a.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"].get("tests/b.t").is_none(), "{bundle}");
    assert!(bundle["units"].get("tests/c.t").is_none(), "{bundle}");
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_file(&s))
        .unwrap();
    held.try_lock()
        .expect("the lock is free once the process is gone");
}

// A7: an edit made during a's launch leaves a unproven, with the exact reason, and b still gets a
// proof. Fails on a tree without the pass: the reason line names no unit.
#[test]
fn an_edit_during_a_unit_launch_leaves_that_unit_unproven() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.age("src/shared.src");
    let fifo = s.fifo();
    let child = spawn_hook(
        &s,
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/a.t"),
        ],
    );
    let writer = meet(&fifo);
    edit(&s, 5);
    release(writer);
    let out = finish(child);
    success(&out);
    let err = text(&out.stderr);
    assert!(
        err.contains(
            "stoop: not recorded for tests/a.t: src/shared.src changed while the command ran"
        ),
        "{err}"
    );
    let bundle = bundle(&s);
    assert!(bundle["units"].get("tests/a.t").is_none(), "{bundle}");
    assert!(bundle["units"]["tests/b.t"][0].is_object(), "{bundle}");
}

// A8: a unit launch exports its unit as STOOP_CHANGED and STOOP_UNITS, and leaves the other hook
// variables empty. From the tests folder, with the runner one level up, the unit is named relative
// to that folder. Fails on a tree without the pass: no launch carries a unit.
#[test]
fn attribution_launches_export_their_unit() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    let launches = s.launches();
    one_per_unit(&launches, &ROSTER);
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.env("changed"), unit);
        assert_eq!(launch.env("units"), unit);
        // The list file and the inputs file sit in this launch's own folder below the store, and
        // the folder is removed when the launch returns. Their content and mode are checked by
        // tests/units_lists.rs, because this runner logs only the paths.
        let id = bundle(&s)["suite"].as_str().unwrap().to_owned();
        let list = Path::new(launch.env("changed_file"));
        let folder = list.parent().unwrap();
        let store = fs::canonicalize(s.root.join(".stoop/units/v1")).unwrap();
        assert_eq!(folder.parent(), Some(store.as_path()), "{folder:?}");
        let folder_name = folder.file_name().unwrap().to_str().unwrap();
        assert!(folder_name.starts_with(&format!(".{id}-")), "{folder_name}");
        assert!(folder_name.ends_with(".scratch"), "{folder_name}");
        assert_eq!(list.file_name().unwrap(), "changed");
        assert_eq!(
            launch.env("changed_inputs_file"),
            folder.join("inputs").to_str().unwrap()
        );
        assert_eq!(launch.env("changed_inputs"), "");
    }

    let tests = s.root.join("tests");
    success(&s.run(&tests, &[], &["../t", HOOK], &[]));
    edit(&s, 3);
    s.clear_log();
    success(&s.run(&tests, &[], &["../t", HOOK], &[]));
    let launches = s.launches();
    assert_eq!(launches.len(), 3, "{launches:?}");
    for (launch, name) in launches.iter().zip(["a.t", "b.t", "c.t"]) {
        assert_eq!(launch.args, [name]);
        assert_eq!(launch.env("changed"), name);
    }
}

// A10i: each value form reaches the runner once per unit, with that form's own text. Each form has
// its own suite (the argv is part of the suite id), so each one takes a cold run and a change.
#[test]
fn value_forms_reach_the_runner_per_unit() {
    let s = Suite::new();
    let docs = s.root.join("docs");
    let root = fs::canonicalize(&s.root).unwrap();
    let abs = |unit: &str| root.join(unit).display().to_string();
    let check = |cwd: &Path, words: &[&str], n: usize, expected: Vec<Vec<String>>| {
        success(&s.run(cwd, &[], words, &[]));
        edit(&s, n);
        s.clear_log();
        // The runner may fail a test that it cannot find from this folder: only the arguments are
        // asserted here.
        s.run(cwd, &[], words, &[]);
        let launches = s.launches();
        assert_eq!(launches.len(), 3, "{words:?}: {launches:?}");
        for (launch, expected) in launches.iter().zip(&expected) {
            assert_eq!(&launch.args, expected, "{words:?}");
        }
    };
    check(
        &s.root,
        &["./t", "--files={changed:**/*.t|!slow/**}"],
        2,
        vec![
            args(&["--files=tests/a.t"]),
            args(&["--files=tests/b.t"]),
            args(&["--files=tests/c.t"]),
        ],
    );
    check(
        &s.root,
        &["./t", "-f", "{changed:each:**/*.t|!slow/**}"],
        3,
        vec![
            args(&["-f", "tests/a.t"]),
            args(&["-f", "tests/b.t"]),
            args(&["-f", "tests/c.t"]),
        ],
    );
    check(
        &docs,
        &["../t", "{changed:root:**/*.t|!slow/**}"],
        4,
        vec![
            args(&["tests/a.t"]),
            args(&["tests/b.t"]),
            args(&["tests/c.t"]),
        ],
    );
    check(
        &docs,
        &["../t", "{changed:abs:**/*.t|!slow/**}"],
        5,
        vec![
            args(&[abs("tests/a.t").as_str()]),
            args(&[abs("tests/b.t").as_str()]),
            args(&[abs("tests/c.t").as_str()]),
        ],
    );
}

// A11: a suite whose lock another stoop holds runs the full command, prints the busy line, and
// leaves its bundle as it was. Fails on a tree without the pass: there is no busy line.
#[test]
fn a_busy_suite_runs_the_full_command() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let before = s.bundle_bytes();
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_file(&s))
        .unwrap();
    held.try_lock().unwrap();
    let id = s
        .bundle_path()
        .unwrap()
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    s.clear_log();
    let out = s.hook(&[]);
    success(&out);
    let err = text(&out.stderr);
    assert!(
        err.contains(&format!(
            "stoop: suite {id} is busy in another stoop; running the full command"
        )),
        "{err}"
    );
    full_form(&s.launches());
    assert_eq!(
        s.bundle_bytes(),
        before,
        "the busy run left the bundle alone"
    );
    drop(held);
}

// A12: forget --units removes a suite's unit proofs. The changed run after that rebuilds the
// suite as the full form, and the next change starts a new pass. Fails on a tree without the pass
// at the first pass.
#[test]
fn forget_units_clears_unit_proofs() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
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
    edit(&s, 3);
    s.clear_log();
    success(&s.hook(&[]));
    full_form(&s.launches());
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
}

// A14: a {unit} placeholder launches once per unit, and each launch exports its unit. Fails on a
// tree without the pass: the changed run is one full launch.
#[test]
fn a_unit_placeholder_launches_once_per_unit() {
    let s = Suite::new();
    let words = ["./t", "{unit:**/*.t|!slow/**}"];
    success(&s.run(&s.root, &[], &words, &[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.run(&s.root, &[], &words, &[]));
    let launches = s.launches();
    one_per_unit(&launches, &ROSTER);
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.env("changed"), unit);
    }
}

// A16u: a bundle that cannot be read never starts a pass. The first half is the control: a
// readable bundle starts one, which fails on a tree without the pass. The second half is the
// unreadable bundle, which takes the full form.
#[test]
fn an_unreadable_bundle_never_starts_a_pass() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);

    let t = Suite::new();
    success(&t.hook(&[]));
    edit(&t, 2);
    let path = t.bundle_path().unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
    t.clear_log();
    success(&t.hook(&[]));
    full_form(&t.launches());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
}

// A18: a launch that exits 0 without reading its unit gets no proof, and the run says so. The
// test asserts neither the exit code nor the launch count, so it survives W6 unchanged. Fails on
// a tree without the pass: no unit launch says anything.
#[test]
fn a_launch_that_never_reads_its_unit_gets_no_proof() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_IGNORE", "1")]);
    let err = text(&out.stderr);
    assert!(
        err.contains("stoop: no proof for tests/a.t: the launch never read it"),
        "{err}"
    );
    assert_eq!(bundle(&s)["units"], json!({}));
}

// A18b: a stat of the unit is not evidence that the launch read it. Fails on a tree without the
// pass: no unit launch says anything.
#[test]
fn a_stat_of_its_unit_is_not_evidence() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.hook(&[("T_STAT_UNIT", "1")]);
    let err = text(&out.stderr);
    assert!(
        err.contains("stoop: no proof for tests/a.t: the launch never read it"),
        "{err}"
    );
    assert_eq!(bundle(&s)["units"], json!({}));
}

// A23: a unit launch prints no runner diagnostic, while the full form does. A `pytest` on the
// PATH is the fixture runner behind a wrapper with the registered name. Fails on a tree without the
// pass: the changed run is the full form, and it prints the diagnostic.
#[test]
fn unit_launches_print_no_runner_diagnostic() {
    let s = Suite::new();
    s.executable(
        "bin/pytest",
        &format!("#!/bin/sh\nexec '{}' \"$@\"\n", s.root.join("t").display()),
    );
    let path = format!("{}:/usr/bin:/bin", s.root.join("bin").display());
    let env = [("PATH", path.as_str())];
    let words = ["pytest", HOOK];
    let full = s.run(&s.root, &[], &words, &env);
    success(&full);
    assert!(
        text(&full.stderr).contains("stoop: observed pytest (diagnostic only)"),
        "{}",
        text(&full.stderr)
    );
    edit(&s, 2);
    s.clear_log();
    let out = s.run(&s.root, &[], &words, &env);
    success(&out);
    one_per_unit(&s.launches(), &ROSTER);
    let err = text(&out.stderr);
    assert!(!err.contains("observed pytest"), "{err}");
}

// A25: a launch the tracer cannot start runs untraced once. Its unit keeps no proof, a keeps
// its proof, and every unit runs exactly once. The shim fails stoop's own fork once the marker
// holds data, which a's launch writes. Fails on a tree without the pass: no unit is named.
#[test]
fn a_launch_that_cannot_be_traced_runs_untraced_once() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let source = s.outside.join("fork-shim.c");
    let library = s.outside.join("fork-shim.so");
    fs::write(&source, FORK_SHIM).unwrap();
    let built = spawning(|| {
        Command::new("cc")
            .args(["-shared", "-fPIC", "-o"])
            .arg(&library)
            .arg(&source)
            .arg("-ldl")
            .output()
    })
    .unwrap();
    assert!(built.status.success(), "{}", text(&built.stderr));
    let marker = s.outside.join("marker");
    s.clear_log();
    let out = s.run(
        &s.root,
        &[],
        &["./t", HOOK],
        &[
            ("LD_PRELOAD", library.to_str().unwrap()),
            ("STOOP_TEST_FORK_MARKER", marker.to_str().unwrap()),
            ("T_WRITE", marker.to_str().unwrap()),
        ],
    );
    let err = text(&out.stderr);
    assert!(err.contains("running tests/b.t without a proof"), "{err}");
    one_per_unit(&s.launches(), &ROSTER);
    let bundle = bundle(&s);
    assert!(bundle["units"]["tests/a.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"].get("tests/b.t").is_none(), "{bundle}");
}

// A20 (guard: passes on the base and must stay green). A filter that selects no unit never
// dispatches. Removing the three roster tests leaves only slow/s.t, which the pinned filter
// excludes, so the changed run is the full form with no roster and writes no unit proof.
#[test]
fn a_filter_that_selects_no_unit_never_dispatches() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let bundle_before = s.bundle_bytes();
    s.remove("tests/a.t");
    s.remove("tests/b.t");
    s.remove("tests/c.t");
    s.clear_log();
    let out = s.hook(&[]);
    success(&out);
    assert!(
        !text(&out.stderr).contains("attribution pass"),
        "{}",
        text(&out.stderr)
    );
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
    assert!(launches[0].ran().is_empty(), "{:?}", launches[0].lines);
    assert_eq!(launches[0].env("changed"), "");
    assert_eq!(s.bundle_bytes(), bundle_before, "no unit proof is written");
}

/// A21's suite: the shell hook is its match, and its roster is the tree's tests.
const SHELL_SUITE: &str = "[[units.suite]]\nid = \"shell\"\nmatch = ['sh', '-c', './t; s=$?; : \"$STOOP_CHANGED\"; exit $s', 'sh']\nunits = ['tests/**/*.t']\n";

// A21: a hook whose shell code reads $STOOP_CHANGED dispatches like any other hook. The changed run
// makes one launch per unit of the roster, and each launch exports its own unit, its own list file
// and an empty inputs file. Fails on a tree that refuses shell environment code: the changed run is
// the full command with one launch and no pass.
#[test]
fn a_shell_environment_hook_dispatches_per_unit() {
    let s = Suite::new();
    s.config(SHELL_SUITE);
    let words = ["sh", "-c", "./t; s=$?; : \"$STOOP_CHANGED\"; exit $s", "sh"];
    success(&s.run(&s.root, &[], &words, &[]));
    edit(&s, 2);
    s.clear_log();
    let out = s.run(&s.root, &[], &words, &[]);
    success(&out);
    assert!(
        text(&out.stderr).contains("attribution pass: 3 units, one launch each"),
        "{}",
        text(&out.stderr)
    );
    let launches = s.launches();
    assert_eq!(launches.len(), 3, "{launches:?}");
    let id = bundle(&s)["suite"].as_str().unwrap().to_owned();
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.env("changed"), unit);
        assert_eq!(launch.env("units"), unit);
        let list = Path::new(launch.env("changed_file"));
        let folder = list.parent().unwrap();
        let folder_name = folder.file_name().unwrap().to_str().unwrap();
        assert!(folder_name.starts_with(&format!(".{id}-")), "{folder_name}");
        assert_eq!(list.file_name().unwrap(), "changed");
        assert_eq!(
            launch.env("changed_inputs_file"),
            folder.join("inputs").to_str().unwrap()
        );
        assert_eq!(launch.env("changed_inputs"), "");
    }
    let bundle = bundle(&s);
    for unit in ROSTER {
        assert!(bundle["units"][unit][0].is_object(), "{unit}: {bundle}");
    }
}

/// The legacy key of the one proof file under `.stoop/proofs`.
fn legacy_key(s: &Suite) -> String {
    let mut keys: Vec<String> = fs::read_dir(s.root.join(".stoop/proofs"))
        .unwrap()
        .map(|entry| {
            let file: Value =
                serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap();
            file["key"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(keys.len(), 1, "{keys:?}");
    keys.pop().unwrap()
}

// A24: a pass that stores no proof leaves a marker for its roster, so the later changed runs of
// that roster take the full form until the roster changes or `forget --units` clears the suite.
// Fails on a tree without the marker: the second changed run starts a pass again. The unchanged
// run after the marker's full form skips, the end-to-end proof that the marker restores skipping.
#[test]
fn a_pass_that_stores_no_proof_is_not_repeated_for_the_same_roster() {
    let s = Suite::new();
    success(&s.hook(&[]));
    // The runner exits 0 without reading its units, so no unit gets a proof.
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[("T_IGNORE", "1")]));
    one_per_unit(&s.launches(), &ROSTER);
    assert!(bundle(&s)["units"].as_object().unwrap().is_empty());
    // The same roster, changed again: the full form, which records the whole command.
    edit(&s, 3);
    s.clear_log();
    success(&s.hook(&[("T_IGNORE", "1")]));
    full_form(&s.launches());
    // Unchanged after that full form: its whole-command proof is a hit, so nothing launches.
    s.clear_log();
    success(&s.hook(&[("T_IGNORE", "1")]));
    assert!(
        s.launches().is_empty(),
        "an unchanged run after the marker's full form skips"
    );
    // The runner reads its units now, but this roster stayed silent, so the full form still runs.
    edit(&s, 4);
    s.clear_log();
    success(&s.hook(&[]));
    full_form(&s.launches());
    // A new unit changes the roster, so the next change starts a pass again.
    s.write("tests/d.t", "src/shared.src\n");
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(
        &s.launches(),
        &["tests/a.t", "tests/b.t", "tests/c.t", "tests/d.t"],
    );
}

// A26: a unit launch captures no Git blob id, so a unit proof carries none, while the legacy proof
// of the same suite still records them. Fails on a tree without the cut: the unit proofs carry
// object ids.
#[test]
fn unit_proofs_carry_no_blob_ids_while_the_legacy_proof_keeps_them() {
    let s = Suite::new();
    s.write(".stoopignore", ".git\n");
    s.config("[units]\ndefault_branch = \"main\"\n");
    s.git("work");
    success(&s.hook(&[]));
    assert!(
        s.proofs().iter().any(|proof| proof["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|input| input["oid"].is_string())),
        "the legacy proof records a blob id in a Git root"
    );
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
    for input in bundle(&s)["table"].as_array().unwrap() {
        assert!(
            input["oid"].is_null(),
            "a unit proof carries a blob id: {input}"
        );
    }
}

// A27: `stoop forget <key>` removes the legacy proof and keeps the bundle, so the next change finds
// no legacy proof and takes the full form, not a pass. Passes on a tree that has the check.
#[test]
fn forgetting_the_legacy_proof_keeps_the_next_change_on_the_full_form() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let key = legacy_key(&s);
    let mut command = s.stoop(&s.root);
    command.args(["forget", "--root"]).arg(&s.root).arg(&key);
    success(&spawning(|| command.output()).unwrap());
    assert!(s.proofs().is_empty(), "the legacy proof is gone");
    assert!(s.bundle_path().is_some(), "the bundle stays");
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    full_form(&s.launches());
}

// A28: a suite that already holds unit proofs and is locked by another stoop starts no pass, so the
// changed run prints no busy line: nothing new is printed for a run that starts no pass. Passes on
// a tree that has the pre-check, and fails without it, because the busy line is printed then.
#[test]
fn a_proven_suite_locked_elsewhere_prints_no_busy_line() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    s.clear_log();
    success(&s.hook(&[]));
    one_per_unit(&s.launches(), &ROSTER);
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_file(&s))
        .unwrap();
    held.try_lock().unwrap();
    edit(&s, 3);
    s.clear_log();
    let out = s.hook(&[]);
    success(&out);
    assert!(!text(&out.stderr).contains("busy"), "{}", text(&out.stderr));
    full_form(&s.launches());
    drop(held);
}

/// M2 (ignored, a measurement). The milliseconds one attribution launch costs in a Git root and in
/// a plain directory, against the same runner run directly. `STOOP_BENCH_UNITS` sets the roster
/// size, from 3 to 4096. Run it in release:
/// `STOOP_BENCH_UNITS=1024 cargo test --release --test units_attribution attribution_pass_cost -- --ignored --nocapture`.
#[test]
#[ignore = "a measurement: STOOP_BENCH_UNITS=256 cargo test --release --test units_attribution attribution_pass_cost -- --ignored --nocapture"]
fn attribution_pass_cost() {
    let units: usize = std::env::var("STOOP_BENCH_UNITS")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(256);
    assert!(
        (3..=4096).contains(&units),
        "STOOP_BENCH_UNITS is 3 to 4096"
    );
    for git in [false, true] {
        let s = Suite::new();
        for index in 0..units - 3 {
            s.write(&format!("tests/u{index:05}.t"), "src/shared.src\n");
        }
        // The same configuration in both modes, so the Git root is the only difference.
        s.config("[units]\ndefault_branch = \"main\"\n");
        if git {
            s.write(".stoopignore", ".git\n");
            s.git("work");
        }
        success(&s.hook(&[]));
        edit(&s, 2);
        s.clear_log();
        let started = std::time::Instant::now();
        let out = s.hook(&[]);
        let pass = started.elapsed();
        success(&out);
        let launches = s.launches().len();
        assert_eq!(launches, units, "one traced launch per unit");
        let bundle = bundle(&s);
        let proven = bundle["units"]
            .as_object()
            .unwrap()
            .values()
            .filter(|versions| versions.as_array().is_some_and(|list| !list.is_empty()))
            .count();
        assert_eq!(proven, units, "every unit stored its proof");
        let mut names: Vec<String> = ROSTER.iter().map(|unit| unit.to_string()).collect();
        for index in 0..units - 3 {
            names.push(format!("tests/u{index:05}.t"));
        }
        let started = std::time::Instant::now();
        for name in &names {
            success(&s.direct(&s.root, &[name.as_str()], &[]));
        }
        let direct = started.elapsed();
        println!(
            "M2 git={git} units={units} launches={launches} proven={proven} pass_ms_per_launch={:.3} direct_ms_per_launch={:.3}",
            pass.as_secs_f64() * 1e3 / units as f64,
            direct.as_secs_f64() * 1e3 / units as f64,
        );
    }
}
