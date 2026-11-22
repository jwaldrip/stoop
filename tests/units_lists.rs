//! List files of unit launches (spec 4.7 and 4.12, plan 3.7). A changed run of a suite whose hook
//! names its units through a list file, or through the environment, launches each unit once, and
//! the list that launch reads holds that unit. These tests drive the stoop binary and the list
//! runner below under the tracer, so they run on Linux x86-64 and arm64 only. Each test that is not
//! a guard fails on a tree without the list forms, for the reason its comment states.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use units_common::*;

/// The changed run's hook: every test of the tree outside `slow/`, named by a file list.
const FILE: &str = "{changed:**/*.t|!slow/**:file}";
/// The same units as a NUL-separated list.
const NUL: &str = "{changed:**/*.t|!slow/**:nul}";
/// The response-file form: the list's path behind an `@`.
const AT_FILE: &str = "@{changed:**/*.t|!slow/**:file}";

/// The list runner, run by each suite as `./list-runner`. POSIX sh, so it runs under dash. Each
/// launch logs what its list holds while it runs: the list's modes, its content and the unit it
/// names. It reads each unit a list names, and each input listed in that unit's file, which is the
/// evidence a unit proof needs. A unit whose `<unit>.flag` says fail fails. A word that is not a
/// list is a unit. With no unit words it runs every `tests/*.t`. LOG, outside the root, gets the
/// record.
const LIST_RUNNER: &str = r##"#!/bin/sh
ROOT=$(cd "$(dirname "$0")" && pwd -P) || exit 2
STATUS=0
HELD=

note() {
	printf '%s\n' "$1" >> "$LOG"
}

# The FIFO hold: one read per launch, at the unit named by T_FIFO_AT or at the first unit.
hold() {
	if [ -n "${T_FIFO:-}" ] && [ -z "$HELD" ]; then
		if [ -z "${T_FIFO_AT:-}" ] || [ "$T_FIFO_AT" = "$1" ]; then
			HELD=1
			read -r _ < "$T_FIFO" || true
		fi
	fi
}

run_unit() {
	note "ran=$1"
	if [ ! -f "$1" ]; then
		note "failed=$1"
		STATUS=1
		return
	fi
	cat "$1" > /dev/null
	while IFS= read -r line || [ -n "$line" ]; do
		if [ -n "$line" ]; then
			cat "$ROOT/$line" > /dev/null
		fi
	done < "$1"
	hold "$1"
	flag=${1%.*}.flag
	if [ -f "$flag" ] && grep -q fail "$flag"; then
		note "failed=$1"
		STATUS=1
	fi
}

list() {
	note "list=$1"
	note "list_dir_mode=$(stat -c %a "$(dirname "$1")")"
	note "list_mode=$(stat -c %a "$1")"
	note "list_newlines=$(tr -cd '\n' < "$1" | wc -c | tr -d ' ')"
	note "list_nuls=$(tr -cd '\000' < "$1" | wc -c | tr -d ' ')"
	note "list_units=$(tr '\n\000' '||' < "$1")"
	old_ifs=$IFS
	IFS='
'
	set -f
	for unit in $(tr '\000' '\n' < "$1"); do
		run_unit "$unit"
	done
	set +f
	IFS=$old_ifs
}

note launch
for word in "$@"; do
	note "arg=$word"
done
note "changed=$(printf '%s' "${STOOP_CHANGED:-}" | tr '\n' '|')"
note "units=$(printf '%s' "${STOOP_UNITS:-}" | tr '\n' '|')"
note "changed_file=${STOOP_CHANGED_FILE:-}"
note "changed_inputs=$(printf '%s' "${STOOP_CHANGED_INPUTS:-}" | tr '\n' '|')"
note "changed_inputs_file=${STOOP_CHANGED_INPUTS_FILE:-}"
note "parent=$(tr '\000' ' ' < "/proc/$PPID/cmdline" 2> /dev/null)"
if [ -n "${STOOP_CHANGED_FILE:-}" ] && [ -f "$STOOP_CHANGED_FILE" ]; then
	note "changed_file_dir_mode=$(stat -c %a "$(dirname "$STOOP_CHANGED_FILE")")"
	note "changed_file_mode=$(stat -c %a "$STOOP_CHANGED_FILE")"
	note "changed_file_content=$(tr '\n\000' '||' < "$STOOP_CHANGED_FILE")"
fi
if [ -n "${STOOP_CHANGED_INPUTS_FILE:-}" ] && [ -f "$STOOP_CHANGED_INPUTS_FILE" ]; then
	note "changed_inputs_file_bytes=$(wc -c < "$STOOP_CHANGED_INPUTS_FILE" | tr -d ' ')"
fi
if [ "${T_LS_ROOT:-}" = 1 ]; then
	note "root_scratch=$(ls -a "$ROOT" | grep -c scratch)"
fi

TESTS=0
for word in "$@"; do
	case $word in
		'' | -*) ;;
		*) TESTS=1 ;;
	esac
done
if [ "$TESTS" = 0 ]; then
	cd "$ROOT" || exit 2
	for unit in tests/*.t; do
		run_unit "$unit"
	done
	exit "$STATUS"
fi
for word in "$@"; do
	case $word in
		'' | -*) ;;
		*.scratch/*) list "${word#@}" ;;
		*) run_unit "$word" ;;
	esac
done
exit "$STATUS"
"##;

/// A suite with the list runner beside the fixture tree of `units_common`.
fn list_suite() -> Suite {
    let s = Suite::new();
    s.executable("list-runner", LIST_RUNNER);
    s
}

/// Makes `src/shared.src` hold `n` lines, a change for certain, as the attribution tests do.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

/// The value of the launch's `name=` line.
fn field<'a>(launch: &'a Launch, name: &str) -> &'a str {
    let prefix = format!("{name}=");
    launch
        .lines
        .iter()
        .find_map(|line| line.strip_prefix(prefix.as_str()))
        .unwrap_or_else(|| panic!("no {name} line in {:?}", launch.lines))
}

/// A cold run of `words` from `cwd` that records the suite, then the changed run of the same words.
fn changed_run(s: &Suite, cwd: &Path, words: &[&str], env: &[(&str, &str)]) -> Output {
    success(&s.run(cwd, &[], words, env));
    edit(s, 2);
    s.clear_log();
    s.run(cwd, &[], words, env)
}

/// The changed run of the list hook, started without waiting so that a test can act mid-launch.
fn spawn_list(s: &Suite, env: &[(&str, &str)]) -> Child {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./list-runner", FILE])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.spawn()).unwrap()
}

/// Where the suite store sits: the default `.stoop`, a store named `cache` inside the root, or a
/// store outside the root.
#[derive(Clone, Copy, Debug)]
enum Placement {
    Default,
    InRoot,
    Outside,
}

impl Placement {
    fn store(self, s: &Suite) -> PathBuf {
        match self {
            Placement::Default => s.root.join(".stoop"),
            Placement::InRoot => s.root.join("cache"),
            Placement::Outside => s.outside.join("store"),
        }
    }
}

/// The environment that selects a placement's store: none for the default.
fn store_env(placement: Placement, store: &str) -> Vec<(&'static str, &str)> {
    match placement {
        Placement::Default => Vec::new(),
        _ => vec![("STOOP_STORE", store)],
    }
}

/// The one suite bundle a store holds.
fn bundle_in(store: &Path) -> Value {
    let mut bundles: Vec<PathBuf> = fs::read_dir(store.join("units/v1"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    assert_eq!(bundles.len(), 1, "{bundles:?}");
    serde_json::from_slice(&fs::read(bundles.pop().unwrap()).unwrap()).unwrap()
}

/// The launch directories a store holds now: `.<suite>-<pid>-<n>.scratch` below its unit folder.
fn scratch_dirs(store: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(store.join("units/v1")) else {
        return Vec::new();
    };
    entries
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            name.starts_with('.') && name.ends_with(".scratch")
        })
        .collect()
}

/// The id of the suite the default store holds.
fn suite_id(s: &Suite) -> String {
    let bundle = s.bundle_path().expect("a suite bundle");
    bundle.file_stem().unwrap().to_str().unwrap().to_owned()
}

/// The input entries of a unit's first stored version, decoded through the bundle's table.
fn input_entries(bundle: &Value, unit: &str) -> Vec<Value> {
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
    input_entries(bundle, unit)
        .iter()
        .find(|input| input["path"] == ".")
        .map(|input| input["id"].as_str().unwrap().to_owned())
}

/// The id the recorder gives the root's listing right now: `dl:` and the BLAKE3 of its entry names,
/// each preceded by its length, in byte order.
fn root_listing_id(root: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
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

// A9: the list file of a unit launch is deleted when the launch returns, and it is never an input or
// an output of the unit. The store sits in the root under the default name, in the root under another
// name, or outside the root. Fails on a tree without the list forms: the changed run is the full
// command with one launch, so there is no list to delete.
#[test]
fn a9_the_list_file_is_deleted_and_never_an_input_with_the_default_store() {
    list_file_is_deleted_and_never_an_input(Placement::Default);
}

#[test]
fn a9_the_list_file_is_deleted_and_never_an_input_with_a_store_in_the_root() {
    list_file_is_deleted_and_never_an_input(Placement::InRoot);
}

#[test]
fn a9_the_list_file_is_deleted_and_never_an_input_with_a_store_outside_the_root() {
    list_file_is_deleted_and_never_an_input(Placement::Outside);
}

fn list_file_is_deleted_and_never_an_input(placement: Placement) {
    let s = list_suite();
    let store = placement.store(&s);
    let store_text = store.to_str().unwrap().to_owned();
    let env = store_env(placement, &store_text);
    let out = changed_run(&s, &s.root, &["./list-runner", FILE], &env);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 3, "{placement:?}: {launches:?}");
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.ran(), [unit], "{placement:?}: {launch:?}");
        assert_eq!(launch.args.len(), 1, "{placement:?}: {launch:?}");
        let list = Path::new(&launch.args[0]);
        assert!(list.starts_with(&store), "{placement:?}: {list:?}");
        assert!(
            !list.exists(),
            "{placement:?}: the list outlives its launch: {list:?}"
        );
    }
    assert!(
        scratch_dirs(&store).is_empty(),
        "{:?}",
        scratch_dirs(&store)
    );
    let bundle = bundle_in(&store);
    for unit in ROSTER {
        assert!(bundle["units"][unit][0].is_object(), "{unit}: {bundle}");
        assert_eq!(
            bundle["units"][unit][0]["outputs"],
            Value::Array(Vec::new())
        );
    }
    for input in bundle["table"].as_array().unwrap() {
        let path = input["path"].as_str().unwrap();
        assert!(
            !path.contains("units/v1") && !path.contains(".scratch"),
            "{placement:?}: {path}"
        );
    }
}

// A9 (negative control): an input whose folder has the store's name is still an input when the store
// is named `cache` inside the root. Fails on a mutant that matches the store's name anywhere: the
// changed run then has no list to read and no input for the unit that reads `src/cache/data.src`.
#[test]
fn a9_an_input_named_like_the_store_is_still_an_input() {
    let s = list_suite();
    s.write("src/cache/data.src", "data\n");
    s.write("tests/a.t", "src/cache/data.src\n");
    let store = s.root.join("cache");
    let store_text = store.to_str().unwrap().to_owned();
    let env = [("STOOP_STORE", store_text.as_str())];
    let out = changed_run(&s, &s.root, &["./list-runner", FILE], &env);
    success(&out);
    assert_eq!(s.launches().len(), 3, "{:?}", s.launches());
    let bundle = bundle_in(&store);
    let inputs: Vec<String> = input_entries(&bundle, "tests/a.t")
        .iter()
        .map(|input| input["path"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        inputs.contains(&"src/cache/data.src".to_owned()),
        "{inputs:?}"
    );
}

// A10 (file rows): each file form hands its unit's list to the launch. The file form names the list,
// the nul form names a NUL-separated list, and the at form is the response-file `@path`. Each list
// holds the unit in its own form, in a 0700 directory, with mode 0600. Fails on a tree without the
// list forms: the changed run is the full command with one launch.
#[test]
fn a10_each_file_form_gives_one_list_per_unit_in_its_own_form() {
    for (hook, nul, at) in [
        (FILE, false, false),
        (NUL, true, false),
        (AT_FILE, false, true),
    ] {
        let s = list_suite();
        let out = changed_run(&s, &s.root, &["./list-runner", hook], &[]);
        success(&out);
        let launches = s.launches();
        assert_eq!(launches.len(), 3, "{hook}: {launches:?}");
        for (launch, unit) in launches.iter().zip(ROSTER) {
            assert_eq!(launch.ran(), [unit], "{hook}: {launch:?}");
            let arg = &launch.args[0];
            assert_eq!(arg.starts_with('@'), at, "{hook}: {arg}");
            let list = Path::new(arg.trim_start_matches('@'));
            let folder = list.parent().unwrap();
            assert!(
                folder
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .ends_with(".scratch"),
                "{hook}: {folder:?}"
            );
            assert_eq!(field(launch, "list_dir_mode"), "700", "{hook}");
            assert_eq!(field(launch, "list_mode"), "600", "{hook}");
            assert_eq!(field(launch, "list_units"), format!("{unit}|"), "{hook}");
            if nul {
                assert_eq!(field(launch, "list_nuls"), "1", "{hook}");
                assert_eq!(field(launch, "list_newlines"), "0", "{hook}");
            } else {
                assert_eq!(field(launch, "list_nuls"), "0", "{hook}");
                assert_eq!(field(launch, "list_newlines"), "1", "{hook}");
            }
        }
    }
}

// A10 (parity): a list holds what the argv form passes from the same folder. From `tests`, the argv
// form passes `a.t`, and the list holds `a.t` for the same unit. Fails on a tree without the list
// forms: the list form's changed run is the full command.
#[test]
fn a10_a_list_holds_what_the_argv_form_passes_from_the_same_folder() {
    let argv = list_suite();
    let tests = argv.root.join("tests");
    let out = changed_run(
        &argv,
        &tests,
        &["../list-runner", "{changed:**/*.t|!slow/**}"],
        &[],
    );
    success(&out);
    let argv_launches = argv.launches();
    assert_eq!(argv_launches.len(), 3, "{argv_launches:?}");
    let listed = list_suite();
    let tests = listed.root.join("tests");
    let out = changed_run(&listed, &tests, &["../list-runner", FILE], &[]);
    success(&out);
    let listed_launches = listed.launches();
    assert_eq!(listed_launches.len(), 3, "{listed_launches:?}");
    for (argv_launch, listed_launch) in argv_launches.iter().zip(&listed_launches) {
        assert_eq!(argv_launch.args.len(), 1, "{argv_launch:?}");
        assert_eq!(
            field(listed_launch, "list_units"),
            format!("{}|", argv_launch.args[0]),
            "{listed_launch:?}"
        );
        assert_eq!(
            field(listed_launch, "changed_file_content"),
            format!("{}|", argv_launch.args[0]),
            "{listed_launch:?}"
        );
    }
}

// A10 (large list): a unit whose path is nearly as long as a unit may be is written to its list
// whole. Fails on a tree without the list forms: the changed run is the full command with one launch.
#[test]
fn a10_a_long_unit_path_is_written_whole_to_its_list() {
    let s = list_suite();
    let folders = vec!["y".repeat(200); 19].join("/");
    let long = format!("{folders}/x.t");
    assert!(long.len() > 3000, "{}", long.len());
    s.write(&long, "src/shared.src\n");
    let out = changed_run(&s, &s.root, &["./list-runner", FILE], &[]);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 4, "{launches:?}");
    let last = launches.last().unwrap();
    assert_eq!(last.ran(), [long.as_str()], "{last:?}");
    assert_eq!(field(last, "list_units"), format!("{long}|"));
}

// A5: a failing unit gets no proof, the other units keep theirs, every launch still runs, the
// invocation fails with the first nonzero status, and no launch directory outlives its launch.
// Fails on a tree without the list forms: the changed run is the full command with one launch.
#[test]
fn a5_a_failing_unit_leaves_no_launch_directory_and_the_invocation_fails() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    s.write("tests/b.flag", "fail\n");
    edit(&s, 2);
    s.clear_log();
    let out = s.run(&s.root, &[], &["./list-runner", FILE], &[]);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(launches.len(), 3, "{launches:?}");
    assert_eq!(launches[1].failed(), ["tests/b.t"], "{:?}", launches[1]);
    assert!(launches[0].failed().is_empty(), "{:?}", launches[0]);
    assert!(launches[2].failed().is_empty(), "{:?}", launches[2]);
    let store = s.root.join(".stoop");
    assert!(
        scratch_dirs(&store).is_empty(),
        "{:?}",
        scratch_dirs(&store)
    );
    let bundle = bundle_in(&store);
    assert!(bundle["units"]["tests/a.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"]["tests/c.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"].get("tests/b.t").is_none(), "{bundle}");
}

// A6: a kill during one unit's launch leaves that unit without a proof and its launch directory in
// the store. The next run takes the suite lock on its first-run form, and that clears the directory.
// Fails on a tree without the list forms: the held launch is the full command, and nothing is left.
#[test]
fn a6_a_killed_launch_leaves_its_directory_until_the_next_run_takes_the_lock() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    edit(&s, 2);
    s.clear_log();
    let fifo = s.fifo();
    let fifo_text = fifo.to_str().unwrap().to_owned();
    let mut child = spawn_list(
        &s,
        &[("T_FIFO", fifo_text.as_str()), ("T_FIFO_AT", "tests/b.t")],
    );
    let writer = meet(&fifo);
    child.kill().unwrap();
    drop(writer);
    finish(child);
    let store = s.root.join(".stoop");
    assert_eq!(scratch_dirs(&store).len(), 1, "{:?}", scratch_dirs(&store));
    let bundle = bundle_in(&store);
    assert!(bundle["units"]["tests/a.t"][0].is_object(), "{bundle}");
    assert!(bundle["units"].get("tests/b.t").is_none(), "{bundle}");
    s.clear_log();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    assert!(
        scratch_dirs(&store).is_empty(),
        "{:?}",
        scratch_dirs(&store)
    );
}

// A11: a run that finds the suite busy takes the full form, and it leaves the directory of the launch
// that holds the lock. Fails on a tree without the list forms: no pass ever asks for the lock, so the
// busy line is never printed.
#[test]
fn a11_a_busy_run_leaves_the_directory_of_the_launch_that_holds_the_lock() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    edit(&s, 2);
    let id = suite_id(&s);
    let store = s.root.join(".stoop");
    let lock = s
        .bundle_path()
        .unwrap()
        .with_file_name(format!("{id}.lock"));
    let holder = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&lock)
        .unwrap();
    holder.try_lock().unwrap();
    let held = store.join(format!("units/v1/.{id}-99999999-0.scratch"));
    fs::create_dir(&held).unwrap();
    fs::set_permissions(&held, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(held.join("changed"), "tests/a.t\n").unwrap();
    s.clear_log();
    let out = s.run(&s.root, &[], &["./list-runner", FILE], &[]);
    success(&out);
    let busy = format!("suite {id} is busy in another stoop; running the full command");
    assert!(text(&out.stderr).contains(&busy), "{}", text(&out.stderr));
    assert_eq!(s.launches().len(), 1, "{:?}", s.launches());
    assert!(
        held.join("changed").is_file(),
        "the holder's directory is cleared while the lock is held"
    );
    drop(holder);
}

// A9b: a leftover directory of a dead launch is removed when a pass takes the suite lock, and the pass
// runs as usual. Fails on a tree without the list forms: no pass runs, so nothing clears the leftover.
#[test]
fn a9b_a_leftover_directory_is_removed_when_a_pass_takes_the_lock() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    let id = suite_id(&s);
    let store = s.root.join(".stoop");
    let leftover = store.join(format!("units/v1/.{id}-99999999-1.scratch"));
    fs::create_dir(&leftover).unwrap();
    fs::set_permissions(&leftover, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(leftover.join("changed"), "tests/a.t\n").unwrap();
    edit(&s, 2);
    s.clear_log();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    assert_eq!(s.launches().len(), 3, "{:?}", s.launches());
    assert!(!leftover.exists(), "the leftover survives the pass");
    assert!(
        scratch_dirs(&store).is_empty(),
        "{:?}",
        scratch_dirs(&store)
    );
}

// A24: the launch directory is never a root entry, so a unit that lists the root records, after the
// pass, the same root listing that the root has. The store is the default `.stoop` or `cache` inside
// the root. Fails on a tree without the list forms: no unit has a root input, because no pass runs.
#[test]
fn a24_the_launch_directory_is_never_a_root_entry() {
    for placement in [Placement::Default, Placement::InRoot] {
        let s = list_suite();
        let store = placement.store(&s);
        let store_text = store.to_str().unwrap().to_owned();
        let mut env = store_env(placement, &store_text);
        env.push(("T_LS_ROOT", "1"));
        let out = changed_run(&s, &s.root, &["./list-runner", FILE], &env);
        success(&out);
        let launches = s.launches();
        assert_eq!(launches.len(), 3, "{placement:?}: {launches:?}");
        for launch in &launches {
            assert_eq!(
                field(launch, "root_scratch"),
                "0",
                "{placement:?}: {launch:?}"
            );
        }
        let bundle = bundle_in(&store);
        let first = root_id(&bundle, "tests/a.t").expect("a root input");
        assert_eq!(first, root_listing_id(&s.root), "{placement:?}");
        for unit in ROSTER {
            assert_eq!(
                root_id(&bundle, unit).as_deref(),
                Some(first.as_str()),
                "{placement:?}: {unit}"
            );
        }
    }
}

// A8 (guard): the first-run form of a list hook exports every hook variable empty, as it did before
// the list forms. Passes on a tree without them.
#[test]
fn a8_the_first_run_form_exports_every_hook_variable_empty() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
    for name in [
        "changed",
        "units",
        "changed_file",
        "changed_inputs",
        "changed_inputs_file",
    ] {
        assert_eq!(launches[0].env(name), "", "{name}");
    }
}

// A8 (guard): `{changed-inputs}` keeps the first-run form beside a list. Passes on a tree without the
// list forms, because a list hook never dispatches there.
#[test]
fn changed_inputs_keeps_the_first_run_form_beside_a_list() {
    let s = list_suite();
    let words = ["./list-runner", FILE, "{changed-inputs}"];
    success(&changed_run(&s, &s.root, &words, &[]));
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{launches:?}");
    assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
    assert_eq!(launches[0].env("changed"), "");
}

// A10 (guard): a list has no join, so a file form with one stays on the first-run form. Passes on a
// tree without the list forms, because a list hook never dispatches there.
#[test]
fn a_list_with_a_join_keeps_the_first_run_form() {
    let s = list_suite();
    let words = ["./list-runner", "{changed:**/*.t|!slow/**:file:comma}"];
    success(&changed_run(&s, &s.root, &words, &[]));
    assert_eq!(s.launches().len(), 1, "{:?}", s.launches());
}

/// The shell code of A15's hook. `exit $?` keeps `sh` from exec'ing the runner, so the runner's
/// parent is the shell and shows this code as written.
const ENV_CODE: &str = "./list-runner --list \"$STOOP_CHANGED_FILE\"; exit $?";

/// A15's suite: the environment-form hook is its match, and its roster is the tree's tests.
const ENV_SUITE: &str = "[[units.suite]]\nid = \"env\"\nmatch = ['sh', '-c', './list-runner --list \"$STOOP_CHANGED_FILE\"; exit $?', 'sh']\nunits = ['tests/**/*.t']\n";

// A15: an environment-form hook dispatches like any other. Its shell code reads `$STOOP_CHANGED_FILE`
// and no placeholder appears, so the changed run makes one launch per unit. Each launch exports its
// own unit and its own list, the launch's parent shows the shell code as written with no path put
// into it, and the inputs file is empty. Fails on a tree that refuses shell environment code: the
// changed run is the full command with one launch and no pass.
#[test]
fn a15_an_environment_form_hook_dispatches_per_unit_and_exports_values_without_substitution() {
    let s = list_suite();
    s.config(ENV_SUITE);
    let words = ["sh", "-c", ENV_CODE, "sh"];
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
    for (launch, unit) in launches.iter().zip(ROSTER) {
        assert_eq!(launch.env("changed"), unit, "{launch:?}");
        assert_eq!(launch.env("units"), unit, "{launch:?}");
        let list = launch.env("changed_file");
        assert_eq!(launch.args, ["--list", list], "{launch:?}");
        assert_eq!(
            field(launch, "list_units"),
            format!("{unit}|"),
            "{launch:?}"
        );
        assert_eq!(launch.ran(), [unit], "{launch:?}");
        let parent = field(launch, "parent");
        assert!(parent.contains("$STOOP_CHANGED_FILE"), "{launch:?}");
        assert!(!parent.contains(list), "{launch:?}");
        let inputs = launch.env("changed_inputs_file");
        assert!(inputs.ends_with("/inputs"), "{inputs}");
        assert_eq!(
            Path::new(inputs).parent(),
            Path::new(list).parent(),
            "{launch:?}"
        );
        assert_eq!(
            field(launch, "changed_inputs_file_bytes"),
            "0",
            "{launch:?}"
        );
        assert_eq!(launch.env("changed_inputs"), "", "{launch:?}");
    }
    let bundle = bundle_in(&s.root.join(".stoop"));
    for unit in ROSTER {
        assert!(bundle["units"][unit][0].is_object(), "{unit}: {bundle}");
    }
}

/// Explain of `words` from the suite's root. It reads the store and launches nothing.
fn explain_words(s: &Suite, words: &[&str]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .arg("--")
        .args(words);
    spawning(|| command.output()).unwrap()
}

// A13: explain predicts the pass that a list hook's changed run starts, with the same launch count.
// Once that pass has stored proofs, explain and a changed run both decline a pass. Fails on a tree
// without the list forms: explain names the form, the run takes the full command, and no pass starts.
#[test]
fn a13_explain_predicts_the_pass_a_list_hook_starts() {
    let s = list_suite();
    success(&s.run(&s.root, &[], &["./list-runner", FILE], &[]));
    edit(&s, 2);
    let explained = explain_words(&s, &["./list-runner", FILE]);
    assert_eq!(code(&explained), 1, "{}", text(&explained.stderr));
    let stderr = text(&explained.stderr);
    assert_eq!(
        stderr.lines().last().unwrap(),
        "stoop: would run an attribution pass: 3 launches",
        "{stderr}"
    );
    s.clear_log();
    let run = s.run(&s.root, &[], &["./list-runner", FILE], &[]);
    success(&run);
    assert!(
        text(&run.stderr).contains("stoop: attribution pass: 3 units, one launch each"),
        "{}",
        text(&run.stderr)
    );
    assert_eq!(s.launches().len(), 3, "{:?}", s.launches());
    let declined = explain_words(&s, &["./list-runner", FILE]);
    let stderr = text(&declined.stderr);
    assert_eq!(
        stderr.lines().last().unwrap(),
        "stoop: no attribution pass: a unit of the roster already has a proof",
        "{stderr}"
    );
    s.clear_log();
    edit(&s, 3);
    let again = s.run(&s.root, &[], &["./list-runner", FILE], &[]);
    success(&again);
    assert!(
        !text(&again.stderr).contains("stoop: attribution pass:"),
        "{}",
        text(&again.stderr)
    );
    assert_eq!(s.launches().len(), 1, "{:?}", s.launches());
}
