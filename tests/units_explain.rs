//! `stoop explain` for a hooked suite (spec 4.16). A suite with a filter gets two lines after the
//! decision explain already prints: the tracked counts, then whether a changed run would start an
//! attribution pass, or the reason it would not. Explain reads the store and takes no lock, so each
//! state checks that nothing is written, created or launched. The lines come from the Linux tracer,
//! so these tests run on Linux x86-64 and arm64 only.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::Output;
use units_common::*;

/// The words of the pinned hook, for `stoop explain` and for the explain of a changed run.
const PINNED: [&str; 2] = ["./t", HOOK];

/// The shell hook of the attribution tests: its match is `SHELL_WORDS`, and its roster is `tests/**/*.t`.
const SHELL_SUITE: &str = "[[units.suite]]\nid = \"shell\"\nmatch = ['sh', '-c', './t; s=$?; : \"$STOOP_CHANGED\"; exit $s', 'sh']\nunits = ['tests/**/*.t']\n";
const SHELL_WORDS: [&str; 4] = ["sh", "-c", "./t; s=$?; : \"$STOOP_CHANGED\"; exit $s", "sh"];

/// The pinned roster has three units, `tests/a.t`, `tests/b.t` and `tests/c.t`.
const TRACKED: usize = 3;

const NO_PASS_COLD: &str = "stoop: no attribution pass: no earlier run left a proof for this command, so the first run is the full command";
const NO_PASS_UNCHANGED: &str = "stoop: no attribution pass: the whole command's proof still holds";
const WOULD_PASS: &str = "stoop: would run an attribution pass: 3 launches";
const NO_PASS_PROVEN: &str = "stoop: no attribution pass: a unit of the roster already has a proof";
const NO_PASS_EVIDENCE: &str =
    "stoop: no attribution pass: the last pass stored no unit proof for this roster";
const NO_PASS_CI: &str = "stoop: no attribution pass: CI is set, so the run keeps the full command";
const NO_PASS_DISABLED: &str =
    "stoop: no attribution pass: splitting is turned off by enabled = false";
const NO_PASS_FORM: &str = "stoop: no attribution pass: the hook uses a form a single unit cannot stand for (a list file, {changed-inputs} or shell code)";
const NO_PASS_OPTIONS: &str = "stoop: no attribution pass: --no-record, --allow-network, --probe, --ignore or --ignore-env keeps the full command";
const NO_PASS_FORCED: &str = "stoop: no attribution pass: the run is forced to the full command";
const NO_PASS_OFF: &str =
    "stoop: no attribution pass: STOOP_OFF turns tracing off, so the run is the full command";
const NO_PASS_NO_BUNDLE: &str =
    "stoop: no attribution pass: the suite has no current record of an earlier full run";
const NO_PASS_NO_UNITS: &str = "stoop: no attribution pass: the filter selects no unit";
const NO_PASS_JOIN: &str =
    "stoop: no attribution pass: a unit's text contains the separator of a joined placeholder";
const NO_PASS_UNRECORDABLE: &str = "stoop: no attribution pass: the roster cannot be recorded: an argument is not UTF-8, a unit name is not valid, or there are more than 4,096 units";

/// Writes `n` copies of the line the pinned roster reads, so each `n` is a different size.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

fn err(out: &Output) -> String {
    text(&out.stderr)
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", err(out));
}

/// The last two lines of explain's output: the tracked counts, then the pass decision.
fn tail(out: &Output) -> (String, String) {
    let stderr = err(out);
    let lines: Vec<&str> = stderr.lines().collect();
    assert!(lines.len() >= 2, "{stderr}");
    (
        lines[lines.len() - 2].to_owned(),
        lines[lines.len() - 1].to_owned(),
    )
}

/// The suite ID that a tracked line names in its last parentheses.
fn id_of(tracked: &str) -> String {
    tracked
        .rsplit_once("(suite ")
        .and_then(|(_, rest)| rest.strip_suffix(')'))
        .unwrap_or_default()
        .to_owned()
}

/// Distinct inputs the suite's bundle knows: its table's length, and 0 with no bundle.
fn inputs(s: &Suite) -> usize {
    s.bundle()
        .map_or(0, |bundle| bundle["table"].as_array().unwrap().len())
}

/// The tracked line for `proven` of the three units, with the bundle's current input count.
fn tracked(s: &Suite, id: &str, proven: usize) -> String {
    format!(
        "stoop: tracked {TRACKED} units, {} inputs; {proven} proven, {} without a proof (suite {id})",
        inputs(s),
        TRACKED - proven
    )
}

fn lock_file(s: &Suite) -> PathBuf {
    let bundle = s.bundle_path().expect("a suite bundle");
    let id = bundle.file_stem().unwrap().to_str().unwrap().to_owned();
    bundle.with_file_name(format!("{id}.lock"))
}

/// `stoop explain --root <root> <options> -- <words>`, with `env` added.
fn explain_words(s: &Suite, words: &[&str], env: &[(&str, &str)], options: &[&str]) -> Output {
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(options)
        .arg("--")
        .args(words);
    for (name, value) in env {
        command.env(name, value);
    }
    spawning(|| command.output()).unwrap()
}

/// Every entry under `.stoop`, directories included, so a folder that explain creates is a change.
fn store_tree(s: &Suite) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut tree = BTreeMap::new();
    let mut pending = vec![s.root.join(".stoop")];
    while let Some(path) = pending.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let rel = path.strip_prefix(&s.root).unwrap().to_path_buf();
        if meta.is_dir() {
            tree.insert(rel, None);
            for entry in fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
        } else {
            tree.insert(rel, Some(fs::read(&path).unwrap()));
        }
    }
    tree
}

/// Explain in its current state, then the same checks every test makes: the store, every file and
/// folder in it, is byte-identical afterwards, and explain launched nothing.
fn explain_is_read_only(
    s: &Suite,
    words: &[&str],
    env: &[(&str, &str)],
    options: &[&str],
) -> Output {
    let tree = store_tree(s);
    let snapshot = s.store_snapshot();
    s.clear_log();
    let out = explain_words(s, words, env, options);
    assert_eq!(store_tree(s), tree, "explain changed the store");
    assert_eq!(s.store_snapshot(), snapshot, "explain changed a file");
    assert!(s.launches().is_empty(), "explain launched the runner");
    out
}

fn predicts_pass(explained: &Output) -> bool {
    tail(explained)
        .1
        .starts_with("stoop: would run an attribution pass:")
}

fn started_pass(run: &Output) -> bool {
    err(run).contains("stoop: attribution pass:")
}

// E1: a cold suite has no bundle and no proof. Explain names the first run, the counts are zero, and
// the first run's bundle carries the ID that explain printed.
#[test]
fn a_cold_suite_explains_the_first_run() {
    let s = Suite::new();
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    let id = id_of(&tracked_line);
    assert_eq!(tracked_line, tracked(&s, &id, 0));
    assert_eq!(decision, NO_PASS_COLD);
    success(&s.hook(&[]));
    let bundle = s.bundle_path().expect("the first run records a bundle");
    assert_eq!(bundle.file_stem().unwrap().to_str().unwrap(), id);
}

// E2: after a recorded full run, an unchanged tree is a whole-command proof hit. Explain says so, and
// exits 0 as it does for any skip.
#[test]
fn an_unchanged_recorded_suite_explains_the_proof_still_holds() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 0, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, NO_PASS_UNCHANGED);
}

// E3: after a recorded full run and an edit, the next changed run would start a pass: three launches,
// and no unit is proven yet.
#[test]
fn a_recorded_suite_after_a_change_predicts_the_pass() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, WOULD_PASS);
}

// E4: after the pass, three units are proven. Explain counts them and names the proof that keeps the
// full command: a unit already has one.
#[test]
fn a_suite_after_its_pass_counts_three_proven() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    success(&s.hook(&[]));
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    let id = id_of(&tracked_line);
    assert_eq!(tracked_line, tracked(&s, &id, TRACKED));
    assert!(inputs(&s) > 0, "the proofs name their inputs");
    assert_eq!(decision, NO_PASS_PROVEN);
}

// E5: a suite that another stoop holds is explained exactly as an unlocked one. Explain takes no
// lock, so it neither blocks nor reports the busy state, which only the run sees.
#[test]
fn explain_does_not_take_the_suite_lock() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let unlocked = explain_is_read_only(&s, &PINNED, &[], &[]);
    let held = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_file(&s))
        .unwrap();
    held.try_lock().unwrap();
    let locked = explain_is_read_only(&s, &PINNED, &[], &[]);
    drop(held);
    assert_eq!(code(&locked), 1, "{}", err(&locked));
    assert_eq!(
        tail(&locked),
        tail(&unlocked),
        "a held lock changes explain"
    );
    assert!(!err(&locked).contains("busy"), "{}", err(&locked));
    assert_eq!(tail(&locked).1, WOULD_PASS);
}

// E6: a pass that stored no unit proof leaves its roster marked. Explain names the marker, and the
// roster has no unit proof.
#[test]
fn a_silent_roster_is_explained_as_silent() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    success(&s.hook(&[("T_IGNORE", "1")]));
    assert!(s.bundle().unwrap()["units"].as_object().unwrap().is_empty());
    edit(&s, 3);
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, NO_PASS_EVIDENCE);
}

// E7: CI on a feature branch of a Git checkout keeps the full command, and the run agrees. A CI
// reader never starts a pass.
#[test]
fn explain_names_ci_on_a_feature_branch() {
    let s = Suite::new();
    s.config("[units]\ndefault_branch = \"main\"\n");
    s.write(".stoopignore", ".git\n");
    s.git("work");
    success(&s.hook(&[]));
    edit(&s, 2);
    let ci: [(&str, &str); 2] = [("CI", "true"), ("CI_COMMIT_BRANCH", "work")];
    let out = explain_is_read_only(&s, &PINNED, &ci, &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, NO_PASS_CI);
    let run = s.hook(&ci);
    success(&run);
    assert!(!started_pass(&run), "{}", err(&run));
}

// E8: splitting turned off, once for every level it can be turned off at. Explain names it, and the
// run takes the full form.
#[test]
fn explain_names_disabled_splitting_at_either_level() {
    for config in [
        "[units]\nenabled = false\n",
        "[[units.suite]]\nid = 'pinned'\nmatch = ['./t', '{changed:**/*.t|!slow/**}']\nunits = ['**/*.t']\nenabled = false\n",
    ] {
        let s = Suite::new();
        s.config(config);
        success(&s.hook(&[]));
        edit(&s, 2);
        let out = explain_is_read_only(&s, &PINNED, &[], &[]);
        assert_eq!(code(&out), 1, "{config}: {}", err(&out));
        let (tracked_line, decision) = tail(&out);
        assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0), "{config}");
        assert_eq!(decision, NO_PASS_DISABLED, "{config}");
        let run = s.hook(&[]);
        success(&run);
        assert!(!started_pass(&run), "{config}: {}", err(&run));
    }
}

// E9: a hook whose shell code reads $STOOP_CHANGED has a roster from config, and no unit form. Explain
// names the form, and the run takes the full command.
#[test]
fn explain_names_a_shell_environment_hook() {
    let s = Suite::new();
    s.config(SHELL_SUITE);
    success(&s.run(&s.root, &[], &SHELL_WORDS, &[]));
    edit(&s, 2);
    let out = explain_is_read_only(&s, &SHELL_WORDS, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, NO_PASS_FORM);
    let run = s.run(&s.root, &[], &SHELL_WORDS, &[]);
    success(&run);
    assert!(!started_pass(&run), "{}", err(&run));
}

// E10: the options, the forced full run and tracing turned off by STOOP_OFF keep a recorded, changed
// suite from a pass. Each names its own reason, nothing is written, and the run agrees.
#[test]
fn explain_names_options_forced_and_untraced_runs() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let out = explain_is_read_only(&s, &PINNED, &[], &["--no-record"]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert_eq!(tail(&out).1, NO_PASS_OPTIONS);
    let out = explain_is_read_only(&s, &PINNED, &[("STOOP_FULL", "1")], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert_eq!(tail(&out).1, NO_PASS_FORCED);
    let untraced: [(&str, &str); 1] = [("STOOP_OFF", "1")];
    let out = explain_is_read_only(&s, &PINNED, &untraced, &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    assert_eq!(tail(&out).1, NO_PASS_OFF);
    let run = s.hook(&untraced);
    success(&run);
    assert!(!started_pass(&run), "{}", err(&run));
}

// E11: a command with no placeholder names no suite, so explain prints neither line.
#[test]
fn a_plain_command_gets_no_suite_lines() {
    let s = Suite::new();
    success(&s.hook(&[]));
    edit(&s, 2);
    let out = explain_is_read_only(&s, &["./t"], &[], &[]);
    assert!(!err(&out).contains("(suite "), "{}", err(&out));
    assert!(!err(&out).contains("attribution pass"), "{}", err(&out));
}

// E12: explain agrees with the run it describes. Each step explains, then runs, and the run starts a
// pass exactly when explain said it would.
#[test]
fn explain_agrees_with_the_next_run_in_each_state() {
    let s = Suite::new();
    assert!(!predicts_pass(&s.explain()), "cold");
    assert!(!started_pass(&s.hook(&[])), "cold");
    edit(&s, 2);
    assert!(predicts_pass(&s.explain()), "changed");
    let run = s.hook(&[]);
    assert!(started_pass(&run), "changed: {}", err(&run));
    assert!(
        err(&run).contains("3 units, one launch each"),
        "{}",
        err(&run)
    );
    edit(&s, 3);
    assert!(!predicts_pass(&s.explain()), "proven");
    assert!(!started_pass(&s.hook(&[])), "proven");
    assert!(!predicts_pass(&s.explain()), "recorded again");
    assert!(!started_pass(&s.hook(&[])), "recorded again");
}

// E13: a suite whose bundle was forgotten has a legacy proof but no current record, so no pass can
// start. Explain names the missing record, and the run takes the full form.
#[test]
fn a_forgotten_suite_is_explained_as_having_no_record() {
    let s = Suite::new();
    success(&s.hook(&[]));
    let id = s
        .bundle_path()
        .unwrap()
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let mut forget = s.stoop(&s.root);
    forget
        .args(["forget", "--root"])
        .arg(&s.root)
        .args(["--units", id.as_str()]);
    success(&spawning(|| forget.output()).unwrap());
    assert!(s.bundle_path().is_none(), "the suite bundle is gone");
    edit(&s, 2);
    let out = explain_is_read_only(&s, &PINNED, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(
        tracked_line,
        format!("stoop: tracked {TRACKED} units, 0 inputs; 0 proven, {TRACKED} without a proof (suite {id})")
    );
    assert_eq!(decision, NO_PASS_NO_BUNDLE);
    let run = s.hook(&[]);
    success(&run);
    assert!(!started_pass(&run), "{}", err(&run));
}

// E14: a filter that selects no unit leaves an empty roster. Explain counts zero units and names the
// filter, and the run takes the full command.
#[test]
fn a_filter_that_selects_no_unit_is_explained() {
    let s = Suite::new();
    let words = ["./t", "{changed:*.none}"];
    success(&s.run(&s.root, &[], &words, &[]));
    let out = explain_is_read_only(&s, &words, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    let id = id_of(&tracked_line);
    assert_eq!(
        tracked_line,
        format!("stoop: tracked 0 units, 0 inputs; 0 proven, 0 without a proof (suite {id})")
    );
    assert_eq!(decision, NO_PASS_NO_UNITS);
    success(&s.run(&s.root, &[], &words, &[]));
}

// E15: a unit whose name holds the separator of a joined placeholder cannot be one launch's word.
// Explain names it, and the run takes the full form.
#[test]
fn a_unit_with_a_join_separator_is_explained() {
    let s = Suite::new();
    s.write("tests/x,y.t", "src/shared.src\n");
    let words = ["./t", "{changed:**/*.t|!slow/**:comma}"];
    success(&s.run(&s.root, &[], &words, &[]));
    edit(&s, 2);
    let out = explain_is_read_only(&s, &words, &[], &[]);
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    let id = id_of(&tracked_line);
    assert_eq!(
        tracked_line,
        format!("stoop: tracked 4 units, 0 inputs; 0 proven, 4 without a proof (suite {id})")
    );
    assert_eq!(decision, NO_PASS_JOIN);
    let run = s.run(&s.root, &[], &words, &[]);
    success(&run);
    assert!(!started_pass(&run), "{}", err(&run));
}

// E16: an argument that is not UTF-8 cannot be written to a bundle, so no roster is recordable.
// Explain names the refusal, and writes nothing.
#[test]
fn an_argument_that_is_not_utf8_is_explained_as_unrecordable() {
    let s = Suite::new();
    let tree = store_tree(&s);
    let mut command = s.stoop(&s.root);
    command
        .args(["explain", "--root"])
        .arg(&s.root)
        .args(["--", "./t"])
        .arg(OsStr::from_bytes(b"\xff"))
        .arg(HOOK);
    let out = spawning(|| command.output()).unwrap();
    assert_eq!(code(&out), 1, "{}", err(&out));
    let (tracked_line, decision) = tail(&out);
    assert_eq!(tracked_line, tracked(&s, &id_of(&tracked_line), 0));
    assert_eq!(decision, NO_PASS_UNRECORDABLE);
    assert_eq!(store_tree(&s), tree, "explain changed the store");
}
