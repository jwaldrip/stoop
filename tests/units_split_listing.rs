//! Listing excuses and changed inputs (spec 3.10 and 3.11; fix round 2 of PR 82). With `STOOP_SPLIT=1`, a change that adds
//! a name to a listing the whole proof holds is excused only for a regular file that an affected unit's stored proof
//! named (rv32, rv32b). Such a file must then be read by content by a new proof of the same run, or the run has no
//! verdict (rv34, rv34b, rv35). `STOOP_CHANGED_INPUTS` is unset above 64 KiB, and its file carries the list (rv31, rv31b).
//! The fixture runner gets review knobs at test time, so the fixture and every other test are unchanged. Linux x86-64
//! and arm64 only, like the other subset tests.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::{Output, Stdio};
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");
const RUNNER: &str = include_str!("fixtures/hook/t");
const CAT_SETUP: &str = "\tcat \"$ROOT/setup.src\"\n";
const NOTE_FILE: &str = "note \"changed_inputs_file=$(flat \"${STOOP_CHANGED_INPUTS_FILE:-}\")\"\n";

/// The fixture runner with four review knobs, inserted at its two fixed anchors:
/// - `T_LS_DIR` with `T_LS_AT=P`: test P lists `$ROOT/$T_LS_DIR`, so the listing is one of its reads.
/// - `T_READ_ABS` with `T_READ_ABS_AT=P`: unit P reads that absolute path by content when launched alone.
/// - `T_BIG_AT=P` with `T_BIG_DIR`: test P reads every file under that directory by content.
///
/// Every launch also logs whether `STOOP_CHANGED_INPUTS` is set (`changed_inputs_set`, empty when unset) and the text of
/// `STOOP_CHANGED_INPUTS_FILE` (`inputs_file_text`, newlines as `|`).
fn review_runner() -> String {
    assert_eq!(RUNNER.matches(CAT_SETUP).count(), 1, "the runner moved");
    assert_eq!(
        RUNNER.matches(NOTE_FILE).count(),
        1,
        "the runner's notes moved"
    );
    let knobs = concat!(
        "\tcat \"$ROOT/setup.src\"\n",
        "\tif [ -n \"${T_LS_DIR:-}\" ] && [ \"${T_LS_AT:-}\" = \"$1\" ]; then ls \"$ROOT/$T_LS_DIR\" > /dev/null; fi\n",
        "\tif [ \"$TESTS\" = 1 ] && [ -n \"${T_READ_ABS:-}\" ] && [ \"${T_READ_ABS_AT:-}\" = \"$1\" ]; then cat \"$T_READ_ABS\" > /dev/null; fi\n",
        "\tif [ -n \"${T_BIG_AT:-}\" ] && [ \"$T_BIG_AT\" = \"$1\" ] && [ -d \"${T_BIG_DIR:-/nonexistent}\" ]; then find \"$T_BIG_DIR\" -type f -exec cat {} + > /dev/null; fi\n",
        "\tif [ -n \"${T_STAT_REL:-}\" ] && [ \"${T_STAT_AT:-}\" = \"$1\" ]; then test -e \"$ROOT/$T_STAT_REL\"; fi\n",
    );
    let notes = concat!(
        "note \"changed_inputs_file=$(flat \"${STOOP_CHANGED_INPUTS_FILE:-}\")\"\n",
        "note \"changed_inputs_set=${STOOP_CHANGED_INPUTS+set}\"\n",
        "if [ -n \"${STOOP_CHANGED_INPUTS_FILE:-}\" ]; then note \"inputs_file_text=$(flat \"$(cat \"$STOOP_CHANGED_INPUTS_FILE\")\")\"; fi\n",
    );
    RUNNER.replace(CAT_SETUP, knobs).replace(NOTE_FILE, notes)
}

/// The default tree with the review runner, and without the runner-only `e2e/x.u`, so the tree alone decides each run.
fn review_suite() -> Suite {
    let s = Suite::new();
    s.executable("t", &review_runner());
    s.remove("e2e/x.u");
    s
}

fn success(out: &Output) {
    assert_eq!(code(out), 0, "{}", text(&out.stderr));
}

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// A change to the source that units `a` and `b` read.
fn edit(s: &Suite, n: usize) {
    s.write("src/shared.src", &"shared\n".repeat(n));
}

/// The pinned hook with the engine on, under `env`.
fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    let mut all = vec![SPLIT];
    all.extend_from_slice(env);
    s.hook(&all)
}

/// The line a cold run prints when its completion learns the three units (spec 3.12).
const COMPLETION_HEADER: &str =
    "stoop: attribution pass after the full run: 3 units, one launch each";

/// A cold run, then one change to the shared source and the subset run that launches the two units reading it, `a` and
/// `b`, under `env`. The cold run's completion learns every unit's proof, so this subset is the first changed run.
fn proven(s: &Suite, env: &[(&str, &str)]) {
    let cold = split(s, env);
    success(&cold);
    assert!(
        stderr(&cold).contains(COMPLETION_HEADER),
        "{}",
        stderr(&cold)
    );
    edit(s, 2);
    s.clear_log();
    let subset = split(s, env);
    success(&subset);
    assert_eq!(
        launched(s),
        ["tests/a.t", "tests/b.t"],
        "{}",
        stderr(&subset)
    );
    assert_eq!(category(&subset), "subset", "{}", stderr(&subset));
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

/// The arguments of each launch since the log was last cleared, one string per launch.
fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

/// The value the runner logged as `name=value` in one launch, or `None` when the launch logged no such line.
fn note<'a>(launch: &'a Launch, name: &str) -> Option<&'a str> {
    launch
        .lines
        .iter()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix('='))
}

/// What a run printed, by the decision line or header the engine prints: `skip`, `pass`, `subset`, `full`, or `none`.
fn category(out: &Output) -> &'static str {
    let log = stderr(out);
    if log.contains("stoop: skip ") {
        "skip"
    } else if log.contains("stoop: attribution pass: ")
        || log.contains("(attribution pass): ")
        || log.contains("would run an attribution pass: ")
    {
        "pass"
    } else if log.contains("inputs; run ") || log.contains(" units affected, one launch each)") {
        "subset"
    } else if log.contains("run full ") {
        "full"
    } else {
        "none"
    }
}

/// What `stoop explain` says a run will do, the run itself under `env`, and the direct full form's status.
struct Judged {
    said: &'static str,
    ran: Output,
    launches: Vec<String>,
    direct: i32,
}

/// Judges one run. Explain must write nothing and launch nothing. The direct full form gives the verdict the run must
/// match, and then the run itself is made.
fn judge(s: &Suite, env: &[(&str, &str)]) -> Judged {
    let before = s.store_snapshot();
    s.clear_log();
    let explained = explain(s, env);
    assert_eq!(s.store_snapshot(), before, "explain changed the store");
    assert!(s.launches().is_empty(), "explain launched");
    s.clear_log();
    let direct = code(&s.direct(&s.root, &[], env));
    s.clear_log();
    let ran = split(s, env);
    Judged {
        said: category(&explained),
        launches: launched(s),
        ran,
        direct,
    }
}

/// The run's verdict is the direct full form's, and explain names the category the run takes.
fn same_verdict(name: &str, judged: &Judged) {
    assert_eq!(
        code(&judged.ran) == 0,
        judged.direct == 0,
        "{name}: the run exits {} and the direct full form {}; launches {:?}\n{}",
        code(&judged.ran),
        judged.direct,
        judged.launches,
        stderr(&judged.ran)
    );
    assert_eq!(
        judged.said,
        category(&judged.ran),
        "{name}: explain and the run disagree\n{}",
        stderr(&judged.ran)
    );
}

/// `count` files of 70 bytes each under `big/`, each holding `body`.
fn big(s: &Suite, count: usize, body: &str) {
    let long = "y".repeat(60);
    for n in 0..count {
        s.write(&format!("big/{n:05}-{long}"), body);
    }
}

/// A file outside the root and outside every default-ignored folder: under the test process's own `HOME`. The suite's own
/// `HOME` is its outside folder, under the system temporary folder, which stoop ignores by default.
fn outside_root_file(name: &str) -> PathBuf {
    let home = PathBuf::from(std::env::var_os("HOME").expect("HOME"));
    assert!(
        !home.starts_with("/tmp") && !home.starts_with("/var/tmp") && !home.starts_with("/run"),
        "HOME {home:?} is default-ignored"
    );
    home.join(format!(".stoop-review82-{}-{name}", std::process::id()))
}

/// One unit's first version, decoded through the bundle's table: its stamp, its inputs and its outputs as (path, id).
type Decoded = (u64, Vec<(String, String)>, Vec<(String, String)>);

fn version_of(bundle: &Value, unit: &str) -> Option<Decoded> {
    let version = bundle["units"].get(unit)?.get(0)?;
    let table = bundle["table"].as_array()?;
    let decode = |key: &str| -> Vec<(String, String)> {
        let mut index = 0usize;
        version[key]
            .as_array()
            .map(|steps| {
                steps
                    .iter()
                    .enumerate()
                    .map(|(at, step)| {
                        let step = step.as_u64().unwrap() as usize;
                        index = if at == 0 { step } else { index + step };
                        (
                            table[index]["path"].as_str().unwrap().to_owned(),
                            table[index]["id"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    Some((
        version["created"].as_u64()?,
        decode("inputs"),
        decode("outputs"),
    ))
}

/// rv32: a name that an affected unit's stored proof named as absent becomes a directory with a failing runner-only test
/// inside. The listing of `tests` gained a directory that the whole proof never listed. Excusing it because a stale version
/// names it would hide the test, so the run takes the full form and fails like the direct command.
#[test]
fn rv32_a_new_directory_named_by_an_affected_units_stale_version_keeps_the_full_verdict() {
    let s = review_suite();
    let env = [
        ("T_U", "1"),
        ("T_LS_DIR", "tests/sub"),
        ("T_LS_AT", "tests/c.t"),
    ];
    proven(&s, &env);
    s.write("tests/sub/z.u", "src/c.src\n");
    s.write("tests/sub/z.flag", "fail\n");
    let judged = judge(&s, &env);
    assert_eq!(
        judged.direct, 1,
        "the full command runs tests/sub/z.u and fails"
    );
    assert_eq!(category(&judged.ran), "full", "{}", stderr(&judged.ran));
    same_verdict("rv32", &judged);
}

/// rv32b: as rv32, with a link to a regular file in place of the directory. A link is not a regular file, so the run takes
/// the full form.
#[test]
fn rv32b_a_link_named_by_an_affected_units_stale_version_keeps_the_full_form() {
    let s = review_suite();
    let env = [("T_LS_DIR", "tests/sub"), ("T_LS_AT", "tests/c.t")];
    proven(&s, &env);
    std::os::unix::fs::symlink("../src/c.src", s.path("tests/sub")).unwrap();
    let judged = judge(&s, &env);
    assert_eq!(category(&judged.ran), "full", "{}", stderr(&judged.ran));
    same_verdict("rv32b", &judged);
}

/// rv34: `c` named `tests/z.u` and `tests/z.flag`, both absent when the full command passed. Then `c` stops naming them and
/// both appear, and `z.u` is a failing runner-only test. `c` is affected, so its stored proof excuses both names, but its new
/// proof no longer reads them and no other unit reads them. Nothing covers them after the run, so the run has no verdict
/// (exit 125) and names the file. The next run takes the full form and fails like the direct command.
#[test]
fn rv34_a_name_that_no_new_proof_reads_is_no_verdict_and_names_the_file() {
    let s = review_suite();
    let env = [("T_U", "1")];
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    proven(&s, &env);
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let judged = judge(&s, &env);
    assert_eq!(
        judged.direct, 1,
        "the full command runs tests/z.u and fails"
    );
    assert_eq!(judged.launches, ["tests/c.t"], "{}", stderr(&judged.ran));
    assert_eq!(code(&judged.ran), 125, "{}", stderr(&judged.ran));
    assert!(
        stderr(&judged.ran).contains("this run has no verdict (exit 125)")
            && stderr(&judged.ran).contains("tests/z.u"),
        "{}",
        stderr(&judged.ran)
    );
    let next = judge(&s, &env);
    assert_eq!(category(&next.ran), "full", "{}", stderr(&next.ran));
    same_verdict("rv34-next", &next);
}

/// rv34b: as rv34, and `a` fails as well, through its flag. The status of a failing launch is the verdict, so the run exits
/// 1 and not 125.
#[test]
fn rv34b_a_failing_launch_wins_over_the_no_verdict() {
    let s = review_suite();
    let env = [("T_U", "1")];
    s.write("tests/a.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    proven(&s, &env);
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/a.flag", "fail\n");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let judged = judge(&s, &env);
    assert_eq!(
        judged.launches,
        ["tests/a.t", "tests/c.t"],
        "{}",
        stderr(&judged.ran)
    );
    assert_eq!(code(&judged.ran), 1, "{}", stderr(&judged.ran));
    assert!(
        !stderr(&judged.ran).contains("exit 125"),
        "{}",
        stderr(&judged.ran)
    );
    same_verdict("rv34b", &judged);
    assert_eq!(s.bundle().unwrap()["residue"]["state"], "none");
    s.write("tests/a.flag", "ok\n");
    let next = judge(&s, &env);
    assert_eq!(next.direct, 1);
    assert_eq!(category(&next.ran), "full", "{}", stderr(&next.ran));
    same_verdict("rv34b-next", &next);
}

/// An appearing runner-only test was named by `c`'s old proof. If `c` fails, that proof remains and the unchanged retry
/// must fail again. Once `c` passes after dropping or only statting the names, its replacement cannot excuse a skip.
#[test]
fn a_failing_excusing_unit_keeps_its_old_proof_until_a_lost_read_is_detected() {
    for mode in ["drop", "stat"] {
        let s = review_suite();
        if mode == "stat" {
            let runner = review_runner();
            let anchor = "cat \"$ROOT/$line\"";
            assert_eq!(runner.matches(anchor).count(), 1);
            let runner = runner.replace(
                anchor,
                "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
            );
            s.executable("t", &runner);
        }
        let env = [("T_U", "1")];
        s.write("tests/c.flag", "ok\n");
        s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
        proven(&s, &env);
        s.write(
            "tests/c.t",
            if mode == "stat" {
                "src/c.src\nstat:tests/z.flag\n"
            } else {
                "src/c.src\n"
            },
        );
        s.write("tests/c.flag", "fail\n");
        s.write("tests/z.u", "src/c.src\n");
        s.write("tests/z.flag", "fail\n");
        let first = judge(&s, &env);
        assert_eq!(first.direct, 1, "{mode}");
        assert_eq!(code(&first.ran), 1, "{mode}: {}", stderr(&first.ran));
        assert_eq!(first.launches, ["tests/c.t"], "{mode}");
        assert_ne!(s.bundle().unwrap()["residue"]["state"], "none", "{mode}");

        let retry = judge(&s, &env);
        assert_eq!(retry.direct, 1, "{mode}");
        assert_eq!(code(&retry.ran), 1, "{mode}: {}", stderr(&retry.ran));
        assert_eq!(retry.launches, ["tests/c.t"], "{mode}");

        s.write("tests/c.flag", "ok\n");
        let refusal = judge(&s, &env);
        assert_eq!(refusal.direct, 1, "{mode}");
        assert_eq!(code(&refusal.ran), 125, "{mode}: {}", stderr(&refusal.ran));
        assert_eq!(refusal.launches, ["tests/c.t"], "{mode}");
        assert_eq!(s.bundle().unwrap()["residue"]["state"], "none", "{mode}");

        let after_refusal = judge(&s, &env);
        assert_eq!(after_refusal.direct, 1, "{mode}");
        assert_eq!(
            category(&after_refusal.ran),
            "full",
            "{mode}: {}",
            stderr(&after_refusal.ran)
        );
        same_verdict(mode, &after_refusal);
    }
}

/// A unit that stats a changed input launches first, so its proof replaces its version and reaches the disk before the
/// run ends. The run is killed while its second unit holds, after that write and before the run settles. The next run
/// must not skip on the stat: the runner-only test reads the input's content and fails (PR 86 review round 3).
#[test]
fn a_kill_after_a_stat_only_replacement_leaves_the_residue_unknown() {
    let s = review_suite();
    // The cold run's residue must name nothing: `c` reads the runner-only test's file, `a` stats its flag, and `c`'s own
    // flag makes `c` run grep, which the full command reads too.
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    let env = [
        ("T_U", "1"),
        ("T_STAT_REL", "tests/z.flag"),
        ("T_STAT_AT", "tests/a.t"),
    ];
    proven(&s, &env);
    s.write("tests/z.flag", "fail\n");
    edit(&s, 3);
    let fifo = s.fifo();
    let fifo_text = fifo.display().to_string();
    let hold = [("T_FIFO", fifo_text.as_str()), ("T_FIFO_AT", "tests/b.t")];
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .env(SPLIT.0, SPLIT.1)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env.iter().chain(&hold) {
        command.env(name, value);
    }
    let mut child = spawning(|| command.spawn()).unwrap();
    let writer = meet(&fifo);
    child.kill().unwrap();
    child.wait().unwrap();
    drop(writer);
    let judged = judge(&s, &env);
    assert_eq!(
        judged.direct, 1,
        "the full command runs tests/z.u and fails"
    );
    same_verdict("kill", &judged);
}

/// rv35: `c` names `tests/z.u`, absent when the full command passed. When `z.u` appears and `c`'s new proof reads it by content,
/// the name is covered by that proof: the run is a subset with exit 0. The full form also runs `z.u` as a runner-only test,
/// which the subset does not (the covered-file gap in blind-spots).
#[test]
fn rv35_a_name_an_affected_unit_reads_is_covered_by_its_new_proof() {
    let s = review_suite();
    let env = [("T_U", "1")];
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    proven(&s, &env);
    s.write("tests/z.u", "src/c.src\n");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    assert_eq!(launched(&s), ["tests/c.t"], "{}", stderr(&out));
    assert_eq!(category(&out), "subset", "{}", stderr(&out));
    assert!(!stderr(&out).contains("no verdict"), "{}", stderr(&out));
}

/// rv31: a unit whose changed inputs are over 128 KiB, the kernel's limit for one environment string. The variable is unset
/// and the list file carries the whole list, so the launch starts and the run's verdict is the direct command's.
#[test]
fn rv31_a_unit_over_128_kib_of_changed_inputs_launches_with_the_file() {
    let s = review_suite();
    let env = [("T_BIG_AT", "tests/a.t"), ("T_BIG_DIR", "big")];
    big(&s, 3_000, "one");
    proven(&s, &env);
    big(&s, 3_000, "two");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{}", stderr(&out));
    assert_eq!(launches[0].args, ["tests/a.t"], "{}", stderr(&out));
    assert_eq!(
        note(&launches[0], "changed_inputs_set"),
        Some(""),
        "unset above 64 KiB"
    );
    let list = note(&launches[0], "inputs_file_text").expect("the list file is logged");
    assert!(list.len() > 128 * 1024, "the list is {} bytes", list.len());
    assert_eq!(
        list.split('|')
            .filter(|path| path.starts_with("big/"))
            .count(),
        3_000
    );
    assert_eq!(
        code(&s.direct(&s.root, &[], &env)),
        0,
        "the direct full command passes"
    );
}

/// rv31b: 100 KiB of changed inputs, between the 64 KiB bound and the kernel's 128 KiB limit. The variable is unset, so a bound
/// at 128 KiB fails here (spec 3.11 sets 64 KiB).
#[test]
fn rv31b_changed_inputs_between_64_and_128_kib_are_not_exported() {
    let s = review_suite();
    let env = [("T_BIG_AT", "tests/a.t"), ("T_BIG_DIR", "big")];
    big(&s, 1_500, "one");
    proven(&s, &env);
    big(&s, 1_500, "two");
    s.clear_log();
    let out = split(&s, &env);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{}", stderr(&out));
    assert_eq!(
        note(&launches[0], "changed_inputs_set"),
        Some(""),
        "unset above 64 KiB"
    );
    let list = note(&launches[0], "inputs_file_text").expect("the list file is logged");
    assert!(
        list.len() > 64 * 1024 && list.len() < 128 * 1024,
        "the list is {} bytes",
        list.len()
    );
    assert_eq!(
        list.split('|')
            .filter(|path| path.starts_with("big/"))
            .count(),
        1_500
    );
}

/// rv17 (K07): `STOOP_CHANGED_INPUTS` and its file name the changed inputs inside the root, sorted, and no path outside it.
/// Unit `a` reads a file under `HOME`, outside the root and outside every default-ignored folder. The file is an input of
/// `a`, changes with the run, and must never be listed.
#[test]
fn rv17_changed_inputs_are_sorted_root_relative_and_inside_the_root() {
    let s = review_suite();
    let abs = outside_root_file("rv17");
    fs::write(&abs, "one\n").unwrap();
    let abs_text = abs.to_str().unwrap().to_owned();
    let env = [
        ("T_READ_ABS", abs_text.as_str()),
        ("T_READ_ABS_AT", "tests/a.t"),
    ];
    s.write("src/zz.src", "zz\n");
    s.write("tests/a.t", "src/zz.src\nsrc/shared.src\n");
    proven(&s, &env);
    let (_, inputs, _) = version_of(&s.bundle().unwrap(), "tests/a.t").unwrap();
    assert!(
        inputs.iter().any(|(path, _)| path == &abs_text),
        "the outside file is not an input of a: {inputs:?}"
    );
    edit(&s, 3);
    s.write("src/zz.src", "zz changed\n");
    fs::write(&abs, "two\n").unwrap();
    s.clear_log();
    let out = split(&s, &env);
    let _ = fs::remove_file(&abs);
    success(&out);
    let launches = s.launches();
    assert_eq!(launches.len(), 2, "{}", stderr(&out));
    assert_eq!(launches[0].args, ["tests/a.t"]);
    assert_eq!(
        launches[0].env("changed_inputs"),
        "src/shared.src|src/zz.src"
    );
    assert_eq!(note(&launches[0], "changed_inputs_set"), Some("set"));
    assert_eq!(
        note(&launches[0], "inputs_file_text"),
        Some("src/shared.src|src/zz.src")
    );
    assert_eq!(launches[1].args, ["tests/b.t"]);
    assert_eq!(launches[1].env("changed_inputs"), "src/shared.src");
    assert_eq!(
        note(&launches[1], "inputs_file_text"),
        Some("src/shared.src")
    );
}

/// Writes `count` files under `big/` whose cwd-relative paths, joined by newlines, are exactly `total` bytes.
fn exact_big(s: &Suite, total: usize, count: usize, body: &str) -> Vec<String> {
    let budget = total - (count - 1);
    let (base, rem) = (budget / count, budget % count);
    (0..count)
        .map(|i| {
            let len = base + usize::from(i < rem);
            let mut name = format!("{i:05}");
            while name.len() < len - 4 {
                name.push('n');
            }
            let path = format!("big/{name}");
            assert_eq!(path.len(), len);
            s.write(&path, body);
            path
        })
        .collect()
}

/// A subset of `a` whose changed inputs are exactly `total` bytes. Returns the variable, the list file's text, whether the
/// variable was set, and the run's status.
fn changed_inputs_at(total: usize) -> (String, String, bool, i32) {
    let s = review_suite();
    let env = [("T_BIG_AT", "tests/a.t"), ("T_BIG_DIR", "big")];
    let paths = exact_big(&s, total, 640, "one\n");
    proven(&s, &env);
    for path in &paths {
        s.write(path, "two\n");
    }
    s.clear_log();
    let out = split(&s, &env);
    let launches = s.launches();
    assert_eq!(launches.len(), 1, "{}", stderr(&out));
    let set = note(&launches[0], "changed_inputs_set") == Some("set");
    let var = launches[0].env("changed_inputs").to_owned();
    let file = note(&launches[0], "inputs_file_text")
        .unwrap_or_default()
        .to_owned();
    (var, file, set, code(&out))
}

/// rv36: changed inputs of exactly 64 KiB are exported whole, and the list file carries them.
#[test]
fn rv36_changed_inputs_of_exactly_64_kib_are_exported() {
    let (var, file, set, status) = changed_inputs_at(65_536);
    assert_eq!(status, 0);
    assert!(set, "the variable is exported at exactly 64 KiB");
    assert_eq!(var.len(), 65_536);
    assert_eq!(file, var);
}

/// rv36b: one byte over 64 KiB leaves the variable unset, and the list file carries the whole list.
#[test]
fn rv36b_changed_inputs_one_byte_over_64_kib_leave_the_variable_unset() {
    let (var, file, set, status) = changed_inputs_at(65_537);
    assert_eq!(status, 0);
    assert!(!set, "the variable must be unset");
    assert!(var.is_empty());
    assert_eq!(file.len(), 65_537);
}

/// rv38: `c` names `tests/z.u` when the full command passed, so the name is absent. Then `c` stops naming it and only stats
/// it, and `z.u` appears as a failing runner-only test. A stat is not a read by content, so the run has no verdict (exit
/// 125) and names the file, where the full command fails.
#[test]
fn rv38_a_name_the_new_proof_only_stats_is_not_a_pass() {
    let s = review_suite();
    let env = [
        ("T_U", "1"),
        ("T_STAT_REL", "tests/z.u"),
        ("T_STAT_AT", "tests/c.t"),
    ];
    s.write("tests/z.flag", "fail\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    proven(&s, &env);
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/z.u", "src/c.src\n");
    let judged = judge(&s, &env);
    assert_eq!(
        judged.direct, 1,
        "the full command runs tests/z.u and fails"
    );
    assert_eq!(code(&judged.ran), 125, "{}", stderr(&judged.ran));
    assert!(
        stderr(&judged.ran).contains("tests/z.u"),
        "{}",
        stderr(&judged.ran)
    );
}

/// rv43: `c` reads `src/dead.src`, which the full run never read, then stops, while a new unit changes the listing of
/// `tests`. `src/dead.src` never appeared and the listing of `src` is unchanged, so no name is excused and the run is 0.
#[test]
fn rv43_a_unit_that_stops_reading_a_file_the_full_run_never_read_is_not_125() {
    let s = Suite::new();
    proven(&s, &[]);
    s.write("tests/c.t", "src/c.src\nsrc/dead.src\n");
    let first = judge(&s, &[]);
    same_verdict("rv43-first", &first);
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/d.t", "src/c.src\n");
    let judged = judge(&s, &[]);
    assert_eq!(judged.direct, 0);
    assert_eq!(
        code(&judged.ran),
        0,
        "a false no-verdict: {}",
        stderr(&judged.ran)
    );
}
