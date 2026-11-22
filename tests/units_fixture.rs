//! The fake hook runner `tests/fixtures/hook/t` is checked knob by knob (F1-F4 and F6-F12). Pins
//! P1-P11 hold today's hooked-run behaviour: each condition that keeps the full form after the
//! attribution pass. F5 checks the purity rule. The runner tests need a POSIX shell; the pins and
//! F5 need the tracer, so they run on Linux x86-64 and arm64.
//!
//! # The runner's contract (spec 3.2 and 3.6)
//!
//! The runner header points here. Change the runner and this table together. A row marked (IF)
//! acts while `T_IF` is unset or names a path that exists; with `T_IF` set to an absent path it
//! does nothing. The `T_IF` path lives outside the root, under `/tmp`, because the `T_*` variables
//! are fingerprinted and cannot change partway through a sequence of runs.
//!
//! | Input | Behaviour |
//! | --- | --- |
//! | no test word (no argument, or only words starting with `-`) | Runs every `*.t` under the root except `slow/`, plus every `*.u` when `T_U=1`, in `LC_ALL=C` sort order, listed by `find`, `sed` and `sort`. With `T_LINT=1` it first executes `<root>/lint`. |
//! | test words | Words starting with `-` are logged only. Every other word is a test path relative to the cwd, run in order. Before the first test it runs `find /dev/null -prune`, `sed -n q` and `LC_ALL=C sort` on empty input: the programs the no-argument form runs to list its roster. So a unit launch traces every program the full form runs (purity). `lint` is the exception, and it is residue by design. |
//! | running test P | With `T_WRITE_AT=P` (IF) and `T_WRITE` set, `written` goes to `T_WRITE` right before `cat P`. Then `cat P`. Then `cat <root>/<line>` for each non-empty line of P. Then `cat <root>/setup.src`. With `T_WRITE_EACH=1`, `written` goes to `${P%.*}.out` after those reads. Then the FIFO hold, if armed. Then the test fails if `${P%.*}.flag` contains `fail`, or, in the test-word form, if `T_FAIL_ALONE=P` (IF). Logs `ran=P`, and `failed=P` on failure. A missing P fails the test. |
//! | `T_IGNORE=1` | With test words: reads nothing and exits 0. The no-argument form is unaffected. |
//! | `T_STAT_UNIT=1` | With test words: `test -e P` instead of running it. Logs `statted=P`. |
//! | `T_FIFO=<path>`, `T_FIFO_AT=<P>` | One `read < $T_FIFO` per invocation, after the first test (or after the test logged as `T_FIFO_AT`) has read its files. |
//! | `T_IF=<path>` | The toggle for the rows marked (IF). |
//! | `T_WRITE=<path>` (IF) | Writes `written` to that path once per invocation, before any test, unless `T_WRITE_AT` is set (then see the running-test row). |
//! | `T_WRITE_AT=<P>` (IF) | Narrows `T_WRITE` to the invocation that runs test P, written right before P's reads. |
//! | `T_WRITE_EACH=1` | Each test P writes `written` to `${P%.*}.out` after its reads, in every invocation that runs it. Not (IF). |
//! | `T_WRITE_FULL=<path>` | The no-argument form writes `written` to the path after it moves to the root and before its first test, so a relative path is root-relative. Not (IF). |
//! | `T_READ_OTHER=<path>` (IF) | Reads that path once per invocation, relative to the cwd. |
//! | `T_STAT_OTHER=<path>` (IF) | Runs `test -e <path>` once per invocation, relative to the cwd, and logs `stat_other=<path>`. The answer does not change the exit status. |
//! | `T_FAIL_FULL=1` (IF) | The no-argument form exits 1 after its tests. |
//! | `T_FAIL_ALONE=<P>` (IF) | In the test-word form, test P fails after it has run. Its reads and the other tests are unchanged. |
//! | `T_LS_ROOT=1` / `T_STAT_ROOT=1` | `ls -a <root>` (logs `ls_root`) / `test -d <root>` (logs `stat_root`), once per invocation. |
//! | `LOG=<path>` (outside the root) | Per invocation it logs `launch`, then `arg=<w>` for each argument, then `changed=`, `units=`, `changed_file=`, `changed_inputs=`, `changed_inputs_file=` (newlines inside a value logged as `\|`), then the per-test lines. |
//! | exit | 1 if any test failed, else 0. |
//!
//! `T_RECORDS` comes in W8 and writes to `$STOOP_RESULT_FILE`.
//!
//! Tree (built by `Suite::new`): `tests/a.t` and `tests/b.t` contain `src/shared.src`;
//! `tests/c.t` contains `src/c.src`; `e2e/x.u` contains `src/shared.src`; `slow/s.t` contains
//! `src/c.src`; plus `setup.src`, `src/{shared,c,dead}.src`, `docs/readme.md` and `lint`.
//! The root and the outside directory both live under `temp_dir()`, where ignores never apply.
#![cfg(unix)]

mod units_common;

use std::fs;
use std::process::Stdio;
use units_common::*;

// The runner, run directly: order, arguments, the environment log, and each knob.

#[test]
fn f1_no_arguments_runs_every_t_except_slow_in_c_order() {
    let s = Suite::new();
    s.write("tests/Z.t", "src/c.src\n");
    let out = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(launches.len(), 1);
    assert!(launches[0].args.is_empty());
    assert_eq!(
        launches[0].ran(),
        ["tests/Z.t", "tests/a.t", "tests/b.t", "tests/c.t"]
    );

    // The same list from another cwd: the runner lists its own root.
    s.clear_log();
    let out = s.direct(&s.root.join("docs"), &[], &[]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        s.launches()[0].ran(),
        ["tests/Z.t", "tests/a.t", "tests/b.t", "tests/c.t"]
    );

    // T_U adds every *.u, in the same order.
    s.clear_log();
    let out = s.direct(&s.root, &[], &[("T_U", "1")]);
    assert_eq!(code(&out), 0);
    assert_eq!(
        s.launches()[0].ran(),
        [
            "e2e/x.u",
            "tests/Z.t",
            "tests/a.t",
            "tests/b.t",
            "tests/c.t"
        ]
    );
}

/// A non-C UTF-8 locale this platform has, if any. `C.UTF-8` collates by code point, the same
/// as `C`, so it cannot show a sort that ignores `LC_ALL=C`; only en_US does.
fn en_us_locale() -> Option<&'static str> {
    let out = spawning(|| std::process::Command::new("locale").arg("-a").output()).ok()?;
    let names = text(&out.stdout);
    ["en_US.UTF-8", "en_US.utf8"]
        .into_iter()
        .find(|candidate| names.lines().any(|line| line == *candidate))
}

#[test]
fn f1_a_non_c_locale_does_not_change_the_c_order() {
    let Some(locale) = en_us_locale() else {
        eprintln!("skipped: no en_US UTF-8 locale on this platform (locale -a)");
        return;
    };
    let s = Suite::new();
    s.write("tests/Z.t", "src/c.src\n");
    let out = s.direct(&s.root, &[], &[("LC_ALL", locale)]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(
        s.launches()[0].ran(),
        ["tests/Z.t", "tests/a.t", "tests/b.t", "tests/c.t"]
    );
}

#[test]
fn f2_arguments_run_relative_to_the_cwd_and_log_the_environment() {
    let s = Suite::new();
    let out = s.direct(
        &s.root.join("tests"),
        &["a.t", "-x", "../tests/b.t"],
        &[
            ("STOOP_CHANGED", "tests/a.t"),
            ("STOOP_UNITS", "tests/a.t\ntests/b.t"),
            ("STOOP_CHANGED_FILE", "/tmp/changed"),
            ("STOOP_CHANGED_INPUTS", "src/shared.src\nsetup.src"),
            ("STOOP_CHANGED_INPUTS_FILE", "/tmp/inputs"),
        ],
    );
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(launches.len(), 1);
    let launch = &launches[0];
    assert_eq!(launch.args, ["a.t", "-x", "../tests/b.t"]);
    // A word starting with '-' is logged, never run.
    assert_eq!(launch.ran(), ["a.t", "../tests/b.t"]);
    let head: Vec<&str> = launch.lines.iter().take(8).map(String::as_str).collect();
    assert_eq!(
        head,
        [
            "arg=a.t",
            "arg=-x",
            "arg=../tests/b.t",
            "changed=tests/a.t",
            "units=tests/a.t|tests/b.t",
            "changed_file=/tmp/changed",
            "changed_inputs=src/shared.src|setup.src",
            "changed_inputs_file=/tmp/inputs",
        ]
    );

    // Unset variables log as empty lines.
    s.clear_log();
    let out = s.direct(&s.root, &["tests/a.t"], &[]);
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    let launch = &launches[0];
    assert_eq!(launch.args, ["tests/a.t"]);
    assert_eq!(launch.ran(), ["tests/a.t"]);
    for name in [
        "changed",
        "units",
        "changed_file",
        "changed_inputs",
        "changed_inputs_file",
    ] {
        assert_eq!(launch.env(name), "", "{name}");
        assert!(launch.lines.contains(&format!("{name}=")), "{name}");
    }
}
#[test]
fn f2_dash_words_alone_take_the_no_argument_form() {
    let s = Suite::new();
    let out = s.direct(&s.root, &["-v"], &[]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(launches[0].args, ["-v"]);
    assert_eq!(launches[0].ran(), ROSTER);

    // A dash word beside a test word runs only the test.
    s.clear_log();
    let out = s.direct(&s.root, &["-v", "tests/a.t"], &[]);
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    assert_eq!(launches[0].args, ["-v", "tests/a.t"]);
    assert_eq!(launches[0].ran(), ["tests/a.t"]);

    // The same holds for each knob that depends on whether a test word is present.
    for (name, value) in [("T_IGNORE", "1"), ("T_STAT_UNIT", "1")] {
        s.clear_log();
        let out = s.direct(&s.root, &["-v"], &[(name, value)]);
        assert_eq!(code(&out), 0, "{name}");
        assert_eq!(s.launches()[0].ran(), ROSTER, "{name}");
    }
    // Lint runs before the roster for a dash-only invocation too.
    s.executable("lint", "#!/bin/sh\nprintf 'linted\\n' >> \"$LOG\"\n");
    s.clear_log();
    let out = s.direct(&s.root, &["-v"], &[("T_LINT", "1")]);
    assert_eq!(code(&out), 0);
    let lines = &s.launches()[0].lines;
    let linted = lines
        .iter()
        .position(|line| line == "linted")
        .expect("lint ran");
    let first = lines
        .iter()
        .position(|line| line == "ran=tests/a.t")
        .unwrap();
    assert!(linted < first, "{lines:?}");
}

#[test]
fn f3_a_flag_naming_fail_fails_its_test_and_the_run() {
    let s = Suite::new();
    s.write("tests/b.flag", "fail\n");
    s.write("tests/a.flag", "ok\n");
    let out = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&out), 1);
    let launches = s.launches();
    assert_eq!(launches[0].ran(), ["tests/a.t", "tests/b.t", "tests/c.t"]);
    assert_eq!(launches[0].failed(), ["tests/b.t"]);

    // The flag is found relative to the cwd, as the test path is.
    s.clear_log();
    s.write("tests/c.flag", "fail");
    let out = s.direct(&s.root.join("tests"), &["c.t"], &[]);
    assert_eq!(code(&out), 1);
    assert_eq!(s.launches()[0].failed(), ["c.t"]);

    // A missing test fails the run.
    s.clear_log();
    let out = s.direct(&s.root, &["tests/none.t"], &[]);
    assert_eq!(code(&out), 1);
    let launches = s.launches();
    assert_eq!(launches[0].ran(), ["tests/none.t"]);
    assert_eq!(launches[0].failed(), ["tests/none.t"]);
}

#[test]
fn f4_t_ignore_reads_nothing_and_exits_zero_for_arguments() {
    let s = Suite::new();
    let out = s.direct(
        &s.root,
        &["tests/a.t", "tests/none.t"],
        &[("T_IGNORE", "1")],
    );
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    let launch = &launches[0];
    assert_eq!(launch.args, ["tests/a.t", "tests/none.t"]);
    assert!(launch.ran().is_empty());
    assert!(launch.failed().is_empty());

    // The no-argument form is unaffected.
    s.clear_log();
    let out = s.direct(&s.root, &[], &[("T_IGNORE", "1")]);
    assert_eq!(code(&out), 0);
    assert_eq!(s.launches()[0].ran(), ROSTER);
}

#[test]
fn f4_t_stat_unit_stats_each_argument_instead_of_running_it() {
    let s = Suite::new();
    let out = s.direct(
        &s.root,
        &["tests/a.t", "tests/none.t"],
        &[("T_STAT_UNIT", "1")],
    );
    assert_eq!(code(&out), 1);
    let launches = s.launches();
    let launch = &launches[0];
    assert_eq!(launch.statted(), ["tests/a.t", "tests/none.t"]);
    assert!(launch.ran().is_empty());
    assert_eq!(launch.failed(), ["tests/none.t"]);

    // The no-argument form still runs.
    s.clear_log();
    let out = s.direct(&s.root, &[], &[("T_STAT_UNIT", "1")]);
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    assert_eq!(launches[0].ran(), ROSTER);
    assert!(launches[0].statted().is_empty());
}

#[test]
fn f4_t_fifo_holds_after_the_first_test_by_default() {
    let s = Suite::new();
    let fifo = s.fifo();
    let mut child = s.direct_child(
        &s.root,
        &[],
        &[("T_FIFO", fifo.to_str().unwrap())],
        Stdio::piped(),
    );
    // The runner is holding when this returns, so it cannot finish until released.
    let writer = meet(&fifo);
    assert!(
        child.try_wait().unwrap().is_none(),
        "the hold released early"
    );
    assert_eq!(s.launches()[0].ran(), ["tests/a.t"]);
    release(writer);
    assert_eq!(code(&finish(child)), 0);
    assert_eq!(s.launches()[0].ran(), ROSTER);
}

#[test]
fn f4_t_fifo_at_holds_after_the_named_test() {
    let s = Suite::new();
    let fifo = s.fifo();
    let mut child = s.direct_child(
        &s.root,
        &[],
        &[
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/b.t"),
        ],
        Stdio::piped(),
    );
    let writer = meet(&fifo);
    assert!(
        child.try_wait().unwrap().is_none(),
        "the hold released early"
    );
    assert_eq!(s.launches()[0].ran(), ["tests/a.t", "tests/b.t"]);
    release(writer);
    assert_eq!(code(&finish(child)), 0);
    assert_eq!(s.launches()[0].ran(), ROSTER);
}

#[test]
fn f4_t_read_other_reads_before_any_test() {
    let s = Suite::new();
    let fifo = s.fifo();
    let mut child = s.direct_child(
        &s.root,
        &["tests/a.t"],
        &[("T_READ_OTHER", fifo.to_str().unwrap())],
        Stdio::piped(),
    );
    let writer = meet(&fifo);
    assert!(
        child.try_wait().unwrap().is_none(),
        "the read released early"
    );
    assert!(s.launches()[0].ran().is_empty());
    release(writer);
    assert_eq!(code(&finish(child)), 0);
    assert_eq!(s.launches()[0].ran(), ["tests/a.t"]);
}

#[test]
fn f4_t_write_writes_its_file() {
    let s = Suite::new();
    let target = s.outside.join("written");
    let out = s.direct(
        &s.root,
        &["tests/a.t"],
        &[("T_WRITE", target.to_str().unwrap())],
    );
    assert_eq!(code(&out), 0);
    assert_eq!(fs::read(&target).unwrap(), b"written\n");
}

#[test]
fn f4_t_lint_runs_first_only_for_the_no_argument_form() {
    let s = Suite::new();
    s.executable("lint", "#!/bin/sh\nprintf 'linted\\n' >> \"$LOG\"\n");
    let out = s.direct(&s.root, &[], &[("T_LINT", "1")]);
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    let lines = &launches[0].lines;
    let linted = lines
        .iter()
        .position(|line| line == "linted")
        .expect("lint ran");
    let first = lines
        .iter()
        .position(|line| line.starts_with("ran="))
        .unwrap();
    assert!(linted < first, "{lines:?}");

    s.clear_log();
    let out = s.direct(&s.root, &[], &[]);
    assert_eq!(code(&out), 0);
    assert!(!s.launches()[0].lines.iter().any(|line| line == "linted"));

    s.clear_log();
    let out = s.direct(&s.root, &["tests/a.t"], &[("T_LINT", "1")]);
    assert_eq!(code(&out), 0);
    assert!(!s.launches()[0].lines.iter().any(|line| line == "linted"));
}

#[test]
fn f4_t_ls_root_and_t_stat_root_log_once_each() {
    let s = Suite::new();
    let out = s.direct(
        &s.root,
        &["tests/a.t"],
        &[("T_LS_ROOT", "1"), ("T_STAT_ROOT", "1")],
    );
    assert_eq!(code(&out), 0);
    let launches = s.launches();
    let lines = &launches[0].lines;
    assert_eq!(lines.iter().filter(|line| *line == "ls_root").count(), 1);
    assert_eq!(lines.iter().filter(|line| *line == "stat_root").count(), 1);

    s.clear_log();
    let out = s.direct(&s.root, &["tests/a.t"], &[]);
    assert_eq!(code(&out), 0);
    assert!(!s.launches()[0].lines.iter().any(|line| line == "ls_root"));
}

// W6-0 (spec 3.2): the purity rule of the runner and its knobs. Each knob has a test that drives
// the runner directly and reads its log or its files. A knob with a T_IF gate also shows that an
// absent path turns it off.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod purity {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;

    /// The (path, id) pairs of the newest legacy proof stored under `key`.
    fn stored_inputs(s: &Suite, key: &str) -> BTreeSet<(String, String)> {
        let file = s.root.join(".stoop/proofs").join(format!("{key}.json"));
        let json: Value = serde_json::from_slice(&fs::read(file).expect("a stored proof")).unwrap();
        assert_eq!(json["key"], key);
        json["proofs"][0]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                (
                    input["path"].as_str().unwrap().to_owned(),
                    input["id"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    // F5: the full form reads nothing a unit launch does not read. The residue rule (W6-2) would
    // otherwise count such an input as residue forever. The roster comes from find, sed and sort,
    // so the test-word form must run those programs too. Directory inputs are excluded: the full
    // form lists directories, and a unit launch lists none.
    #[test]
    fn f5_the_full_form_reads_nothing_a_test_launch_does_not() {
        let s = Suite::new();
        let runs: [(&str, &[&str]); 4] = [
            ("full", &["./t"]),
            ("a", &["./t", "tests/a.t"]),
            ("b", &["./t", "tests/b.t"]),
            ("c", &["./t", "tests/c.t"]),
        ];
        for (key, words) in runs {
            let out = s.run(&s.root, &["--key", key], words, &[]);
            assert_eq!(code(&out), 0, "{key}: {}", text(&out.stderr));
        }
        let units: BTreeSet<(String, String)> = ["a", "b", "c"]
            .into_iter()
            .flat_map(|key| stored_inputs(&s, key))
            .collect();
        let stray: Vec<(String, String)> = stored_inputs(&s, "full")
            .into_iter()
            .filter(|(_, id)| id != "d" && !id.starts_with("dl:"))
            .filter(|input| !units.contains(input))
            .collect();
        assert!(
            stray.is_empty(),
            "the full form reads what no unit launch reads: {stray:?}"
        );
    }
}

#[test]
fn f6_t_if_absent_turns_off_t_write_and_t_read_other() {
    let s = Suite::new();
    let toggle = s.outside.join("toggle");
    let written = s.outside.join("written");
    let out = s.direct(
        &s.root,
        &["tests/a.t"],
        &[
            ("T_IF", toggle.to_str().unwrap()),
            ("T_WRITE", written.to_str().unwrap()),
        ],
    );
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(!written.exists(), "T_WRITE wrote with T_IF absent");

    // A read of a FIFO with no writer blocks, so `finish` fails the test if the read happens.
    let fifo = s.fifo();
    let child = s.direct_child(
        &s.root,
        &["tests/a.t"],
        &[
            ("T_IF", toggle.to_str().unwrap()),
            ("T_READ_OTHER", fifo.to_str().unwrap()),
        ],
        Stdio::piped(),
    );
    assert_eq!(
        code(&finish(child)),
        0,
        "T_READ_OTHER read with T_IF absent"
    );

    // Once the path exists, both act: the write lands before any test, and the read holds the
    // runner until a writer releases it.
    fs::write(&toggle, "").unwrap();
    let fifo = s.fifo();
    let mut child = s.direct_child(
        &s.root,
        &["tests/a.t"],
        &[
            ("T_IF", toggle.to_str().unwrap()),
            ("T_WRITE", written.to_str().unwrap()),
            ("T_READ_OTHER", fifo.to_str().unwrap()),
        ],
        Stdio::piped(),
    );
    let writer = meet(&fifo);
    assert!(written.exists(), "T_WRITE did not write with T_IF present");
    assert!(
        child.try_wait().unwrap().is_none(),
        "the read released early"
    );
    release(writer);
    assert_eq!(code(&finish(child)), 0);
}

#[test]
fn f7_t_write_at_writes_only_for_the_named_test_before_its_reads() {
    let s = Suite::new();
    // b reads out.src after its own inputs, so a write made before b's reads shows in its output.
    s.write("tests/b.t", "src/shared.src\nout.src\n");
    let target = s.path("out.src");
    let toggle = s.outside.join("write-at-toggle");
    let env = [
        ("T_WRITE", target.to_str().unwrap()),
        ("T_WRITE_AT", "tests/b.t"),
    ];

    // An invocation that does not run b writes nothing.
    let out = s.direct(&s.root, &["tests/a.t", "tests/c.t"], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(
        !target.exists(),
        "T_WRITE_AT wrote in an invocation without b"
    );

    // Running b writes before b reads, so its output shows the file it reads.
    let out = s.direct(&s.root, &["tests/b.t"], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("written\n"),
        "{}",
        text(&out.stdout)
    );
    assert_eq!(fs::read(&target).unwrap(), b"written\n");

    // The full form runs b too, and the write happens once, before b.
    fs::remove_file(&target).unwrap();
    let out = s.direct(&s.root, &[], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("written\n"));
    assert!(target.exists());

    // T_IF gates the write as it gates T_WRITE.
    fs::remove_file(&target).unwrap();
    let gated = [env[0], env[1], ("T_IF", toggle.to_str().unwrap())];
    let out = s.direct(&s.root, &["tests/b.t"], &gated);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(!target.exists(), "T_WRITE_AT wrote with T_IF absent");
    fs::write(&toggle, "").unwrap();
    let out = s.direct(&s.root, &["tests/b.t"], &gated);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(
        target.exists(),
        "T_WRITE_AT did not write with T_IF present"
    );
}

#[test]
fn f8_t_write_each_writes_each_tests_own_output_in_every_run_of_it() {
    let s = Suite::new();
    let toggle = s.outside.join("write-each-toggle");
    // T_IF does not gate T_WRITE_EACH, so an absent toggle changes nothing.
    let env = [("T_WRITE_EACH", "1"), ("T_IF", toggle.to_str().unwrap())];
    let out = s.direct(&s.root, &["tests/a.t", "tests/c.t"], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(fs::read(s.path("tests/a.out")).unwrap(), b"written\n");
    assert_eq!(fs::read(s.path("tests/c.out")).unwrap(), b"written\n");
    assert!(
        !s.path("tests/b.out").exists(),
        "b did not run, so it wrote nothing"
    );

    let out = s.direct(&s.root, &[], &[("T_WRITE_EACH", "1")]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    for name in ["tests/a.out", "tests/b.out", "tests/c.out"] {
        assert_eq!(fs::read(s.path(name)).unwrap(), b"written\n", "{name}");
    }
}

#[test]
fn f9_t_write_full_writes_in_the_full_form_before_its_first_test() {
    let s = Suite::new();
    let toggle = s.outside.join("write-full-toggle");
    // T_IF does not gate T_WRITE_FULL, so an absent toggle changes nothing.
    let env = [
        ("T_WRITE_FULL", "full.out"),
        ("T_IF", toggle.to_str().unwrap()),
    ];

    // The full form moves to the root first, so a relative path is root-relative.
    let out = s.direct(&s.root.join("docs"), &[], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert_eq!(fs::read(s.path("full.out")).unwrap(), b"written\n");
    assert!(
        !s.path("docs/full.out").exists(),
        "the path is not root-relative"
    );

    // The file exists when the first test holds, so it was written before the tests.
    s.remove("full.out");
    let fifo = s.fifo();
    let child = s.direct_child(
        &s.root,
        &[],
        &[
            ("T_WRITE_FULL", "full.out"),
            ("T_FIFO", fifo.to_str().unwrap()),
            ("T_FIFO_AT", "tests/a.t"),
        ],
        Stdio::piped(),
    );
    let writer = meet(&fifo);
    assert!(
        s.path("full.out").exists(),
        "the file came after the first test"
    );
    release(writer);
    assert_eq!(code(&finish(child)), 0);

    // The test-word form writes nothing.
    s.remove("full.out");
    let out = s.direct(&s.root, &["tests/a.t"], &[("T_WRITE_FULL", "full.out")]);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(
        !s.path("full.out").exists(),
        "the test-word form wrote the file"
    );
}

#[test]
fn f10_t_stat_other_stats_its_path_once_per_invocation() {
    let s = Suite::new();
    let toggle = s.outside.join("stat-other-toggle");
    let env = [
        ("T_STAT_OTHER", "tests/none.t"),
        ("T_IF", toggle.to_str().unwrap()),
    ];
    let out = s.direct(&s.root, &["tests/a.t", "tests/c.t"], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    let stats = |lines: &[String]| {
        lines
            .iter()
            .filter(|l| *l == "stat_other=tests/none.t")
            .count()
    };
    assert_eq!(stats(&s.launches()[0].lines), 0, "T_IF absent");

    fs::write(&toggle, "").unwrap();
    let runs: [&[&str]; 2] = [&["tests/a.t", "tests/c.t"], &[]];
    for words in runs {
        s.clear_log();
        let out = s.direct(&s.root, words, &env);
        // A missing path is not a failure: `test -e` only asks.
        assert_eq!(code(&out), 0, "{}", text(&out.stderr));
        let launches = s.launches();
        assert_eq!(launches.len(), 1);
        assert_eq!(stats(&launches[0].lines), 1, "{:?}", launches[0].lines);
    }
}

#[test]
fn f11_t_fail_full_fails_the_full_form_after_its_tests() {
    let s = Suite::new();
    let toggle = s.outside.join("fail-full-toggle");
    let env = [("T_FAIL_FULL", "1"), ("T_IF", toggle.to_str().unwrap())];
    let out = s.direct(&s.root, &[], &env);
    assert_eq!(code(&out), 0, "T_IF absent: {}", text(&out.stderr));
    assert_eq!(s.launches()[0].ran(), ROSTER);

    fs::write(&toggle, "").unwrap();
    s.clear_log();
    let out = s.direct(&s.root, &[], &env);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(launches[0].ran(), ROSTER, "the tests run first");
    assert!(launches[0].failed().is_empty(), "{:?}", launches[0].lines);

    // The test-word form is not affected.
    s.clear_log();
    let out = s.direct(&s.root, &["tests/a.t"], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(s.launches()[0].failed().is_empty());
}

#[test]
fn f12_t_fail_alone_fails_its_test_in_the_test_word_form() {
    let s = Suite::new();
    let toggle = s.outside.join("fail-alone-toggle");
    let env = [
        ("T_FAIL_ALONE", "tests/b.t"),
        ("T_IF", toggle.to_str().unwrap()),
    ];
    let out = s.direct(&s.root, &["tests/a.t", "tests/b.t"], &env);
    assert_eq!(code(&out), 0, "T_IF absent: {}", text(&out.stderr));
    assert!(s.launches()[0].failed().is_empty());

    fs::write(&toggle, "").unwrap();
    s.clear_log();
    let out = s.direct(&s.root, &["tests/a.t", "tests/b.t"], &env);
    assert_eq!(code(&out), 1, "{}", text(&out.stderr));
    let launches = s.launches();
    assert_eq!(
        launches[0].ran(),
        ["tests/a.t", "tests/b.t"],
        "b still runs"
    );
    assert_eq!(launches[0].failed(), ["tests/b.t"]);

    // The no-argument form runs b and does not fail it.
    s.clear_log();
    let out = s.direct(&s.root, &[], &env);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
    assert!(s.launches()[0].failed().is_empty());
}

// Pins of today's hooked-run behaviour. Each one holds on the base and must still hold after the
// attribution pass. Each changes `src/shared.src` (read by a and b) and expects the full form:
// one launch with no test argument and an empty `changed=`, so the runner runs its own roster.
// Cited lines are the code that makes today's answer.

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod pins {
    use super::*;
    use serde_json::json;
    use std::process::Output;

    fn success(out: &Output) {
        assert_eq!(code(out), 0, "{}", text(&out.stderr));
    }

    fn change(s: &Suite) {
        s.write("src/shared.src", "shared, changed\n");
    }

    /// One launch of the full form: no test argument, an empty `changed=`, the whole roster.
    fn full_form(s: &Suite) {
        let launches = s.launches();
        assert_eq!(launches.len(), 1, "{launches:?}");
        assert!(launches[0].args.is_empty(), "{:?}", launches[0].args);
        assert_eq!(launches[0].env("changed"), "");
        assert_eq!(launches[0].ran(), ROSTER);
    }

    /// A cold run records the legacy proof and the suite bundle. Dispatch needs both: a stored
    /// legacy proof (check 3) and a bundle with `whole` set (check 8), so each is asserted.
    fn cold(s: &Suite) {
        success(&s.hook(&[]));
        assert!(
            !s.proofs().is_empty(),
            "the cold run stored no legacy proof"
        );
        let bundle = s.bundle().expect("the cold run stored no suite bundle");
        assert!(bundle["whole"].is_string(), "{bundle}");
        assert_eq!(bundle["roster"]["units"], json!(ROSTER));
    }

    // P1: the first run of a suite is the full form, and its bundle records the roster with
    // no unit proofs. The roster comes from the hook's filter, `units/bundle.rs:243-248`.
    #[test]
    fn p1_a_cold_run_is_the_full_form_and_writes_the_roster() {
        let s = Suite::new();
        cold(&s);
        full_form(&s);
        let bundle = s.bundle().expect("a suite bundle");
        assert_eq!(bundle["roster"]["units"], json!(ROSTER));
        assert_eq!(bundle["units"], json!({}));
    }

    // P2: an unchanged run is a whole-command hit that skips, `run.rs:1289`.
    #[test]
    fn p2_an_unchanged_run_skips() {
        let s = Suite::new();
        cold(&s);
        let bundle = s.bundle_bytes();
        s.clear_log();
        success(&s.hook(&[]));
        assert!(s.launches().is_empty());
        assert_eq!(s.bundle_bytes(), bundle);
    }

    // P3: CI on a feature branch of a Git root is not a default branch, so `forced_reason` finds
    // no reason (`units/policy.rs:187`, `:291-336`) and the changed run still takes the full form.
    #[test]
    fn p3_ci_on_a_feature_branch_runs_the_full_form_on_a_change() {
        let s = Suite::new();
        s.config("[units]\ndefault_branch = \"main\"\n");
        // Without this, stoop refuses every legacy proof in a repository: its own reads of .git
        // could hide a history change. The existing Git fixtures ignore it the same way.
        s.write(".stoopignore", ".git\n");
        s.git("work");
        // The cold run has no CI, so the changed run's CI is the only variable.
        cold(&s);
        change(&s);
        let env = [("CI", "true"), ("CI_COMMIT_BRANCH", "work")];
        s.clear_log();
        success(&s.hook(&env));
        full_form(&s);
    }

    // P4: STOOP_FULL is a forced reason, `run.rs:1180-1181`.
    #[test]
    fn p4_stoop_full_runs_the_full_form_on_a_change() {
        let s = Suite::new();
        cold(&s);
        change(&s);
        s.clear_log();
        success(&s.hook(&[("STOOP_FULL", "1")]));
        full_form(&s);
    }

    // P5: `enabled = false` opts a suite out of splitting, at the top level and per suite.
    // The flags are parsed and then discarded today, `units/config.rs:299-302`.
    #[test]
    fn p5_enabled_false_runs_the_full_form_at_either_level() {
        for toml in [
            "[units]\nenabled = false\n",
            "[[units.suite]]\nid = \"tests\"\nmatch = [\"./t\", \"{changed:**/*.t|!slow/**}\"]\nenabled = false\n",
        ] {
            let s = Suite::new();
            s.config(toml);
            cold(&s);
            change(&s);
            s.clear_log();
            success(&s.hook(&[]));
            full_form(&s);
        }
    }

    // P6: explain never records or persists, `run.rs:852` (eligibility excludes explain),
    // `run.rs:1060` and `:1228`, and it returns at `run.rs:1476-1490` with status 1 and the
    // decision line. It launches nothing and leaves every file under `.stoop` byte-identical.
    #[test]
    fn p6_explain_after_a_change_launches_nothing_and_writes_nothing() {
        let s = Suite::new();
        cold(&s);
        change(&s);
        s.clear_log();
        let before = s.store_snapshot();
        let out = s.explain();
        assert_eq!(code(&out), 1, "{}", text(&out.stderr));
        let err = text(&out.stderr);
        assert!(err.contains("would run full"), "{err}");
        assert!(err.contains("src/shared.src changed"), "{err}");
        assert!(s.launches().is_empty());
        assert_eq!(s.store_snapshot(), before);
    }

    // P7: an empty roster is not a bundle, `units/bundle.rs:243`. The changed run is the full
    // form with the runner's own roster, which is now empty, and the old bundle stays.
    #[test]
    fn p7_a_roster_that_becomes_empty_runs_the_full_form() {
        let s = Suite::new();
        cold(&s);
        let bundle = s.bundle_bytes();
        s.remove("tests/a.t");
        s.remove("tests/b.t");
        s.remove("tests/c.t");
        s.clear_log();
        success(&s.hook(&[]));
        let launches = s.launches();
        assert_eq!(launches.len(), 1, "{launches:?}");
        assert!(launches[0].args.is_empty());
        assert_eq!(launches[0].env("changed"), "");
        assert!(launches[0].ran().is_empty());
        assert_eq!(s.bundle_bytes(), bundle);
    }

    // P8: each option that makes a run ineligible for units, `run.rs:848-861`, takes the full form
    // on a change. The cold run omits the option, so only the option decides this launch.
    #[test]
    fn p8_ineligible_options_run_the_full_form_on_a_change() {
        let options: [&[&str]; 5] = [
            &["--no-record"],
            &["--allow-network"],
            &["--probe", "true"],
            &["--ignore", "irrelevant"],
            &["--ignore-env", "IRRELEVANT"],
        ];
        for options in options {
            let s = Suite::new();
            cold(&s);
            change(&s);
            s.clear_log();
            success(&s.run(&s.root, options, &["./t", HOOK], &[]));
            full_form(&s);
        }
    }

    // P9: a bundle with a newer version is read as other and is never overwritten,
    // `units/bundle.rs:766-774` and `:851-852`. The changed run is the full form.
    #[test]
    fn p9_a_newer_bundle_version_runs_the_full_form_and_is_left_untouched() {
        let s = Suite::new();
        cold(&s);
        let mut newer = s.bundle().expect("a suite bundle");
        newer["v"] = 2.into();
        newer["generation"] = "a future schema".into();
        let bytes = serde_json::to_vec(&newer).unwrap();
        fs::write(s.bundle_path().unwrap(), &bytes).unwrap();
        change(&s);
        s.clear_log();
        success(&s.hook(&[]));
        full_form(&s);
        assert_eq!(s.bundle_bytes().unwrap(), bytes);
    }

    // P10: the full form lists the root, and the root listing is never a legacy input,
    // `run.rs:1991` (`key.is_empty()` is skipped). The `.` input must stay absent.
    #[test]
    fn p10_the_legacy_proof_never_records_the_root_listing() {
        let s = Suite::new();
        success(&s.hook(&[("T_LS_ROOT", "1")]));
        let launches = s.launches();
        assert_eq!(launches.len(), 1);
        assert!(launches[0].lines.iter().any(|line| line == "ls_root"));
        let proofs = s.proofs();
        assert!(!proofs.is_empty());
        for proof in &proofs {
            let paths: Vec<&str> = proof["inputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|input| input["path"].as_str().unwrap())
                .collect();
            assert!(paths.contains(&"tests/a.t"), "{paths:?}");
            assert!(!paths.contains(&"."), "{paths:?}");
        }
    }

    // P11: dispatch needs a stored legacy proof (spec 3.1, check 3: `!lookup.proofs.is_empty()`).
    // A bundle without one is the state a legacy proof's removal leaves, while the bundle
    // survives. Here the proofs go and the bundle stays, then a change must take the full form.
    // Check 8 holds here (the bundle is current with `whole` set), so this pin alone stops a dispatch.
    #[test]
    fn p11_a_bundle_without_a_legacy_proof_runs_the_full_form() {
        let s = Suite::new();
        cold(&s);
        fs::remove_dir_all(s.root.join(".stoop/proofs")).unwrap();
        assert!(
            s.bundle().is_some(),
            "the bundle must survive the proof's removal"
        );
        change(&s);
        s.clear_log();
        success(&s.hook(&[]));
        full_form(&s);
    }
}
