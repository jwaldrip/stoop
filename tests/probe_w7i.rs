//! Probe-only cross-reader sequences for PR 86. These tests are not part of the PR branch.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

mod units_common;

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::process::{Child, Output, Stdio};
use std::time::{Duration, Instant};
use units_common::*;

const TU: [(&str, &str); 1] = [("T_U", "1")];

fn split(s: &Suite, extra: &[(&str, &str)]) -> Output {
    let mut env = vec![("STOOP_SPLIT", "1")];
    env.extend_from_slice(extra);
    s.hook(&env)
}

fn fixture(shared_reader: bool) -> Suite {
    fixture_runner(shared_reader, false, false)
}

fn fixture_runner(shared_reader: bool, stat: bool, missing_fails: bool) -> Suite {
    let s = Suite::new();
    let mut runner = include_str!("fixtures/hook/t").to_owned();
    if stat {
        let anchor = "cat \"$ROOT/$line\"";
        assert_eq!(runner.matches(anchor).count(), 1);
        runner = runner.replace(anchor, "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac");
    }
    if missing_fails {
        let anchor = "if [ -f \"$flag\" ] && grep -q fail \"$flag\"; then";
        assert_eq!(runner.matches(anchor).count(), 1);
        runner = runner.replace(anchor, "if { [ \"$1\" = tests/z.u ] && [ ! -f \"$flag\" ]; } || { [ -f \"$flag\" ] && grep -q fail \"$flag\"; }; then");
    }
    if stat || missing_fails {
        s.executable("t", &runner);
    }
    s.remove("e2e/x.u");
    s.write("tests/z.u", "src/c.src\n");
    s.write("tests/z.flag", "ok\n");
    s.write("tests/c.flag", "ok\n");
    s.write("tests/c.t", "src/c.src\ntests/z.u\ntests/z.flag\n");
    if shared_reader {
        s.write("tests/a.t", "src/shared.src\ntests/z.u\ntests/z.flag\n");
    }
    let cold = split(&s, &TU);
    assert_eq!(code(&cold), 0, "{}", text(&cold.stderr));
    assert!(
        text(&cold.stderr).contains("attribution pass after the full run"),
        "{}",
        text(&cold.stderr)
    );
    s
}

fn listings(s: &Suite) -> BTreeMap<String, BTreeSet<String>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(s.path("tests")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|extension| extension == "t") {
            let name = format!("tests/{}", path.file_name().unwrap().to_str().unwrap());
            let text = fs::read_to_string(path).unwrap();
            result.insert(name, text.lines().map(str::to_owned).collect());
        }
    }
    result
}

fn checked(
    s: &Suite,
    env: &[(&str, &str)],
    label: &str,
    before: &BTreeMap<String, BTreeSet<String>>,
) -> Output {
    let oracle = s.direct(&s.root, &[], env);
    s.clear_log();
    let subject = split(s, env);
    let launches = s.launches();
    let err = text(&subject.stderr);
    eprintln!(
        "PROBE {label}: subject={} oracle={} launches={launches:?}\n{err}",
        code(&subject),
        code(&oracle)
    );
    if code(&subject) == 125 {
        let path = no_verdict_path(&err)
            .unwrap_or_else(|| panic!("{label}: 125 lacks its exact no-verdict line: {err}"));
        let after = listings(s);
        assert!(
            launches.iter().flat_map(|launch| &launch.args).any(|unit| {
                before.get(unit).is_some_and(|old| old.contains(path))
                    && after.get(unit).is_some_and(|new| !new.contains(path))
            }),
            "{label}: 125 names {path}, which no launched unit dropped in this step: {err}"
        );
        s.clear_log();
        let retry = split(s, env);
        let retry_err = text(&retry.stderr);
        eprintln!(
            "PROBE {label}/unchanged retry: subject={} oracle={} launches={:?}\n{retry_err}",
            code(&retry),
            code(&oracle),
            s.launches()
        );
        if code(&retry) == 125 {
            assert_eq!(
                no_verdict_path(&retry_err),
                Some(path),
                "{label}: {retry_err}"
            );
        } else {
            assert_ne!(code(&retry), 2, "{label}: {retry_err}");
            assert_eq!(
                code(&retry) == 0,
                code(&oracle) == 0,
                "{label}: WRONG VERDICT on unchanged retry: subject {} oracle {}\n{retry_err}",
                code(&retry),
                code(&oracle)
            );
        }
    } else {
        assert_ne!(code(&subject), 2, "{label}: {err}");
        assert_eq!(
            code(&subject) == 0,
            code(&oracle) == 0,
            "{label}: WRONG VERDICT: subject {} oracle {}\n{err}",
            code(&subject),
            code(&oracle)
        );
    }
    subject
}
fn no_verdict_path(err: &str) -> Option<&str> {
    err.lines().find_map(|line| {
        let rest = line.strip_prefix("stoop: this run has no verdict (exit 125): ")?;
        rest.strip_suffix(", and no unit's new proof reads it")
            .and_then(|named| named.strip_suffix(" changed"))
            .or_else(|| {
                rest.split_once(" appeared, and no unit's new proof reads it; earlier proofs of ")
                    .filter(|(_, units)| !units.is_empty())
                    .map(|(path, _)| path)
            })
            .filter(|path| !path.is_empty())
    })
}

#[test]
fn w7k_stat_only_drop_refuses_then_checks_the_unchanged_retry() {
    let s = fixture_runner(false, true, false);
    let before = listings(&s);
    s.write("tests/c.t", "src/c.src\ntests/z.u\nstat:tests/z.flag\n");
    s.write("tests/z.flag", "fail\n");
    let out = checked(
        &s,
        &TU,
        "stat-only reader with failing runner-only test",
        &before,
    );
    assert_eq!(code(&out), 125, "{}", text(&out.stderr));
}

#[test]
fn w7k_content_reader_with_a_changed_passing_flag_matches_the_full_command() {
    let s = fixture_runner(false, true, false);
    let before = listings(&s);
    s.write("tests/z.flag", "ok changed\n");
    let out = checked(&s, &TU, "content reader with changed passing flag", &before);
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
}

#[test]
fn w7k_removed_input_and_its_last_reader_match_the_full_command() {
    let s = fixture_runner(false, false, true);
    let before = listings(&s);
    s.remove("tests/z.flag");
    s.write("tests/c.t", "src/c.src\ntests/z.u\n");
    let out = checked(&s, &TU, "removed flag and last live reader", &before);
    assert_ne!(code(&out), 0, "{}", text(&out.stderr));
}

fn hold_lock(s: &Suite) -> File {
    let path = s.bundle_path().unwrap().with_extension("lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    // SAFETY: lock is an open file descriptor and flock takes no pointers.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    lock
}

fn lock_free(s: &Suite) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(s.bundle_path().unwrap().with_extension("lock"))
            .unwrap();
        // SAFETY: lock is an open file descriptor and flock takes no pointers.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return;
        }
        assert!(Instant::now() < deadline, "suite lock stayed held");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_split(s: &Suite, extra: &[(&str, &str)]) -> Child {
    let mut command = s.stoop(&s.root);
    command
        .args(["run", "--root"])
        .arg(&s.root)
        .args(["--", "./t", HOOK])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("STOOP_SPLIT", "1");
    for (name, value) in extra {
        command.env(name, value);
    }
    spawning(|| command.spawn()).unwrap()
}

#[test]
fn dropped_cross_reader_after_distinct_full_paths() {
    for cause in ["environment", "global", "new-file", "forced", "ci", "busy"] {
        let s = fixture(false);
        let before = listings(&s);
        s.write("tests/c.t", "src/c.src\n");
        let mut env = vec![("T_U", "1")];
        match cause {
            "environment" => env.push(("FOO", "1")),
            "global" | "busy" => s.write("setup.src", "changed setup\n"),
            "new-file" => s.write("tests/new-note.txt", "note\n"),
            "forced" => env.push(("STOOP_FULL", "1")),
            "ci" => env.push(("CI", "1")),
            _ => unreachable!(),
        }
        let lock = (cause == "busy").then(|| hold_lock(&s));
        let first = checked(&s, &env, &format!("{cause}/drop"), &before);
        drop(lock);
        assert_eq!(code(&first), 0, "{cause}: {}", text(&first.stderr));
        let before = listings(&s);
        s.write("tests/z.flag", "fail\n");
        if cause == "forced" || cause == "ci" {
            env.pop();
        }
        let second = checked(&s, &env, &format!("{cause}/flag"), &before);
        assert_ne!(code(&second), 0, "{cause}: runner-only test failed");
    }
}

#[test]
fn rename_delete_and_readd_cross_reader() {
    let s = fixture(false);
    let before = listings(&s);
    s.remove("tests/c.t");
    s.write("tests/d.t", "src/c.src\n");
    let first = checked(&s, &TU, "rename c to d and drop reads", &before);
    assert_eq!(code(&first), 0, "{}", text(&first.stderr));
    let before = listings(&s);
    s.write("tests/z.flag", "fail\n");
    let second = checked(&s, &TU, "renamed reader's runner-only flag fails", &before);
    assert_ne!(code(&second), 0);
    let before = listings(&s);
    s.write("tests/z.flag", "ok\n");
    s.remove("tests/d.t");
    s.write("tests/c.t", "src/c.src\n\n");
    let third = checked(&s, &TU, "delete d and readd c", &before);
    assert_eq!(code(&third), 0, "{}", text(&third.stderr));
    let before = listings(&s);
    s.write("tests/z.flag", "fail\n");
    let fourth = checked(&s, &TU, "readded reader's runner-only flag fails", &before);
    assert_ne!(code(&fourth), 0);
}

#[test]
fn both_shared_readers_drop_a_failing_flag_in_one_step() {
    let s = fixture(true);
    let before = listings(&s);
    s.write("tests/a.t", "src/shared.src\n");
    s.write("tests/c.t", "src/c.src\n");
    s.write("tests/z.flag", "fail\n");
    let out = checked(&s, &TU, "both readers drop the failing flag", &before);
    assert_ne!(code(&out), 0);
}

#[test]
fn sigkill_during_relearning_never_yields_a_false_pass() {
    let s = fixture(false);
    let fifo = s.fifo();
    let fifo_text = fifo.to_str().unwrap();
    s.write("tests/c.t", "src/c.src\n");
    s.write("setup.src", "changed setup\n");
    let env = [
        ("T_U", "1"),
        ("T_FIFO", fifo_text),
        ("T_FIFO_AT", "tests/c.t"),
    ];
    let mut child = spawn_split(&s, &env);
    release(meet(&fifo));
    let writer = meet(&fifo);
    child.kill().unwrap();
    child.wait().unwrap();
    drop(writer);
    lock_free(&s);
    let before = listings(&s);
    s.write("tests/z.flag", "fail\n");
    let out = checked(
        &s,
        &TU,
        "flag fails after SIGKILL during completion",
        &before,
    );
    assert_ne!(code(&out), 0);
}
