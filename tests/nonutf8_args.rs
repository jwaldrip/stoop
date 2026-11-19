//! Non-UTF-8 command-line words must reach the child byte for byte, must never be read as
//! stoop's own options or placeholders, and must never crash stoop.
#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

const WORKFLOW: &str = "name: fixture\non: push\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  stoop-plan:\n    runs-on: ubuntu-latest\n    steps: []\n  a:\n    needs: [stoop-plan]\n    if: ${{ !cancelled() && !contains(needs.stoop-plan.outputs.skip, ',a,') }}\n    runs-on: ubuntu-latest\n    steps:\n      - run: cat a.txt > /dev/null\n";

fn raw(bytes: &[u8]) -> OsString {
    OsString::from_vec(bytes.to_vec())
}

fn os(words: &[&str]) -> Vec<OsString> {
    words.iter().map(|word| OsString::from(*word)).collect()
}

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "stoop-nonutf8-args-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Dir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .status()
        .unwrap()
        .success();
    assert!(ok, "git {args:?}");
}

fn repo(dir: &Path, files: &[(&str, &str)]) {
    for (path, text) in files {
        let file = dir.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, text).unwrap();
    }
    git(dir, &["init", "-q", "-b", "main"]);
    git(dir, &["add", "."]);
    git(dir, &["commit", "-qm", "fixture"]);
}

/// Runs stoop with arguments that may not be UTF-8.
fn stoop(dir: &Path, args: &[OsString]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    command
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", dir)
        .env("TMPDIR", dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    command
}

fn text(output: &Output) -> String {
    format!(
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_panic(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "stoop panicked on a non-UTF-8 argument:\n{}",
        text(output)
    );
}

/// The child shell prints its first argument, so the test reads back the exact bytes it got.
fn echo_first_argument(prefix: &[&str], word: OsString) -> Vec<OsString> {
    let mut args = os(prefix);
    args.extend([
        OsString::from("/bin/sh"),
        OsString::from("-c"),
        OsString::from(r#"printf %s "$1""#),
        OsString::from("sh"),
        word,
    ]);
    args
}

#[test]
fn run_hands_a_non_utf8_word_to_the_child_byte_for_byte() {
    let dir = Dir::new("run");
    repo(dir.path(), &[("a.txt", "a\n")]);
    let word = raw(b"x-\xff-\xfe");
    let args = echo_first_argument(&["run", "--"], word);
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(output.stdout, b"x-\xff-\xfe", "{}", text(&output));
}

#[test]
fn explain_survives_a_non_utf8_word() {
    let dir = Dir::new("explain");
    repo(dir.path(), &[("a.txt", "a\n")]);
    let args = echo_first_argument(&["explain", "--"], raw(b"\xff"));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert_ne!(output.status.code(), Some(101), "{}", text(&output));
}

#[test]
fn sh_passes_non_utf8_script_arguments_byte_for_byte() {
    let dir = Dir::new("sh");
    repo(
        dir.path(),
        &[(".github/workflows/ci.yml", WORKFLOW), ("a.txt", "a\n")],
    );
    let runner = dir.path().join("runner");
    fs::create_dir_all(&runner).unwrap();
    fs::write(dir.path().join("step.sh"), "printf %s \"$1\"\n").unwrap();
    let mut args = os(&["sh", "step.sh"]);
    args.push(raw(b"x-\xff-\xfe"));
    let output = stoop(dir.path(), &args)
        .env("GITHUB_ACTIONS", "true")
        .env("GITHUB_REPOSITORY", "owner/repo")
        .env(
            "GITHUB_WORKFLOW_REF",
            "owner/repo/.github/workflows/ci.yml@refs/heads/main",
        )
        .env("GITHUB_WORKFLOW", "fixture")
        .env("GITHUB_JOB", "a")
        .env("GITHUB_SHA", "1111111111111111111111111111111111111111")
        .env("GITHUB_RUN_ID", "1")
        .env("GITHUB_RUN_ATTEMPT", "1")
        .env("RUNNER_TEMP", &runner)
        .output()
        .unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    let needle: &[u8] = b"x-\xff-\xfe";
    assert!(
        output.stdout.windows(needle.len()).any(|w| w == needle),
        "the script did not receive the exact bytes:\n{}",
        text(&output)
    );
}

#[test]
fn plan_rejects_a_non_utf8_word_as_an_unknown_option_with_valid_text() {
    let dir = Dir::new("plan");
    repo(dir.path(), &[(".github/workflows/ci.yml", WORKFLOW)]);
    let mut args = os(&["plan"]);
    args.push(raw(b"\xff"));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert!(!output.status.success(), "{}", text(&output));
    let stderr = std::str::from_utf8(&output.stderr)
        .unwrap_or_else(|_| panic!("the error is not valid text:\n{}", text(&output)));
    assert!(stderr.contains("unknown option"), "{stderr}");
}

#[test]
fn ls_ignores_a_non_utf8_word() {
    let dir = Dir::new("ls");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let mut args = os(&["ls"]);
    args.push(raw(b"\xff"));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
}

#[test]
fn forget_names_a_non_utf8_key_as_no_proof() {
    let dir = Dir::new("forget");
    repo(dir.path(), &[("in.txt", "one\n")]);
    let mut args = os(&["forget"]);
    args.push(raw(b"\xff"));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("no proof named"),
        "{}",
        text(&output)
    );
}

#[test]
fn a_non_utf8_word_that_looks_like_a_placeholder_is_an_ordinary_word() {
    let dir = Dir::new("placeholder");
    repo(dir.path(), &[("a.txt", "a\n")]);
    // Not UTF-8, so it cannot be a placeholder. Lossy conversion would make it one.
    let args = echo_first_argument(&["run", "--"], raw(b"{changed:*.rs\xff}"));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(output.stdout, b"{changed:*.rs\xff}", "{}", text(&output));
}

#[test]
fn a_non_utf8_option_value_is_refused_with_a_clear_error() {
    let dir = Dir::new("option-value");
    repo(dir.path(), &[("a.txt", "a\n")]);
    let mut args = os(&["run", "--key"]);
    args.push(raw(b"\xff"));
    args.extend(os(&["--", "true"]));
    let output = stoop(dir.path(), &args).output().unwrap();
    assert_no_panic(&output);
    assert_eq!(output.status.code(), Some(2), "{}", text(&output));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--key needs a UTF-8 value"),
        "{}",
        text(&output)
    );
}
