use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const URL: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const TOKEN: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";
const URL_VALUE: &str = "http://127.0.0.1:1/test-token-endpoint";
const TOKEN_VALUE: &[u8] = b"fixture-token-\xff";
const OTHER_VALUE: &[u8] = b"other-bytes-\xfe";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "stoop-token-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
        cmd.args(args)
            .current_dir(&self.0)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.0)
            .env("TMPDIR", &self.0)
            .env("STOOP_FULL", "1")
            .env(URL, URL_VALUE)
            .env(TOKEN, OsString::from_vec(TOKEN_VALUE.to_vec()))
            .env("STOOP_TEST_OTHER", OsString::from_vec(OTHER_VALUE.to_vec()))
            .env("ACTIONS_RUNTIME_TOKEN", "separate-runtime-token")
            .env("ACTIONS_CACHE_URL", "http://127.0.0.1:2/cache");
        cmd
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn success(out: &Output) {
    assert!(
        out.status.success(),
        "exit {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}
fn env_has(bytes: &[u8], name: &str, value: &[u8]) -> bool {
    let mut expected = name.as_bytes().to_vec();
    expected.push(b'=');
    expected.extend_from_slice(value);
    bytes.split(|b| *b == b'\n').any(|line| line == expected)
}
fn no_token(bytes: &[u8]) {
    assert!(
        !bytes.windows(URL.len()).any(|w| w == URL.as_bytes()),
        "request URL leaked into child environment"
    );
    assert!(
        !bytes.windows(TOKEN.len()).any(|w| w == TOKEN.as_bytes()),
        "request token leaked into child environment"
    );
    assert!(
        env_has(bytes, "STOOP_TEST_OTHER", OTHER_VALUE),
        "unrelated non-UTF-8 environment value changed"
    );
    assert!(env_has(
        bytes,
        "ACTIONS_RUNTIME_TOKEN",
        b"separate-runtime-token"
    ));
    assert!(env_has(
        bytes,
        "ACTIONS_CACHE_URL",
        b"http://127.0.0.1:2/cache"
    ));
}

#[test]
fn commands_and_nested_shells_do_not_inherit_request_credentials() {
    let f = Fixture::new();
    for args in [
        vec!["run", "--no-record", "--", "/usr/bin/env"],
        vec!["run", "--", "/bin/sh", "-c", "exec /usr/bin/env"],
    ] {
        let out = f.command(&args).output().unwrap();
        success(&out);
        no_token(&out.stdout);
    }
    let out = f
        .command(&["run", "--", "/usr/bin/env"])
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    success(&out);
    no_token(&out.stdout);
}

#[test]
fn shell_mode_does_not_inherit_request_credentials() {
    let f = Fixture::new();
    let script = f.0.join("step.sh");
    fs::write(&script, "exec /bin/sh -c /usr/bin/env\n").unwrap();
    let out = f
        .command(&["sh", script.to_str().unwrap()])
        .output()
        .unwrap();
    success(&out);
    no_token(&out.stdout);
}

#[test]
fn token_passthrough_requires_an_explicit_flag_and_each_name() {
    let f = Fixture::new();
    let out = f
        .command(&["run", "--allow-id-token", "--", "/usr/bin/env"])
        .env("STOOP_PASS_ENV", TOKEN)
        .output()
        .unwrap();
    success(&out);
    assert!(env_has(&out.stdout, TOKEN, TOKEN_VALUE));
    assert!(!out.stdout.windows(URL.len()).any(|w| w == URL.as_bytes()));
    assert!(env_has(&out.stdout, "STOOP_TEST_OTHER", OTHER_VALUE));
    let both = format!("{TOKEN}, {URL}, {TOKEN}");
    let out = f
        .command(&["run", "--allow-id-token", "--", "/usr/bin/env"])
        .env("STOOP_PASS_ENV", both)
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    success(&out);
    assert!(env_has(&out.stdout, TOKEN, TOKEN_VALUE));
    assert!(env_has(&out.stdout, URL, URL_VALUE.as_bytes()));
    let out = f
        .command(&["run", "--allow-id-token", "--", "/usr/bin/env"])
        .output()
        .unwrap();
    success(&out);
    no_token(&out.stdout);
}

#[test]
fn allowed_shell_blocks_journal_before_launch_and_fails_closed_if_it_cannot() {
    let f = Fixture::new();
    let script = f.0.join("allowed.sh");
    fs::write(
        &script,
        "test -f \"$RUNNER_TEMP/stoop/journal.blocked\"\nexec /usr/bin/env\n",
    )
    .unwrap();
    let workflow = f.0.join(".github/workflows/ci.yml");
    fs::create_dir_all(workflow.parent().unwrap()).unwrap();
    fs::write(&workflow, "name: fixture\ndefaults:\n  run:\n    shell: stoop sh {0}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@1111111111111111111111111111111111111111\n      - run: |\n          test -f \"$RUNNER_TEMP/stoop/journal.blocked\"\n          exec /usr/bin/env\n").unwrap();
    for args in [
        &["init", "-q", "-b", "main"][..],
        &["add", ".github/workflows/ci.yml"][..],
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ][..],
    ] {
        let out = Command::new("git")
            .current_dir(&f.0)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let context = |command: &mut Command, temp: &std::path::Path| {
        command
            .env("GITHUB_ACTIONS", "true")
            .env("STOOP_TEST_OTHER", "fixture")
            .env("GITHUB_REPOSITORY", "owner/repo")
            .env(
                "GITHUB_WORKFLOW_REF",
                "owner/repo/.github/workflows/ci.yml@refs/heads/main",
            )
            .env("GITHUB_WORKFLOW", "fixture")
            .env("GITHUB_JOB", "test")
            .env("GITHUB_RUN_ID", "123")
            .env("GITHUB_RUN_ATTEMPT", "1")
            .env("RUNNER_TEMP", temp);
    };
    let baseline_temp = f.0.join("baseline");
    let mut baseline = f.command(&["sh", script.to_str().unwrap()]);
    context(&mut baseline, &baseline_temp);
    let baseline = baseline.output().unwrap();
    assert_eq!(
        baseline.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    assert!(
        baseline_temp.join("stoop/journal.json").is_file(),
        "the normal journal did not open: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    assert!(!baseline_temp.join("stoop/journal.blocked").exists());
    let mut allowed = f.command(&["sh", "--allow-id-token", script.to_str().unwrap()]);
    context(&mut allowed, &f.0);
    allowed.env("STOOP_PASS_ENV", TOKEN);
    let out = allowed.output().unwrap();
    success(&out);
    assert!(env_has(&out.stdout, TOKEN, TOKEN_VALUE));
    assert!(f.0.join("stoop/journal.blocked").is_file());

    let bad_temp = f.0.join("not-a-directory");
    fs::write(&bad_temp, "file").unwrap();
    let marker = f.0.join("must-not-run");
    fs::write(&script, format!("touch {}\n", marker.display())).unwrap();
    let out = f
        .command(&["sh", "--allow-id-token", script.to_str().unwrap()])
        .env("GITHUB_ACTIONS", "true")
        .env("RUNNER_TEMP", &bad_temp)
        .env("STOOP_PASS_ENV", TOKEN)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!marker.exists());
}

#[test]
fn invalid_passthrough_is_rejected_before_running_or_opening_the_journal() {
    let f = Fixture::new();
    let marker = f.0.join("marker");
    let script = format!("touch {}", marker.display());
    for value in [
        TOKEN,
        "PATH",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN=value",
        "actions_id_token_request_token",
    ] {
        let out = f
            .command(&["run", "--", "/bin/sh", "-c", &script])
            .env("STOOP_PASS_ENV", value)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "value {value:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!marker.exists());
    }
    let file = f.0.join("step.sh");
    fs::write(&file, &script).unwrap();
    let out = f
        .command(&["sh", file.to_str().unwrap()])
        .env("GITHUB_ACTIONS", "true")
        .env("RUNNER_TEMP", &f.0)
        .env("STOOP_PASS_ENV", TOKEN)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!marker.exists());
    assert!(!f.0.join("stoop/journal.json").exists());
    let out = f
        .command(&["run", "--allow-id-token", "--", "/bin/sh", "-c", &script])
        .env("STOOP_PASS_ENV", OsString::from_vec(b"\xff".to_vec()))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(!marker.exists());
}

#[test]
fn explain_with_explicit_token_never_runs_the_command() {
    let f = Fixture::new();
    let marker = f.0.join("marker");
    let script = format!("touch {}", marker.display());
    let out = f
        .command(&[
            "explain",
            "--allow-id-token",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env("STOOP_PASS_ENV", TOKEN)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!marker.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn proc_environ_keeps_the_original_environment_after_removal() {
    let f = Fixture::new();
    let out = f
        .command(&[
            "run",
            "--no-record",
            "--",
            "/bin/sh",
            "-c",
            "cat /proc/$PPID/environ",
        ])
        .output()
        .unwrap();
    success(&out);
    assert!(out
        .stdout
        .windows(URL.len())
        .any(|window| window == URL.as_bytes()));
    assert!(out
        .stdout
        .windows(TOKEN.len())
        .any(|window| window == TOKEN.as_bytes()));
}

#[cfg(target_os = "linux")]
#[test]
fn probes_do_not_inherit_credentials_in_run_or_explain() {
    let f = Fixture::new();
    let probe = "env > \"$STOOP_PROBE_OUT\"";
    let output = f.0.join("probe.out");
    let run = || {
        f.command(&["run", "--probe", probe, "--", "/bin/true"])
            .env("STOOP_PROBE_OUT", &output)
            .output()
            .unwrap()
    };
    let out = run();
    success(&out);
    no_token(&fs::read(&output).unwrap());
    fs::remove_file(&output).unwrap();
    let out = f
        .command(&["explain", "--probe", probe, "--", "/bin/true"])
        .env("STOOP_PROBE_OUT", &output)
        .env_remove("STOOP_FULL")
        .output()
        .unwrap();
    assert!(out.status.code().is_some());
    no_token(&fs::read(&output).unwrap());
}

#[cfg(target_os = "linux")]
#[test]
fn allowed_commands_are_never_skipped_or_recorded() {
    let f = Fixture::new();
    let marker = f.0.join("count");
    let script = format!("printf x >> {}", marker.display());
    let args = [
        "run",
        "--key",
        "token-proof",
        "--allow-id-token",
        "--",
        "/bin/sh",
        "-c",
        &script,
    ];
    for _ in 0..2 {
        let out = f
            .command(&args)
            .env("STOOP_PASS_ENV", TOKEN)
            .env_remove("STOOP_FULL")
            .output()
            .unwrap();
        success(&out);
    }
    assert_eq!(fs::read(&marker).unwrap(), b"xx");
    let out = f
        .command(&[
            "explain",
            "--key",
            "token-proof",
            "--",
            "/bin/sh",
            "-c",
            &script,
        ])
        .env_remove("STOOP_FULL")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no proof yet"));
}
