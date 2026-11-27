//! Configuration and full-verification behavior through the public CLI.
#![cfg(unix)]

mod common;

use serde_json::json;

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(
            root.join("runner"),
            "#!/bin/sh\nprintf 'run'\nfor arg do printf ' <%s>' \"$arg\"; done\nprintf '\\n'\n",
        )
        .unwrap();
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
        Self { root }
    }

    fn config(&self, body: &str) {
        fs::write(self.root.join(".stoop.toml"), body).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("STOOP_STORE", self.root.join(".stoop"))
            .current_dir(&self.root)
            .args(["run", "--no-learn-volatile"]);
        for name in [
            "STOOP_RUN_NUMBER",
            "STOOP_SYNC_WRITE",
            "STOOP_DEFAULT_BRANCH",
            "GITHUB_RUN_NUMBER",
            "GITHUB_EVENT_NAME",
            "GITHUB_REF",
            "GITHUB_REF_NAME",
            "GITHUB_REF_TYPE",
            "GITHUB_HEAD_REF",
            "GITHUB_BASE_REF",
            "CI_COMMIT_BRANCH",
            "CI_DEFAULT_BRANCH",
            "BUILDKITE_BRANCH",
        ] {
            command.args(["--ignore-env", name]);
        }
        command.args(["--", "./runner"]).args(args);
        command
    }

    fn off(&self, args: &[&str]) -> Output {
        self.command(args).env("STOOP_OFF", "1").output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn assert_ran(output: &Output) {
    assert!(output.status.success(), "{}", stderr(output));
    assert_eq!(output.stdout, b"run\n", "{}", stderr(output));
    assert!(
        !stderr(output).contains("stoop: skip"),
        "{}",
        stderr(output)
    );
}

fn fifo(path: &Path) {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
}

fn bounded(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("command blocked on a special file: {}", stderr(&output));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn erased_hook_recovers_the_declared_many_full_form() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "base", "more", "{changed}"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    assert_ran(&f.off(&["--files", "base", "more", "{changed}"]));
    let erased = f.off(&["--files", "base", "more"]);
    assert_ran(&erased);
    assert!(
        stderr(&erased).contains("shell expanded"),
        "{}",
        stderr(&erased)
    );
}

#[test]
fn erased_hook_without_the_needed_declaration_refuses_instead_of_running_restricted() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "base", "more", "{changed}"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    assert_ran(&f.off(&["--files", "base", "more", "{changed}"]));
    f.config("[units]\n");
    let erased = f.off(&["--files", "base", "more"]);
    assert_eq!(erased.status.code(), Some(2), "{}", stderr(&erased));
    assert!(erased.stdout.is_empty(), "{}", stderr(&erased));
    assert!(
        stderr(&erased).contains("cannot tell where"),
        "{}",
        stderr(&erased)
    );
}

#[test]
fn configured_erased_hooks_with_different_full_forms_are_refused() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "one"
match = ["./runner", "--files={changed}", "{changed-inputs}", "--label"]
options = [{ names = ["--files"], values = "many" }, { names = ["--label"], values = 0 }]
[[units.suite]]
id = "many"
match = ["./runner", "--files={changed}", "--label", "{changed-inputs}"]
options = [{ names = ["--files"], values = "many" }, { names = ["--label"], values = 1 }]
"#,
    );
    let a = f.off(&["--files={changed}", "{changed-inputs}", "--label"]);
    let b = f.off(&["--files={changed}", "--label", "{changed-inputs}"]);
    assert!(
        a.status.success() && b.status.success(),
        "{} {}",
        stderr(&a),
        stderr(&b)
    );
    let erased = f.off(&["--files=", "--label"]);
    assert_eq!(erased.status.code(), Some(2), "{}", stderr(&erased));
    assert!(erased.stdout.is_empty());
}

#[test]
fn erased_full_forms_remain_ambiguous_after_configuration_is_removed() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "one"
match = ["./runner", "--files={changed}", "{changed-inputs}", "--label"]
options = [{ names = ["--files"], values = "many" }, { names = ["--label"], values = 0 }]
independent = false
[[units.suite]]
id = "two"
match = ["./runner", "--files={changed}", "--label", "{changed-inputs}"]
options = [{ names = ["--files"], values = "many" }, { names = ["--label"], values = 1 }]
independent = false
"#,
    );
    let first = f.off(&["--files={changed}", "{changed-inputs}", "--label"]);
    let second = f.off(&["--files={changed}", "--label", "{changed-inputs}"]);
    assert!(
        first.status.success() && second.status.success(),
        "{} {}",
        stderr(&first),
        stderr(&second)
    );
    f.config("[units]\n");
    let out = f.off(&["--files=", "--label"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn undeclared_single_dash_options_keep_their_exact_spelling() {
    let f = Fixture::new();
    let out = f.off(&["-v=debug", "-vv", "{changed}"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <-v=debug>\n");
}

#[test]
fn legacy_undeclared_adjacent_options_keep_exact_spelling() {
    for (args, expected) in [
        (vec!["--files", "{changed}"], "run\n"),
        (vec!["-v=debug", "-vv", "{changed}"], "run <-v=debug>\n"),
        (vec!["-files=old", "-files", "{changed}"], "run\n"),
    ] {
        let f = Fixture::new();
        let out = f.off(&args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        assert_eq!(String::from_utf8_lossy(&out.stdout), expected, "{args:?}");
    }
}

#[test]
fn legacy_undeclared_attached_placeholders_remain_supported() {
    for args in [
        vec!["--files={changed}"],
        vec!["-f={changed}"],
        vec!["-f{changed}"],
        vec!["@{changed:file}"],
    ] {
        let f = Fixture::new();
        assert_ran(&f.off(&args));
    }
}

#[test]
fn undeclared_partial_attached_forms_keep_2a_behavior() {
    for carrier in ["-foo{changed}", "--files=base{changed}"] {
        let f = Fixture::new();
        let out = f.off(&[carrier, "tail"]);
        assert!(out.status.success(), "{carrier}: {}", stderr(&out));
        assert_eq!(out.stdout, b"run <tail>\n", "{carrier}");
    }
}

#[test]
fn legacy_attached_carrier_removes_prior_occurrences() {
    let f = Fixture::new();
    assert_ran(&f.off(&["-f", "base", "-f{changed}"]));
}

#[test]
fn consecutive_legacy_placeholders_do_not_reuse_a_removed_carrier() {
    let f = Fixture::new();
    assert_ran(&f.off(&["--files", "{changed}", "{changed-inputs}"]));
}

#[test]
fn declared_long_name_does_not_claim_a_distinct_prefix_option() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files-extra", "keep", "--files", "{changed}"]
options = [{ names = ["--files"], values = 1 }]
"#,
    );
    let out = f.off(&["--files-extra", "keep", "--files", "{changed}"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--files-extra> <keep>\n");
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files-extra={changed}"]
options = [{ names = ["--files"], values = 1 }]
"#,
    );
    assert_ran(&f.off(&["--files-extra={changed}"]));
}

#[test]
fn declared_zero_arity_rejects_an_attached_placeholder() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "flag"
match = ["./runner", "--flag={changed}", "--flag", "keep"]
options = [{ names = ["--flag"], values = 0 }]
"#,
    );
    let out = f.off(&["--flag={changed}", "--flag", "keep"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn declared_long_partial_placeholder_is_refused() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files=base{changed}", "tail"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    let out = f.off(&["--files=base{changed}", "tail"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn legacy_carrier_does_not_remove_identical_option_after_terminator() {
    let f = Fixture::new();
    let out = f.off(&["--files", "{changed}", "--", "--files", "positional"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--> <--files> <positional>\n");
}

#[test]
fn option_like_word_after_terminator_is_positional_not_adjacent_carrier() {
    let f = Fixture::new();
    // `--files` is positional after `--`, so the 2a adjacent-option rule cannot own it.
    let out = f.off(&["--", "--files", "{changed}"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--> <--files>\n");
}

#[test]
fn undeclared_options_survive_when_placeholder_is_after_terminator() {
    let f = Fixture::new();
    let out = f.off(&["-v=debug", "-vv", "--", "{changed}"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <-v=debug> <-vv>\n");
}

#[test]
fn declared_short_attached_values_are_refused() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "short"
match = ["./runner", "*", "*"]
options = [{ names = ["-f"], values = "many" }]
"#,
    );
    let out = f.off(&["-fVALUE", "{changed}"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
    f.config(
        r#"[[units.suite]]
id = "short-before-terminator"
match = ["./runner", "*", "*", "*"]
options = [{ names = ["-f"], values = "many" }]
"#,
    );
    let out = f.off(&["-fVALUE", "--", "{changed}"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn changed_declarations_cannot_change_a_recorded_full_form() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "many"
match = ["./runner", "--files", "{changed}", "tail"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    assert_ran(&f.off(&["--files", "{changed}", "tail"]));
    f.config("[units]\n");
    let erased = f.off(&["--files", "tail"]);
    assert_eq!(erased.status.code(), Some(2), "{}", stderr(&erased));
    assert!(erased.stdout.is_empty());
}

#[test]
fn changed_config_with_same_full_form_cannot_recover_an_old_hook() {
    let f = Fixture::new();
    let config = r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "{changed}"]
options = [{ names = ["--files"], values = "many" }]
"#;
    f.config(config);
    assert_ran(&f.off(&["--files", "{changed}"]));
    f.config(&format!("{config}# changed\n"));
    let erased = f.off(&["--files"]);
    assert_eq!(erased.status.code(), Some(2), "{}", stderr(&erased));
    assert!(erased.stdout.is_empty());
}

#[test]
fn quoted_hook_refresh_supersedes_stale_config_record() {
    let f = Fixture::new();
    let config = r#"[[units.suite]]
id = "predicate"
match = ["./runner", "--predicate", "{changed}"]
options = [{ names = ["--predicate"], values = "many" }]
"#;
    f.config(config);
    assert_ran(&f.off(&["--predicate", "{changed}"]));
    f.config(&format!("{config}# refreshed\n"));
    let stale = f.off(&["--predicate"]);
    assert_eq!(stale.status.code(), Some(2), "{}", stderr(&stale));
    assert!(stale.stdout.is_empty());
    assert_ran(&f.off(&["--predicate", "{changed}"]));
    let refreshed = f.off(&["--predicate"]);
    assert_ran(&refreshed);
    assert!(
        stderr(&refreshed).contains("shell expanded"),
        "{}",
        stderr(&refreshed)
    );
}

#[test]
fn invalid_configuration_never_recovers_an_erased_hook() {
    let f = Fixture::new();
    f.config("[units]\nunknown = true\n");
    assert_ran(&f.off(&["{changed}"]));
    let erased = f.off(&[]);
    assert_eq!(erased.status.code(), Some(2), "{}", stderr(&erased));
    assert!(erased.stdout.is_empty());
}

#[test]
fn placeholder_words_after_end_of_options_are_positional() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--", "--files={changed}", "keep"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    let out = f.off(&["--", "--files={changed}", "keep"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--> <keep>\n");
}

#[test]
fn attached_placeholder_uses_the_longest_declared_alias() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "-foo{changed}", "tail"]
options = [{ names = ["-foo"], values = "many" }]
"#,
    );
    let out = f.off(&["-foo{changed}", "tail"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn declared_one_consumes_an_option_looking_operand() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "-old", "--files", "{changed}"]
options = [{ names = ["--files"], values = 1 }]
"#,
    );
    assert_ran(&f.off(&["--files", "-old", "--files", "{changed}"]));
}

#[test]
fn attached_many_placeholder_removes_following_values() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files={changed}", "tail"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    assert_ran(&f.off(&["--files={changed}", "tail"]));
}

#[test]
fn many_alias_removal_stops_at_the_end_of_options() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "{changed}", "--", "-f", "positional"]
options = [{ names = ["--files", "-f"], values = "many" }]
"#,
    );
    let out = f.off(&["--files", "{changed}", "--", "-f", "positional"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--> <-f> <positional>\n");
}

#[test]
fn many_short_alias_does_not_remove_a_distinct_longer_declared_option() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "-f", "{changed}", "-foo", "labels"]
options = [{ names = ["-f"], values = "many" }, { names = ["-foo"], values = 1 }]
"#,
    );
    let out = f.off(&["-f", "{changed}", "-foo", "labels"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <-foo> <labels>\n");
}

#[test]
fn config_fifo_symlink_is_rejected_without_blocking() {
    let f = Fixture::new();
    let pipe = f.root.join("config-fifo");
    fifo(&pipe);
    symlink(&pipe, f.root.join(".stoop.toml")).unwrap();
    let mut command = f.command(&["{changed}"]);
    command.env("STOOP_OFF", "1");
    let out = bounded(command);
    assert_ran(&out);
    assert_eq!(
        stderr(&out)
            .matches("ignoring the unit configuration")
            .count(),
        1
    );
}

#[test]
fn oversized_config_is_rejected_without_a_skip() {
    let f = Fixture::new();
    let mut config = "[units]\n".to_string();
    config.push_str(&" ".repeat(8 * 1024 * 1024));
    f.config(&config);
    let out = f.off(&["{changed}"]);
    assert_ran(&out);
    assert_eq!(
        stderr(&out)
            .matches("ignoring the unit configuration")
            .count(),
        1
    );
}

#[test]
fn declared_many_removes_every_value() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "base", "more", "{changed}"]
options = [{ names = ["--files", "-f"], values = "many" }]
"#,
    );
    let out = f.off(&["--files", "base", "more", "{changed}"]);
    assert_ran(&out);
}

#[test]
fn values_one_and_zero() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "one"
match = ["./runner", "--label", "base", "{changed}"]
options = [{ names = ["--label"], values = 1 }]

[[units.suite]]
id = "zero"
match = ["./runner", "--verbose", "{changed}"]
options = [{ names = ["--verbose"], values = 0 }]
"#,
    );
    let one = f.off(&["--label", "base", "{changed}"]);
    assert!(one.status.success(), "{}", stderr(&one));
    assert_eq!(one.stdout, b"run <--label> <base>\n");
    let zero = f.off(&["--verbose", "{changed}"]);
    assert!(zero.status.success(), "{}", stderr(&zero));
    assert_eq!(zero.stdout, b"run <--verbose>\n");
}

#[test]
fn many_removes_aliases_until_the_next_option_and_normalizes_placeholders() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "aliases"
cwd = "."
match = ["./runner", "--files", "base", "-f", "more", "{changed:*.t}", "--verbose"]
options = [{ names = ["--files", "-f"], values = "many" }]
"#,
    );
    let out = f.off(&[
        "--files",
        "base",
        "-f",
        "more",
        "${STOOP_UNITS:*.t}",
        "--verbose",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(out.stdout, b"run <--verbose>\n", "{}", stderr(&out));
}

#[test]
fn many_handles_attached_values_and_one_keeps_an_already_consumed_option() {
    let f = Fixture::new();
    f.config(
        r#"[[units.suite]]
id = "many"
match = ["./runner", "--files=base", "more", "{changed}"]
options = [{ names = ["--files"], values = "many" }]

[[units.suite]]
id = "one"
match = ["./runner", "--label=base", "{changed}"]
options = [{ names = ["--label"], values = 1 }]
"#,
    );
    assert_ran(&f.off(&["--files=base", "more", "{changed}"]));
    let one = f.off(&["--label=base", "{changed}"]);
    assert!(one.status.success(), "{}", stderr(&one));
    assert_eq!(one.stdout, b"run <--label=base>\n");
}

#[test]
fn unit_env_takes_a_table_of_strings_and_refuses_the_rest() {
    let f = Fixture::new();
    let prefix = "[[units.suite]]\nid = 'x'\nmatch = ['./runner', '{changed}']\n";
    for table in [
        "unit_env = {}\n",
        "unit_env = { MODE = 'pass', _NAME9 = 'literal $HOME' }\n",
        "[units.suite.unit_env]\nPATH = '/usr/bin'\n",
    ] {
        f.config(&format!("{prefix}{table}"));
        let out = f.off(&["{changed}"]);
        assert_ran(&out);
        assert!(
            !stderr(&out).contains("ignoring the unit configuration"),
            "{table}: {}",
            stderr(&out)
        );
    }
    let boundary = (0..32)
        .map(|n| format!("V{n} = '{}'", "x".repeat(4096)))
        .collect::<Vec<_>>()
        .join(", ");
    f.config(&format!("{prefix}unit_env = {{ {boundary} }}\n"));
    let out = f.off(&["{changed}"]);
    assert_ran(&out);
    assert!(!stderr(&out).contains("ignoring the unit configuration"));

    let names = "unit_env names are letters, digits and underscores, not starting with a digit or with STOOP_";
    let limits = "unit_env holds at most 32 variables, each value at most 4096 bytes";
    let too_many = (0..33)
        .map(|n| format!("V{n} = 'x'"))
        .collect::<Vec<_>>()
        .join(", ");
    let cases = [
        ("unit_env = 1".to_string(), "invalid type"),
        ("unit_env = { MODE = 1 }".to_string(), "invalid type"),
        ("unit_env = { '1MODE' = 'x' }".to_string(), names),
        ("unit_env = { 'BAD-NAME' = 'x' }".to_string(), names),
        ("unit_env = { 'É' = 'x' }".to_string(), names),
        ("unit_env = { STOOP_SPLIT = '1' }".to_string(), names),
        (
            "unit_env = { MODE = \"a\\u0000b\" }".to_string(),
            "unit_env values cannot hold NUL",
        ),
        (
            format!("unit_env = {{ MODE = '{}' }}", "x".repeat(4097)),
            limits,
        ),
        (format!("unit_env = {{ {too_many} }}"), limits),
    ];
    for (table, message) in cases {
        f.config(&format!("{prefix}{table}\n"));
        let out = f.off(&["{changed}"]);
        assert_ran(&out);
        let error = stderr(&out);
        assert!(error.contains(message), "{table}: {error}");
        assert!(error.contains(".stoop.toml:4:"), "{table}: {error}");
        assert!(error.contains("ignoring the unit configuration"), "{error}");
    }
}

#[test]
fn parser_errors_report_the_offending_line() {
    let f = Fixture::new();
    for (text, line) in [
        ("[units]\nunknown = true\n", 2),
        ("[units]\nenabled = true\nenabled = false\n", 3),
    ] {
        f.config(text);
        let out = f.off(&["{changed}"]);
        assert_ran(&out);
        assert!(
            stderr(&out).contains(&format!(".stoop.toml:{line}:")),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn malformed_configuration_warns_and_does_not_interpret_plain_commands() {
    let f = Fixture::new();
    for text in [
        "[units]\nverify_every = 0\n",
        "[units]\njobs = 2\n",
        "[units.runner.pytest]\nenabled = true\n",
        "[[units.suite]]\nid = 'x'\nmatch = []\n",
        "[[units.suite]]\nid = 'x'\ncwd = '../outside'\nmatch = ['*']\n",
        "[[units.suite]]\nid = 'x'\nmatch = ['*']\noptions = [{ names = ['--x'], values = 2 }]\n",
        "[[units.suite]]\nid = 'x'\nmatch = ['*']\nunits = ['[']\n",
    ] {
        f.config(text);
        let hooked = f.off(&["{changed}"]);
        assert_ran(&hooked);
        let error = stderr(&hooked);
        assert!(error.contains(".stoop.toml:"), "{text}: {error}");
        assert_eq!(error.matches("ignoring the unit configuration").count(), 1);
        let plain_fixture = Fixture::new();
        plain_fixture.config(text);
        let plain = plain_fixture.off(&[]);
        assert!(plain.status.success(), "{text}: {}", stderr(&plain));
        assert!(
            !stderr(&plain).contains(".stoop.toml"),
            "{text}: {}",
            stderr(&plain)
        );
    }
}

#[test]
fn mcp_and_cli_share_declared_and_ambiguous_option_handling() {
    let f = Fixture::new();
    let args = ["./runner", "--files", "base", "more", "{changed}"];
    f.config(
        r#"[[units.suite]]
id = "files"
match = ["./runner", "--files", "base", "more", "{changed}"]
options = [{ names = ["--files"], values = "many" }]
"#,
    );
    let mut mcp = common::Mcp::spawn(&["--allow-run"], &f.root);
    let invoke = |mcp: &mut common::Mcp, id| {
        mcp.call(
            json!(id),
            "tools/call",
            common::modern(common::tool_call("run", json!({"argv": args}))),
        )
    };
    let accepted = invoke(&mut mcp, 1);
    assert_eq!(
        common::result(&accepted)["structuredContent"]["decision"],
        "ran"
    );
    assert_eq!(
        common::result(&accepted)["structuredContent"]["exit_code"],
        0
    );
    assert_ran(&f.off(&args[1..]));
    f.config("[units]\n");
    let cli = f.off(&args[1..]);
    assert_eq!(cli.status.code(), Some(2), "{}", stderr(&cli));
    let refused = invoke(&mut mcp, 2);
    let outcome = &common::result(&refused)["structuredContent"];
    assert_eq!(outcome["decision"], "refused", "{refused}");
    assert_eq!(outcome["exit_code"], 2, "{refused}");
    assert_eq!(outcome["stderr"]["text"], stderr(&cli));
    mcp.finish();
}

// Independent reference grammar: exact declared words and long `--name=value` only.
// `--` ends option parsing; undeclared adjacent carriers retain the 2a rule.
fn oracle_full(args: &[&str]) -> Result<Vec<String>, ()> {
    let definitions = [
        ("--many", "many", 2),
        ("--zero", "zero", 0),
        ("--one", "one", 1),
        ("-foo", "foo", 1),
        ("-m", "many", 2),
    ];
    let touches = |word: &str, name: &str| {
        word == name
            || word.strip_prefix(name).is_some_and(|tail| {
                !tail.is_empty() && (!name.starts_with("--") || tail.starts_with('='))
            })
    };
    let end = args
        .iter()
        .position(|word| *word == "--")
        .unwrap_or(args.len());
    for (i, word) in args.iter().enumerate() {
        if i < end
            && word.contains("{changed}")
            && *word != "{changed}"
            && definitions.iter().any(|(name, _, _)| touches(word, name))
            && !definitions.iter().any(|(name, _, arity)| {
                *arity != 0 && name.starts_with("--") && *word == format!("{name}={{changed}}")
            })
        {
            return Err(());
        }
    }
    let mut removed: Vec<bool> = args.iter().map(|word| word.contains("{changed}")).collect();
    let mut groups: Vec<(&str, Vec<usize>)> = Vec::new();
    let mut selected = std::collections::HashSet::new();
    let mut unknown_before: Option<&str> = None;
    let mut i = 0;
    while i < args.len() && args[i] != "--" {
        let word = args[i];
        let found = definitions.iter().find_map(|&(name, id, arity)| {
            if word == name {
                Some((id, arity, false))
            } else if name.starts_with("--")
                && word
                    .strip_prefix(name)
                    .is_some_and(|tail| tail.starts_with('='))
            {
                Some((id, arity, true))
            } else {
                None
            }
        });
        let Some((id, arity, attached)) = found else {
            if definitions
                .iter()
                .any(|(name, _, _)| touches(word, name) && word != *name)
            {
                return Err(());
            }
            if word.starts_with('-') && word.len() > 1 {
                let name = if word.contains("{changed}") && !word.starts_with("--") {
                    &word[..2]
                } else {
                    word.split_once('=').map_or(word, |(name, _)| name)
                };
                let mut owned = vec![i];
                i += 1;
                let attached = word.contains('=') || word.contains("{changed}");
                let adjacent = !attached && i < end && args[i] == "{changed}";
                if adjacent {
                    owned.push(i);
                    i += 1;
                }
                if adjacent || word.contains("{changed}") {
                    selected.insert(name);
                    unknown_before = None;
                } else {
                    unknown_before = (!attached).then_some(name);
                }
                groups.push((name, owned));
            } else {
                if word == "{changed}" && unknown_before.is_some() {
                    return Err(());
                }
                i += 1;
            }
            continue;
        };
        if arity == 0 && attached {
            return Err(());
        }
        unknown_before = None;
        let mut owned = vec![i];
        i += 1;
        if arity == 1 && !attached && i < args.len() && args[i] != "--" {
            owned.push(i);
            i += 1;
        } else if arity == 2 {
            while i < args.len()
                && args[i] != "--"
                && !(args[i].starts_with('-') && args[i].len() > 1)
            {
                owned.push(i);
                i += 1;
            }
        }
        if owned.iter().any(|&at| args[at].contains("{changed}")) {
            selected.insert(id);
        }
        groups.push((id, owned));
    }
    for (id, owned) in groups {
        if selected.contains(id) {
            for at in owned {
                removed[at] = true;
            }
        }
    }
    let mut result: Vec<String> = args
        .iter()
        .enumerate()
        .filter(|(i, _)| !removed[*i])
        .map(|(_, word)| (*word).to_string())
        .collect();
    if result.last().is_some_and(|word| word == "--") {
        result.pop();
    }
    Ok(result)
}

#[test]
fn generated_declared_argv_matches_independent_removal_grammar() {
    let f = Fixture::new();
    let prefixes: &[&[&str]] = &[
        &[],
        &["--zero"],
        &["--one", "v"],
        &["--one", "-old"],
        &["--many", "v"],
        &["--many", "v", "v"],
        &["--"],
        &["v"],
        &["-foo", "v"],
    ];
    let forms: &[&[&str]] = &[
        &["{changed}"],
        &["--one", "{changed}"],
        &["--many", "{changed}"],
        &["--many={changed}"],
        &["-m{changed}"],
        &["--", "--many={changed}"],
        &["--other", "{changed}"],
        &["-q=debug", "-qq", "{changed}"],
        &["--other={changed}"],
        &["@{changed}"],
        &["--many-extra", "keep", "--many", "{changed}"],
        &["--many-extra={changed}"],
        &["--zero={changed}", "--zero", "keep"],
    ];
    let suffixes: &[&[&str]] = &[
        &[],
        &["tail"],
        &["--zero"],
        &["--", "tail"],
        &["--one", "v"],
        &["--many", "v"],
    ];
    let mut checked = 0;
    for prefix in prefixes {
        for form in forms {
            for suffix in suffixes {
                let args: Vec<&str> = prefix.iter().chain(*form).chain(*suffix).copied().collect();
                let matches = std::iter::repeat_n("\"*\"", args.len())
                    .collect::<Vec<_>>()
                    .join(", ");
                f.config(&format!(
                    "[[units.suite]]\nid = 'generated'\nmatch = [\"./runner\", {matches}]\noptions = [{{ names = [\"--zero\"], values = 0 }}, {{ names = [\"--one\"], values = 1 }}, {{ names = [\"--many\", \"-m\"], values = \"many\" }}, {{ names = [\"-foo\"], values = 1 }}]\n"
                ));
                let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &f.root)
                    .env("STOOP_OFF", "1")
                    .current_dir(&f.root)
                    .args(["run", "--no-record", "--", "./runner"])
                    .args(&args)
                    .output()
                    .unwrap();
                let expected = oracle_full(&args);
                match expected {
                    Ok(expected) => {
                        let text = format!(
                            "run{}\n",
                            expected
                                .iter()
                                .map(|word| format!(" <{word}>"))
                                .collect::<String>()
                        );
                        assert!(
                            out.status.success(),
                            "argv={args:?} stderr={}",
                            stderr(&out)
                        );
                        assert_eq!(
                            String::from_utf8_lossy(&out.stdout),
                            text,
                            "argv={args:?} stderr={}",
                            stderr(&out)
                        );
                    }
                    Err(()) => {
                        assert_eq!(
                            out.status.code(),
                            Some(2),
                            "argv={args:?} stderr={}",
                            stderr(&out)
                        );
                        assert!(out.stdout.is_empty(), "argv={args:?}");
                    }
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 702);
}

#[cfg(target_os = "linux")]
mod traced {
    use super::*;

    impl Fixture {
        fn git(&self, args: &[&str]) {
            let output = Command::new("git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.root)
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "git {args:?}: {}", stderr(&output));
        }

        fn repo() -> Self {
            let f = Self::new();
            f.git(&["init", "-q", "-b", "feature"]);
            f.git(&[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/main",
            ]);
            f
        }

        fn branch(&self, name: &str) {
            self.git(&["symbolic-ref", "HEAD", &format!("refs/heads/{name}")]);
        }

        fn event(&self, contents: &str) {
            fs::write(self.root.join("event.json"), contents).unwrap();
        }

        fn github(&self, event: &str, reference: &str) -> Command {
            let mut command = self.command(&["{changed}"]);
            command
                .env("CI", "true")
                .env("GITHUB_ACTIONS", "true")
                .env("GITHUB_EVENT_NAME", event)
                .env("GITHUB_REF", reference)
                .env("GITHUB_EVENT_PATH", self.root.join("event.json"));
            command
        }

        fn hook(&self) -> Output {
            self.command(&["{changed}"]).output().unwrap()
        }

        fn hit(&self) {
            assert_ran(&self.hook());
            assert_skipped(&self.hook());
        }
    }

    fn assert_skipped(output: &Output) {
        assert!(output.status.success(), "{}", stderr(output));
        assert!(output.stdout.is_empty(), "{}", stderr(output));
        assert!(stderr(output).contains("stoop: skip"), "{}", stderr(output));
    }

    fn valid_event() -> &'static str {
        r#"{"ref":"refs/heads/feature","repository":{"default_branch":"main"}}"#
    }

    fn pull_event() -> &'static str {
        r#"{"number":42,"pull_request":{"number":42,"head":{"ref":"feature"},"base":{"ref":"main"}},"repository":{"default_branch":"main"}}"#
    }

    #[test]
    fn an_unknown_key_rejects_the_file_names_its_location_and_runs_the_full_command() {
        let f = Fixture::repo();
        f.hit();
        f.config("[units]\nunknown = true\n");
        let out = f.hook();
        assert_ran(&out);
        let error = stderr(&out);
        assert!(error.contains(".stoop.toml:2:"), "{error}");
        assert!(error.contains("unknown"), "{error}");
        assert_eq!(error.matches("ignoring the unit configuration").count(), 1);
    }

    #[test]
    fn a_duplicate_key_rejects_the_file() {
        let f = Fixture::repo();
        f.hit();
        f.config("[units]\nenabled = true\nenabled = false\n");
        let out = f.hook();
        assert_ran(&out);
        let error = stderr(&out);
        assert!(error.contains(".stoop.toml:3:"), "{error}");
        assert!(error.contains("duplicate"), "{error}");
    }

    #[test]
    fn verify_every_two_runs_full_on_every_second_run() {
        let f = Fixture::repo();
        f.config("[units]\nverify_every = 2\n");
        let run = |n: &str| {
            f.command(&["{changed}"])
                .env("STOOP_RUN_NUMBER", n)
                .output()
                .unwrap()
        };
        assert_ran(&run("1"));
        assert_skipped(&run("1"));
        let second = run("2");
        assert_ran(&second);
        assert!(stderr(&second).contains("verify_every 2: run 2"));
        assert_skipped(&run("3"));
        let fourth = run("4");
        assert_ran(&fourth);
        assert!(stderr(&fourth).contains("verify_every 2: run 4"));
    }

    #[test]
    fn verify_every_without_a_run_number_runs_full() {
        let f = Fixture::repo();
        f.config("[units]\nverify_every = 2\n");
        let first = f
            .command(&["{changed}"])
            .env("STOOP_RUN_NUMBER", "1")
            .output()
            .unwrap();
        assert_ran(&first);
        let missing = f.hook();
        assert_ran(&missing);
        assert!(stderr(&missing).contains("no run number for verify_every"));
    }

    #[test]
    fn github_run_number_is_the_fallback_and_invalid_override_forces_full() {
        let f = Fixture::repo();
        f.event(valid_event());
        f.config("[units]\nverify_every = 2\n");
        let run = |number: &str| {
            f.github("push", "refs/heads/feature")
                .env("GITHUB_RUN_NUMBER", number)
                .output()
                .unwrap()
        };
        assert_ran(&run("1"));
        assert_skipped(&run("1"));
        assert_ran(&run("2"));
        let invalid = f
            .github("push", "refs/heads/feature")
            .env("GITHUB_RUN_NUMBER", "1")
            .env("STOOP_RUN_NUMBER", "bad")
            .output()
            .unwrap();
        assert_ran(&invalid);
        assert!(stderr(&invalid).contains("no run number for verify_every"));
    }

    #[test]
    fn a_default_branch_push_runs_full_even_with_a_proof() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = |reference| f.github("push", reference).output().unwrap();
        assert_ran(&run("refs/heads/feature"));
        assert_skipped(&run("refs/heads/feature"));
        f.event(r#"{"ref":"refs/heads/main","repository":{"default_branch":"main"}}"#);
        let main = run("refs/heads/main");
        assert_ran(&main);
        assert!(stderr(&main).contains("default branch main"));
    }

    #[test]
    fn a_pull_request_is_not_a_default_branch_push() {
        let f = Fixture::repo();
        f.event(pull_event());
        let run = || {
            f.github("pull_request", "refs/pull/42/merge")
                .output()
                .unwrap()
        };
        assert_ran(&run());
        assert_skipped(&run());
    }

    #[test]
    fn pull_request_target_always_forces_full() {
        let f = Fixture::repo();
        f.event(pull_event());
        let normal = || {
            f.github("pull_request", "refs/pull/42/merge")
                .output()
                .unwrap()
        };
        assert_ran(&normal());
        assert_skipped(&normal());
        for reference in ["refs/pull/42/merge", "refs/heads/main"] {
            let output = f.github("pull_request_target", reference).output().unwrap();
            assert_ran(&output);
        }
    }

    #[test]
    fn pull_request_requires_a_canonical_merge_ref() {
        let f = Fixture::repo();
        f.event(pull_event());
        let normal = || {
            f.github("pull_request", "refs/pull/42/merge")
                .output()
                .unwrap()
        };
        assert_ran(&normal());
        assert_skipped(&normal());
        for reference in [
            "refs/pull/+42/merge",
            "refs/pull/042/merge",
            "refs/pull/ 42/merge",
            "refs/pull/4x2/merge",
            "refs/pull/42/head",
            "refs/pull/42/merge/extra",
        ] {
            let output = f.github("pull_request", reference).output().unwrap();
            assert_ran(&output);
        }
    }

    #[test]
    fn conflicting_github_refs_force_full() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || f.github("push", "refs/heads/feature");
        assert_ran(&run().output().unwrap());
        assert_skipped(&run().output().unwrap());
        let conflict = run().env("GITHUB_REF_NAME", "main").output().unwrap();
        assert_ran(&conflict);
        assert!(stderr(&conflict).contains("conflicting GitHub"));
        f.event(r#"{"ref":"refs/heads/main","repository":{"default_branch":"main"}}"#);
        let conflict = run().output().unwrap();
        assert_ran(&conflict);
        assert!(stderr(&conflict).contains("conflicting GitHub"));
    }

    #[test]
    fn missing_and_conflicting_ci_branch_context_force_a_full_run() {
        let f = Fixture::repo();
        let run = || {
            let mut command = f.command(&["{changed}"]);
            command.env("CI", "true").env("CI_DEFAULT_BRANCH", "main");
            command
        };
        let initial = run().env("CI_COMMIT_BRANCH", "feature").output().unwrap();
        assert_ran(&initial);
        let matching = run().env("CI_COMMIT_BRANCH", "feature").output().unwrap();
        assert_skipped(&matching);
        let missing = run().output().unwrap();
        assert_ran(&missing);
        let conflict = run()
            .env("CI_COMMIT_BRANCH", "feature")
            .env("BUILDKITE_BRANCH", "other")
            .output()
            .unwrap();
        assert_ran(&conflict);
    }

    #[test]
    fn local_checkout_ignores_stray_ci_branch_variables() {
        let f = Fixture::repo();
        f.hit();
        f.branch("main");
        let out = f
            .command(&["{changed}"])
            .env("CI_COMMIT_BRANCH", "feature")
            .output()
            .unwrap();
        assert_ran(&out);
        assert!(stderr(&out).contains("default branch main"));
    }

    #[test]
    fn a_local_checkout_on_the_default_branch_runs_full() {
        let f = Fixture::repo();
        f.hit();
        f.branch("main");
        let main = f.hook();
        assert_ran(&main);
        assert!(stderr(&main).contains("default branch main"));
    }

    #[test]
    fn a_feature_branch_skips_as_before() {
        let f = Fixture::repo();
        f.hit();
    }

    #[test]
    fn a_sync_writer_runs_full() {
        let f = Fixture::repo();
        f.hit();
        let mut command = f.command(&["{changed}"]);
        command.env("STOOP_SYNC_WRITE", "1");
        let writer = command.output().unwrap();
        assert_ran(&writer);
        assert!(stderr(&writer).contains("sync writer"));
    }

    #[test]
    fn a_suite_declared_not_independent_runs_even_on_a_hit() {
        let f = Fixture::repo();
        f.hit();
        f.config(
            r#"[[units.suite]]
id = "coupled"
match = ["./runner", "{changed}"]
independent = false
"#,
        );
        let out = f.hook();
        assert_ran(&out);
        assert!(stderr(&out).contains("not independent"));
    }

    #[test]
    fn configured_default_branch_can_require_more_work() {
        let f = Fixture::repo();
        f.hit();
        let out = f
            .command(&["{changed}"])
            .env("STOOP_DEFAULT_BRANCH", "feature")
            .output()
            .unwrap();
        assert_ran(&out);
        assert!(stderr(&out).contains("default branch feature"));
    }

    #[test]
    fn two_matching_suites_refuse() {
        let f = Fixture::repo();
        f.hit();
        f.config(
            r#"[[units.suite]]
id = "first"
match = ["./runner", "{changed}"]

[[units.suite]]
id = "second"
match = ["./runner", "*"]
"#,
        );
        let out = f.hook();
        assert_ran(&out);
        let error = stderr(&out);
        assert!(
            error.contains("first") && error.contains("second"),
            "{error}"
        );
        assert!(error.contains("ignoring the unit configuration"), "{error}");
    }

    #[test]
    fn plain_commands_keep_legacy_caching_on_the_default_branch() {
        let f = Fixture::repo();
        let run = || f.command(&[]).output().unwrap();
        assert_ran(&run());
        assert_skipped(&run());
        f.branch("main");
        assert_skipped(&run());
    }

    #[test]
    fn an_event_payload_over_8_mib_runs_full() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || f.github("push", "refs/heads/feature").output().unwrap();
        assert_ran(&run());
        assert_skipped(&run());
        let mut oversized = valid_event().to_string();
        oversized.push_str(&" ".repeat(8 * 1024 * 1024));
        f.event(&oversized);
        let out = run();
        assert_ran(&out);
    }
    #[test]
    fn configured_default_cannot_cancel_the_remote_default() {
        let f = Fixture::repo();
        f.hit();
        f.branch("main");
        f.config("[units]\ndefault_branch = 'other'\n");
        let out = f.hook();
        assert_ran(&out);
        assert!(stderr(&out).contains("default branch main"));
    }

    #[test]
    fn env_default_cannot_cancel_the_remote_default() {
        let f = Fixture::repo();
        f.hit();
        f.branch("main");
        let out = f
            .command(&["{changed}"])
            .env("STOOP_DEFAULT_BRANCH", "other")
            .output()
            .unwrap();
        assert_ran(&out);
        assert!(stderr(&out).contains("default branch main"));
    }

    #[test]
    fn pull_request_ref_name_disagreement_forces_full() {
        let f = Fixture::repo();
        f.event(pull_event());
        let run = || f.github("pull_request", "refs/pull/42/merge");
        assert_ran(&run().output().unwrap());
        assert_skipped(&run().output().unwrap());
        let out = run().env("GITHUB_REF_NAME", "main").output().unwrap();
        assert_ran(&out);
    }

    #[test]
    fn pull_request_ref_type_disagreement_forces_full() {
        let f = Fixture::repo();
        f.event(pull_event());
        let run = || f.github("pull_request", "refs/pull/42/merge");
        assert_ran(&run().output().unwrap());
        assert_skipped(&run().output().unwrap());
        let out = run().env("GITHUB_REF_TYPE", "tag").output().unwrap();
        assert_ran(&out);
    }

    #[test]
    fn pull_request_payload_disagreements_force_full() {
        let f = Fixture::repo();
        let event = |number, head, base| {
            format!(
            "{{\"number\":{number},\"pull_request\":{{\"number\":{number},\"head\":{{\"ref\":\"{head}\"}},\"base\":{{\"ref\":\"{base}\"}}}},\"repository\":{{\"default_branch\":\"main\"}}}}"
        )
        };
        f.event(&event(42, "real-head", "real-base"));
        let run = || {
            f.github("pull_request", "refs/pull/42/merge")
                .env("GITHUB_REF_NAME", "42/merge")
                .env("GITHUB_REF_TYPE", "branch")
                .env("GITHUB_HEAD_REF", "real-head")
                .env("GITHUB_BASE_REF", "real-base")
                .output()
                .unwrap()
        };
        assert_ran(&run());
        assert_skipped(&run());
        for payload in [
            event(43, "real-head", "real-base"),
            event(42, "other", "real-base"),
            event(42, "real-head", "other"),
        ] {
            f.event(&payload);
            assert_ran(&run());
        }
    }

    #[test]
    fn duplicate_github_default_branch_forces_full() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || f.github("push", "refs/heads/feature").output().unwrap();
        assert_ran(&run());
        assert_skipped(&run());
        f.event(r#"{"ref":"refs/heads/feature","repository":{"default_branch":"feature","default_branch":"main"}}"#);
        assert_ran(&run());
    }

    #[test]
    fn github_event_fifo_is_rejected_without_blocking() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || f.github("push", "refs/heads/feature");
        assert_ran(&run().output().unwrap());
        assert_skipped(&run().output().unwrap());
        fs::remove_file(f.root.join("event.json")).unwrap();
        fifo(&f.root.join("event.json"));
        let out = bounded(run());
        assert_ran(&out);
    }
    #[test]
    fn push_with_pull_request_payload_forces_full() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || f.github("push", "refs/heads/feature").output().unwrap();
        assert_ran(&run());
        assert_skipped(&run());
        f.event(r#"{"ref":"refs/heads/feature","number":42,"pull_request":{"number":42,"head":{"ref":"feature"},"base":{"ref":"main"}},"repository":{"default_branch":"main"}}"#);
        assert_ran(&run());
        for payload in [
            r#"{"ref":"refs/heads/feature","number":null,"repository":{"default_branch":"main"}}"#,
            r#"{"ref":"refs/heads/feature","pull_request":null,"repository":{"default_branch":"main"}}"#,
            r#"{"ref":null,"repository":{"default_branch":"main"}}"#,
        ] {
            f.event(payload);
            assert_ran(&run());
        }
    }
    #[test]
    fn push_payload_without_ref_forces_full() {
        let f = Fixture::repo();
        f.event(r#"{"ref":"refs/heads/feature","repository":{"default_branch":"main"}}"#);
        let run = || f.github("push", "refs/heads/feature").output().unwrap();
        assert_ran(&run());
        assert_skipped(&run());
        f.event(r#"{"repository":{"default_branch":"main"}}"#);
        assert_ran(&run());
    }

    #[test]
    fn pull_request_payload_without_identity_forces_full() {
        let f = Fixture::repo();
        f.event(r#"{"number":42,"pull_request":{"number":42,"head":{"ref":"feature"},"base":{"ref":"main"}},"repository":{"default_branch":"main"}}"#);
        let run = || {
            f.github("pull_request", "refs/pull/42/merge")
                .output()
                .unwrap()
        };
        assert_ran(&run());
        assert_skipped(&run());
        for payload in [
            r#"{"repository":{"default_branch":"main"}}"#,
            r#"{"pull_request":{"head":{"ref":"feature"},"base":{"ref":"main"}},"repository":{"default_branch":"main"}}"#,
            r#"{"pull_request":{"number":42,"base":{"ref":"main"}},"repository":{"default_branch":"main"}}"#,
            r#"{"pull_request":{"number":42,"head":{"ref":"feature"}},"repository":{"default_branch":"main"}}"#,
        ] {
            f.event(payload);
            assert_ran(&run());
        }
    }
}
