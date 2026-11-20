//! Configuration and full-verification behavior through the public CLI.
#![cfg(unix)]

mod common;

use serde_json::json;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

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
        let plain = f.off(&[]);
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
        r#"{"repository":{"default_branch":"main"}}"#
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
        let main = run("refs/heads/main");
        assert_ran(&main);
        assert!(stderr(&main).contains("default branch main"));
    }

    #[test]
    fn a_pull_request_is_not_a_default_branch_push() {
        let f = Fixture::repo();
        f.event(valid_event());
        let run = || {
            f.github("pull_request", "refs/pull/42/merge")
                .output()
                .unwrap()
        };
        assert_ran(&run());
        assert_skipped(&run());
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
}
