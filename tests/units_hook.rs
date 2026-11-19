//! The explicit hook remains a full-command execution until unit proofs exist.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    runner: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-hook-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let runner = root.join("runner");
        fs::write(
            &runner,
            "#!/bin/sh\n: > \"$LOG\"\nfor arg do printf 'arg=<%s>\\n' \"$arg\" >> \"$LOG\"; done\nprintf 'changed=<%s>\\n' \"${STOOP_CHANGED-UNSET}\" >> \"$LOG\"\n[ \"${FAIL:-0}\" != 1 ]\n",
        )
        .unwrap();
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
        Self { root, runner }
    }

    fn command(&self, off: bool) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.root)
            .env("LOG", self.root.join("log"))
            .env("STOOP_STORE", self.root.join(".stoop"))
            .current_dir(&self.root);
        if off {
            command.env("STOOP_OFF", "1");
        }
        command
    }

    fn invoke(&self, opts: &[&str], args: &[&str], off: bool) -> Output {
        self.command(off)
            .arg("run")
            .args(opts)
            .arg("--")
            .arg(&self.runner)
            .args(args)
            .output()
            .unwrap()
    }

    fn log(&self) -> String {
        fs::read_to_string(self.root.join("log")).unwrap_or_default()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn err(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn full_form_removes_the_placeholder_and_its_option() {
    for args in [
        vec!["--files", "{changed}"],
        vec!["--files={changed}"],
        vec!["-f", "{changed}"],
        vec!["-f={changed}"],
        vec!["-f{changed}"],
        vec!["--files", "base.t", "--files", "{changed:*.t|!slow/**}"],
        vec!["--files=base.t", "--files={changed:*.t}"],
        vec!["{changed:*.t}"],
        vec!["--files", "$STOOP_CHANGED"],
        vec!["--files=${STOOP_CHANGED:*.t}"],
        vec!["@{changed:file}"],
    ] {
        let f = Fixture::new();
        let out = f.invoke(&[], &args, true);
        assert!(out.status.success(), "args={args:?} stderr={}", err(&out));
        assert_eq!(f.log(), "changed=<>\n", "args={args:?}");
    }
}

#[test]
fn terminator_and_unrelated_options_survive_full_form() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-v", "--", "{changed}"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "arg=<-v>\nchanged=<>\n");
}

#[test]
fn ambiguous_option_arity_fails_before_the_runner() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "one", "two", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("--files"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn malformed_and_shell_mangled_placeholders_fail_before_launch() {
    for bad in [
        "{changed:}",
        "{changed:*.t|}",
        "{changed:*.t,*.u}",
        "{changed:*.t:*.u}",
        "{changed:{a,b}}",
        "{changed:!slow/**}",
        "{changed:*.t",
        "changed:*.t",
        "--files=changed:*.t",
    ] {
        let f = Fixture::new();
        let out = f.invoke(&[], &[bad], true);
        assert_eq!(
            out.status.code(),
            Some(2),
            "bad={bad:?} stderr={}",
            err(&out)
        );
        assert!(!f.root.join("log").exists(), "bad={bad:?}");
    }
}

#[test]
fn a_placeholder_embedded_in_a_word_with_spaces_is_refused_before_launch() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["echo {changed} now"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("embedded"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_hook_run_prints_the_words_it_removed_without_tracing() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("removed [\"--files\", \"{changed}\"]"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn an_inherited_value_is_replaced_and_named_for_a_plain_run() {
    let f = Fixture::new();
    let out = f
        .command(false)
        .env("STOOP_CHANGED", "a.t")
        .args(["run", "--"])
        .arg(&f.runner)
        .args(["--other", "a.t"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("ignoring inherited STOOP_CHANGED"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "arg=<--other>\narg=<a.t>\nchanged=<>\n");
}

#[test]
fn a_quoted_placeholder_does_not_name_an_inherited_value() {
    let f = Fixture::new();
    let out = f
        .command(false)
        .env("STOOP_CHANGED", "a.t")
        .args(["run", "--"])
        .arg(&f.runner)
        .arg("{changed}")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains("inherited"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn an_inherited_unit_variable_is_an_ordinary_variable() {
    let f = Fixture::new();
    let out = f
        .command(false)
        .env("STOOP_UNIT", "only_this.t")
        .args(["run", "--", "sh", "-c", "printf %s \"$STOOP_UNIT\""])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "only_this.t");
    assert!(!err(&out).contains("removed"), "{}", err(&out));
}

#[test]
fn literal_mode_and_ordinary_empty_values_do_not_rewrite_argv() {
    let f = Fixture::new();
    let out = f.invoke(&["--literal"], &["--files", "{changed}"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "arg=<--files>\narg=<{changed}>\nchanged=<UNSET>\n");

    let f = Fixture::new();
    let out = f.invoke(&[], &["--only", ""], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("quote"), "{}", err(&out));
    assert_eq!(f.log(), "arg=<--only>\narg=<>\nchanged=<UNSET>\n");
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn failed_hook_still_detects_erased_forms_without_skipping() {
    for (hook, erased) in [
        (vec!["--files", "{changed:*.t}"], vec!["--files", ""]),
        (vec!["--files", "{changed:*.t}"], vec!["--files"]),
        (vec!["--files={changed:*.t}"], vec!["--files="]),
    ] {
        let f = Fixture::new();
        let before = f.invoke(&[], &erased, false);
        assert!(before.status.success(), "{}", err(&before));
        let before_log = f.log();
        let failed = f
            .command(false)
            .env("FAIL", "1")
            .arg("run")
            .arg("--")
            .arg(&f.runner)
            .args(&hook)
            .output()
            .unwrap();
        assert_eq!(failed.status.code(), Some(1), "{}", err(&failed));
        fs::write(f.root.join("log"), before_log).unwrap();
        let after = f.invoke(&[], &erased, false);
        assert!(after.status.success(), "{}", err(&after));
        assert!(err(&after).contains("quote"), "{}", err(&after));
        assert!(!err(&after).contains("stoop: skip"), "{}", err(&after));
        assert_eq!(f.log(), "changed=<>\n");
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn explicit_keys_cannot_share_hook_and_ordinary_proofs() {
    let f = Fixture::new();
    let first = f.invoke(&["--key", "same"], &["--files", "one.t"], false);
    assert!(first.status.success(), "{}", err(&first));
    let hook = f.invoke(&["--key", "same"], &["--files", "{changed}"], false);
    assert!(hook.status.success(), "{}", err(&hook));
    assert!(!err(&hook).contains("stoop: skip"), "{}", err(&hook));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn a_placeholder_cannot_be_the_executable() {
    let f = Fixture::new();
    let out = f
        .command(true)
        .args(["run", "--", "{changed}"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_placeholder_takes_only_one_filter() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed:*.t:*.u}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_first_sighting_records_the_template_before_the_run_outcome() {
    let f = Fixture::new();
    let failed = f
        .command(false)
        .env("FAIL", "1")
        .args(["run", "--", "./runner", "--files", "{changed}"])
        .output()
        .unwrap();
    assert_eq!(failed.status.code(), Some(1), "{}", err(&failed));
    let catalog = fs::read_to_string(f.root.join(".stoop/hooks-v1.json")).unwrap();
    assert!(catalog.contains("{changed}"), "{catalog}");
}

#[test]
fn several_values_before_the_placeholder_are_refused_with_the_documented_fix() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "a", "b", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    let text = err(&out);
    assert!(
        text.contains("cannot tell where the values for --files end"),
        "{text}"
    );
    assert!(text.contains("attach the placeholder with ="), "{text}");
    assert!(text.contains("after --"), "{text}");
    assert!(!text.contains("=VALUE"), "{text}");
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_single_valued_python_module_option_is_refused_without_the_value_syntax() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-m", "pytest", "{changed:test_*.py}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        err(&out).contains("cannot tell where the values for -m end"),
        "{}",
        err(&out)
    );
    assert!(!err(&out).contains("=VALUE"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_repeated_option_with_an_ambiguous_value_extent_is_refused() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files={changed}", "--files", "a", "b"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        !f.root.join("log").exists(),
        "the command must not run as ./t b"
    );
}

#[test]
fn a_brace_inside_a_filter_is_a_usage_error() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed:*.t{x}}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn changed_inputs_takes_no_filter() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed-inputs:*.t}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_placeholder_takes_one_modifier_per_group() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed:cwd:root}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn an_attached_short_option_is_ambiguous_beside_a_short_placeholder() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-fbase", "-f{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn an_empty_long_option_value_gets_the_hint_and_runs_as_typed() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files="], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("--files has an empty value"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "arg=<--files=>\nchanged=<UNSET>\n");
}

#[test]
fn a_placeholder_cannot_occupy_the_dollar_zero_of_a_shell_string() {
    let f = Fixture::new();
    let out = f
        .command(true)
        .args(["run", "--", "sh", "-c", "printf %s \"$0\"", "{changed}"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_brace_form_with_a_short_option_prefix_is_refused() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-fchanged:x.t"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn a_double_colon_word_is_an_ordinary_argument() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["units::hook::tests"], true);
    assert!(out.status.success(), "{}", err(&out));
    assert_eq!(f.log(), "arg=<units::hook::tests>\nchanged=<UNSET>\n");
}

#[test]
fn a_single_colon_brace_shape_is_refused_and_names_the_literal_escape() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--only", "unit:true"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("--literal"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[test]
fn an_argument_hint_cannot_start_a_workflow_command_line() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--only\n::warning::injected", ""], false);
    assert!(out.status.success(), "{}", err(&out));
    let text = err(&out);
    assert!(!text.contains("::warning::"), "{text}");
    assert!(
        text.lines()
            .all(|line| !line.starts_with("::") && !line.starts_with("##[")),
        "{text}"
    );
    assert!(text.contains("%3A%3Awarning"), "{text}");
}

#[test]
fn a_removed_word_cannot_carry_a_workflow_command_prefix() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed:##[error]x}"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains("##["), "{}", err(&out));
    assert!(err(&out).contains("#%23[error]x"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn a_cut_off_word_cannot_carry_a_workflow_command_prefix() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["{changed:##[error]x"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(err(&out).contains("is cut off"), "{}", err(&out));
    assert!(!err(&out).contains("##["), "{}", err(&out));
}

#[test]
fn a_refusal_carrying_a_newline_stays_on_one_line() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-f\n::error::injected", "a", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        err(&out).lines().all(|line| !line.starts_with("::")),
        "{}",
        err(&out)
    );
}

#[test]
fn a_recorded_template_expires_on_read() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    set_created(&f, 0);
    fs::remove_file(f.root.join("log")).unwrap();
    let out = f.invoke(&[], &["--files", ""], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains("the shell expanded"), "{}", err(&out));
    assert!(
        err(&out).contains("--files has an empty value"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "arg=<--files>\narg=<>\nchanged=<UNSET>\n");
}

#[test]
fn a_run_with_a_short_max_age_keeps_other_commands_templates() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    set_created(&f, 0);
    let out = f
        .command(false)
        .args(["run", "--max-age", "60", "--"])
        .arg(&f.runner)
        .args(["--only", "{changed}"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", err(&out));
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root.join(".stoop/hooks-v1.json")).unwrap()).unwrap();
    let kept = catalog["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|record| record["argv"].to_string().contains("--files"));
    assert!(kept, "{catalog}");
}

fn set_created(f: &Fixture, created: u64) {
    let path = f.root.join(".stoop/hooks-v1.json");
    let mut catalog: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    for record in catalog["records"].as_array_mut().unwrap() {
        record["created"] = serde_json::json!(created);
    }
    fs::write(&path, serde_json::to_vec(&catalog).unwrap()).unwrap();
}

#[test]
fn explain_names_the_expanded_hook_and_the_argv_it_would_run() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    fs::remove_file(f.root.join("log")).unwrap();
    let out = f
        .command(false)
        .args(["explain", "--"])
        .arg(&f.runner)
        .arg("--files")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    let text = err(&out);
    assert!(
        text.contains("would run full: the shell expanded the recorded hook"),
        "{text}"
    );
    assert!(text.contains("--files '{changed}'"), "{text}");
    assert!(text.contains("it would run"), "{text}");
    assert!(!f.root.join("log").exists());
}

#[test]
fn explain_names_an_empty_value_with_no_recorded_hook() {
    let f = Fixture::new();
    let out = f
        .command(false)
        .args(["explain", "--"])
        .arg(&f.runner)
        .args(["--only", ""])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    assert!(
        err(&out).contains("would run as typed: no hook recorded with a placeholder at --only"),
        "{}",
        err(&out)
    );
    assert!(!f.root.join("log").exists());
}

#[test]
fn stoop_off_still_prints_the_empty_value_hint() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--only", ""], true);
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("--only has an empty value"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "arg=<--only>\narg=<>\nchanged=<UNSET>\n");
}

#[test]
fn stoop_off_runs_an_expanded_shape_as_its_full_form() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    let out = f.invoke(&[], &["--files", ""], true);
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("the shell expanded"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn an_expanded_line_names_the_option_the_full_command_drops() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["-y", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    let out = f.invoke(&[], &["-y"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("after -y"), "{}", err(&out));
    assert!(err(&out).contains("drops -y"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn several_recorded_full_forms_do_not_refuse_a_plain_command() {
    let f = Fixture::new();
    assert!(f.invoke(&[], &["{changed}", "-x"], false).status.success());
    assert!(f.invoke(&[], &["-x", "{changed}"], false).status.success());
    let out = f.invoke(&[], &["-x"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(
        err(&out).contains("matches 2 recorded hooks"),
        "{}",
        err(&out)
    );
    assert_eq!(f.log(), "arg=<-x>\nchanged=<UNSET>\n");
}

#[test]
fn explain_never_launches_and_no_split_is_refused() {
    let f = Fixture::new();
    let out = f.invoke(&["--no-split"], &["--files", "{changed}"], true);
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
    assert!(
        err(&out).contains("unknown option --no-split"),
        "{}",
        err(&out)
    );
    assert!(!f.root.join("log").exists());
    let out = f
        .command(false)
        .args(["explain", "--"])
        .arg(&f.runner)
        .arg("{changed}")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", err(&out));
    assert!(err(&out).contains("{changed}"), "{}", err(&out));
    assert!(!f.root.join("log").exists());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn an_ambiguous_plain_command_never_skips_on_a_stored_proof() {
    let f = Fixture::new();
    assert!(f.invoke(&[], &["{changed}", "-x"], false).status.success());
    assert!(f.invoke(&[], &["-x", "{changed}"], false).status.success());
    let first = f.invoke(&[], &["-x"], false);
    assert!(first.status.success(), "{}", err(&first));
    let second = f.invoke(&[], &["-x"], false);
    assert!(second.status.success(), "{}", err(&second));
    assert!(!err(&second).contains("stoop: skip"), "{}", err(&second));
}

#[test]
fn a_removed_word_cannot_carry_a_raw_control_character() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed:\u{1b}x}"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains('\u{1b}'), "{:?}", err(&out));
    assert!(err(&out).contains("\\u{1b}"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn two_recorded_forms_with_one_full_command_still_expand_to_it() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed}"], false);
    assert!(out.status.success(), "{}", err(&out));
    let out = f.invoke(&[], &["--files", "{changed:*.t}"], false);
    assert!(out.status.success(), "{}", err(&out));
    let out = f.invoke(&[], &["--files", ""], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(err(&out).contains("the shell expanded"), "{}", err(&out));
    assert!(!err(&out).contains("matches 2 recorded hooks"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}

#[test]
fn three_identical_hook_runs_leave_one_record() {
    let f = Fixture::new();
    for _ in 0..3 {
        let out = f.invoke(&[], &["--files", "{changed}"], false);
        assert!(out.status.success(), "{}", err(&out));
    }
    let catalog: serde_json::Value =
        serde_json::from_slice(&fs::read(f.root.join(".stoop/hooks-v1.json")).unwrap()).unwrap();
    assert_eq!(catalog["records"].as_array().unwrap().len(), 1, "{catalog}");
}

#[test]
fn a_removed_word_with_bidi_formatting_prints_as_text() {
    let f = Fixture::new();
    let out = f.invoke(&[], &["--files", "{changed:\u{202e}x}"], false);
    assert!(out.status.success(), "{}", err(&out));
    assert!(!err(&out).contains('\u{202e}'), "{:?}", err(&out));
    assert!(err(&out).contains("\\u{202e}"), "{}", err(&out));
    assert_eq!(f.log(), "changed=<>\n");
}
