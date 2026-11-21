//! Regressions from independent review of the read-only unit catalog.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    base: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "stoop-review-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let root = base.join("root");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(base.join("home")).unwrap();
        Self { base, root }
    }

    fn file(&self, path: &str, bytes: &[u8]) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn git(&self, args: &[&str]) {
        let out = Command::new("git")
            .current_dir(&self.root)
            .env("HOME", self.base.join("home"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn command(&self, action: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.base.join("home"))
            .env("STOOP_STORE", self.root.join(".stoop"))
            .current_dir(&self.root)
            .args([action, "--root", ".", "--no-learn-volatile", "--"])
            .args(args);
        cmd
    }

    fn explain(&self, placeholder: &str) -> Output {
        bounded(self.command("explain", &["runner", placeholder]))
    }

    fn fake_git(&self, body: &str) -> PathBuf {
        let bin = self.base.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let git = bin.join("git");
        fs::write(&git, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&git, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(self.root.join(".git")).unwrap();
        bin
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn bounded(mut command: Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let drain = |mut reader: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).unwrap();
            bytes
        })
    };
    let stdout = drain(Box::new(stdout));
    let stderr = drain(Box::new(stderr));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return Output {
                status,
                stdout: stdout.join().unwrap(),
                stderr: stderr.join().unwrap(),
            };
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            let _ = stdout.join().unwrap();
            let stderr = stderr.join().unwrap();
            panic!(
                "explain blocked ({status}): {}",
                String::from_utf8_lossy(&stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn err(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
fn unknown(output: &Output) {
    assert!(
        err(output).contains("stoop: no unit universe:"),
        "{}",
        err(output)
    );
}

#[test]
fn native_shell_fallback_is_not_a_conflicting_unit_filter() {
    let f = Fixture::new();
    let out = f
        .command(
            "run",
            &[
                "sh",
                "-c",
                "printf '<%s>\\n' \"${STOOP_CHANGED:-fallback}\" \"$@\"",
                "sentinel",
                "--files",
                "{changed:*.t}",
            ],
        )
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(out.stdout, b"<fallback>\n");
}

#[test]
fn single_quoted_shell_placeholder_text_stays_literal() {
    let f = Fixture::new();
    let out = f
        .command(
            "run",
            &[
                "sh",
                "-c",
                "printf '%s\\n' '${STOOP_CHANGED:*.u}'",
                "sentinel",
                "--files",
                "{changed:*.t}",
            ],
        )
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", err(&out));
    assert_eq!(out.stdout, b"${STOOP_CHANGED:*.u}\n");
}

#[test]
fn bash_array_and_multiline_arithmetic_stay_native() {
    let f = Fixture::new();
    for code in [
        "printf '<%s>\\n' \"${STOOP_CHANGED: a[\"0\"]}\" \"$@\"",
        "printf '<%s>\\n' \"${STOOP_CHANGED: 1\n + 1}\" \"$@\"",
    ] {
        let out = f
            .command(
                "run",
                &["bash", "-c", code, "sentinel", "--files", "{changed:*.t}"],
            )
            .env("STOOP_OFF", "1")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(0), "{code:?}: {}", err(&out));
        assert_eq!(out.stdout, b"<>\n");
    }
}

#[test]
fn unmodeled_shell_operand_uses_config_and_reports_the_fallback() {
    let f = Fixture::new();
    f.file("a.t", b"");
    f.file(
        ".stoop.toml",
        b"[[units.suite]]\nid = 'shell'\nmatch = ['sh', '-c', '*', 'zero']\nunits = ['*.t']\n",
    );
    for code in [
        "echo $(printf x) ${STOOP_CHANGED:*.u}",
        "echo $'x' ${STOOP_CHANGED:*.u}",
        "echo `printf x` ${STOOP_CHANGED:*.u}",
        "echo x # ${STOOP_CHANGED:*.u}",
        "cat <<EOF\n${STOOP_CHANGED:*.u}\nEOF",
        "echo $(printf %s ${STOOP_CHANGED:*.u})",
        "echo ${STOOP_CHANGED:*.u} '",
        "echo ${STOOP_CHANGED:*.u} \\",
    ] {
        let out = f
            .command("explain", &["sh", "-c", code, "zero"])
            .output()
            .unwrap();
        let text = err(&out);
        assert!(
            text.contains("tracked 1 units; filter '*.t'"),
            "{code:?}: {text}"
        );
        assert!(
            text.contains("unsupported shell syntax"),
            "{code:?}: {text}"
        );
    }
}

#[test]
fn explain_uses_config_for_native_shell_fallback_and_names_the_ambiguity() {
    let f = Fixture::new();
    f.file("a.t", b"");
    f.file(
        ".stoop.toml",
        b"[[units.suite]]\nid = 'shell'\nmatch = ['sh', '-c', '*', 'zero']\nunits = ['*.t']\n",
    );
    let out = f
        .command(
            "explain",
            &[
                "sh",
                "-c",
                "printf '%s\\n' \"${STOOP_CHANGED:-fallback}\"",
                "zero",
            ],
        )
        .output()
        .unwrap();
    let text = err(&out);
    assert!(
        text.contains("tracked 1 units; filter '*.t' (.stoop.toml suite shell)"),
        "{text}"
    );
    assert!(text.contains("native shell"), "{text}");
    assert!(text.contains("{changed:/foo}"), "{text}");
}

#[test]
fn explain_rejects_distinct_real_shell_filters() {
    let f = Fixture::new();
    let out = f
        .command(
            "explain",
            &[
                "sh",
                "-c",
                "echo ${STOOP_CHANGED:*.u} ${STOOP_CHANGED:*.t}",
                "zero",
            ],
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", err(&out));
}

#[test]
fn rooted_exact_name_filter_selects_only_the_top_level_file() {
    let f = Fixture::new();
    f.file("foo", b"");
    f.file("sub/foo", b"");
    let out = f.explain("{changed:/foo}");
    assert!(
        err(&out).contains("tracked 1 units; filter '/foo'"),
        "{}",
        err(&out)
    );
}

#[test]
fn mixed_leading_exclusion_starts_from_the_configured_universe() {
    let f = Fixture::new();
    f.file("tests/fast.t", b"");
    f.file("tests/slow.t", b"");
    f.file("other/smoke.t", b"");
    f.file("main.rs", b"");
    f.file(
        ".stoop.toml",
        b"[[units.suite]]\nid = 'suite'\nmatch = ['runner', '*']\nunits = ['tests/*.t']\n",
    );
    let out = f.explain("{changed:!tests/slow.t|other/smoke.t}");
    assert!(err(&out).contains("tracked 2 units"), "{}", err(&out));
}

#[test]
fn empty_character_classes_do_not_select_files_and_preserve_full_runs() {
    for class in ["[]", "[!]", "[^]"] {
        let f = Fixture::new();
        f.file("normal.t", b"");
        let placeholder = format!("{{changed:{class}*.t}}");
        let out = f.explain(&placeholder);
        unknown(&out);
        let run = f
            .command("run", &["/bin/echo", &placeholder])
            .env("STOOP_OFF", "1")
            .output()
            .unwrap();
        assert!(run.status.success(), "{}", err(&run));
        assert_eq!(run.stdout, b"\n");
    }
}

#[test]
fn pathological_no_match_catalog_exhausts_a_bounded_work_budget() {
    let f = Fixture::new();
    for i in 0..800 {
        f.file(&format!("tests/{}-{i:04}.t", "a".repeat(220)), b"");
    }
    let pattern = format!("tests/{}z", "*a".repeat(1024));
    f.file(".stoop.toml", format!("[[units.suite]]\nid = 'suite'\nmatch = ['runner', '{{changed}}']\nunits = ['{pattern}']\n").as_bytes());
    let out = f.explain("{changed}");
    unknown(&out);
    assert!(err(&out).contains("budget"), "{}", err(&out));
}

#[test]
fn excessive_filter_length_and_pattern_count_leave_the_universe_unknown() {
    for pattern in ["a".repeat(65_537), format!("{}a", "a|".repeat(2048))] {
        let f = Fixture::new();
        f.file("a.t", b"");
        let placeholder = format!("{{changed:{pattern}}}");
        let out = f.explain(&placeholder);
        unknown(&out);
        let run = f
            .command("run", &["/bin/echo", &placeholder])
            .env("STOOP_OFF", "1")
            .output()
            .unwrap();
        assert!(run.status.success(), "{}", err(&run));
        assert_eq!(run.stdout, b"\n");
    }
}

#[test]
fn overlong_exclusion_only_filter_keeps_the_legacy_refusal() {
    let f = Fixture::new();
    let placeholder = format!("{{changed:!{}}}", "a".repeat(65_537));
    let run = f
        .command("run", &["/bin/echo", &placeholder])
        .env("STOOP_OFF", "1")
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(2), "{}", err(&run));
}

#[test]
fn ignore_symlink_outside_root_is_refused() {
    let f = Fixture::new();
    f.file("a.t", b"");
    let outside = f.base.join("outside-ignore");
    fs::write(&outside, b"a.t\n").unwrap();
    symlink(&outside, f.root.join(".stoopignore")).unwrap();
    unknown(&f.explain("{changed:*.t}"));
}

#[test]
fn ignore_fifo_is_refused_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    let f = Fixture::new();
    let path = std::ffi::CString::new(f.root.join(".stoopignore").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    unknown(&f.explain("{changed:*.t}"));
}

#[test]
fn oversized_ignore_file_is_refused_but_regular_ignore_is_applied() {
    let f = Fixture::new();
    f.file("a.t", b"");
    f.file(".stoopignore", b"a.t\n");
    assert!(err(&f.explain("{changed:*.t}")).contains("tracked 0 units"));
    f.file(".stoopignore", &vec![b'x'; 1024 * 1024 + 1]);
    unknown(&f.explain("{changed:*.t}"));
}

#[test]
fn git_case_spelling_mismatch_never_silently_drops_a_unit() {
    let f = Fixture::new();
    f.git(&["init", "-q"]);
    f.git(&["config", "core.ignorecase", "true"]);
    f.file("sample.t", b"");
    f.git(&["add", "sample.t"]);
    fs::rename(f.root.join("sample.t"), f.root.join("temporary.t")).unwrap();
    fs::rename(f.root.join("temporary.t"), f.root.join("Sample.t")).unwrap();
    let out = f.explain("{changed:*.t}");
    let text = err(&out);
    assert!(
        text.contains("no unit universe:") || text.contains("tracked 1 units"),
        "{text}"
    );
}

fn explain_with_fake_git(f: &Fixture, script: &str) -> Output {
    let bin = f.fake_git(script);
    let mut cmd = f.command("explain", &["runner", "{changed:*.t}"]);
    cmd.env("PATH", format!("{}:/usr/bin:/bin", bin.display()));
    bounded(cmd)
}

#[test]
fn git_case_and_unicode_spelling_mismatches_fail_closed() {
    for (walked, reported) in [("Sample.t", "sample.t"), ("cafe\u{301}.t", "café.t")] {
        let f = Fixture::new();
        f.file(walked, b"");
        let script = format!(
            "case \" $* \" in *' --cached '*) printf '%s\\000' '{reported}' ;; esac\nexit 0"
        );
        unknown(&explain_with_fake_git(&f, &script));
    }
}

#[test]
fn unclassified_git_file_makes_the_universe_unknown() {
    let f = Fixture::new();
    f.file("a.t", b"");
    unknown(&explain_with_fake_git(&f, "exit 0"));
}

#[test]
fn changing_git_inventory_between_probes_makes_the_universe_unknown() {
    let f = Fixture::new();
    f.file("a.t", b"");
    let script = "case \" $* \" in *' --cached '*) if [ ! -e \"$HOME/counter\" ]; then : > \"$HOME/counter\"; printf 'a.t\\000'; fi ;; esac\nexit 0";
    unknown(&explain_with_fake_git(&f, script));
}
