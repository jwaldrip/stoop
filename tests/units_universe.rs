//! Read-only unit catalog discovery through the public CLI.
#![cfg(any(target_os = "linux", target_os = "macos"))]

#[cfg(unix)]
use std::collections::BTreeMap;
use std::fs;
#[cfg(unix)]
use std::path::Path;
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
            "stoop-universe-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn file(&self, path: &str) {
        let path = self.root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"fixture\n").unwrap();
    }

    fn config(&self, source: &str) {
        fs::write(self.root.join(".stoop.toml"), source).unwrap();
    }

    fn command(&self, action: &str, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stoop"))
            .current_dir(&self.root)
            .env("HOME", &self.root)
            .env("STOOP_STORE", self.root.join(".stoop"))
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env_remove("STOOP_SYNC")
            .args([action, "--root", ".", "--no-learn-volatile", "--"])
            .args(args)
            .output()
            .unwrap()
    }

    fn explain(&self, placeholder: &str) -> String {
        let output = self.command("explain", &["runner", placeholder]);
        assert_ne!(output.status.code(), Some(2), "{}", stderr(&output));
        stderr(&output)
    }

    fn git(&self, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(&self.root)
            .env("HOME", &self.root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", stderr(&output));
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

fn tracked(output: &str, count: usize) {
    assert!(
        output.contains(&format!("stoop: tracked {count} units; filter '")),
        "{output}"
    );
}

#[cfg(unix)]
fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(base: &Path, current: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(base, &path, result);
            } else {
                result.insert(
                    path.strip_prefix(base).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut result = BTreeMap::new();
    if root.exists() {
        visit(root, root, &mut result);
    }
    result
}

#[test]
fn explain_counts_units_for_an_inline_filter() {
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file("sub/b.t");
    f.file("src/main.rs");
    let output = f.explain("{changed:**/*.t}");
    tracked(&output, 2);
    assert!(output.contains("(inline)"), "{output}");
}

#[test]
fn config_units_is_the_default_filter() {
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file("other/b.t");
    f.config(
        "[[units.suite]]\nid = 'tests'\nmatch = ['runner', '{changed}']\nunits = ['tests/*.t']\n",
    );
    let output = f.explain("{changed}");
    tracked(&output, 1);
    assert!(output.contains(".stoop.toml suite tests"), "{output}");
}

#[test]
fn an_inline_filter_overrides_config() {
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file("other/a.t");
    f.file("other/b.t");
    f.config("[[units.suite]]\nid = 'tests'\nmatch = ['runner', '*']\nunits = ['tests/*.t']\n");
    let output = f.explain("{changed:other/*.t}");
    tracked(&output, 2);
    assert!(output.contains("(inline)"), "{output}");
}

#[test]
fn an_exclusion_only_filter_narrows_config_units() {
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file("slow/a.t");
    f.file("other/not-a-unit.u");
    f.config("[[units.suite]]\nid = 'tests'\nmatch = ['runner', '*']\nunits = ['**/*.t']\n");
    tracked(&f.explain("{changed:!slow/**}"), 1);
}

#[test]
fn explain_without_a_universe_suggests_a_filter() {
    let f = Fixture::new();
    f.file("tests/a.test.ts");
    let output = f.explain("{changed}");
    assert!(output.contains("stoop: no unit universe:"), "{output}");
    assert!(output.contains("*.test."), "{output}");
}

#[test]
fn the_walk_skips_git_store_and_stoopignore() {
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file("nested/.git/hidden.t");
    f.file(".stoop/hidden.t");
    f.file("ignored/hidden.t");
    fs::write(f.root.join(".stoopignore"), "ignored\n").unwrap();
    tracked(&f.explain("{changed:**/*.t}"), 1);
}

#[test]
fn the_walk_skips_git_ignored_paths_but_keeps_tracked_files() {
    let f = Fixture::new();
    f.git(&["init", "-q"]);
    fs::write(f.root.join(".gitignore"), "ignored/\n*.secret.t\n").unwrap();
    f.file("tests/a.t");
    f.file("ignored/b.t");
    f.file("tracked.secret.t");
    f.git(&["add", "-f", "tracked.secret.t"]);
    tracked(&f.explain("{changed:**/*.t}"), 2);
}

#[cfg(unix)]
#[test]
fn directory_symlinks_are_not_followed() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let external = Fixture::new();
    f.file("tests/a.t");
    external.file("outside.t");
    symlink(&external.root, f.root.join("linked")).unwrap();
    symlink(f.root.join("tests/a.t"), f.root.join("file-link.t")).unwrap();
    tracked(&f.explain("{changed:**/*.t}"), 1);
}

#[test]
fn more_than_4096_units_is_an_unknown_universe() {
    let f = Fixture::new();
    for i in 0..4097 {
        f.file(&format!("tests/{i:04}.t"));
    }
    let output = f.explain("{changed:**/*.t}");
    assert!(output.contains("stoop: no unit universe:"), "{output}");
    assert!(output.contains("4096"), "{output}");
    assert!(!output.contains("stoop: tracked 4096 units"), "{output}");
}

#[cfg(unix)]
#[test]
fn explain_walks_but_never_launches_or_writes() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    f.file("tests/a.t");
    f.file(".stoop/proofs/example.json");
    f.file(".stoop/other/nested");
    fs::write(f.root.join("runner"), "#!/bin/sh\ntouch launched\n").unwrap();
    fs::set_permissions(f.root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
    let before = snapshot(&f.root.join(".stoop"));
    let output = f.command("explain", &["./runner", "{changed:**/*.t}"]);
    tracked(&stderr(&output), 1);
    assert!(!f.root.join("launched").exists());
    assert_eq!(snapshot(&f.root.join(".stoop")), before);
}

#[test]
fn two_filters_in_one_command_are_a_usage_error() {
    let f = Fixture::new();
    let output = f.command("explain", &["runner", "{changed:*.t}", "{unit:*.u}"]);
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(!f.root.join(".stoop").exists());
}

#[cfg(unix)]
#[test]
fn a_hooked_run_preserves_the_full_command_argv() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new();
    fs::write(
        f.root.join("runner"),
        "#!/bin/sh\nprintf 'argc=%s\\n' \"$#\"\nfor arg do printf '<%s>\\n' \"$arg\"; done\n",
    )
    .unwrap();
    fs::set_permissions(f.root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .current_dir(&f.root)
        .env("STOOP_OFF", "1")
        .args([
            "run",
            "--root",
            ".",
            "--no-record",
            "--",
            "./runner",
            "--verbose",
            "--files={changed:*.t}",
            "tail",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, b"argc=2\n<--verbose>\n<tail>\n");
}

#[test]
fn matcher_globs_obey_anchoring_case_and_double_star() {
    let f = Fixture::new();
    for path in ["a.t", "A.T", "tests/a.t", "tests/sub/b.t", "sub/tests/c.t"] {
        f.file(path);
    }
    for (pattern, count) in [
        ("*.t", 4),
        ("**/*.t", 4),
        ("tests/*.t", 1),
        ("tests/**/b.t", 1),
        ("**/tests/*.t", 2),
        ("A.t", 0),
    ] {
        tracked(&f.explain(&format!("{{changed:{pattern}}}")), count);
    }
}

#[test]
fn matcher_last_match_wins_and_escaped_metacharacters_are_literal() {
    let f = Fixture::new();
    for path in ["tests/a.t", "tests/b.t", "tests/literal!.t", "other/c.t"] {
        f.file(path);
    }
    tracked(&f.explain("{changed:**/*.t|!tests/**|tests/a.t}"), 2);
    tracked(&f.explain(r"{changed:**/literal\!.t}"), 1);
    tracked(&f.explain("{changed:tests/[ab].t}"), 2);
}

#[test]
fn matcher_directory_only_pattern_does_not_match_files() {
    let f = Fixture::new();
    f.file("tests/a.t");
    tracked(&f.explain("{changed:**/*.t/}"), 0);
}
