//! Command identity and root discovery, exercised through the real binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Workspace(PathBuf);

impl Workspace {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "stoop-cwd-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }

    fn dir(&self, path: &str) -> PathBuf {
        let dir = self.0.join(path);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn repo(&self, path: &str) -> PathBuf {
        let dir = self.dir(path);
        fs::create_dir(dir.join(".git")).unwrap();
        dir
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn stoop(cwd: &Path, args: &[&str], store: Option<&Path>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_stoop"));
    cmd.current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(args);
    if let Some(store) = store {
        cmd.env("STOOP_STORE", store);
    }
    cmd.output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn key(out: &Output) -> String {
    let text = stderr(out);
    let line = text
        .lines()
        .find(|line| line.starts_with("stoop: would run ") || line.starts_with("stoop: run "))
        .unwrap_or_else(|| panic!("no command key in {text}"));
    let name = line
        .strip_prefix("stoop: would run ")
        .or_else(|| line.strip_prefix("stoop: run "))
        .unwrap();
    name.split_whitespace()
        .next()
        .unwrap()
        .trim_end_matches(':')
        .to_string()
}

fn explain(cwd: &Path, store: Option<&Path>) -> Output {
    stoop(cwd, &["explain", "--", "cat", "./data.txt"], store)
}

fn write_proof(store: &Path, key: &str, cwd: Option<&str>) {
    let dir = store.join("proofs");
    fs::create_dir_all(&dir).unwrap();
    let mut proof = serde_json::json!({
        "created": 4_000_000_000u64,
        "argv": ["cat", "./data.txt"],
        "provenance": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "tracer": "ptrace-seccomp",
            "version": 1
        },
        "env": {"PATH": blake3::hash(b"/usr/bin:/bin").to_hex().to_string()},
        "inputs": [],
        "outputs": [],
        "probes": {}
    });
    if let Some(cwd) = cwd {
        proof["cwd"] = cwd.into();
    }
    fs::write(
        dir.join(format!("{key}.json")),
        serde_json::to_vec(&serde_json::json!({"v": 2, "key": key, "proofs": [proof]})).unwrap(),
    )
    .unwrap();
}

#[test]
fn relative_directory_is_part_of_default_key() {
    let w = Workspace::new();
    let root = w.repo("repo");
    let a = w.dir("repo/a");
    let b = w.dir("repo/b");
    let root_key = key(&explain(&root, None));
    let a_key = key(&explain(&a, None));
    let b_key = key(&explain(&b, None));
    assert_ne!(root_key, a_key);
    assert_ne!(a_key, b_key);
    assert_ne!(root_key, b_key);
}

#[test]
fn git_file_and_nested_repository_set_the_nearest_root() {
    let w = Workspace::new();
    let outer = w.repo("outer");
    let inner = w.dir("outer/inner");
    fs::write(inner.join(".git"), "gitdir: ../elsewhere\n").unwrap();
    let sub = w.dir("outer/inner/sub");
    let other = w.repo("other");
    let other_sub = w.dir("other/sub");
    assert_eq!(key(&explain(&sub, None)), key(&explain(&other_sub, None)));
    assert_ne!(key(&explain(&sub, None)), key(&explain(&inner, None)));
    let outer_root = outer.to_str().unwrap();
    let from_outer = stoop(
        &sub,
        &["explain", "--root", outer_root, "--", "cat", "./data.txt"],
        None,
    );
    assert_ne!(key(&explain(&sub, None)), key(&from_outer));
    assert!(other.join(".git").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_and_dotdot_roots_resolve_to_the_physical_directory() {
    use std::os::unix::fs::symlink;

    let w = Workspace::new();
    let root = w.repo("repo");
    let sub = w.dir("repo/sub");
    let link = w.0.join("repo-link");
    symlink(&root, &link).unwrap();
    let physical = key(&explain(&sub, None));
    assert_eq!(physical, key(&explain(&link.join("sub"), None)));
    let explicit_link = stoop(
        &sub,
        &[
            "explain",
            "--root",
            link.to_str().unwrap(),
            "--",
            "cat",
            "./data.txt",
        ],
        None,
    );
    assert_eq!(physical, key(&explicit_link));
    let explicit_dotdot = stoop(
        &sub,
        &["explain", "--root", "../sub/..", "--", "cat", "./data.txt"],
        None,
    );
    assert_eq!(physical, key(&explicit_dotdot));
    let sub_link = w.0.join("sub-link");
    symlink(&sub, &sub_link).unwrap();
    let through_link = sub_link.join("..");
    let out = stoop(
        &sub,
        &[
            "explain",
            "--root",
            through_link.to_str().unwrap(),
            "--",
            "cat",
            "./data.txt",
        ],
        None,
    );
    assert_eq!(physical, key(&out));
}

#[test]
fn roots_without_git_are_separate_even_in_one_shared_store() {
    let w = Workspace::new();
    let a = w.dir("a");
    let b = w.dir("b");
    let store = w.dir("shared");
    assert_eq!(key(&explain(&a, None)), key(&explain(&b, None)));
    assert_ne!(a.join(".stoop"), b.join(".stoop"));
    assert_ne!(
        key(&explain(&a, Some(&store))),
        key(&explain(&b, Some(&store)))
    );
    let root = w.0.to_str().unwrap();
    let args = ["explain", "--root", root, "--", "cat", "./data.txt"];
    assert_ne!(
        key(&stoop(&a, &args, Some(&store))),
        key(&stoop(&b, &args, Some(&store)))
    );
}

#[test]
fn different_repositories_do_not_collide_in_a_shared_store() {
    let w = Workspace::new();
    w.repo("one");
    w.repo("two");
    let a = w.dir("one/sub");
    let b = w.dir("two/sub");
    let store = w.dir("shared");
    assert_ne!(
        key(&explain(&a, Some(&store))),
        key(&explain(&b, Some(&store)))
    );
    let store_arg = store.to_str().unwrap();
    let args = ["explain", "--store", store_arg, "--", "cat", "./data.txt"];
    assert_ne!(key(&stoop(&a, &args, None)), key(&stoop(&b, &args, None)));
}

#[test]
fn checkouts_with_the_same_origin_can_share_a_store() {
    let w = Workspace::new();
    let store = w.dir("shared");
    let mut keys = Vec::new();
    for name in ["first", "second"] {
        let root = w.dir(name);
        for args in [
            vec!["init", "-q"],
            vec![
                "remote",
                "add",
                "origin",
                "https://example.test/project.git",
            ],
        ] {
            let out = Command::new("git")
                .current_dir(&root)
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", stderr(&out));
        }
        let sub = root.join("sub");
        fs::create_dir(&sub).unwrap();
        keys.push(key(&explain(&sub, Some(&store))));
    }
    assert_eq!(keys[0], keys[1]);
}

#[test]
fn directory_names_are_escaped_in_diagnostics() {
    let w = Workspace::new();
    w.repo("repo");
    let sub = w.dir("repo/a\nb");
    let out = explain(&sub, None);
    assert!(stderr(&out).contains("dir \"a\\nb\""), "{}", stderr(&out));
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_directories_do_not_share_keys() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let w = Workspace::new();
    let root = w.repo("repo");
    let a = root.join(OsString::from_vec(b"dir-\x80".to_vec()));
    let b = root.join(OsString::from_vec(b"dir-\x81".to_vec()));
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    assert_ne!(key(&explain(&a, None)), key(&explain(&b, None)));
}

#[test]
fn explicitly_named_proofs_cannot_skip_from_another_directory() {
    let w = Workspace::new();
    let root = w.repo("repo");
    let a = w.dir("repo/a");
    let b = w.dir("repo/b");
    write_proof(&root.join(".stoop"), "manual", Some("a"));
    let args = ["explain", "--key", "manual", "--", "cat", "./data.txt"];
    let in_a = stoop(&a, &args, None);
    assert_eq!(
        in_a.status.success(),
        cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        "{}",
        stderr(&in_a)
    );
    let in_b = stoop(&b, &args, None);
    assert_eq!(in_b.status.code(), Some(1), "{}", stderr(&in_b));
}

#[test]
fn legacy_proof_without_a_directory_cannot_hide_a_command() {
    let w = Workspace::new();
    let root = w.repo("repo");
    let sub = w.dir("repo/sub");
    write_proof(&root.join(".stoop"), "manual", None);
    let out = stoop(
        &sub,
        &["explain", "--key", "manual", "--", "cat", "./data.txt"],
        None,
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn explain_and_ls_name_the_directory() {
    let w = Workspace::new();
    let root = w.repo("repo");
    let sub = w.dir("repo/sub");
    let miss = explain(&sub, None);
    assert!(stderr(&miss).contains("dir \"sub\""), "{}", stderr(&miss));
    write_proof(&root.join(".stoop"), "manual", Some("sub"));
    let hit = stoop(
        &sub,
        &["explain", "--key", "manual", "--", "cat", "./data.txt"],
        None,
    );
    assert_eq!(
        hit.status.success(),
        cfg!(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )),
        "{}",
        stderr(&hit)
    );
    assert!(stderr(&hit).contains("dir \"sub\""), "{}", stderr(&hit));
    let ls = stoop(&root, &["ls"], None);
    let text = String::from_utf8_lossy(&ls.stdout);
    assert!(
        text.contains("manual") && text.contains("dir \"sub\""),
        "{text}"
    );
}

#[test]
fn shell_mode_keys_include_script_arguments_and_directory() {
    let w = Workspace::new();
    w.repo("repo");
    let a = w.dir("repo/a");
    let b = w.dir("repo/b");
    fs::write(a.join("step.sh"), "exit 0\n").unwrap();
    fs::write(b.join("step.sh"), "exit 0\n").unwrap();
    let first = stoop(&a, &["sh", "step.sh", "one"], None);
    let other_arg = stoop(&a, &["sh", "step.sh", "two"], None);
    let other_dir = stoop(&b, &["sh", "step.sh", "one"], None);
    assert_ne!(key(&first), key(&other_arg));
    assert_ne!(key(&first), key(&other_dir));
}

#[cfg(target_os = "linux")]
mod traced {
    use super::*;

    fn run(cwd: &Path, store: Option<&Path>) -> Output {
        stoop(cwd, &["run", "--", "cat", "./data.txt"], store)
    }

    fn recorded(out: &Output) {
        assert!(
            out.status.success() && stderr(out).contains("recorded"),
            "{}",
            stderr(out)
        );
        assert!(!stderr(out).contains("stoop: skip"), "{}", stderr(out));
    }

    fn skipped(out: &Output) {
        assert!(
            out.status.success() && stderr(out).contains("stoop: skip"),
            "{}",
            stderr(out)
        );
    }

    #[test]
    fn records_and_skips_are_independent_in_both_directions() {
        for reverse in [false, true] {
            let w = Workspace::new();
            let root = w.repo("repo");
            let a = w.dir("repo/a");
            let b = w.dir("repo/b");
            fs::write(root.join("data.txt"), "root").unwrap();
            fs::write(a.join("data.txt"), "a").unwrap();
            fs::write(b.join("data.txt"), "b").unwrap();
            let (first, second) = if reverse { (&b, &a) } else { (&a, &b) };
            let one = run(first, None);
            let two = run(second, None);
            recorded(&one);
            recorded(&two);
            assert_ne!(key(&one), key(&two));
            assert_eq!(fs::read_dir(root.join(".stoop/proofs")).unwrap().count(), 2);
            skipped(&run(first, None));
            skipped(&run(second, None));
            let at_root = run(&root, None);
            recorded(&at_root);
            assert_ne!(key(&at_root), key(&one));
            skipped(&run(&root, None));
            fs::write(first.join("data.txt"), "changed").unwrap();
            skipped(&run(second, None));
            recorded(&run(first, None));
        }
    }

    #[test]
    fn portable_proof_records_relative_inputs_and_survives_a_move() {
        let w = Workspace::new();
        let root = w.repo("repo");
        let sub = w.dir("repo/sub");
        fs::write(sub.join("data.txt"), "same").unwrap();
        let first = run(&sub, None);
        recorded(&first);
        let proof = fs::read_to_string(
            root.join(".stoop/proofs")
                .join(format!("{}.json", key(&first))),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&proof).unwrap();
        let inputs = json["proofs"][0]["inputs"].as_array().unwrap();
        assert!(
            inputs.iter().any(|input| input["path"] == "sub/data.txt"),
            "{proof}"
        );
        assert!(
            !inputs.iter().any(|input| input["path"]
                .as_str()
                .unwrap()
                .starts_with(root.to_str().unwrap())),
            "{proof}"
        );
        let moved = w.0.join("moved");
        fs::rename(&root, &moved).unwrap();
        skipped(&run(&moved.join("sub"), None));
    }

    #[test]
    fn shared_store_keeps_repositories_and_no_git_directories_apart() {
        let w = Workspace::new();
        let store = w.dir("shared");
        let a = w.repo("a");
        let b = w.repo("b");
        for dir in [&a, &b] {
            fs::write(dir.join("data.txt"), "same").unwrap();
        }
        let first = run(&a, Some(&store));
        let second = run(&b, Some(&store));
        recorded(&first);
        recorded(&second);
        assert_ne!(key(&first), key(&second));
        skipped(&run(&a, Some(&store)));
        skipped(&run(&b, Some(&store)));
        let c = w.dir("c");
        let d = w.dir("d");
        for dir in [&c, &d] {
            fs::write(dir.join("data.txt"), "same").unwrap();
            recorded(&run(dir, Some(&store)));
            skipped(&run(dir, Some(&store)));
        }
    }

    #[test]
    fn named_proofs_remain_separate_across_directories_and_roots() {
        let w = Workspace::new();
        let root = w.repo("one");
        let a = w.dir("one/a");
        let b = w.dir("one/b");
        let other = w.repo("two");
        let c = w.dir("two/a");
        let store = w.dir("shared");
        for dir in [&a, &b, &c] {
            fs::write(dir.join("data.txt"), "same").unwrap();
        }
        let run = |cwd: &Path| {
            stoop(
                cwd,
                &["run", "--key", "manual", "--", "cat", "./data.txt"],
                Some(&store),
            )
        };
        for dir in [&a, &b, &c] {
            recorded(&run(dir));
        }
        for dir in [&a, &b, &c] {
            skipped(&run(dir));
        }
        assert!(root.join(".git").exists() && other.join(".git").exists());
    }

    #[test]
    fn directories_without_git_have_separate_default_stores() {
        let w = Workspace::new();
        let a = w.dir("a");
        let b = w.dir("b");
        for dir in [&a, &b] {
            fs::write(dir.join("data.txt"), "same").unwrap();
            recorded(&run(dir, None));
            skipped(&run(dir, None));
            assert_eq!(fs::read_dir(dir.join(".stoop/proofs")).unwrap().count(), 1);
        }
    }
}
