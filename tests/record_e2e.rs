//! What the recorder writes down: priors, removals and reasons, read from the stored
//! proof JSON of a real run. Linux only, because tracing is.
#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

struct Ws {
    root: PathBuf,
}

impl Ws {
    fn new(name: &str) -> Ws {
        let root = std::env::temp_dir().join(format!("stoop-record-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(root.with_file_name(format!(
            "{}-store",
            root.file_name().unwrap().to_string_lossy()
        )));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("in.txt"), "one").unwrap();
        Ws { root }
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn syscall_probe(&self) {
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/recorder_syscalls.c");
        let status = Command::new("cc")
            .arg(source)
            .arg("-o")
            .arg(self.root.join("syscall-probe"))
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn store(&self) -> PathBuf {
        self.root.with_file_name(format!(
            "{}-store",
            self.root.file_name().unwrap().to_string_lossy()
        ))
    }

    /// `stoop run` in the workspace, as a CI step would, with key `t`. Returns (exit, stderr).
    fn sh(&self, script: &str) -> (i32, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
            .args(["run", "--root", ".", "--key", "t", "--", "sh", "-c", script])
            .current_dir(&self.root)
            .env("STOOP_STORE", self.store())
            .env_remove("STOOP_FULL")
            .env_remove("STOOP_OFF")
            .env_remove("GITHUB_ACTIONS")
            .env_remove("RUNNER_TEMP")
            .env_remove("STOOP_MATRIX")
            .env_remove("STOOP_SYNC")
            .env_remove("STOOP_SYNC_WRITE")
            .env_remove("STOOP_ENV_SALT")
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The newest proof stored under key `t`. Panics when the run recorded nothing.
    fn proof(&self) -> Value {
        let file = self.store().join("proofs").join("t.json");
        let v: Value = serde_json::from_slice(&fs::read(&file).expect("a proof was recorded"))
            .expect("the proof file is JSON");
        v["proofs"][0].clone()
    }
}

/// Run `script` and return the newest proof, asserting the run passed and was recorded.
fn recorded(w: &Ws, script: &str) -> Value {
    let (code, err) = w.sh(script);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("recorded"), "not recorded: {err}");
    w.proof()
}

/// (path, id) pairs of a proof array field (`inputs`, `outputs`, `priors`).
fn pairs(p: &Value, field: &str) -> Vec<(String, String)> {
    p[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} is missing"))
        .iter()
        .map(|e| {
            (
                e["path"].as_str().unwrap().to_string(),
                e["id"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

fn prior(p: &Value, path: &str) -> Option<String> {
    pairs(p, "priors")
        .into_iter()
        .find(|(k, _)| k == path)
        .map(|(_, id)| id)
}

fn reasons(p: &Value) -> Vec<String> {
    p["unplannable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect()
}

fn has_reason(p: &Value, needle: &str) -> bool {
    reasons(p).iter().any(|r| r.contains(needle))
}

fn removed(p: &Value) -> Vec<String> {
    p["removed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect()
}

fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[test]
fn sed_in_place_records_the_old_bytes_and_the_temp_file() {
    let w = Ws::new("sed");
    w.write("config.txt", "foo\n");
    let p = recorded(&w, "sed -i s/foo/bar/ config.txt");
    assert_eq!(
        prior(&p, "config.txt"),
        Some(format!("f:{}", hash(b"foo\n")))
    );
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
    let outputs = pairs(&p, "outputs");
    assert!(outputs.contains(&("config.txt".into(), format!("f:{}", hash(b"bar\n")))));
    // sed's temp file was created and renamed away: it is a removal that began absent.
    let temp: Vec<String> = removed(&p);
    assert_eq!(temp.len(), 1, "{temp:?}");
    assert_eq!(prior(&p, &temp[0]), Some("a".into()));
}

#[test]
fn mkdir_then_write_records_both_as_absent_before() {
    let w = Ws::new("mkdir");
    let p = recorded(&w, "mkdir build && echo ok > build/out");
    assert_eq!(prior(&p, "build"), Some("a".into()));
    assert_eq!(prior(&p, "build/out"), Some("a".into()));
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
}

#[test]
fn mkdir_p_on_a_tracked_directory_is_an_input_not_a_prior() {
    let w = Ws::new("mkdirp");
    w.write("src/lib.rs", "x");
    let p = recorded(&w, "mkdir -p src");
    assert_eq!(prior(&p, "src"), None);
    assert!(pairs(&p, "inputs").contains(&("src".into(), "d".into())));
}

#[test]
fn renaming_directories_is_unplannable() {
    let w = Ws::new("dirrename");
    w.write("x/f", "x");
    w.write("y/f", "y");
    let p = recorded(&w, "mv y yold && mv x y");
    assert!(
        has_reason(&p, "renamed the directory y to yold"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn removing_a_tree_names_every_entry_it_removed() {
    let w = Ws::new("rmrf");
    w.write("d/a", "a");
    w.write("d/b", "b");
    let p = recorded(&w, "rm -rf d");
    for path in ["d/a", "d/b", "d"] {
        assert!(
            removed(&p).contains(&path.to_string()),
            "{path} in {:?}",
            removed(&p)
        );
        assert!(prior(&p, path).is_some(), "prior for {path}");
    }
    assert_eq!(prior(&p, "d"), Some("d".into()));
}

#[test]
fn rmdir_of_a_non_empty_directory_is_unplannable() {
    let w = Ws::new("rmdir");
    w.write("d/keep", "k");
    let p = recorded(&w, "rmdir d || true");
    assert!(
        has_reason(&p, "removed the non-empty directory d"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn writing_through_a_symlink_is_unplannable() {
    let w = Ws::new("symlink");
    w.write("t.txt", "t");
    let p = recorded(&w, "ln -s t.txt l && echo x > l");
    assert!(
        has_reason(&p, "wrote through the symlink l"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn a_file_over_eight_mebibytes_is_too_large_to_record() {
    let w = Ws::new("big");
    let big = fs::File::create(w.root.join("big")).unwrap();
    big.set_len(9 << 20).unwrap();
    drop(big);
    let p = recorded(&w, "cat big >/dev/null && echo x >> big");
    assert!(has_reason(&p, "too large"), "{:?}", reasons(&p));
}

#[test]
fn the_run_budget_for_prior_content_is_enforced() {
    let w = Ws::new("budget");
    let mut script = String::from("for i in $(seq 40); do echo x >> f$i; done");
    for i in 1..=40 {
        let f = fs::File::create(w.root.join(format!("f{i}"))).unwrap();
        f.set_len(7 << 20).unwrap();
    }
    script.push_str(" ; true");
    let p = recorded(&w, &script);
    assert!(has_reason(&p, "too large"), "{:?}", reasons(&p));
}

#[test]
fn writes_under_an_ignored_directory_cost_nothing() {
    let w = Ws::new("ignored");
    w.write(".stoopignore", "target\n");
    let p = recorded(
        &w,
        "mkdir -p target/a && echo x > target/a/f && mv target/a target/b",
    );
    assert!(pairs(&p, "priors")
        .iter()
        .all(|(k, _)| !k.starts_with("target")));
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
}

#[test]
fn a_read_through_an_outside_alias_is_recorded_under_the_in_repo_key() {
    let w = Ws::new("alias");
    let alias = std::env::temp_dir().join(format!("stoop-record-alias-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(w.root.join("in.txt"), &alias).unwrap();
    let p = recorded(&w, &format!("cat {}", alias.display()));
    let _ = fs::remove_file(&alias);
    assert!(
        pairs(&p, "inputs").contains(&("in.txt".into(), format!("f:{}", hash(b"one")))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn chmod_plus_x_is_an_output_with_an_executable_id() {
    let w = Ws::new("chmod");
    w.write("s.sh", "echo hi\n");
    let p = recorded(&w, "chmod +x s.sh");
    assert!(
        pairs(&p, "outputs").contains(&("s.sh".into(), format!("x:{}", hash(b"echo hi\n")))),
        "{:?}",
        pairs(&p, "outputs")
    );
    // A mode change keeps the bytes, so the prior records them, not just the mode.
    assert_eq!(prior(&p, "s.sh"), Some(format!("f:{}", hash(b"echo hi\n"))));
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
}

#[test]
fn a_read_only_step_has_empty_priors_and_no_reason() {
    let w = Ws::new("readonly");
    let p = recorded(&w, "cat in.txt > /dev/null");
    assert_eq!(p["priors"].as_array().map(Vec::len), Some(0));
    assert!(reasons(&p).is_empty());
    assert!(removed(&p).is_empty());
}

#[test]
fn a_failed_create_records_the_missing_parent() {
    let w = Ws::new("failed");
    let p = recorded(&w, "echo x > nodir/file || true");
    assert_eq!(prior(&p, "nodir"), Some("a".into()));
    assert_eq!(prior(&p, "nodir/file"), Some("a".into()));
}

#[test]
fn a_failed_create_under_a_file_records_the_file() {
    let w = Ws::new("notdir");
    let p = recorded(&w, "echo x > in.txt/x || true");
    assert_eq!(prior(&p, "in.txt"), Some(format!("f:{}", hash(b"one"))));
    assert_eq!(prior(&p, "in.txt/x"), Some("a".into()));
}

#[test]
fn non_utf8_repository_access_never_records_a_proof() {
    use std::os::unix::ffi::OsStringExt;
    let w = Ws::new("nonutf8");
    let invalid = w
        .root
        .join(std::ffi::OsString::from_vec(b"bad\xffname".to_vec()));
    fs::write(&invalid, b"one").unwrap();
    for script in [
        "cat \"$(printf 'bad\\377name')\" >/dev/null",
        "printf x > \"$(printf 'bad\\377name')\"",
        "ls \"$(printf 'bad\\377name')\" >/dev/null",
    ] {
        let (code, err) = w.sh(script);
        assert_eq!(code, 0, "{err}");
        assert!(
            err.contains("not recorded") && err.contains("not valid UTF-8"),
            "{err}"
        );
        assert!(!w.store().join("proofs/t.json").exists(), "{err}");
    }
}

#[test]
fn an_append_keeps_the_old_bytes_so_the_prior_records_them() {
    let w = Ws::new("append");
    w.write("config.txt", "foo\n");
    let p = recorded(&w, "echo y >> config.txt");
    assert_eq!(
        prior(&p, "config.txt"),
        Some(format!("f:{}", hash(b"foo\n")))
    );
}

#[test]
fn a_truncating_write_records_the_old_content() {
    let w = Ws::new("truncate");
    w.write("config.txt", "foo\n");
    let p = recorded(&w, "echo y > config.txt");
    assert_eq!(
        prior(&p, "config.txt"),
        Some(format!("f:{}", hash(b"foo\n")))
    );
}

#[test]
fn a_truncated_executable_records_its_content_and_mode() {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new("truncexec");
    w.write("run.sh", "echo hi\n");
    fs::set_permissions(w.root.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
    let p = recorded(&w, "echo y > run.sh");
    assert_eq!(
        prior(&p, "run.sh"),
        Some(format!("x:{}", hash(b"echo hi\n")))
    );
}

#[test]
fn a_write_through_a_symlinked_directory_is_recorded_under_the_real_key() {
    let w = Ws::new("symdir");
    w.write("sub/keep", "k");
    let p = recorded(&w, "ln -s sub d && echo x > d/f");
    assert!(
        has_reason(&p, "wrote through the symlink d"),
        "{:?}",
        reasons(&p)
    );
    assert!(
        pairs(&p, "outputs").iter().any(|(k, _)| k == "sub/f"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn a_read_through_an_outside_directory_alias_is_recorded_under_the_in_repo_key() {
    let w = Ws::new("diralias");
    w.write("sub/f", "inside");
    let alias = std::env::temp_dir().join(format!("stoop-record-dir-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(w.root.join("sub"), &alias).unwrap();
    let p = recorded(&w, &format!("cat {}/f", alias.display()));
    let _ = fs::remove_file(&alias);
    assert!(
        pairs(&p, "inputs").contains(&("sub/f".into(), format!("f:{}", hash(b"inside")))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn a_read_through_an_alias_of_a_written_path_is_unplannable() {
    let w = Ws::new("aliaswritten");
    let alias = std::env::temp_dir().join(format!("stoop-record-written-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(w.root.join("in.txt"), &alias).unwrap();
    let p = recorded(&w, &format!("echo y > in.txt && cat {}", alias.display()));
    let _ = fs::remove_file(&alias);
    assert!(has_reason(&p, "and also wrote it"), "{:?}", reasons(&p));
}

#[test]
fn a_cached_parent_is_not_reused_after_a_symlink_replaces_it() {
    let w = Ws::new("cache");
    w.write("sub/keep", "k");
    let p = recorded(
        &w,
        "mkdir d && echo a > d/f && rm -r d && ln -s sub d && echo b > d/g",
    );
    assert!(
        has_reason(&p, "wrote through the symlink d"),
        "{:?}",
        reasons(&p)
    );
    assert!(
        pairs(&p, "outputs").iter().any(|(k, _)| k == "sub/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn a_write_through_a_link_wholly_outside_the_repository_records_nothing() {
    let w = Ws::new("outsidelink");
    let pid = std::process::id();
    let target = std::env::temp_dir().join(format!("stoop-record-out-target-{pid}"));
    let alias = std::env::temp_dir().join(format!("stoop-record-out-{pid}"));
    fs::write(&target, "t").unwrap();
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(&target, &alias).unwrap();
    let p = recorded(
        &w,
        &format!("echo x > {} && echo y > /dev/stdout", alias.display()),
    );
    let _ = fs::remove_file(&alias);
    let _ = fs::remove_file(&target);
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
    assert!(
        pairs(&p, "outputs").is_empty(),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn a_write_through_a_dangling_link_in_the_repository_is_unplannable() {
    let w = Ws::new("dangling");
    let p = recorded(&w, "ln -s nowhere d && echo x > d");
    assert!(
        has_reason(&p, "wrote through the symlink d"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn reading_a_link_after_writing_through_it_keeps_the_link_as_an_input() {
    let w = Ws::new("linkread");
    w.write("t.txt", "t");
    std::os::unix::fs::symlink(w.root.join("t.txt"), w.root.join("l")).unwrap();
    let p = recorded(&w, "echo x > l && cat l > /dev/null");
    assert!(
        pairs(&p, "inputs")
            .contains(&("l".into(), format!("l:{}", w.root.join("t.txt").display()))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn writing_through_symlink_then_dotdot_is_unplannable() {
    let w = Ws::new("linkdotdot");
    w.write("sub/inner/keep", "k");
    std::os::unix::fs::symlink("sub/inner", w.root.join("link")).unwrap();
    let p = recorded(&w, "echo ok > link/../out");
    assert!(
        has_reason(&p, "wrote through the symlink link"),
        "{:?}",
        reasons(&p)
    );
    assert!(pairs(&p, "outputs").iter().any(|(key, _)| key == "sub/out"));
}

#[test]
fn outside_alias_through_in_repo_symlink_is_unplannable() {
    let w = Ws::new("aliassymlink");
    w.write("sub/keep", "k");
    std::os::unix::fs::symlink("sub", w.root.join("link")).unwrap();
    let alias = std::env::temp_dir().join(format!("stoop-record-aliasdir-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(w.root.join("link"), &alias).unwrap();
    let p = recorded(&w, &format!("echo ok > {}/out", alias.display()));
    let _ = fs::remove_file(alias);
    assert!(
        has_reason(&p, "wrote through the symlink link"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn reading_through_symlink_then_dotdot_records_physical_path() {
    let w = Ws::new("readdotdot");
    w.write("sub/inner/keep", "k");
    w.write("sub/f", "content");
    std::os::unix::fs::symlink("sub/inner", w.root.join("link")).unwrap();
    let p = recorded(&w, "cat link/../f >/dev/null");
    assert!(pairs(&p, "inputs").contains(&("sub/f".into(), format!("f:{}", hash(b"content")))));
    assert!(
        pairs(&p, "inputs").contains(&("link".into(), "l:sub/inner".into())),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn proc_alias_read_then_truncate_records_old_content() {
    let w = Ws::new("procread");
    w.write("config.txt", "old content");
    let p = recorded(
        &w,
        "cat /proc/self/cwd/config.txt >/dev/null; echo new > config.txt",
    );
    assert_eq!(
        prior(&p, "config.txt"),
        Some(format!("f:{}", hash(b"old content")))
    );
}

#[test]
fn outside_alias_read_then_truncate_records_old_content() {
    let w = Ws::new("outside-before-write");
    w.write("config.txt", "old content");
    let alias = std::env::temp_dir().join(format!("stoop-old-config-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(w.root.join("config.txt"), &alias).unwrap();
    let p = recorded(
        &w,
        &format!("cat {} >/dev/null; echo new > config.txt", alias.display()),
    );
    let _ = fs::remove_file(alias);
    assert_eq!(
        prior(&p, "config.txt"),
        Some(format!("f:{}", hash(b"old content")))
    );
}

#[test]
fn inherited_stdin_read_then_truncate_records_old_content() {
    let w = Ws::new("inherited-stdin");
    w.write("config.txt", "old content");
    let input = fs::File::open(w.root.join("config.txt")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .args([
            "run",
            "--root",
            ".",
            "--key",
            "t",
            "--",
            "sh",
            "-c",
            "cat >/dev/null; echo new > config.txt",
        ])
        .current_dir(&w.root)
        .env("STOOP_STORE", w.store())
        .env_remove("STOOP_FULL")
        .env_remove("STOOP_OFF")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("STOOP_SYNC")
        .stdin(input)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        prior(&w.proof(), "config.txt"),
        Some(format!("f:{}", hash(b"old content")))
    );
}

#[test]
fn bind_mount_alias_of_unwritten_repo_file_is_a_documented_residual() {
    let w = Ws::new("bind-residual");
    w.write("config.txt", "old");
    let alias = std::env::temp_dir().join(format!("stoop-bind-{}", std::process::id()));
    fs::create_dir_all(&alias).unwrap();
    let mounted = Command::new("mount")
        .args(["--bind", w.root.to_str().unwrap(), alias.to_str().unwrap()])
        .output();
    if !mounted.is_ok_and(|o| o.status.success()) {
        let _ = fs::remove_dir(&alias);
        return;
    }
    let script = format!("cat {}/config.txt >/dev/null", alias.display());
    let first = w.sh(&script);
    w.write("config.txt", "new");
    let second = w.sh(&script);
    let unmounted = Command::new("umount").arg(&alias).status().unwrap();
    let _ = fs::remove_dir(&alias);
    assert!(unmounted.success());
    assert_eq!(first.0, 0, "{}", first.1);
    assert!(
        second.1.contains("stoop: skip"),
        "documented bind alias blind spot changed: {}",
        second.1
    );
}

#[test]
fn proof_stores_effective_ignore_patterns() {
    let w = Ws::new("ignore-patterns");
    w.write(".stoopignore", "# ignored comment\nbuild/\n*.log\n");
    let p = recorded(&w, "cat in.txt >/dev/null");
    let patterns: Vec<&str> = p["ignore"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert!(patterns.contains(&"build"));
    assert!(patterns.contains(&"*.log"));
    assert!(patterns.contains(&"/tmp"));
    assert!(!patterns.contains(&"# ignored comment"));
}

#[test]
fn anonymous_tmpfile_without_link_records_without_writing_directory() {
    let w = Ws::new("tmpfile-unlinked");
    w.syscall_probe();
    fs::create_dir(w.root.join("tmpdir")).unwrap();
    let p = recorded(&w, "./syscall-probe tmp tmpdir");
    assert!(pairs(&p, "priors").is_empty(), "{:?}", pairs(&p, "priors"));
    assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
}

#[test]
fn anonymous_tmpfile_linked_through_proc_fd_refuses_recording() {
    let w = Ws::new("tmpfile-linked");
    w.syscall_probe();
    let (code, err) = w.sh("./syscall-probe tmp . output");
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("descriptor alias"),
        "{err}"
    );
    assert!(!w.store().join("proofs/t.json").exists());
}

#[test]
fn rename_exchange_captures_both_original_files() {
    let w = Ws::new("rename-exchange");
    w.syscall_probe();
    w.write("a", "aaa");
    w.write("b", "bbb");
    let p = recorded(&w, "./syscall-probe exchange a b");
    assert_eq!(prior(&p, "a"), Some(format!("f:{}", hash(b"aaa"))));
    assert_eq!(prior(&p, "b"), Some(format!("f:{}", hash(b"bbb"))));
    assert!(pairs(&p, "outputs").contains(&("a".into(), format!("f:{}", hash(b"bbb")))));
    assert!(pairs(&p, "outputs").contains(&("b".into(), format!("f:{}", hash(b"aaa")))));
}

#[test]
fn rename_source_prior_contains_its_original_bytes() {
    let w = Ws::new("rename-source");
    w.syscall_probe();
    w.write("a", "old");
    let p = recorded(&w, "./syscall-probe rename a b");
    assert_eq!(prior(&p, "a"), Some(format!("f:{}", hash(b"old"))));
    assert_eq!(prior(&p, "b"), Some("a".into()));
}

#[test]
fn creat_and_nonzero_truncate_record_original_bytes() {
    for operation in ["creat", "truncate"] {
        let w = Ws::new(operation);
        w.syscall_probe();
        w.write("f", "original");
        let p = recorded(&w, &format!("./syscall-probe {operation} f"));
        assert_eq!(prior(&p, "f"), Some(format!("f:{}", hash(b"original"))));
    }
}

#[test]
fn fchmodat2_and_fchmod_record_mode_changes_and_original_bytes() {
    for operation in ["fchmodat2", "fchmod"] {
        let w = Ws::new(operation);
        w.syscall_probe();
        w.write("f", "original");
        let p = recorded(&w, &format!("./syscall-probe {operation} f"));
        assert_eq!(prior(&p, "f"), Some(format!("f:{}", hash(b"original"))));
        assert!(pairs(&p, "outputs").contains(&("f".into(), format!("x:{}", hash(b"original")))));
    }
}

#[test]
fn accesses_through_deleted_directory_fd_refuse_recording() {
    let w = Ws::new("deleted-fd");
    w.syscall_probe();
    fs::create_dir(w.root.join("d")).unwrap();
    let (code, err) = w.sh("./syscall-probe deleted-dirfd d");
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("deleted directory"),
        "{err}"
    );
    assert!(!w.store().join("proofs/t.json").exists());
}

#[test]
fn exchanging_a_file_with_a_directory_is_unplannable() {
    let w = Ws::new("exchange-directory");
    w.syscall_probe();
    w.write("a", "file");
    w.write("d/child", "entry");
    let p = recorded(&w, "./syscall-probe exchange a d");
    assert!(has_reason(&p, "renamed the directory"), "{:?}", reasons(&p));
}

/// Explicitly regenerate the committed real-recorder planner fixtures on Linux.
#[test]
#[ignore]
fn regenerate_planner_recorder_fixtures() {
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::env::var("STOOP_REGENERATE_RECORDER_FIXTURES").as_deref(),
        Ok("1")
    );
    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/recorder");
    fs::create_dir_all(&out).unwrap();
    for case in [
        "sed", "mkdir", "rename", "eol", "chmod", "parent", "failed", "symlink", "proc",
    ] {
        let w = Ws::new(&format!("fixture-{case}"));
        let script = match case {
            "sed" => {
                w.write("config.txt", "foo\n");
                "sed -i s/foo/bar/ config.txt"
            }
            "mkdir" => {
                w.write("src/keep", "keep");
                "mkdir -p src"
            }
            "rename" => {
                w.write("d/file", "keep");
                "mv d moved"
            }
            "eol" => "cat in.txt >/dev/null",
            "chmod" => {
                w.write("s.sh", "echo hi\n");
                fs::set_permissions(w.root.join("s.sh"), fs::Permissions::from_mode(0o755))
                    .unwrap();
                "chmod -x s.sh"
            }
            "parent" => {
                w.write("build/.keep", "keep");
                "echo data > build/out"
            }
            "failed" => "echo x > missing/file || true",
            "symlink" => {
                w.write("sub/inner/keep", "keep");
                std::os::unix::fs::symlink("sub/inner", w.root.join("link")).unwrap();
                "echo x > link/../out"
            }
            "proc" => {
                w.write("config.txt", "old content");
                "cat /proc/self/cwd/config.txt >/dev/null; echo new > config.txt"
            }
            _ => unreachable!(),
        };
        let _ = recorded(&w, script);
        let fixture = out.join(case);
        fs::create_dir_all(&fixture).unwrap();
        fs::copy(w.store().join("proofs/t.json"), fixture.join("proof.json")).unwrap();
    }
}

#[test]
fn invalidating_an_outside_alias_parent_prevents_stale_physical_keys() {
    let w = Ws::new("outside-cache");
    w.write("other/keep", "k");
    let alias = std::env::temp_dir().join(format!("stoop-cache-alias-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(&w.root, &alias).unwrap();
    let path = alias.display();
    let script = format!("mkdir {path}/d; echo a > {path}/d/f; rm -r {path}/d; ln -s other {path}/d; echo b > {path}/d/g");
    let p = recorded(&w, &script);
    let _ = fs::remove_file(alias);
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "other/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn unlinkat_removedir_of_nonempty_directory_is_unplannable() {
    let w = Ws::new("unlinkat-rmdir");
    w.syscall_probe();
    w.write("d/keep", "k");
    let p = recorded(&w, "./syscall-probe unlinkat-rmdir d");
    assert!(
        has_reason(&p, "removed the non-empty directory d"),
        "{:?}",
        reasons(&p)
    );
}

#[test]
fn reading_written_file_through_outside_directory_alias_is_unplannable() {
    let w = Ws::new("dir-alias-written");
    let alias = std::env::temp_dir().join(format!("stoop-written-dir-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(&w.root, &alias).unwrap();
    let p = recorded(
        &w,
        &format!(
            "cat {}/in.txt >/dev/null; echo new > in.txt",
            alias.display()
        ),
    );
    let _ = fs::remove_file(alias);
    assert!(has_reason(&p, "and also wrote it"), "{:?}", reasons(&p));
}

#[test]
fn replacing_an_ignored_directory_invalidates_cached_parents() {
    let w = Ws::new("ignored-cache-replace");
    w.write(".stoopignore", "build/\n");
    w.write("src/out", "original");
    fs::create_dir_all(w.root.join("build/x")).unwrap();
    let p = recorded(
        &w,
        "echo a > build/x/f; rm -r build/x; ln -s ../src build/x; echo y > build/x/out",
    );
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "src/out"),
        "{:?}",
        pairs(&p, "outputs")
    );
    assert!(has_reason(&p, "symlink build/x"), "{:?}", reasons(&p));
}

#[test]
fn replacing_an_outside_alias_invalidates_cached_parents() {
    let w = Ws::new("outside-alias-replace");
    w.write("sub/keep", "k");
    let alias = std::env::temp_dir().join(format!("stoop-retarget-alias-{}", std::process::id()));
    let _ = fs::remove_file(&alias);
    std::os::unix::fs::symlink(&w.root, &alias).unwrap();
    let script = format!(
        "echo a > {0}/f; rm {0}; ln -s {1}/sub {0}; echo b > {0}/g",
        alias.display(),
        w.root.display()
    );
    let p = recorded(&w, &script);
    let _ = fs::remove_file(alias);
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "sub/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn reopening_pipe_descriptors_is_recordable() {
    for (name, directory) in [("dev", "/dev/fd"), ("thread", "/proc/thread-self/fd")] {
        let w = Ws::new(&format!("pipe-{name}"));
        w.syscall_probe();
        let p = recorded(&w, &format!("./syscall-probe pipe-fd {directory}"));
        assert!(reasons(&p).is_empty(), "{:?}", reasons(&p));
    }
}

#[test]
fn fchdir_then_relative_open_is_an_input() {
    let w = Ws::new("fchdir");
    w.syscall_probe();
    w.write("sub/f", "old");
    let p = recorded(&w, "./syscall-probe fchdir sub");
    assert!(
        pairs(&p, "inputs").contains(&("sub/f".into(), format!("f:{}", hash(b"old")))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn read_only_proc_self_cwd_is_an_input() {
    let w = Ws::new("read-only-proc");
    let p = recorded(&w, "cat /proc/self/cwd/in.txt >/dev/null");
    assert!(
        pairs(&p, "inputs").contains(&("in.txt".into(), format!("f:{}", hash(b"one")))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn unresolved_numeric_process_alias_refuses_recording() {
    let w = Ws::new("missing-proc-alias");
    let (status, err) = w.sh("cat /proc/99999999/cwd/in.txt >/dev/null 2>&1 || true");
    assert_eq!(status, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("process path alias"),
        "{err}"
    );
}
