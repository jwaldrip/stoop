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
        self.sh_in(script, &self.root)
    }

    fn sh_in(&self, script: &str, cwd: &std::path::Path) -> (i32, String) {
        self.sh_with_affinity(script, cwd, false)
    }

    fn sh_with_affinity(&self, script: &str, cwd: &std::path::Path, pin: bool) -> (i32, String) {
        let mut cmd = if pin {
            let cpu = unsafe { libc::sched_getcpu() };
            assert!(cpu >= 0);
            let mut cmd = Command::new("taskset");
            cmd.args(["-c", &cpu.to_string(), env!("CARGO_BIN_EXE_stoop")]);
            cmd
        } else {
            Command::new(env!("CARGO_BIN_EXE_stoop"))
        };
        let out = cmd
            .args([
                "run",
                "--root",
                self.root.to_str().unwrap(),
                "--key",
                "t",
                "--",
                "sh",
                "-c",
                script,
            ])
            .current_dir(cwd)
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
        "sed", "mkdir", "rename", "eol", "chmod", "parent", "failed", "symlink", "proc", "app",
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
            "app" => {
                w.write("app/build.sh", "#!/bin/sh\ncat input.txt >/dev/null\n");
                w.write("app/input.txt", "app input");
                fs::set_permissions(
                    w.root.join("app/build.sh"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                "./build.sh"
            }
            _ => unreachable!(),
        };
        if case == "app" {
            let (status, err) = w.sh_in(script, &w.root.join("app"));
            assert_eq!(status, 0, "{err}");
            assert!(err.contains("stoop: recorded"), "{err}");
        } else {
            let _ = recorded(&w, script);
        }
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

#[test]
fn retargeting_an_alias_via_a_different_spelling_clears_parent_cache() {
    let w = Ws::new("nested-outside-alias");
    w.write("sub/keep", "keep");
    let outside = std::env::temp_dir().join(format!("stoop-nested-alias-{}", std::process::id()));
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir(&outside).unwrap();
    let x = outside.join("x");
    let y = outside.join("y");
    fs::create_dir(&y).unwrap();
    std::os::unix::fs::symlink(&y, &x).unwrap();
    std::os::unix::fs::symlink(&w.root, y.join("alias")).unwrap();
    let script = format!(
        "echo a > {}/alias/f; rm {}/alias; ln -s {}/sub {}/alias; echo b > {}/alias/g",
        x.display(),
        y.display(),
        w.root.display(),
        y.display(),
        x.display()
    );
    let p = recorded(&w, &script);
    let _ = fs::remove_dir_all(outside);
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "sub/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn retargeting_a_release_link_via_another_alias_records_the_new_target() {
    let w = Ws::new("nested-release-alias");
    w.write("build/build-1/keep", "one");
    w.write("build/build-2/keep", "two");
    std::os::unix::fs::symlink("build/current", w.root.join("out")).unwrap();
    std::os::unix::fs::symlink("build-1", w.root.join("build/current")).unwrap();
    let p = recorded(
        &w,
        "echo a > out/f; ln -sfn build-2 build/current; echo b > out/g",
    );
    assert!(
        pairs(&p, "outputs")
            .iter()
            .any(|(key, _)| key == "build/build-2/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn chained_magic_symlinks_do_not_resolve_again_in_the_recorder() {
    let w = Ws::new("chained-proc-link");
    w.write("config.txt", "root copy");
    w.write("sub/config.txt", "tracee copy");
    std::os::unix::fs::symlink("link-b", w.root.join("link-a")).unwrap();
    std::os::unix::fs::symlink("/proc/self/cwd/config.txt", w.root.join("link-b")).unwrap();
    let p = recorded(&w, "cd sub && cat ../link-a >/dev/null");
    let inputs = pairs(&p, "inputs");
    assert!(
        inputs.contains(&(
            "sub/config.txt".into(),
            format!("f:{}", hash(b"tracee copy"))
        )),
        "{inputs:?}"
    );
    assert!(
        !inputs
            .iter()
            .any(|(path, _)| path == "config.txt" || path.is_empty()),
        "{inputs:?}"
    );
}

#[test]
fn reads_before_final_symlink_changes_keep_call_time_target() {
    use std::os::unix::fs::PermissionsExt;
    for (name, command, link, target, content) in [
        (
            "grep-retarget",
            "grep -q 1 l && ln -sfn t2.txt l",
            "l",
            "t1.txt",
            "1\n",
        ),
        (
            "cat-retarget",
            "cat l > out.txt && ln -sfn t2.txt l",
            "l",
            "t1.txt",
            "1\n",
        ),
        (
            "cat-remove",
            "cat l > out.txt && rm l",
            "l",
            "t1.txt",
            "1\n",
        ),
        (
            "cat-rename",
            "cat l > out.txt && mv l l2",
            "l",
            "t1.txt",
            "1\n",
        ),
        (
            "exec-retarget",
            "./run > out.txt && ln -sfn run2.sh run",
            "run",
            "run1.sh",
            "#!/bin/sh\necho one\n",
        ),
    ] {
        let w = Ws::new(name);
        w.write("t1.txt", "1\n");
        w.write("t2.txt", "2\n");
        w.write("run1.sh", "#!/bin/sh\necho one\n");
        w.write("run2.sh", "#!/bin/sh\necho two\n");
        for script in ["run1.sh", "run2.sh"] {
            fs::set_permissions(w.root.join(script), fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::os::unix::fs::symlink(target, w.root.join(link)).unwrap();
        let p = recorded(&w, command);
        let prefix = if name == "exec-retarget" { "x" } else { "f" };
        let expected = (
            target.to_string(),
            format!("{prefix}:{}", hash(content.as_bytes())),
        );
        assert!(
            pairs(&p, "inputs").contains(&expected),
            "{name}: {:?}",
            pairs(&p, "inputs")
        );
    }
}

#[test]
fn every_read_through_a_retargeted_directory_keeps_its_call_time_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut missing = Vec::new();
    for spelling in ["plain", "dotdot", "outside", "exec"] {
        for position in ["first", "second"] {
            let w = Ws::new(&format!("directory-target-{spelling}-{position}"));
            for dir in ["d1", "d2"] {
                w.write(&format!("{dir}/a.txt"), &format!("a {dir}\n"));
                w.write(&format!("{dir}/f.txt"), &format!("f {dir}\n"));
                w.write(
                    &format!("{dir}/run.sh"),
                    &format!("#!/bin/sh\necho {dir}\n"),
                );
                fs::set_permissions(
                    w.root.join(dir).join("run.sh"),
                    fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            symlink("d1", w.root.join("dl")).unwrap();
            let outside = w.root.with_extension("outside");
            let _ = fs::remove_dir_all(&outside);
            fs::create_dir(&outside).unwrap();
            symlink(w.root.join("d1"), outside.join("dl")).unwrap();
            let prefix = match spelling {
                "dotdot" => "dl/../dl".to_owned(),
                "outside" => outside.join("dl").display().to_string(),
                _ => "dl".to_owned(),
            };
            let target = if spelling == "exec" {
                "run.sh"
            } else {
                "f.txt"
            };
            let read = if spelling == "exec" {
                format!("{prefix}/{target} >/dev/null")
            } else {
                format!("cat {prefix}/{target} >/dev/null")
            };
            let ordered = if spelling == "exec" {
                if position == "first" {
                    format!("{read}; test -e {prefix}/a.txt")
                } else {
                    format!("test -e {prefix}/a.txt; {read}")
                }
            } else if position == "first" {
                format!("cat {prefix}/{target} {prefix}/a.txt >/dev/null")
            } else {
                format!("cat {prefix}/a.txt {prefix}/{target} >/dev/null")
            };
            let retarget = if spelling == "outside" {
                format!("ln -sfn \"$PWD/d2\" {prefix}")
            } else {
                "ln -sfn d2 dl".to_owned()
            };
            let p = recorded(&w, &format!("{ordered}; {retarget}"));
            let key = format!("d1/{target}");
            if !pairs(&p, "inputs").iter().any(|(path, _)| path == &key) {
                missing.push(format!("{spelling} {position}: {:?}", pairs(&p, "inputs")));
            }
            let _ = fs::remove_dir_all(outside);
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

fn assert_unkeyable_proc_fd_is_not_recorded(method: &str) {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new(&format!("procfd-{method}"));
    w.write("interp", "#!/bin/sh\nexit 0\n");
    w.write("prog.sh", "#!./interp\n");
    for f in ["interp", "prog.sh"] {
        fs::set_permissions(w.root.join(f), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let setup = if method == "memfd" {
        "f=os.memfd_create(\"x\", 0); os.write(f, open(\"prog.sh\", \"rb\").read())"
    } else {
        "f=os.open(\"prog.sh\", os.O_RDONLY); os.unlink(\"prog.sh\")"
    };
    let (status, err) = w.sh(&format!(
        "python3 -c 'import os; {setup}; os.execv(\"/proc/self/fd/%d\" % f, [\"x\"])'"
    ));
    assert_eq!(status, 0, "{method}: {err}");
    assert!(
        err.contains("not recorded") && err.contains("unkeyable file descriptor"),
        "{method}: {err}"
    );
}

#[test]
fn execve_memfd_script_through_proc_fd_is_not_recorded() {
    assert_unkeyable_proc_fd_is_not_recorded("memfd");
}

#[test]
fn execve_deleted_script_through_proc_fd_is_not_recorded() {
    assert_unkeyable_proc_fd_is_not_recorded("deleted");
}

#[test]
fn removing_alias_target_invalidates_other_spelling() {
    let w = Ws::new("topology-remove");
    w.write("sub1/keep", "one");
    std::os::unix::fs::symlink("sub1", w.root.join("cur")).unwrap();
    std::os::unix::fs::symlink("cur", w.root.join("out")).unwrap();
    let p = recorded(&w, "echo a > out/f; rm -rf cur; mkdir cur; echo b > out/g");
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "cur/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn replacing_alias_by_rename_invalidates_other_spelling() {
    let w = Ws::new("topology-rename");
    w.write("sub1/keep", "one");
    w.write("sub2/keep", "two");
    std::os::unix::fs::symlink("sub1", w.root.join("cur")).unwrap();
    std::os::unix::fs::symlink("sub2", w.root.join("next")).unwrap();
    std::os::unix::fs::symlink("cur", w.root.join("out")).unwrap();
    let p = recorded(
        &w,
        "echo a > out/f; python3 -c 'import os; os.replace(\"next\", \"cur\")'; echo b > out/g",
    );
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "sub2/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn exchanging_aliases_by_rename_invalidates_other_spelling() {
    let w = Ws::new("topology-exchange");
    w.syscall_probe();
    w.write("s1/keep", "one");
    w.write("s2/keep", "two");
    std::os::unix::fs::symlink("s1", w.root.join("a")).unwrap();
    std::os::unix::fs::symlink("s2", w.root.join("b")).unwrap();
    std::os::unix::fs::symlink("a", w.root.join("out")).unwrap();
    let p = recorded(
        &w,
        "echo a > out/f; ./syscall-probe exchange a b; echo b > out/g",
    );
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "s2/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn replacing_symlink_destination_by_rename_invalidates_other_spelling() {
    let w = Ws::new("topology-rename-destination");
    w.write("sub1/keep", "one");
    w.write("p", "plain file");
    std::os::unix::fs::symlink("sub1", w.root.join("cur")).unwrap();
    std::os::unix::fs::symlink("cur", w.root.join("out")).unwrap();
    let p = recorded(&w, "echo a > out/f; python3 -c 'import os; os.replace(\"p\", \"cur\")'; rm cur; mkdir cur; echo b > out/g");
    assert!(
        pairs(&p, "outputs").iter().any(|(key, _)| key == "cur/g"),
        "{:?}",
        pairs(&p, "outputs")
    );
}

#[test]
fn creating_proc_cwd_alias_invalidates_cached_negative_walk() {
    let w = Ws::new("topology-create");
    w.write("sub/config.txt", "contents");
    let p = recorded(
        &w,
        "cd sub; (cat d/x 2>/dev/null; true); ln -s /proc/self/cwd d; cat d/config.txt",
    );
    assert!(
        pairs(&p, "inputs")
            .contains(&("sub/config.txt".into(), format!("f:{}", hash(b"contents")))),
        "{:?}",
        pairs(&p, "inputs")
    );
}

#[test]
fn app_working_directory_records_script_key_without_dot_components() {
    use std::os::unix::fs::PermissionsExt;
    let w = Ws::new("app-script-key");
    w.write("app/build.sh", "#!/bin/sh\nexit 0\n");
    fs::set_permissions(
        w.root.join("app/build.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let (status, err) = w.sh_in("./build.sh", &w.root.join("app"));
    assert_eq!(status, 0, "{err}");
    let p = w.proof();
    let inputs = pairs(&p, "inputs");
    assert!(
        inputs.iter().any(|(path, _)| path == "app/build.sh"),
        "{inputs:?}"
    );
    assert!(
        !inputs
            .iter()
            .any(|(path, _)| path.contains("/./") || path.is_empty()),
        "{inputs:?}"
    );
}

#[test]
fn namespace_change_attempt_is_not_recorded() {
    let w = Ws::new("namespace-attempt");
    w.syscall_probe();
    let (status, err) = w.sh("./syscall-probe unshare ignored");
    assert_eq!(status, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("namespaces"),
        "{err}"
    );
    assert!(!w.store().join("proofs/t.json").exists());
}

#[test]
fn mount_api_and_namespace_clone_attempts_are_not_recorded() {
    for op in [
        "mount",
        "umount2",
        "chroot",
        "pivot_root",
        "setns",
        "open_tree",
        "move_mount",
        "fsopen",
        "fsconfig",
        "fsmount",
        "fspick",
        "mount_setattr",
        "clone",
        "clone3",
    ] {
        let w = Ws::new(&format!("namespace-{op}"));
        w.syscall_probe();
        let (status, err) = w.sh(&format!("./syscall-probe namespace-call {op}"));
        assert_eq!(status, 0, "{op}: {err}");
        assert!(err.contains("not recorded"), "{op}: {err}");
        assert!(!w.store().join("proofs/t.json").exists(), "{op}: {err}");
    }
}

#[test]
fn pinned_concurrent_retarget_has_no_stale_output_after_changer_sleeps_or_exits() {
    use std::os::unix::fs::symlink;
    for variant in ["sleep", "exit"] {
        for trial in 0..40 {
            let w = Ws::new(&format!("pending-{variant}-{trial}"));
            w.write("sub/keep", "keep");
            let outside = w.root.with_extension("pending");
            let _ = fs::remove_dir_all(&outside);
            fs::create_dir(&outside).unwrap();
            let x = outside.join("x");
            let y = outside.join("y");
            fs::create_dir(&y).unwrap();
            symlink(&y, &x).unwrap();
            symlink(&w.root, y.join("alias")).unwrap();
            let delay = if variant == "sleep" {
                "time.sleep(0.4)"
            } else {
                ""
            };
            let change = format!(
                "import os,time; time.sleep(0.03); os.symlink({:?}, {:?}); os.replace({:?}, {:?}); {delay}",
                w.root.join("sub"), y.join("next"), y.join("next"), y.join("alias")
            );
            let script = format!(
                "(i=0; while [ ! -e stop ] && [ $i -lt 50000 ]; do echo x > {}/alias/b; i=$((i+1)); done) & B=$!; python3 -c '{}' & A=$!; while [ \"$(readlink {}/alias)\" != \"$PWD/sub\" ]; do sleep 0.005; done; : > stop; wait $B; echo g > {}/alias/g; wait $A",
                x.display(), change, y.display(), x.display()
            );
            let (status, err) = w.sh_with_affinity(&script, &w.root, true);
            assert_eq!(status, 0, "{variant} trial {trial}: {err}");
            assert!(err.contains("recorded"), "{variant} trial {trial}: {err}");
            let p = w.proof();
            assert!(
                pairs(&p, "outputs").iter().any(|(key, _)| key == "sub/g"),
                "{variant} trial {trial}: {:?}; removed {:?}",
                pairs(&p, "outputs"),
                removed(&p)
            );
            let _ = fs::remove_dir_all(outside);
        }
    }
}

#[test]
fn concurrent_alias_retargets_do_not_leave_stale_cached_parents() {
    for trial in 0..6 {
        let w = Ws::new(&format!("topology-race-{trial}"));
        w.write("sub/keep", "keep");
        w.write("race.py", include_str!("fixtures/topology_race.py"));
        let outside =
            std::env::temp_dir().join(format!("stoop-race-{}-{trial}", std::process::id()));
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir(&outside).unwrap();
        let x = outside.join("x");
        let y = outside.join("y");
        fs::create_dir(&y).unwrap();
        std::os::unix::fs::symlink(&y, &x).unwrap();
        std::os::unix::fs::symlink(&w.root, y.join("alias")).unwrap();
        let script = format!(
            "python3 race.py {} {} {}",
            x.display(),
            y.display(),
            w.root.display()
        );
        let p = recorded(&w, &script);
        let _ = fs::remove_dir_all(outside);
        assert!(
            pairs(&p, "outputs")
                .iter()
                .any(|(key, _)| key == "sub/final"),
            "trial {trial}: {:?}",
            pairs(&p, "outputs")
        );
    }
}

#[test]
fn executing_an_unkeyable_memfd_refuses_recording() {
    let w = Ws::new("fexecve-memfd");
    let script = "python3 -c 'import os; f=os.memfd_create(\"stoop\", 0); os.write(f, open(\"/bin/sh\", \"rb\").read()); os.execve(f, [\"sh\", \"-c\", \"exit 0\"], os.environ)'";
    let (status, err) = w.sh(script);
    assert_eq!(status, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("unkeyable file descriptor"),
        "{err}"
    );
}

#[test]
fn absolute_dot_components_do_not_enter_recorded_keys() {
    let w = Ws::new("absolute-dot-key");
    let p = recorded(&w, "cat \"$PWD/./in.txt\" >/dev/null");
    let inputs = pairs(&p, "inputs");
    assert!(inputs.iter().any(|(key, _)| key == "in.txt"), "{inputs:?}");
    assert!(
        !inputs
            .iter()
            .any(|(key, _)| key.contains("/./") || key.starts_with("./")),
        "{inputs:?}"
    );
}

#[test]
fn repository_root_symlink_does_not_create_empty_input_key() {
    let w = Ws::new("root-symlink-key");
    std::os::unix::fs::symlink(".", w.root.join("selfref")).unwrap();
    let p = recorded(&w, "cat selfref/in.txt >/dev/null");
    let inputs = pairs(&p, "inputs");
    assert!(!inputs.iter().any(|(key, _)| key.is_empty()), "{inputs:?}");
}

#[test]
fn coincident_parent_and_replaced_directory_reads_keep_call_time_targets() {
    for case in ["coincident", "dirswap"] {
        let w = Ws::new(&format!("call-time-{case}"));
        w.write("a.txt", "a root\n");
        w.write("f.txt", "f root\n");
        w.write("d1/keep", "keep\n");
        w.write("dx/keep", "keep\n");
        w.write("sub/d2x/keep", "keep\n");
        w.write("sub/a.txt", "a sub\n");
        w.write("sub/f.txt", "f sub\n");
        std::os::unix::fs::symlink("d1", w.root.join("dl")).unwrap();
        let command = if case == "coincident" {
            "cat dl/../a.txt dl/../f.txt > out.txt && ln -sfn sub/d2x dl"
        } else {
            "cat dx/../f.txt > out.txt && python3 -c 'import os; os.unlink(\"dx/keep\"); os.rmdir(\"dx\"); os.symlink(\"sub/d2x\", \"dx\")'"
        };
        let p = recorded(&w, command);
        assert!(
            pairs(&p, "inputs").contains(&("f.txt".into(), format!("f:{}", hash(b"f root\n")))),
            "{case}: {:?}",
            pairs(&p, "inputs")
        );
    }
}

#[test]
fn direct_nonread_observations_keep_call_time_target() {
    for op in ["chdir", "tmpfile", "mkdir", "chmod"] {
        let w = Ws::new(&format!("observation-{op}"));
        w.write("d1/a.txt", "a\n");
        w.write("d1/sub/keep", "keep\n");
        w.write("d2/sub/keep", "other\n");
        std::os::unix::fs::symlink("d1", w.root.join("dl")).unwrap();
        let action = match op {
            "chdir" => "os.chdir(\"dl/../dl/sub\")",
            "tmpfile" => "os.close(os.open(\"dl/../dl/sub\", os.O_TMPFILE | os.O_WRONLY, 0o600))",
            "mkdir" => "exec(\"try:\\n os.mkdir(\\\"dl/../dl/sub\\\")\\n raise SystemExit(1)\\nexcept FileExistsError:\\n pass\")",
            _ => "os.chmod(\"dl/../dl/sub\", 0o755)",
        };
        let command = format!(
            "python3 -c 'import os; open(\"dl/../dl/a.txt\").read(); {action}' && ln -sfn d2 dl"
        );
        let p = recorded(&w, &command);
        assert!(
            pairs(&p, "inputs").iter().any(|(key, _)| key == "d1/sub"),
            "{op}: {:?}",
            pairs(&p, "inputs")
        );
    }
}

#[test]
fn second_absence_probe_keeps_the_physical_missing_path() {
    use std::os::unix::fs::symlink;
    for case in ["dotdot", "outside"] {
        let w = Ws::new(&format!("absence-{case}"));
        w.write("sub/d1n/keep", "keep\n");
        w.write("d1/keep", "keep\n");
        symlink("sub/d1n", w.root.join("dln")).unwrap();
        let outside = w.root.with_extension("absence");
        let _ = fs::remove_dir_all(&outside);
        fs::create_dir(&outside).unwrap();
        symlink(w.root.join("d1"), outside.join("dl")).unwrap();
        let prefix = if case == "dotdot" {
            "dln/../missing".to_owned()
        } else {
            format!("{}/dl/missing", outside.display())
        };
        let command = format!("python3 -c 'import os; os.path.exists(\"{prefix}/a.txt\"); assert not os.path.exists(\"{prefix}/x.txt\")'; echo ok > out.txt");
        let p = recorded(&w, &command);
        let key = if case == "dotdot" {
            "sub/missing/x.txt"
        } else {
            "d1/missing/x.txt"
        };
        assert!(
            pairs(&p, "inputs").contains(&(key.into(), "a".into())),
            "{case}: {:?}",
            pairs(&p, "inputs")
        );
        let _ = fs::remove_dir_all(outside);
    }
}

#[test]
fn open_by_handle_attempt_is_not_recorded() {
    let w = Ws::new("open-by-handle");
    w.syscall_probe();
    let (status, err) = w.sh("./syscall-probe open-by-handle ignored");
    assert_eq!(status, 0, "{err}");
    assert!(
        err.contains("not recorded") && err.contains("file by handle"),
        "{err}"
    );
}
