//! Read-time identity (slice 3a). A run records only what it read: a file, listing, link or
//! absence that changes after the command first looked at it leaves the run unrecorded.
//!
//! Each test holds the command blocked on a FIFO and changes the tree while it waits, so the
//! change lands mid-run. Files that must be "aged" are older than the 2 s racy window when the
//! command first looks at them.
#![cfg(target_os = "linux")]

use serde_json::Value;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

/// A repository root and the scratch space around it, under the test's temporary directory.
/// Removed when the test ends.
struct Case {
    dir: PathBuf,
}

impl Case {
    fn new(name: &str) -> Case {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join("read-identity")
            .join(format!("{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("root")).unwrap();
        Case { dir }
    }

    fn root(&self) -> PathBuf {
        self.dir.join("root")
    }

    fn file(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    /// A FIFO outside the root. Opening it for writing returns once the command opens it for reading.
    fn fifo(&self, name: &str) -> PathBuf {
        let path = self.dir.join(name);
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(c.as_ptr(), 0o600) },
            0,
            "mkfifo {name}"
        );
        path
    }

    /// A file outside the root, under the same temporary directory.
    fn outside(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.dir.join("outside").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }

    fn proof(&self, key: &str) -> PathBuf {
        self.root()
            .join(".stoop")
            .join("proofs")
            .join(format!("{key}.json"))
    }
}

impl Drop for Case {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Leave the environment the tests control: no inherited stoop or git settings.
fn clean(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy().into_owned();
        if name.starts_with("STOOP_") || name.starts_with("GIT_") || name == "GITHUB_ACTIONS" {
            command.env_remove(&key);
        }
    }
}

fn spawn(case: &Case, key: &str, script: &str, env: &[(&str, &Path)]) -> Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    clean(&mut command);
    command
        .args(["run", "--root"])
        .arg(case.root())
        .args(["--key", key, "--", "sh", "-c", script])
        .current_dir(case.root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        command.env(name, value);
    }
    command.spawn().unwrap()
}

fn run(case: &Case, key: &str, script: &str, env: &[(&str, &Path)]) -> Output {
    spawn(case, key, script, env).wait_with_output().unwrap()
}

/// Wait for the command to open the FIFO for reading, then return the writing end.
/// Dropping the returned file releases the command.
fn meet(fifo: &Path) -> File {
    let (sender, receiver) = mpsc::channel();
    let path = fifo.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(OpenOptions::new().write(true).open(&path));
    });
    receiver
        .recv_timeout(Duration::from_secs(60))
        .expect("the command never reached the FIFO")
        .expect("open the FIFO for writing")
}

/// Release a retry if it reaches the FIFO; a skipped command never opens the FIFO.
fn meet_if_running(fifo: &Path, child: &mut Child) -> Option<File> {
    let started = Instant::now();
    loop {
        match OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(fifo)
        {
            Ok(file) => return Some(file),
            Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {}
            Err(err) => panic!("opening retry FIFO: {err}"),
        }
        if child.try_wait().unwrap().is_some() {
            return None;
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "retry neither exited nor reached the FIFO"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Sleep past git's racy window so a file written now is not racy when the command reads it.
fn age() {
    thread::sleep(Duration::from_millis(2_200));
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The run finished with the command's status, wrote no proof, and said why.
fn assert_not_recorded(out: &Output, case: &Case, key: &str, message: &str) {
    let err = stderr(out);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains(&format!("stoop: not recorded: {message}")),
        "expected `{message}` in:\n{err}"
    );
    assert!(
        !case.proof(key).exists(),
        "a refused run wrote a proof:\n{err}"
    );
}

fn assert_recorded(out: &Output, case: &Case, key: &str) {
    let err = stderr(out);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("stoop: recorded "), "{err}");
    assert!(case.proof(key).exists(), "no proof written:\n{err}");
}

fn assert_refused_for(out: &Output, case: &Case, key: &str, paths: &[&str]) {
    let err = stderr(out);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("stoop: not recorded:"), "{err}");
    assert!(
        paths.iter().any(|path| err.contains(path)),
        "expected one of {paths:?} in:\n{err}"
    );
    assert!(
        !case.proof(key).exists(),
        "a refused run wrote a proof:\n{err}"
    );
}

fn proof(case: &Case, key: &str) -> Value {
    let value: Value = serde_json::from_slice(&fs::read(case.proof(key)).unwrap()).unwrap();
    value["proofs"][0].clone()
}

fn assert_entry_id(stored: &Value, field: &str, path: &str, expected: &str) {
    let entries = stored[field].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|entry| entry["path"] == path)
        .unwrap_or_else(|| panic!("missing {path} in {field}: {entries:?}"));
    assert_eq!(entry["id"].as_str(), Some(expected), "{entry}");
}

fn assert_file_entry(stored: &Value, field: &str, path: &str, bytes: &[u8]) {
    let expected = format!("f:{}", blake3::hash(bytes).to_hex());
    assert_entry_id(stored, field, path, &expected);
}

fn touch_ahead(path: &Path) {
    let status = Command::new("touch")
        .args(["-d", "+60 seconds"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

// Inputs the command must not be able to change under it.

#[test]
fn same_size_rewrite_while_the_command_blocks_is_not_recorded() {
    let case = Case::new("t1");
    let a = case.file("src/a", b"alpha-one\n");
    age();
    let fifo = case.fifo("t1.fifo");
    let script = "cat src/a >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t1", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(&a, b"bravo-two\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t1", "src/a changed while the command ran");
    let again = run(&case, "t1", "cat src/a >/dev/null", &[]);
    assert!(stderr(&again).contains("stoop: run "), "{}", stderr(&again));
}

#[test]
fn a_missing_path_that_appears_mid_run_is_not_recorded() {
    let case = Case::new("t2");
    fs::create_dir_all(case.root().join("gen")).unwrap();
    let fifo = case.fifo("t2.fifo");
    let script = "test -e gen/x; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t2", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(case.root().join("gen/x"), b"appeared\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t2", "gen/x changed while the command ran");
}

#[test]
fn a_listed_directory_that_gains_an_entry_mid_run_is_not_recorded() {
    let case = Case::new("t3");
    case.file("d/old", b"old\n");
    age();
    let fifo = case.fifo("t3.fifo");
    let script = "ls d >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t3", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(case.root().join("d/new"), b"new\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t3", "d changed while the command ran");
}

#[test]
fn a_file_modified_just_before_the_read_is_hashed_at_the_read_and_recorded() {
    let case = Case::new("t4");
    let a = case.file("src/a", b"alpha\n");
    touch_ahead(&a);
    let debug: &[(&str, &Path)] = &[("STOOP_DEBUG", Path::new("1"))];
    let out = run(&case, "t4", "cat src/a >/dev/null", debug);
    assert_recorded(&out, &case, "t4");
    assert!(
        stderr(&out).contains("stoop: debug: hashed src/a at the read"),
        "{}",
        stderr(&out)
    );
    let again = run(&case, "t4", "cat src/a >/dev/null", &[]);
    assert!(
        stderr(&again).contains("stoop: skip t4"),
        "{}",
        stderr(&again)
    );
}

#[test]
fn an_old_file_is_not_hashed_at_the_read() {
    let case = Case::new("t5");
    case.file("src/a", b"alpha\n");
    age();
    let debug: &[(&str, &Path)] = &[("STOOP_DEBUG", Path::new("1"))];
    let out = run(&case, "t5", "cat src/a >/dev/null", debug);
    assert_recorded(&out, &case, "t5");
    assert!(
        !stderr(&out).contains("stoop: debug: hashed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_stat_only_look_at_a_recent_file_is_not_hashed() {
    let case = Case::new("t6");
    let a = case.file("src/a", b"alpha\n");
    touch_ahead(&a);
    let debug: &[(&str, &Path)] = &[("STOOP_DEBUG", Path::new("1"))];
    let out = run(&case, "t6", "test -f src/a", debug);
    assert_recorded(&out, &case, "t6");
    assert!(
        !stderr(&out).contains("stoop: debug: hashed"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn an_own_entry_change_after_a_directory_listing_refuses_the_record() {
    // Excluding the command's entry can also hide a foreign change to that entry.
    let case = Case::new("t7-aged");
    case.file("d/x", b"x\n");
    age();
    let out = run(&case, "t7-aged", "ls d >/dev/null; touch d/out", &[]);
    assert_refused_for(&out, &case, "t7-aged", &["read d ", "d changed", "d/out"]);

    let case = Case::new("t7-racy");
    case.file("d/x", b"x\n");
    let out = run(&case, "t7-racy", "ls d >/dev/null; touch d/out", &[]);
    assert_refused_for(&out, &case, "t7-racy", &["read d ", "d changed", "d/out"]);
}

#[test]
fn a_file_read_then_written_by_the_command_still_records() {
    // The verified read-time bytes stay an input and prior, separate from the final output.
    let case = Case::new("t8");
    case.file("f", b"start\n");
    age();
    let out = run(&case, "t8", "cat f >/dev/null; echo x >> f", &[]);
    assert_recorded(&out, &case, "t8");
    let stored = proof(&case, "t8");
    assert_file_entry(&stored, "inputs", "f", b"start\n");
    assert_file_entry(&stored, "priors", "f", b"start\n");
    assert_file_entry(&stored, "outputs", "f", b"start\nx\n");
}

#[test]
fn rename_over_after_the_read_is_not_recorded() {
    let case = Case::new("t9");
    let a = case.file("src/a", b"alpha-one\n");
    let tmp = case.root().join("src/a.tmp");
    fs::write(&tmp, b"bravo-two\n").unwrap();
    age();
    let fifo = case.fifo("t9.fifo");
    let script = "cat src/a >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t9", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::rename(&tmp, &a).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t9", "src/a changed while the command ran");
}

#[test]
fn append_after_the_read_is_not_recorded() {
    let case = Case::new("t10");
    let a = case.file("src/a", b"alpha\n");
    age();
    let fifo = case.fifo("t10.fifo");
    let script = "cat src/a >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t10", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    OpenOptions::new()
        .append(true)
        .open(&a)
        .unwrap()
        .write_all(b"more\n")
        .unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t10", "src/a changed while the command ran");
}

#[test]
fn truncate_in_place_after_the_read_is_not_recorded() {
    let case = Case::new("t11");
    let a = case.file("src/a", b"alpha-alpha-alpha\n");
    age();
    let fifo = case.fifo("t11.fifo");
    let script = "cat src/a >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t11", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    File::create(&a).unwrap().write_all(b"short\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t11", "src/a changed while the command ran");
}

#[test]
fn a_write_through_a_hard_link_after_the_read_is_not_recorded() {
    let case = Case::new("t12");
    let a = case.file("src/a", b"alpha-one\n");
    let b = case.root().join("src/b");
    fs::hard_link(&a, &b).unwrap();
    age();
    let fifo = case.fifo("t12.fifo");
    let script = "cat src/a >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t12", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(&b, b"bravo-two\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t12", "src/a changed while the command ran");
}

#[test]
fn an_outside_root_input_rewritten_mid_run_is_not_recorded() {
    let case = Case::new("t13");
    let outside = case.outside("data.txt", b"alpha-one\n");
    age();
    let fifo = case.fifo("t13.fifo");
    let script = "cat \"$OUTSIDE\" >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(
        &case,
        "t13",
        script,
        &[("FIFO", &fifo), ("OUTSIDE", &outside)],
    );
    let release = meet(&fifo);
    fs::write(&outside, b"bravo-two\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    let message = format!("{} changed while the command ran", outside.display());
    assert_not_recorded(&out, &case, "t13", &message);
}

#[test]
fn an_outside_root_input_deleted_mid_run_is_not_recorded() {
    let case = Case::new("t14");
    let outside = case.outside("data.txt", b"alpha-one\n");
    age();
    let fifo = case.fifo("t14.fifo");
    let script = "cat \"$OUTSIDE\" >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(
        &case,
        "t14",
        script,
        &[("FIFO", &fifo), ("OUTSIDE", &outside)],
    );
    let release = meet(&fifo);
    fs::remove_file(&outside).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    let message = format!("{} changed while the command ran", outside.display());
    assert_not_recorded(&out, &case, "t14", &message);
}

#[test]
fn a_symlink_retargeted_mid_run_is_not_recorded() {
    let case = Case::new("t15");
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    symlink("a", case.root().join("src/link")).unwrap();
    age();
    let fifo = case.fifo("t15.fifo");
    let script = "cat src/link >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t15", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let link = case.root().join("src/link");
    fs::remove_file(&link).unwrap();
    symlink("b", &link).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t15", "src/link changed while the command ran");
}

#[test]
fn a_path_that_appears_is_read_and_disappears_is_not_recorded() {
    let case = Case::new("t16");
    fs::create_dir_all(case.root().join("gen")).unwrap();
    let first = case.fifo("t16-one.fifo");
    let second = case.fifo("t16-two.fifo");
    let script = "test -e gen/x; cat \"$FIRST\" >/dev/null; cat gen/x >/dev/null; cat \"$SECOND\" >/dev/null";
    let child = spawn(
        &case,
        "t16",
        script,
        &[("FIRST", &first), ("SECOND", &second)],
    );
    let release = meet(&first);
    fs::write(case.root().join("gen/x"), b"appeared\n").unwrap();
    drop(release);
    let release = meet(&second);
    fs::remove_file(case.root().join("gen/x")).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t16", "gen/x changed while the command ran");
}

#[test]
fn a_gitattributes_edit_mid_run_keeps_the_record_without_blob_ids() {
    let case = Case::new("t17");
    let root = case.root();
    case.file("src/a.txt", b"alpha\n");
    case.file(".gitattributes", b"# no attributes yet\n");
    let git = |args: &[&str]| {
        let status = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(&root)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    git(&["add", "-A"]);
    git(&["commit", "-q", "-m", "init"]);
    age();

    let baseline = run(&case, "t17-base", "cat src/a.txt >/dev/null", &[]);
    assert_recorded(&baseline, &case, "t17-base");
    let proof: Value = serde_json::from_slice(&fs::read(case.proof("t17-base")).unwrap()).unwrap();
    let oid = proof["proofs"][0]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["path"] == "src/a.txt")
        .map(|item| item["oid"].clone())
        .unwrap();
    assert!(
        oid.is_string(),
        "the baseline should carry a blob id: {proof}"
    );

    let fifo = case.fifo("t17.fifo");
    let script = "cat src/a.txt >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t17", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    OpenOptions::new()
        .append(true)
        .open(root.join(".gitattributes"))
        .unwrap()
        .write_all(b"*.bin binary\n")
        .unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_recorded(&out, &case, "t17");
    let proof: Value = serde_json::from_slice(&fs::read(case.proof("t17")).unwrap()).unwrap();
    let inputs = proof["proofs"][0]["inputs"].as_array().unwrap();
    let item = inputs
        .iter()
        .find(|item| item["path"] == "src/a.txt")
        .expect("src/a.txt is an input");
    assert!(
        item["oid"].is_null(),
        "a watched source changed, so no blob id: {item}"
    );
}

#[test]
fn a_stoop_sh_step_with_a_mid_run_edit_is_not_recorded() {
    let case = Case::new("t18");
    case.file("src/a", b"alpha-one\n");
    let step = case.file(
        "step.sh",
        b"cat src/a >/dev/null\ncat \"$FIFO\" >/dev/null\n",
    );
    age();
    let fifo = case.fifo("t18.fifo");
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    clean(&mut command);
    let child = command
        .args(["sh"])
        .arg(&step)
        .current_dir(case.root())
        .env("FIFO", &fifo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let release = meet(&fifo);
    fs::write(case.root().join("src/a"), b"bravo-two\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    let err = stderr(&out);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains("not recorded: ") && err.contains("src/a changed while the command ran"),
        "{err}"
    );
    let proofs = case.root().join(".stoop/proofs");
    let written = fs::read_dir(&proofs)
        .map(|entries| entries.count())
        .unwrap_or(0);
    assert_eq!(written, 0, "a refused stoop sh step wrote a proof:\n{err}");
}

#[test]
fn replacing_a_link_hop_after_reading_through_it_refuses_the_record() {
    // Owning one hop does not prove that the read route still resolves to the observed target.
    let case = Case::new("t17-own-hop");
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    symlink("a", case.root().join("src/link2")).unwrap();
    symlink("link2", case.root().join("src/link1")).unwrap();
    age();
    let script = "cat src/link1 >/dev/null; ln -s b src/link2.new && mv -f src/link2.new src/link2";
    let out = run(&case, "t17-own-hop", script, &[]);
    assert_refused_for(&out, &case, "t17-own-hop", &["src/link1", "src/link2"]);
}

#[test]
fn a_link_hop_another_process_replaces_is_not_recorded() {
    let case = Case::new("t17-outside-hop");
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    symlink("a", case.root().join("src/link2")).unwrap();
    symlink("link2", case.root().join("src/link1")).unwrap();
    age();
    let fifo = case.fifo("t17.fifo");
    let script = "cat src/link1 >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t17-outside-hop", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let link2 = case.root().join("src/link2");
    fs::remove_file(&link2).unwrap();
    symlink("b", &link2).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(&out, &case, "t17-outside-hop", "src/link");
}

#[test]
fn a_write_through_a_dangling_link_records_the_target_as_output() {
    let case = Case::new("t18-own-dangling");
    case.file("src/keep", b"keep\n");
    symlink("new", case.root().join("src/dl")).unwrap();
    let out = run(
        &case,
        "t18-own-dangling",
        "test -e src/new; echo made > src/dl",
        &[],
    );
    // The observed absence remains an input and prior, even though the command created the file.
    assert_recorded(&out, &case, "t18-own-dangling");
    let stored = proof(&case, "t18-own-dangling");
    assert_entry_id(&stored, "inputs", "src/new", "a");
    assert_entry_id(&stored, "priors", "src/new", "a");
    assert_file_entry(&stored, "outputs", "src/new", b"made\n");
}

#[test]
fn a_dangling_output_link_retargeted_by_an_outside_writer_refuses() {
    let key = "dangling-output-retarget";
    let case = Case::new(key);
    case.file("src/other", b"outside\n");
    let link = case.root().join("src/dl");
    symlink("new", &link).unwrap();
    let fifo = case.fifo("dangling-retarget.fifo");
    let child = spawn(
        &case,
        key,
        "echo made > src/dl; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::remove_file(&link).unwrap();
    symlink("other", &link).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["src/dl"]);
}

#[test]
fn a_dangling_link_target_another_process_creates_is_not_recorded() {
    let case = Case::new("t18-outside-dangling");
    case.file("src/keep", b"keep\n");
    symlink("new", case.root().join("src/dl")).unwrap();
    age();
    let fifo = case.fifo("t18.fifo");
    let script = "test -e src/new; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t18-outside-dangling", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(case.root().join("src/new"), b"made outside\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "t18-outside-dangling",
        "src/new changed while the command ran",
    );
}

#[test]
fn a_dangling_link_resolved_by_an_outside_creator_refuses() {
    let key = "dangling-link-outside-create";
    let case = Case::new(key);
    case.file("src/keep", b"keep\n");
    symlink("new", case.root().join("src/dl")).unwrap();
    let fifo = case.fifo("outside-create.fifo");
    let child = spawn(
        &case,
        key,
        "test -e src/dl || :; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(case.root().join("src/new"), b"outside\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["src/dl"]);
}

#[test]
fn a_write_through_an_alias_inside_the_root_records_the_real_path() {
    // The absence that preceded the write is retained under the physical target.
    let case = Case::new("t19-own-alias");
    case.file("src/keep", b"keep\n");
    fs::create_dir_all(case.root().join("real")).unwrap();
    symlink("real", case.root().join("alias")).unwrap();
    let out = run(
        &case,
        "t19-own-alias",
        "test -e real/x; echo made > alias/x",
        &[],
    );
    assert_recorded(&out, &case, "t19-own-alias");
    let stored = proof(&case, "t19-own-alias");
    assert_entry_id(&stored, "inputs", "real/x", "a");
    assert_entry_id(&stored, "priors", "real/x", "a");
    assert_file_entry(&stored, "outputs", "real/x", b"made\n");
}

#[test]
fn a_file_another_process_creates_at_an_alias_target_is_not_recorded() {
    let case = Case::new("t19-outside-alias");
    case.file("src/keep", b"keep\n");
    fs::create_dir_all(case.root().join("real")).unwrap();
    symlink("real", case.root().join("alias")).unwrap();
    age();
    let fifo = case.fifo("t19.fifo");
    let script = "test -e real/x; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t19-outside-alias", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(case.root().join("real/x"), b"made outside\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "t19-outside-alias",
        "real/x changed while the command ran",
    );
}

#[test]
fn writing_a_hard_link_name_after_reading_its_twin_refuses_the_record() {
    // An outside writer can restore the original bytes after the command writes the other name.
    let case = Case::new("t20-hard-link");
    let a = case.file("src/a", b"alpha-one\n");
    fs::hard_link(&a, case.root().join("src/b")).unwrap();
    age();
    let script = "cat src/a >/dev/null; printf 'bravo-two\\n' > src/b";
    let out = run(&case, "t20-hard-link", script, &[]);
    assert_refused_for(&out, &case, "t20-hard-link", &["src/a", "src/b"]);
}

#[test]
fn a_file_the_command_overwrites_and_reads_back_refuses_the_record() {
    // Final output bytes cannot prove whether the command or a foreign writer supplied the read.
    let case = Case::new("t21-read-back");
    case.file("src/f", b"start\n");
    age();
    let out = run(
        &case,
        "t21-read-back",
        "echo fresh > src/f; cat src/f >/dev/null",
        &[],
    );
    assert_refused_for(&out, &case, "t21-read-back", &["src/f"]);
}

#[test]
fn metadata_and_directory_opens_of_confirmed_outputs_are_bookkeeping() {
    let key = "own-metadata-looks";
    let case = Case::new(key);
    let script = concat!(
        "python3 -c 'import ctypes, os; ",
        "fd = os.open(\"out\", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); ",
        "os.write(fd, b\"data\"); os.fstat(fd); os.close(fd); ",
        "fd = os.open(\"out\", os.O_PATH | os.O_RDWR); os.fstat(fd); ",
        "libc = ctypes.CDLL(None, use_errno=True); buf = ctypes.create_string_buffer(512); ",
        "assert libc.fstatat(fd, b\"\", ctypes.byref(buf), 0x1000) == 0; ",
        "os.close(fd); os.stat(\"out\"); ",
        "os.mkdir(\"dir\"); fd = os.open(\"dir\", os.O_RDONLY | os.O_DIRECTORY); ",
        "os.fstat(fd); os.close(fd)'",
    );
    let out = run(&case, key, script, &[]);
    assert_recorded(&out, &case, key);
}

#[test]
fn executing_a_new_output_is_still_a_content_read() {
    let key = "own-executable-readback";
    let case = Case::new(key);
    let out = run(
        &case,
        key,
        "cat /bin/true > program; chmod +x program; ./program",
        &[],
    );
    assert_refused_for(&out, &case, key, &["program"]);
}

#[test]
fn stat_of_an_output_replaced_from_outside_refuses_the_record() {
    let key = "foreign-output-stat";
    let case = Case::new(key);
    let replacement = case.outside("replacement", b"foreign\n");
    let fifo = case.fifo("before-stat.fifo");
    let script = "printf 'own\\n' > out; cat \"$FIFO\" >/dev/null; test -s out";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let output = case.root().join("out");
    let original = fs::metadata(&output).unwrap();
    let foreign = fs::metadata(&replacement).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (foreign.dev(), foreign.ino())
    );
    fs::rename(&replacement, &output).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["out"]);
}

#[test]
fn stat_of_an_output_replaced_with_another_own_output_refuses_the_record() {
    let key = "other-output-inode-stat";
    let case = Case::new(key);
    let fifo = case.fifo("before-stat.fifo");
    let script =
        "printf 'first\\n' > out; printf 'second\\n' > other; cat \"$FIFO\" >/dev/null; test -s out";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let output = case.root().join("out");
    let other = case.root().join("other");
    let original = fs::metadata(&output).unwrap();
    let replacement = fs::metadata(&other).unwrap();
    assert_ne!(
        (original.dev(), original.ino()),
        (replacement.dev(), replacement.ino())
    );
    fs::rename(&other, &output).unwrap();
    assert_eq!(
        fs::metadata(&output).map(|m| (m.dev(), m.ino())).unwrap(),
        (replacement.dev(), replacement.ino())
    );
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["out"]);
}

#[test]
fn restoring_the_pre_rename_inode_does_not_count_as_a_landing() {
    let key = "restored-pre-rename-inode";
    let case = Case::new(key);
    let output = case.file("out", b"old\n");
    let saved = case.dir.join("saved-old");
    fs::hard_link(&output, &saved).unwrap();
    let old = fs::metadata(&output).unwrap();
    let fifo = case.fifo("before-stat.fifo");
    let script = concat!(
        "python3 -c 'import os; ",
        "fd = os.open(\"stage\", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); ",
        "os.write(fd, b\"new\"); os.close(fd); os.replace(\"stage\", \"out\"); ",
        "f = open(os.environ[\"FIFO\"]); f.read(); f.close(); os.stat(\"out\")'",
    );
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let landed = fs::metadata(&output).unwrap();
    assert_ne!((old.dev(), old.ino()), (landed.dev(), landed.ino()));
    fs::rename(&saved, &output).unwrap();
    assert_eq!(
        fs::metadata(&output).map(|m| (m.dev(), m.ino())).unwrap(),
        (old.dev(), old.ino())
    );
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["out"]);
}

#[test]
fn fstat_of_a_replaced_output_descriptor_refuses_the_record() {
    let key = "foreign-output-fstat";
    let case = Case::new(key);
    let replacement = case.outside("replacement", b"foreign\n");
    let fifo = case.fifo("before-fstat.fifo");
    let script = concat!(
        "python3 -c 'import os; ",
        "fd = os.open(\"out\", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600); ",
        "os.write(fd, b\"own\"); ",
        "f = open(os.environ[\"FIFO\"]); f.read(); f.close(); ",
        "os.fstat(fd); os.close(fd)'",
    );
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::rename(&replacement, case.root().join("out")).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["out"]);
}

#[test]
fn foreign_same_inode_metadata_change_is_an_accepted_v9_gap() {
    let key = "same-inode-metadata-gap";
    let case = Case::new(key);
    let before = case.fifo("before.fifo");
    let after = case.fifo("after.fifo");
    let script = concat!(
        "printf 'own\\n' > out; cat \"$BEFORE\" >/dev/null; ",
        "if [ -x out ]; then printf executable > choice; else printf plain > choice; fi; ",
        "cat \"$AFTER\" >/dev/null",
    );
    let env = [("BEFORE", before.as_path()), ("AFTER", after.as_path())];
    let child = spawn(&case, key, script, &env);
    let release = meet(&before);
    let output = case.root().join("out");
    let original = fs::metadata(&output).unwrap();
    fs::set_permissions(
        &output,
        fs::Permissions::from_mode(original.permissions().mode() | 0o111),
    )
    .unwrap();
    let changed = fs::metadata(&output).unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (changed.dev(), changed.ino())
    );
    drop(release);
    let release = meet(&after);
    assert_eq!(fs::read(case.root().join("choice")).unwrap(), b"executable");
    fs::set_permissions(&output, original.permissions()).unwrap();
    let restored = fs::metadata(&output).unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (restored.dev(), restored.ino())
    );
    drop(release);
    let first = child.wait_with_output().unwrap();
    assert_recorded(&first, &case, key);

    // The restored output identity allows a skip even though a rerun would take the other branch.
    let mut retry = spawn(&case, key, script, &env);
    let release = meet_if_running(&before, &mut retry);
    let reran = release.is_some();
    drop(release);
    if reran {
        drop(meet_if_running(&after, &mut retry));
    }
    let second = retry.wait_with_output().unwrap();
    assert!(
        !reran && stderr(&second).contains("stoop: skip"),
        "{}",
        stderr(&second)
    );
}

#[test]
fn a_write_through_an_alias_read_back_through_the_real_path_refuses_the_record() {
    // The real path still names bytes that an outside writer could have supplied.
    let case = Case::new("t19-own-readback");
    case.file("src/keep", b"keep\n");
    fs::create_dir_all(case.root().join("real")).unwrap();
    symlink("real", case.root().join("alias")).unwrap();
    let script = "test -e real/x; echo made > alias/x; cat real/x >/dev/null";
    let out = run(&case, "t19-own-readback", script, &[]);
    assert_refused_for(&out, &case, "t19-own-readback", &["real/x", "alias/x"]);
}

#[test]
fn a_directory_link_retargeted_mid_run_is_refused_for_the_link_read_through_it() {
    // src/link1 leads through the directory link src/dl to src/dirA/x. The command reads it once,
    // then another process retargets src/dl to src/dirB. The file the command read is no longer
    // what src/link1 names, so the record would follow the old file and could skip wrongly.
    let case = Case::new("t22-outside-dir-link");
    case.file("src/dirA/x", b"alpha\n");
    case.file("src/dirB/x", b"bravo\n");
    symlink("dirA", case.root().join("src/dl")).unwrap();
    symlink("dl/x", case.root().join("src/link1")).unwrap();
    age();
    let fifo = case.fifo("t22.fifo");
    let script = "cat src/link1 >/dev/null; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, "t22-outside-dir-link", script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    let dl = case.root().join("src/dl");
    fs::remove_file(&dl).unwrap();
    symlink("dirB", &dl).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "t22-outside-dir-link",
        "src/dl changed while the command ran",
    );
}

#[test]
fn dangling_link_writes_record_the_target_or_refuse_and_rerun_if_it_disappears() {
    for (key, two_hops) in [
        ("dangling-output-one", false),
        ("dangling-output-two", true),
    ] {
        let case = Case::new(key);
        case.file("src/keep", b"keep\n");
        if two_hops {
            symlink("dl2", case.root().join("src/dl")).unwrap();
            symlink("new", case.root().join("src/dl2")).unwrap();
        } else {
            symlink("new", case.root().join("src/dl")).unwrap();
        }
        let script = "printf 'made\\n' > src/dl";
        let first = run(&case, key, script, &[]);
        let err = stderr(&first);
        assert!(first.status.success(), "{err}");
        if err.contains("stoop: recorded ") {
            let stored = proof(&case, key);
            let outputs = stored["outputs"].as_array().unwrap();
            let target = outputs
                .iter()
                .find(|entry| entry["path"] == "src/new")
                .unwrap_or_else(|| panic!("missing created target in {outputs:?}"));
            let expected = format!("f:{}", blake3::hash(b"made\n").to_hex());
            assert_eq!(target["id"].as_str(), Some(expected.as_str()), "{target}");
            assert!(
                !outputs.iter().any(|entry| entry["path"] == "src/dl2"),
                "{outputs:?}"
            );
        } else {
            assert_refused_for(&first, &case, key, &["src/new", "src/dl"]);
        }

        fs::remove_file(case.root().join("src/new")).unwrap();
        let again = run(&case, key, script, &[]);
        let err = stderr(&again);
        assert!(again.status.success(), "{err}");
        assert!(
            err.contains("stoop: run ") && !err.contains("stoop: skip"),
            "{err}"
        );
        assert_eq!(fs::read(case.root().join("src/new")).unwrap(), b"made\n");
    }
}

#[test]
fn foreign_bytes_read_back_after_an_own_write_refuse_and_the_retry_fails() {
    let key = "foreign-read-back";
    let case = Case::new(key);
    let file = case.file("src/f", b"original\n");
    symlink("f", case.root().join("src/link")).unwrap();
    age();
    let fifo = case.fifo("read-back.fifo");
    let script = "printf 'bad\\n' > src/f; cat \"$FIFO\" >/dev/null; grep -qx good src/link";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(&file, b"good\n").unwrap();
    drop(release);
    let first = child.wait_with_output().unwrap();

    let mut retry = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet_if_running(&fifo, &mut retry);
    let reached_fifo = release.is_some();
    drop(release);
    let again = retry.wait_with_output().unwrap();
    assert_refused_for(&first, &case, key, &["src/f", "src/link"]);
    let err = stderr(&again);
    assert!(reached_fifo, "retry never reached the FIFO:\n{err}");
    assert_eq!(again.status.code(), Some(1), "{err}");
    assert!(!err.contains("stoop: skip"), "{err}");
    assert!(!case.proof(key).exists(), "retry wrote a proof:\n{err}");
}

#[test]
fn replacing_a_hard_link_source_after_the_link_refuses_the_record() {
    let key = "hard-link-replaced-source";
    let case = Case::new(key);
    let source = case.file("src/a", b"good\n");
    let replacement = case.outside("replacement", b"bad\n");
    age();
    let fifo = case.fifo("hard-link.fifo");
    let script = "grep -qx good src/a && ln src/a src/b && cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::rename(&replacement, &source).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(case.root().join("src/b")).unwrap(), b"good\n");
    assert_eq!(fs::read(&source).unwrap(), b"bad\n");
    assert_refused_for(&out, &case, key, &["src/a", "src/b"]);
}

#[test]
fn an_own_write_open_does_not_hide_a_foreign_hard_link_rewrite() {
    let key = "hard-link-open-foreign-write";
    let case = Case::new(key);
    let source = case.file("src/a", b"good\n");
    let alias = case.root().join("src/b");
    fs::hard_link(&source, &alias).unwrap();
    age();
    let fifo = case.fifo("hard-link-open.fifo");
    let script = "grep -qx good src/a && : >> src/b && cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(&alias, b"evil\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&source).unwrap(), b"evil\n");
    assert_refused_for(&out, &case, key, &["src/a", "src/b"]);
}

#[test]
fn linking_a_read_file_fails_closed_without_a_verified_link_prior() {
    // The new name's prior absence must be a runtime input, and the source's ctime change must be
    // attributable to this link. Until both are proven, recording could skip a later EEXIST.
    let key = "hard-link-metadata-only";
    let case = Case::new(key);
    case.file("src/a", b"good\n");
    age();
    let out = run(&case, key, "cat src/a >/dev/null && ln src/a src/b", &[]);
    assert_refused_for(&out, &case, key, &["src/a", "src/b"]);
}

#[test]
fn writing_a_hard_link_after_reading_its_other_name_refuses_the_record() {
    let key = "hard-link-content-write";
    let case = Case::new(key);
    let source = case.file("src/a", b"good\n");
    fs::hard_link(&source, case.root().join("src/b")).unwrap();
    age();
    let out = run(
        &case,
        key,
        "cat src/a >/dev/null && printf 'bad\\n' > src/b",
        &[],
    );
    assert_refused_for(&out, &case, key, &["src/a", "src/b"]);
}

#[test]
fn replacing_an_own_rewritten_link_hop_from_outside_refuses_the_read_route() {
    let key = "own-hop-then-foreign";
    let case = Case::new(key);
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    case.file("src/c", b"charlie\n");
    symlink("a", case.root().join("src/link2")).unwrap();
    symlink("link2", case.root().join("src/link1")).unwrap();
    let replacement = case.outside("next-link", b"");
    fs::remove_file(&replacement).unwrap();
    symlink("c", &replacement).unwrap();
    age();
    let fifo = case.fifo("hop.fifo");
    let script =
        "cat src/link1 > result && rm src/link2 && ln -s b src/link2 && cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    assert_eq!(
        fs::read_link(case.root().join("src/link2")).unwrap(),
        Path::new("b")
    );
    fs::rename(&replacement, case.root().join("src/link2")).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(case.root().join("result")).unwrap(), b"alpha\n");
    assert_refused_for(&out, &case, key, &["src/link1", "src/link2"]);
}

#[test]
fn retargeting_an_external_directory_hop_refuses_the_in_root_read_route() {
    let key = "external-directory-hop";
    let case = Case::new(key);
    case.file("src/keep", b"keep\n");
    let old = case.outside("a/data", b"alpha\n");
    case.outside("b/data", b"bravo\n");
    let hop = case.dir.join("outside/hop");
    symlink("a", &hop).unwrap();
    symlink(hop.join("data"), case.root().join("src/link")).unwrap();
    let next = case.dir.join("outside/next-hop");
    symlink("b", &next).unwrap();
    age();
    let fifo = case.fifo("external-hop.fifo");
    let child = spawn(
        &case,
        key,
        "cat src/link > result && cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::rename(&next, &hop).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&old).unwrap(), b"alpha\n");
    assert_eq!(fs::read(case.root().join("result")).unwrap(), b"alpha\n");
    assert_refused_for(
        &out,
        &case,
        key,
        &["src/link", hop.to_str().unwrap(), old.to_str().unwrap()],
    );
}

#[test]
fn a_racy_open_restored_after_the_descriptor_read_refuses_the_record() {
    let key = "racy-descriptor-restored";
    let case = Case::new(key);
    let file = case.file("src/a", b"bad!\n");
    touch_ahead(&file);
    let original = fs::metadata(&file).unwrap();
    let first = case.fifo("racy-first.fifo");
    let second = case.fifo("racy-second.fifo");
    let script = "exec 3< src/a || exit; cat \"$FIRST\" >/dev/null || exit; grep -qx good <&3 || exit; cat \"$SECOND\" >/dev/null";
    let child = spawn(
        &case,
        key,
        script,
        &[("FIRST", &first), ("SECOND", &second)],
    );
    let release = meet(&first);
    thread::sleep(Duration::from_millis(10));
    fs::write(&file, b"good\n").unwrap();
    drop(release);
    let release = meet(&second);
    thread::sleep(Duration::from_millis(10));
    fs::write(&file, b"bad!\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"bad!\n");
    let restored = fs::metadata(&file).unwrap();
    assert_eq!(
        (
            original.dev(),
            original.ino(),
            original.mode(),
            original.size()
        ),
        (
            restored.dev(),
            restored.ino(),
            restored.mode(),
            restored.size()
        )
    );
    assert_ne!(
        (original.mtime(), original.mtime_nsec()),
        (restored.mtime(), restored.mtime_nsec())
    );
    assert_refused_for(&out, &case, key, &["src/a"]);
}

#[test]
fn a_foreign_retarget_before_an_alias_write_cannot_record_the_wrong_output() {
    let key = "alias-retarget-before-open";
    let case = Case::new(key);
    case.file("a/keep", b"keep\n");
    case.file("b/keep", b"keep\n");
    let outside = case.dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let hop = outside.join("hop");
    let next = outside.join("next-hop");
    symlink(case.root().join("a"), &hop).unwrap();
    symlink(case.root().join("b"), &next).unwrap();
    symlink(&hop, case.root().join("alias")).unwrap();
    let fifo = case.fifo("alias-write.fifo");
    let script = "cat \"$FIFO\" >/dev/null; printf 'written\\n' > alias/out";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::rename(&next, &hop).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    let err = stderr(&out);
    assert!(out.status.success(), "{err}");
    assert_eq!(fs::read(case.root().join("b/out")).unwrap(), b"written\n");
    assert!(!case.root().join("a/out").exists());
    if err.contains("stoop: recorded ") {
        let stored = proof(&case, key);
        let outputs = stored["outputs"].as_array().unwrap();
        let output = outputs
            .iter()
            .find(|entry| entry["path"] == "b/out")
            .unwrap_or_else(|| panic!("missing kernel destination in {outputs:?}"));
        let expected = format!("f:{}", blake3::hash(b"written\n").to_hex());
        assert_eq!(output["id"].as_str(), Some(expected.as_str()), "{output}");
        assert!(
            !outputs.iter().any(|entry| entry["path"] == "a/out"),
            "{outputs:?}"
        );

        fs::remove_file(case.root().join("b/out")).unwrap();
        let mut retry = spawn(&case, key, script, &[("FIFO", &fifo)]);
        let release = meet_if_running(&fifo, &mut retry);
        let reached_fifo = release.is_some();
        drop(release);
        let again = retry.wait_with_output().unwrap();
        let err = stderr(&again);
        assert!(reached_fifo, "retry never reached the FIFO:\n{err}");
        assert!(again.status.success(), "{err}");
        assert!(!err.contains("stoop: skip"), "{err}");
        assert_eq!(fs::read(case.root().join("b/out")).unwrap(), b"written\n");
    } else {
        assert_refused_for(&out, &case, key, &["alias", "b/out", hop.to_str().unwrap()]);
    }
}

#[test]
fn opening_an_existing_file_for_writing_does_not_own_its_directory_entry() {
    let key = "write-open-foreign-delete";
    let case = Case::new(key);
    let marker = case.file("d/marker", b"present\n");
    age();
    let fifo = case.fifo("write-open.fifo");
    let script = "ls d | grep -qx marker && python3 -c 'import os; fd = os.open(\"d/marker\", os.O_WRONLY); os.close(fd)' && cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::remove_file(&marker).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["d changed", "d/marker"]);
}

#[test]
fn a_failed_namespace_change_does_not_own_a_later_foreign_deletion() {
    let key = "failed-link-foreign-delete";
    let case = Case::new(key);
    let marker = case.file("d/marker", b"present\n");
    age();
    let fifo = case.fifo("failed-link.fifo");
    let script = "ls d | grep -qx marker || exit 9; if ln -s target d/marker 2>/dev/null; then exit 7; fi; test -f d/marker || exit 8; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::remove_file(&marker).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["d changed", "d/marker"]);
}

#[test]
fn a_failed_namespace_attempt_without_an_outside_change_still_records() {
    let key = "failed-link-no-change";
    let case = Case::new(key);
    case.file("d/marker", b"present\n");
    age();
    let script = "ls d | grep -qx marker || exit 9; if ln -s target d/marker 2>/dev/null; then exit 7; fi; test -f d/marker";
    let out = run(&case, key, script, &[]);
    assert_recorded(&out, &case, key);
}

#[test]
fn a_changed_ignored_regular_path_does_not_refuse_an_otherwise_recordable_run() {
    let key = "ignored-path-appears";
    let case = Case::new(key);
    case.file(".stoopignore", b"scratch/\n");
    case.file("src/keep", b"keep\n");
    fs::create_dir(case.root().join("scratch")).unwrap();
    let fifo = case.fifo("ignored-path.fifo");
    let script = "cat src/keep >/dev/null; test -e scratch/flag || :; cat \"$FIFO\" >/dev/null; cat scratch/flag >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(case.root().join("scratch/flag"), b"appeared\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_recorded(&out, &case, key);
}

#[test]
fn an_ignored_alias_does_not_hide_a_foreign_rewrite_of_its_tracked_target() {
    let key = "ignored-alias-tracked-target";
    let case = Case::new(key);
    case.file(".stoopignore", b"scratch/\n");
    let target = case.file("src/a", b"alpha\n");
    fs::create_dir(case.root().join("scratch")).unwrap();
    symlink("../src/a", case.root().join("scratch/al")).unwrap();
    age();
    let fifo = case.fifo("ignored-alias.fifo");
    let script = "cat scratch/al >/dev/null; cat \"$FIFO\" >/dev/null; grep -qx bravo scratch/al";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::write(&target, b"bravo\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_refused_for(&out, &case, key, &["src/a", "scratch/al"]);
}

#[test]
fn a_foreign_replacement_between_reading_and_own_writing_refuses_the_record() {
    let key = "foreign-before-own-write";
    let case = Case::new(key);
    let target = case.file("src/f", b"first\n");
    let replacement = case.outside("next-file", b"foreign\n");
    age();
    let fifo = case.fifo("before-own-write.fifo");
    let script = "cat src/f >/dev/null; cat \"$FIFO\" >/dev/null; printf 'own\\n' >> src/f";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    fs::rename(&replacement, &target).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"foreign\nown\n");
    assert_refused_for(&out, &case, key, &["src/f"]);
}

#[test]
fn reading_through_a_created_link_tracks_the_target_and_reruns_after_a_change() {
    let key = "created-link-target-input";
    let case = Case::new(key);
    let target = case.file("src/a", b"first\n");
    age();
    let script = "ln -sf a src/l && cat src/l >/dev/null";
    let first = run(&case, key, script, &[]);
    // Either refuse the unprovable write/read ordering or retain the actual target as an input.
    if stderr(&first).contains("stoop: recorded ") {
        assert_recorded(&first, &case, key);
        let stored = proof(&case, key);
        let inputs = stored["inputs"].as_array().unwrap();
        let input = inputs
            .iter()
            .find(|entry| entry["path"] == "src/a")
            .unwrap_or_else(|| panic!("missing target in {inputs:?}"));
        let expected = format!("f:{}", blake3::hash(b"first\n").to_hex());
        assert_eq!(input["id"].as_str(), Some(expected.as_str()), "{input}");
        let unchanged = run(&case, key, script, &[]);
        assert!(
            stderr(&unchanged).contains("stoop: skip"),
            "{}",
            stderr(&unchanged)
        );
    } else {
        assert_refused_for(&first, &case, key, &["src/a", "src/l"]);
    }
    fs::write(target, b"second\n").unwrap();
    let again = run(&case, key, script, &[]);
    let err = stderr(&again);
    assert!(again.status.success(), "{err}");
    assert!(
        err.contains("stoop: run ") && !err.contains("stoop: skip"),
        "{err}"
    );
}

#[test]
fn an_open_alias_descriptor_keeps_its_original_destination_after_retargeting() {
    let key = "alias-retarget-after-open";
    let case = Case::new(key);
    case.file("a/keep", b"keep\n");
    case.file("b/keep", b"keep\n");
    let outside = case.dir.join("outside");
    fs::create_dir_all(&outside).unwrap();
    let hop = outside.join("hop");
    let next = outside.join("next-hop");
    symlink(case.root().join("a"), &hop).unwrap();
    symlink(case.root().join("b"), &next).unwrap();
    symlink(&hop, case.root().join("alias")).unwrap();
    let fifo = case.fifo("alias-descriptor.fifo");
    let script = "exec 3> alias/out && cat \"$FIFO\" >/dev/null && printf 'written\\n' >&3";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    assert_eq!(fs::read(case.root().join("a/out")).unwrap(), b"");
    fs::rename(&next, &hop).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    let err = stderr(&out);
    assert!(out.status.success(), "{err}");
    assert_eq!(fs::read(case.root().join("a/out")).unwrap(), b"written\n");
    assert!(!case.root().join("b/out").exists());
    if err.contains("stoop: recorded ") {
        let stored = proof(&case, key);
        let outputs = stored["outputs"].as_array().unwrap();
        let output = outputs
            .iter()
            .find(|entry| entry["path"] == "a/out")
            .unwrap_or_else(|| panic!("missing descriptor destination in {outputs:?}"));
        let expected = format!("f:{}", blake3::hash(b"written\n").to_hex());
        assert_eq!(output["id"].as_str(), Some(expected.as_str()), "{output}");
        assert!(
            !outputs.iter().any(|entry| entry["path"] == "b/out"),
            "{outputs:?}"
        );

        fs::remove_file(case.root().join("a/out")).unwrap();
        let mut retry = spawn(&case, key, script, &[("FIFO", &fifo)]);
        let release = meet_if_running(&fifo, &mut retry);
        let reached_fifo = release.is_some();
        drop(release);
        let again = retry.wait_with_output().unwrap();
        let err = stderr(&again);
        assert!(reached_fifo, "retry never reached the FIFO:\n{err}");
        assert!(again.status.success(), "{err}");
        assert!(!err.contains("stoop: skip"), "{err}");
        assert_eq!(fs::read(case.root().join("b/out")).unwrap(), b"written\n");
    } else {
        assert_refused_for(&out, &case, key, &["alias", "a/out", hop.to_str().unwrap()]);
    }
}

#[test]
fn a_non_idempotent_in_place_rewrite_runs_again_against_its_previous_output() {
    let key = "rewrite-non-idempotent";
    let case = Case::new(key);
    let file = case.file("src/a", b"one\n");
    age();
    let script = "sed -i 's/^/x/' src/a";

    let first = run(&case, key, script, &[]);
    assert_recorded(&first, &case, key);
    assert_eq!(fs::read(&file).unwrap(), b"xone\n");
    let stored = proof(&case, key);
    assert_file_entry(&stored, "inputs", "src/a", b"one\n");
    assert_file_entry(&stored, "priors", "src/a", b"one\n");
    assert_file_entry(&stored, "outputs", "src/a", b"xone\n");

    let second = run(&case, key, script, &[]);
    let err = stderr(&second);
    assert!(
        err.contains("stoop: run ") && !err.contains("stoop: skip"),
        "{err}"
    );
    assert_recorded(&second, &case, key);
    assert_eq!(fs::read(&file).unwrap(), b"xxone\n");
    let stored = proof(&case, key);
    assert_file_entry(&stored, "inputs", "src/a", b"xone\n");
    assert_file_entry(&stored, "priors", "src/a", b"xone\n");
    assert_file_entry(&stored, "outputs", "src/a", b"xxone\n");
}

#[test]
fn an_idempotent_in_place_rewrite_skips_only_after_input_and_output_converge() {
    let key = "rewrite-idempotent";
    let case = Case::new(key);
    let file = case.file("src/a", b"one\n");
    age();
    let script = "sed -i 's/^one$/done/' src/a";

    let first = run(&case, key, script, &[]);
    assert_recorded(&first, &case, key);
    assert_eq!(fs::read(&file).unwrap(), b"done\n");
    let stored = proof(&case, key);
    assert_file_entry(&stored, "inputs", "src/a", b"one\n");
    assert_file_entry(&stored, "priors", "src/a", b"one\n");
    assert_file_entry(&stored, "outputs", "src/a", b"done\n");

    let second = run(&case, key, script, &[]);
    let err = stderr(&second);
    assert!(
        err.contains("stoop: run ") && !err.contains("stoop: skip"),
        "{err}"
    );
    assert_recorded(&second, &case, key);
    assert_eq!(fs::read(&file).unwrap(), b"done\n");
    let stored = proof(&case, key);
    assert_file_entry(&stored, "inputs", "src/a", b"done\n");
    assert_file_entry(&stored, "priors", "src/a", b"done\n");
    assert_file_entry(&stored, "outputs", "src/a", b"done\n");

    let third = run(&case, key, script, &[]);
    let err = stderr(&third);
    assert!(
        third.status.success() && err.contains("stoop: skip "),
        "{err}"
    );
    assert_eq!(fs::read(&file).unwrap(), b"done\n");
}

#[test]
fn foreign_restore_after_a_hard_link_append_cannot_create_a_skippable_proof() {
    let key = "hard-link-foreign-restore";
    let case = Case::new(key);
    let source = case.file("src/a", b"good\n");
    let alias = case.root().join("src/b");
    fs::hard_link(&source, &alias).unwrap();
    age();
    let fifo = case.fifo("hard-link-restore.fifo");
    let script = "grep -qx good src/a && printf 'added\\n' >> src/b && cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    assert_eq!(fs::read(&alias).unwrap(), b"good\nadded\n");
    fs::write(&source, b"good\n").unwrap();
    drop(release);
    let first = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&alias).unwrap(), b"good\n");
    assert_refused_for(&first, &case, key, &["src/a", "src/b"]);

    let mut retry = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet_if_running(&fifo, &mut retry);
    let reached_fifo = release.is_some();
    drop(release);
    let again = retry.wait_with_output().unwrap();
    let err = stderr(&again);
    assert!(reached_fifo, "retry never reached the FIFO:\n{err}");
    assert!(
        again.status.success() && !err.contains("stoop: skip"),
        "{err}"
    );
    assert_eq!(fs::read(&alias).unwrap(), b"good\nadded\n");
}

#[test]
fn a_converged_direct_write_refuses_and_never_skips() {
    let key = "direct-write-converged";
    let case = Case::new(key);
    let file = case.file("src/a", b"done\n");
    age();
    let script = "cat src/a >/dev/null; printf 'done\\n' > src/a";

    for _ in 0..2 {
        let out = run(&case, key, script, &[]);
        assert_refused_for(&out, &case, key, &["src/a"]);
        assert!(!stderr(&out).contains("stoop: skip"), "{}", stderr(&out));
        assert_eq!(fs::read(&file).unwrap(), b"done\n");
    }
}

#[test]
fn a_foreign_restore_after_a_direct_write_cannot_create_a_skippable_proof() {
    let key = "direct-write-foreign-restore";
    let case = Case::new(key);
    let file = case.file("src/a", b"original\n");
    age();
    let fifo = case.fifo("direct-restore.fifo");
    let script = "cat src/a >/dev/null; printf 'changed\\n' > src/a; cat \"$FIFO\" >/dev/null";
    let child = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet(&fifo);
    assert_eq!(fs::read(&file).unwrap(), b"changed\n");
    fs::write(&file, b"original\n").unwrap();
    drop(release);
    let first = child.wait_with_output().unwrap();
    assert_eq!(fs::read(&file).unwrap(), b"original\n");
    assert_refused_for(&first, &case, key, &["src/a"]);

    let mut retry = spawn(&case, key, script, &[("FIFO", &fifo)]);
    let release = meet_if_running(&fifo, &mut retry);
    let reached_fifo = release.is_some();
    drop(release);
    let again = retry.wait_with_output().unwrap();
    let err = stderr(&again);
    assert!(reached_fifo, "retry never reached the FIFO:\n{err}");
    assert!(
        again.status.success() && !err.contains("stoop: skip"),
        "{err}"
    );
    assert_eq!(fs::read(&file).unwrap(), b"changed\n");
}

fn assert_ran_with_zero_status(out: &Output, key: &str) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains(&format!("stoop: run {key}:")), "{err}");
    assert!(!err.contains(&format!("stoop: skip {key}:")), "{err}");
}

fn assert_unrecorded_run(out: &Output, case: &Case, key: &str) {
    assert_ran_with_zero_status(out, key);
    let err = stderr(out);
    assert!(err.contains("stoop: not recorded:"), "{err}");
    assert!(!case.proof(key).exists(), "unexpected proof:\n{err}");
}

fn assert_skipped_with_zero_status(out: &Output, key: &str) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains(&format!("stoop: skip {key}:")), "{err}");
    assert!(out.stdout.is_empty(), "skipped command produced output");
}

fn assert_removed_name_is_an_input(
    case: &Case,
    key: &str,
    script: &str,
    directory: bool,
    child_input: Option<&str>,
) {
    let first = run(case, key, script, &[]);
    assert_ran_with_zero_status(&first, key);
    assert_recorded(&first, case, key);
    let stored = proof(case, key);
    assert_entry_id(&stored, "inputs", "stage", "a");
    if let Some(path) = child_input {
        assert_entry_id(&stored, "inputs", path, "a");
    }

    let second = run(case, key, script, &[]);
    assert_skipped_with_zero_status(&second, key);

    let stage = case.root().join("stage");
    if directory {
        fs::create_dir(&stage).unwrap();
    } else {
        fs::write(&stage, b"foreign\n").unwrap();
    }
    let third = run(case, key, script, &[]);
    assert_ran_with_zero_status(&third, key);
    assert_eq!(third.stdout, b"replacement observed\n");
}

#[test]
fn metadata_look_after_removing_a_new_file_records_an_absence_input() {
    let key = "removed-file-absence-input";
    let case = Case::new(key);
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "try:\n",
        "    fd = os.open(\"stage\", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n",
        "except FileExistsError:\n",
        "    print(\"replacement observed\")\n",
        "    sys.exit(0)\n",
        "os.write(fd, b\"own\")\n",
        "os.close(fd)\n",
        "os.unlink(\"stage\")\n",
        "if os.path.exists(\"stage\"): sys.exit(21)'",
    );
    assert_removed_name_is_an_input(&case, key, script, false, None);
}

#[test]
fn metadata_look_after_removing_a_new_directory_records_an_absence_input() {
    let key = "removed-directory-absence-input";
    let case = Case::new(key);
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "try:\n",
        "    os.mkdir(\"stage\")\n",
        "except FileExistsError:\n",
        "    print(\"replacement observed\")\n",
        "    sys.exit(0)\n",
        "os.rmdir(\"stage\")\n",
        "if os.path.lexists(\"stage\"): sys.exit(21)'",
    );
    assert_removed_name_is_an_input(&case, key, script, true, None);
}

#[test]
fn metadata_look_after_moving_a_new_directory_records_its_old_name() {
    let key = "moved-directory-absence-input";
    let case = Case::new(key);
    case.file(".stoopignore", b"parked/\n");
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "try:\n",
        "    os.mkdir(\"stage\")\n",
        "except FileExistsError:\n",
        "    print(\"replacement observed\")\n",
        "    sys.exit(0)\n",
        "if os.path.exists(\"stage/tag\"): sys.exit(21)\n",
        "fd = os.open(\"stage/tag\", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n",
        "os.write(fd, b\"tag\")\n",
        "os.close(fd)\n",
        "os.rename(\"stage\", \"parked\")\n",
        "if os.path.lexists(\"stage\"): sys.exit(22)\n",
        "os.mkdir(\"parked/child\")\n",
        "os.stat(\"parked\")\n",
        "fd = os.open(\"parked\", os.O_RDONLY | os.O_DIRECTORY)\n",
        "os.fstat(fd)\n",
        "os.close(fd)'",
    );
    assert_removed_name_is_an_input(&case, key, script, true, Some("stage/tag"));
}

#[test]
fn replacement_before_the_absence_look_refuses_even_if_removed_before_exit() {
    let key = "recreated-before-absence-look";
    let case = Case::new(key);
    let before = case.fifo("before-look.fifo");
    let after = case.fifo("after-look.fifo");
    let env = [("BEFORE", before.as_path()), ("AFTER", after.as_path())];
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "os.mkdir(\"stage\")\n",
        "os.rmdir(\"stage\")\n",
        "open(os.environ[\"BEFORE\"]).read()\n",
        "if not os.path.isdir(\"stage\"): sys.exit(21)\n",
        "print(\"observed replacement\")\n",
        "open(os.environ[\"AFTER\"]).read()'",
    );
    let stage = case.root().join("stage");

    for _ in 0..2 {
        let mut child = spawn(&case, key, script, &env);
        let release = meet_if_running(&before, &mut child).expect("command did not reach look");
        assert!(!stage.exists());
        fs::create_dir(&stage).unwrap();
        drop(release);
        let release = meet_if_running(&after, &mut child).expect("command did not see replacement");
        fs::remove_dir(&stage).unwrap();
        drop(release);
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.stdout, b"observed replacement\n");
        assert_unrecorded_run(&out, &case, key);
    }
}

#[test]
fn replacement_after_the_absence_look_refuses_at_record_time() {
    let key = "recreated-after-absence-look";
    let case = Case::new(key);
    let fifo = case.fifo("after-look.fifo");
    let env = [("FIFO", fifo.as_path())];
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "os.mkdir(\"stage\")\n",
        "os.rmdir(\"stage\")\n",
        "if os.path.lexists(\"stage\"): sys.exit(21)\n",
        "print(\"observed absence\")\n",
        "open(os.environ[\"FIFO\"]).read()'",
    );
    let stage = case.root().join("stage");
    let mut child = spawn(&case, key, script, &env);
    let release = meet_if_running(&fifo, &mut child).expect("command did not reach FIFO");
    assert!(!stage.exists());
    fs::create_dir(&stage).unwrap();
    drop(release);
    let first = child.wait_with_output().unwrap();
    assert_eq!(first.stdout, b"observed absence\n");
    assert!(stage.is_dir());
    assert_unrecorded_run(&first, &case, key);

    fs::remove_dir(&stage).unwrap();
    let mut retry = spawn(&case, key, script, &env);
    let release = meet_if_running(&fifo, &mut retry).expect("unrecorded command skipped");
    drop(release);
    let second = retry.wait_with_output().unwrap();
    assert_eq!(second.stdout, b"observed absence\n");
    assert_ran_with_zero_status(&second, key);
    assert_recorded(&second, &case, key);
    assert_entry_id(&proof(&case, key), "inputs", "stage", "a");

    let mut retry = spawn(&case, key, script, &env);
    let release = meet_if_running(&fifo, &mut retry);
    let reached_fifo = release.is_some();
    drop(release);
    let third = retry.wait_with_output().unwrap();
    assert!(!reached_fifo, "recorded command reached the FIFO");
    assert_skipped_with_zero_status(&third, key);
}

#[test]
fn a_content_open_of_the_removed_name_is_not_an_absence_look() {
    let key = "removed-name-content-open";
    let case = Case::new(key);
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "fd = os.open(\"stage\", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n",
        "os.write(fd, b\"own\")\n",
        "os.close(fd)\n",
        "os.unlink(\"stage\")\n",
        "try:\n",
        "    fd = os.open(\"stage\", os.O_RDONLY)\n",
        "except FileNotFoundError:\n",
        "    print(\"content open failed\")\n",
        "else:\n",
        "    os.close(fd)\n",
        "    sys.exit(21)'",
    );
    for _ in 0..2 {
        let out = run(&case, key, script, &[]);
        assert_eq!(out.stdout, b"content open failed\n");
        assert_unrecorded_run(&out, &case, key);
    }
}

#[test]
fn reading_a_moved_outputs_content_still_refuses_the_record() {
    let key = "moved-output-content-read";
    let case = Case::new(key);
    case.file(".stoopignore", b"parked\n");
    let script = concat!(
        "python3 -c 'import os, sys\n",
        "fd = os.open(\"stage\", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n",
        "os.write(fd, b\"own\")\n",
        "os.close(fd)\n",
        "os.rename(\"stage\", \"parked\")\n",
        "fd = os.open(\"parked\", os.O_RDONLY)\n",
        "data = os.read(fd, 16)\n",
        "os.close(fd)\n",
        "if data != b\"own\": sys.exit(21)\n",
        "if os.path.lexists(\"stage\"): sys.exit(22)\n",
        "print(\"read moved content\")'",
    );
    for _ in 0..2 {
        let out = run(&case, key, script, &[]);
        assert_eq!(out.stdout, b"read moved content\n");
        assert_unrecorded_run(&out, &case, key);
    }
}

#[test]
fn an_absent_name_outside_the_root_remains_untracked() {
    let key = "outside-absence-untracked";
    let case = Case::new(key);
    let outside = case.dir.join("outside-name");
    let env = [("OUTSIDE", outside.as_path())];
    let script = concat!(
        "python3 -c 'import os\n",
        "if os.path.lexists(os.environ[\"OUTSIDE\"]): print(\"outside present\")'",
    );

    let first = run(&case, key, script, &env);
    assert_ran_with_zero_status(&first, key);
    assert_recorded(&first, &case, key);
    let stored = proof(&case, key);
    let inputs = stored["inputs"].as_array().unwrap();
    assert!(
        !inputs
            .iter()
            .any(|input| { input["path"].as_str() == outside.to_str() && input["id"] == "a" }),
        "outside absence was recorded: {inputs:?}"
    );

    let second = run(&case, key, script, &env);
    assert_skipped_with_zero_status(&second, key);
    fs::write(&outside, b"foreign\n").unwrap();
    let third = run(&case, key, script, &env);
    assert_skipped_with_zero_status(&third, key);
}
