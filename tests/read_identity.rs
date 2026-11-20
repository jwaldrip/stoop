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
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

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
fn the_commands_own_entries_in_a_listed_directory_do_not_refuse_the_record() {
    let case = Case::new("t7-aged");
    case.file("d/x", b"x\n");
    age();
    let out = run(&case, "t7-aged", "ls d >/dev/null; touch d/out", &[]);
    assert_recorded(&out, &case, "t7-aged");

    let case = Case::new("t7-racy");
    case.file("d/x", b"x\n");
    let out = run(&case, "t7-racy", "ls d >/dev/null; touch d/out", &[]);
    assert_recorded(&out, &case, "t7-racy");
}

#[test]
fn a_file_read_then_written_by_the_command_still_records() {
    let case = Case::new("t8");
    case.file("f", b"start\n");
    age();
    let out = run(&case, "t8", "cat f >/dev/null; echo x >> f", &[]);
    assert_recorded(&out, &case, "t8");
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
fn a_link_hop_the_command_replaces_does_not_refuse_its_reader() {
    // src/link1 leads through src/link2 to src/a. The command replaces src/link2 itself, so the
    // change of target is its own, and the record of the reader stands.
    let case = Case::new("t17-own-hop");
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    symlink("a", case.root().join("src/link2")).unwrap();
    symlink("link2", case.root().join("src/link1")).unwrap();
    age();
    let script = "cat src/link1 >/dev/null; ln -s b src/link2.new && mv -f src/link2.new src/link2";
    let out = run(&case, "t17-own-hop", script, &[]);
    assert_recorded(&out, &case, "t17-own-hop");
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
    assert_recorded(&out, &case, "t18-own-dangling");
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
fn a_write_through_an_alias_inside_the_root_records_the_real_path() {
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
fn a_hard_link_name_the_command_writes_is_recorded() {
    // The command reads src/a, then writes src/b, which is the same inode. The write is the
    // command's own change, so the record stands.
    let case = Case::new("t20-hard-link");
    let a = case.file("src/a", b"alpha-one\n");
    fs::hard_link(&a, case.root().join("src/b")).unwrap();
    age();
    let script = "cat src/a >/dev/null; printf 'bravo-two\\n' > src/b";
    let out = run(&case, "t20-hard-link", script, &[]);
    assert_recorded(&out, &case, "t20-hard-link");
}

#[test]
fn a_file_the_command_overwrites_and_reads_back_still_records() {
    // The command's own write is its output, so its read back of the file is not an input.
    let case = Case::new("t21-read-back");
    case.file("src/f", b"start\n");
    age();
    let out = run(
        &case,
        "t21-read-back",
        "echo fresh > src/f; cat src/f >/dev/null",
        &[],
    );
    assert_recorded(&out, &case, "t21-read-back");
}

#[test]
fn a_write_through_an_alias_read_back_through_the_real_path_records() {
    // The command creates real/x through an alias and then reads it through its real path. The
    // created file is the command's own output, so the read back is not an outside change.
    let case = Case::new("t19-own-readback");
    case.file("src/keep", b"keep\n");
    fs::create_dir_all(case.root().join("real")).unwrap();
    symlink("real", case.root().join("alias")).unwrap();
    let script = "test -e real/x; echo made > alias/x; cat real/x >/dev/null";
    let out = run(&case, "t19-own-readback", script, &[]);
    assert_recorded(&out, &case, "t19-own-readback");
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
        "changed while the command ran",
    );
}
