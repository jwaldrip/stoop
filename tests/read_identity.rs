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
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::symlink;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
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
    let mut retry = spawn(&case, "t1", script, &[("FIFO", &fifo)]);
    let release = meet_if_running(&fifo, &mut retry);
    assert!(
        release.is_some(),
        "the same command skipped after the refused run"
    );
    drop(release);
    let again = retry.wait_with_output().unwrap();
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
        .args(["sh", "--root"])
        .arg(case.root())
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
fn own_entry_change_after_a_listing_records_for_aged_and_racy_directories() {
    for (key, aged) in [("t7-aged", true), ("t7-racy", false)] {
        let case = Case::new(key);
        case.file("d/x", b"x\n");
        if aged {
            age();
        }
        let debug: &[(&str, &Path)] = &[("STOOP_DEBUG", Path::new("1"))];
        let out = run(&case, key, "ls d >/dev/null; touch d/out", debug);
        assert_recorded(&out, &case, key);
        assert!(
            stderr(&out).contains("stoop: debug: not compared d: OwnEntries"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn a_file_read_then_written_by_the_command_still_records() {
    let case = Case::new("t8");
    case.file("f", b"start\n");
    age();
    let out = run(&case, "t8", "cat f >/dev/null; echo x >> f", &[]);
    assert_recorded(&out, &case, "t8");
    let stored = proof(&case, "t8");
    assert!(stored["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entry| entry["path"] != "f"));
    assert_file_entry(&stored, "priors", "f", b"start\n");
    assert_file_entry(&stored, "outputs", "f", b"start\nx\n");
}

#[test]
fn a_link_replaced_and_restored_during_the_run_is_not_recorded() {
    let case = Case::new("t15b");
    case.file("src/a", b"alpha\n");
    case.file("src/b", b"bravo\n");
    let link = case.root().join("src/link");
    symlink("a", &link).unwrap();
    age();
    let fifo = case.fifo("t15b.fifo");
    let child = spawn(
        &case,
        "t15b",
        "cat src/link >/dev/null; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::remove_file(&link).unwrap();
    symlink("b", &link).unwrap();
    fs::remove_file(&link).unwrap();
    symlink("a", &link).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "t15b",
        "src/link changed while the command ran",
    );
}

#[test]
fn a_read_beneath_a_renamed_directory_is_skipped_as_own_path() {
    let case = Case::new("x1");
    case.file("d/f", b"before\n");
    let out = run(
        &case,
        "x1",
        "cat d/f >/dev/null; mv d e",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "x1");
    assert!(
        stderr(&out).contains("stoop: debug: not compared d/f: OwnPath"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_hard_link_write_skips_the_read_twin_by_inode() {
    let case = Case::new("x2");
    let a = case.file("src/a", b"before\n");
    fs::hard_link(&a, case.root().join("src/b")).unwrap();
    let out = run(
        &case,
        "x2",
        "cat src/a >/dev/null; printf x >> src/b",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "x2");
    assert!(
        stderr(&out).contains("stoop: debug: not compared src/a: OwnInode"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn outside_link_route_is_skipped() {
    let case = Case::new("x4");
    let file = case.outside("real/f", b"before\n");
    let real = file.parent().unwrap();
    let alias = case.dir.join("alias");
    symlink(real, &alias).unwrap();
    let out = run(
        &case,
        "x4",
        "cat \"$ALIAS/f\" >/dev/null; mv \"$REAL/f\" \"$REAL/g\"",
        &[
            ("STOOP_DEBUG", Path::new("1")),
            ("ALIAS", &alias),
            ("REAL", real),
        ],
    );
    assert_recorded(&out, &case, "x4");
    let expected = format!(
        "stoop: debug: not compared {}: Route",
        alias.join("f").display()
    );
    assert!(stderr(&out).contains(&expected), "{}", stderr(&out));
}

#[test]
fn inherited_writable_descriptor_skips_its_inode() {
    let case = Case::new("x5");
    let path = case.file("in.txt", b"before\n");
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    clean(&mut command);
    command
        .args(["run", "--root"])
        .arg(case.root())
        .args([
            "--key",
            "x5",
            "--",
            "sh",
            "-c",
            "cat in.txt >/dev/null; printf x >&3",
        ])
        .current_dir(case.root())
        .env("STOOP_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let source = fd.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().unwrap();
    assert_recorded(&out, &case, "x5");
    assert!(
        stderr(&out).contains("stoop: debug: not compared in.txt: OwnInode"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_read_beneath_an_outside_renamed_directory_is_skipped_as_own_path() {
    let case = Case::new("x6");
    let file = case.outside("d/f", b"before\n");
    let dir = file.parent().unwrap();
    let dest = case.dir.join("outside/e");
    let out = run(
        &case,
        "x6",
        "cat \"$DIR/f\" >/dev/null; mv \"$DIR\" \"$DEST\"",
        &[
            ("STOOP_DEBUG", Path::new("1")),
            ("DIR", dir),
            ("DEST", &dest),
        ],
    );
    assert_recorded(&out, &case, "x6");
    let expected = format!("stoop: debug: not compared {}: OwnPath", file.display());
    assert!(stderr(&out).contains(&expected), "{}", stderr(&out));
}

#[test]
fn an_unobserved_outside_link_target_keeps_v9_behavior() {
    let case = Case::new("x7");
    let outside = case.outside("f", b"before\n");
    symlink(&outside, case.root().join("link")).unwrap();
    let out = run(
        &case,
        "x7",
        "cat link >/dev/null",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "x7");
    let expected = format!(
        "stoop: debug: not compared {}: NotObserved",
        outside.display()
    );
    assert!(stderr(&out).contains(&expected), "{}", stderr(&out));
}

#[test]
fn a_racy_target_reached_through_a_link_is_hashed_at_the_read() {
    let case = Case::new("x9");
    let a = case.file("src/a", b"before\n");
    symlink("src/a", case.root().join("l")).unwrap();
    touch_ahead(&a);
    let out = run(
        &case,
        "x9",
        "cat l >/dev/null",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "x9");
    assert!(
        stderr(&out).contains("stoop: debug: hashed src/a at the read"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn received_descriptor_uncertainty_skips_comparison() {
    let case = Case::new("x8");
    case.file("src/a", b"before\n");
    let out = run(
        &case,
        "x8",
        "cat src/a >/dev/null; python3 -c 'import socket; a,b=socket.socketpair(); a.send(b\"x\"); b.recvmsg(1)'",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "x8");
    assert!(
        stderr(&out).contains("stoop: debug: not compared src/a: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn listing_through_a_symlink_then_creating_an_entry_still_records() {
    let case = Case::new("review-listing-alias");
    case.file("d/old", b"old\n");
    symlink("d", case.root().join("l")).unwrap();
    let out = run(
        &case,
        "review-listing-alias",
        "ls l >/dev/null; echo x > d/new",
        &[],
    );
    assert_recorded(&out, &case, "review-listing-alias");
}

#[test]
fn chmod_of_a_directory_does_not_refuse_an_earlier_descendant_read() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this test requires an unprivileged user"
    );
    let case = Case::new("review-chmod-directory");
    case.file("d/f", b"input\n");
    let out = run(
        &case,
        "review-chmod-directory",
        "cat d/f >/dev/null; chmod 000 d",
        &[],
    );
    fs::set_permissions(case.root().join("d"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_recorded(&out, &case, "review-chmod-directory");
}

#[test]
fn unchanged_stat_visible_unreadable_file_still_records() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this test requires an unprivileged user"
    );
    let case = Case::new("review-unreadable");
    let file = case.file("secret", b"private\n");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    let out = run(&case, "review-unreadable", "stat secret >/dev/null", &[]);
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert_recorded(&out, &case, "review-unreadable");
    assert_entry_id(&proof(&case, "review-unreadable"), "inputs", "secret", "u");
}

fn set_old_atime(path: &Path) -> i128 {
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, UNIX_EPOCH};
    let file = File::open(path).unwrap();
    file.set_times(
        fs::FileTimes::new().set_accessed(UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
    )
    .unwrap();
    let metadata = file.metadata().unwrap();
    i128::from(metadata.atime()) * 1_000_000_000 + i128::from(metadata.atime_nsec())
}

#[test]
fn read_probe_does_not_change_the_atime_seen_by_the_tracee() {
    let case = Case::new("review-file-atime");
    let file = case.file("src/a", b"payload\n");
    let before = set_old_atime(&file);
    let out = run(
        &case,
        "review-file-atime",
        "python3 -c 'import os; fd=os.open(\"src/a\",os.O_RDONLY); print(os.fstat(fd).st_atime_ns)' > seen",
        &[],
    );
    assert_recorded(&out, &case, "review-file-atime");
    let observed = fs::read_to_string(case.root().join("seen")).unwrap();
    assert_eq!(observed.trim(), before.to_string());
}

#[test]
fn listing_probe_does_not_change_directory_atime_seen_by_the_tracee() {
    let case = Case::new("review-directory-atime");
    case.file("d/x", b"x\n");
    let before = set_old_atime(&case.root().join("d"));
    let out = run(
        &case,
        "review-directory-atime",
        "python3 -c 'import os; fd=os.open(\"d\",os.O_RDONLY|os.O_DIRECTORY|os.O_NOATIME); os.listdir(fd); print(os.fstat(fd).st_atime_ns)' > seen",
        &[],
    );
    assert_recorded(&out, &case, "review-directory-atime");
    let observed = fs::read_to_string(case.root().join("seen")).unwrap();
    assert_eq!(observed.trim(), before.to_string());
}

#[test]
fn read_only_proc_descriptor_reopen_does_not_hide_an_external_edit() {
    let case = Case::new("review-proc-readonly");
    let file = case.file("src/a", b"old\n");
    age();
    let fifo = case.fifo("review-proc-readonly.fifo");
    let child = spawn(
        &case,
        "review-proc-readonly",
        "exec 3<src/a; cat /proc/self/fd/3 >/dev/null; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(file, b"new and longer\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-proc-readonly",
        "src/a changed while the command ran",
    );
}

#[test]
fn writable_reopen_of_an_inherited_unlinked_descriptor_keeps_v9_recording() {
    let case = Case::new("review-unlinked-fd");
    let a = case.file("a", b"before\n");
    fs::hard_link(&a, case.root().join("b")).unwrap();
    let fd = OpenOptions::new().read(true).open(&a).unwrap();
    fs::remove_file(a).unwrap();
    let source = fd.as_raw_fd();
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    clean(&mut command);
    command
        .args(["run", "--root"])
        .arg(case.root())
        .args([
            "--key",
            "review-unlinked-fd",
            "--",
            "sh",
            "-c",
            "cat b >/dev/null; : > /proc/self/fd/3",
        ])
        .current_dir(case.root())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = command.output().unwrap();
    assert_recorded(&out, &case, "review-unlinked-fd");
}

#[test]
#[ignore = "requires sudo mount --bind on an isolated Linux CI runner"]
fn bind_mount_entry_change_does_not_refuse_the_original_listing() {
    struct Mount(PathBuf);
    impl Drop for Mount {
        fn drop(&mut self) {
            let _ = Command::new("sudo").arg("umount").arg(&self.0).status();
        }
    }
    let case = Case::new("review-bind-mount");
    case.file("d/old", b"old\n");
    let alias = case.dir.join("alias");
    fs::create_dir(&alias).unwrap();
    assert!(Command::new("sudo")
        .args(["mount", "--bind"])
        .arg(case.root().join("d"))
        .arg(&alias)
        .status()
        .unwrap()
        .success());
    let mount = Mount(alias.clone());
    let out = run(
        &case,
        "review-bind-mount",
        "ls d >/dev/null; echo x > \"$ALIAS/new\"",
        &[("ALIAS", &alias)],
    );
    drop(mount);
    assert_recorded(&out, &case, "review-bind-mount");
}

#[test]
fn overlapping_symlink_retarget_and_blocked_write_skip_comparison() {
    let case = Case::new("review-overlap");
    case.file("src/b", b"before\n");
    let blocked = case.fifo("review-blocked.fifo");
    let sync = case.fifo("review-sync.fifo");
    symlink(&blocked, case.root().join("src/link")).unwrap();
    let child = spawn(
        &case,
        "review-overlap",
        "cat src/b >/dev/null; (exec 4>src/link) & sleep 1; ln -sfn b src/link; cat \"$SYNC\" >/dev/null; wait",
        &[("SYNC", &sync), ("STOOP_DEBUG", Path::new("1"))],
    );
    let release = meet(&sync);
    let reader = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&blocked)
        .unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    drop(reader);
    assert_recorded(&out, &case, "review-overlap");
    assert!(
        stderr(&out).contains("stoop: debug: not compared src/b: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn fchmod_of_a_directory_does_not_refuse_an_earlier_descendant_read() {
    use std::os::unix::fs::PermissionsExt;
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let case = Case::new("review-fchmod-directory");
    case.file("d/f", b"input\n");
    let out = run(
        &case,
        "review-fchmod-directory",
        "cat d/f >/dev/null; python3 -c 'import os; fd=os.open(\"d\",os.O_RDONLY|os.O_DIRECTORY); os.fchmod(fd,0)'",
        &[],
    );
    fs::set_permissions(case.root().join("d"), fs::Permissions::from_mode(0o700)).unwrap();
    assert_recorded(&out, &case, "review-fchmod-directory");
}

#[test]
fn owner_change_of_a_directory_excludes_descendants() {
    let case = Case::new("review-owner-directory");
    case.file("d/f", b"input\n");
    let out = run(
        &case,
        "review-owner-directory",
        "cat d/f >/dev/null; python3 -c 'import os; fd=os.open(\"d\",os.O_RDONLY|os.O_DIRECTORY); os.fchown(fd,os.getuid(),os.getgid())'",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-owner-directory");
    assert!(
        stderr(&out).contains("stoop: debug: not compared d/f: OwnPath"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn read_only_proc_cwd_alias_does_not_hide_an_external_edit() {
    let case = Case::new("review-proc-cwd");
    let file = case.file("src/a", b"old\n");
    age();
    let fifo = case.fifo("review-proc-cwd.fifo");
    let child = spawn(
        &case,
        "review-proc-cwd",
        "cat src/a >/dev/null; cat /proc/self/cwd/src/a >/dev/null; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(file, b"new and longer\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-proc-cwd",
        "src/a changed while the command ran",
    );
}
#[test]
fn inherited_readonly_unlinked_descriptor_does_not_hide_external_edit() {
    let case = Case::new("review-inherited-readonly");
    let a = case.file("a", b"before\n");
    let b = case.root().join("b");
    fs::hard_link(&a, &b).unwrap();
    let fd = OpenOptions::new().read(true).open(&a).unwrap();
    fs::remove_file(a).unwrap();
    let source = fd.as_raw_fd();
    let fifo = case.fifo("inherited-readonly.fifo");
    let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
    clean(&mut command);
    command
        .args(["run", "--root"])
        .arg(case.root())
        .args(["--key", "review-inherited-readonly", "--", "sh", "-c"])
        .arg("cat b >/dev/null; cat \"$FIFO\" >/dev/null")
        .current_dir(case.root())
        .env("FIFO", &fifo)
        .env("STOOP_DEBUG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(source, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let release = meet(&fifo);
    fs::write(b, b"changed externally\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-inherited-readonly",
        "b changed while the command ran",
    );
}

#[test]
fn writable_proc_reopen_of_descriptor_unlinked_after_start_excludes_inode() {
    let case = Case::new("review-late-unlinked-fd");
    let a = case.file("a", b"before\n");
    fs::hard_link(&a, case.root().join("b")).unwrap();
    let fifo = case.fifo("late-unlinked-fd.fifo");
    let child = spawn(
        &case,
        "review-late-unlinked-fd",
        "exec 3<a; cat b >/dev/null; cat \"$FIFO\" >/dev/null; : > /proc/self/fd/3",
        &[("FIFO", &fifo), ("STOOP_DEBUG", Path::new("1"))],
    );
    let release = meet(&fifo);
    fs::remove_file(a).unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_recorded(&out, &case, "review-late-unlinked-fd");
    assert!(stderr(&out).contains("stoop: debug: not compared b: OwnInode"));
}

#[test]
fn listed_directory_alias_candidates_both_exclude_own_entries() {
    let case = Case::new("review-listing-alias-debug");
    case.file("d/old", b"old\n");
    symlink("d", case.root().join("l")).unwrap();
    let out = run(
        &case,
        "review-listing-alias-debug",
        "ls l >/dev/null; echo x > d/new",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-listing-alias-debug");
    let log = stderr(&out);
    assert!(
        log.matches("stoop: debug: not compared d: OwnEntries")
            .count()
            >= 2,
        "{log}"
    );
}

#[test]
fn missing_parent_write_does_not_hide_external_edit() {
    let case = Case::new("review-missing-parent");
    let file = case.file("input", b"before\n");
    let fifo = case.fifo("missing-parent.fifo");
    let child = spawn(
        &case,
        "review-missing-parent",
        "cat input >/dev/null; python3 -c 'import os; p=\"target/a/b\"; exec(\"try:\\n os.mkdir(p)\\nexcept FileNotFoundError:\\n os.makedirs(p)\")'; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(file, b"changed externally\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-missing-parent",
        "input changed while the command ran",
    );
}

#[test]
fn concurrent_symlink_creation_skips_comparison() {
    let case = Case::new("review-symlink-create");
    case.file("input", b"before\n");
    let out = run(
        &case,
        "review-symlink-create",
        "cat input >/dev/null; sleep 1 & ln -s input link; wait",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-symlink-create");
    assert!(
        stderr(&out).contains("stoop: debug: not compared input: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
#[ignore = "requires sudo mount --bind on an isolated Linux CI runner"]
fn chmod_directory_through_bind_alias_keeps_v9_recording() {
    use std::os::unix::fs::PermissionsExt;
    struct Mount(PathBuf);
    impl Drop for Mount {
        fn drop(&mut self) {
            let _ = Command::new("sudo").arg("umount").arg(&self.0).status();
        }
    }
    let case = Case::new("review-bind-chmod");
    case.file("d/f", b"input\n");
    let alias = case.dir.join("alias");
    fs::create_dir(&alias).unwrap();
    assert!(Command::new("sudo")
        .args(["mount", "--bind"])
        .arg(case.root().join("d"))
        .arg(&alias)
        .status()
        .unwrap()
        .success());
    let mount = Mount(alias.clone());
    let out = run(
        &case,
        "review-bind-chmod",
        "cat d/f >/dev/null; chmod 000 \"$ALIAS\"",
        &[("ALIAS", &alias)],
    );
    fs::set_permissions(case.root().join("d"), fs::Permissions::from_mode(0o700)).unwrap();
    drop(mount);
    assert_recorded(&out, &case, "review-bind-chmod");
}

#[test]
fn concurrent_symlink_rename_skips_comparison() {
    let case = Case::new("review-symlink-rename");
    case.file("input", b"before\n");
    symlink("input", case.root().join("link")).unwrap();
    let out = run(
        &case,
        "review-symlink-rename",
        "cat input >/dev/null; sleep 1 & mv -T link other; wait",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-symlink-rename");
    assert!(
        stderr(&out).contains("stoop: debug: not compared input: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn concurrent_symlink_source_hard_link_skips_comparison() {
    let case = Case::new("review-symlink-source-link");
    case.file("input", b"before\n");
    symlink("input", case.root().join("source")).unwrap();
    let out = run(
        &case,
        "review-symlink-source-link",
        "cat input >/dev/null; sleep 1 & python3 -c 'import os; os.link(\"source\", \"other\", follow_symlinks=False)'; wait",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-symlink-source-link");
    assert!(
        stderr(&out).contains("stoop: debug: not compared input: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn hard_link_of_a_regular_file_with_a_live_task_keeps_comparison() {
    let case = Case::new("review-regular-hard-link");
    let input = case.file("input", b"before\n");
    case.file("source", b"source\n");
    let fifo = case.fifo("regular-hard-link.fifo");
    let child = spawn(
        &case,
        "review-regular-hard-link",
        "cat input >/dev/null; sleep 2 & ln source other; cat \"$FIFO\" >/dev/null; wait",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(input, b"changed externally\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-regular-hard-link",
        "input changed while the command ran",
    );
}

#[test]
fn a_directory_rename_without_a_hard_link_keeps_comparison() {
    let case = Case::new("review-rename-only");
    let input = case.file("input", b"before\n");
    case.file("d/x", b"x\n");
    let fifo = case.fifo("rename-only.fifo");
    let child = spawn(
        &case,
        "review-rename-only",
        "cat input >/dev/null; mv d e; cat \"$FIFO\" >/dev/null",
        &[("FIFO", &fifo)],
    );
    let release = meet(&fifo);
    fs::write(input, b"changed externally\n").unwrap();
    drop(release);
    let out = child.wait_with_output().unwrap();
    assert_not_recorded(
        &out,
        &case,
        "review-rename-only",
        "input changed while the command ran",
    );
}

#[test]
fn a_directory_rename_and_a_hard_link_in_one_run_skip_comparison() {
    let case = Case::new("review-rename-link");
    case.file("input", b"before\n");
    case.file("d/x", b"x\n");
    case.file("source", b"source\n");
    let out = run(
        &case,
        "review-rename-link",
        "cat input >/dev/null; sleep 1 & ln source other; mv d e; wait",
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-rename-link");
    assert!(
        stderr(&out).contains("stoop: debug: not compared input: Unknown"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_directory_exchange_and_a_hard_link_in_one_run_skip_comparison() {
    let case = Case::new("review-exchange-link");
    case.file("input", b"before\n");
    case.file("left/x", b"x\n");
    case.file("right/y", b"y\n");
    case.file("source", b"source\n");
    let exchange = "python3 -c 'import ctypes; libc = ctypes.CDLL(None, use_errno=True); raise SystemExit(libc.renameat2(-100, b\"left\", -100, b\"right\", 2))'";
    let out = run(
        &case,
        "review-exchange-link",
        &format!("cat input >/dev/null; sleep 1 & ln source other; {exchange}; wait"),
        &[("STOOP_DEBUG", Path::new("1"))],
    );
    assert_recorded(&out, &case, "review-exchange-link");
    assert!(
        stderr(&out).contains("stoop: debug: not compared input: Unknown"),
        "{}",
        stderr(&out)
    );
}
