use super::*;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    local: PathBuf,
    remote: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "stoop-bounded-sync-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let local = root.join("local");
        let remote = root.join("remote.git");
        fs::create_dir_all(&local).unwrap();
        fs::create_dir_all(&remote).unwrap();
        let fixture = Self {
            root,
            local,
            remote,
        };
        fixture.git(&fixture.local, &["init", "-q"]);
        fixture.git(&fixture.remote, &["init", "--bare", "-q"]);
        fixture.git(
            &fixture.local,
            &["remote", "add", "origin", fixture.remote.to_str().unwrap()],
        );
        fixture
    }

    fn command(&self, dir: &Path) -> Command {
        let mut command = Command::new("git");
        command
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_ATTR_SOURCE");
        command
    }

    fn git(&self, dir: &Path, args: &[&str]) -> Vec<u8> {
        let output = self.command(dir).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "git fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    fn blob(&self, bytes: &[u8]) -> String {
        let file = self.root.join("blob");
        fs::write(&file, bytes).unwrap();
        String::from_utf8(self.git(&self.remote, &["hash-object", "-w", file.to_str().unwrap()]))
            .unwrap()
            .trim()
            .to_owned()
    }

    fn update(&self, name: &str, oid: &str) {
        self.git(&self.remote, &["update-ref", name, oid]);
    }

    fn client(&self) -> Remote {
        Remote::from_spec("git", &self.local, false).unwrap()
    }

    fn script(&self, name: &str, contents: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn uploadpack(&self, script: &Path) {
        let quoted = shell_quote(script);
        self.git(
            &self.local,
            &["config", "remote.origin.uploadpack", &quoted],
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn wait_until_gone(pid: &str) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let output = Command::new("ps")
            .args(["-o", "stat=", "-p", pid])
            .output()
            .unwrap();
        let state = String::from_utf8_lossy(&output.stdout);
        if state.trim().is_empty() || state.trim().starts_with('Z') {
            return;
        }
        assert!(Instant::now() < until, "child still alive: {pid}");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn listing_counts_tail_matches_and_caps_bytes_before_parsing() {
    let fixture = Fixture::new();
    let oid = fixture.blob(b"proof");
    fixture.update("refs/stoop/a", &oid);
    fixture.update("refs/stoop/b", &oid);
    fixture.update("refs/tags/x/refs/stoop/c", &oid);
    let listing = fixture.git(
        &fixture.local,
        &["ls-remote", "--", "origin", "refs/stoop/*"],
    );
    assert_eq!(listing.iter().filter(|b| **b == b'\n').count(), 3);
    // The byte-level parser also handles remote names that the host filesystem
    // may not permit as local Git ref filenames.
    let mut non_utf8_listing = listing.clone();
    non_utf8_listing.extend_from_slice(oid.as_bytes());
    non_utf8_listing.extend_from_slice(b"\trefs/heads/\xff/refs/stoop/d\n");
    assert_eq!(parse_listing(&non_utf8_listing, 4).unwrap().len(), 2);
    assert_eq!(
        parse_listing(&non_utf8_listing, 3),
        Err(Failure::ListingRefs(3))
    );
    let client = fixture.client();
    let mut limits = Limits::PLAN;
    limits.listing_bytes = listing.len() as u64;
    limits.refs = 3;
    let snapshot = client.snapshot(limits).unwrap();
    assert_eq!(snapshot.len(), 2);
    assert!(snapshot.contains("refs/stoop/a"));
    assert!(snapshot.contains("refs/stoop/b"));
    limits.refs = 2;
    assert_eq!(
        client.snapshot(limits).err().unwrap(),
        Failure::ListingRefs(2).to_string()
    );
    limits.refs = 3;
    limits.listing_bytes -= 1;
    assert_eq!(
        client.snapshot(limits).err().unwrap(),
        Failure::ListingBytes(limits.listing_bytes).to_string()
    );
}

#[test]
fn malformed_listings_are_rejected_without_echoing_their_contents() {
    let oid = "a".repeat(40);
    assert_eq!(parse_listing(b"broken\n", 10), Err(Failure::Listing));
    assert_eq!(
        parse_listing(format!("{oid}\trefs/stoop/a").as_bytes(), 10),
        Err(Failure::Listing)
    );
    assert_eq!(
        parse_listing(
            format!("{oid}\trefs/stoop/a\n{oid}\trefs/stoop/a\n").as_bytes(),
            10
        ),
        Err(Failure::Listing)
    );
    assert_eq!(
        parse_listing(format!("{oid}\trefs/stoop/a\r\n").as_bytes(), 10),
        Err(Failure::Listing)
    );
    assert_eq!(
        parse_listing(format!("{}\trefs/stoop/a\n", "A".repeat(40)).as_bytes(), 10),
        Err(Failure::Listing)
    );
    let non_stoop = [oid.as_bytes(), b"\trefs/heads/\xff/refs/stoop/x\n"].concat();
    assert!(parse_listing(&non_stoop, 1).unwrap().is_empty());
}

#[test]
fn blob_and_total_budgets_are_shared_across_fetches() {
    let fixture = Fixture::new();
    let oid = fixture.blob(&[b'x'; 100]);
    fixture.update("refs/stoop/a", &oid);
    fixture.update("refs/stoop/b", &oid);
    let client = fixture.client();
    let names = ["refs/stoop/a".to_owned(), "refs/stoop/b".to_owned()];
    let mut limits = Limits::PLAN;
    limits.blob_bytes = 99;
    let snapshot = client.snapshot(limits).unwrap();
    let mut called = false;
    assert_eq!(
        snapshot.fetch(&names[..1], |_, _| {
            called = true;
            Ok(())
        }),
        Err(Failure::BlobBytes(99).to_string())
    );
    assert!(!called);

    limits.blob_bytes = 100;
    limits.total_bytes = 150;
    let snapshot = client.snapshot(limits).unwrap();
    snapshot
        .fetch(&names[..1], |_, bytes| {
            assert_eq!(bytes.len(), 100);
            Ok(())
        })
        .unwrap();
    assert_eq!(
        snapshot.fetch(&names[1..], |_, _| {
            called = true;
            Ok(())
        }),
        Err(Failure::TotalBytes(150).to_string())
    );
    assert!(!called);

    limits.total_bytes = 200;
    let snapshot = client.snapshot(limits).unwrap();
    let mut count = 0;
    for name in &names {
        snapshot
            .fetch(std::slice::from_ref(name), |_, bytes| {
                assert_eq!(bytes.len(), 100);
                count += 1;
                Ok(())
            })
            .unwrap();
    }
    assert_eq!(count, 2);
}

#[test]
fn deadline_is_not_reset_after_listing() {
    let fixture = Fixture::new();
    let oid = fixture.blob(b"proof");
    fixture.update("refs/stoop/a", &oid);
    let count = fixture.root.join("count");
    let script = fixture.script(
        "count-uploadpack",
        &format!(
            "#!/bin/sh\nprintf x >> {}\nexec git-upload-pack \"$@\"\n",
            shell_quote(&count)
        ),
    );
    fixture.uploadpack(&script);
    let client = fixture.client();
    let limits = Limits {
        deadline: Duration::from_secs(1),
        ..Limits::PLAN
    };
    let snapshot = client.snapshot(limits).unwrap();
    thread::sleep(Duration::from_millis(1100));
    assert_eq!(
        snapshot.fetch(&["refs/stoop/a".into()], |_, _| Ok(())),
        Err(Failure::Deadline(limits.deadline).to_string())
    );
    assert_eq!(fs::read(count).unwrap(), b"x");
    let local_ref = fixture
        .command(&fixture.local)
        .args(["rev-parse", "--verify", "refs/stoop/a"])
        .output()
        .unwrap();
    assert!(!local_ref.status.success());
}

#[test]
fn deadline_terminates_stalled_process_group() {
    let fixture = Fixture::new();
    let pid_path = fixture.root.join("stall-pid");
    let script = fixture.script(
        "stall-uploadpack",
        &format!(
            "#!/bin/sh\necho $$ > {}\nexec sleep 30\n",
            shell_quote(&pid_path)
        ),
    );
    fixture.uploadpack(&script);
    let client = fixture.client();
    let limits = Limits {
        deadline: Duration::from_secs(1),
        ..Limits::PLAN
    };
    let start = Instant::now();
    assert_eq!(
        client.snapshot(limits).err().unwrap(),
        Failure::Deadline(limits.deadline).to_string()
    );
    assert!(start.elapsed() < Duration::from_secs(10));
    let pid = fs::read_to_string(pid_path).unwrap();
    wait_until_gone(pid.trim());
}

#[test]
fn exited_leader_with_inherited_stdout_cannot_block_the_caller() {
    let fixture = Fixture::new();
    let pid_path = fixture.root.join("inherited-pid");
    let script = fixture.script(
        "hold-output",
        &format!(
            "#!/bin/sh\nsleep 30 &\necho $! > {}\nexit 0\n",
            shell_quote(&pid_path)
        ),
    );
    let alias = format!("alias.hold=!{}", shell_quote(&script));
    let client = fixture.client();
    let duration = Duration::from_secs(1);
    let start = Instant::now();
    let result = run_git(
        &client,
        Operation::LsRemote,
        start + duration,
        duration,
        &["-c", &alias, "hold"],
        (false, true),
        |_, output| {
            let mut bytes = Vec::new();
            output
                .unwrap()
                .read_to_end(&mut bytes)
                .map_err(|_| Failure::Output(Operation::LsRemote).to_string())?;
            Ok(())
        },
    );
    assert_eq!(result, Err(Failure::Deadline(duration).to_string()));
    assert!(start.elapsed() < Duration::from_secs(10));
    let pid = fs::read_to_string(pid_path).unwrap();
    wait_until_gone(pid.trim());
}

#[test]
fn remote_and_legacy_errors_never_disclose_credentials() {
    let fixture = Fixture::new();
    let marker = "STOOPMARK";
    let remote = Remote::from_spec(
        "git:file:///nonexistent/stoop?token=STOOPMARK",
        &fixture.local,
        false,
    )
    .unwrap();
    assert_eq!(
        remote.snapshot(Limits::PLAN).err().unwrap(),
        Failure::Exit(Operation::LsRemote, 128).to_string()
    );
    assert!(!remote
        .pull_job("job-missing")
        .err()
        .unwrap()
        .contains(marker));
    assert_eq!(
        Remote::from_spec("https://u:STOOPMARK@x", &fixture.local, false)
            .err()
            .unwrap(),
        "unknown sync backend; use `git` or `git:<remote>`"
    );
}

#[test]
fn large_batch_is_read_in_request_order_without_pipe_deadlock() {
    let fixture = Fixture::new();
    let oid = fixture.blob(b"one");
    let names: Vec<String> = (0..4000).map(|i| format!("refs/stoop/sh-{i:04}")).collect();
    let mut child = fixture
        .command(&fixture.remote)
        .args(["update-ref", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut input = child.stdin.take().unwrap();
        for name in &names {
            writeln!(input, "update {name} {oid}").unwrap();
        }
    }
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let client = fixture.client();
    let snapshot = client.snapshot(Limits::PLAN).unwrap();
    assert_eq!(snapshot.len(), names.len());
    let mut index = 0;
    snapshot
        .fetch(&names, |name, bytes| {
            assert_eq!(name, names[index]);
            assert_eq!(bytes, b"one");
            index += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(index, names.len());
}
