//! Helpers for the hook-fixture tests: a throwaway suite (the fake runner in `fixtures/hook/t`
//! and a small tree), the stoop CLI with a clean environment, and a reader for the runner's log.
#![allow(dead_code)]

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

/// The hook every pin uses. Its inline filter is the roster; the full form runs the runner with no arguments.
pub const HOOK: &str = "{changed:**/*.t|!slow/**}";

/// The roster the tree yields for `HOOK`: every `*.t` outside `slow/`.
pub const ROSTER: [&str; 3] = ["tests/a.t", "tests/b.t", "tests/c.t"];

const RUNNER: &str = include_str!("../fixtures/hook/t");

/// Group only the seeded model subjects when explicitly requested.
pub fn model_group_enabled() -> bool {
    std::env::var("STOOP_MODEL_GROUP").is_ok_and(|value| value == "1")
}

pub fn model_subject_env<'a>(env: &[(&'a str, &'a str)], grouped: bool) -> Vec<(&'a str, &'a str)> {
    let mut subject_env = env.to_vec();
    if grouped {
        subject_env.push(("STOOP_SPLIT_GROUP", "1"));
    }
    subject_env
}

/// Keep the empty full-run record while separating grouped unit arguments.
pub fn model_launch_units(launches: &[String], grouped: bool) -> Vec<String> {
    if grouped {
        launches
            .iter()
            .flat_map(|launch| launch.split(' ').map(str::to_owned))
            .collect()
    } else {
        launches.to_vec()
    }
}

#[derive(Default)]
pub struct ModelGroupTally {
    grouped_launches: usize,
    inexact_versions_written: usize,
    root: Option<PathBuf>,
    versions: BTreeMap<String, Vec<Value>>,
}

/// Resolve delta-encoded table indices before comparing versions, since table compaction can renumber them.
fn model_version(version: &Value, table: &[Value]) -> Value {
    let mut version = version.clone();
    for field in ["inputs", "outputs"] {
        let mut index = 0usize;
        let mut inputs: Vec<Value> = version[field]
            .as_array()
            .expect("version indices")
            .iter()
            .map(|delta| {
                index += delta.as_u64().expect("version index") as usize;
                table.get(index).expect("version table entry").clone()
            })
            .collect();
        inputs.sort_by_key(Value::to_string);
        version[field] = Value::Array(inputs);
    }
    version
}

impl ModelGroupTally {
    /// Count grouped launches and newly observed inexact member versions, not unchanged versions seen again.
    pub fn record(&mut self, s: &Suite, launches: &[String]) {
        if self.root.as_ref() != Some(&s.root) {
            self.root = Some(s.root.clone());
            self.versions.clear();
        }
        let groups: Vec<Vec<&str>> = launches
            .iter()
            .map(|launch| launch.split(' ').collect())
            .filter(|members: &Vec<&str>| members.len() > 1)
            .collect();
        self.grouped_launches += groups.len();
        let members: BTreeSet<&str> = groups.into_iter().flatten().collect();
        let versions = s.bundle().map_or_else(BTreeMap::new, |bundle| {
            let table = bundle["table"].as_array().expect("bundle table");
            bundle["units"]
                .as_object()
                .expect("bundle units")
                .iter()
                .map(|(unit, versions)| {
                    let inexact = versions
                        .as_array()
                        .expect("unit versions")
                        .iter()
                        .filter(|version| version["exact"].as_bool() == Some(false))
                        .map(|version| model_version(version, table))
                        .collect();
                    (unit.clone(), inexact)
                })
                .collect()
        });
        for (unit, inexact) in &versions {
            if members.contains(unit.as_str()) && self.versions.get(unit) != Some(inexact) {
                self.inexact_versions_written += inexact.len();
            }
        }
        self.versions = versions;
    }

    pub fn summary(&self, grouped: bool) -> String {
        if grouped {
            format!(
                ", grouped launches: {}, inexact versions written (observed lower bound): {}",
                self.grouped_launches, self.inexact_versions_written
            )
        } else {
            String::new()
        }
    }
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// Writing an executable and spawning a child must not overlap. A child forked while a
/// writer's descriptor is open inherits it, and exec of that file then fails with `ETXTBSY`
/// until the child exits. Writers take the write side around the write, which closes the
/// file before the lock is released. Every spawn takes the read side, which returns once the
/// child has exec'd (Rust's `spawn` reports exec failure through a close-on-exec pipe).
static EXEC: RwLock<()> = RwLock::new(());

pub fn spawning<T>(spawn: impl FnOnce() -> T) -> T {
    let _guard = EXEC.read().unwrap_or_else(|poisoned| poisoned.into_inner());
    spawn()
}

/// A suite under the system temporary folder: `root/` holds the runner and tree, `outside/`
/// holds the log and FIFOs. Paths under the root are root-relative, so `/tmp` ignores never apply.
pub struct Suite {
    pub root: PathBuf,
    pub outside: PathBuf,
    pub log: PathBuf,
    base: PathBuf,
}

impl Suite {
    pub fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "stoop-units-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&base);
        let suite = Suite {
            root: base.join("root"),
            outside: base.join("outside"),
            log: base.join("outside/log"),
            base,
        };
        fs::create_dir_all(&suite.root).unwrap();
        fs::create_dir_all(&suite.outside).unwrap();
        suite.executable("t", RUNNER);
        suite.executable("lint", "#!/bin/sh\nexit 0\n");
        suite.write("tests/a.t", "src/shared.src\n");
        suite.write("tests/b.t", "src/shared.src\n");
        suite.write("tests/c.t", "src/c.src\n");
        suite.write("e2e/x.u", "src/shared.src\n");
        suite.write("slow/s.t", "src/c.src\n");
        suite.write("setup.src", "setup\n");
        suite.write("src/shared.src", "shared\n");
        suite.write("src/c.src", "c\n");
        suite.write("src/dead.src", "dead\n");
        suite.write("docs/readme.md", "docs\n");
        suite
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    /// Write a root-relative file, creating its folders.
    pub fn write(&self, rel: &str, body: &str) {
        let path = self.root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    /// Write a root-relative file that is executable, as the runner and `lint` must be.
    pub fn executable(&self, rel: &str, body: &str) {
        let _guard = EXEC
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.write(rel, body);
        fs::set_permissions(self.root.join(rel), fs::Permissions::from_mode(0o755)).unwrap();
    }

    pub fn remove(&self, rel: &str) {
        fs::remove_file(self.root.join(rel)).unwrap();
    }

    /// Write `.stoop.toml` at the root.
    pub fn config(&self, toml: &str) {
        self.write(".stoop.toml", toml);
    }

    /// Make the root a Git repository on `branch`, committing everything in it.
    pub fn git(&self, branch: &str) {
        let run = |args: &[&str]| {
            let status = spawning(|| {
                Command::new("git")
                    .current_dir(&self.root)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &self.outside)
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .args(args)
                    .status()
            })
            .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        run(&["init", "-q"]);
        run(&["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")]);
        run(&["add", "-A"]);
        run(&[
            "-c",
            "user.name=stoop",
            "-c",
            "user.email=stoop@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        ]);
    }

    /// Set a root-relative file's modification time to 2000-01-01, so it is older than any run.
    pub fn age(&self, rel: &str) {
        let status = spawning(|| {
            Command::new("touch")
                .args(["-t", "200001010000"])
                .arg(self.root.join(rel))
                .status()
        })
        .unwrap();
        assert!(status.success(), "touch {rel}");
    }

    /// The stoop CLI in `cwd` with a clean environment: only the variables this suite sets.
    pub fn stoop(&self, cwd: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .current_dir(cwd)
            .stdin(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.outside)
            .env("LOG", &self.log)
            .env("STOOP_LEARN_VOLATILE", "0");
        command
    }

    /// `stoop run --root <root> <options> -- <words>`, with `env` added.
    pub fn run(
        &self,
        cwd: &Path,
        options: &[&str],
        words: &[&str],
        env: &[(&str, &str)],
    ) -> Output {
        let mut command = self.stoop(cwd);
        command.args(["run", "--root"]).arg(&self.root);
        command.args(options).arg("--").args(words);
        for (name, value) in env {
            command.env(name, value);
        }
        spawning(|| command.output()).unwrap()
    }

    /// The pinned hook, run from the root: `stoop run -- ./t '{changed:**/*.t|!slow/**}'`.
    pub fn hook(&self, env: &[(&str, &str)]) -> Output {
        self.run(&self.root, &[], &["./t", HOOK], env)
    }

    /// `stoop explain` of the pinned hook from the root.
    pub fn explain(&self) -> Output {
        let mut command = self.stoop(&self.root);
        command
            .args(["explain", "--root"])
            .arg(&self.root)
            .args(["--", "./t", HOOK]);
        spawning(|| command.output()).unwrap()
    }

    /// The runner itself, run directly with `LOG` set and no stoop around it.
    pub fn direct(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        self.direct_child(cwd, args, env, Stdio::piped())
            .wait_with_output()
            .unwrap()
    }

    /// The runner started directly, for a test that must act while it runs.
    pub fn direct_child(
        &self,
        cwd: &Path,
        args: &[&str],
        env: &[(&str, &str)],
        stdout: Stdio,
    ) -> Child {
        let mut command = Command::new(self.root.join("t"));
        command
            .current_dir(cwd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::piped())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LOG", &self.log);
        for (name, value) in env {
            command.env(name, value);
        }
        spawning(|| command.spawn()).unwrap()
    }

    /// Every invocation the runner logged, in order.
    pub fn launches(&self) -> Vec<Launch> {
        let Ok(text) = fs::read_to_string(&self.log) else {
            return Vec::new();
        };
        let mut launches: Vec<Launch> = Vec::new();
        for line in text.lines() {
            if line == "launch" {
                launches.push(Launch::default());
                continue;
            }
            let launch = launches.last_mut().expect("a log line before its launch");
            if let Some(word) = line.strip_prefix("arg=") {
                launch.args.push(word.to_string());
            } else if let Some((name, value)) = line.split_once('=') {
                if ENV_LINES.contains(&name) {
                    launch.env.insert(name.to_string(), value.to_string());
                }
            }
            launch.lines.push(line.to_string());
        }
        launches
    }

    pub fn clear_log(&self) {
        let _ = fs::remove_file(&self.log);
    }

    /// The one suite bundle under `.stoop/units/v1`, if there is one.
    pub fn bundle_path(&self) -> Option<PathBuf> {
        let dir = self.root.join(".stoop/units/v1");
        let mut paths: Vec<PathBuf> = fs::read_dir(dir)
            .ok()?
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
            .collect();
        assert!(paths.len() <= 1, "more than one suite bundle: {paths:?}");
        paths.pop()
    }

    /// The one suite bundle under `.stoop/units/v1`, as bytes.
    pub fn bundle_bytes(&self) -> Option<Vec<u8>> {
        self.bundle_path().map(|path| fs::read(path).unwrap())
    }

    /// The one suite bundle as JSON.
    pub fn bundle(&self) -> Option<Value> {
        self.bundle_bytes()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
    }

    /// The legacy proofs under `.stoop/proofs`, each as its JSON value.
    pub fn proofs(&self) -> Vec<Value> {
        let dir = self.root.join(".stoop/proofs");
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut proofs = Vec::new();
        for entry in entries {
            let file: Value =
                serde_json::from_slice(&fs::read(entry.unwrap().path()).unwrap()).unwrap();
            proofs.extend(file["proofs"].as_array().unwrap().iter().cloned());
        }
        proofs
    }

    /// Every file under `.stoop`, by root-relative path, so a test can prove nothing changed.
    pub fn store_snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut pending = vec![self.root.join(".stoop")];
        while let Some(dir) = pending.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    // A directory's stamp changes when an entry in it is made or removed, even one removed again.
                    let meta = fs::metadata(&path).unwrap();
                    let stamp = format!(
                        "{:?} {} {}",
                        meta.modified().unwrap(),
                        meta.ctime(),
                        meta.ctime_nsec()
                    );
                    let rel = path.strip_prefix(&self.root).unwrap().to_path_buf();
                    files.insert(rel, stamp.into_bytes());
                    pending.push(path);
                } else {
                    let rel = path.strip_prefix(&self.root).unwrap().to_path_buf();
                    files.insert(rel, fs::read(&path).unwrap());
                }
            }
        }
        files
    }

    /// A FIFO outside the root. Its writer opens once a reader does: see [`meet`].
    pub fn fifo(&self) -> PathBuf {
        let path = self
            .outside
            .join(format!("fifo-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let c = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0, "mkfifo");
        path
    }
}

impl Drop for Suite {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// The variables the runner logs, one line each.
const ENV_LINES: [&str; 5] = [
    "changed",
    "units",
    "changed_file",
    "changed_inputs",
    "changed_inputs_file",
];

/// One invocation of the runner, as the log shows it.
#[derive(Debug, Default, PartialEq)]
pub struct Launch {
    pub args: Vec<String>,
    /// The `changed=`, `units=` and other value lines, by name.
    pub env: BTreeMap<String, String>,
    /// Every line after `launch`, in order.
    pub lines: Vec<String>,
}

impl Launch {
    pub fn env(&self, name: &str) -> &str {
        self.env.get(name).map_or("", String::as_str)
    }

    fn after(&self, prefix: &str) -> Vec<&str> {
        self.lines
            .iter()
            .filter_map(|line| line.strip_prefix(prefix))
            .collect()
    }

    pub fn ran(&self) -> Vec<&str> {
        self.after("ran=")
    }

    pub fn failed(&self) -> Vec<&str> {
        self.after("failed=")
    }

    pub fn statted(&self) -> Vec<&str> {
        self.after("statted=")
    }
}

/// A runner held at its FIFO hold, and the writer that releases it. See [`meet`] and [`release`].
pub struct Held {
    file: File,
    fifo: PathBuf,
}

/// How long a release waits for the runner to pass its hold, and how often it looks.
const HOLD_WAIT: Duration = Duration::from_secs(60);
const HOLD_POLL: Duration = Duration::from_millis(20);

/// Wait until the runner opens the FIFO for reading, then return the writer that releases it. The open blocks until a
/// reader arrives. That reader is the runner's hold or the reader stoop opens to hash the FIFO (issue #87), so this can
/// return before the runner reaches its hold. [`release`] works either way.
pub fn meet(fifo: &Path) -> Held {
    let (sender, receiver) = mpsc::channel();
    let path = fifo.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(fs::OpenOptions::new().write(true).open(&path));
    });
    let file = receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("the runner never reached the FIFO")
        .expect("open the FIFO for writing");
    Held {
        file,
        fifo: fifo.to_path_buf(),
    }
}

/// The runner's pass marker for a FIFO: one line per hold it has passed, in `<fifo>.passed` (`fixtures/hook/t`).
fn passes(fifo: &Path) -> usize {
    let mut marker = fifo.as_os_str().to_owned();
    marker.push(".passed");
    fs::read_to_string(marker).map_or(0, |text| text.lines().count())
}

/// Release a runner held at its FIFO hold, and return once it has passed the hold.
///
/// Issue #87: stoop opens a FIFO that a traced command reads, to hash it, and that open can pair with the writer
/// [`meet`] returned. A line written then is discarded when the pipe's last file closes, and the runner's own open
/// waits for a writer that has gone, so the runner never passes. So the writer stays open until the runner passes,
/// and the line goes in only once a reader is present (EPIPE means none is). A line stays in the pipe while a writer
/// is open, so the first write that lands is the line the hold reads. Exactly one line is written, so none strays
/// into a later hold on the same FIFO. Once issue #87 is fixed, the first write always lands and the retry never runs.
pub fn release(held: Held) {
    let Held { mut file, fifo } = held;
    let before = passes(&fifo);
    let deadline = Instant::now() + HOLD_WAIT;
    while let Err(error) = file.write_all(b"go\n") {
        assert_eq!(
            error.kind(),
            ErrorKind::BrokenPipe,
            "write the release to {}",
            fifo.display()
        );
        assert!(
            Instant::now() < deadline,
            "no reader took the release on {}",
            fifo.display()
        );
        thread::sleep(HOLD_POLL);
    }
    while passes(&fifo) == before {
        assert!(
            Instant::now() < deadline,
            "the runner never passed its hold on {}; the log ends with {:?}",
            fifo.display(),
            last_line(&fifo)
        );
        thread::sleep(HOLD_POLL);
    }
}

/// The last line of the suite's log, which sits beside its FIFOs (see [`Suite::fifo`]).
fn last_line(fifo: &Path) -> String {
    let log = fs::read_to_string(fifo.with_file_name("log")).unwrap_or_default();
    log.lines().last().unwrap_or_default().to_owned()
}

/// Collect a child's output, failing rather than hanging when it does not finish.
pub fn finish(child: Child) -> Output {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(child.wait_with_output());
    });
    receiver
        .recv_timeout(Duration::from_secs(60))
        .expect("the runner did not finish")
        .unwrap()
}

pub fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

pub fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The exact changed-path refusal, excluding bare, appeared-path, or suffixed diagnostic lines.
pub fn no_verdict_changed(out: &Output) -> Option<String> {
    text(&out.stderr).lines().find_map(|line| {
        let path = line
            .strip_prefix("stoop: this run has no verdict (exit 125): ")?
            .strip_suffix(" changed, and no unit's new proof reads it")?;
        (!path.is_empty()).then(|| path.to_owned())
    })
}

/// Failed test paths recorded by the most recent direct runner.
pub fn oracle_failed_tests(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .flat_map(|launch| {
            launch
                .lines
                .iter()
                .filter_map(|line| line.strip_prefix("failed=").map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Full-run policy failures recorded separately from failed tests.
pub fn oracle_policy_failures(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .flat_map(|launch| {
            launch
                .lines
                .iter()
                .filter_map(|line| line.strip_prefix("failed-policy=").map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// The refusal names a failing runner-only test or its flag, rather than an unrelated path.
pub fn failing_runner_depends_on(failed: &[String], runners: &[String], path: &str) -> bool {
    failed.iter().any(|test| {
        runners.contains(test)
            && (path == test
                || test
                    .strip_suffix(".u")
                    .is_some_and(|stem| path.strip_suffix(".flag") == Some(stem)))
    })
}

pub fn false_pass_after_125(previous_125: bool, noop: bool, subject: i32, oracle: i32) -> bool {
    previous_125 && noop && subject == 0 && oracle != 0
}
/// Whether a unit actually stopped reading the path's contents, including a unit-only content line.
pub fn content_read_dropped(
    before: &std::collections::BTreeSet<String>,
    after: &std::collections::BTreeSet<String>,
    path: &str,
) -> bool {
    let unit_only = format!("unit-only:{path}");
    let reads = |lines: &std::collections::BTreeSet<String>| {
        lines.contains(path) || lines.contains(&unit_only)
    };
    reads(before) && !reads(after)
}

/// The current guard for the fixture command. The fixture clears its environment before adding these values.
pub fn model_current_guard(s: &Suite, bundle: &Value, extra: &[(&str, &str)]) -> Option<String> {
    #[derive(serde::Serialize)]
    struct Guard {
        env: BTreeMap<String, String>,
        env_excluded: Vec<String>,
        ignore: Vec<String>,
    }
    let guard = bundle.get("guard")?;
    let mut values = BTreeMap::from([
        ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
        ("HOME".to_owned(), s.outside.to_str()?.to_owned()),
        ("LOG".to_owned(), s.log.to_str()?.to_owned()),
    ]);
    for &(name, value) in extra {
        if !name.starts_with("STOOP_") {
            values.insert(name.to_owned(), value.to_owned());
        }
    }
    let mut env_excluded: Vec<String> = guard["env_excluded"]
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    env_excluded.retain(|name| values.contains_key(name));
    env_excluded.sort();
    env_excluded.dedup();
    let env = values
        .into_iter()
        .filter(|(name, _)| !env_excluded.contains(name))
        .map(|(name, value)| (name, blake3::hash(value.as_bytes()).to_hex().to_string()))
        .collect();
    let mut ignore: Vec<String> = guard["ignore"]
        .as_array()?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    ignore.sort();
    ignore.dedup();
    let canonical = Guard {
        env,
        env_excluded,
        ignore,
    };
    Some(
        blake3::hash(&serde_json::to_vec(&canonical).ok()?)
            .to_hex()
            .to_string(),
    )
}

/// Identify a fixture path with the same regular-file, link, absence and directory identities as the engine.
pub fn model_identity(s: &Suite, key: &str, listed: bool) -> Option<String> {
    let path = s.path(key);
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            return (!key.starts_with('/')).then(|| "a".to_owned());
        }
        Err(_) => return None,
    };
    if meta.file_type().is_symlink() {
        return Some(format!("l:{}", fs::read_link(path).ok()?.to_string_lossy()));
    }
    if meta.is_dir() {
        if !listed {
            return Some("d".to_owned());
        }
        let mut names = fs::read_dir(path)
            .ok()?
            .map(|entry| {
                entry
                    .ok()
                    .map(|entry| entry.file_name().as_bytes().to_vec())
            })
            .collect::<Option<Vec<_>>>()?;
        names.sort();
        let mut hash = blake3::Hasher::new();
        for name in names {
            hash.update(&(name.len() as u64).to_le_bytes());
            hash.update(&name);
        }
        return Some(format!("dl:{}", hash.finalize().to_hex()));
    }
    if meta.is_file() {
        let bytes = fs::read(path).ok()?;
        let kind = if meta.mode() & 0o111 == 0 { "f" } else { "x" };
        return Some(format!("{kind}:{}", blake3::hash(&bytes).to_hex()));
    }
    None
}

/// A stored version holds only if its guard, age, every input and every output hold.
/// `previous` supplies the observed pre-step identity of the one flag a launched reader is rerunning for.
pub fn model_version_holds(
    s: &Suite,
    table: &[Value],
    version: &Value,
    guard: &str,
    previous: Option<(&str, &str)>,
) -> bool {
    if version["guard"].as_str() != Some(guard) {
        return false;
    }
    let Some(created) = version["created"].as_u64() else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    if now.saturating_sub(created) > 7 * 86_400 {
        return false;
    }
    for field in ["inputs", "outputs"] {
        let Some(entries) = version[field].as_array() else {
            return false;
        };
        let mut index = 0u64;
        for (at, delta) in entries.iter().enumerate() {
            let Some(delta) = delta.as_u64() else {
                return false;
            };
            let Some(next) = (if at == 0 {
                Some(delta)
            } else {
                index.checked_add(delta)
            }) else {
                return false;
            };
            index = next;
            let Some(entry) = table.get(index as usize) else {
                return false;
            };
            let (Some(path), Some(id)) = (entry["path"].as_str(), entry["id"].as_str()) else {
                return false;
            };
            let current = previous
                .filter(|(name, _)| field == "inputs" && *name == path)
                .map(|(_, id)| id.to_owned())
                .or_else(|| model_identity(s, path, id.starts_with("dl:")));
            if current.as_deref() != Some(id) {
                return false;
            }
        }
    }
    true
}
pub type ModelListings = BTreeMap<String, std::collections::BTreeSet<String>>;

/// Paths the model observed the last successful full runner reading.
#[derive(Default)]
pub struct ModelWholeInputs {
    paths: std::collections::BTreeSet<String>,
}

fn content_line(line: &str) -> Option<&str> {
    if line.is_empty() || line == "fail" || line.starts_with("stat:") {
        None
    } else {
        Some(line.strip_prefix("unit-only:").unwrap_or(line))
    }
}
// Match the serialized fields and their order in Proof::digest. The bundle names the last full
// proof by digest; neither the first proof file nor the first proof in it is necessarily that proof.
#[derive(serde::Deserialize, serde::Serialize)]
struct ModelOidBasis {
    text: String,
    eol: String,
    filter: String,
    ident: String,
    working_tree_encoding: String,
    export_subst: String,
    crlf: String,
    autocrlf: String,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ModelProofInput {
    path: String,
    id: String,
    #[serde(default)]
    oid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    oid_basis: Option<ModelOidBasis>,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct ModelProvenance {
    os: String,
    arch: String,
    tracer: String,
    version: u32,
}

#[derive(serde::Deserialize)]
struct ModelStoredProof {
    inputs: Vec<ModelProofInput>,
    #[serde(default)]
    outputs: Vec<ModelProofInput>,
    #[serde(default)]
    removed: Vec<String>,
    env: BTreeMap<String, String>,
    #[serde(default)]
    probes: BTreeMap<String, String>,
    #[serde(default)]
    env_excluded: Vec<String>,
    #[serde(default)]
    ignore: Option<Vec<String>>,
    #[serde(default)]
    priors: Option<Vec<ModelProofInput>>,
    #[serde(default)]
    unplannable: Vec<String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    provenance: Option<ModelProvenance>,
}

fn model_proof_digest(value: &Value) -> String {
    let proof: ModelStoredProof =
        serde_json::from_value(value.clone()).expect("a stored proof must match the model");
    let bytes = serde_json::to_vec(&(
        &proof.inputs,
        &proof.outputs,
        &proof.removed,
        &proof.env,
        &proof.probes,
        &proof.env_excluded,
        &proof.ignore,
        &proof.priors,
        &proof.unplannable,
        &proof.cwd,
        &proof.scope,
        &proof.provenance,
    ))
    .expect("model proof fields serialize");
    format!("p-{}", &blake3::hash(&bytes).to_hex()[..32])
}

impl ModelWholeInputs {
    pub fn record(&mut self, s: &Suite, units: &[String], runners: &[String]) {
        self.paths.clear();
        self.paths.insert("t".to_owned());
        self.paths.insert("setup.src".to_owned());
        for test in units.iter().chain(runners) {
            self.paths.insert(test.clone());
            if let Some((stem, _)) = test.rsplit_once('.') {
                self.paths.insert(format!("{stem}.flag"));
            }
            if let Ok(body) = fs::read_to_string(s.path(test)) {
                for line in body.lines() {
                    if line.is_empty() || line == "fail" || line.starts_with("unit-only:") {
                        continue;
                    }
                    self.paths
                        .insert(line.strip_prefix("stat:").unwrap_or(line).to_owned());
                }
            }
        }
    }

    pub fn contains(&self, s: &Suite, path: &str) -> bool {
        self.paths.contains(path)
            && s.bundle()
                .and_then(|bundle| bundle["whole"].as_str().map(str::to_owned))
                .is_some_and(|whole| {
                    s.proofs().iter().any(|proof| {
                        model_proof_digest(proof) == whole
                            && proof["inputs"].as_array().is_some_and(|inputs| {
                                inputs
                                    .iter()
                                    .any(|input| input["path"].as_str() == Some(path))
                            })
                    })
                })
    }
}

/// Whether no roster unit reads this path by content in the current model state.
pub fn no_content_reader(s: &Suite, units: &ModelListings, path: &str) -> bool {
    if !units.is_empty() && matches!(path, "t" | "setup.src") {
        return false;
    }
    units.iter().all(|(unit, lines)| {
        let own_flag = unit
            .rsplit_once('.')
            .is_some_and(|(stem, _)| path.strip_suffix(".flag") == Some(stem));
        unit != path
            && !(own_flag && s.path(path).is_file())
            && !lines.iter().any(|line| content_line(line) == Some(path))
    })
}

/// Make the full runner list and require a directory that its unit discovery prunes.
pub fn listed_policy_runner(script: &str) -> String {
    let full = "\tset -f\n";
    let prune = "-o -path ./slow ";
    assert_eq!(script.matches(full).count(), 1);
    assert_eq!(script.matches(prune).count(), 2);
    script
        .replace(prune, "-o -path ./slow -o -path ./policy-r6 ")
        .replace(
            full,
            "\tfor item in \"$ROOT\"/policy-r6/zone/*; do :; done\n\tif [ ! -d \"$ROOT/policy-r6/zone\" ]; then note 'failed-policy=policy-r6/zone'; STATUS=1; fi\n\tset -f\n",
        )
}

/// Start with two empty directories, one listed and one serving as a link target.
pub fn listed_policy_setup(s: &Suite) {
    fs::create_dir_all(s.path("policy-r6/zone")).unwrap();
    fs::create_dir_all(s.path("policy-r6/target")).unwrap();
}

/// Replace the listed directory with an absence, empty directory, regular file or link.
pub fn listed_policy_replace(s: &Suite, kind: usize) {
    let path = s.path("policy-r6/zone");
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir(&path).unwrap(),
        Ok(_) => fs::remove_file(&path).unwrap(),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => panic!("cannot inspect listed directory: {error}"),
    }
    match kind {
        0 => {}
        1 => fs::create_dir(&path).unwrap(),
        2 => fs::write(&path, "not a directory\n").unwrap(),
        3 => std::os::unix::fs::symlink("target", &path).unwrap(),
        _ => panic!("unknown listed-directory kind {kind}"),
    }
    println!("R6 MODEL listed-directory kind={kind}");
}
