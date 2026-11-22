//! Helpers for the hook-fixture tests: a throwaway suite (the fake runner in `fixtures/hook/t`
//! and a small tree), the stoop CLI with a clean environment, and a reader for the runner's log.
#![allow(dead_code)]

use serde_json::Value;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, RwLock};
use std::thread;
use std::time::Duration;

/// The hook every pin uses. Its inline filter is the roster; the full form runs the runner with no arguments.
pub const HOOK: &str = "{changed:**/*.t|!slow/**}";

/// The roster the tree yields for `HOOK`: every `*.t` outside `slow/`.
pub const ROSTER: [&str; 3] = ["tests/a.t", "tests/b.t", "tests/c.t"];

const RUNNER: &str = include_str!("../fixtures/hook/t");

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

/// Wait until the runner opens the FIFO for reading, then return the writing end. The open
/// blocks until a reader arrives, so this returns exactly when the runner reaches its hold.
/// Dropping the returned file releases the runner.
pub fn meet(fifo: &Path) -> File {
    let (sender, receiver) = mpsc::channel();
    let path = fifo.to_path_buf();
    thread::spawn(move || {
        let _ = sender.send(fs::OpenOptions::new().write(true).open(&path));
    });
    receiver
        .recv_timeout(Duration::from_secs(30))
        .expect("the runner never reached the FIFO")
        .expect("open the FIFO for writing")
}

/// Release a held runner with one line, then drop the writer.
pub fn release(mut writer: File) {
    writer.write_all(b"go\n").unwrap();
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
