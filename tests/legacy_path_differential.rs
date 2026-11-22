//! Compare the legacy path against a separately built base binary.
#![cfg(target_os = "linux")]

use serde_json::Value;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

struct Pair {
    dir: PathBuf,
    roots: [PathBuf; 2],
    bins: [PathBuf; 2],
}

impl Pair {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("stoop-w5r-{}-{name}", std::process::id()));
        fs::create_dir_all(dir.join("home")).unwrap();
        let roots = [dir.join("base"), dir.join("subject")];
        for root in &roots {
            fs::create_dir_all(root).unwrap();
            fs::write(root.join("in.txt"), b"one\n").unwrap();
        }
        let base =
            PathBuf::from(std::env::var_os("STOOP_BASE_BIN").expect("STOOP_BASE_BIN is required"));
        let subject = std::env::var_os("STOOP_SUBJECT_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_stoop")));
        Self {
            dir,
            roots,
            bins: [base, subject],
        }
    }

    fn write(&self, path: &str, bytes: impl AsRef<[u8]>) {
        for root in &self.roots {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes.as_ref()).unwrap();
        }
    }

    fn remove(&self, path: &str) {
        for root in &self.roots {
            fs::remove_file(root.join(path)).unwrap();
        }
    }

    fn command(&self, side: usize, cwd: &str, args: &[&str], env: &[(&str, &str)]) -> Command {
        let mut command = Command::new(&self.bins[side]);
        command
            .current_dir(self.roots[side].join(cwd))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.dir.join("home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("STOOP_LEARN_VOLATILE", "0")
            .args(args);
        for (key, value) in env {
            command.env(key, value);
        }
        command
    }

    fn step(&self, label: &str, cwd: &str, args: &[&str], env: &[(&str, &str)]) -> String {
        let left = self.command(0, cwd, args, env).output().unwrap();
        let right = self.command(1, cwd, args, env).output().unwrap();
        self.compare_output(label, &left, &right)
    }

    fn compare_output(&self, label: &str, left: &Output, right: &Output) -> String {
        let a = normalize(&String::from_utf8_lossy(&left.stderr), &self.roots[0]);
        let b = normalize(&String::from_utf8_lossy(&right.stderr), &self.roots[1]);
        assert_eq!(
            left.status.code(),
            right.status.code(),
            "{label}: status\n{a}\n{b}"
        );
        assert_eq!(left.stdout, right.stdout, "{label}: stdout\n{a}\n{b}");
        assert_eq!(a, b, "{label}: stderr");
        a
    }

    fn run(
        &self,
        label: &str,
        key: &str,
        options: &[&str],
        script: &str,
        env: &[(&str, &str)],
    ) -> String {
        let mut args = vec!["run", "--root", ".", "--key", key];
        args.extend_from_slice(options);
        args.extend(["--", "sh", "-c", script]);
        self.step(label, "", &args, env)
    }

    fn explain(&self, label: &str, key: &str, options: &[&str], script: &str) -> String {
        let mut args = vec!["explain", "--root", ".", "--key", key];
        args.extend_from_slice(options);
        args.extend(["--", "sh", "-c", script]);
        self.step(label, "", &args, &[])
    }

    fn edit_proof(&self, key: &str, change: impl Fn(&mut Value)) {
        for root in &self.roots {
            let path = root.join(format!(".stoop/proofs/{key}.json"));
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            change(&mut value);
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
    }

    fn compare_store(&self, relative: &str) {
        let a = store_snapshot(&self.roots[0].join(relative));
        let b = store_snapshot(&self.roots[1].join(relative));
        assert_eq!(
            a.keys().collect::<Vec<_>>(),
            b.keys().collect::<Vec<_>>(),
            "{relative}: file list"
        );
        assert_eq!(a, b, "{relative}: proof or hook content");
    }

    fn compare_file(&self, path: &str) {
        let a = fs::read(self.roots[0].join(path)).unwrap();
        let b = fs::read(self.roots[1].join(path)).unwrap();
        assert_eq!(a, b, "{path}");
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        for root in &self.roots {
            let proofs = root.join(".stoop/proofs");
            if proofs.exists() {
                let _ = fs::set_permissions(proofs, fs::Permissions::from_mode(0o755));
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn normalize(text: &str, root: &Path) -> String {
    let text = text.replace(root.to_str().unwrap(), "<root>");
    let bytes = text.as_bytes();
    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if bytes[i..].starts_with(b"ms)") {
                result.push_str("<ms>");
            } else if [b"s ago".as_slice(), b"m ago", b"h ago", b"d ago"]
                .iter()
                .any(|suffix| bytes[i..].starts_with(suffix))
            {
                result.push_str("<age>");
                i += 5;
            } else {
                result.push_str(&text[start..i]);
            }
        } else {
            let ch = text[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8();
        }
    }
    result
}

fn without_created(value: &mut Value) {
    match value {
        Value::Object(map) => {
            map.remove("created");
            for value in map.values_mut() {
                without_created(value);
            }
        }
        Value::Array(values) => values.iter_mut().for_each(without_created),
        _ => {}
    }
}

fn store_snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, Option<Value>> {
    fn visit(
        base: &Path,
        dir: &Path,
        out: &mut std::collections::BTreeMap<PathBuf, Option<Value>>,
    ) {
        if !dir.exists() {
            return;
        }
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                visit(base, &path, out);
            } else {
                let relative = path.strip_prefix(base).unwrap().to_path_buf();
                let is_proof = relative.starts_with("proofs")
                    && relative.extension().is_some_and(|x| x == "json");
                let value = if is_proof || relative == Path::new("hooks-v1.json") {
                    let mut value: Value =
                        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                    without_created(&mut value);
                    Some(value)
                } else {
                    None
                };
                out.insert(relative, value);
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    visit(root, root, &mut out);
    out
}

fn contains(text: &str, expected: &str) {
    assert!(text.contains(expected), "expected {expected:?} in:\n{text}");
}

fn basic_scenarios() {
    let pair = Pair::new("basic");
    let script = "cat in.txt >/dev/null";
    contains(
        &pair.run("D1 record", "basic", &[], script, &[]),
        "recorded",
    );
    contains(
        &pair.run("D1 skip", "basic", &[], script, &[]),
        "stoop: skip",
    );
    pair.write("in.txt", "changed\n");
    contains(&pair.explain("D2 explain", "basic", &[], script), "in.txt");
    contains(
        &pair.run("D2 run", "basic", &[], script, &[]),
        "in.txt changed",
    );
    contains(
        &pair.run("D3 record", "output", &[], "cat in.txt > built", &[]),
        "recorded",
    );
    pair.remove("built");
    contains(
        &pair.run("D3 removed", "output", &[], "cat in.txt > built", &[]),
        "output built missing",
    );

    contains(
        &pair.run("D4 env record", "env", &[], script, &[("FOO", "a")]),
        "recorded",
    );
    contains(
        &pair.run("D4 env changed", "env", &[], script, &[("FOO", "b")]),
        "env changed",
    );
    contains(
        &pair.run(
            "D4 exclusion record",
            "excluded",
            &[],
            script,
            &[("FOO", "a")],
        ),
        "recorded",
    );
    contains(
        &pair.run(
            "D4 ignore changes counted env",
            "excluded",
            &["--ignore-env", "FOO"],
            script,
            &[("FOO", "a")],
        ),
        "env changed",
    );
    pair.edit_proof("excluded", |v| {
        v["proofs"][0]["env_excluded"]
            .as_array_mut()
            .unwrap()
            .push(Value::from("EXCLUDED"));
    });
    contains(
        &pair.run(
            "D4 exclusion changed",
            "excluded",
            &["--ignore-env", "FOO"],
            script,
            &[("FOO", "a")],
        ),
        "env exclusions changed",
    );

    for key in ["expired", "missing", "provenance"] {
        contains(&pair.run("D5 record", key, &[], script, &[]), "recorded");
    }
    pair.edit_proof("expired", |v| v["proofs"][0]["created"] = Value::from(1));
    contains(
        &pair.run("D5 expired", "expired", &["--max-age", "1"], script, &[]),
        "proof expired",
    );
    pair.edit_proof("missing", |v| {
        v["proofs"][0].as_object_mut().unwrap().remove("provenance");
    });
    contains(
        &pair.run("D5 missing", "missing", &[], script, &[]),
        "provenance missing",
    );
    pair.edit_proof("provenance", |v| {
        v["proofs"][0]["provenance"]["version"] = Value::from(999999)
    });
    contains(
        &pair.run("D5 changed", "provenance", &[], script, &[]),
        "provenance changed",
    );
    pair.compare_store(".stoop");
}

fn directory_and_scope() {
    let pair = Pair::new("scope");
    pair.write("sub/in.txt", "one\n");
    let script = "cat in.txt >/dev/null";
    contains(
        &pair.run("D6 directory record", "dir", &[], script, &[]),
        "recorded",
    );
    let text = pair.step(
        "D6 directory changed",
        "sub",
        &[
            "run", "--root", "..", "--key", "dir", "--", "sh", "-c", script,
        ],
        &[],
    );
    contains(&text, "directory changed");
    for root in &pair.roots {
        git(root, &["init", "-q"]);
        git(
            root,
            &["remote", "add", "origin", "https://example.org/repo-a.git"],
        );
    }
    contains(
        &pair.run(
            "D6 repository record",
            "repo",
            &["--store", "shared"],
            script,
            &[],
        ),
        "recorded",
    );
    for root in &pair.roots {
        git(
            root,
            &[
                "remote",
                "set-url",
                "origin",
                "https://example.org/repo-b.git",
            ],
        );
    }
    contains(
        &pair.run(
            "D6 repository changed",
            "repo",
            &["--store", "shared"],
            script,
            &[],
        ),
        "repository changed",
    );
    pair.compare_store(".stoop");
    pair.compare_store("shared");
}

fn probes() {
    let pair = Pair::new("probes");
    pair.write("probe.txt", "v1\n");
    let probe = "printf 'probe\\n' >> probe.log; cat probe.txt";
    let options = ["--probe", probe];
    let script = "cat in.txt >/dev/null";
    contains(
        &pair.run("D7 record", "probe", &options, script, &[]),
        "recorded",
    );
    contains(
        &pair.run("D7 hit", "probe", &options, script, &[]),
        "stoop: skip",
    );
    pair.write("probe.txt", "v2\n");
    contains(
        &pair.run("D7 changed", "probe", &options, script, &[]),
        "changed",
    );
    let failing = "printf 'failed\\n' >> probe.log; false";
    let failed_script =
        "cat in.txt >/dev/null; printf 'ran\\n' >> probe-failed-child.log; printf 'child ran\\n'";
    contains(
        &pair.run(
            "D7 failed before",
            "fail-before",
            &["--probe", failing],
            failed_script,
            &[],
        ),
        "probe failed before",
    );
    let conditional = "printf 'check\\n' >> probe.log; [ ! -f fail ] && cat probe.txt";
    let conditional_script =
        "cat in.txt >/dev/null; printf 'ran\\n' >> probe-lookup-child.log; printf 'child ran\\n'";
    contains(
        &pair.run(
            "D7 conditional record",
            "fail-after",
            &["--probe", conditional],
            conditional_script,
            &[],
        ),
        "recorded",
    );
    pair.write("fail", "fail\n");
    contains(
        &pair.run(
            "D7 failing lookup",
            "fail-after",
            &["--probe", conditional],
            conditional_script,
            &[],
        ),
        "probe failed",
    );
    pair.remove("fail");
    contains(
        &pair.run(
            "D7 changes during",
            "during",
            &options,
            "cat in.txt >/dev/null; printf 'ran\\n' >> probe-during-child.log; printf 'child ran\\n'; echo v3 > probe.txt",
            &[],
        ),
        "probe changed while the command ran",
    );
    for (path, expected) in [
        ("probe-failed-child.log", "ran\n"),
        ("probe-lookup-child.log", "ran\nran\n"),
        ("probe-during-child.log", "ran\n"),
    ] {
        pair.compare_file(path);
        assert_eq!(
            fs::read_to_string(pair.roots[0].join(path)).unwrap(),
            expected,
            "D7 child execution for {path}"
        );
    }
    pair.compare_file("probe.log");
    assert_eq!(
        fs::read_to_string(pair.roots[0].join("probe.log")).unwrap(),
        "probe\nprobe\nprobe\nprobe\nprobe\nprobe\nfailed\ncheck\ncheck\ncheck\ncheck\nprobe\nprobe\n"
    );
    pair.compare_file("probe.txt");
    pair.compare_store(".stoop");
}

fn explain_many() {
    let pair = Pair::new("many");
    let script = "cat inputs/* >/dev/null";
    for version in 0..8 {
        for n in 0..25 {
            pair.write(&format!("inputs/{n:02}"), format!("version {version}\n"));
        }
        contains(&pair.run("D8 record", "many", &[], script, &[]), "recorded");
    }
    for n in 0..25 {
        pair.write(&format!("inputs/{n:02}"), "final\n");
    }
    let text = pair.explain("D8 explain", "many", &[], script);
    assert_eq!(text.matches("proof ").count(), 8, "{text}");
    contains(&text, "more)");
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("  changed:"))
            .count(),
        8 * 20,
        "{text}"
    );
    pair.compare_store(".stoop");
}

fn nonrecording() {
    let pair = Pair::new("nonrecording");
    let args = [
        "run",
        "--root",
        ".",
        "--key",
        "exit",
        "--",
        "sh",
        "-c",
        "cat in.txt >/dev/null; exit 3",
    ];
    let base = pair.command(0, "", &args, &[]).output().unwrap();
    let subject = pair.command(1, "", &args, &[]).output().unwrap();
    assert_eq!(base.status.code(), Some(3));
    contains(
        &pair.compare_output("D9 exit 3", &base, &subject),
        "stoop: run",
    );
    contains(
        &pair.run(
            "D9 no record",
            "norecord",
            &["--no-record"],
            "cat in.txt >/dev/null",
            &[],
        ),
        "stoop: run",
    );
    let network = "cat in.txt >/dev/null; bash -c 'exec 3<>/dev/tcp/127.0.0.1/9' 2>/dev/null; true";
    contains(
        &pair.run("D9 network", "network", &[], network, &[]),
        "network",
    );
    pair.write(".git/config", "[core]\n\trepositoryformatversion = 0\n");
    contains(
        &pair.run(
            "D9 git read",
            "gitread",
            &[],
            "cat .git/config >/dev/null",
            &[],
        ),
        "not recorded",
    );
    for root in &pair.roots {
        for key in ["exit", "norecord", "network", "gitread"] {
            assert!(!root.join(format!(".stoop/proofs/{key}.json")).exists());
        }
    }
    pair.compare_store(".stoop");
}

fn midrun() {
    let pair = Pair::new("midrun");
    for side in 0..2 {
        let root = &pair.roots[side];
        let old = Command::new("touch")
            .args(["-d", "2000-01-01", root.join("in.txt").to_str().unwrap()])
            .status()
            .unwrap();
        assert!(old.success());
        let gate = pair.dir.join(format!("gate-{side}"));
        let fifo = CString::new(gate.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    }
    let mut outputs = Vec::new();
    for side in 0..2 {
        let gate_path = pair.dir.join(format!("gate-{side}"));
        let args = [
            "run",
            "--root",
            ".",
            "--key",
            "mid",
            "--",
            "sh",
            "-c",
            "cat in.txt >/dev/null; cat \"$FIFO\" >/dev/null",
        ];
        let mut child = pair
            .command(side, "", &args, &[("FIFO", gate_path.to_str().unwrap())])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let started = Instant::now();
        let gate = loop {
            match OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&gate_path)
            {
                Ok(gate) => break gate,
                Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                Err(error) => panic!("open gate: {error}"),
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "D10 child exited before gate"
            );
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "D10 gate timed out"
            );
            thread::sleep(Duration::from_millis(10));
        };
        fs::write(pair.roots[side].join("in.txt"), b"changed length\n").unwrap();
        drop(gate);
        outputs.push(child.wait_with_output().unwrap());
    }
    let text = pair.compare_output("D10 refusal", &outputs[0], &outputs[1]);
    contains(&text, "in.txt changed while the command ran");
    for root in &pair.roots {
        assert!(!root.join(".stoop/proofs/mid.json").exists());
    }
    pair.compare_store(".stoop");
}

fn readonly_and_full() {
    let readonly = Pair::new("readonly");
    for root in &readonly.roots {
        let proofs = root.join(".stoop/proofs");
        fs::create_dir_all(&proofs).unwrap();
        fs::set_permissions(proofs, fs::Permissions::from_mode(0o555)).unwrap();
    }
    contains(
        &readonly.run(
            "D11 readonly",
            "readonly",
            &[],
            "cat in.txt >/dev/null",
            &[],
        ),
        "could not save proof",
    );
    readonly.compare_store(".stoop");

    let pair = Pair::new("full");
    let script = "cat in.txt >/dev/null; printf 'ran\\n' >> invocation.log";
    contains(
        &pair.run("D12 record", "full", &[], script, &[]),
        "recorded",
    );
    contains(
        &pair.run("D12 hit", "full", &[], script, &[]),
        "stoop: skip",
    );
    contains(
        &pair.run("D12 full", "full", &[], script, &[("STOOP_FULL", "1")]),
        "STOOP_FULL is set",
    );
    assert!(pair
        .run("D12 quiet hit", "full", &["--quiet"], script, &[])
        .is_empty());
    pair.compare_file("invocation.log");
    assert_eq!(
        fs::read_to_string(pair.roots[0].join("invocation.log")).unwrap(),
        "ran\nran\n",
        "D12 quiet hit must not run the child"
    );
    pair.edit_proof("full", |value| {
        let proofs = value["proofs"].as_array_mut().unwrap();
        assert_eq!(proofs.len(), 2, "D12 proofs before quiet forced run");
        for (index, proof) in proofs.iter_mut().enumerate() {
            proof["created"] = Value::from(index as u64 + 1);
        }
    });
    assert!(pair
        .run(
            "D12 quiet full",
            "full",
            &["--quiet", "--max-age", "0"],
            script,
            &[("STOOP_FULL", "1")]
        )
        .is_empty());
    let mut normalized = Vec::new();
    for root in &pair.roots {
        assert_eq!(
            fs::read_to_string(root.join("invocation.log")).unwrap(),
            "ran\nran\nran\n",
            "D12 quiet forced child must run exactly once"
        );
        let path = root.join(".stoop/proofs/full.json");
        let mut value: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let proofs = value["proofs"].as_array_mut().unwrap();
        assert_eq!(proofs.len(), 3, "D12 quiet forced proof count");
        assert!(proofs[0]["created"].as_u64().unwrap() > 2);
        assert_eq!(proofs[1]["created"], 1);
        assert_eq!(proofs[2]["created"], 2);
        proofs[0]["created"] = Value::from(3);
        normalized.push(value);
    }
    assert_eq!(
        normalized[0], normalized[1],
        "D12 normalized proof creation order"
    );
    pair.compare_file("invocation.log");
    pair.compare_store(".stoop");
}

fn hooked() {
    let pair = Pair::new("hooked");
    pair.write(
        "runner",
        "#!/bin/sh\ncat in.txt >/dev/null\nprintf 'hook\\n'\n",
    );
    pair.write(".stoop.toml", "[units]\nverify_every = 2\n");
    for root in &pair.roots {
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let unknown = pair.step(
        "D13 unknown",
        "",
        &[
            "explain",
            "--",
            "sh",
            "-c",
            "echo ${STOOP_CHANGED:*.t}",
            "sh",
        ],
        &[],
    );
    contains(&unknown, "no unit universe");
    let args = [
        "run",
        "--key",
        "hook",
        "--",
        "./runner",
        "--files",
        "{changed}",
    ];
    contains(
        &pair.step("D13 hook record", "", &args, &[("STOOP_RUN_NUMBER", "1")]),
        "recorded",
    );
    contains(
        &pair.step("D13 hook skip", "", &args, &[("STOOP_RUN_NUMBER", "1")]),
        "stoop: skip",
    );
    contains(
        &pair.step("D13 forced", "", &args, &[("STOOP_RUN_NUMBER", "2")]),
        "verify_every 2: run 2",
    );
    let expanded = pair.step(
        "D13 expanded",
        "",
        &["run", "--key", "hook", "--", "./runner", "--files"],
        &[("STOOP_RUN_NUMBER", "1")],
    );
    contains(&expanded, "shell expanded");
    pair.compare_store(".stoop");
}

/// Each condition that keeps a recorded, filtered suite on the full form must print, store and
/// exit exactly as the base does. The suite is changed each time, so none of these is a skip.
fn attribution_not_dispatched() {
    fn setup(pair: &Pair, config: &str) {
        pair.write(
            "runner",
            "#!/bin/sh\ncat in.txt >/dev/null\nprintf 'unit\\n'\n",
        );
        pair.write("tests/a.t", "in.txt\n");
        pair.write("tests/b.t", "in.txt\n");
        if !config.is_empty() {
            pair.write(".stoop.toml", config);
        }
        for root in &pair.roots {
            fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    let run = [
        "run",
        "--key",
        "units",
        "--",
        "./runner",
        "{changed:**/*.t}",
    ];
    let no_record = [
        "run",
        "--key",
        "units",
        "--no-record",
        "--",
        "./runner",
        "{changed:**/*.t}",
    ];

    let pair = Pair::new("attribution");
    setup(&pair, "");
    contains(&pair.step("D15 cold", "", &run, &[]), "recorded");
    pair.write("in.txt", "two\n");
    contains(
        &pair.step("D15 STOOP_FULL", "", &run, &[("STOOP_FULL", "1")]),
        "STOOP_FULL is set",
    );
    pair.write("in.txt", "three\n");
    contains(
        &pair.step("D15 CI outside Git", "", &run, &[("CI", "true")]),
        "unknown CI branch context",
    );
    pair.write("in.txt", "five\n");
    pair.step("D15 no-record", "", &no_record, &[]);
    pair.compare_store(".stoop");

    let disabled = Pair::new("attribution-disabled");
    setup(&disabled, "[units]\nenabled = false\n");
    contains(
        &disabled.step("D15 disabled cold", "", &run, &[]),
        "recorded",
    );
    disabled.write("in.txt", "two\n");
    disabled.step("D15 disabled change", "", &run, &[]);
    disabled.compare_store(".stoop");

    let newer = Pair::new("attribution-newer");
    setup(&newer, "");
    contains(&newer.step("D15 newer cold", "", &run, &[]), "recorded");
    for root in &newer.roots {
        for entry in fs::read_dir(root.join(".stoop/units/v1")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "json") {
                let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                value["v"] = 2.into();
                value["generation"] = "a future schema".into();
                fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            }
        }
    }
    newer.write("in.txt", "two\n");
    newer.step("D15 newer bundle change", "", &run, &[]);
    newer.compare_store(".stoop");
}

/// Explain of a recorded, filtered suite after a change appends two lines to the base's output (spec
/// 4.16). The base prints the same decision and nothing after it, so the subject's stderr starts with
/// the base's. Its stdout, its status and the store are the base's.
fn explain_of_a_suite() {
    let pair = Pair::new("suite-explain");
    pair.write(
        "runner",
        "#!/bin/sh\ncat in.txt >/dev/null\nprintf 'unit\\n'\n",
    );
    pair.write("tests/a.t", "in.txt\n");
    pair.write("tests/b.t", "in.txt\n");
    for root in &pair.roots {
        fs::set_permissions(root.join("runner"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let run = [
        "run",
        "--key",
        "units",
        "--",
        "./runner",
        "{changed:**/*.t}",
    ];
    let explain = [
        "explain",
        "--key",
        "units",
        "--",
        "./runner",
        "{changed:**/*.t}",
    ];
    contains(&pair.step("D17 cold", "", &run, &[]), "recorded");
    pair.write("in.txt", "two\n");
    let outputs: Vec<Output> = (0..2)
        .map(|side| pair.command(side, "", &explain, &[]).output().unwrap())
        .collect();
    assert_eq!(
        outputs[0].status.code(),
        outputs[1].status.code(),
        "D17 explain: status"
    );
    assert_eq!(outputs[0].stdout, outputs[1].stdout, "D17 explain: stdout");
    let base = normalize(&String::from_utf8_lossy(&outputs[0].stderr), &pair.roots[0]);
    let subject = normalize(&String::from_utf8_lossy(&outputs[1].stderr), &pair.roots[1]);
    assert!(
        subject.starts_with(&base),
        "D17 explain: the base's lines come first\n{base}\n{subject}"
    );
    let added = &subject[base.len()..];
    if prints_suite_lines(&base) {
        // A base that already prints the suite lines adds none. A later parity run compares such a base
        // with this binary, and so does an A/A run that uses a byte-identical copy of this binary.
        assert_eq!(
            added, "",
            "D17 explain: a base that prints the suite lines adds none\n{subject}"
        );
    } else {
        let mut lines = added.lines();
        let tracked = lines.next().unwrap_or_default();
        assert!(
            tracked.starts_with(
                "stoop: tracked 2 units, 0 inputs; 0 proven, 2 without a proof (suite "
            ),
            "{added}"
        );
        assert_eq!(
            lines.next(),
            Some("stoop: would run an attribution pass: 2 launches"),
            "{added}"
        );
        assert_eq!(lines.next(), None, "{added}");
    }
    pair.compare_store(".stoop");
}

/// Whether explain's output ends with the two suite lines (spec 4.16): the tracked counts, then a pass
/// decision or a no-pass reason. A base binary built from this change prints them.
fn prints_suite_lines(text: &str) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    let [.., tracked, decision] = lines.as_slice() else {
        return false;
    };
    tracked.starts_with("stoop: tracked ")
        && tracked.contains(" (suite ")
        && (decision.starts_with("stoop: would run an attribution pass: ")
            || decision.starts_with("stoop: no attribution pass: "))
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn remote_ref(remote: &Path, key: &str) -> Value {
    let text = git(remote, &["cat-file", "blob", &format!("refs/stoop/{key}")]);
    serde_json::from_str(&text).unwrap()
}

fn set_remote_future(remote: &Path, key: &str) {
    let mut value = remote_ref(remote, key);
    value["proofs"][0]["created"] = Value::from(u64::MAX);
    let mut child = Command::new("git")
        .current_dir(remote)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["hash-object", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&value).unwrap())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let oid = String::from_utf8(output.stdout).unwrap();
    git(
        remote,
        &["update-ref", &format!("refs/stoop/{key}"), oid.trim()],
    );
}

fn sync() {
    let pair = Pair::new("sync");
    for root in &pair.roots {
        let remote = root.join("remote.git");
        fs::create_dir_all(&remote).unwrap();
        git(&remote, &["init", "--bare", "-q"]);
        for checkout in ["source", "writer", "reader"] {
            let dir = root.join(checkout);
            fs::create_dir_all(&dir).unwrap();
            fs::write(
                dir.join("in.txt"),
                if checkout == "writer" {
                    "local\n"
                } else {
                    "remote\n"
                },
            )
            .unwrap();
            git(&dir, &["init", "-q"]);
            git(&dir, &["remote", "add", "origin", remote.to_str().unwrap()]);
        }
    }
    let plain = [
        "run",
        "--key",
        "shared",
        "--",
        "sh",
        "-c",
        "cat in.txt >/dev/null",
    ];
    let publish = [
        "run",
        "--key",
        "shared",
        "--sync",
        "git",
        "--sync-write",
        "--",
        "sh",
        "-c",
        "cat in.txt >/dev/null",
    ];
    contains(
        &pair.step("D14 writer local", "writer", &plain, &[]),
        "recorded",
    );
    contains(
        &pair.step("D14 source publish", "source", &publish, &[]),
        "published",
    );
    for root in &pair.roots {
        set_remote_future(&root.join("remote.git"), "shared");
    }
    contains(
        &pair.step(
            "D14 writer refresh",
            "writer",
            &publish,
            &[("STOOP_FULL", "1")],
        ),
        "published",
    );
    pair.compare_store("writer/.stoop");
    let mut a = remote_ref(&pair.roots[0].join("remote.git"), "shared");
    let mut b = remote_ref(&pair.roots[1].join("remote.git"), "shared");
    without_created(&mut a);
    without_created(&mut b);
    assert_eq!(a, b, "D14 decoded remote refs");
    assert_eq!(
        a["proofs"].as_array().unwrap().len(),
        2,
        "D14 both checkouts' proofs"
    );
    let read = [
        "run",
        "--key",
        "shared",
        "--sync",
        "git",
        "--",
        "sh",
        "-c",
        "cat in.txt >/dev/null",
    ];
    contains(
        &pair.step("D14 reader pulls", "reader", &read, &[]),
        "stoop: skip",
    );
    pair.compare_store("reader/.stoop");
    let script = "cat in.txt >/dev/null\n";
    let mut hasher = blake3::Hasher::new();
    for field in [script.as_bytes(), b"fixture", b"test", b""] {
        hasher.update(&(field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    let step_key = format!("sh-{}", &hasher.finalize().to_hex()[..20]);
    let mut outputs = Vec::new();
    for side in 0..2 {
        let root = &pair.roots[side];
        let temp = root.join("runner-temp");
        let journal = temp.join("stoop/journal.json");
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        fs::write(root.join("writer/job.sh"), script).unwrap();
        let data = serde_json::json!({
            "path": journal,
            "key": "job-w5r",
            "expected": [step_key],
            "record": {"created": 0, "started": 1, "status": "running", "run": "42/1", "steps": []},
            "blocked": false
        });
        fs::write(&journal, serde_json::to_vec(&data).unwrap()).unwrap();
        let args = ["sh", "--sync", "git", "--sync-write", "job.sh"];
        let env = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_WORKFLOW", "fixture"),
            ("GITHUB_JOB", "test"),
            ("RUNNER_TEMP", temp.to_str().unwrap()),
        ];
        outputs.push(pair.command(side, "writer", &args, &env).output().unwrap());
    }
    let text = pair.compare_output("D14 deferred", &outputs[0], &outputs[1]);
    contains(&text, "recorded");
    assert!(!text.contains("stoop: published"), "{text}");
    let mut jobs = Vec::new();
    let mut proofs = Vec::new();
    for root in &pair.roots {
        let remote = root.join("remote.git");
        let mut job = remote_ref(&remote, "job-w5r");
        assert_eq!(job["records"][0]["steps"][0]["key"], step_key);
        without_created(&mut job);
        jobs.push(job);
        let mut proof = remote_ref(&remote, &step_key);
        without_created(&mut proof);
        proofs.push(proof);
    }
    assert_eq!(jobs[0], jobs[1], "D14 deferred job");
    assert_eq!(proofs[0], proofs[1], "D14 deferred proof");
    pair.compare_store("source/.stoop");
    pair.compare_store("writer/.stoop");
}

#[test]
#[ignore = "requires STOOP_BASE_BIN and a Linux tracer"]
fn legacy_paths_match_the_base() {
    basic_scenarios();
    directory_and_scope();
    probes();
    explain_many();
    nonrecording();
    midrun();
    readonly_and_full();
    hooked();
    attribution_not_dispatched();
    explain_of_a_suite();
    sync();
}

/// A listed root stays out of a whole-command proof: a recorded run that lists the root stores the
/// base's proof, byte for byte, and skips the same way. Unit proofs record the root as `.`; this
/// guards the legacy side on both binaries, where pin P10 checks only the head.
#[test]
#[ignore = "requires STOOP_BASE_BIN and a Linux tracer"]
fn a_listed_root_stays_out_of_a_whole_command_proof() {
    let pair = Pair::new("root-listing");
    let script = "ls -a . > /dev/null && cat in.txt > /dev/null";
    contains(
        &pair.run("D16 record", "listed", &[], script, &[]),
        "recorded",
    );
    contains(
        &pair.run("D16 skip", "listed", &[], script, &[]),
        "stoop: skip",
    );
    pair.compare_store(".stoop");
}
