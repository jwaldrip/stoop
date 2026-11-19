//! What the recorder writes down: priors, removals and reasons, read from the stored
//! proof JSON of a real run. Linux only, because tracing is.
#![cfg(target_os = "linux")]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn clear_git_env(command: &mut Command) {
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("GIT_") {
            command.env_remove(key);
        }
    }
}

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

    fn git(&self, args: &[&str]) -> String {
        let mut command = Command::new("git");
        clear_git_env(&mut command);
        let out = command
            .args(args)
            .current_dir(&self.root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_ATTR_SOURCE")
            .env_remove("GIT_TEMPLATE_DIR")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn init_git(&self) {
        self.git(&["init", "-q", "--object-format=sha1"]);
    }

    fn commit_all(&self) {
        self.git(&["add", "--all"]);
        self.git(&[
            "-c",
            "user.name=Stoop Test",
            "-c",
            "user.email=stoop@example.org",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "fixture",
        ]);
    }

    fn clean(&self) {
        fs::remove_dir_all(&self.root).unwrap();
        fs::remove_dir_all(self.store()).unwrap();
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
        self.sh_with_options(script, cwd, pin, false)
    }

    fn sh_with_options(
        &self,
        script: &str,
        cwd: &std::path::Path,
        pin: bool,
        debug: bool,
    ) -> (i32, String) {
        let mut cmd = if pin {
            let cpu = unsafe { libc::sched_getcpu() };
            assert!(cpu >= 0);
            let mut cmd = Command::new("taskset");
            cmd.args(["-c", &cpu.to_string(), env!("CARGO_BIN_EXE_stoop")]);
            cmd
        } else {
            Command::new(env!("CARGO_BIN_EXE_stoop"))
        };
        clear_git_env(&mut cmd);
        if debug {
            cmd.env("STOOP_DEBUG", "1");
        }
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
            .env("HOME", self.store().join("home"))
            .env("XDG_CONFIG_HOME", self.store().join("xdg"))
            .env_remove("GIT_CONFIG")
            .env_remove("GIT_CONFIG_GLOBAL")
            .env_remove("GIT_CONFIG_SYSTEM")
            .env_remove("GIT_CONFIG_NOSYSTEM")
            .env_remove("GIT_CONFIG_COUNT")
            .env_remove("GIT_CONFIG_PARAMETERS")
            .env_remove("GIT_ATTR_SOURCE")
            .env_remove("GIT_DIR")
            .env_remove("GIT_WORK_TREE")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_COMMON_DIR")
            .env_remove("GIT_OBJECT_DIRECTORY")
            .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
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

fn entry<'a>(proof: &'a Value, field: &str, path: &str) -> &'a Value {
    proof[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} is missing"))
        .iter()
        .find(|item| item["path"].as_str() == Some(path))
        .unwrap_or_else(|| panic!("missing {field} entry {path}: {}", proof[field]))
}

fn assert_blob_oid(proof: &Value, field: &str, path: &str, git_oid: &str) {
    let expected = format!("sha1:{git_oid}");
    let item = entry(proof, field, path);
    assert_eq!(item["oid"].as_str(), Some(expected.as_str()), "{item}");
    let basis = item["oid_basis"]
        .as_object()
        .expect("OID requires an attribute basis");
    for name in [
        "text",
        "eol",
        "filter",
        "ident",
        "working_tree_encoding",
        "export_subst",
        "crlf",
    ] {
        let value = basis[name].as_str().unwrap();
        assert_eq!(value, "unspecified", "{item}");
    }
    assert!(
        matches!(basis["autocrlf"].as_str(), Some("unset" | "false")),
        "{item}"
    );
}

fn assert_no_oid(item: &Value) {
    assert!(item["oid"].is_null(), "{item}");
}

fn assert_unknown_oid_basis(item: &Value) {
    assert_no_oid(item);
    assert!(item.get("oid_basis").is_none(), "{item}");
}

fn assert_known_conversion(item: &Value) {
    assert_no_oid(item);
    assert!(item["oid_basis"].is_object(), "{item}");
}

#[test]
fn git_root_records_blob_ids_for_file_inputs_and_symlink_targets() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    for gitdir_file in [false, true] {
        let w = Ws::new(if gitdir_file {
            "oid-input-gitdir-file"
        } else {
            "oid-input-gitdir"
        });
        w.write("a.txt", "alpha\n");
        w.write("bin/x.sh", "#!/bin/sh\nexit 0\n");
        w.write("target.txt", "target\n");
        w.write("empty.txt", "");
        w.write("dirty.txt", "committed\n");
        w.write("prior.txt", "before\n");
        fs::set_permissions(w.root.join("bin/x.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("target.txt", w.root.join("alias.txt")).unwrap();
        symlink("/etc/passwd", w.root.join("outside-link")).unwrap();
        w.init_git();
        w.commit_all();
        if gitdir_file {
            fs::rename(w.root.join(".git"), w.root.join(".git-dir")).unwrap();
            w.write(".git", "gitdir: .git-dir\n");
        }
        w.write("dirty.txt", "working tree\n");

        let p = recorded(
            &w,
            "cat a.txt bin/x.sh alias.txt dirty.txt empty.txt /etc/passwd outside-link >/dev/null && ls bin >/dev/null && test ! -e missing.txt && printf 'after\\n' > prior.txt",
        );
        for (path, contents, kind) in [
            ("a.txt", "alpha\n", "f"),
            ("bin/x.sh", "#!/bin/sh\nexit 0\n", "x"),
            ("target.txt", "target\n", "f"),
            ("empty.txt", "", "f"),
        ] {
            let item = entry(&p, "inputs", path);
            let id = format!("{kind}:{}", hash(contents.as_bytes()));
            assert_eq!(item["id"].as_str(), Some(id.as_str()), "{item}");
            let tree_path = format!("HEAD:{path}");
            let oid = w.git(&["rev-parse", &tree_path]);
            if gitdir_file {
                assert_unknown_oid_basis(item);
            } else {
                assert_blob_oid(&p, "inputs", path, &oid);
            }
        }

        let dirty = entry(&p, "inputs", "dirty.txt");
        let dirty_id = format!("f:{}", hash(b"working tree\n"));
        assert_eq!(dirty["id"].as_str(), Some(dirty_id.as_str()), "{dirty}");
        let dirty_oid = w.git(&["hash-object", "--no-filters", "dirty.txt"]);
        assert_ne!(dirty_oid, w.git(&["rev-parse", "HEAD:dirty.txt"]));
        if gitdir_file {
            assert_unknown_oid_basis(dirty);
        } else {
            assert_blob_oid(&p, "inputs", "dirty.txt", &dirty_oid);
        }
        let prior = entry(&p, "priors", "prior.txt");
        assert_eq!(prior["id"], format!("f:{}", hash(b"before\n")));
        if gitdir_file {
            assert_unknown_oid_basis(prior);
        } else {
            let oid = w.git(&["rev-parse", "HEAD:prior.txt"]);
            assert_blob_oid(&p, "priors", "prior.txt", &oid);
        }

        for (path, target) in [
            ("alias.txt", "l:target.txt"),
            ("outside-link", "l:/etc/passwd"),
        ] {
            let link = entry(&p, "inputs", path);
            assert_eq!(link["id"].as_str(), Some(target), "{link}");
            assert_no_oid(link);
        }
        let directory = entry(&p, "inputs", "bin");
        assert!(
            directory["id"].as_str().unwrap().starts_with("dl:"),
            "{directory}"
        );
        assert_no_oid(directory);
        let missing = entry(&p, "inputs", "missing.txt");
        assert_eq!(missing["id"].as_str(), Some("a"), "{missing}");
        assert_no_oid(missing);
        // /etc/hostname is ignored by default; passwd is an ordinary outside input.
        let outside = entry(&p, "inputs", "/etc/passwd");
        assert!(
            outside["id"].as_str().unwrap().starts_with("f:"),
            "{outside}"
        );
        assert_no_oid(outside);
        w.clean();
    }
}

#[test]
fn prior_blob_attributes_are_queried_once_for_128_overwrites() {
    use std::os::unix::fs::PermissionsExt;

    let w = Ws::new("oid-prior-batch");
    w.init_git();
    for i in 0..128 {
        w.write(&format!("prior/{i:03}.txt"), "before\n");
    }
    w.commit_all();
    let oid = w.git(&["hash-object", "--no-filters", "prior/000.txt"]);

    let path = std::env::var_os("PATH").expect("PATH for Git");
    let real_git = std::env::split_paths(&path)
        .map(|dir| dir.join("git"))
        .find(|path| {
            fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
        .and_then(|path| fs::canonicalize(path).ok())
        .expect("executable Git");
    let store = w.store();
    let bin = store.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let wrapper = bin.join("git");
    fs::write(
        &wrapper,
        "#!/bin/sh\n\
         printf '%s\\n' invocation >> \"$STOOP_TEST_GIT_LOG\"\n\
         for arg in \"$@\"; do\n\
           case \"$arg\" in\n\
             check-attr) printf '%s\\n' check-attr >> \"$STOOP_TEST_GIT_LOG\" ;;\n\
             --list) printf '%s\\n' config-list >> \"$STOOP_TEST_GIT_LOG\" ;;\n\
           esac\n\
         done\n\
         exec \"$STOOP_TEST_REAL_GIT\" \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let log = store.join("git-invocations");
    let path =
        std::env::join_paths(std::iter::once(bin).chain(std::env::split_paths(&path))).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_stoop"))
        .env_clear()
        .env("PATH", path)
        .env("HOME", store.join("home"))
        .env("XDG_CONFIG_HOME", store.join("xdg"))
        .env("STOOP_STORE", &store)
        .env("STOOP_TEST_REAL_GIT", real_git)
        .env("STOOP_TEST_GIT_LOG", &log)
        .current_dir(&w.root)
        .args([
            "run",
            "--root",
            w.root.to_str().unwrap(),
            "--key",
            "t",
            "--",
            "sh",
            "-c",
            "for f in prior/*; do printf after > \"$f\"; done",
        ])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(err.contains("recorded"), "{err}");
    let p = w.proof();
    for i in 0..128 {
        let path = format!("prior/{i:03}.txt");
        let item = entry(&p, "priors", &path);
        assert_eq!(item["id"], format!("f:{}", hash(b"before\n")));
        assert_blob_oid(&p, "priors", &path, &oid);
    }
    let invocations = fs::read_to_string(log).unwrap();
    let total = invocations
        .lines()
        .filter(|line| *line == "invocation")
        .count();
    assert!(
        total <= 16,
        "{total} Git processes for 128 priors: {invocations}"
    );
    assert_eq!(
        invocations
            .lines()
            .filter(|line| *line == "config-list")
            .count(),
        1,
        "{invocations}"
    );
    assert_eq!(
        invocations
            .lines()
            .filter(|line| *line == "check-attr")
            .count(),
        1,
        "{invocations}"
    );
    w.clean();
}

#[test]
fn any_inherited_git_environment_omits_input_and_prior_oid_evidence() {
    for (name, override_var) in [
        ("clean", None),
        ("prompt", Some(("GIT_TERMINAL_PROMPT", "0"))),
        ("global", Some(("GIT_CONFIG_GLOBAL", "/dev/null"))),
        ("count", Some(("GIT_CONFIG_COUNT", "0"))),
        ("attributes", Some(("GIT_ATTR_SOURCE", "HEAD"))),
        ("directory", Some(("GIT_DIR", "/nonexistent"))),
        ("unknown", Some(("GIT_CUSTOM_UNRECOGNIZED", "1"))),
    ] {
        let w = Ws::new(&format!("oid-git-env-{name}"));
        w.init_git();
        w.write("prior.txt", "before\n");
        w.commit_all();
        let input_oid = w.git(&["hash-object", "--no-filters", "in.txt"]);
        let prior_oid = w.git(&["hash-object", "--no-filters", "prior.txt"]);
        let store = w.store();
        let mut command = Command::new(env!("CARGO_BIN_EXE_stoop"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", store.join("home"))
            .env("XDG_CONFIG_HOME", store.join("xdg"))
            .env("STOOP_STORE", &store)
            .current_dir(&w.root)
            .args([
                "run",
                "--root",
                w.root.to_str().unwrap(),
                "--key",
                "t",
                "--",
                "sh",
                "-c",
                "cat in.txt >/dev/null; printf after > prior.txt",
            ]);
        if let Some((key, value)) = override_var {
            command.env(key, value);
        }
        let out = command.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{name}: {err}");
        assert!(err.contains("recorded"), "{name}: {err}");
        let p = w.proof();
        if override_var.is_some() {
            assert_unknown_oid_basis(entry(&p, "inputs", "in.txt"));
            assert_unknown_oid_basis(entry(&p, "priors", "prior.txt"));
        } else {
            assert_blob_oid(&p, "inputs", "in.txt", &input_oid);
            assert_blob_oid(&p, "priors", "prior.txt", &prior_oid);
        }
        w.clean();
    }
}

#[test]
fn submodule_descendants_do_not_use_the_parent_git_attributes() {
    let child = Ws::new("oid-submodule-child");
    child.init_git();
    child.write("read.txt", "child read\n");
    child.write("prior.txt", "child prior\n");
    child.commit_all();

    let w = Ws::new("oid-submodule-parent");
    w.init_git();
    w.git(&[
        "-c",
        "protocol.file.allow=always",
        "submodule",
        "add",
        "-q",
        child.root.to_str().unwrap(),
        "sub",
    ]);
    w.commit_all();
    let parent_oid = w.git(&["hash-object", "--no-filters", "in.txt"]);
    let p = recorded(
        &w,
        "cat in.txt sub/read.txt >/dev/null; printf after > sub/prior.txt",
    );
    assert_blob_oid(&p, "inputs", "in.txt", &parent_oid);
    for (field, path, bytes) in [
        ("inputs", "sub/read.txt", b"child read\n".as_slice()),
        ("priors", "sub/prior.txt", b"child prior\n".as_slice()),
    ] {
        let item = entry(&p, field, path);
        assert_eq!(item["id"], format!("f:{}", hash(bytes)));
        assert_unknown_oid_basis(item);
    }
    w.clean();
    fs::remove_dir_all(&child.root).unwrap();
}

#[test]
fn git_root_records_original_content_prior_but_never_output_blob_ids() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let w = Ws::new("oid-priors");
    w.write("config.txt", "old\n");
    w.write("executable.sh", "echo old\n");
    fs::set_permissions(
        w.root.join("executable.sh"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    symlink("config.txt", w.root.join("link")).unwrap();
    fs::create_dir(w.root.join("empty-dir")).unwrap();
    w.init_git();
    w.commit_all();
    let p = recorded(
        &w,
        "printf 'new\\n' > config.txt && chmod -x executable.sh && rmdir empty-dir && echo output > built.txt",
    );

    for (path, old, kind) in [
        ("config.txt", "old\n", "f"),
        ("executable.sh", "echo old\n", "x"),
    ] {
        let item = entry(&p, "priors", path);
        let id = format!("{kind}:{}", hash(old.as_bytes()));
        assert_eq!(item["id"].as_str(), Some(id.as_str()), "{item}");
        let tree_path = format!("HEAD:{path}");
        let old_oid = w.git(&["rev-parse", &tree_path]);
        assert_blob_oid(&p, "priors", path, &old_oid);
    }
    assert_ne!(
        w.git(&["hash-object", "--no-filters", "config.txt"]),
        w.git(&["rev-parse", "HEAD:config.txt"])
    );
    for (path, id) in [("empty-dir", "d"), ("built.txt", "a")] {
        let item = entry(&p, "priors", path);
        assert_eq!(item["id"].as_str(), Some(id), "{item}");
        assert_no_oid(item);
    }
    for path in ["config.txt", "executable.sh", "built.txt"] {
        assert_no_oid(entry(&p, "outputs", path));
    }
    let outputs = p["outputs"].as_array().unwrap();
    assert!(!outputs.is_empty(), "{p}");
    for output in outputs {
        assert_no_oid(output);
    }
    for item in p["priors"].as_array().unwrap() {
        let id = item["id"].as_str().unwrap();
        if !id.starts_with("f:") && !id.starts_with("x:") {
            assert_no_oid(item);
        }
    }
    fs::remove_file(w.store().join("proofs/t.json")).unwrap();
    let link_proof = recorded(&w, "rm link");
    let link = entry(&link_proof, "priors", "link");
    assert_eq!(link["id"], "l:config.txt");
    assert_unknown_oid_basis(link);
    w.clean();
}

#[test]
fn owner_change_makes_every_oid_of_its_run_unknown() {
    let w = Ws::new("oid-chown");
    w.init_git();
    w.commit_all();
    let p = recorded(
        &w,
        "cat in.txt >/dev/null && chown \"$(id -u):$(id -g)\" in.txt",
    );
    assert_unknown_oid_basis(entry(&p, "inputs", "in.txt"));
    w.clean();
}

#[test]
fn sed_in_place_is_an_uncertain_owner_change() {
    let w = Ws::new("oid-sed-owner");
    w.init_git();
    w.commit_all();
    let p = recorded(&w, "sed -i s/one/two/ in.txt");
    assert_unknown_oid_basis(entry(&p, "priors", "in.txt"));
    w.clean();
}

#[test]
fn special_node_creation_makes_every_oid_of_its_run_unknown() {
    let w = Ws::new("oid-mknod");
    w.init_git();
    w.commit_all();
    let p = recorded(&w, "cat in.txt >/dev/null && mkfifo pipe.node");
    assert_unknown_oid_basis(entry(&p, "inputs", "in.txt"));
    w.clean();
}

#[test]
fn root_without_git_records_no_blob_ids() {
    let w = Ws::new("oid-no-git");
    assert!(!w.root.join(".git").exists());
    w.write("config.txt", "old\n");
    let p = recorded(
        &w,
        "cat in.txt >/dev/null; printf 'new\\n' > config.txt; printf 'out\\n' > built.txt",
    );
    assert_eq!(
        entry(&p, "inputs", "in.txt")["id"].as_str(),
        Some(format!("f:{}", hash(b"one")).as_str())
    );
    assert_eq!(
        entry(&p, "priors", "config.txt")["id"].as_str(),
        Some(format!("f:{}", hash(b"old\n")).as_str())
    );
    entry(&p, "outputs", "built.txt");
    for field in ["inputs", "priors", "outputs"] {
        let items = p[field].as_array().unwrap();
        assert!(!items.is_empty(), "{field}: {p}");
        for item in items {
            assert_unknown_oid_basis(item);
        }
    }
    w.clean();
}

#[test]
fn git_conversion_attributes_omit_input_and_prior_oids_without_running_filters() {
    use std::os::unix::fs::symlink;

    let w = Ws::new("oid-conversions");
    w.init_git();
    w.write(".git/info/attributes", "");
    for name in ["poison", "unset", "unspecified"] {
        w.git(&[
            "config",
            "--local",
            &format!("filter.{name}.clean"),
            "touch .git/clean-filter-ran; cat",
        ]);
    }
    let cases: &[(&str, &str, &[u8])] = &[
        ("text", "text", b"one\r\ntwo\r\n"),
        ("text-auto", "text=auto", b"one\r\ntwo\r\n"),
        ("legacy-crlf", "crlf", b"one\r\ntwo\r\n"),
        ("legacy-crlf-input", "crlf=input", b"one\r\ntwo\r\n"),
        ("eol-crlf", "eol=crlf", b"one\r\ntwo\r\n"),
        ("eol-lf", "eol=lf", b"one\r\ntwo\r\n"),
        ("filter", "filter=poison", b"filter data\n"),
        ("filter-unset", "filter=unset", b"filter data\n"),
        ("filter-unspecified", "filter=unspecified", b"filter data\n"),
        ("filter-prefixed", "filter=present:unset", b"filter data\n"),
        ("ident", "ident", b"$Id: recorded $\n"),
        ("encoding", "working-tree-encoding=UTF-16LE", b"x\0\r\0\n\0"),
        ("export-subst", "export-subst", b"$Format:%H$\n"),
        (
            "negative",
            "-text -eol -filter -ident -working-tree-encoding -export-subst -crlf",
            b"plain\n",
        ),
    ];
    let mut attributes = String::new();
    let mut script = String::from("set -e; ");
    for (name, attribute, bytes) in cases {
        let input = format!("input-{name}");
        let prior = format!("prior-{name}");
        attributes.push_str(&format!("{input} {attribute}\n{prior} {attribute}\n"));
        fs::write(w.root.join(&input), bytes).unwrap();
        fs::write(w.root.join(&prior), bytes).unwrap();
        script.push_str(&format!(
            "cat {input} >/dev/null; printf 'new\\n' > {prior}; "
        ));
    }
    w.write("input-plain", "plain\r\n");
    w.write("prior-plain", "plain\r\n");
    symlink("input-text", w.root.join("alias-to-text")).unwrap();
    symlink("input-plain", w.root.join("alias-to-plain")).unwrap();
    attributes.push_str("input-plain !text\nprior-plain !text\nalias-to-plain filter=poison\n");
    w.write(".gitattributes", &attributes);
    script.push_str(
        "cat input-plain alias-to-text alias-to-plain >/dev/null; printf 'new\\n' > prior-plain",
    );

    let p = recorded(&w, &script);
    for (name, _, bytes) in cases {
        let id = format!("f:{}", hash(bytes));
        let input = entry(&p, "inputs", &format!("input-{name}"));
        let prior = entry(&p, "priors", &format!("prior-{name}"));
        assert_eq!(input["id"].as_str(), Some(id.as_str()), "{input}");
        assert_eq!(prior["id"].as_str(), Some(id.as_str()), "{prior}");
        assert_known_conversion(input);
        assert_known_conversion(prior);
        assert_eq!(input["oid_basis"], prior["oid_basis"], "{name}");
        let (field, value) = match *name {
            "text" => ("text", "present:set"),
            "text-auto" => ("text", "auto"),
            "legacy-crlf" => ("crlf", "present:set"),
            "legacy-crlf-input" => ("crlf", "input"),
            "eol-crlf" => ("eol", "crlf"),
            "eol-lf" => ("eol", "lf"),
            "filter" => ("filter", "poison"),
            "filter-unset" => ("filter", "present:unset"),
            "filter-unspecified" => ("filter", "present:unspecified"),
            "filter-prefixed" => ("filter", "present:present:unset"),
            "ident" => ("ident", "present:set"),
            "encoding" => ("working_tree_encoding", "UTF-16LE"),
            "export-subst" => ("export_subst", "present:set"),
            "negative" => ("text", "present:unset"),
            _ => unreachable!(),
        };
        assert_eq!(input["oid_basis"][field], value, "{name}: {input}");
        assert_no_oid(entry(&p, "outputs", &format!("prior-{name}")));
    }
    for field in [
        "text",
        "eol",
        "filter",
        "ident",
        "working_tree_encoding",
        "export_subst",
        "crlf",
    ] {
        assert_eq!(
            entry(&p, "inputs", "input-negative")["oid_basis"][field],
            "present:unset"
        );
    }
    for alias in ["alias-to-text", "alias-to-plain"] {
        let link = entry(&p, "inputs", alias);
        assert!(link["id"].as_str().unwrap().starts_with("l:"), "{link}");
        assert_no_oid(link);
    }
    let plain_oid = w.git(&["hash-object", "--no-filters", "input-plain"]);
    assert_blob_oid(&p, "inputs", "input-plain", &plain_oid);
    assert_blob_oid(&p, "priors", "prior-plain", &plain_oid);
    assert_eq!(
        entry(&p, "inputs", "input-plain")["oid_basis"]["text"],
        "unspecified"
    );
    assert_eq!(
        entry(&p, "inputs", "input-plain")["oid_basis"]["autocrlf"],
        "unset"
    );
    // These paths have built-in conversions only, never a configured clean driver.
    for name in [
        "text",
        "text-auto",
        "legacy-crlf",
        "legacy-crlf-input",
        "eol-crlf",
        "eol-lf",
        "ident",
        "encoding",
    ] {
        let path = format!("input-{name}");
        let raw = w.git(&["hash-object", "--no-filters", &path]);
        let converted = w.git(&["hash-object", &format!("--path={path}"), &path]);
        assert_ne!(raw, converted, "{path}");
    }
    assert!(!w.root.join(".git/clean-filter-ran").exists());
    w.clean();
}

#[test]
fn core_autocrlf_only_allows_unset_or_false_for_inputs_and_priors() {
    for (name, setting, safe) in [
        ("absent", None, true),
        ("false", Some("false"), true),
        ("true", Some("true"), false),
        ("input", Some("input"), false),
        ("invalid", Some("invalid"), false),
    ] {
        let w = Ws::new(&format!("oid-autocrlf-{name}"));
        w.init_git();
        if let Some(setting) = setting {
            w.git(&["config", "--local", "core.autocrlf", setting]);
        }
        w.write("input.txt", "one\r\ntwo\r\n");
        w.write("prior.txt", "one\r\ntwo\r\n");
        let p = recorded(&w, "cat input.txt >/dev/null; printf 'new\\n' > prior.txt");
        let id = format!("f:{}", hash(b"one\r\ntwo\r\n"));
        for (field, path) in [("inputs", "input.txt"), ("priors", "prior.txt")] {
            let item = entry(&p, field, path);
            assert_eq!(item["id"].as_str(), Some(id.as_str()), "{item}");
            if safe {
                let oid = w.git(&["hash-object", "--no-filters", "input.txt"]);
                assert_blob_oid(&p, field, path, &oid);
                assert_eq!(item["oid_basis"]["autocrlf"], setting.unwrap_or("unset"));
            } else {
                assert_no_oid(item);
                if name != "invalid" {
                    assert_known_conversion(item);
                    assert_eq!(item["oid_basis"]["autocrlf"], setting.unwrap());
                }
            }
        }
        assert_no_oid(entry(&p, "outputs", "prior.txt"));
        w.clean();
    }
}

#[test]
fn symlink_targets_use_physical_path_attributes() {
    use std::os::unix::fs::symlink;

    for (kind, alias) in [
        ("file", "alias.txt"),
        ("directory", "alias-dir/content.txt"),
    ] {
        for target_is_converted in [false, true] {
            let w = Ws::new(&format!(
                "oid-physical-attributes-{kind}-{target_is_converted}"
            ));
            w.init_git();
            w.write("real/content.txt", "one\r\ntwo\r\n");
            if kind == "file" {
                symlink("real/content.txt", w.root.join("alias.txt")).unwrap();
            } else {
                symlink("real", w.root.join("alias-dir")).unwrap();
            }
            let converted = if target_is_converted {
                "real/content.txt"
            } else {
                alias
            };
            w.write(".gitattributes", &format!("{converted} text\n"));
            let p = recorded(&w, &format!("cat {alias} >/dev/null"));
            let target = entry(&p, "inputs", "real/content.txt");
            assert_eq!(
                target["id"].as_str(),
                Some(format!("f:{}", hash(b"one\r\ntwo\r\n")).as_str())
            );
            if target_is_converted {
                assert_known_conversion(target);
            } else {
                let oid = w.git(&["hash-object", "--no-filters", "real/content.txt"]);
                assert_blob_oid(&p, "inputs", "real/content.txt", &oid);
            }
            w.clean();
        }
    }
}

#[test]
fn changing_attribute_sources_drops_previously_captured_oids() {
    for (name, mutation) in [
        ("root", "printf '# changed\\n' > .gitattributes"),
        ("nested", "printf '# changed\\n' > nested/.gitattributes"),
        ("remove", "rm nested/.gitattributes"),
        (
            "rename-file",
            "mv nested/.gitattributes nested/attributes.old",
        ),
        ("rename-directory", "mv nested moved"),
        (
            "remove-nonempty-directory",
            "rmdir nested 2>/dev/null || true",
        ),
        ("create-symlink", "ln -s nested new-alias"),
        ("remove-symlink", "rm alias"),
        ("retarget-symlink", "ln -sfn . alias"),
        ("git-config", "printf '\\n# changed\\n' >> .git/config"),
    ] {
        let w = Ws::new(&format!("oid-changed-attributes-{name}"));
        w.init_git();
        w.write(".gitattributes", "# initial\n");
        w.write("nested/.gitattributes", "# initial\n");
        std::os::unix::fs::symlink("nested", w.root.join("alias")).unwrap();
        w.write(".stoopignore", ".git\n");
        w.write("prior.txt", "before\n");
        let p = recorded(
            &w,
            &format!("cat in.txt >/dev/null; printf 'after\\n' > prior.txt; {mutation}"),
        );
        let input = entry(&p, "inputs", "in.txt");
        let prior = entry(&p, "priors", "prior.txt");
        assert_eq!(
            input["id"].as_str(),
            Some(format!("f:{}", hash(b"one")).as_str())
        );
        assert_eq!(
            prior["id"].as_str(),
            Some(format!("f:{}", hash(b"before\n")).as_str())
        );
        assert_unknown_oid_basis(input);
        assert_unknown_oid_basis(prior);
        w.clean();
    }
}

#[test]
fn separate_git_dir_attribute_write_invalidates_oid_evidence() {
    let w = Ws::new("oid-separate-gitdir");
    w.init_git();
    fs::rename(w.root.join(".git"), w.root.join("administrative")).unwrap();
    w.write(".git", "gitdir: administrative\n");
    w.write("administrative/info/attributes", "# initial\n");
    let p = recorded(
        &w,
        "cat in.txt >/dev/null; printf '# changed\\n' > administrative/info/attributes",
    );
    assert_unknown_oid_basis(entry(&p, "inputs", "in.txt"));
    w.clean();
}

#[test]
fn sha256_repository_never_records_sha1_input_or_prior_oids() {
    let w = Ws::new("oid-sha256");
    w.git(&["init", "-q", "--object-format=sha256"]);
    w.write("prior.txt", "before\n");
    let p = recorded(&w, "cat in.txt >/dev/null; printf after > prior.txt");
    assert_unknown_oid_basis(entry(&p, "inputs", "in.txt"));
    assert_unknown_oid_basis(entry(&p, "priors", "prior.txt"));
    w.clean();
}

#[test]
fn git_root_does_not_record_special_files_as_inputs() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    let w = Ws::new("oid-special-files");
    w.init_git();
    let fifo = CString::new(w.root.join("fifo").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let listener = UnixListener::bind(w.root.join("socket")).unwrap();
    let p = recorded(
        &w,
        "test -p fifo && test -S socket && cat in.txt >/dev/null",
    );
    let oid = w.git(&["hash-object", "--no-filters", "in.txt"]);
    assert_blob_oid(&p, "inputs", "in.txt", &oid);
    let inputs = p["inputs"].as_array().unwrap();
    for path in ["fifo", "socket"] {
        assert!(
            !inputs
                .iter()
                .any(|item| item["path"].as_str() == Some(path)),
            "{path}: {inputs:?}"
        );
    }
    drop(listener);
    w.clean();
}

#[test]
#[ignore = "reads a sparse file larger than 2 GiB twice"]
fn sparse_input_over_two_gib_keeps_its_blob_oid() {
    let w = Ws::new("oid-over-two-gib");
    w.init_git();
    let len = (2u64 << 30) + 1;
    let file = fs::File::create(w.root.join("large-sparse")).unwrap();
    file.set_len(len).unwrap();
    drop(file);
    let p = recorded(&w, "head -c 1 large-sparse >/dev/null");
    let mut blake = blake3::Hasher::new();
    let zeros = vec![0; 1024 * 1024];
    for _ in 0..2048 {
        blake.update(&zeros);
    }
    blake.update(&[0]);
    let item = entry(&p, "inputs", "large-sparse");
    assert_eq!(
        item["id"].as_str(),
        Some(format!("f:{}", blake.finalize().to_hex()).as_str())
    );
    let oid = w.git(&["hash-object", "--no-filters", "large-sparse"]);
    assert_blob_oid(&p, "inputs", "large-sparse", &oid);
    w.clean();
}

#[test]
fn recorder_base_vs_head_timing_fixture() {
    use std::time::Instant;

    let Some(base) = std::env::var_os("STOOP_BENCH_BASE_BIN") else {
        eprintln!("base/head timing not run: STOOP_BENCH_BASE_BIN is unset");
        return;
    };
    let base = fs::canonicalize(base).expect("STOOP_BENCH_BASE_BIN must name the base binary");
    let previous = std::env::var_os("STOOP_BENCH_PREVIOUS_BIN")
        .map(|path| fs::canonicalize(path).expect("previous binary must exist"));
    let head = fs::canonicalize(env!("CARGO_BIN_EXE_stoop")).unwrap();
    let w = Ws::new("oid-base-head-timing");
    w.init_git();
    fs::write(w.root.join("payload.bin"), vec![b'x'; 16 * 1024 * 1024]).unwrap();
    fs::create_dir(w.root.join("small")).unwrap();
    for i in 0..128 {
        fs::write(w.root.join(format!("small/{i:04}.txt")), [b'x'; 1024]).unwrap();
    }
    w.commit_all();
    eprintln!(
        "stoop benchmark: same repository and runner, tracked files, fresh store per run, \
         3 alternating base/head pairs per workload; base={}; head={}",
        base.display(),
        head.display()
    );
    for (workload, script, expected_count, field) in [
        ("large-16MiB", "cat payload.bin >/dev/null", 1, "inputs"),
        (
            "small-128x1KiB",
            "cat small/*.txt >/dev/null",
            128,
            "inputs",
        ),
        (
            "overwrite-128",
            "for f in small/*.txt; do printf x > \"$f\"; done",
            128,
            "priors",
        ),
    ] {
        let comparison = if workload == "overwrite-128" {
            let Some(previous) = &previous else {
                eprintln!("overwrite timing not run: STOOP_BENCH_PREVIOUS_BIN is unset");
                continue;
            };
            previous
        } else {
            &base
        };
        eprintln!(
            "stoop benchmark: workload={workload} comparison={}",
            comparison.display()
        );
        for iteration in 0..3 {
            let binaries = if iteration % 2 == 0 {
                [("base", comparison), ("head", &head)]
            } else {
                [("head", &head), ("base", comparison)]
            };
            for (label, binary) in binaries {
                if workload == "overwrite-128" {
                    for i in 0..128 {
                        fs::write(w.root.join(format!("small/{i:04}.txt")), [b'x'; 1024]).unwrap();
                    }
                }
                let store = w
                    .root
                    .join(".git")
                    .join(format!("bench-{workload}-{iteration}-{label}"));
                let started = Instant::now();
                let mut command = Command::new(binary);
                clear_git_env(&mut command);
                let out = command
                    .args([
                        "run",
                        "--root",
                        w.root.to_str().unwrap(),
                        "--key",
                        "bench",
                        "--",
                        "sh",
                        "-c",
                        script,
                    ])
                    .current_dir(&w.root)
                    .env("STOOP_STORE", &store)
                    .env("STOOP_DEBUG", "1")
                    .env_remove("STOOP_FULL")
                    .env("HOME", w.store().join("home"))
                    .env("XDG_CONFIG_HOME", w.store().join("xdg"))
                    .env_remove("GIT_CONFIG")
                    .env_remove("GIT_CONFIG_GLOBAL")
                    .env_remove("GIT_CONFIG_SYSTEM")
                    .env_remove("GIT_CONFIG_NOSYSTEM")
                    .env_remove("GIT_CONFIG_COUNT")
                    .env_remove("GIT_CONFIG_PARAMETERS")
                    .env_remove("GIT_ATTR_SOURCE")
                    .env_remove("GIT_DIR")
                    .env_remove("GIT_WORK_TREE")
                    .env_remove("GIT_INDEX_FILE")
                    .env_remove("GIT_COMMON_DIR")
                    .env_remove("GIT_OBJECT_DIRECTORY")
                    .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
                    .env_remove("STOOP_OFF")
                    .env_remove("GITHUB_ACTIONS")
                    .env_remove("RUNNER_TEMP")
                    .env_remove("STOOP_MATRIX")
                    .env_remove("STOOP_SYNC")
                    .env_remove("STOOP_SYNC_WRITE")
                    .env_remove("STOOP_ENV_SALT")
                    .output()
                    .unwrap();
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!(
                    "stoop benchmark: workload={workload} pair={} revision={label} \
                     process+command+trace+record={elapsed_ms:.3}ms\n{stderr}",
                    iteration + 1
                );
                assert!(out.status.success(), "{stderr}");
                assert!(stderr.contains("recorded"), "{stderr}");
                let file: Value = serde_json::from_slice(
                    &fs::read(store.join("proofs/bench.json")).expect("benchmark proof"),
                )
                .unwrap();
                let inputs = file["proofs"][0][field].as_array().unwrap();
                let count = inputs
                    .iter()
                    .filter(|item| {
                        let path = item["path"].as_str().unwrap();
                        if workload == "large-16MiB" {
                            path == "payload.bin"
                        } else {
                            path.starts_with("small/")
                        }
                    })
                    .count();
                assert_eq!(count, expected_count, "{workload}: {inputs:?}");
                if label == "head" {
                    for item in inputs.iter().filter(|item| {
                        let path = item["path"].as_str().unwrap();
                        path == "payload.bin" || path.starts_with("small/")
                    }) {
                        assert!(item["oid"].as_str().is_some(), "{item}");
                        assert!(item["oid_basis"].is_object(), "{item}");
                    }
                }
            }
        }
    }
    fs::remove_dir_all(&w.root).unwrap();
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
