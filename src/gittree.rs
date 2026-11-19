//! Read repository state from git objects without executing repository code.
//! A1 assumes the plan runner and job runner have equivalent global and system
//! attributes and checkout settings, as covered by the job's runner identity.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Debug)]
pub enum Entry {
    Tree,
    Blob { oid: String, exec: bool },
    Link { oid: String },
    Gitlink,
}
#[derive(Debug)]
pub struct GitError(pub String);
struct Batch {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Drop for Batch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct TempDir(PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
static NEXT: AtomicU64 = AtomicU64::new(0);
fn git(root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    command
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_ATTR_SOURCE")
        .env_remove("GIT_INDEX_FILE");
    #[cfg(test)]
    command
        .env("HOME", root)
        .env("XDG_CONFIG_HOME", root.join(".git/stoop-test-home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    #[cfg(not(test))]
    let _ = root;
    command
}

pub struct GitTree {
    root: PathBuf,
    commit: String,
    entries: BTreeMap<Vec<u8>, Entry>,
    hashes: BTreeMap<String, String>,
    links: BTreeMap<String, String>,
    batch: Option<Batch>,
    reads: usize,
    fetched: usize,
    conversions: Option<BTreeMap<Vec<u8>, String>>,
    attr_error: Option<String>,
    #[cfg(test)]
    test_home: Option<PathBuf>,
}
impl GitTree {
    pub fn load(root: &Path, rev: &str) -> Result<Self, GitError> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err(GitError("invalid revision".into()));
        }
        let run = |args: &[&str]| -> Result<Vec<u8>, GitError> {
            let out = git(root)
                .current_dir(root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(args)
                .output()
                .map_err(|e| GitError(e.to_string()))?;
            if !out.status.success() {
                return Err(GitError(String::from_utf8_lossy(&out.stderr).trim().into()));
            }
            Ok(out.stdout)
        };
        let top = run(&["rev-parse", "--show-toplevel"])?;
        let top = std::str::from_utf8(&top)
            .map_err(|_| GitError("non-UTF-8 repository root".into()))?
            .trim_end_matches('\n');
        if root.canonicalize().map_err(|e| GitError(e.to_string()))?
            != Path::new(top)
                .canonicalize()
                .map_err(|e| GitError(e.to_string()))?
        {
            return Err(GitError("root is not the repository top level".into()));
        }
        let expression = format!("{rev}^{{commit}}");
        let resolved = run(&["rev-parse", "--verify", "--end-of-options", &expression])?;
        let commit = std::str::from_utf8(&resolved)
            .map_err(|_| GitError("invalid commit".into()))?
            .trim()
            .to_owned();
        let bytes = run(&["ls-tree", "-r", "-t", "-z", "--full-tree", &commit])?;
        let mut entries = BTreeMap::new();
        for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let tab = record
                .iter()
                .position(|b| *b == b'\t')
                .ok_or_else(|| GitError("invalid tree entry".into()))?;
            let meta = std::str::from_utf8(&record[..tab])
                .map_err(|_| GitError("invalid tree metadata".into()))?;
            let mut fields = meta.split_whitespace();
            let mode = fields
                .next()
                .ok_or_else(|| GitError("missing mode".into()))?;
            let kind = fields
                .next()
                .ok_or_else(|| GitError("missing type".into()))?;
            let oid = fields
                .next()
                .ok_or_else(|| GitError("missing object".into()))?;
            if fields.next().is_some() {
                return Err(GitError("unexpected tree metadata field".into()));
            }
            let entry = match (mode, kind) {
                ("040000", "tree") => Entry::Tree,
                ("160000", "commit") => Entry::Gitlink,
                ("120000", "blob") => Entry::Link { oid: oid.into() },
                ("100644" | "100755", "blob") => Entry::Blob {
                    oid: oid.into(),
                    exec: mode == "100755",
                },
                _ => return Err(GitError("unsupported tree entry".into())),
            };
            entries.insert(record[tab + 1..].to_vec(), entry);
        }
        Ok(Self {
            root: root.to_owned(),
            commit,
            entries,
            hashes: BTreeMap::new(),
            links: BTreeMap::new(),
            batch: None,
            reads: 0,
            fetched: 0,
            conversions: None,
            attr_error: None,
            #[cfg(test)]
            test_home: None,
        })
    }
    #[cfg(test)]
    pub fn set_test_home(&mut self, path: PathBuf) {
        self.test_home = Some(path);
    }
    pub fn commit(&self) -> &str {
        &self.commit
    }
    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path.as_bytes())
    }
    pub fn child_names_raw(&self, dir: &str) -> BTreeSet<Vec<u8>> {
        let prefix = if dir.is_empty() {
            Vec::new()
        } else {
            format!("{dir}/").into_bytes()
        };
        self.entries
            .range(prefix.clone()..)
            .take_while(|(p, _)| p.starts_with(&prefix))
            .filter_map(|(p, _)| {
                p[prefix.len()..]
                    .split(|b| *b == b'/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(<[u8]>::to_vec)
            })
            .collect()
    }
    pub fn child_names(&self, dir: &str) -> BTreeSet<String> {
        self.child_names_raw(dir)
            .into_iter()
            .filter_map(|p| String::from_utf8(p).ok())
            .collect()
    }
    pub fn below(&self, dir: &str) -> Vec<String> {
        let prefix = if dir.is_empty() {
            Vec::new()
        } else {
            format!("{dir}/").into_bytes()
        };
        self.entries
            .range(prefix.clone()..)
            .take_while(|(p, _)| p.starts_with(&prefix))
            .filter_map(|(p, _)| String::from_utf8(p.clone()).ok())
            .collect()
    }
    pub fn has_non_utf8_below(&self, dir: &str) -> bool {
        let prefix = format!("{dir}/").into_bytes();
        self.entries
            .range(prefix.clone()..)
            .take_while(|(p, _)| p.starts_with(&prefix))
            .any(|(p, _)| std::str::from_utf8(p).is_err())
    }
    pub fn blob_reads(&self) -> usize {
        self.reads
    }

    pub fn fetched_objects(&self) -> usize {
        self.fetched
    }

    fn missing_objects(&self, oids: &[String]) -> Result<Vec<String>, GitError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let input = oids.join("\n") + "\n";
        let mut child = git(&self.root)
            .current_dir(&self.root)
            .args(["cat-file", "--batch-check"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| GitError(e.to_string()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| GitError("missing batch-check input".into()))?;
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let output = child
            .wait_with_output()
            .map_err(|e| GitError(e.to_string()))?;
        writer
            .join()
            .map_err(|_| GitError("batch-check input failed".into()))?
            .map_err(|e| GitError(e.to_string()))?;
        if !output.status.success() {
            return Err(GitError("git batch-check failed".into()));
        }
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|_| GitError("invalid batch-check output".into()))?;
        let lines: Vec<_> = text.lines().collect();
        if lines.len() != oids.len() {
            return Err(GitError("invalid batch-check output count".into()));
        }
        let mut missing = Vec::new();
        for (oid, line) in oids.iter().zip(lines) {
            let mut fields = line.split_whitespace();
            if fields.next() != Some(oid.as_str()) {
                return Err(GitError("invalid batch-check object".into()));
            }
            match fields.next() {
                Some("missing") if fields.next().is_none() => missing.push(oid.clone()),
                Some("blob" | "tree" | "commit" | "tag")
                    if fields.next().is_some() && fields.next().is_none() => {}
                _ => return Err(GitError("invalid batch-check object type".into())),
            }
        }
        Ok(missing)
    }

    pub fn ensure_present(&mut self, oids: &[String]) -> Result<usize, GitError> {
        if oids.iter().any(|oid| {
            !matches!(oid.len(), 40 | 64)
                || !oid
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        }) {
            return Err(GitError("invalid object id".into()));
        }
        let unique: Vec<String> = oids
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let missing = self.missing_objects(&unique)?;
        if missing.is_empty() {
            return Ok(0);
        }
        let config = git(&self.root)
            .current_dir(&self.root)
            .args(["config", "--get-regexp", r"^remote\..*\.promisor$"])
            .output()
            .map_err(|e| GitError(e.to_string()))?;
        if !config.status.success() && config.status.code() != Some(1) {
            return Err(GitError("cannot read promisor configuration".into()));
        }
        let config = std::str::from_utf8(&config.stdout)
            .map_err(|_| GitError("invalid promisor configuration".into()))?;
        let remote = config
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(char::is_whitespace)?;
                let value = value.trim();
                if !["true", "yes", "on", "1"]
                    .iter()
                    .any(|v| value.eq_ignore_ascii_case(v))
                {
                    return None;
                }
                key.strip_prefix("remote.")
                    .and_then(|s| s.strip_suffix(".promisor"))
            })
            .filter(|name| {
                !name.is_empty() && !name.starts_with('-') && !name.chars().any(char::is_control)
            })
            .ok_or_else(|| {
                GitError(format!(
                    "object {} is missing and the repository is not a partial clone",
                    missing[0]
                ))
            })?;
        let input = missing.join("\n") + "\n";
        // A long-lived batch process must not retain a stale missing-object view.
        self.batch.take();
        let mut child = git(&self.root)
            .current_dir(&self.root)
            .env_remove("GIT_NO_LAZY_FETCH")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "http.lowSpeedLimit=1000",
                "-c",
                "http.lowSpeedTime=20",
                "-c",
                "fetch.negotiationAlgorithm=noop",
                "fetch",
                "--no-tags",
                "--no-write-fetch-head",
                "--recurse-submodules=no",
                "--filter=blob:none",
                "--stdin",
                "--",
                remote,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| GitError(e.to_string()))?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| GitError("missing fetch input".into()))?;
        let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
        let output = child
            .wait_with_output()
            .map_err(|e| GitError(e.to_string()))?;
        writer
            .join()
            .map_err(|_| GitError("fetch input failed".into()))?
            .map_err(|e| GitError(e.to_string()))?;
        if !output.status.success() {
            return Err(GitError(
                "cannot fetch missing objects from promisor remote".into(),
            ));
        }
        let still_missing = self.missing_objects(&missing)?;
        if let Some(oid) = still_missing.first() {
            return Err(GitError(format!(
                "object {oid} remains missing after fetch"
            )));
        }
        self.fetched += missing.len();
        Ok(missing.len())
    }
    fn consume<T, F>(&mut self, oid: &str, read: F) -> Result<T, GitError>
    where
        F: FnOnce(&mut dyn Read) -> Result<T, GitError>,
    {
        let mut read = Some(read);
        let result = (|| {
            if let Some(value) = self.consume_inner(oid, &mut read)? {
                return Ok(value);
            }
            self.batch.take();
            self.ensure_present(&[oid.to_string()])?;
            self.consume_inner(oid, &mut read)?
                .ok_or_else(|| GitError(format!("blob {oid} remains missing after fetch")))
        })();
        if result.is_err() {
            self.batch.take();
        }
        result
    }
    fn consume_inner<T, F>(
        &mut self,
        oid: &str,
        read: &mut Option<F>,
    ) -> Result<Option<T>, GitError>
    where
        F: FnOnce(&mut dyn Read) -> Result<T, GitError>,
    {
        if self.batch.is_none() {
            let mut child = git(&self.root)
                .current_dir(&self.root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(["cat-file", "--batch"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| GitError(e.to_string()))?;
            let input = child
                .stdin
                .take()
                .ok_or_else(|| GitError("missing batch input".into()))?;
            let output = BufReader::new(
                child
                    .stdout
                    .take()
                    .ok_or_else(|| GitError("missing batch output".into()))?,
            );
            self.batch = Some(Batch {
                child,
                input,
                output,
            });
        }
        let batch = self.batch.as_mut().unwrap();
        writeln!(batch.input, "{oid}")
            .and_then(|_| batch.input.flush())
            .map_err(|e| GitError(e.to_string()))?;
        let mut header = String::new();
        batch
            .output
            .read_line(&mut header)
            .map_err(|e| GitError(e.to_string()))?;
        let mut fields = header.split_whitespace();
        let name = fields.next();
        let kind = fields.next();
        if name == Some(oid) && kind == Some("missing") && fields.next().is_none() {
            return Ok(None);
        }
        if name != Some(oid) || kind != Some("blob") {
            return Err(GitError(format!("cannot read blob {oid}")));
        }
        self.reads += 1;
        let size: u64 = fields
            .next()
            .ok_or_else(|| GitError("missing blob size".into()))?
            .parse()
            .map_err(|_| GitError("invalid blob size".into()))?;
        let mut limited = (&mut batch.output).take(size);
        let result = read
            .take()
            .ok_or_else(|| GitError("blob reader already consumed".into()))?(
            &mut limited
        )?;
        if limited.limit() != 0 {
            return Err(GitError("truncated blob".into()));
        }
        let mut newline = [0];
        batch
            .output
            .read_exact(&mut newline)
            .map_err(|e| GitError(e.to_string()))?;
        if newline != *b"\n" {
            return Err(GitError("invalid blob delimiter".into()));
        }
        Ok(Some(result))
    }
    pub fn file_id(&mut self, oid: &str, exec: bool) -> Result<String, GitError> {
        if let Some(hash) = self.hashes.get(oid) {
            return Ok(crate::input::file_id(exec, hash));
        }
        let hash = self.consume(oid, |reader| {
            let mut h = blake3::Hasher::new();
            std::io::copy(reader, &mut h).map_err(|e| GitError(e.to_string()))?;
            Ok(h.finalize().to_hex().to_string())
        })?;
        let id = crate::input::file_id(exec, &hash);
        self.hashes.insert(oid.into(), hash);
        Ok(id)
    }
    pub fn link_target(&mut self, oid: &str) -> Result<String, GitError> {
        if let Some(target) = self.links.get(oid) {
            return Ok(target.clone());
        }
        let target = self.consume(oid, |reader| {
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|e| GitError(e.to_string()))?;
            Ok(String::from_utf8_lossy(&bytes).into_owned())
        })?;
        self.links.insert(oid.into(), target.clone());
        Ok(target)
    }
    fn attribute_data(&mut self) -> Result<(), GitError> {
        let attrs: Vec<_> = self
            .entries
            .iter()
            .filter(|(p, _)| {
                p.split(|b| *b == b'/').next_back() == Some(b".gitattributes".as_slice())
            })
            .map(|(p, e)| (p.clone(), e.clone()))
            .collect();
        let hit = !attrs.is_empty();
        let mut attr_oids = Vec::with_capacity(attrs.len());
        for (path, entry) in attrs {
            let Entry::Blob { oid, .. } = entry else {
                self.attr_error = Some(format!(
                    "{} is not a regular file",
                    String::from_utf8_lossy(&path)
                ));
                self.conversions = Some(BTreeMap::new());
                return Ok(());
            };
            attr_oids.push(oid);
        }
        self.ensure_present(&attr_oids)?;
        let mut conversions = BTreeMap::new();
        if hit {
            let dir = std::env::temp_dir().join(format!(
                "stoop-index-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&dir).map_err(|e| GitError(e.to_string()))?;
            let tmp = TempDir(dir);
            let index = tmp.0.join("index");
            let status = git(&self.root)
                .current_dir(&self.root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .env("GIT_INDEX_FILE", &index)
                .args(["read-tree", &self.commit])
                .stderr(Stdio::null())
                .status()
                .map_err(|e| GitError(e.to_string()))?;
            if !status.success() {
                return Err(GitError("read-tree failed".into()));
            }
            let paths: Vec<u8> = self
                .entries
                .iter()
                .filter(|(_, e)| matches!(e, Entry::Blob { .. }))
                .flat_map(|(p, _)| p.iter().copied().chain(std::iter::once(0)))
                .collect();
            let mut command = git(&self.root);
            #[cfg(test)]
            if let Some(home) = &self.test_home {
                command
                    .env("HOME", home)
                    .env("XDG_CONFIG_HOME", home.join(".config"));
            }
            let mut child = command
                .current_dir(&self.root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .env("GIT_INDEX_FILE", &index)
                .args([
                    "-c",
                    "core.ignorecase=false",
                    "check-attr",
                    "--cached",
                    "-z",
                    "--stdin",
                    "eol",
                    "ident",
                    "filter",
                    "working-tree-encoding",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| GitError(e.to_string()))?;
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| GitError("missing check-attr input".into()))?;
            let writer = std::thread::spawn(move || stdin.write_all(&paths));
            let out = child
                .wait_with_output()
                .map_err(|e| GitError(e.to_string()))?;
            writer
                .join()
                .map_err(|_| GitError("check-attr input failed".into()))?
                .map_err(|e| GitError(e.to_string()))?;
            if !out.status.success() {
                return Err(GitError("check-attr failed".into()));
            }
            let parts: Vec<_> = out.stdout.split(|b| *b == 0).collect();
            if parts.last() != Some(&&[][..]) || (parts.len() - 1) % 3 != 0 {
                return Err(GitError("invalid check-attr output".into()));
            }
            for triple in parts[..parts.len() - 1].as_chunks::<3>().0 {
                let attr = String::from_utf8_lossy(triple[1]);
                let value = String::from_utf8_lossy(triple[2]);
                if (attr == "eol" && value == "crlf")
                    || (attr != "eol" && value != "unspecified" && value != "unset")
                {
                    conversions
                        .entry(triple[0].to_vec())
                        .or_insert_with(|| format!("{attr}={value}"));
                }
            }
        }
        self.conversions = Some(conversions);
        Ok(())
    }
    pub fn conversion(&mut self, path: &str) -> Result<Option<String>, GitError> {
        if self.conversions.is_none() {
            self.attribute_data()?;
        }
        Ok(self.attr_error.clone().or_else(|| {
            self.conversions
                .as_ref()
                .and_then(|c| c.get(path.as_bytes()).cloned())
        }))
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) -> std::process::Output {
        let mut command = Command::new("git");
        command
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.org",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args);
        if args.first() == Some(&"checkout") {
            command.env_remove("GIT_NO_LAZY_FETCH");
        } else {
            command.env("GIT_NO_LAZY_FETCH", "1");
        }
        command.output().unwrap()
    }
    fn ok(dir: &Path, args: &[&str]) -> String {
        let out = git(dir, args);
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }
    struct Fixture {
        base: PathBuf,
        source: PathBuf,
        server: PathBuf,
        full: PathBuf,
        sparse: PathBuf,
        blobless: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "stoop-partial-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let source = base.join("source");
            let server = base.join("server.git");
            let full = base.join("full");
            let sparse = base.join("sparse");
            let blobless = base.join("blobless");
            std::fs::create_dir_all(source.join(".github/workflows")).unwrap();
            std::fs::create_dir_all(source.join("sub")).unwrap();
            std::fs::write(source.join(".github/workflows/ci.yml"), "name: test\n").unwrap();
            std::fs::write(source.join("root.txt"), "root\n").unwrap();
            std::fs::write(source.join(".gitattributes"), "# root attributes\n").unwrap();
            std::fs::write(source.join("sub/.gitattributes"), "*.sh text eol=crlf\n").unwrap();
            std::fs::write(source.join("sub/run.sh"), "echo test\n").unwrap();
            std::fs::write(source.join("sub/other.txt"), "other\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::{symlink, PermissionsExt};
                std::fs::set_permissions(
                    source.join("sub/run.sh"),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
                symlink("run.sh", source.join("sub/link.sh")).unwrap();
            }
            ok(&source, &["init", "-q"]);
            ok(&source, &["add", "."]);
            ok(&source, &["commit", "-qm", "fixture"]);
            std::fs::write(source.join("root.txt"), "older\n").unwrap();
            ok(&source, &["add", "root.txt"]);
            ok(&source, &["commit", "-qm", "second"]);
            std::fs::write(source.join("root.txt"), "root\n").unwrap();
            ok(&source, &["add", "root.txt"]);
            ok(&source, &["commit", "-qm", "third"]);
            std::fs::create_dir_all(&server).unwrap();
            ok(&server, &["init", "--bare", "-q"]);
            ok(&server, &["config", "uploadpack.allowFilter", "true"]);
            ok(
                &server,
                &["config", "uploadpack.allowAnySHA1InWant", "true"],
            );
            ok(
                &source,
                &[
                    "push",
                    "-q",
                    server.to_str().unwrap(),
                    "HEAD:refs/heads/main",
                ],
            );
            ok(&server, &["symbolic-ref", "HEAD", "refs/heads/main"]);
            let url = format!("file://{}", server.display());
            ok(
                &base,
                &["clone", "-q", "--depth=1", &url, full.to_str().unwrap()],
            );
            ok(
                &base,
                &[
                    "clone",
                    "-q",
                    "--no-checkout",
                    "--filter=blob:none",
                    "--depth=1",
                    &url,
                    blobless.to_str().unwrap(),
                ],
            );
            ok(
                &base,
                &[
                    "clone",
                    "-q",
                    "--no-checkout",
                    "--filter=blob:none",
                    "--depth=1",
                    &url,
                    sparse.to_str().unwrap(),
                ],
            );
            ok(&sparse, &["sparse-checkout", "init", "--cone"]);
            ok(&sparse, &["sparse-checkout", "set", ".github"]);
            ok(&sparse, &["checkout", "-q"]);
            Self {
                base,
                source,
                server,
                full,
                sparse,
                blobless,
            }
        }
        fn oid(&self, path: &str) -> String {
            ok(&self.source, &["rev-parse", &format!("HEAD:{path}")])
        }
        fn present(&self, dir: &Path, oid: &str) -> bool {
            git(dir, &["cat-file", "-e", oid]).status.success()
        }
        fn object_count(&self, dir: &Path) -> usize {
            ok(
                dir,
                &[
                    "cat-file",
                    "--batch-all-objects",
                    "--batch-check=%(objectname)",
                ],
            )
            .lines()
            .count()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(unix)]
    #[test]
    fn load_reads_a_blobless_clone() {
        let f = Fixture::new();
        let before = f.object_count(&f.blobless);
        let partial = GitTree::load(&f.blobless, "HEAD").unwrap();
        let full = GitTree::load(&f.full, "HEAD").unwrap();
        assert_eq!(
            format!("{:?}", partial.entries),
            format!("{:?}", full.entries)
        );
        assert!(matches!(
            partial.entry("sub/run.sh"),
            Some(Entry::Blob { exec: true, .. })
        ));
        #[cfg(unix)]
        assert!(matches!(
            partial.entry("sub/link.sh"),
            Some(Entry::Link { .. })
        ));
        assert_eq!(before, f.object_count(&f.blobless));
        assert!(!f.present(&f.blobless, &f.oid("sub/run.sh")));
    }

    #[test]
    fn replaced_objects_cannot_change_blob_or_attributes() {
        let f = Fixture::new();
        let file = f.oid("sub/run.sh");
        let attrs = f.oid("sub/.gitattributes");
        let replacement = f.oid("root.txt");
        ok(&f.full, &["replace", &file, &replacement]);
        ok(&f.full, &["replace", &attrs, &replacement]);
        let mut tree = GitTree::load(&f.full, "HEAD").unwrap();
        assert_eq!(
            tree.file_id(&file, true).unwrap(),
            format!("x:{}", blake3::hash(b"echo test\n").to_hex())
        );
        assert_eq!(
            tree.conversion("sub/run.sh").unwrap().as_deref(),
            Some("eol=crlf")
        );
    }

    #[test]
    fn fetched_older_commit_has_the_same_tree_as_the_source() {
        let f = Fixture::new();
        let older = ok(&f.source, &["rev-parse", "HEAD~1"]);
        let old_oid = ok(&f.source, &["rev-parse", "HEAD~1:root.txt"]);
        let head_oid = ok(&f.source, &["rev-parse", "HEAD:root.txt"]);
        assert_ne!(old_oid, head_oid);
        ok(
            &f.full,
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--depth=1",
                "origin",
                &older,
            ],
        );
        let clone = GitTree::load(&f.full, &older).unwrap();
        let source = GitTree::load(&f.source, &older).unwrap();
        assert!(
            matches!(clone.entry("root.txt"), Some(Entry::Blob { oid, .. }) if oid == &old_oid)
        );
        assert_eq!(
            format!("{:?}", clone.entries),
            format!("{:?}", source.entries)
        );
    }
    #[test]
    fn nested_attributes_are_fetched_before_check_attr() {
        let f = Fixture::new();
        let oid = f.oid("sub/.gitattributes");
        assert!(!f.present(&f.sparse, &oid));
        let mut tree = GitTree::load(&f.sparse, "HEAD").unwrap();
        assert_eq!(
            tree.conversion("sub/run.sh").unwrap().as_deref(),
            Some("eol=crlf")
        );
        assert_eq!(tree.fetched_objects(), 1);
        assert!(f.present(&f.sparse, &oid));
        let g = Fixture::new();
        ok(&g.sparse, &["config", "--unset", "remote.origin.promisor"]);
        let mut tree = GitTree::load(&g.sparse, "HEAD").unwrap();
        assert!(tree.conversion("sub/run.sh").is_err());
    }
    #[test]
    fn missing_blob_is_fetched_once() {
        let f = Fixture::new();
        let oid = f.oid("sub/other.txt");
        assert!(!f.present(&f.blobless, &oid));
        let mut tree = GitTree::load(&f.blobless, "HEAD").unwrap();
        let actual = tree.file_id(&oid, false).unwrap();
        assert_eq!(actual, format!("f:{}", blake3::hash(b"other\n").to_hex()));
        assert!(f.present(&f.blobless, &oid));
        assert_eq!(tree.fetched_objects(), 1);
        assert_eq!(tree.file_id(&oid, false).unwrap(), actual);
        assert_eq!(tree.fetched_objects(), 1);
    }
    #[cfg(unix)]
    #[test]
    fn git_tree_never_requests_sizes_or_implicit_fetches() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(root) = std::env::var_os("STOOP_P1_GIT_WRAPPER_CHILD") {
            let mut tree = GitTree::load(Path::new(&root), "HEAD").unwrap();
            assert_eq!(
                tree.conversion("sub/run.sh").unwrap().as_deref(),
                Some("eol=crlf")
            );
            return;
        }
        let f = Fixture::new();
        let bin = f.base.join("bin");
        std::fs::create_dir(&bin).unwrap();
        let actual = Command::new("which").arg("git").output().unwrap();
        assert!(actual.status.success());
        let actual = String::from_utf8(actual.stdout).unwrap();
        let wrapper = bin.join("git");
        let quoted = actual.trim().replace('\'', "'\\''");
        std::fs::write(&wrapper, format!("#!/bin/sh\nfor arg in \"$@\"; do\n  [ \"$arg\" = -l ] && exit 91\n  case \"$arg\" in ls-tree|cat-file|check-attr) [ \"$GIT_NO_LAZY_FETCH\" = 1 ] || exit 92;; esac\ndone\nexec '{quoted}' \"$@\"\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gittree::partial_tests::git_tree_never_requests_sizes_or_implicit_fetches",
                "--nocapture",
            ])
            .env("STOOP_P1_GIT_WRAPPER_CHILD", &f.full)
            .env("PATH", path)
            .env_remove("GIT_NO_LAZY_FETCH")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn long_tree_listing_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(root) = std::env::var_os("STOOP_P1_LONG_CHILD") {
            let error = match GitTree::load(Path::new(&root), "HEAD") {
                Ok(_) => panic!("long tree listing was accepted"),
                Err(error) => error,
            };
            assert!(
                error.0.contains("unexpected tree metadata field"),
                "{error:?}"
            );
            return;
        }
        let f = Fixture::new();
        let bin = f.base.join("long-bin");
        std::fs::create_dir(&bin).unwrap();
        let actual = Command::new("which").arg("git").output().unwrap();
        assert!(actual.status.success());
        let quoted = String::from_utf8(actual.stdout)
            .unwrap()
            .trim()
            .replace('\'', "'\\''");
        let wrapper = bin.join("git");
        std::fs::write(&wrapper, format!("#!/bin/sh\nif [ \"$1\" = ls-tree ]; then shift; exec '{quoted}' ls-tree --long \"$@\"; fi\nexec '{quoted}' \"$@\"\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gittree::partial_tests::long_tree_listing_is_rejected",
                "--nocapture",
            ])
            .env("STOOP_P1_LONG_CHILD", &f.full)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn successful_fetch_without_objects_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        if let Some(root) = std::env::var_os("STOOP_P1_EMPTY_FETCH_CHILD") {
            let mut tree = GitTree::load(Path::new(&root), "HEAD").unwrap();
            assert!(tree.conversion("sub/run.sh").is_err());
            assert_eq!(tree.fetched_objects(), 0);
            return;
        }
        let f = Fixture::new();
        assert!(!f.present(&f.sparse, &f.oid("sub/.gitattributes")));
        let bin = f.base.join("empty-fetch-bin");
        std::fs::create_dir(&bin).unwrap();
        let actual = Command::new("which").arg("git").output().unwrap();
        assert!(actual.status.success());
        let quoted = String::from_utf8(actual.stdout)
            .unwrap()
            .trim()
            .replace('\'', "'\\''");
        let wrapper = bin.join("git");
        std::fs::write(&wrapper, format!("#!/bin/sh\nfor arg in \"$@\"; do\n  if [ \"$arg\" = fetch ]; then cat >/dev/null; exit 0; fi\ndone\nexec '{quoted}' \"$@\"\n")).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "gittree::partial_tests::successful_fetch_without_objects_is_an_error",
                "--nocapture",
            ])
            .env("STOOP_P1_EMPTY_FETCH_CHILD", &f.sparse)
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    bin.display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    #[test]
    fn ensure_present_batches_missing_and_restarts_the_reader() {
        let f = Fixture::new();
        let present = f.oid("root.txt");
        let first = f.oid("sub/other.txt");
        let second = f.oid("sub/run.sh");
        let mut tree = GitTree::load(&f.sparse, "HEAD").unwrap();
        assert!(f.present(&f.sparse, &present));
        assert!(!f.present(&f.sparse, &first));
        assert!(!f.present(&f.sparse, &second));
        tree.file_id(&present, false).unwrap();
        assert!(tree.batch.is_some());
        assert_eq!(
            tree.ensure_present(&[first.clone(), second.clone(), first.clone()])
                .unwrap(),
            2
        );
        assert!(tree.batch.is_none());
        assert_eq!(tree.fetched_objects(), 2);
        assert_eq!(
            tree.ensure_present(&[first.clone(), second.clone()])
                .unwrap(),
            0
        );
        assert_eq!(tree.fetched_objects(), 2);
        assert_eq!(
            tree.file_id(&first, false).unwrap(),
            format!("f:{}", blake3::hash(b"other\n").to_hex())
        );
        assert!(f.present(&f.sparse, &second));
    }
    #[cfg(unix)]
    #[test]
    fn explicit_object_fetch_does_not_contact_initialized_submodules() {
        use std::os::unix::fs::PermissionsExt;
        let f = Fixture::new();
        let subsource = f.base.join("subsource");
        std::fs::create_dir(&subsource).unwrap();
        ok(&subsource, &["init", "-q"]);
        std::fs::write(subsource.join("file"), "submodule\n").unwrap();
        ok(&subsource, &["add", "."]);
        ok(&subsource, &["commit", "-qm", "submodule"]);
        ok(
            &f.source,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                subsource.to_str().unwrap(),
                "deps/project",
            ],
        );
        ok(&f.source, &["commit", "-qm", "add submodule"]);
        ok(
            &f.source,
            &[
                "push",
                "-q",
                f.server.to_str().unwrap(),
                "HEAD:refs/heads/main",
            ],
        );
        let clone = f.base.join("with-submodule");
        let url = format!("file://{}", f.server.display());
        ok(
            &f.base,
            &[
                "clone",
                "-q",
                "--no-checkout",
                "--filter=blob:none",
                "--depth=1",
                &url,
                clone.to_str().unwrap(),
            ],
        );
        ok(&clone, &["sparse-checkout", "init", "--cone"]);
        ok(&clone, &["sparse-checkout", "set", ".github", "deps"]);
        ok(&clone, &["checkout", "-q"]);
        ok(
            &clone,
            &[
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "update",
                "--init",
                "--",
                "deps/project",
            ],
        );
        let submodule = clone.join("deps/project");
        let contact = f.base.join("submodule-contact");
        let hook = f.base.join("submodule-upload-pack");
        std::fs::write(
            &hook,
            format!(
                "#!/bin/sh\nprintf contact >> '{}'\nexit 1\n",
                contact.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        ok(
            &submodule,
            &["config", "remote.origin.uploadpack", hook.to_str().unwrap()],
        );
        ok(&clone, &["config", "fetch.recurseSubmodules", "true"]);
        let missing = f.oid("sub/other.txt");
        assert!(!f.present(&clone, &missing));
        let mut tree = GitTree::load(&clone, "HEAD").unwrap();
        assert_eq!(
            tree.file_id(&missing, false).unwrap(),
            format!("f:{}", blake3::hash(b"other\n").to_hex())
        );
        assert!(!contact.exists(), "submodule remote was contacted");
    }
    #[test]
    fn unreachable_promisor_is_an_error() {
        let f = Fixture::new();
        let oid = f.oid("sub/other.txt");
        let mut tree = GitTree::load(&f.blobless, "HEAD").unwrap();
        std::fs::rename(&f.server, f.base.join("unreachable.git")).unwrap();
        assert!(tree.file_id(&oid, false).is_err());
    }
}
