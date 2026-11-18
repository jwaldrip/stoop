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
    Blob { oid: String, exec: bool, size: u64 },
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
    command.env("GIT_NO_LAZY_FETCH", "1");
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
        let bytes = run(&["ls-tree", "-r", "-t", "-z", "-l", "--full-tree", &commit])?;
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
            let size = fields
                .next()
                .ok_or_else(|| GitError("missing size".into()))?;
            let entry = match (mode, kind) {
                ("040000", "tree") => Entry::Tree,
                ("160000", "commit") => Entry::Gitlink,
                ("120000", "blob") => Entry::Link { oid: oid.into() },
                ("100644" | "100755", "blob") => Entry::Blob {
                    oid: oid.into(),
                    exec: mode == "100755",
                    size: size
                        .parse()
                        .map_err(|_| GitError("invalid blob size".into()))?,
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
    fn consume<T>(
        &mut self,
        oid: &str,
        read: impl FnOnce(&mut dyn Read) -> Result<T, GitError>,
    ) -> Result<T, GitError> {
        let result = self.consume_inner(oid, read);
        if result.is_err() {
            self.batch.take();
        }
        result
    }
    fn consume_inner<T>(
        &mut self,
        oid: &str,
        read: impl FnOnce(&mut dyn Read) -> Result<T, GitError>,
    ) -> Result<T, GitError> {
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
        self.reads += 1;
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
        if fields.next() != Some(oid) || fields.next() != Some("blob") {
            return Err(GitError(format!("cannot read blob {oid}")));
        }
        let size: u64 = fields
            .next()
            .ok_or_else(|| GitError("missing blob size".into()))?
            .parse()
            .map_err(|_| GitError("invalid blob size".into()))?;
        let mut limited = (&mut batch.output).take(size);
        let result = read(&mut limited)?;
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
        Ok(result)
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
        for (path, entry) in attrs {
            let Entry::Blob { .. } = entry else {
                self.attr_error = Some(format!(
                    "{} is not a regular file",
                    String::from_utf8_lossy(&path)
                ));
                self.conversions = Some(BTreeMap::new());
                return Ok(());
            };
        }
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
