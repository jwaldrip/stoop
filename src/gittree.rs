//! Read repository state from git objects, never from the working tree.
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

#[derive(Clone, Debug)]
pub enum Entry {
    Tree,
    Blob(String),
    Link(String),
    Gitlink,
}

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

pub struct GitTree {
    root: PathBuf,
    entries: BTreeMap<Vec<u8>, Entry>,
    hashes: BTreeMap<String, String>,
    batch: Option<Batch>,
    partial: bool,
}

impl GitTree {
    pub fn load(root: &Path, rev: &str) -> Result<Self, String> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err("invalid revision".into());
        }
        let run = |args: &[&str]| -> Result<Vec<u8>, String> {
            let out = Command::new("git")
                .current_dir(root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(args)
                .output()
                .map_err(|e| format!("git: {e}"))?;
            if !out.status.success() {
                return Err(format!(
                    "git: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ));
            }
            Ok(out.stdout)
        };
        let top = run(&["rev-parse", "--show-toplevel"])?;
        let top = std::str::from_utf8(&top)
            .map_err(|_| "git: non-UTF-8 repository root")?
            .trim_end_matches('\n');
        if root.canonicalize().map_err(|e| format!("git: {e}"))?
            != Path::new(top)
                .canonicalize()
                .map_err(|e| format!("git: {e}"))?
        {
            return Err("git: root is not the repository top level".into());
        }
        let expression = format!("{rev}^{{commit}}");
        let resolved = run(&["rev-parse", "--verify", "--end-of-options", &expression])?;
        let commit = std::str::from_utf8(&resolved)
            .map_err(|_| "git: invalid commit")?
            .trim();
        let bytes = run(&["ls-tree", "-r", "-t", "-z", "--full-tree", commit])?;
        let config = Command::new("git")
            .current_dir(root)
            .env("GIT_NO_LAZY_FETCH", "1")
            .args([
                "config",
                "--get-regexp",
                r"^(extensions\.partialclone|remote\..*\.promisor)$",
            ])
            .output()
            .map_err(|e| format!("git: {e}"))?;
        if !config.status.success() && config.status.code() != Some(1) {
            return Err("git: cannot inspect partial clone configuration".into());
        }
        let partial = !config.stdout.is_empty();
        let mut entries = BTreeMap::new();
        for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let tab = record
                .iter()
                .position(|b| *b == b'\t')
                .ok_or("git: invalid tree entry")?;
            let meta =
                std::str::from_utf8(&record[..tab]).map_err(|_| "git: invalid tree metadata")?;
            let mut fields = meta.split(' ');
            let mode = fields.next().ok_or("git: missing mode")?;
            let kind = fields.next().ok_or("git: missing type")?;
            let oid = fields.next().ok_or("git: missing object")?;
            let entry = match (mode, kind) {
                ("040000", "tree") => Entry::Tree,
                ("160000", "commit") => Entry::Gitlink,
                ("120000", "blob") => Entry::Link(oid.into()),
                ("100644" | "100755", "blob") => Entry::Blob(oid.into()),
                _ => return Err("git: unsupported tree entry".into()),
            };
            entries.insert(record[tab + 1..].to_vec(), entry);
        }
        Ok(Self {
            root: root.to_owned(),
            entries,
            hashes: BTreeMap::new(),
            batch: None,
            partial,
        })
    }
    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path.as_bytes())
    }
    pub fn paths(&self) -> impl Iterator<Item = &[u8]> {
        self.entries.keys().map(Vec::as_slice)
    }
    pub fn partial(&self) -> bool {
        self.partial
    }

    fn consume<T>(
        &mut self,
        oid: &str,
        read: impl FnOnce(&mut dyn Read) -> Result<T, String>,
    ) -> Result<T, String> {
        if self.batch.is_none() {
            let mut child = Command::new("git")
                .current_dir(&self.root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(["cat-file", "--batch"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("git: {e}"))?;
            let input = child.stdin.take().ok_or("git: missing batch input")?;
            let output = BufReader::new(child.stdout.take().ok_or("git: missing batch output")?);
            self.batch = Some(Batch {
                child,
                input,
                output,
            });
        }
        let batch = self.batch.as_mut().unwrap();
        writeln!(batch.input, "{oid}")
            .and_then(|_| batch.input.flush())
            .map_err(|e| format!("git: {e}"))?;
        let mut header = String::new();
        batch
            .output
            .read_line(&mut header)
            .map_err(|e| format!("git: {e}"))?;
        let mut fields = header.split_whitespace();
        if fields.next() != Some(oid) || fields.next() != Some("blob") {
            return Err(format!("git: cannot read blob {oid}"));
        }
        let size: u64 = fields
            .next()
            .ok_or("git: missing blob size")?
            .parse()
            .map_err(|_| "git: invalid blob size")?;
        let mut limited = (&mut batch.output).take(size);
        let result = read(&mut limited)?;
        if limited.limit() != 0 {
            return Err("git: truncated blob".into());
        }
        let mut newline = [0];
        batch
            .output
            .read_exact(&mut newline)
            .map_err(|e| format!("git: {e}"))?;
        if newline != *b"\n" {
            return Err("git: invalid blob delimiter".into());
        }
        Ok(result)
    }
    pub fn file_id(&mut self, oid: &str) -> Result<String, String> {
        if let Some(id) = self.hashes.get(oid) {
            return Ok(id.clone());
        }
        let id = self.consume(oid, |reader| {
            let mut hasher = blake3::Hasher::new();
            std::io::copy(reader, &mut hasher).map_err(|e| format!("git: {e}"))?;
            Ok(format!("f:{}", hasher.finalize().to_hex()))
        })?;
        self.hashes.insert(oid.to_owned(), id.clone());
        Ok(id)
    }
    pub fn blob(&mut self, oid: &str) -> Result<Vec<u8>, String> {
        self.consume(oid, |reader| {
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .map_err(|e| format!("git: {e}"))?;
            Ok(bytes)
        })
    }
    pub fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match self.entry(path).cloned() {
            Some(Entry::Blob(oid)) => Ok(Some(self.blob(&oid)?)),
            Some(_) => Err(format!("{path} is not a file")),
            None => Ok(None),
        }
    }
}
