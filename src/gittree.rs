//! Read repository state from git objects, never from the working tree.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Debug)]
pub enum Entry {
    Tree,
    Blob(String),
    Link(String),
    Gitlink,
}

pub struct GitTree {
    root: PathBuf,
    entries: BTreeMap<String, Entry>,
    blobs: BTreeMap<String, Vec<u8>>,
}

impl GitTree {
    pub fn load(root: &Path, rev: &str) -> Result<Self, String> {
        if rev.is_empty() || rev.starts_with('-') {
            return Err("invalid revision".into());
        }
        let output = Command::new("git")
            .current_dir(root)
            .env("GIT_NO_LAZY_FETCH", "1")
            .args(["ls-tree", "-r", "-t", "-z", "--full-tree", rev])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("cannot read git tree".into());
        }
        let mut entries = BTreeMap::new();
        for record in output.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let tab = record
                .iter()
                .position(|b| *b == b'\t')
                .ok_or("invalid tree entry")?;
            let meta = std::str::from_utf8(&record[..tab]).map_err(|_| "invalid tree metadata")?;
            let path =
                std::str::from_utf8(&record[tab + 1..]).map_err(|_| "non-UTF-8 tree path")?;
            let mut fields = meta.split(' ');
            let mode = fields.next().ok_or("missing mode")?;
            let kind = fields.next().ok_or("missing type")?;
            let oid = fields.next().ok_or("missing object")?;
            let entry = match (mode, kind) {
                ("040000", "tree") => Entry::Tree,
                ("160000", "commit") => Entry::Gitlink,
                ("120000", "blob") => Entry::Link(oid.into()),
                ("100644" | "100755", "blob") => Entry::Blob(oid.into()),
                _ => return Err("unsupported tree entry".into()),
            };
            entries.insert(path.to_string(), entry);
        }
        Ok(Self {
            root: root.to_owned(),
            entries,
            blobs: BTreeMap::new(),
        })
    }

    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }
    pub fn paths(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
    pub fn blob(&mut self, oid: &str) -> Result<&[u8], String> {
        if !self.blobs.contains_key(oid) {
            let out = Command::new("git")
                .current_dir(&self.root)
                .env("GIT_NO_LAZY_FETCH", "1")
                .args(["cat-file", "blob", oid])
                .output()
                .map_err(|e| e.to_string())?;
            if !out.status.success() {
                return Err(format!("cannot read blob {oid}"));
            }
            self.blobs.insert(oid.to_string(), out.stdout);
        }
        Ok(&self.blobs[oid])
    }
    pub fn read(&mut self, path: &str) -> Result<Option<Vec<u8>>, String> {
        match self.entry(path).cloned() {
            Some(Entry::Blob(oid)) => Ok(Some(self.blob(&oid)?.to_vec())),
            Some(_) => Err(format!("{path} is not a file")),
            None => Ok(None),
        }
    }
}
