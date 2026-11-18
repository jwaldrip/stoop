//! Downloaded GitHub Action tree witnesses.

use crate::gha::resolve::{self, Resolver};
use crate::gha::workflow;
use crate::plan::spec::Code;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::{Duration, Instant};

/// A shared limit across the whole graph, rather than a timeout per action.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(90);
pub const MAX_COMPRESSED: usize = 64 * 1024 * 1024;
const MAX_UNPACKED: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 30_000;
const MAX_PATH: usize = 4096;
const MAX_ACTIONS: usize = 256;
const MAX_DEPTH: usize = 16;
pub const WITNESS_KEY: &str = "!stoop-action-trees-v1";

#[derive(Clone, Debug)]
struct File {
    executable: bool,
    bytes: Vec<u8>,
}

/// Only ordinary files are accepted. Paths, executable bits, and contents all
/// contribute to the digest; archive order and archive metadata do not.
#[derive(Clone, Debug, Default)]
pub struct Tree {
    files: BTreeMap<String, File>,
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH
        && !path.contains(['\\', '\0', ':'])
        && !path.starts_with('/')
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

fn read_bounded(
    mut reader: impl Read,
    expected: u64,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 32 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err("action verification timed out".into());
        }
        let n = reader
            .read(&mut chunk)
            .map_err(|e| format!("cannot read action content: {e}"))?;
        if n == 0 {
            break;
        }
        if bytes.len() as u64 + n as u64 > expected {
            return Err("action content exceeded its declared size".into());
        }
        bytes.extend_from_slice(&chunk[..n]);
    }
    if bytes.len() as u64 != expected {
        return Err("action content changed or was truncated while reading".into());
    }
    Ok(bytes)
}

impl Tree {
    #[cfg(test)]
    pub fn from_gzip(bytes: &[u8]) -> Result<Self, String> {
        Self::from_gzip_before(bytes, Instant::now() + TOTAL_TIMEOUT)
    }

    pub fn from_gzip_before(bytes: &[u8], deadline: Instant) -> Result<Self, String> {
        if bytes.len() > MAX_COMPRESSED {
            return Err("action archive exceeds the compressed size limit".into());
        }
        Self::from_tar_before(
            flate2::read::GzDecoder::new(Cursor::new(bytes)),
            true,
            deadline,
        )
    }

    pub fn from_tar_before(
        reader: impl Read,
        strip_root: bool,
        deadline: Instant,
    ) -> Result<Self, String> {
        let max_tar = MAX_UNPACKED + (MAX_ENTRIES as u64 * 1024) + 16 * 1024 * 1024;
        let mut archive = tar::Archive::new(reader.take(max_tar));
        let mut tree = Self::default();
        let mut size = 0u64;
        let mut count = 0usize;
        let mut root: Option<String> = None;
        for entry in archive
            .entries()
            .map_err(|e| format!("invalid action archive: {e}"))?
        {
            if Instant::now() >= deadline {
                return Err("action verification timed out".into());
            }
            let mut entry = entry.map_err(|e| format!("invalid action archive entry: {e}"))?;
            count += 1;
            if count > MAX_ENTRIES {
                return Err("action archive exceeds the entry limit".into());
            }
            if entry.header().entry_type().is_pax_global_extensions() {
                if count != 1
                    || entry.path_bytes().as_ref() != b"pax_global_header"
                    || entry.size() != 52
                {
                    return Err("unsupported global action archive metadata".into());
                }
                let comment = read_bounded(&mut entry, 52, deadline)?;
                if !comment.starts_with(b"52 comment=")
                    || comment[51] != b'\n'
                    || !comment[11..51]
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                {
                    return Err("unsupported global action archive metadata".into());
                }
                continue;
            }
            let name = String::from_utf8(entry.path_bytes().into_owned())
                .map_err(|_| "action archive has a non-UTF-8 path")?;
            let name = name.trim_end_matches('/');
            if !valid_path(name) {
                return Err(format!("invalid action archive path {name:?}"));
            }
            let name = if strip_root {
                let (head, rest) = name.split_once('/').unwrap_or((name, ""));
                match &root {
                    Some(expected) if expected != head => {
                        return Err("action archive contains multiple roots".into());
                    }
                    None => root = Some(head.to_owned()),
                    _ => {}
                }
                rest
            } else {
                name
            };
            let kind = entry.header().entry_type();
            if kind.is_dir() {
                continue;
            }
            if !kind.is_file() || name.is_empty() {
                return Err("action archive contains an unsupported entry".into());
            }
            if name.split('/').any(|part| part == ".gitmodules") {
                return Err("action repository declares submodules".into());
            }
            let len = entry.size();
            size = size
                .checked_add(len)
                .ok_or("action archive size overflow")?;
            if size > MAX_UNPACKED {
                return Err("action archive exceeds the unpacked size limit".into());
            }
            let executable = entry.header().mode().map_err(|e| e.to_string())? & 0o111 != 0;
            let bytes = read_bounded(&mut entry, len, deadline)?;
            if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
                return Err(format!(
                    "action file {name} is an unresolved Git LFS pointer"
                ));
            }
            if tree
                .files
                .insert(name.to_owned(), File { executable, bytes })
                .is_some()
            {
                return Err(format!("duplicate action archive path {name}"));
            }
        }
        if tree.files.is_empty() {
            return Err("action archive contains no files".into());
        }
        Ok(tree)
    }

    #[cfg(test)]
    pub fn from_directory(root: &Path) -> Result<Self, String> {
        Self::from_directory_before(root, Instant::now() + TOTAL_TIMEOUT)
    }

    pub fn from_directory_before(root: &Path, deadline: Instant) -> Result<Self, String> {
        fn walk(
            root: &Path,
            dir: &Path,
            tree: &mut Tree,
            count: &mut usize,
            size: &mut u64,
            deadline: Instant,
        ) -> Result<(), String> {
            for entry in
                fs::read_dir(dir).map_err(|e| format!("cannot read runner action copy: {e}"))?
            {
                if Instant::now() >= deadline {
                    return Err("action verification timed out".into());
                }
                let entry = entry.map_err(|e| e.to_string())?;
                *count += 1;
                if *count > MAX_ENTRIES {
                    return Err("runner action copy exceeds the entry limit".into());
                }
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
                if metadata.file_type().is_symlink() {
                    return Err("runner action copy contains an unsupported symlink".into());
                }
                let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
                let name = relative
                    .to_str()
                    .ok_or("runner action copy has a non-UTF-8 path")?;
                if !valid_path(name) {
                    return Err(format!("invalid runner action path {name:?}"));
                }
                if name.split('/').any(|part| part == ".gitmodules") {
                    return Err("runner action copy declares submodules".into());
                }
                if metadata.is_dir() {
                    walk(root, &path, tree, count, size, deadline)?;
                } else if metadata.is_file() {
                    *size = size
                        .checked_add(metadata.len())
                        .ok_or("runner copy size overflow")?;
                    if *size > MAX_UNPACKED {
                        return Err("runner action copy exceeds the size limit".into());
                    }
                    let mut options = fs::OpenOptions::new();
                    options.read(true);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
                        if metadata.nlink() != 1 {
                            return Err("runner action copy contains a hard-linked file".into());
                        }
                        options.custom_flags(libc::O_NOFOLLOW);
                    }
                    let mut file = options.open(&path).map_err(|e| e.to_string())?;
                    let opened = file.metadata().map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
                            return Err("runner action copy changed while opening".into());
                        }
                    }
                    let bytes = read_bounded(
                        (&mut file).take(metadata.len() + 1),
                        metadata.len(),
                        deadline,
                    )?;
                    let after = file.metadata().map_err(|e| e.to_string())?;
                    if opened.len() != metadata.len()
                        || after.len() != metadata.len()
                        || opened.modified().ok() != after.modified().ok()
                    {
                        return Err("runner action copy changed while reading".into());
                    }
                    if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
                        return Err(format!("runner action file {name} is a Git LFS pointer"));
                    }
                    #[cfg(unix)]
                    let executable = {
                        use std::os::unix::fs::PermissionsExt;
                        metadata.permissions().mode() & 0o111 != 0
                    };
                    #[cfg(not(unix))]
                    let executable = false;
                    tree.files.insert(
                        name.replace(std::path::MAIN_SEPARATOR, "/"),
                        File { executable, bytes },
                    );
                } else {
                    return Err("runner action copy contains an unsupported entry".into());
                }
            }
            Ok(())
        }
        if fs::symlink_metadata(root)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
        {
            return Err("runner action directory is a symlink".into());
        }
        let mut tree = Self::default();
        walk(root, root, &mut tree, &mut 0, &mut 0, deadline)?;
        if tree.files.is_empty() {
            return Err("runner action copy contains no files".into());
        }
        Ok(tree)
    }

    pub fn subtree(&self, prefix: &str) -> Result<Self, String> {
        if !valid_path(prefix) {
            return Err(format!("invalid local action path {prefix:?}"));
        }
        let prefix = format!("{prefix}/");
        let files = self
            .files
            .iter()
            .filter_map(|(path, file)| {
                path.strip_prefix(&prefix)
                    .map(|relative| (relative.to_owned(), file.clone()))
            })
            .collect();
        let tree = Self { files };
        if tree.files.is_empty() {
            return Err("local action is absent from the target revision".into());
        }
        Ok(tree)
    }

    pub fn digest(&self) -> String {
        let mut hash = blake3::Hasher::new();
        hash.update(b"stoop-action-tree-v1\0");
        for (path, file) in &self.files {
            hash.update(&(path.len() as u64).to_be_bytes());
            hash.update(path.as_bytes());
            hash.update(&[u8::from(file.executable)]);
            hash.update(&(file.bytes.len() as u64).to_be_bytes());
            hash.update(&file.bytes);
        }
        format!("b3:{}", hash.finalize().to_hex())
    }

    pub fn nested(&self, path: &str) -> Result<Vec<String>, String> {
        if !path.is_empty() && !valid_path(path) {
            return Err(format!("invalid action subdirectory {path:?}"));
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let file = self
            .files
            .get(&format!("{prefix}action.yml"))
            .or_else(|| self.files.get(&format!("{prefix}action.yaml")))
            .ok_or("action metadata is absent")?;
        if file.bytes.len() > 1024 * 1024 {
            return Err("action metadata exceeds the size limit".into());
        }
        let text = std::str::from_utf8(&file.bytes).map_err(|_| "action metadata is not UTF-8")?;
        let metadata = workflow::parse_document(text)?;
        let runs = metadata
            .get("runs")
            .and_then(|v| v.as_object())
            .ok_or("action metadata has no runs")?;
        let using = runs
            .get("using")
            .and_then(|v| v.as_str())
            .ok_or("action metadata has no static runs.using")?;
        match using.to_ascii_lowercase().as_str() {
            "composite" => {
                let steps = runs
                    .get("steps")
                    .and_then(|v| v.as_array())
                    .ok_or("composite action has no steps")?;
                let mut refs = Vec::new();
                for step in steps {
                    let step = step
                        .as_object()
                        .ok_or("composite action step is not an object")?;
                    if let Some(value) = step.get("uses") {
                        let raw = value
                            .as_str()
                            .filter(|s| !s.contains("${{"))
                            .ok_or("composite action has a dynamic uses")?;
                        refs.push(raw.to_owned());
                    } else if !step.get("run").is_some_and(|v| v.as_str().is_some()) {
                        return Err("composite action step has neither uses nor run".into());
                    }
                }
                Ok(refs)
            }
            "node12" | "node16" | "node20" | "node24" => {
                for key in ["main", "pre", "post"] {
                    if let Some(value) = runs.get(key) {
                        let path = value
                            .as_str()
                            .filter(|p| valid_path(p))
                            .ok_or("invalid action entrypoint")?;
                        if !self.files.contains_key(&format!("{prefix}{path}")) {
                            return Err(format!("action entrypoint {path} is absent"));
                        }
                    } else if key == "main" {
                        return Err("action main entrypoint is absent".into());
                    }
                }
                Ok(Vec::new())
            }
            "docker" => {
                let image = runs
                    .get("image")
                    .and_then(|v| v.as_str())
                    .ok_or("docker action has no static image")?;
                docker_digest(image)?;
                Ok(vec![image.to_owned()])
            }
            _ => Err(format!("unsupported action runtime {using}")),
        }
    }
}

pub fn docker_digest(raw: &str) -> Result<String, String> {
    let image = raw
        .strip_prefix("docker://")
        .ok_or("docker action must name a digest-pinned image")?;
    let (name, digest) = image
        .rsplit_once("@sha256:")
        .ok_or("docker action image has no sha256 digest")?;
    if name.is_empty()
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("docker action image has an invalid sha256 digest".into());
    }
    Ok(format!("sha256:{digest}"))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Witness {
    sha: String,
    digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Witnesses {
    version: u32,
    roots: Vec<String>,
    items: BTreeMap<String, Witness>,
}

struct Walk<'a> {
    resolver: &'a dyn Resolver,
    deadline: Instant,
    recorded: Option<&'a Witnesses>,
    items: BTreeMap<String, Witness>,
    active: BTreeSet<String>,
    strict: bool,
}

impl Walk<'_> {
    fn visit(&mut self, raw: &str, depth: usize) -> Result<(), (Code, String)> {
        let bad = |message: String| (Code::ActionUnverifiable, format!("action {raw}: {message}"));
        if Instant::now() >= self.deadline {
            return Err(bad("verification exceeded the total timeout".into()));
        }
        if self.items.contains_key(raw) {
            return Ok(());
        }
        if depth > MAX_DEPTH || self.items.len() + self.active.len() >= MAX_ACTIONS {
            return Err(bad("action dependency graph exceeds its limit".into()));
        }
        if !self.active.insert(raw.to_owned()) {
            return Err(bad("cyclic composite actions".into()));
        }
        let old = self
            .recorded
            .map(|w| {
                w.items
                    .get(raw)
                    .ok_or_else(|| bad("record has no content witness".into()))
            })
            .transpose()?;
        let (sha, digest, nested) = if raw.starts_with("docker://") {
            let digest = docker_digest(raw).map_err(bad)?;
            (digest.clone(), digest, Vec::new())
        } else if let Some(path) = raw.strip_prefix("./") {
            if !valid_path(path) {
                return Err(bad("invalid local action path".into()));
            }
            let (sha, tree) = self.resolver.local_tree(path, self.deadline).map_err(bad)?;
            if let Some(old) = old {
                if old.sha != sha {
                    return Err((
                        Code::ActionMoved,
                        format!("local action {raw} is at {sha}, recorded at {}", old.sha),
                    ));
                }
            }
            let digest = tree.digest();
            if old.is_some_and(|w| w.digest != digest) {
                return Err((
                    Code::ActionContentChanged,
                    format!("action {raw} content differs from the recorded copy"),
                ));
            }
            if self.recorded.is_none() {
                let copy = self.resolver.local_copy(path, self.deadline).map_err(bad)?;
                if copy.digest() != digest {
                    return Err(bad(
                        "local action copy differs from the committed tree".into()
                    ));
                }
            }
            let nested = tree.nested("").map_err(bad)?;
            (sha, digest, nested)
        } else {
            let (name, reference) = raw
                .rsplit_once('@')
                .ok_or_else(|| bad("action has no ref".into()))?;
            let mut parts = name.split('/');
            let owner = parts.next().unwrap_or("");
            let repo = parts.next().unwrap_or("");
            let path = parts.collect::<Vec<_>>().join("/");
            let action = resolve::classify(raw).map_err(bad)?;
            if self.strict && !matches!(&action, resolve::Action::Pinned(_)) {
                return Err(bad("strict mode requires a full commit SHA".into()));
            }
            let sha = match action {
                resolve::Action::Pinned(sha) => sha,
                resolve::Action::Remote {
                    owner,
                    repo,
                    reference,
                } => self
                    .resolver
                    .commit_before(&owner, &repo, &reference, self.deadline)
                    .map_err(bad)?,
            };
            if let Some(old) = old {
                if old.sha != sha {
                    return Err((
                        Code::ActionMoved,
                        format!("action {raw} resolves to {sha}, recorded as {}", old.sha),
                    ));
                }
            }
            let tree = self
                .resolver
                .action_tree(owner, repo, &sha, self.deadline)
                .map_err(bad)?;
            let digest = tree.digest();
            if old.is_some_and(|w| w.digest != digest) {
                return Err((
                    Code::ActionContentChanged,
                    format!("action {raw} content differs from the recorded copy"),
                ));
            }
            if self.recorded.is_none() {
                let copy = self
                    .resolver
                    .runner_copy(owner, repo, reference, self.deadline)
                    .map_err(bad)?;
                if copy.digest() != digest {
                    return Err(bad(
                        "runner action copy differs from the downloaded tree".into()
                    ));
                }
            }
            let nested = tree.nested(&path).map_err(bad)?;
            (sha, digest, nested)
        };
        if let Some(old) = old {
            if old.sha != sha {
                return Err((
                    Code::ActionMoved,
                    format!("action {raw} resolves to {sha}, recorded as {}", old.sha),
                ));
            }
            if old.digest != digest {
                return Err((
                    Code::ActionContentChanged,
                    format!("action {raw} content differs from the recorded copy"),
                ));
            }
        }
        for child in nested {
            self.visit(&child, depth + 1)?;
        }
        self.active.remove(raw);
        self.items.insert(raw.to_owned(), Witness { sha, digest });
        Ok(())
    }
}

fn roots(uses: &[String]) -> Vec<String> {
    uses.iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Failed capture returns no witness, so the journal can never authorize a skip.
pub fn capture(
    uses: &[String],
    resolver: &dyn Resolver,
    strict: bool,
) -> Result<BTreeMap<String, String>, String> {
    let roots = roots(uses);
    let mut walk = Walk {
        resolver,
        deadline: Instant::now() + TOTAL_TIMEOUT,
        recorded: None,
        items: BTreeMap::new(),
        active: BTreeSet::new(),
        strict,
    };
    for raw in &roots {
        walk.visit(raw, 0).map_err(|(_, detail)| detail)?;
    }
    let mut actions = BTreeMap::new();
    for (raw, witness) in &walk.items {
        actions.insert(raw.clone(), witness.sha.clone());
    }
    let witnesses = Witnesses {
        version: 1,
        roots,
        items: walk.items,
    };
    actions.insert(
        WITNESS_KEY.into(),
        serde_json::to_string(&witnesses).map_err(|e| e.to_string())?,
    );
    Ok(actions)
}

pub fn verify(
    uses: &[String],
    actions: &BTreeMap<String, String>,
    resolver: &dyn Resolver,
    strict: bool,
    deadline: Instant,
) -> Result<(), (Code, String)> {
    let invalid = |message: &str| (Code::ActionUnverifiable, message.to_owned());
    let text = actions
        .get(WITNESS_KEY)
        .ok_or_else(|| invalid("record has no action content witness"))?;
    let witnesses: Witnesses = serde_json::from_str(text)
        .map_err(|_| invalid("record has an invalid action content witness"))?;
    let roots = roots(uses);
    if witnesses.version != 1 || witnesses.roots != roots {
        return Err(invalid("record action roots do not match the job"));
    }
    let mut walk = Walk {
        resolver,
        deadline,
        recorded: Some(&witnesses),
        items: BTreeMap::new(),
        active: BTreeSet::new(),
        strict,
    };
    for raw in &roots {
        walk.visit(raw, 0)?;
    }
    if walk.items.len() != witnesses.items.len() {
        return Err(invalid(
            "record action graph does not match the downloaded actions",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) struct FixtureServer {
    pub url: String,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl FixtureServer {
    pub fn new(root: std::path::PathBuf) -> Self {
        use std::sync::atomic::Ordering;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = std::thread::spawn(move || {
            use std::io::{BufRead, BufReader, Write};
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap_or(0);
                        let target = line.split_whitespace().nth(1).unwrap_or("");
                        let relative = target.strip_prefix('/').filter(|p| valid_path(p));
                        let body = relative.and_then(|p| fs::read(root.join(p)).ok());
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                                break;
                            }
                        }
                        match body {
                            Some(bytes) => {
                                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", bytes.len());
                                let _ = stream.write_all(&bytes);
                            }
                            None => {
                                let _ = write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            }
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        Self {
            url,
            stop,
            thread: Some(thread),
        }
    }
}

#[cfg(test)]
impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

#[cfg(test)]
pub(crate) fn fixture_archive() -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (name, contents) in [
        (
            "action.yml",
            &b"runs:\n  using: node20\n  main: index.js\n"[..],
        ),
        ("index.js", &b"fixture\n"[..]),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, format!("repo-sha/{name}"), contents)
            .unwrap();
    }
    tar.into_inner().unwrap().finish().unwrap()
}

#[cfg(test)]
pub(crate) fn fixture_tree() -> Tree {
    Tree::from_gzip(&fixture_archive()).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn archive(files: &[(&str, &[u8])]) -> Vec<u8> {
        let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut tar = tar::Builder::new(gz);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, format!("repo-sha/{name}"), *contents)
                .unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[derive(Default)]
    struct Source {
        refs: std::cell::RefCell<BTreeMap<String, String>>,
        trees: std::cell::RefCell<BTreeMap<String, Tree>>,
        copies: std::cell::RefCell<BTreeMap<String, Tree>>,
    }
    impl Source {
        fn add(&self, name: &str, sha: &str, tree: Tree) {
            self.refs
                .borrow_mut()
                .insert(format!("{name}@v1"), sha.into());
            self.copies.borrow_mut().insert(name.into(), tree.clone());
            self.trees.borrow_mut().insert(name.into(), tree);
        }
    }
    impl Resolver for Source {
        fn commit(&self, owner: &str, repo: &str, reference: &str) -> Result<String, String> {
            self.refs
                .borrow()
                .get(&format!("{owner}/{repo}@{reference}"))
                .cloned()
                .ok_or("missing ref".into())
        }
        fn action_tree(
            &self,
            owner: &str,
            repo: &str,
            _: &str,
            _: Instant,
        ) -> Result<std::rc::Rc<Tree>, String> {
            self.trees
                .borrow()
                .get(&format!("{owner}/{repo}"))
                .cloned()
                .map(std::rc::Rc::new)
                .ok_or("missing tree".into())
        }
        fn runner_copy(
            &self,
            owner: &str,
            repo: &str,
            _: &str,
            _: Instant,
        ) -> Result<Tree, String> {
            self.copies
                .borrow()
                .get(&format!("{owner}/{repo}"))
                .cloned()
                .ok_or("missing copy".into())
        }
    }

    #[test]
    fn action_paths_reject_traversal_and_platform_escapes() {
        assert!(valid_path("nested/action.yml"));
        for invalid in [
            "",
            "../secret",
            "nested/../secret",
            "/absolute",
            "nested//action.yml",
            "nested/./action.yml",
            "nested\\action.yml",
            "C:/action.yml",
            "nul\0byte",
            &"x".repeat(MAX_PATH + 1),
        ] {
            assert!(!valid_path(invalid), "accepted {invalid:?}");
        }
    }

    #[test]
    fn archives_reject_submodules_and_lfs_pointers() {
        let submodule = archive(&[(".gitmodules", b"[submodule \"x\"]\n")]);
        assert!(Tree::from_gzip(&submodule)
            .unwrap_err()
            .contains("submodules"));
        let lfs = archive(&[(
            "index.js",
            b"version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 9\n",
        )]);
        assert!(Tree::from_gzip(&lfs).unwrap_err().contains("Git LFS"));
    }

    #[test]
    fn archives_reject_duplicate_file_paths() {
        let duplicate = archive(&[("index.js", b"first"), ("index.js", b"second")]);
        assert!(Tree::from_gzip(&duplicate)
            .unwrap_err()
            .contains("duplicate"));
    }

    #[test]
    fn archives_bound_unpacked_bytes_and_entry_count() {
        let mut header = tar::Header::new_ustar();
        header.set_path("big").unwrap();
        header.set_mode(0o644);
        header.set_size(MAX_UNPACKED + 1);
        header.set_cksum();
        let archive = Cursor::new(header.as_bytes().to_vec())
            .chain(std::io::repeat(0).take(MAX_UNPACKED + 1))
            .chain(std::io::repeat(0).take(511 + 1024));
        let result = Tree::from_tar_before(archive, false, Instant::now() + TOTAL_TIMEOUT);
        assert!(
            matches!(&result, Err(reason) if reason.contains("unpacked size")),
            "oversized uncompressed archive was not refused"
        );

        let mut archive = tar::Builder::new(Vec::new());
        let mut file = tar::Header::new_ustar();
        file.set_mode(0o644);
        file.set_size(1);
        file.set_cksum();
        archive.append_data(&mut file, "file", &b"x"[..]).unwrap();
        for index in 0..MAX_ENTRIES {
            let mut dir = tar::Header::new_ustar();
            dir.set_entry_type(tar::EntryType::Directory);
            dir.set_mode(0o755);
            dir.set_size(0);
            dir.set_cksum();
            archive
                .append_data(&mut dir, format!("d{index}/"), &[][..])
                .unwrap();
        }
        let bytes = archive.into_inner().unwrap();
        assert!(
            Tree::from_tar_before(Cursor::new(bytes), false, Instant::now() + TOTAL_TIMEOUT)
                .unwrap_err()
                .contains("entry limit")
        );
    }

    #[test]
    fn composite_graph_rejects_cycles_and_excessive_depth() {
        fn composite(child: &str) -> Tree {
            let metadata = format!("runs:\n  using: composite\n  steps:\n    - uses: {child}\n");
            Tree::from_gzip(&archive(&[("action.yml", metadata.as_bytes())])).unwrap()
        }
        let source = Source::default();
        let sha = "1111111111111111111111111111111111111111";
        source.add("owner/a", sha, composite("owner/b@v1"));
        source.add("owner/b", sha, composite("owner/a@v1"));
        assert!(capture(&["owner/a@v1".into()], &source, false)
            .unwrap_err()
            .contains("cyclic"));

        let source = Source::default();
        for index in 0..=MAX_DEPTH {
            source.add(
                &format!("owner/n{index}"),
                sha,
                composite(&format!("owner/n{}@v1", index + 1)),
            );
        }
        source.add(&format!("owner/n{}", MAX_DEPTH + 1), sha, fixture_tree());
        assert!(capture(&["owner/n0@v1".into()], &source, false)
            .unwrap_err()
            .contains("graph exceeds"));
    }

    #[test]
    fn composite_graph_counts_active_parents_toward_the_limit() {
        let source = Source::default();
        let sha = "1111111111111111111111111111111111111111";
        let mut metadata = String::from("runs:\n  using: composite\n  steps:\n");
        for index in 0..(MAX_ACTIONS - 1) {
            metadata.push_str(&format!("    - uses: owner/c{index}@v1\n"));
            source.add(&format!("owner/c{index}"), sha, fixture_tree());
        }
        let at_limit = Tree::from_gzip(&archive(&[("action.yml", metadata.as_bytes())])).unwrap();
        source.add("owner/parent", sha, at_limit);
        assert!(capture(&["owner/parent@v1".into()], &source, false).is_ok());
        metadata.push_str(&format!("    - uses: owner/c{}@v1\n", MAX_ACTIONS - 1));
        source.add(&format!("owner/c{}", MAX_ACTIONS - 1), sha, fixture_tree());
        let parent = Tree::from_gzip(&archive(&[("action.yml", metadata.as_bytes())])).unwrap();
        source.add("owner/parent", sha, parent);
        let result = capture(&["owner/parent@v1".into()], &source, false);
        assert!(
            matches!(&result, Err(reason) if reason.contains("graph exceeds")),
            "oversized composite action graph was not refused"
        );
    }

    #[test]
    fn unexpected_witness_graph_entries_are_refused() {
        let source = Source::default();
        source.add(
            "owner/tool",
            "1111111111111111111111111111111111111111",
            fixture_tree(),
        );
        let refs = vec!["owner/tool@v1".to_owned()];
        let mut record = capture(&refs, &source, false).unwrap();
        let mut witness: Witnesses = serde_json::from_str(&record[WITNESS_KEY]).unwrap();
        let extra = witness.items["owner/tool@v1"].clone();
        witness.items.insert("owner/extra@v1".into(), extra);
        record.insert(WITNESS_KEY.into(), serde_json::to_string(&witness).unwrap());
        let (code, detail) = verify(
            &refs,
            &record,
            &source,
            false,
            Instant::now() + TOTAL_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(code, Code::ActionUnverifiable);
        assert!(detail.contains("graph"));
    }

    #[test]
    fn unchanged_then_moved_and_tampered_actions_are_distinct() {
        let source = Source::default();
        let first = "1111111111111111111111111111111111111111";
        let second = "2222222222222222222222222222222222222222";
        source.add("owner/tool", first, fixture_tree());
        let refs = vec!["owner/tool@v1".to_owned()];
        let witness = capture(&refs, &source, false).unwrap();
        let check = |source: &Source| {
            verify(
                &refs,
                &witness,
                source,
                false,
                Instant::now() + TOTAL_TIMEOUT,
            )
        };
        assert!(check(&source).is_ok());
        source
            .refs
            .borrow_mut()
            .insert("owner/tool@v1".into(), second.into());
        assert_eq!(check(&source).unwrap_err().0, Code::ActionMoved);
        source
            .refs
            .borrow_mut()
            .insert("owner/tool@v1".into(), first.into());
        let changed = Tree::from_gzip(&archive(&[
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
            ("index.js", b"tampered"),
        ]))
        .unwrap();
        source
            .trees
            .borrow_mut()
            .insert("owner/tool".into(), changed);
        assert_eq!(check(&source).unwrap_err().0, Code::ActionContentChanged);
    }

    #[test]
    fn recording_refuses_missing_or_tampered_runner_copy() {
        let source = Source::default();
        source.add(
            "owner/tool",
            "1111111111111111111111111111111111111111",
            fixture_tree(),
        );
        let refs = vec!["owner/tool@v1".to_owned()];
        assert!(capture(&refs, &source, false).is_ok());
        let changed = Tree::from_gzip(&archive(&[
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
            ("index.js", b"tampered"),
        ]))
        .unwrap();
        source
            .copies
            .borrow_mut()
            .insert("owner/tool".into(), changed);
        assert!(capture(&refs, &source, false)
            .unwrap_err()
            .contains("runner action copy differs"));
        source.copies.borrow_mut().clear();
        assert!(capture(&refs, &source, false).is_err());
    }

    #[test]
    fn nested_composite_action_movement_blocks_the_parent() {
        let source = Source::default();
        let composite = Tree::from_gzip(&archive(&[(
            "action.yml",
            b"runs:\n  using: composite\n  steps:\n    - uses: owner/child@v1\n",
        )]))
        .unwrap();
        source.add(
            "owner/parent",
            "1111111111111111111111111111111111111111",
            composite,
        );
        source.add(
            "owner/child",
            "2222222222222222222222222222222222222222",
            fixture_tree(),
        );
        let refs = vec!["owner/parent@v1".to_owned()];
        let witness = capture(&refs, &source, false).unwrap();
        assert!(verify(
            &refs,
            &witness,
            &source,
            false,
            Instant::now() + TOTAL_TIMEOUT
        )
        .is_ok());
        source.refs.borrow_mut().insert(
            "owner/child@v1".into(),
            "3333333333333333333333333333333333333333".into(),
        );
        let (code, detail) = verify(
            &refs,
            &witness,
            &source,
            false,
            Instant::now() + TOTAL_TIMEOUT,
        )
        .unwrap_err();
        assert_eq!(code, Code::ActionMoved);
        assert!(detail.contains("owner/child@v1"));
    }

    #[test]
    fn deadline_and_unpinned_docker_ref_fail_wide() {
        let source = Source::default();
        source.add(
            "owner/tool",
            "1111111111111111111111111111111111111111",
            fixture_tree(),
        );
        let refs = vec!["owner/tool@v1".to_owned()];
        let witness = capture(&refs, &source, false).unwrap();
        assert_eq!(
            verify(&refs, &witness, &source, false, Instant::now())
                .unwrap_err()
                .0,
            Code::ActionUnverifiable
        );
        assert!(capture(&["docker://alpine:latest".into()], &source, false).is_err());
    }

    #[test]
    fn tar_digest_is_order_independent_and_tracks_bytes_and_mode() {
        let first = archive(&[
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
            ("index.js", b"one"),
        ]);
        let reordered = archive(&[
            ("index.js", b"one"),
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
        ]);
        let changed = archive(&[
            ("index.js", b"two"),
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
        ]);
        let a = Tree::from_gzip(&first).unwrap();
        assert_eq!(a.digest(), Tree::from_gzip(&reordered).unwrap().digest());
        assert_ne!(a.digest(), Tree::from_gzip(&changed).unwrap().digest());
    }

    #[test]
    fn oversized_and_unsupported_archive_entries_fail_wide() {
        let mut raw = vec![0; MAX_COMPRESSED + 1];
        assert!(Tree::from_gzip(&raw).unwrap_err().contains("size"));
        raw.clear();
        for kind in [
            tar::EntryType::Symlink,
            tar::EntryType::Link,
            tar::EntryType::Char,
            tar::EntryType::Block,
            tar::EntryType::Fifo,
        ] {
            let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            let mut tar = tar::Builder::new(gz);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(0);
            header.set_mode(0o777);
            if matches!(kind, tar::EntryType::Symlink | tar::EntryType::Link) {
                header.set_link_name("../outside").unwrap();
            }
            header.set_cksum();
            tar.append_data(&mut header, "repo-sha/link", &[][..])
                .unwrap();
            let bytes = tar.into_inner().unwrap().finish().unwrap();
            assert!(Tree::from_gzip(&bytes).unwrap_err().contains("unsupported"));
        }
    }

    #[test]
    fn git_archive_comment_is_accepted_and_other_global_metadata_is_refused() {
        fn with_global(value: &[u8]) -> Vec<u8> {
            let mut archive = tar::Builder::new(Vec::new());
            let mut header = tar::Header::new_ustar();
            header.set_entry_type(tar::EntryType::XGlobalHeader);
            header.set_mode(0o644);
            header.set_size(value.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, "pax_global_header", value)
                .unwrap();
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o644);
            header.set_size(1);
            header.set_cksum();
            archive.append_data(&mut header, "file", &b"x"[..]).unwrap();
            archive.into_inner().unwrap()
        }
        let comment = b"52 comment=1111111111111111111111111111111111111111\n";
        assert!(Tree::from_tar_before(
            Cursor::new(with_global(comment)),
            false,
            Instant::now() + TOTAL_TIMEOUT
        )
        .is_ok());
        assert!(Tree::from_tar_before(
            Cursor::new(with_global(b"13 path=evil\n")),
            false,
            Instant::now() + TOTAL_TIMEOUT
        )
        .is_err());
        for (index, byte) in [(3, b'p'), (11, b'G'), (51, b'!')] {
            let mut malformed = comment.to_vec();
            malformed[index] = byte;
            assert!(Tree::from_tar_before(
                Cursor::new(with_global(&malformed)),
                false,
                Instant::now() + TOTAL_TIMEOUT
            )
            .is_err());
        }
    }

    #[test]
    fn nested_composite_refs_are_enumerated_and_dynamic_refs_refused() {
        let body = b"name: fixture\nruns:\n  using: composite\n  steps:\n    - uses: owner/child@v1\n    - run: echo ok\n      shell: bash\n";
        let tree = Tree::from_gzip(&archive(&[("action.yml", body)])).unwrap();
        assert_eq!(tree.nested("").unwrap(), vec!["owner/child@v1"]);
        let dynamic = b"runs:\n  using: composite\n  steps:\n    - uses: '${{ inputs.action }}'\n";
        let tree = Tree::from_gzip(&archive(&[("action.yml", dynamic)])).unwrap();
        assert!(tree.nested("").is_err());
    }

    #[test]
    fn docker_images_need_a_sha256_digest() {
        assert!(docker_digest("docker://alpine:latest").is_err());
        let pinned = format!("docker://alpine@sha256:{}", "1".repeat(64));
        assert_eq!(
            docker_digest(&pinned).unwrap(),
            format!("sha256:{}", "1".repeat(64))
        );
    }

    #[test]
    fn runner_copy_must_match_the_downloaded_tree() {
        let temp = std::env::temp_dir().join(format!(
            "stoop-action-copy-{}-{}",
            std::process::id(),
            crate::proof::now()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        std::fs::File::create(temp.join("action.yml"))
            .unwrap()
            .write_all(b"runs:\n  using: node20\n  main: index.js\n")
            .unwrap();
        std::fs::write(temp.join("index.js"), b"one").unwrap();
        let tree = Tree::from_gzip(&archive(&[
            ("action.yml", b"runs:\n  using: node20\n  main: index.js\n"),
            ("index.js", b"one"),
        ]))
        .unwrap();
        assert_eq!(tree.digest(), Tree::from_directory(&temp).unwrap().digest());
        std::fs::write(temp.join("index.js"), b"tampered").unwrap();
        assert_ne!(tree.digest(), Tree::from_directory(&temp).unwrap().digest());
        #[cfg(unix)]
        {
            std::fs::hard_link(temp.join("index.js"), temp.join("hardlink.js")).unwrap();
            assert!(Tree::from_directory(&temp)
                .unwrap_err()
                .contains("hard-linked"));
            std::fs::remove_file(temp.join("hardlink.js")).unwrap();
            std::os::unix::fs::symlink("index.js", temp.join("symlink.js")).unwrap();
            assert!(Tree::from_directory(&temp).unwrap_err().contains("symlink"));
            std::fs::remove_file(temp.join("symlink.js")).unwrap();
        }
        std::fs::write(
            temp.join("index.js"),
            b"version https://git-lfs.github.com/spec/v1\noid sha256:123\nsize 9\n",
        )
        .unwrap();
        assert!(Tree::from_directory(&temp).unwrap_err().contains("Git LFS"));
        std::fs::remove_dir_all(temp).unwrap();
    }
}
