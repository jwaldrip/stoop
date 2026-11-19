//! Evidence that hashing raw working-tree bytes is safe for Git object IDs.
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidBasis {
    pub text: Cow<'static, str>,
    pub eol: Cow<'static, str>,
    pub filter: Cow<'static, str>,
    pub ident: Cow<'static, str>,
    pub working_tree_encoding: Cow<'static, str>,
    pub export_subst: Cow<'static, str>,
    pub crlf: Cow<'static, str>,
    pub autocrlf: Cow<'static, str>,
}

impl OidBasis {
    /// Raw bytes are Git blob bytes only when no conversion is configured.
    pub fn allows_oid(&self) -> bool {
        [
            &self.text,
            &self.eol,
            &self.filter,
            &self.ident,
            &self.working_tree_encoding,
            &self.export_subst,
            &self.crlf,
        ]
        .iter()
        .all(|value| value.as_ref() == "unspecified")
            && (self.autocrlf == "unset"
                || self.autocrlf.eq_ignore_ascii_case("false")
                || self.autocrlf.eq_ignore_ascii_case("no")
                || self.autocrlf.eq_ignore_ascii_case("off")
                || self.autocrlf == "0")
    }
}

/// The Git and attribute state observed before tracing begins.
#[derive(Clone, Debug)]
pub struct Epoch {
    pub basis: HashMap<String, OidBasis>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub git_dir: PathBuf,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub common_dir: PathBuf,
    /// The names whose change can alter what Git reads for attributes or configuration.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub watch: Watch,
}

/// Git's attribute and configuration sources, resolved once before the run. Each name on the way
/// to a source counts (directories and symbolic links included), so renaming, removing or
/// replacing any of them changes what Git reads. A source that exists also counts by identity, so
/// a hard link to it does.
#[derive(Clone, Debug, Default)]
pub struct Watch {
    names: BTreeSet<PathBuf>,
    inodes: BTreeSet<(u64, u64)>,
}

impl Watch {
    /// Whether a namespace change at this physical name, or a write to a file there, can change
    /// what Git reads.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn names_contain(&self, physical: &Path) -> bool {
        self.names.contains(physical)
    }

    /// Whether this metadata is a watched file, whatever name it is reached by.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn is_watched_file(&self, metadata: &std::fs::Metadata) -> bool {
        metadata.is_file() && self.inodes.contains(&(metadata.dev(), metadata.ino()))
    }
}

// Limit every response, including large index and attribute reports. An
// oversized repository is unknown rather than evidence for an OID.
const MAX_OUTPUT: usize = 64 * 1024 * 1024;

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn safe_file_or_absent(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_file() && m.nlink() == 1,
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

fn safe_default_attributes() -> bool {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return false;
    };
    if !home.is_absolute() {
        return false;
    }
    let config_home = match std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
    {
        Some(path) if path.is_absolute() => path,
        Some(_) => return false,
        None => home.join(".config"),
    };
    safe_file_or_absent(&config_home.join("git/attributes"))
}

fn safe_dir_or_absent(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(m) => m.file_type().is_dir(),
        Err(e) => e.kind() == std::io::ErrorKind::NotFound,
    }
}

fn nul_fields(bytes: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    let (bytes, count) = if bytes.is_empty() {
        (bytes, 0)
    } else {
        (bytes.strip_suffix(&[0])?, usize::MAX)
    };
    Some(bytes.split(|b| *b == 0).take(count))
}

fn repo_dirs(root: &Path) -> Option<(PathBuf, PathBuf)> {
    let root = root.canonicalize().ok()?;
    let dot_git = root.join(".git");
    // Gitfiles, symlinks, separate gitdirs and linked worktrees need topology
    // tracking beyond a simple worktree. Decline them instead of guessing.
    if !std::fs::symlink_metadata(&dot_git)
        .ok()?
        .file_type()
        .is_dir()
        || !safe_file_or_absent(&dot_git.join("config"))
        || !safe_file_or_absent(&dot_git.join("config.worktree"))
        || !safe_file_or_absent(&dot_git.join("index"))
        || !safe_dir_or_absent(&dot_git.join("info"))
        || !safe_file_or_absent(&dot_git.join("info/attributes"))
    {
        return None;
    }
    let report = crate::gitprobe::output(
        &root,
        &[
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
            "--absolute-git-dir",
            "--git-common-dir",
            "--show-object-format",
        ],
        b"",
        MAX_OUTPUT,
    )?;
    let report = report.strip_suffix(b"\n")?;
    let mut lines = report.split(|byte| *byte == b'\n');
    let top = Path::new(OsStr::from_bytes(lines.next()?))
        .canonicalize()
        .ok()?;
    let git_dir = Path::new(OsStr::from_bytes(lines.next()?))
        .canonicalize()
        .ok()?;
    let common_dir = Path::new(OsStr::from_bytes(lines.next()?))
        .canonicalize()
        .ok()?;
    let format = lines.next()?;
    if lines.next().is_some()
        || format != b"sha1"
        || top != root
        || git_dir != dot_git.canonicalize().ok()?
        || common_dir != git_dir
    {
        return None;
    }
    Some((git_dir, common_dir))
}

// Git's human-readable states collide with literal attribute values. --all
// reports only present attributes, so escape these spellings and the escape
// prefix. No caller can confuse a present value with an absent attribute.
fn present_value(value: &str) -> Cow<'static, str> {
    match value {
        "set" => Cow::Borrowed("present:set"),
        "unset" => Cow::Borrowed("present:unset"),
        "unspecified" => Cow::Borrowed("present:unspecified"),
        _ if value.starts_with("present:") => Cow::Owned(format!("present:{value}")),
        _ => Cow::Owned(value.to_owned()),
    }
}

fn config(root: &Path) -> Option<String> {
    let report = crate::gitprobe::output(
        root,
        &[
            "config",
            "--null",
            "--list",
            "--no-includes",
            "--show-origin",
        ],
        b"",
        MAX_OUTPUT,
    )?;
    let mut fields = nul_fields(&report)?;
    let mut autocrlf = "unset".to_owned();
    while let Some(origin) = fields.next() {
        let entry = fields.next()?;
        let (key, value) = match entry.iter().position(|byte| *byte == b'\n') {
            Some(i) => (&entry[..i], &entry[i + 1..]),
            None => (entry, b"true".as_slice()),
        };
        // `git var -l` prints each entry as a line, so a value with a newline could forge a
        // `GIT_CONFIG_GLOBAL=` or `GIT_ATTR_GLOBAL=` line. No such value is trusted.
        if value.contains(&b'\n') {
            return None;
        }
        let key = std::str::from_utf8(key).ok()?.to_ascii_lowercase();
        if key.is_empty()
            || key == "core.attributesfile"
            || key == "attr.tree"
            || key == "core.worktree"
            || key.starts_with("include.")
            || key.starts_with("includeif.")
        {
            return None;
        }
        if let Some(path) = origin.strip_prefix(b"file:") {
            let path = Path::new(OsStr::from_bytes(path));
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            };
            // A config emitted by Git must still exist and must not redirect
            // to another file or be a FIFO.
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.file_type().is_file() || metadata.nlink() != 1 {
                return None;
            }
        } else if origin != b"command line:" {
            return None;
        }
        if key == "core.autocrlf" {
            let value = std::str::from_utf8(value).ok()?;
            autocrlf = present_value(value).into_owned();
        }
    }
    Some(autocrlf)
}

fn attributes_file(path: &str) -> bool {
    path == ".gitattributes" || path.ends_with("/.gitattributes")
}

#[derive(Default)]
struct Index {
    paths: HashSet<String>,
    gitlinks: HashSet<String>,
    // Tracked attribute files. Git can read one from the index when its worktree
    // copy is missing, as in a sparse checkout, so each is checked below.
    attribute_files: HashSet<String>,
}

fn index_paths(root: &Path) -> Option<Index> {
    let report = crate::gitprobe::output(root, &["ls-files", "--stage", "-z"], b"", MAX_OUTPUT)?;
    let mut index = Index::default();
    for entry in nul_fields(&report)? {
        let tab = entry.iter().position(|byte| *byte == b'\t')?;
        let mut header = entry[..tab].split(|byte| *byte == b' ');
        let mode = header.next()?;
        let oid = header.next()?;
        let stage = header.next()?;
        if header.next().is_some()
            || oid.len() != 40
            || !oid.iter().all(u8::is_ascii_hexdigit)
            || stage != b"0"
        {
            return None;
        }
        let path = std::str::from_utf8(&entry[tab + 1..])
            .ok()
            .filter(|path| valid_path(path));
        match mode {
            b"160000" => {
                // Everything beneath a gitlink is excluded. A gitlink whose name cannot be
                // represented would leave its scope unknown, so the whole snapshot fails.
                let path = path?;
                if attributes_file(path)
                    || index.paths.contains(path)
                    || !index.gitlinks.insert(path.to_owned())
                {
                    return None;
                }
            }
            b"100644" | b"100755" | b"120000" => {
                // A path that cannot be represented has no evidence and so no OID.
                let Some(path) = path else { continue };
                if attributes_file(path) {
                    if mode == b"120000" {
                        return None;
                    }
                    index.attribute_files.insert(path.to_owned());
                }
                if !index.paths.insert(path.to_owned()) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    Some(index)
}

fn beneath_gitlink(path: &str, gitlinks: &HashSet<String>) -> bool {
    gitlinks.contains(path)
        || path
            .match_indices('/')
            .any(|(i, _)| gitlinks.contains(&path[..i]))
}

// An attribute file applies to its own directory and everything beneath it. The
// empty name stands for the root.
fn beneath_directory(path: &str, dirs: &HashSet<String>) -> bool {
    dirs.contains("")
        || path
            .match_indices('/')
            .any(|(i, _)| dirs.contains(&path[..i]))
}

fn regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

/// The tracked paths that get a basis. Untracked files get none: a worktree walk for them would
/// cost time on every run, and an untracked file has no committed blob for an id to match.
fn known_paths(root: &Path) -> Option<HashSet<String>> {
    let index = index_paths(root)?;
    // A tracked attribute file missing from the worktree, as in a sparse checkout,
    // may still apply to its directory. Paths beneath it have unknown attributes.
    let unmaterialized: HashSet<String> = index
        .attribute_files
        .iter()
        .filter(|file| !regular_file(&root.join(file)))
        .map(|file| {
            file.strip_suffix(".gitattributes")
                .unwrap_or("")
                .trim_end_matches('/')
                .to_owned()
        })
        .collect();
    let mut paths = index.paths;
    paths.retain(|path| {
        !beneath_gitlink(path, &index.gitlinks) && !beneath_directory(path, &unmaterialized)
    });
    Some(paths)
}

// Do not let a symlink, hard link or special file redirect a worktree attribute
// source. A missing file is fine; a tracked one that is missing is handled in known_paths.
fn safe_worktree_sources(root: &Path, paths: &HashSet<String>) -> bool {
    if !safe_file_or_absent(&root.join(".gitattributes")) {
        return false;
    }
    let mut checked = HashSet::new();
    for path in paths {
        for (i, _) in path.match_indices('/') {
            let dir = &path[..i];
            if checked.insert(dir)
                && (!safe_dir_or_absent(&root.join(dir))
                    || !safe_file_or_absent(&root.join(dir).join(".gitattributes")))
            {
                return false;
            }
        }
    }
    true
}

fn empty_basis(autocrlf: &str) -> OidBasis {
    OidBasis {
        text: "unspecified".into(),
        eol: "unspecified".into(),
        filter: "unspecified".into(),
        ident: "unspecified".into(),
        working_tree_encoding: "unspecified".into(),
        export_subst: "unspecified".into(),
        crlf: "unspecified".into(),
        autocrlf: if autocrlf == "unset" {
            Cow::Borrowed("unset")
        } else {
            Cow::Owned(autocrlf.to_owned())
        },
    }
}

fn attributes(
    mut basis: HashMap<String, OidBasis>,
    report: &[u8],
) -> Option<HashMap<String, OidBasis>> {
    let mut seen = HashSet::new();
    let mut fields = nul_fields(report)?;
    while let Some(path) = fields.next() {
        let attr = fields.next()?;
        let value = fields.next()?;
        if attr.is_empty() || !seen.insert((path, attr)) {
            return None;
        }
        let path = std::str::from_utf8(path).ok()?;
        let item = basis.get_mut(path)?;
        let value = std::str::from_utf8(value).ok()?;
        let field = match attr {
            b"text" => &mut item.text,
            b"eol" => &mut item.eol,
            b"filter" => &mut item.filter,
            b"ident" => &mut item.ident,
            b"working-tree-encoding" => &mut item.working_tree_encoding,
            b"export-subst" => &mut item.export_subst,
            b"crlf" => &mut item.crlf,
            _ => continue,
        };
        *field = present_value(value);
    }
    Some(basis)
}

/// Git variables that cannot change which attribute sources, object format or
/// directories Git uses. Shells export some of them by default, so declining on
/// them would leave every interactive run unrecorded.
const HARMLESS_GIT_ENV: &[&[u8]] = &[
    b"GIT_ASKPASS",
    b"GIT_EDITOR",
    b"GIT_MERGE_AUTOEDIT",
    b"GIT_PAGER",
    b"GIT_SEQUENCE_EDITOR",
    b"GIT_TERMINAL_PROMPT",
];

/// Capture the repository's configuration and attribute batch for the known
/// worktree paths, for this process. An inherited `GIT_*` variable declines the
/// capture unless it is in `HARMLESS_GIT_ENV`, because Git's environment can
/// select attribute sources, object formats or directories that this capture
/// does not model.
pub fn capture(root: &Path) -> Option<Epoch> {
    let declined = std::env::vars_os().any(|(key, _)| {
        let key = key.as_os_str().as_bytes();
        key.starts_with(b"GIT_") && !HARMLESS_GIT_ENV.contains(&key)
    });
    if declined {
        return None;
    }
    snapshot(root)
}

/// The repository's configuration and attribute batch, read without consulting
/// this process's environment. Unsupported topology, ambiguous state or a failed
/// Git probe returns no epoch, not a guessed basis.
pub(crate) fn snapshot(root: &Path) -> Option<Epoch> {
    if !safe_default_attributes() {
        return None;
    }
    let root = root.canonicalize().ok()?;
    let (git_dir, common_dir) = repo_dirs(&root)?;
    let autocrlf = config(&root)?;
    let watch = build_watch(&git_dir, &external_sources(&root)?)?;
    let paths = known_paths(&root)?;
    if !safe_worktree_sources(&root, &paths) {
        return None;
    }
    let mut input = Vec::new();
    let mut basis = HashMap::with_capacity(paths.len());
    for path in paths {
        input.extend_from_slice(path.as_bytes());
        input.push(0);
        basis.insert(path, empty_basis(&autocrlf));
    }
    let report = crate::gitprobe::output(
        &root,
        &["check-attr", "--all", "-z", "--stdin"],
        &input,
        MAX_OUTPUT,
    )?;
    Some(Epoch {
        basis: attributes(basis, &report)?,
        git_dir,
        common_dir,
        watch,
    })
}

/// Observe conversion evidence even when it makes the path ineligible.
#[cfg(test)]
pub fn observe(root: &Path, path: &str) -> Option<OidBasis> {
    snapshot(root)?.basis.remove(path)
}

/// Evidence for a known path only when Git hashes its raw bytes.
#[cfg(test)]
pub fn check(root: &Path, path: &str) -> Option<OidBasis> {
    observe(root, path).filter(OidBasis::allows_oid)
}

#[cfg(test)]
/// Restrict evidence to known, conversion-free paths.
pub fn check_many(root: &Path, paths: &[String]) -> HashMap<String, OidBasis> {
    let Some(mut epoch) = snapshot(root) else {
        return HashMap::new();
    };
    paths
        .iter()
        .filter_map(|path| {
            let basis = epoch.basis.remove(path)?;
            basis.allows_oid().then(|| (path.clone(), basis))
        })
        .collect()
}

/// An unknown or nonempty directory may hide an attribute source.
#[cfg(any(target_os = "linux", test))]
pub fn directory_removal_invalidates(path: &Path) -> bool {
    !std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

/// The configuration and attribute files Git reads from outside the repository. `git var -l` names
/// them whether or not they exist, so a file the run creates is watched too. Git's system files are
/// also watched by their fixed names, whatever the report says. A relative name, or a report without
/// a global configuration and attribute file, declines.
fn external_sources(root: &Path) -> Option<Vec<PathBuf>> {
    let report = crate::gitprobe::output(root, &["var", "-l"], b"", MAX_OUTPUT)?;
    external_sources_in(&report)
}

/// The external sources that a `git var -l` report names. See `external_sources`.
fn external_sources_in(report: &[u8]) -> Option<Vec<PathBuf>> {
    let mut sources = vec![
        PathBuf::from("/etc/gitconfig"),
        PathBuf::from("/etc/gitattributes"),
    ];
    let (mut config, mut attributes) = (false, false);
    for line in report.split(|byte| *byte == b'\n') {
        let Some(split) = line.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        let (key, value) = (&line[..split], &line[split + 1..]);
        match key {
            b"GIT_CONFIG_GLOBAL" => config = true,
            b"GIT_ATTR_GLOBAL" => attributes = true,
            b"GIT_CONFIG_SYSTEM" | b"GIT_ATTR_SYSTEM" => {}
            _ => continue,
        }
        if !value.is_empty() {
            let path = Path::new(OsStr::from_bytes(value));
            if !path.is_absolute() {
                return None;
            }
            sources.push(path.to_path_buf());
        }
    }
    (config && attributes).then_some(sources)
}

#[cfg(test)]
mod external_source_tests {
    use super::external_sources_in;
    use std::path::PathBuf;

    #[test]
    fn every_reported_name_counts_and_a_missing_global_name_declines() {
        let report = b"user.name=x\nGIT_CONFIG_SYSTEM=/opt/git/gitconfig\nGIT_ATTR_SYSTEM=/opt/git/gitattributes\nGIT_CONFIG_GLOBAL=/h/.config/git/config\nGIT_CONFIG_GLOBAL=/h/.gitconfig\nGIT_ATTR_GLOBAL=/h/.config/git/attributes\n";
        let sources = external_sources_in(report).unwrap();
        for path in [
            "/etc/gitconfig",
            "/etc/gitattributes",
            "/opt/git/gitconfig",
            "/opt/git/gitattributes",
            "/h/.config/git/config",
            "/h/.gitconfig",
            "/h/.config/git/attributes",
        ] {
            assert!(sources.contains(&PathBuf::from(path)), "{path}");
        }
        assert!(external_sources_in(b"GIT_CONFIG_GLOBAL=/h/.gitconfig\n").is_none());
        assert!(external_sources_in(b"GIT_ATTR_GLOBAL=/h/attributes\n").is_none());
        assert!(
            external_sources_in(b"GIT_CONFIG_GLOBAL=.gitconfig\nGIT_ATTR_GLOBAL=/h/a\n").is_none()
        );
    }
}

pub(crate) fn is_absent(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENOTDIR)
}

/// Record every name on the way to an absolute `path`: each directory, each symbolic link and the
/// file. Names that do not exist yet count too, since the run may create them. A file that exists
/// is recorded by identity as well. None when a name cannot be read or the path loops.
fn watch_path(path: &Path, watch: &mut Watch) -> Option<()> {
    let mut pending = path_parts(path);
    let mut current = PathBuf::from("/");
    let mut links = 0;
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            current.pop();
            continue;
        }
        let name = current.join(&part);
        watch.names.insert(name.clone());
        match std::fs::symlink_metadata(&name) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                links += 1;
                if links > 40 {
                    return None;
                }
                let target = std::fs::read_link(&name).ok()?;
                if target.is_absolute() {
                    current = PathBuf::from("/");
                }
                for part in path_parts(&target).into_iter().rev() {
                    pending.push_front(part);
                }
            }
            Ok(metadata) if pending.is_empty() => {
                if metadata.is_file() {
                    watch.inodes.insert((metadata.dev(), metadata.ino()));
                }
                return Some(());
            }
            Ok(metadata) if metadata.is_dir() => current = name,
            Ok(_) => return names_below(name, &mut pending, watch),
            Err(error) if is_absent(&error) => return names_below(name, &mut pending, watch),
            Err(_) => return None,
        }
    }
    Some(())
}

fn path_parts(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::RootDir | Component::CurDir | Component::Prefix(_) => None,
        })
        .collect()
}

/// The names beneath a name that is missing, or is not a directory. None of them can exist yet,
/// so the run may create any of them. A parent reference past such a name cannot be followed.
fn names_below(
    mut name: PathBuf,
    pending: &mut VecDeque<OsString>,
    watch: &mut Watch,
) -> Option<()> {
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            return None;
        }
        name.push(part);
        watch.names.insert(name.clone());
    }
    Some(())
}

/// The watched set for one repository: Git's external sources, and the files of its git directory
/// that Git reads for attributes or configuration. The index counts too: Git reads an attribute
/// file from it when the worktree copy is missing.
pub(crate) fn build_watch(git_dir: &Path, sources: &[PathBuf]) -> Option<Watch> {
    let mut watch = Watch::default();
    for source in sources {
        watch_path(source, &mut watch)?;
    }
    for name in [
        "config",
        "config.worktree",
        "commondir",
        "index",
        "info/attributes",
    ] {
        watch_path(&git_dir.join(name), &mut watch)?;
    }
    Some(watch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Repo(PathBuf);

    impl Repo {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stoop-oid-attrs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let repo = Self(path);
            repo.git(&["init", "-q"]);
            repo.write("plain.txt", "plain\n");
            repo.write("file.txt", "file\n");
            // Fixture inputs are tracked, as committed inputs are. A file that is only written is
            // untracked and has no basis.
            repo.git(&["add", "--", "plain.txt", "file.txt"]);
            repo
        }

        fn git(&self, args: &[&str]) {
            let mut cmd = Command::new("git");
            for (key, _) in std::env::vars_os() {
                if key.as_os_str().as_bytes().starts_with(b"GIT_") {
                    cmd.env_remove(key);
                }
            }
            let out = cmd
                .current_dir(&self.0)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_TERMINAL_PROMPT", "0")
                .args(args)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(out.status.success(), "fixture git failed");
        }

        fn write(&self, path: &str, contents: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn directory_removal_requires_proven_empty() {
        let repo = Repo::new();
        let dir = repo.0.join("nested");
        assert!(directory_removal_invalidates(&dir));
        fs::create_dir(&dir).unwrap();
        assert!(!directory_removal_invalidates(&dir));
        fs::write(dir.join(".gitattributes"), "* text\n").unwrap();
        assert!(directory_removal_invalidates(&dir));
    }

    #[test]
    fn defaults_and_exact_autocrlf_state() {
        let repo = Repo::new();
        let default = check(&repo.0, "plain.txt").unwrap();
        assert_eq!(
            default,
            OidBasis {
                text: "unspecified".into(),
                eol: "unspecified".into(),
                filter: "unspecified".into(),
                ident: "unspecified".into(),
                working_tree_encoding: "unspecified".into(),
                export_subst: "unspecified".into(),
                crlf: "unspecified".into(),
                autocrlf: "unset".into(),
            }
        );
        for value in ["false", "FALSE", "off", "no", "0"] {
            repo.git(&["config", "--local", "core.autocrlf", value]);
            assert_eq!(check(&repo.0, "plain.txt").unwrap().autocrlf, value);
        }
        for value in ["true", "input", "yes", "on", "1", "garbage"] {
            repo.git(&["config", "--local", "core.autocrlf", value]);
            assert!(check(&repo.0, "plain.txt").is_none());
        }
        repo.git(&["config", "--local", "--unset-all", "core.autocrlf"]);
        assert_eq!(check(&repo.0, "plain.txt").unwrap().autocrlf, "unset");
    }

    #[test]
    fn explicit_conversion_attributes_are_never_admitted() {
        let repo = Repo::new();
        for attr in [
            "text",
            "text=auto",
            "-text",
            "eol=lf",
            "eol=crlf",
            "-eol",
            "ident",
            "-ident",
            "filter=driver",
            "-filter",
            "working-tree-encoding=UTF-16LE",
            "-working-tree-encoding",
            "export-subst",
            "-export-subst",
            "crlf",
            "-crlf",
            "crlf=input",
        ] {
            repo.write(".gitattributes", &format!("* {attr}\n"));
            assert!(check(&repo.0, "file.txt").is_none(), "accepted {attr}");
        }
        repo.write(".gitattributes", "* !text\n");
        assert!(check(&repo.0, "file.txt").is_some());
    }

    #[test]
    fn literal_state_names_cannot_hide_filter_drivers() {
        let repo = Repo::new();
        for name in ["unset", "unspecified"] {
            let key = format!("filter.{name}.clean");
            let marker = repo.0.join(format!("driver-{name}"));
            let driver = format!("touch {}", marker.display());
            repo.git(&["config", "--local", &key, &driver]);
            repo.write(".gitattributes", &format!("* filter={name}\n"));
            assert_eq!(
                observe(&repo.0, "file.txt").unwrap().filter,
                format!("present:{name}")
            );
            assert!(check(&repo.0, "file.txt").is_none());
            assert!(!marker.exists());
        }
    }

    #[test]
    fn snapshot_preserves_conversion_evidence_and_known_path_scope() {
        let repo = Repo::new();
        repo.write(
            ".gitattributes",
            "file.txt eol=crlf\nplain.txt custom=unspecified\n",
        );
        repo.write(".gitignore", "ignored.txt\n");
        repo.write("ignored.txt", "ignored\n");
        let epoch = snapshot(&repo.0).unwrap();
        let plain = &epoch.basis["plain.txt"];
        assert_eq!(plain.eol, "unspecified");
        assert!(plain.allows_oid());
        let converted = &epoch.basis["file.txt"];
        assert_eq!(converted.eol, "crlf");
        assert!(!converted.allows_oid());
        assert!(!epoch.basis.contains_key("ignored.txt"));
        assert!(!epoch.basis.contains_key("never-seen.txt"));
        assert_eq!(epoch.git_dir, repo.0.join(".git").canonicalize().unwrap());
        assert_eq!(epoch.common_dir, epoch.git_dir);
    }

    #[test]
    fn present_attribute_state_names_are_not_absence() {
        let repo = Repo::new();
        for (attr, expected) in [
            ("text", "present:set"),
            ("-text", "present:unset"),
            ("text=unset", "present:unset"),
            ("text=unspecified", "present:unspecified"),
            ("text=present:unset", "present:present:unset"),
        ] {
            repo.write(".gitattributes", &format!("file.txt {attr}\n"));
            let basis = observe(&repo.0, "file.txt").unwrap();
            assert_eq!(basis.text, expected, "{attr}");
            assert!(!basis.allows_oid(), "{attr}");
        }
        repo.write(".gitattributes", "file.txt !text\n");
        let basis = observe(&repo.0, "file.txt").unwrap();
        assert_eq!(basis.text, "unspecified");
        assert!(basis.allows_oid());
    }

    #[test]
    fn known_gitlink_and_descendants_are_not_parent_blob_candidates() {
        let parent = Repo::new();
        let child = Repo::new();
        child.git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.org",
            "commit",
            "-qm",
            "initial",
        ]);
        parent.git(&[
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            "-q",
            child.0.to_str().unwrap(),
            "module",
        ]);
        let epoch = snapshot(&parent.0).unwrap();
        assert!(parent.0.join("module/plain.txt").is_file());
        assert!(!epoch.basis.contains_key("module"));
        assert!(!epoch.basis.contains_key("module/plain.txt"));
        assert!(epoch.basis["plain.txt"].allows_oid());
    }

    #[test]
    fn tracked_attributes_missing_from_the_worktree_leave_their_directory_unknown() {
        let repo = Repo::new();
        repo.write("sub/.gitattributes", "* text\n");
        repo.write("sub/file.txt", "file\n");
        repo.git(&["add", "--", "sub/.gitattributes"]);
        fs::remove_file(repo.0.join("sub/.gitattributes")).unwrap();
        let epoch = snapshot(&repo.0).unwrap();
        assert!(!epoch.basis.contains_key("sub/file.txt"));
        assert!(!epoch.basis.contains_key("sub/.gitattributes"));
        assert!(epoch.basis["plain.txt"].allows_oid());
    }

    #[test]
    fn sha256_repository_has_no_epoch() {
        let path = std::env::temp_dir().join(format!(
            "stoop-oid-sha256-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let repo = Repo(path);
        repo.git(&["init", "-q", "--object-format=sha256"]);
        repo.write("file.txt", "file\n");
        assert!(snapshot(&repo.0).is_none());
    }

    #[test]
    fn clean_git_env_probe_child() {
        if let Some(root) = std::env::var_os("STOOP_CLEAN_GIT_ENV_PROBE") {
            let epoch = capture(Path::new(&root)).unwrap();
            assert!(epoch.basis["plain.txt"].allows_oid());
        }
    }

    #[test]
    fn git_env_absent_allows_safe_worktree() {
        let repo = Repo::new();
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "oid_attrs::tests::clean_git_env_probe_child"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &repo.0)
            .env("STOOP_CLEAN_GIT_ENV_PROBE", &repo.0)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn redirected_attribute_files_in_the_worktree_are_rejected() {
        use std::os::unix::fs::symlink;
        let repo = Repo::new();
        repo.write("attributes-target", "file.txt text\n");
        symlink("attributes-target", repo.0.join(".gitattributes")).unwrap();
        assert!(snapshot(&repo.0).is_none());
        fs::remove_file(repo.0.join(".gitattributes")).unwrap();
        symlink(
            "../../attributes-target",
            repo.0.join(".git/info/attributes"),
        )
        .unwrap();
        assert!(snapshot(&repo.0).is_none());
    }

    #[test]
    fn worktree_nested_info_and_configured_attribute_files_apply() {
        let repo = Repo::new();
        repo.write(".gitattributes", "*.root text\n");
        repo.write("nested/.gitattributes", "*.nested ident\n");
        repo.write(".git/info/attributes", "*.info filter=driver\n");
        repo.write(
            "custom-attributes",
            "*.global working-tree-encoding=UTF-16LE\n",
        );
        let attr_path = repo.0.join("custom-attributes");
        repo.git(&[
            "config",
            "--local",
            "core.attributesFile",
            attr_path.to_str().unwrap(),
        ]);
        for path in [
            "file.root",
            "nested/file.nested",
            "file.info",
            "file.global",
        ] {
            assert!(check(&repo.0, path).is_none(), "accepted {path}");
        }
        assert!(check(&repo.0, "other.txt").is_none());
    }

    #[test]
    fn included_git_config_is_not_assumed_safe() {
        let repo = Repo::new();
        repo.write("config-extra", "[core]\n\tautocrlf = false\n");
        repo.git(&["config", "--local", "include.path", "../config-extra"]);
        assert!(check(&repo.0, "plain.txt").is_none());
    }

    #[test]
    fn configured_attribute_tree_is_not_assumed_safe() {
        let repo = Repo::new();
        repo.git(&["config", "--local", "attr.tree", "HEAD"]);
        assert!(check(&repo.0, "plain.txt").is_none());
    }

    #[test]
    fn configured_attribute_file_declines_the_snapshot() {
        let repo = Repo::new();
        repo.write("custom-attributes", "*.txt text\n");
        let attr_path = repo.0.join("custom-attributes");
        repo.git(&[
            "config",
            "--local",
            "core.attributesFile",
            attr_path.to_str().unwrap(),
        ]);
        assert!(snapshot(&repo.0).is_none());
    }

    #[test]
    fn conditional_git_config_include_is_not_assumed_safe() {
        let repo = Repo::new();
        repo.git(&[
            "config",
            "--local",
            "includeIf.gitdir:/nonexistent/.path",
            "config-extra",
        ]);
        assert!(check(&repo.0, "plain.txt").is_none());
    }

    #[test]
    fn batch_handles_odd_names_duplicates_and_unsafe_paths() {
        let repo = Repo::new();
        repo.write(".gitattributes", "*.converted filter=driver\n");
        let names = [
            "--leading option",
            "line\nfeed\t'quoted'\\name",
            "accent-é.txt",
            "normal.converted",
            "../outside",
            "/absolute",
            "bad\0name",
            "--leading option",
        ];
        for path in &names[..4] {
            repo.write(path, "contents\n");
            repo.git(&["add", "--", *path]);
        }
        let paths: Vec<_> = names.iter().map(|s| (*s).to_owned()).collect();
        let result = check_many(&repo.0, &paths);
        assert_eq!(result.len(), 3);
        for path in &names[..3] {
            assert!(result.contains_key(*path));
        }
        for path in &names[3..7] {
            assert!(!result.contains_key(*path));
        }
    }

    #[test]
    fn untracked_files_get_no_basis() {
        let repo = Repo::new();
        repo.write("loose.txt", "loose\n");
        assert!(check(&repo.0, "loose.txt").is_none());
        assert!(observe(&repo.0, "loose.txt").is_none());
        assert!(snapshot(&repo.0).unwrap().basis.contains_key("file.txt"));
    }

    /// A scratch directory that removes itself. Its path is canonical, because watched names are
    /// physical.
    fn scratch(name: &str) -> Repo {
        let path = std::env::temp_dir().join(format!(
            "stoop-oid-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Repo(fs::canonicalize(path).unwrap())
    }

    #[test]
    fn watch_names_every_name_on_the_way_to_a_source() {
        let base = scratch("watch-names");
        fs::create_dir_all(base.0.join("a/b")).unwrap();
        fs::write(base.0.join("a/b/file"), "x").unwrap();
        std::os::unix::fs::symlink("a/b", base.0.join("link")).unwrap();
        let mut watch = Watch::default();
        watch_path(&base.0.join("link/file"), &mut watch).unwrap();
        for name in ["link", "a", "a/b", "a/b/file"] {
            assert!(watch.names_contain(&base.0.join(name)), "{name}");
        }
        assert!(watch.is_watched_file(&fs::metadata(base.0.join("a/b/file")).unwrap()));
        let mut missing = Watch::default();
        watch_path(&base.0.join("a/new/leaf"), &mut missing).unwrap();
        for name in ["a/new", "a/new/leaf"] {
            assert!(missing.names_contain(&base.0.join(name)), "{name}");
        }
    }

    #[test]
    fn watch_declines_loops_long_chains_and_unreadable_names() {
        let base = scratch("watch-loops");
        std::os::unix::fs::symlink("loop2", base.0.join("loop1")).unwrap();
        std::os::unix::fs::symlink("loop1", base.0.join("loop2")).unwrap();
        assert!(watch_path(&base.0.join("loop1"), &mut Watch::default()).is_none());
        fs::write(base.0.join("target"), "x").unwrap();
        // Forty links resolve. A forty-first declines.
        for (links, resolves) in [(40, true), (41, false)] {
            for i in 0..links {
                let next = if i + 1 == links {
                    "target".to_owned()
                } else {
                    format!("c{}", i + 1)
                };
                std::os::unix::fs::symlink(next, base.0.join(format!("c{i}"))).unwrap();
            }
            let watched = watch_path(&base.0.join("c0"), &mut Watch::default()).is_some();
            assert_eq!(watched, resolves, "{links} links");
            for i in 0..links {
                fs::remove_file(base.0.join(format!("c{i}"))).unwrap();
            }
        }
        // Root reads every name, so the unreadable case is only meaningful without it.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let locked = base.0.join("locked");
            fs::create_dir_all(locked.join("inner")).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
            let unknown = watch_path(&locked.join("inner/file"), &mut Watch::default()).is_none();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(unknown, "a name that cannot be read counts");
        }
    }

    #[test]
    fn a_parent_reference_past_a_missing_name_is_unknown() {
        let base = scratch("watch-dotdot");
        assert!(watch_path(&base.0.join("missing/../file"), &mut Watch::default()).is_none());
    }

    #[test]
    fn the_git_directory_sources_are_watched_whether_or_not_they_exist() {
        let base = scratch("watch-git");
        let git_dir = base.0.join(".git");
        fs::create_dir_all(git_dir.join("info")).unwrap();
        fs::create_dir_all(git_dir.join("objects/aa")).unwrap();
        let watch = build_watch(&git_dir, &[base.0.join("home/.gitconfig")]).unwrap();
        for name in [
            "config",
            "config.worktree",
            "commondir",
            "index",
            "info/attributes",
        ] {
            assert!(watch.names_contain(&git_dir.join(name)), "{name}");
        }
        assert!(watch.names_contain(&base.0.join("home/.gitconfig")));
        assert!(!watch.names_contain(&git_dir.join("objects/aa")));
    }

    #[test]
    fn a_hard_link_to_a_watched_file_is_watched_by_identity() {
        let base = scratch("watch-identity");
        fs::create_dir_all(base.0.join("home")).unwrap();
        fs::create_dir_all(base.0.join("other")).unwrap();
        fs::write(base.0.join("home/.gitconfig"), "[user]\n").unwrap();
        let watch = build_watch(&base.0.join(".git"), &[base.0.join("home/.gitconfig")]).unwrap();
        let alias = base.0.join("other/alias");
        fs::hard_link(base.0.join("home/.gitconfig"), &alias).unwrap();
        assert!(watch.is_watched_file(&fs::metadata(&alias).unwrap()));
        assert!(!watch.names_contain(&alias));
    }

    #[test]
    fn rejects_failed_git_and_parent_repository_discovery() {
        let repo = Repo::new();
        fs::create_dir(repo.0.join("child")).unwrap();
        assert!(check(&repo.0.join("child"), "file").is_none());
        assert!(check(&repo.0.join("missing"), "file").is_none());
        repo.write(".git/config", "[broken\n");
        assert!(check(&repo.0, "file").is_none());
    }

    #[test]
    fn malformed_duplicate_and_unexpected_attribute_records_fail_closed() {
        let basis = HashMap::from([("one".to_owned(), empty_basis("unset"))]);
        let empty = attributes(basis.clone(), b"").unwrap();
        assert!(empty["one"].allows_oid());
        for invalid in [
            b"other\0custom\0value\0".as_slice(),
            b"one\0custom\0value".as_slice(),
            b"one\0custom\0value\0one\0custom\0value\0".as_slice(),
            b"one\0text\0".as_slice(),
        ] {
            assert!(attributes(basis.clone(), invalid).is_none());
        }
        let present = attributes(basis, b"one\0filter\0unspecified\0").unwrap();
        assert_eq!(present["one"].filter, "present:unspecified");
        assert!(!present["one"].allows_oid());
    }

    #[test]
    fn fifo_probe_child() {
        if let Some(root) = std::env::var_os("STOOP_FIFO_PROBE") {
            assert!(capture(Path::new(&root)).is_none());
        }
    }

    #[test]
    fn fifo_attribute_source_does_not_hang() {
        use std::os::unix::process::CommandExt;
        use std::time::{Duration, Instant};
        let repo = Repo::new();
        let fifo = repo.0.join("attrs-fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        repo.git(&[
            "config",
            "--local",
            "core.attributesFile",
            fifo.to_str().unwrap(),
        ]);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oid_attrs::tests::fifo_probe_child",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &repo.0)
            .env("STOOP_FIFO_PROBE", &repo.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                let _ = child.wait();
                panic!("attribute source FIFO blocked recording");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn global_config_fifo_is_bounded_by_the_deadline() {
        use std::os::unix::process::CommandExt;
        use std::time::{Duration, Instant};
        let repo = Repo::new();
        let home = repo.0.join("home");
        fs::create_dir(&home).unwrap();
        let fifo = home.join(".gitconfig");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "oid_attrs::tests::fifo_probe_child",
                "--nocapture",
            ])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", &home)
            .env("STOOP_FIFO_PROBE", &repo.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
                let _ = child.wait();
                panic!("global Git config FIFO blocked recording");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn git_env_probe_child() {
        if let Some(root) = std::env::var_os("STOOP_GIT_ENV_PROBE") {
            assert!(capture(Path::new(&root)).is_none());
        }
    }

    #[test]
    fn redirected_attribute_source_is_never_treated_as_safe() {
        let repo = Repo::new();
        for (name, value) in [
            ("GIT_ATTR_SOURCE", "HEAD"),
            ("GIT_DIR", "/nonexistent"),
            ("GIT_COMMON_DIR", "/nonexistent"),
            ("GIT_WORK_TREE", "/nonexistent"),
            ("GIT_INDEX_FILE", "/nonexistent"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_UNRECOGNIZED_OVERRIDE", "1"),
        ] {
            let out = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "oid_attrs::tests::git_env_probe_child"])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap())
                .env("HOME", &repo.0)
                .env("STOOP_GIT_ENV_PROBE", &repo.0)
                .env(name, value)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }

    #[test]
    fn harmless_git_env_probe_child() {
        if let Some(root) = std::env::var_os("STOOP_HARMLESS_GIT_ENV_PROBE") {
            assert!(capture(Path::new(&root)).is_some());
        }
    }

    #[test]
    fn harmless_git_variables_keep_the_snapshot() {
        let repo = Repo::new();
        for name in HARMLESS_GIT_ENV {
            let name = std::str::from_utf8(name).unwrap();
            let out = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "oid_attrs::tests::harmless_git_env_probe_child"])
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap())
                .env("HOME", &repo.0)
                .env("STOOP_HARMLESS_GIT_ENV_PROBE", &repo.0)
                .env(name, "1")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stdout)
            );
        }
    }
}
