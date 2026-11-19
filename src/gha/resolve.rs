//! Resolves action refs and verifies the trees downloaded for their commits.
//! Missing content, credentials, or runner copies make the job run.

use crate::gha::actions::{self, Tree};
use crate::job::JobRecord;
use crate::plan::spec::{Code, JobSpec, RecordCheck};
use crate::run;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashMap};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

/// How a `uses:` reference is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// `owner/repo[/path]@ref`, where `ref` is a tag, a branch or another ref name.
    Remote {
        owner: String,
        repo: String,
        reference: String,
    },
    /// `owner/repo[/path]@<40 lowercase hex>`. The workflow already names the commit.
    Pinned(String),
}

/// Classifies a `uses:` value. `Err` says why it cannot be resolved here, and the job runs.
pub fn classify(uses: &str) -> Result<Action, String> {
    if uses.starts_with("./") || uses.starts_with(".\\") {
        return Err("local actions are not resolved".into());
    }
    if uses
        .get(..9)
        .is_some_and(|p| p.eq_ignore_ascii_case("docker://"))
    {
        return Err("docker image actions are not resolved".into());
    }
    let (name, reference) = uses.rsplit_once('@').ok_or("action has no ref")?;
    let parts: Vec<&str> = name.split('/').collect();
    let (owner, repo) = match parts.as_slice() {
        [owner, repo, rest @ ..]
            if owner_ok(owner) && repo_ok(repo) && rest.iter().all(|p| path_ok(p)) =>
        {
            (*owner, *repo)
        }
        _ => return Err(format!("{name} is not owner/repo[/path]")),
    };
    if reference.is_empty() {
        return Err("action has an empty ref".into());
    }
    if is_full_sha(reference) {
        return Ok(Action::Pinned(reference.into()));
    }
    if reference.len() >= 4 && reference.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{reference} looks like a commit name that is not a full lowercase 40-character SHA; pin the full SHA"
        ));
    }
    if !reference
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_./+".contains(&b))
    {
        return Err(format!(
            "ref {reference} has characters this planner does not resolve"
        ));
    }
    Ok(Action::Remote {
        owner: owner.into(),
        repo: repo.into(),
        reference: reference.into(),
    })
}

fn owner_ok(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn repo_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn path_ok(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn is_full_sha(s: &str) -> bool {
    // All zeros is git's null object id: it names no commit, and git prints it for
    // a listing line whose id it could not parse.
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}

#[cfg(test)]
fn assert_fixture_url(url: &str) {
    let loopback = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .and_then(|rest| rest.split('/').next())
        .and_then(|authority| authority.parse::<std::net::SocketAddr>().ok())
        .is_some_and(|address| address.ip().is_loopback());
    assert!(
        url.starts_with("file:///") || loopback,
        "non-local action network access in a test"
    );
}

/// Answers what a `uses:` reference names on its server.
pub trait Resolver {
    /// The commit `owner/repo@reference` names now, or why that is unknown.
    fn commit(&self, owner: &str, repo: &str, reference: &str) -> Result<String, String>;

    fn commit_before(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
        _deadline: Instant,
    ) -> Result<String, String> {
        self.commit(owner, repo, reference)
    }
    fn action_tree(
        &self,
        _owner: &str,
        _repo: &str,
        _sha: &str,
        _deadline: Instant,
    ) -> Result<Rc<Tree>, String> {
        Err("action tree download is unavailable".into())
    }
    fn runner_copy(
        &self,
        _owner: &str,
        _repo: &str,
        _reference: &str,
        _deadline: Instant,
    ) -> Result<Tree, String> {
        Err("runner action copy is unavailable".into())
    }
    fn local_tree(&self, _path: &str, _deadline: Instant) -> Result<(String, Rc<Tree>), String> {
        Err("local action tree is unavailable".into())
    }
    fn local_copy(&self, _path: &str, _deadline: Instant) -> Result<Tree, String> {
        Err("local action copy is unavailable".into())
    }
}
type DownloadCache = HashMap<(String, String, String), Rc<Tree>>;

/// Resolves through `git ls-remote` against `<base>/<owner>/<repo>.git`.
pub struct Git {
    dir: PathBuf,
    base: String,
    timeout: Duration,
    api: String,
    revision: Option<String>,
    budget: Cell<u64>,
    downloaded: RefCell<DownloadCache>,
}

impl Git {
    /// Fifteen seconds per lookup. A slow server fails wide rather than stalling every job.
    pub const TIMEOUT: Duration = Duration::from_secs(15);

    pub fn new(dir: impl Into<PathBuf>, base: impl Into<String>, timeout: Duration) -> Self {
        let base = base.into().trim_end_matches('/').to_string();
        let api = if base == "https://github.com" {
            "https://api.github.com".to_string()
        } else {
            format!("{base}/api/v3")
        };
        Self {
            dir: dir.into(),
            base,
            timeout,
            api,
            revision: None,
            budget: Cell::new(actions::MAX_RETAINED),
            downloaded: RefCell::new(HashMap::new()),
        }
    }

    pub fn with_revision(mut self, revision: impl Into<String>) -> Self {
        self.revision = Some(revision.into());
        self
    }

    #[cfg(test)]
    fn set_test_budget(&self, bytes: u64) {
        self.budget.set(bytes);
    }

    /// The server is `GITHUB_SERVER_URL` in Actions, else github.com. `dir` is the
    /// workspace, so git reads its credentials.
    pub fn from_env(dir: &Path) -> Self {
        let base = run::env_str("GITHUB_SERVER_URL").unwrap_or_else(|| "https://github.com".into());
        let mut git = Self::new(dir, base, Self::TIMEOUT);
        if let Some(api) = run::env_str("GITHUB_API_URL") {
            git.api = api.trim_end_matches('/').to_owned();
        }
        git
    }

    fn ls_remote(
        &self,
        url: &str,
        patterns: &[String],
        total_deadline: Instant,
    ) -> Result<String, String> {
        #[cfg(test)]
        assert_fixture_url(url);
        let mut command = Command::new("git");
        command
            .current_dir(&self.dir)
            .args(["-c", "http.followRedirects=false", "ls-remote", "--", url])
            .args(patterns)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_ATTR_SOURCE",
        ] {
            command.env_remove(var);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot run git: {e}"))?;
        let out = drain(child.stdout.take());
        let err = drain(child.stderr.take());
        let deadline = (Instant::now() + self.timeout).min(total_deadline);
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "git ls-remote timed out after {:.0}s",
                        self.timeout.as_secs_f64()
                    ));
                }
                Err(e) => {
                    let _ = child.kill();
                    return Err(format!("cannot wait for git: {e}"));
                }
            }
        };
        let stdout = out.join().map_err(|_| "git output reader panicked")?;
        let stderr = err.join().map_err(|_| "git error reader panicked")?;
        if stdout.len() > 1024 * 1024 || stderr.len() > 1024 * 1024 {
            return Err("git ls-remote output exceeds the size limit".into());
        }
        if !status.success() {
            let text = String::from_utf8_lossy(&stderr);
            let first = text
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("no error output")
                .trim();
            return Err(format!("git ls-remote failed: {first}"));
        }
        String::from_utf8(stdout).map_err(|_| "git ls-remote output is not UTF-8".into())
    }

    fn run_bounded(
        &self,
        mut command: Command,
        input: Option<&[u8]>,
        limit: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        if Instant::now() >= deadline {
            return Err("action verification timed out".into());
        }
        command
            .current_dir(&self.dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(test)]
        let check_redirect = command.get_program() == std::ffi::OsStr::new("curl");
        #[cfg(test)]
        if check_redirect {
            command.stderr(Stdio::piped());
        }
        command.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        for var in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_ATTR_SOURCE",
        ] {
            command.env_remove(var);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start action verification: {e}"))?;
        #[cfg(test)]
        let redirect_log = child.stderr.take().map(|pipe| drain(Some(pipe)));
        if let Some(input) = input {
            if let Some(mut stdin) = child.stdin.take() {
                if let Err(e) = stdin.write_all(input) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("cannot send verification input: {e}"));
                }
            }
        }
        let stdout = child
            .stdout
            .take()
            .ok_or("cannot capture action verification output")?;
        let reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take((limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("action verification timed out".into());
                }
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("cannot wait for action verification: {e}"));
                }
            }
        };
        let bytes = reader
            .join()
            .map_err(|_| "action output reader panicked")?
            .map_err(|e| format!("cannot read action verification output: {e}"))?;
        #[cfg(test)]
        if let Some(log) = redirect_log {
            let bytes = log.join().map_err(|_| "curl error reader panicked")?;
            let text = String::from_utf8_lossy(&bytes);
            if let Some(url) = text
                .lines()
                .find_map(|line| line.strip_prefix("stoop-effective:"))
            {
                assert_fixture_url(url);
            }
        }
        if bytes.len() > limit {
            return Err("action download exceeds the size limit".into());
        }
        if !status.success() {
            return Err("action verification command failed".into());
        }
        Ok(bytes)
    }

    fn download(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        deadline: Instant,
    ) -> Result<Rc<Tree>, String> {
        if !is_full_sha(sha) {
            return Err("resolved action commit is not a full SHA".into());
        }
        let key = (owner.to_owned(), repo.to_owned(), sha.to_owned());
        if let Some(cached) = self.downloaded.borrow().get(&key) {
            return Ok(cached.clone());
        }
        let key_cost = 256u64
            .saturating_add(owner.len() as u64)
            .saturating_add(repo.len() as u64)
            .saturating_add(sha.len() as u64);
        let remaining = self
            .budget
            .get()
            .checked_sub(key_cost)
            .ok_or(actions::BUDGET_EXCEEDED)?;
        let result = (|| {
            let repository_url = format!("{}/{owner}/{repo}.git", self.base);
            let mut config = Command::new("git");
            config.args([
                "config",
                "--get-urlmatch",
                "http.extraheader",
                &repository_url,
            ]);
            // A missing header is normal for public repositories. Do not print it.
            let header = self.run_bounded(config, None, 8192, deadline).ok();
            let url = format!("{}/repos/{owner}/{repo}/tarball/{sha}", self.api);
            #[cfg(test)]
            assert_fixture_url(&url);
            let protocol = if url.starts_with("https://") {
                "=https"
            } else if url.starts_with("http://") {
                "=http"
            } else if url.starts_with("file:///") {
                "=file"
            } else {
                return Err("unsupported action archive API protocol".into());
            };
            let mut curl = Command::new("curl");
            let seconds = deadline
                .saturating_duration_since(Instant::now())
                .as_secs_f64()
                .min(self.timeout.as_secs_f64());
            if seconds <= 0.0 {
                return Err("action download timed out".into());
            }
            curl.args([
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-redirs",
                "3",
                "--proto",
                protocol,
                "--proto-redir",
                protocol,
                "--max-time",
                &format!("{seconds:.3}"),
                "--connect-timeout",
                "5",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                "User-Agent: stoop",
            ]);
            #[cfg(test)]
            {
                curl.args(["--noproxy", "*"]);
                curl.args(["--write-out", "%{stderr}stoop-effective:%{url_effective}\n"]);
                if let Some(address) = self
                    .api
                    .strip_prefix("http://")
                    .or_else(|| self.api.strip_prefix("https://"))
                    .and_then(|rest| rest.split('/').next())
                    .and_then(|authority| authority.parse::<std::net::SocketAddr>().ok())
                {
                    curl.args(["--connect-to", &format!("::{address}")]);
                }
            }
            if header.is_some() {
                curl.args(["--header", "@-"]);
            }
            curl.args(["--url", &url]);
            let bytes =
                self.run_bounded(curl, header.as_deref(), actions::MAX_COMPRESSED, deadline)?;
            let tree = Rc::new(Tree::from_gzip_before(&bytes, deadline, remaining)?);
            self.budget.set(remaining - tree.retained());
            Ok(tree)
        })();
        if let Ok(tree) = &result {
            self.downloaded.borrow_mut().insert(key, tree.clone());
        }
        result
    }

    fn checked_copy(
        &self,
        base: &Path,
        relative: &Path,
        deadline: Instant,
    ) -> Result<Tree, String> {
        let base_meta = std::fs::symlink_metadata(base)
            .map_err(|e| format!("action copy base is inaccessible: {e}"))?;
        if base_meta.file_type().is_symlink() || !base_meta.is_dir() {
            return Err("action copy base is not a real directory".into());
        }
        let mut path = base.to_path_buf();
        for component in relative.components() {
            match component {
                std::path::Component::Normal(part) => path.push(part),
                _ => return Err("invalid action copy path".into()),
            }
            if std::fs::symlink_metadata(&path)
                .map_err(|e| format!("action copy is inaccessible: {e}"))?
                .file_type()
                .is_symlink()
            {
                return Err("action copy path contains a symlink".into());
            }
        }
        Tree::from_directory_before(&path, deadline)
    }
}

/// Reads a reader to its end on its own thread, so a full pipe cannot stall git.
/// A timed-out child is left to its reader, which ends when the pipe closes.
fn drain<R: Read + Send + 'static>(pipe: Option<R>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(pipe) = pipe {
            let _ = pipe.take(1024 * 1024 + 1).read_to_end(&mut buf);
        }
        buf
    })
}

impl Resolver for Git {
    fn commit(&self, owner: &str, repo: &str, reference: &str) -> Result<String, String> {
        self.commit_before(owner, repo, reference, Instant::now() + self.timeout)
    }

    fn commit_before(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
        deadline: Instant,
    ) -> Result<String, String> {
        let url = format!("{}/{owner}/{repo}.git", self.base);
        let patterns = if reference.starts_with("refs/") {
            vec![reference.to_string(), format!("{reference}^{{}}")]
        } else {
            vec![
                format!("refs/tags/{reference}"),
                format!("refs/tags/{reference}^{{}}"),
                format!("refs/heads/{reference}"),
            ]
        };
        pick(&self.ls_remote(&url, &patterns, deadline)?, reference)
    }

    fn action_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        deadline: Instant,
    ) -> Result<Rc<Tree>, String> {
        self.download(owner, repo, sha, deadline)
    }

    fn runner_copy(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
        deadline: Instant,
    ) -> Result<Tree, String> {
        let workspace = run::env_str("RUNNER_WORKSPACE").ok_or("RUNNER_WORKSPACE is not set")?;
        let parent = Path::new(&workspace)
            .parent()
            .ok_or("invalid RUNNER_WORKSPACE")?;
        let base = parent.join("_actions");
        self.checked_copy(
            &base,
            &PathBuf::from(owner).join(repo).join(reference),
            deadline,
        )
    }

    fn local_tree(&self, path: &str, deadline: Instant) -> Result<(String, Rc<Tree>), String> {
        let sha = self
            .revision
            .clone()
            .or_else(|| run::env_str("GITHUB_SHA"))
            .ok_or("target revision is unavailable")?;
        if !is_full_sha(&sha) {
            return Err("target revision is not a full commit SHA".into());
        }
        let mut ls = Command::new("git");
        ls.args(["ls-tree", "-r", &sha, "--", path]);
        let listing = self.run_bounded(ls, None, 4 * 1024 * 1024, deadline)?;
        if String::from_utf8_lossy(&listing)
            .lines()
            .any(|line| line.starts_with("160000 "))
        {
            return Err("local action contains a submodule".into());
        }
        let mut archive = Command::new("git");
        archive.args(["archive", "--format=tar", &sha, "--", path]);
        let bytes = self.run_bounded(archive, None, 300 * 1024 * 1024, deadline)?;
        let tree = Tree::from_tar_before(std::io::Cursor::new(bytes), false, deadline, u64::MAX)?
            .subtree(path)?;
        Ok((sha, Rc::new(tree)))
    }

    fn local_copy(&self, path: &str, deadline: Instant) -> Result<Tree, String> {
        self.checked_copy(&self.dir, Path::new(path), deadline)
    }
}

/// Picks the commit `reference` names from `git ls-remote` output.
///
/// A tag names the commit its `^{}` line peels to; a lightweight tag names its own
/// object. A tag and a branch of the same name must name the same commit, or the
/// reference is ambiguous. Any malformed line fails the whole listing.
pub fn pick(listing: &str, reference: &str) -> Result<String, String> {
    let mut names: HashMap<&str, &str> = HashMap::new();
    for line in listing.lines() {
        let (sha, name) = line
            .split_once('\t')
            .ok_or_else(|| format!("malformed ls-remote line {line:?}"))?;
        if !is_full_sha(sha) {
            return Err(format!("malformed object id in ls-remote line {line:?}"));
        }
        if names.insert(name, sha).is_some() {
            return Err(format!("ls-remote listed {name} twice"));
        }
    }
    let commit_of = |name: &str| {
        names
            .get(format!("{name}^{{}}").as_str())
            .or_else(|| names.get(name))
            .copied()
    };
    let mut candidates = Vec::new();
    if reference.starts_with("refs/") {
        candidates.extend(commit_of(reference));
    } else {
        candidates.extend(commit_of(&format!("refs/tags/{reference}")));
        candidates.extend(
            names
                .get(format!("refs/heads/{reference}").as_str())
                .copied(),
        );
    }
    let distinct: BTreeSet<&str> = candidates.into_iter().collect();
    match distinct.len() {
        0 => Err(format!("no tag or branch named {reference}")),
        1 => Ok(distinct.into_iter().next().unwrap_or_default().to_string()),
        _ => Err(format!(
            "{reference} is both a tag and a branch naming different commits"
        )),
    }
}

/// The `(owner, repo, ref)` a lookup asks about.
type Query = (String, String, String);

/// Caches each `owner/repo@ref` answer for one run, so every distinct action costs
/// one lookup, errors included.
pub struct Memo<'a> {
    inner: &'a dyn Resolver,
    seen: RefCell<HashMap<Query, Result<String, String>>>,
}

impl<'a> Memo<'a> {
    pub fn new(inner: &'a dyn Resolver) -> Self {
        Self {
            inner,
            seen: RefCell::new(HashMap::new()),
        }
    }
}

impl Resolver for Memo<'_> {
    fn commit(&self, owner: &str, repo: &str, reference: &str) -> Result<String, String> {
        self.commit_before(
            owner,
            repo,
            reference,
            Instant::now() + actions::TOTAL_TIMEOUT,
        )
    }

    fn commit_before(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
        deadline: Instant,
    ) -> Result<String, String> {
        let key = (owner.to_string(), repo.to_string(), reference.to_string());
        if let Some(answer) = self.seen.borrow().get(&key) {
            return answer.clone();
        }
        let answer = self.inner.commit_before(owner, repo, reference, deadline);
        self.seen.borrow_mut().insert(key, answer.clone());
        answer
    }

    fn action_tree(
        &self,
        owner: &str,
        repo: &str,
        sha: &str,
        deadline: Instant,
    ) -> Result<Rc<Tree>, String> {
        self.inner.action_tree(owner, repo, sha, deadline)
    }
    fn runner_copy(
        &self,
        owner: &str,
        repo: &str,
        reference: &str,
        deadline: Instant,
    ) -> Result<Tree, String> {
        self.inner.runner_copy(owner, repo, reference, deadline)
    }
    fn local_tree(&self, path: &str, deadline: Instant) -> Result<(String, Rc<Tree>), String> {
        self.inner.local_tree(path, deadline)
    }
    fn local_copy(&self, path: &str, deadline: Instant) -> Result<Tree, String> {
        self.inner.local_copy(path, deadline)
    }
}

/// Whether an image reference is pinned to a `sha256` digest. Only a digest names
/// the same bytes forever, and resolving a tag needs a registry client, so a tag is
/// unresolvable here.
pub fn image_pinned(image: &str) -> bool {
    image.rsplit_once("@sha256:").is_some_and(|(name, digest)| {
        !name.is_empty()
            && digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Verifies the attested action graph against fresh downloads for this plan run.
pub struct ActionCheck<'a> {
    memo: Memo<'a>,
    strict: bool,
    deadline: Instant,
}

impl<'a> ActionCheck<'a> {
    pub fn new(resolver: &'a dyn Resolver) -> Self {
        Self::with_strict(resolver, false)
    }
    /// Explicit policy for callers that obtain strictness from a plan option.
    pub fn with_strict(resolver: &'a dyn Resolver, strict: bool) -> Self {
        Self {
            memo: Memo::new(resolver),
            strict,
            deadline: Instant::now() + actions::TOTAL_TIMEOUT,
        }
    }
}

impl RecordCheck for ActionCheck<'_> {
    fn check(&self, spec: &JobSpec, record: &JobRecord) -> Result<(), (Code, String)> {
        for image in &spec.images {
            if !image_pinned(image) {
                return Err((
                    Code::UnresolvedAction,
                    format!(
                        "image {image} is not pinned to a digest, so it cannot be resolved here"
                    ),
                ));
            }
        }
        actions::verify(
            &spec.actions,
            &record.actions,
            &self.memo,
            self.strict,
            self.deadline,
        )
    }
}

#[cfg(test)]
pub mod fake {
    use super::Resolver;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::time::Instant;

    /// A resolver with fixed answers, counting every lookup it receives.
    #[derive(Default)]
    pub struct Fake {
        answers: RefCell<HashMap<String, Result<String, String>>>,
        calls: Cell<usize>,
    }

    impl Fake {
        pub fn new() -> Self {
            Self::default()
        }
        /// Sets the answer for `owner/repo@reference`.
        pub fn set(&self, owner_repo_ref: &str, answer: Result<&str, &str>) {
            self.answers.borrow_mut().insert(
                owner_repo_ref.into(),
                answer.map(String::from).map_err(String::from),
            );
        }
        pub fn calls(&self) -> usize {
            self.calls.get()
        }
    }

    impl Resolver for Fake {
        fn commit(&self, owner: &str, repo: &str, reference: &str) -> Result<String, String> {
            self.calls.set(self.calls.get() + 1);
            let key = format!("{owner}/{repo}@{reference}");
            self.answers
                .borrow()
                .get(&key)
                .cloned()
                .unwrap_or_else(|| Err(format!("no fake answer for {key}")))
        }

        fn action_tree(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Instant,
        ) -> Result<Rc<super::Tree>, String> {
            Ok(Rc::new(crate::gha::actions::fixture_tree()))
        }

        fn runner_copy(
            &self,
            _: &str,
            _: &str,
            _: &str,
            _: Instant,
        ) -> Result<super::Tree, String> {
            Ok(crate::gha::actions::fixture_tree())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;
    use crate::plan::spec::JobSpec;
    use std::collections::BTreeMap;
    use std::net::TcpListener;
    use std::process::Command as Cmd;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const TAG_OBJECT: &str = "3333333333333333333333333333333333333333";
    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn unit_test_resolver_refuses_real_network_destinations() {
        assert_fixture_url("http://127.0.0.1:1234/api/v3");
        assert_fixture_url("file:///tmp/fixture");
        assert!(std::panic::catch_unwind(|| assert_fixture_url("https://github.com")).is_err());
        assert!(std::panic::catch_unwind(|| assert_fixture_url(
            "http://127.0.0.1.example.com:1234"
        ))
        .is_err());
    }

    fn spec(actions: &[&str], images: &[&str]) -> JobSpec {
        JobSpec {
            workflow: "ci".into(),
            path: ".github/workflows/ci.yml".into(),
            job: "test".into(),
            leg: None,
            key: Some("job-x".into()),
            runs_on: serde_json::Value::Null,
            needs: vec![],
            if_text: None,
            steps: vec![],
            blocked: None,
            actions: actions.iter().map(|s| s.to_string()).collect(),
            images: images.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn record(actions: &[(&str, &str)]) -> JobRecord {
        let fake = Fake::new();
        for (raw, sha) in actions {
            fake.set(raw, Ok(*sha));
        }
        let refs: Vec<String> = actions.iter().map(|(raw, _)| raw.to_string()).collect();
        let actions = crate::gha::actions::capture(&refs, &fake, false).unwrap();
        JobRecord {
            created: 1,
            started: 1,
            status: None,
            failed: None,
            actions,
            commit: None,
            host: BTreeMap::new(),
            event_path: None,
            run: None,
            steps: vec![],
            attest: None,
            workflow_ref: None,
            job_workflow_ref: None,
        }
    }

    #[test]
    fn classify_separates_remote_pinned_and_unresolvable_forms() {
        let remote = |o: &str, r: &str, rf: &str| Action::Remote {
            owner: o.into(),
            repo: r.into(),
            reference: rf.into(),
        };
        assert_eq!(
            classify("actions/checkout@v4"),
            Ok(remote("actions", "checkout", "v4"))
        );
        assert_eq!(
            classify("actions/checkout@main"),
            Ok(remote("actions", "checkout", "main"))
        );
        assert_eq!(
            classify("github/codeql-action/init@refs/tags/v3"),
            Ok(remote("github", "codeql-action", "refs/tags/v3"))
        );
        assert_eq!(
            classify(&format!("actions/checkout@{A}")),
            Ok(Action::Pinned(A.into()))
        );
        // Reusable workflow paths resolve against their repository.
        assert_eq!(
            classify("owner/repo/.github/workflows/x.yml@v1"),
            Ok(remote("owner", "repo", "v1"))
        );
        for bad in [
            "actions/checkout@abcd",                                     // short SHA
            "actions/checkout@1234567",                                  // short SHA, all digits
            "actions/checkout@ABCDEF0123456789ABCDEF0123456789ABCDEF01", // uppercase full SHA is not pinned
            "./local@v1",
            "docker://alpine:3.19",
            "ghe.example.com/owner/repo@v1", // host-qualified
            "actions/checkout",              // no ref
            "actions/checkout@",             // empty ref
            "actions/checkout@v1 x",         // odd characters
            "owner/repo/../x@v1",            // traversal
        ] {
            assert!(classify(bad).is_err(), "{bad} must not resolve");
        }
    }

    #[test]
    fn pick_peels_annotated_tags_and_rejects_ambiguity() {
        let peeled = format!("{A}\trefs/tags/v2\n{TAG_OBJECT}\trefs/tags/v2^{{}}\n");
        // Annotated tag: the commit is the peeled line, not the tag object.
        assert_eq!(
            pick(
                &format!("{TAG_OBJECT}\trefs/tags/v2\n{A}\trefs/tags/v2^{{}}\n"),
                "v2"
            ),
            Ok(A.into())
        );
        assert_eq!(pick(&format!("{A}\trefs/tags/v1\n"), "v1"), Ok(A.into()));
        assert_eq!(
            pick(&format!("{A}\trefs/heads/main\n"), "main"),
            Ok(A.into())
        );
        // A tag and a branch naming the same commit agree; different commits are ambiguous.
        assert_eq!(
            pick(&format!("{A}\trefs/tags/x\n{A}\trefs/heads/x\n"), "x"),
            Ok(A.into())
        );
        assert!(pick(&format!("{A}\trefs/tags/x\n{B}\trefs/heads/x\n"), "x").is_err());
        assert!(pick(&peeled, "v9").is_err(), "missing ref");
        assert!(pick("", "v1").is_err(), "empty listing");
        assert!(pick("garbage\n", "v1").is_err(), "no tab");
        assert!(
            pick("notahash\trefs/tags/v1\n", "v1").is_err(),
            "bad object id"
        );
        assert!(
            pick(&format!("{A}\trefs/tags/v1\n{B}\trefs/tags/v1\n"), "v1").is_err(),
            "duplicate"
        );
        let null_id = "0".repeat(40);
        assert!(
            pick(&format!("{null_id}\trefs/tags/v1\n"), "v1").is_err(),
            "null object id"
        );
        assert!(
            classify(&format!("actions/checkout@{null_id}")).is_err(),
            "null pinned SHA"
        );
    }

    fn bare_remote(root: &Path, owner: &str, repo: &str) -> PathBuf {
        let work = root.join(format!("work-{owner}-{repo}"));
        std::fs::create_dir_all(&work).unwrap();
        git(&work, &["init", "-q", "-b", "main"]);
        git(&work, &["commit", "-q", "--allow-empty", "-m", "one"]);
        git(&work, &["tag", "v1"]);
        git(&work, &["tag", "-a", "-m", "annotated", "v2"]);
        let owner_dir = root.join(owner);
        std::fs::create_dir_all(&owner_dir).unwrap();
        let bare = owner_dir.join(format!("{repo}.git"));
        git(
            &work,
            &["clone", "-q", "--bare", ".", bare.to_str().unwrap()],
        );
        bare
    }

    fn git(dir: &Path, args: &[&str]) -> String {
        let out = Cmd::new("git")
            .current_dir(dir)
            .args([
                "-c",
                "commit.gpgsign=false",
                "-c",
                "tag.gpgsign=false",
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("stoop-resolve-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn action_memory_budget_is_shared_across_distinct_job_graphs() {
        let base = scratch("action-memory-budget");
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let api_root = base.join("api");
        let server = crate::gha::actions::FixtureServer::new(api_root.clone());
        let mut archive = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        let data = vec![b'x'; 128 * 1024];
        for (name, bytes) in [
            (
                "action.yml",
                &b"runs:\n  using: node20\n  main: index.js\n"[..],
            ),
            ("index.js", &data[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive
                .append_data(&mut header, format!("repo-sha/{name}"), bytes)
                .unwrap();
        }
        let bytes = archive.into_inner().unwrap().finish().unwrap();
        for index in 0..8 {
            let path = api_root.join(format!("repos/owner/repo{index}/tarball/{A}"));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &bytes).unwrap();
        }
        let bad = api_root.join(format!("repos/owner/broken/tarball/{A}"));
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(bad, b"not a gzip stream").unwrap();
        let mut git = Git::new(&root, &server.url, Duration::from_secs(120));
        git.api = server.url.clone();
        git.set_test_budget(661_000);
        let deadline = Instant::now() + Duration::from_secs(300);
        let budget_before_failure = git.budget.get();
        assert!(git.action_tree("owner", "missing", A, deadline).is_err());
        assert_eq!(git.budget.get(), budget_before_failure);
        assert!(git.action_tree("owner", "broken", A, deadline).is_err());
        assert_eq!(git.budget.get(), budget_before_failure);
        let first = git.action_tree("owner", "repo0", A, deadline).unwrap();
        for index in 1..5 {
            assert!(git
                .action_tree("owner", &format!("repo{index}"), A, deadline)
                .is_ok());
        }
        for index in 5..8 {
            let result = git.action_tree("owner", &format!("repo{index}"), A, deadline);
            assert!(
                matches!(&result, Err(reason) if reason.contains("memory budget")),
                "{:?}",
                result.as_ref().err()
            );
        }
        let cached = git.action_tree("owner", "repo0", A, deadline).unwrap();
        assert!(Rc::ptr_eq(&first, &cached));
        struct Capturer(Rc<Tree>);
        impl Resolver for Capturer {
            fn commit(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
                Err("pinned actions need no ref lookup".into())
            }
            fn action_tree(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: Instant,
            ) -> Result<Rc<Tree>, String> {
                Ok(self.0.clone())
            }
            fn runner_copy(&self, _: &str, _: &str, _: &str, _: Instant) -> Result<Tree, String> {
                Ok((*self.0).clone())
            }
        }
        let tree = Rc::new(Tree::from_gzip_before(&bytes, deadline, u64::MAX).unwrap());
        let mut key_budget = Git::new(&root, &server.url, Duration::from_secs(120));
        key_budget.api = server.url.clone();
        key_budget.set_test_budget(tree.retained());
        let result = key_budget.action_tree("owner", "repo0", A, deadline);
        assert!(
            matches!(&result, Err(reason) if reason.contains("memory budget")),
            "{:?}",
            result.as_ref().err()
        );
        let refs: Vec<String> = (0..8)
            .map(|index| format!("owner/repo{index}@{A}"))
            .collect();
        let recorded = actions::capture(&refs, &Capturer(tree), false).unwrap();
        let mut graph_git = Git::new(&root, &server.url, Duration::from_secs(120));
        graph_git.api = server.url.clone();
        graph_git.set_test_budget(661_000);
        let (code, detail) =
            actions::verify(&refs, &recorded, &graph_git, false, deadline).unwrap_err();
        assert_eq!(code, Code::ActionUnverifiable);
        assert!(detail.contains("memory budget"), "{detail}");
        drop(server);
        std::fs::remove_dir_all(base).unwrap();
    }

    fn file_resolver(root: &Path) -> Git {
        Git::new(
            root,
            format!("file://{}", root.display()),
            Duration::from_secs(60),
        )
    }

    #[test]
    fn git_resolves_tags_branches_and_peels_annotated_tags() {
        let root = scratch("local");
        let bare = bare_remote(&root, "acme", "tool");
        let _ = bare;
        let r = file_resolver(&root);
        let head = git(&root.join("work-acme-tool"), &["rev-parse", "HEAD"]);
        let tag_object = git(&root.join("work-acme-tool"), &["rev-parse", "refs/tags/v2"]);
        assert_ne!(
            tag_object, head,
            "v2 is annotated, so its tag object differs from HEAD"
        );
        assert_eq!(r.commit("acme", "tool", "v1").unwrap(), head);
        assert_eq!(
            r.commit("acme", "tool", "v2").unwrap(),
            head,
            "peeled to the commit"
        );
        assert_eq!(r.commit("acme", "tool", "main").unwrap(), head);
        assert!(
            r.commit("acme", "tool", "nope").is_err(),
            "missing ref fails wide"
        );
        assert!(
            r.commit("acme", "missing", "v1").is_err(),
            "missing repository fails wide"
        );
    }

    #[test]
    fn git_detects_a_moved_tag_and_a_deleted_one() {
        let root = scratch("moved");
        bare_remote(&root, "acme", "tool");
        let work = root.join("work-acme-tool");
        let r = file_resolver(&root);
        let before = r.commit("acme", "tool", "v1").unwrap();
        git(&work, &["commit", "-q", "--allow-empty", "-m", "two"]);
        let moved = git(&work, &["rev-parse", "HEAD"]);
        git(
            &work,
            &[
                "push",
                "-q",
                "-f",
                root.join("acme/tool.git").to_str().unwrap(),
                "HEAD:refs/tags/v1",
            ],
        );
        let after = r.commit("acme", "tool", "v1").unwrap();
        assert_ne!(before, after, "a moved tag must not look unchanged");
        assert_eq!(after, moved);
        git(
            &work,
            &[
                "push",
                "-q",
                root.join("acme/tool.git").to_str().unwrap(),
                ":refs/tags/v1",
            ],
        );
        assert!(
            r.commit("acme", "tool", "v1").is_err(),
            "deleted ref fails wide"
        );
    }

    #[test]
    fn git_fails_wide_on_tag_and_branch_naming_different_commits() {
        let root = scratch("clash");
        bare_remote(&root, "acme", "tool");
        let work = root.join("work-acme-tool");
        let bare = root.join("acme/tool.git");
        git(&work, &["commit", "-q", "--allow-empty", "-m", "two"]);
        git(
            &work,
            &["push", "-q", bare.to_str().unwrap(), "HEAD:refs/heads/v1"],
        );
        assert!(file_resolver(&root).commit("acme", "tool", "v1").is_err());
    }

    /// Serves a fixed response to every connection, like a dumb HTTP git server.
    /// `hold` accepts and never answers, for timeouts.
    fn serve(status: &'static str, body: String, hold: bool) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            for stream in listener.incoming().take(6) {
                let Ok(mut stream) = stream else { return };
                let mut request = [0u8; 4096];
                let _ = std::io::Read::read(&mut stream, &mut request);
                if hold {
                    thread::sleep(Duration::from_secs(30));
                    return;
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nLocation: http://127.0.0.1:9/elsewhere\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            }
        });
        (base, handle)
    }

    /// Redirects git's smart-HTTP probe (the request carrying `service=`) to `target`,
    /// and serves the plain listing on every other request, as a dumb server does. A
    /// client that follows the redirect reaches a valid listing; one that refuses it fails.
    fn serve_redirecting_probe(target: String) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let listing = format!("{A}\trefs/tags/v1\n");
        let handle = thread::spawn(move || {
            for stream in listener.incoming().take(6) {
                let Ok(mut stream) = stream else { return };
                let mut request = [0u8; 4096];
                let n = std::io::Read::read(&mut stream, &mut request).unwrap_or(0);
                let head = String::from_utf8_lossy(&request[..n]).to_string();
                let response = if head.contains("service=") {
                    format!("HTTP/1.1 301 Moved Permanently\r\nLocation: {target}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{listing}",
                        listing.len()
                    )
                };
                let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
            }
        });
        (base, handle)
    }

    /// A resolver whose working directory no other test touches.
    fn http_resolver(base: String, timeout: Duration) -> Git {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Git::new(scratch(&format!("http-{n}")), base, timeout)
    }

    #[test]
    fn git_reads_a_dumb_listing_with_peeled_tags() {
        let body = format!("{A}\trefs/tags/v2\n{B}\trefs/tags/v2^{{}}\n{A}\trefs/heads/main\n");
        let (base, _h) = serve("200 OK", body, false);
        assert_eq!(
            http_resolver(base, Duration::from_secs(10))
                .commit("o", "r", "v2")
                .unwrap(),
            B
        );
    }

    #[test]
    fn git_fails_wide_on_every_error_class() {
        let bad_id = format!("{}\trefs/tags/v1\n", "x".repeat(40));
        let duplicate = format!("{A}\trefs/tags/v1\n{B}\trefs/tags/v1\n");
        // Each case must fail wide: 401 must not prompt, and a listing that is not a
        // listing is never trusted.
        let cases: [(&str, &str); 7] = [
            ("429 Too Many Requests", "slow down"),
            ("500 Internal Server Error", "boom"),
            ("401 Unauthorized", "no"),
            ("200 OK", "not a listing\n"),
            ("200 OK", bad_id.as_str()),
            ("200 OK", duplicate.as_str()),
            ("200 OK", "<html>captive portal</html>\n"),
        ];
        for (status, body) in cases {
            let (base, _h) = serve(status, body.to_string(), false);
            let result = http_resolver(base, Duration::from_secs(10)).commit("o", "r", "v1");
            assert!(
                result.is_err(),
                "{status} with {body:?} must fail wide, got {result:?}"
            );
        }
    }

    #[test]
    fn git_does_not_follow_a_redirect_to_a_valid_listing() {
        // The target serves a valid listing on every request, so a client that follows
        // the redirect succeeds. Only refusing the redirect makes this fail wide.
        let (target, _t) = serve("200 OK", format!("{A}\trefs/tags/v1\n"), false);
        let target = format!("{target}/moved/o/r.git/info/refs?service=git-upload-pack");
        let (base, _h) = serve_redirecting_probe(target);
        let result = http_resolver(base, Duration::from_secs(10)).commit("o", "r", "v1");
        assert!(result.is_err(), "a redirect must fail wide, got {result:?}");
    }

    #[test]
    fn git_times_out_instead_of_stalling_a_plan() {
        let (base, _h) = serve("200 OK", String::new(), true);
        let started = Instant::now();
        let result = http_resolver(base, Duration::from_millis(800)).commit("o", "r", "v1");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "stalled for {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn git_fails_wide_when_the_server_is_unreachable() {
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let r = http_resolver(format!("http://127.0.0.1:{port}"), Duration::from_secs(10));
        assert!(r.commit("o", "r", "v1").is_err());
    }

    #[test]
    fn full_sha_needs_no_lookup_and_memo_asks_once_per_action() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        fake.set("actions/setup-node@v4", Err("no such ref"));
        let refs = vec![
            "actions/checkout@v4".into(),
            "actions/checkout@v4".into(),
            format!("actions/cache@{B}"),
        ];
        let actions = crate::gha::actions::capture(&refs, &fake, false).unwrap();
        assert_eq!(
            fake.calls(),
            1,
            "pinned commits need no lookup, duplicates share one lookup"
        );
        assert_eq!(
            actions.get("actions/checkout@v4").map(String::as_str),
            Some(A)
        );
        assert_eq!(
            actions
                .get(&format!("actions/cache@{B}"))
                .map(String::as_str),
            Some(B)
        );
        assert!(
            crate::gha::actions::capture(&["actions/setup-node@v4".into()], &fake, false).is_err()
        );
    }

    #[test]
    fn record_then_plan_accepts_the_same_commits() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        fake.set("actions/setup-node@v4", Ok(B));
        let actions = crate::gha::actions::capture(
            &["actions/checkout@v4".into(), "actions/setup-node@v4".into()],
            &fake,
            false,
        )
        .unwrap();
        let rec = JobRecord {
            actions,
            ..record(&[])
        };
        let check = ActionCheck::new(&fake);
        assert!(check
            .check(
                &spec(&["actions/checkout@v4", "actions/setup-node@v4"], &[]),
                &rec
            )
            .is_ok());
    }

    #[test]
    fn a_moved_action_fails_as_an_input_change() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let rec = record(&[("actions/checkout@v4", A)]);
        fake.set("actions/checkout@v4", Ok(B)); // the tag moved after the record
        let check = ActionCheck::new(&fake);
        let (code, detail) = check
            .check(&spec(&["actions/checkout@v4"], &[]), &rec)
            .unwrap_err();
        assert_eq!(code, Code::ActionMoved);
        assert!(detail.contains(B) && detail.contains(A), "{detail}");
    }

    #[test]
    fn a_resolution_error_is_unresolved_not_unchanged() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Err("git ls-remote timed out"));
        let rec = record(&[("actions/checkout@v4", A)]);
        let check = ActionCheck::new(&fake);
        let (code, _) = check
            .check(&spec(&["actions/checkout@v4"], &[]), &rec)
            .unwrap_err();
        assert_eq!(
            code,
            Code::ActionUnverifiable,
            "an error must never read as unchanged"
        );
    }

    #[test]
    fn a_record_without_the_action_cannot_prove_it() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let check = ActionCheck::new(&fake);
        let (code, _) = check
            .check(&spec(&["actions/checkout@v4"], &[]), &record(&[]))
            .unwrap_err();
        assert_eq!(
            code,
            Code::ActionUnverifiable,
            "records from before resolution have no answer"
        );
    }

    #[test]
    fn unresolvable_forms_and_floating_images_run_the_job() {
        let fake = Fake::new();
        let rec = record(&[]);
        let check = ActionCheck::new(&fake);
        for s in [
            spec(&["actions/checkout@abcd"], &[]),
            spec(&["./local@v1"], &[]),
        ] {
            assert_eq!(
                check.check(&s, &rec).unwrap_err().0,
                Code::ActionUnverifiable
            );
        }
        for s in [
            spec(&[], &["node:20"]),
            spec(&[], &["ghcr.io/acme/app:latest"]),
        ] {
            assert_eq!(check.check(&s, &rec).unwrap_err().0, Code::UnresolvedAction);
        }
        assert_eq!(fake.calls(), 0, "classification never reaches the network");
        assert!(ActionCheck::new(&fake)
            .check(&spec(&[], &[&format!("node@{DIGEST}")]), &rec)
            .is_ok());
        assert!(image_pinned(&format!("node@{DIGEST}")));
        assert!(!image_pinned("node@sha256:short"));
        assert!(!image_pinned("node@md5:0123"));
    }

    #[test]
    fn check_asks_once_per_distinct_action_across_records() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let check = ActionCheck::new(&fake);
        let s = spec(&["actions/checkout@v4", "actions/checkout@v4"], &[]);
        for _ in 0..3 {
            let _ = check.check(&s, &record(&[("actions/checkout@v4", A)]));
        }
        assert_eq!(fake.calls(), 1);
    }
    #[test]
    fn strict_policy_refuses_floating_actions_but_accepts_pins() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let floating = spec(&["actions/checkout@v4"], &[]);
        let rec = record(&[("actions/checkout@v4", A)]);
        assert_eq!(
            ActionCheck::with_strict(&fake, true)
                .check(&floating, &rec)
                .unwrap_err()
                .0,
            Code::ActionUnverifiable
        );
        assert_eq!(fake.calls(), 0);
        assert!(ActionCheck::with_strict(&fake, false)
            .check(&floating, &rec)
            .is_ok());
        let pin = format!("actions/checkout@{A}");
        assert!(matches!(classify(&pin), Ok(Action::Pinned(_))));
        assert!(ActionCheck::with_strict(&fake, true)
            .check(&spec(&[&pin], &[]), &record(&[(&pin, A)]))
            .is_ok());
    }
    #[test]
    fn second_action_change_and_second_image_are_checked() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        fake.set("actions/setup-node@v4", Ok(B));
        let rec = record(&[("actions/checkout@v4", A), ("actions/setup-node@v4", A)]);
        let check = ActionCheck::with_strict(&fake, false);
        assert_eq!(
            check
                .check(
                    &spec(&["actions/checkout@v4", "actions/setup-node@v4"], &[]),
                    &rec
                )
                .unwrap_err()
                .0,
            Code::ActionMoved
        );
        let pinned = format!("node@{DIGEST}");
        assert_eq!(
            check
                .check(&spec(&[], &[&pinned, "redis:7"]), &rec)
                .unwrap_err()
                .0,
            Code::UnresolvedAction
        );
    }

    #[test]
    fn failed_lookups_are_cached_across_records() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Err("unavailable"));
        let check = ActionCheck::with_strict(&fake, false);
        let s = spec(&["actions/checkout@v4"], &[]);
        for _ in 0..3 {
            assert_eq!(
                check
                    .check(&s, &record(&[("actions/checkout@v4", A)]))
                    .unwrap_err()
                    .0,
                Code::ActionUnverifiable
            );
        }
        assert_eq!(fake.calls(), 1);
    }
    #[test]
    fn plan_caller_controls_strict_policy_not_constructor_environment() {
        const CHILD: &str = "STOOP_STRICT_POLICY_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let out = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "gha::resolve::tests::plan_caller_controls_strict_policy_not_constructor_environment"])
                .env(CHILD, "1")
                .env("STOOP_STRICT_ACTIONS", "1")
                .output().unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stdout)
            );
            return;
        }
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let job = spec(&["actions/checkout@v4"], &[]);
        let recorded = record(&[("actions/checkout@v4", A)]);
        assert!(ActionCheck::new(&fake).check(&job, &recorded).is_ok());
        let strict = run::env_flag("STOOP_STRICT_ACTIONS");
        assert_eq!(
            ActionCheck::with_strict(&fake, strict)
                .check(&job, &recorded)
                .unwrap_err()
                .0,
            Code::ActionUnverifiable
        );
    }

    #[test]
    fn ghes_tarball_download_is_cached_within_a_plan() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let body = crate::gha::actions::fixture_archive();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for hop in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.ends_with(b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..n]);
                }
                requests.push(String::from_utf8(request).unwrap());
                if hop == 0 {
                    write!(stream, "HTTP/1.1 302 Found\r\nLocation: http://{address}/archive\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
            requests
        });
        let base = std::env::temp_dir().join(format!(
            "stoop-action-http-{}-{}",
            std::process::id(),
            address.port()
        ));
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let git = Git::new(&root, format!("http://{address}"), Duration::from_secs(5));
        let first = git
            .action_tree("owner", "repo", A, Instant::now() + Duration::from_secs(5))
            .unwrap();
        let second = git
            .action_tree("owner", "repo", A, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(
            Rc::ptr_eq(&first, &second),
            "same-run cache must avoid a second request"
        );
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(&format!("GET /api/v3/repos/owner/repo/tarball/{A} ")));
        assert!(requests[1].starts_with("GET /archive "));
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn archive_redirects_are_bounded_and_cannot_change_scheme() {
        use std::io::{Read, Write};
        for change_scheme in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let server = thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(3);
                let mut seen = 0;
                while Instant::now() < end && seen < 5 {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            stream
                                .set_read_timeout(Some(Duration::from_millis(500)))
                                .unwrap();
                            let mut request = [0u8; 4096];
                            let _ = stream.read(&mut request);
                            seen += 1;
                            if seen == 5 {
                                let body = crate::gha::actions::fixture_archive();
                                let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                                let _ = stream.write_all(&body);
                            } else {
                                let scheme = if change_scheme { "https" } else { "http" };
                                let _ = write!(stream, "HTTP/1.1 302 Found\r\nLocation: {scheme}://{address}/again\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5))
                        }
                        Err(e) => panic!("fixture accept: {e}"),
                    }
                }
                seen
            });
            let base = scratch(if change_scheme {
                "redirect-scheme"
            } else {
                "redirect-limit"
            });
            let git = Git::new(&base, format!("http://{address}"), Duration::from_secs(5));
            assert!(git
                .action_tree("owner", "repo", A, Instant::now() + Duration::from_secs(5))
                .is_err());
            assert_eq!(server.join().unwrap(), if change_scheme { 1 } else { 4 });
            std::fs::remove_dir_all(base).unwrap();
        }
    }

    #[test]
    fn redirected_nonlocal_host_is_rejected_by_the_test_transport() {
        use std::io::{Read, Write};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for hop in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request);
                if hop == 0 {
                    write!(stream, "HTTP/1.1 302 Found\r\nLocation: http://example.invalid/archive\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                } else {
                    let body = crate::gha::actions::fixture_archive();
                    write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
        });
        let base = scratch("nonlocal-redirect");
        let git = Git::new(&base, format!("http://{address}"), Duration::from_secs(5));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            git.action_tree("owner", "repo", A, Instant::now() + Duration::from_secs(5))
        }));
        assert!(result.is_err(), "non-loopback redirect must fail the test");
        server.join().unwrap();
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn stalled_tarball_fails_within_the_total_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(2);
            while Instant::now() < end {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !request.ends_with(b"\r\n\r\n") {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => request.extend_from_slice(&chunk[..n]),
                            }
                        }
                        thread::sleep(Duration::from_millis(500));
                        let body = crate::gha::actions::fixture_archive();
                        let _ = write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(&body);
                        return;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
        });
        let base = std::env::temp_dir().join(format!(
            "stoop-action-timeout-{}-{}",
            std::process::id(),
            address.port()
        ));
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let git = Git::new(&root, format!("http://{address}"), Duration::from_secs(3));
        assert!(git
            .action_tree(
                "owner",
                "repo",
                A,
                Instant::now() + Duration::from_millis(150)
            )
            .is_err());
        server.join().unwrap();
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn fresh_http_download_detects_tampered_bytes_for_the_same_sha() {
        use std::io::{Read, Write};
        struct Network<'a>(&'a Git);
        impl Resolver for Network<'_> {
            fn commit(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
                Ok(A.into())
            }
            fn action_tree(
                &self,
                owner: &str,
                repo: &str,
                sha: &str,
                deadline: Instant,
            ) -> Result<Rc<Tree>, String> {
                self.0.action_tree(owner, repo, sha, deadline)
            }
            fn runner_copy(&self, _: &str, _: &str, _: &str, _: Instant) -> Result<Tree, String> {
                Ok(crate::gha::actions::fixture_tree())
            }
        }
        let mut tar = tar::Builder::new(flate2::write::GzEncoder::new(
            Vec::new(),
            flate2::Compression::default(),
        ));
        for (name, contents) in [
            (
                "action.yml",
                &b"runs:\n  using: node20\n  main: index.js\n"[..],
            ),
            ("index.js", &b"tampered\n"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o644);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, format!("repo-sha/{name}"), contents)
                .unwrap();
        }
        let tampered = tar.into_inner().unwrap().finish().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let mut bodies = vec![crate::gha::actions::fixture_archive(), tampered].into_iter();
            let end = Instant::now() + Duration::from_secs(10);
            let mut served = 0;
            while Instant::now() < end {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 1024];
                        while !request.ends_with(b"\r\n\r\n") {
                            let n = stream.read(&mut chunk).unwrap();
                            if n == 0 {
                                break;
                            }
                            request.extend_from_slice(&chunk[..n]);
                        }
                        let Some(body) = bodies.next() else { break };
                        write!(
                            stream,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        stream.write_all(&body).unwrap();
                        served += 1;
                        if served == 2 {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("fixture accept: {e}"),
                }
            }
            served
        });
        let base = std::env::temp_dir().join(format!(
            "stoop-action-tamper-{}-{}",
            std::process::id(),
            address.port()
        ));
        let root = base.join("repo");
        std::fs::create_dir_all(&root).unwrap();
        let make_git = || Git::new(&root, format!("http://{address}"), Duration::from_secs(5));
        let recording = make_git();
        let refs = vec!["owner/repo@v1".to_string()];
        let saved = actions::capture(&refs, &Network(&recording), false).unwrap();
        let planning = make_git();
        let (code, _) = actions::verify(
            &refs,
            &saved,
            &Network(&planning),
            false,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap_err();
        assert_eq!(code, Code::ActionContentChanged);
        assert_eq!(server.join().unwrap(), 2);
        std::fs::remove_dir_all(base).unwrap();
    }
}
