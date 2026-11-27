//! Bounded, local suite rosters. A bundle does not itself confer a proof hit.

use super::attribution::Refusal;
use super::residue;
use crate::input::Input;
use crate::proof::{now, Proof};
#[cfg(not(unix))]
use crate::sys::Private;
use crate::trace::Provenance;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const VERSION: u32 = 1;
const GENERATION: u32 = 2;
const MAX_UNITS: usize = 4096;
const MAX_UNIT_BYTES: usize = 4096;
const MAX_VERSIONS: usize = 8;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// `forget --units` removes the lock file, so a process waiting on the old file can take a lock
/// that no other process contends for. A lock is trusted only while it is still the named entry.
const LOCK_ATTEMPTS: usize = 3;
/// The least time between two writes of a pass's bundle. A pass writes its bundle when it stores
/// its first unit proof, then at most once a second as it stores more, and at its end. A killed
/// pass keeps what its last write held; units whose proofs were lost get no unit proof until
/// `stoop forget --units`.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Serialize, Deserialize)]
struct Origin {
    kind: String,
    cwd: String,
    scope: Option<String>,
    /// A digest of the argument words and the label, bound to the suite ID. The words themselves
    /// are never stored: a secret passed as an argument must not reach the suite store.
    invocation: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Roster {
    source: String,
    units: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct LaunchGuard {
    #[serde(deserialize_with = "unique_map")]
    pub(crate) env: BTreeMap<String, String>,
    pub(crate) env_excluded: Vec<String>,
    pub(crate) ignore: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) unit_env: Option<String>,
}

impl LaunchGuard {
    /// The guard's digest: a BLAKE3 hash of its JSON, in which the environment, the excluded names and the ignore
    /// patterns each appear in one canonical form, sorted with repeats removed. Every guard digest goes through
    /// this function, so two guards that differ only in the order of their lists share one digest (spec 3.6).
    pub(crate) fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Canonical<'a> {
            env: &'a BTreeMap<String, String>,
            env_excluded: Vec<&'a str>,
            ignore: Vec<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            unit_env: Option<&'a str>,
        }
        let canonical = Canonical {
            env: &self.env,
            env_excluded: sorted(&self.env_excluded),
            ignore: sorted(&self.ignore),
            unit_env: self.unit_env.as_deref(),
        };
        let bytes = serde_json::to_vec(&canonical).expect("a guard always serializes");
        blake3::hash(&bytes).to_hex().to_string()
    }
}

/// The distinct strings of a list, sorted.
fn sorted(items: &[String]) -> Vec<&str> {
    let mut out: Vec<&str> = items.iter().map(String::as_str).collect();
    out.sort_unstable();
    out.dedup();
    out
}

#[derive(Clone, Serialize, Deserialize)]
struct UnitVersion {
    created: u64,
    exact: bool,
    source: ResultSource,
    guard: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unit_env: Option<String>,
    inputs: Vec<u32>,
    outputs: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResultSource {
    Exit,
    Records,
    Receipt { decoder: String },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResidueState {
    None,
    Provisional,
    Confirmed,
}

#[derive(Clone, Serialize, Deserialize)]
struct Residue {
    state: ResidueState,
    /// The first `residue::STORED` paths, in sorted order. `count` is how many paths the residue holds in all.
    paths: Vec<String>,
    /// How many paths the residue holds (spec 3.8). A bundle written before this field holds no residue to count.
    #[serde(default)]
    count: usize,
    whole: Option<String>,
}

impl Default for Residue {
    fn default() -> Self {
        Self {
            state: ResidueState::None,
            paths: Vec::new(),
            count: 0,
            whole: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SuiteState {
    Ready,
    Disabled {
        code: String,
        phase: String,
        label: String,
        at: u64,
    },
}

#[derive(Serialize, Deserialize)]
struct SuiteBundleV1 {
    v: u32,
    generation: u32,
    suite: String,
    provenance: Provenance,
    origin: Origin,
    /// A digest of the legacy whole-command key, which names the program as typed.
    whole_key_digest: String,
    whole: Option<String>,
    policy: String,
    guard: LaunchGuard,
    guard_digest: String,
    roster: Roster,
    /// The roster that the whole proof was judged with (spec 3.10, PR 86 review round 5). Only a split run's full command
    /// sets it. Empty when no split run recorded the proof, which makes every roster unit new until the next full run.
    /// It is omitted when empty, so a bundle that no split run recorded keeps its bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    whole_roster: Vec<String>,
    table: Vec<Input>,
    #[serde(deserialize_with = "unique_map")]
    units: BTreeMap<String, Vec<UnitVersion>>,
    residue: Residue,
    state: SuiteState,
}

/// A JSON object with a repeated key is ambiguous, so the whole file is refused as corrupt.
fn unique_map<'de, D, V>(deserializer: D) -> Result<BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Deserialize<'de>,
{
    struct Unique<V>(std::marker::PhantomData<V>);

    impl<'de, V: Deserialize<'de>> serde::de::Visitor<'de> for Unique<V> {
        type Value = BTreeMap<String, V>;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some((key, value)) = map.next_entry::<String, V>()? {
                if out.insert(key, value).is_some() {
                    return Err(serde::de::Error::custom("a key is repeated"));
                }
            }
            Ok(out)
        }
    }

    deserializer.deserialize_map(Unique(std::marker::PhantomData))
}

/// A roster and invocation identity, captured before the whole command runs.
pub(crate) struct Pending {
    suite: String,
    origin: Origin,
    roster: Roster,
    policy: String,
    /// The catalog's listing paths for this run's walk, sorted. The residue leaves them out (spec 3.8).
    listings: Vec<String>,
    unit_env: BTreeMap<String, String>,
    unit_env_digest: Option<String>,
}

impl Pending {
    pub(crate) fn suite(&self) -> &str {
        &self.suite
    }

    pub(crate) fn units(&self) -> &[String] {
        &self.roster.units
    }

    pub(crate) fn listings(&self) -> &[String] {
        &self.listings
    }

    pub(crate) fn unit_env(&self) -> &BTreeMap<String, String> {
        &self.unit_env
    }

    pub(crate) fn unit_env_digest(&self) -> Option<String> {
        self.unit_env_digest.clone()
    }
}

fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

/// An absent value and an empty value are different inputs, so each carries a presence byte.
fn optional(hash: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        None => {
            hash.update(&[0]);
        }
        Some(value) => {
            hash.update(&[1]);
            field(hash, value.as_bytes());
        }
    }
}

pub(crate) fn suite_id(
    argv: &[OsString],
    cwd: &str,
    scope: Option<&str>,
    label: Option<&str>,
) -> String {
    let mut hash = blake3::Hasher::new_derive_key("stoop suite id v1");
    field(&mut hash, b"hook");
    optional(&mut hash, scope);
    field(&mut hash, cwd.as_bytes());
    for word in argv {
        field(&mut hash, word.as_encoded_bytes());
    }
    optional(&mut hash, label);
    hash.finalize().to_hex()[..32].to_string()
}

/// A domain-separated digest of the invocation. It stands in for the argument text, which is
/// never persisted: the suite ID binds the same inputs.
fn invocation_digest(argv: &[OsString], label: Option<&str>) -> String {
    let mut hash = blake3::Hasher::new_derive_key("stoop suite invocation v1");
    for word in argv {
        field(&mut hash, word.as_encoded_bytes());
    }
    optional(&mut hash, label);
    hash.finalize().to_hex().to_string()
}

fn digest_text(context: &str, text: &str) -> String {
    let mut hash = blake3::Hasher::new_derive_key(context);
    field(&mut hash, text.as_bytes());
    hash.finalize().to_hex().to_string()
}

pub(crate) struct PendingSpec<'a> {
    pub argv: &'a [OsString],
    pub cwd: &'a str,
    pub scope: Option<&'a str>,
    pub label: Option<&'a str>,
    pub source: &'a str,
    pub filter: &'a str,
    pub units: Vec<String>,
    pub config: Option<&'a [u8]>,
    pub config_suite: Option<&'a str>,
    pub unit_env: BTreeMap<String, String>,
    /// The listing paths of this run's catalog walk, which the residue leaves out (spec 3.8).
    pub listings: Vec<String>,
}

/// The caller supplies the catalog rebuilt for this invocation, never its listing inputs.
pub(crate) fn pending(spec: PendingSpec<'_>) -> Result<Pending, Refusal> {
    let PendingSpec {
        argv,
        cwd,
        scope,
        label,
        source,
        filter,
        units,
        config,
        config_suite,
        unit_env,
        listings,
    } = spec;
    if units.is_empty() {
        return Err(Refusal::NoUnits);
    }
    if units.len() > MAX_UNITS
        || !valid_roster(&units)
        || argv.iter().any(|word| word.to_str().is_none())
    {
        return Err(Refusal::Unrecordable);
    }
    let mut hash = blake3::Hasher::new_derive_key("stoop suite policy v1");
    field(&mut hash, source.as_bytes());
    field(&mut hash, filter.as_bytes());
    field(&mut hash, config_suite.unwrap_or("").as_bytes());
    field(&mut hash, config.unwrap_or_default());
    let unit_env_digest = (!unit_env.is_empty()).then(|| {
        let mut hash = blake3::Hasher::new_derive_key("stoop unit env v1");
        for (name, value) in &unit_env {
            field(&mut hash, name.as_bytes());
            field(&mut hash, value.as_bytes());
        }
        hash.finalize().to_hex().to_string()
    });
    Ok(Pending {
        suite: suite_id(argv, cwd, scope, label),
        origin: Origin {
            kind: "hook".into(),
            cwd: cwd.into(),
            scope: scope.map(str::to_owned),
            invocation: invocation_digest(argv, label),
        },
        roster: Roster {
            source: source.into(),
            units,
        },
        policy: hash.finalize().to_hex().to_string(),
        listings,
        unit_env,
        unit_env_digest,
    })
}

fn valid_suite_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_unit(unit: &str) -> bool {
    let path = unit.strip_suffix('/').unwrap_or(unit);
    !path.is_empty()
        && unit.len() <= MAX_UNIT_BYTES
        && !unit.contains(['\0', '\n'])
        && !path.starts_with('/')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}

fn valid_roster(units: &[String]) -> bool {
    units.iter().all(|unit| valid_unit(unit)) && units.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_bundle(bundle: &SuiteBundleV1, id: &str) -> bool {
    bundle.v == VERSION
        && bundle.suite == id
        && bundle.roster.units.len() <= MAX_UNITS
        && valid_roster(&bundle.roster.units)
        && bundle.whole_roster.len() <= MAX_UNITS
        && valid_roster(&bundle.whole_roster)
        && bundle.units.len() <= MAX_UNITS
        && bundle
            .units
            .iter()
            .all(|(unit, versions)| valid_unit(unit) && versions.len() <= MAX_VERSIONS)
        && valid_residue(&bundle.residue)
}

/// A residue names the first `residue::STORED` of its paths, in sorted order, and its count holds every path.
fn valid_residue(residue: &Residue) -> bool {
    residue.paths.len() == residue.count.min(residue::STORED)
        && residue.paths.windows(2).all(|pair| pair[0] < pair[1])
}

fn bundle_name(id: &str) -> String {
    format!("{id}.json")
}

fn lock_name(id: &str) -> String {
    format!("{id}.lock")
}

/// What an entry below the suite directory is.
#[derive(Clone, Copy)]
struct Stat {
    regular: bool,
    #[cfg_attr(not(unix), allow(dead_code))]
    id: (u64, u64),
}

/// The longest path that a launch's list file can take under `store` for `suite` (spec 6): the scratch folder's name with
/// 20 digits each for its pid and its counter, and the longest list name. Explain and the run both count a list path at
/// this length, so the fit check agrees with the launch.
pub(crate) fn scratch_path_max(store: &Path, suite: &str) -> usize {
    let digits = "0".repeat(20);
    let folder = format!(".{suite}-{digits}-{digits}.scratch");
    store
        .join("units")
        .join("v1")
        .join(folder)
        .join("changed-root")
        .as_os_str()
        .len()
}

/// The suite directory `<store>/units/v1`. Every name below it is opened, renamed and removed
/// relative to this descriptor without following links, so a link in the suite path refuses the
/// access instead of leading it outside the store. The configured store directory itself may be a
/// link, because the user chose it.
pub(crate) struct Area {
    #[cfg(unix)]
    dir: std::os::fd::OwnedFd,
    /// The suite directory's own path, which each launch's list files are named under (spec 3.7).
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(not(unix))]
    dir: PathBuf,
}

#[cfg(not(unix))]
fn is_link(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    meta.file_type().is_symlink() || reparse
}

#[cfg(not(unix))]
fn refuse_link(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if is_link(&meta) => Err(io::Error::other(
            "a link is in the suite store; it is not followed",
        )),
        _ => Ok(()),
    }
}

impl Area {
    /// Opens `<store>/units/v1`. `Ok(None)` means it is absent and `create` is false.
    pub(crate) fn open(store: &Path, create: bool) -> io::Result<Option<Area>> {
        if create {
            fs::create_dir_all(store)?;
        }
        #[cfg(unix)]
        {
            let root = match at::open_store(store) {
                Ok(root) => root,
                Err(error) if !create && error.kind() == io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
            let Some(units) = at::open_dir(&root, "units", create)? else {
                return Ok(None);
            };
            let Some(dir) = at::open_dir(&units, "v1", create)? else {
                return Ok(None);
            };
            Ok(Some(Area {
                dir,
                path: store.join("units").join("v1"),
            }))
        }
        #[cfg(not(unix))]
        {
            let units = store.join("units");
            let dir = units.join("v1");
            for part in [&units, &dir] {
                match fs::symlink_metadata(part) {
                    Ok(meta) if is_link(&meta) => {
                        return Err(io::Error::other(
                            "a link is in the suite store; it is not followed",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound && create => {
                        fs::create_dir(part)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                    Err(error) => return Err(error),
                }
            }
            Ok(Some(Area { dir }))
        }
    }

    /// Opens a regular entry for reading. `Ok(None)` when it is absent.
    fn read(&self, name: &str) -> io::Result<Option<File>> {
        #[cfg(unix)]
        {
            match at::open_file(&self.dir, name, libc::O_RDONLY | libc::O_NONBLOCK) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
        #[cfg(not(unix))]
        {
            let path = self.dir.join(name);
            refuse_link(&path)?;
            match File::open(&path) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
    }

    /// Opens the lock entry, creating it if needed. Only a regular file with one name is taken. A
    /// FIFO, device or directory is refused before it is locked, and a hard-linked file is shared
    /// with another name.
    fn lock_file(&self, name: &str) -> io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let file = at::open_file(
                &self.dir,
                name,
                libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK,
            )?;
            let meta = file.metadata()?;
            if !meta.is_file() || meta.nlink() != 1 {
                return Err(io::Error::other(
                    "the suite lock is not a regular file with one name",
                ));
            }
            Ok(file)
        }
        #[cfg(not(unix))]
        {
            let path = self.dir.join(name);
            refuse_link(&path)?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .private()
                .open(path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::other("the suite lock is not a regular file"));
            }
            Ok(file)
        }
    }

    /// Creates a new temporary entry. It fails if the name exists.
    fn create_temp(&self, name: &str) -> io::Result<File> {
        #[cfg(unix)]
        {
            at::open_file(
                &self.dir,
                name,
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            )
        }
        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .private()
                .open(self.dir.join(name))
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            at::rename(&self.dir, from, to)
        }
        #[cfg(not(unix))]
        {
            refuse_link(&self.dir.join(to))?;
            fs::rename(self.dir.join(from), self.dir.join(to))
        }
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            at::unlink(&self.dir, name)
        }
        #[cfg(not(unix))]
        {
            fs::remove_file(self.dir.join(name))
        }
    }

    /// What the entry is, without following a link. `Ok(None)` when it is absent.
    fn stat(&self, name: &str) -> io::Result<Option<Stat>> {
        #[cfg(unix)]
        {
            at::stat(&self.dir, name)
        }
        #[cfg(not(unix))]
        {
            match fs::symlink_metadata(self.dir.join(name)) {
                Ok(meta) => Ok(Some(Stat {
                    regular: meta.is_file() && !is_link(&meta),
                    id: (0, 0),
                })),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error),
            }
        }
    }

    fn names(&self) -> io::Result<Vec<String>> {
        #[cfg(unix)]
        {
            at::names(&self.dir)
        }
        #[cfg(not(unix))]
        {
            Ok(fs::read_dir(&self.dir)?
                .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
                .collect())
        }
    }

    /// Whether a new entry can be made in the suite directory. A pass that could not store its
    /// first proof would launch every unit and keep nothing, so it does not start.
    fn writable(&self, suite: &str) -> bool {
        let name = format!(
            ".{suite}-{}-{}.tmp",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        match self.create_temp(&name) {
            Ok(file) => {
                drop(file);
                let _ = self.unlink(&name);
                true
            }
            Err(_) => false,
        }
    }

    /// Whether a new entry can be made in the suite directory, checked without making one: the
    /// directory's write permission. Explain uses this, so it creates nothing. Windows has no such
    /// check here, and explain prints no suite lines there, because the tracer is unavailable.
    fn writable_dir(&self) -> bool {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the descriptor is an open directory, and "." is a valid C string.
            unsafe { libc::faccessat(self.dir.as_raw_fd(), c".".as_ptr(), libc::W_OK, 0) == 0 }
        }
        #[cfg(not(unix))]
        {
            true
        }
    }

    /// Removes a launch directory that a killed run left, with the files it holds. A name that is
    /// not a directory is removed as an entry. Only a pass that holds the suite lock calls this.
    fn clear_scratch(&self, name: &str) {
        #[cfg(unix)]
        {
            match at::open_dir(&self.dir, name, false) {
                Ok(Some(dir)) => {
                    at::empty(&dir);
                    drop(dir);
                    let _ = at::rmdir(&self.dir, name);
                }
                _ => {
                    let _ = at::unlink(&self.dir, name);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let path = self.dir.join(name);
            if fs::remove_dir_all(&path).is_err() {
                let _ = fs::remove_file(&path);
            }
        }
    }

    /// Whether the open lock file is still the entry the name refers to. Windows offers no file
    /// identity through std, so the lock is trusted as opened there.
    fn same_entry(&self, file: &File, name: &str) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (file.metadata(), self.stat(name)) {
                (Ok(held), Ok(Some(named))) => {
                    named.regular && (held.dev(), held.ino()) == named.id
                }
                _ => false,
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (file, name);
            true
        }
    }
}

#[cfg(unix)]
mod at {
    use super::Stat;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    fn name(text: &str) -> io::Result<CString> {
        CString::new(text)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a name holds a NUL byte"))
    }

    fn check(rc: libc::c_int) -> io::Result<libc::c_int> {
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc)
        }
    }

    fn owned(fd: libc::c_int) -> OwnedFd {
        // SAFETY: `fd` is a freshly opened descriptor that nothing else owns.
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    /// The configured store directory. It may be reached through a link, because the user chose it.
    pub(super) fn open_store(path: &Path) -> io::Result<OwnedFd> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a path holds a NUL byte"))?;
        // SAFETY: `path` is a NUL-terminated string that lives for the call.
        let fd = check(unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        Ok(owned(fd))
    }

    /// Opens a directory below `parent` without following a link. `Ok(None)` when it is absent
    /// and `create` is false. A name that something else holds makes `mkdirat` fail, and the open
    /// that follows refuses it.
    pub(super) fn open_dir(
        parent: &OwnedFd,
        text: &str,
        create: bool,
    ) -> io::Result<Option<OwnedFd>> {
        let text = name(text)?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `text` is NUL-terminated and `parent` is an open directory descriptor.
        let mut fd = unsafe { libc::openat(parent.as_raw_fd(), text.as_ptr(), flags) };
        if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
            // SAFETY: as above; the mode is private to the user.
            unsafe { libc::mkdirat(parent.as_raw_fd(), text.as_ptr(), 0o700) };
            // SAFETY: as above.
            fd = unsafe { libc::openat(parent.as_raw_fd(), text.as_ptr(), flags) };
        }
        if fd < 0 {
            let error = io::Error::last_os_error();
            return if !create && error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        Ok(Some(owned(fd)))
    }

    /// Opens a file below `dir` without following a link. A created file is private to the user.
    pub(super) fn open_file(dir: &OwnedFd, text: &str, flags: libc::c_int) -> io::Result<File> {
        let text = name(text)?;
        // SAFETY: `text` is NUL-terminated; the mode is read only when the flags create the file.
        let fd = check(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                text.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600_u32,
            )
        })?;
        Ok(File::from(owned(fd)))
    }

    pub(super) fn rename(dir: &OwnedFd, from: &str, to: &str) -> io::Result<()> {
        let from = name(from)?;
        let to = name(to)?;
        // SAFETY: both names are NUL-terminated and relative to the same open directory.
        check(unsafe {
            libc::renameat(dir.as_raw_fd(), from.as_ptr(), dir.as_raw_fd(), to.as_ptr())
        })?;
        Ok(())
    }

    pub(super) fn unlink(dir: &OwnedFd, text: &str) -> io::Result<()> {
        let text = name(text)?;
        // SAFETY: `text` is NUL-terminated and relative to an open directory.
        check(unsafe { libc::unlinkat(dir.as_raw_fd(), text.as_ptr(), 0) })?;
        Ok(())
    }

    /// Makes a private directory below `dir`, with `mode`. A name that something else holds fails.
    pub(super) fn mkdir(dir: &OwnedFd, text: &str, mode: libc::mode_t) -> io::Result<()> {
        let text = name(text)?;
        // SAFETY: `text` is NUL-terminated and relative to an open directory.
        check(unsafe { libc::mkdirat(dir.as_raw_fd(), text.as_ptr(), mode) })?;
        Ok(())
    }

    /// Removes an empty directory below `dir`. Without `AT_REMOVEDIR` unlinkat would refuse a
    /// directory, and a directory that still holds entries makes this fail.
    pub(super) fn rmdir(dir: &OwnedFd, text: &str) -> io::Result<()> {
        let text = name(text)?;
        // SAFETY: `text` is NUL-terminated and relative to an open directory.
        check(unsafe { libc::unlinkat(dir.as_raw_fd(), text.as_ptr(), libc::AT_REMOVEDIR) })?;
        Ok(())
    }

    pub(super) fn stat(dir: &OwnedFd, text: &str) -> io::Result<Option<Stat>> {
        let text = name(text)?;
        let mut buf = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `buf` is written by fstatat before it is read below.
        let rc = unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                text.as_ptr(),
                buf.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: fstatat returned 0, so the structure is initialised.
        let buf = unsafe { buf.assume_init() };
        #[allow(clippy::unnecessary_cast)]
        let dev = buf.st_dev as u64;
        Ok(Some(Stat {
            regular: buf.st_mode & libc::S_IFMT == libc::S_IFREG,
            id: (dev, buf.st_ino),
        }))
    }

    /// The names in a directory. A read that fails part way ends the listing, which only
    /// informs `ls` and the cleanup of leftover temporary files.
    pub(super) fn names(dir: &OwnedFd) -> io::Result<Vec<String>> {
        // SAFETY: the duplicate is owned by the stream from here on and closed with it.
        let fd = check(unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: `fd` is an open directory descriptor, now owned by the stream.
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: `fd` was not taken over by fdopendir.
            unsafe { libc::close(fd) };
            return Err(error);
        }
        let mut names = Vec::new();
        loop {
            // SAFETY: `stream` is a live directory stream until closedir below.
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            // SAFETY: readdir returned a valid entry whose name is NUL-terminated.
            let text = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if let Ok(text) = text.to_str() {
                if text != "." && text != ".." {
                    names.push(text.to_owned());
                }
            }
        }
        // SAFETY: the stream is open and not used after this call.
        unsafe { libc::closedir(stream) };
        Ok(names)
    }

    /// Removes every entry of a directory, so the directory is empty. An entry is unlinked as itself, so a
    /// link is removed and never followed. An entry that will not unlink is a folder: it is emptied the same
    /// way and then removed. An entry that still cannot go is left, and so is the folder that holds it.
    pub(super) fn empty(dir: &OwnedFd) {
        for name in names(dir).unwrap_or_default() {
            if unlink(dir, &name).is_ok() {
                continue;
            }
            if let Ok(Some(child)) = open_dir(dir, &name, false) {
                empty(&child);
                drop(child);
                let _ = rmdir(dir, &name);
            }
        }
    }
}

// Keeping the bundle inline avoids a separate allocation on every successful read.
#[allow(clippy::large_enum_variant)]
enum ReadBundle {
    Missing,
    /// The file could not be read, so it is left as it is.
    Unreadable,
    /// The file was read and its content is malformed or too large.
    Corrupt,
    OtherVersion,
    Current(SuiteBundleV1),
}

#[derive(Deserialize)]
struct Header {
    v: u64,
    generation: Option<serde_json::Value>,
}

fn read_bundle(area: &Area, id: &str) -> ReadBundle {
    let file = match area.read(&bundle_name(id)) {
        Ok(Some(file)) => file,
        Ok(None) => return ReadBundle::Missing,
        Err(_) => return ReadBundle::Unreadable,
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return ReadBundle::Unreadable,
    };
    if !metadata.is_file() {
        return ReadBundle::Unreadable;
    }
    if metadata.len() > MAX_BYTES {
        return ReadBundle::Corrupt;
    }
    let mut bytes = Vec::new();
    if file.take(MAX_BYTES + 1).read_to_end(&mut bytes).is_err() {
        return ReadBundle::Unreadable;
    }
    if bytes.len() as u64 > MAX_BYTES {
        return ReadBundle::Corrupt;
    }
    // The bundle is parsed once. A bundle this build cannot read in full is still another version when its header says
    // so, and only that path reads the header.
    match serde_json::from_slice::<SuiteBundleV1>(&bytes) {
        Ok(mut bundle) => {
            if bundle.v != VERSION || bundle.generation > GENERATION {
                return ReadBundle::OtherVersion;
            }
            // A residue that does not match its own count is unknown, not corrupt. An older binary keeps the residue
            // and writes the bundle back without its count, while the units and the state stay true (spec 3.8).
            if !valid_residue(&bundle.residue) {
                bundle.residue = Residue::default();
            }
            if valid_bundle(&bundle, id) && valid_versions(&bundle) {
                ReadBundle::Current(bundle)
            } else {
                ReadBundle::Corrupt
            }
        }
        Err(_) => match serde_json::from_slice::<Header>(&bytes) {
            Ok(header)
                if header.v != u64::from(VERSION)
                    || header
                        .generation
                        .as_ref()
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|generation| generation > u64::from(GENERATION)) =>
            {
                ReadBundle::OtherVersion
            }
            _ => ReadBundle::Corrupt,
        },
    }
}

fn lock(area: &Area, id: &str) -> io::Result<File> {
    lock_with(area, id, || {})
}

fn lock_with(area: &Area, id: &str, mut after_open: impl FnMut()) -> io::Result<File> {
    let name = lock_name(id);
    for _ in 0..LOCK_ATTEMPTS {
        let file = area.lock_file(&name)?;
        after_open();
        file.try_lock().map_err(io::Error::from)?;
        if area.same_entry(&file, &name) {
            return Ok(file);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "the suite lock was replaced while it was taken",
    ))
}

/// Removes the temporary files and the launch directories that a killed run left for this suite.
/// Only a pass or a record that holds the suite lock calls this.
fn clear_temps(area: &Area, id: &str) {
    let prefix = format!(".{id}-");
    for name in area.names().unwrap_or_default() {
        if !name.starts_with(&prefix) {
            continue;
        }
        if name.ends_with(".tmp") {
            let _ = area.unlink(&name);
        } else if name.ends_with(".scratch") {
            area.clear_scratch(&name);
        }
    }
}

/// The bytes of a bundle that may be stored: within the bounds, and self-consistent.
fn encode(bundle: &SuiteBundleV1) -> io::Result<Vec<u8>> {
    let bytes = serde_json::to_vec(bundle).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_BYTES || !valid_bundle(bundle, &bundle.suite) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "suite bundle exceeds its bounds",
        ));
    }
    Ok(bytes)
}

fn write_bundle(area: &Area, bundle: &SuiteBundleV1) -> io::Result<()> {
    let bytes = encode(bundle)?;
    write_bytes(area, &bundle.suite, &bytes)
}

/// Writes already-checked bytes under a temporary name, then renames them over the bundle.
fn write_bytes(area: &Area, suite: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = format!(
        ".{}-{}-{}.tmp",
        suite,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let result = (|| {
        let mut file = area.create_temp(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        area.rename(&temp, &bundle_name(suite))
    })();
    if result.is_err() {
        let _ = area.unlink(&temp);
    }
    result
}

/// Best effort only: no diagnostic or decision changes when a bundle cannot be saved. Both arguments are borrowed, so a
/// learning run that follows the record still holds them (spec 3.10, completion). With the switch off the residue is
/// measured as main measures it, so the bundle is the one main writes (PR 86 review round 2, switch-off parity). With the
/// switch on, a residue is kept only when it is already known for this proof, and stored unknown otherwise.
pub(crate) fn record(
    store: &Path,
    pending: &Pending,
    key: &str,
    digest: &str,
    proof: &Proof,
    split: bool,
) {
    let Ok(Some(area)) = Area::open(store, true) else {
        return;
    };
    let Ok(_lock) = lock(&area, &pending.suite) else {
        return;
    };
    clear_temps(&area, &pending.suite);
    let previous = match read_bundle(&area, &pending.suite) {
        ReadBundle::OtherVersion | ReadBundle::Unreadable => return,
        ReadBundle::Current(bundle) => Some(bundle),
        ReadBundle::Missing | ReadBundle::Corrupt => None,
    };
    let Some(provenance) = proof.provenance.clone() else {
        return;
    };
    let guard = LaunchGuard {
        env: proof.env.clone(),
        env_excluded: proof.env_excluded.clone(),
        ignore: proof.ignore.clone().unwrap_or_default(),
        unit_env: pending.unit_env_digest(),
    };
    let guard_digest = guard.digest();
    // A full run keeps the suite's state whatever its roster: only `forget --units` or a generation bump clears a
    // disabled suite (spec 3.6).
    let (table, mut units, residue, state) = match previous {
        Some(old) if old.generation == GENERATION && old.provenance == provenance => {
            (old.table, old.units, old.residue, old.state)
        }
        Some(old) if old.generation == GENERATION => {
            (Vec::new(), BTreeMap::new(), Residue::default(), old.state)
        }
        _ => (
            Vec::new(),
            BTreeMap::new(),
            Residue::default(),
            SuiteState::Ready,
        ),
    };
    // Only the roster's units keep a version (C19). A unit that left the roster is no longer a claim about this suite.
    let removed = bundle_readers(
        &table,
        units
            .iter()
            .filter(|(unit, _)| pending.roster.units.binary_search(*unit).is_err())
            .flat_map(|(_, versions)| versions.iter()),
    );
    units.retain(|unit, _| pending.roster.units.binary_search(unit).is_ok());
    let suite = pending.suite.clone();
    let origin = pending.origin.clone();
    let roster = pending.roster.clone();
    let policy = pending.policy.clone();
    let mut bundle = SuiteBundleV1 {
        v: VERSION,
        generation: GENERATION,
        suite,
        provenance,
        origin,
        whole_key_digest: digest_text("stoop whole key v1", key),
        whole: Some(digest.into()),
        policy,
        guard,
        guard_digest,
        roster,
        whole_roster: if split {
            pending.roster.units.clone()
        } else {
            Vec::new()
        },
        table,
        units,
        residue,
        state,
    };
    if !versions_hold_current_unit_env(
        bundle.guard.unit_env.as_deref(),
        bundle
            .units
            .values()
            .flatten()
            .map(|version| version.unit_env.as_deref()),
    ) {
        bundle.residue = Residue::default();
    }
    if !split {
        store_residue(&mut bundle, &proof.inputs, digest, pending.listings());
    } else {
        if !removed.is_empty()
            && lost_reader(
                &removed,
                &bundle_readers(&bundle.table, bundle.units.values().flatten()),
            )
        {
            bundle.residue = Residue::default();
        }
        // The residue of a new whole proof stays unknown until completion measures it against valid versions. The versions
        // this bundle holds may be stale (a unit whose flag is gone still names it), so measuring them here would store a
        // count that a later subset trusts. A residue already known for this proof stays (spec 3.8, PR 86 review round 2).
        if !residue_known(&bundle.residue, digest) {
            bundle.residue = Residue::default();
        }
    }
    let _ = write_bundle(&area, &bundle);
}

/// Stores the residue of a whole proof's inputs (spec 3.8, points i and ii). It is measured only when every roster unit
/// holds an exact version, and it is kept while it is already known for `digest`. It is stored provisional: W6 compares
/// paths and cannot confirm them (C4, C5). A residue that would take the bundle past its bound is not kept.
fn store_residue(bundle: &mut SuiteBundleV1, whole: &[Input], digest: &str, listings: &[String]) {
    if !versions_hold_current_unit_env(
        bundle.guard.unit_env.as_deref(),
        bundle
            .units
            .values()
            .flatten()
            .map(|version| version.unit_env.as_deref()),
    ) {
        bundle.residue = Residue::default();
        return;
    }
    if residue_known(&bundle.residue, digest) {
        return;
    }
    let complete = bundle.roster.units.iter().all(|unit| {
        bundle
            .units
            .get(unit)
            .is_some_and(|versions| versions.iter().any(|version| version.exact))
    });
    let next = if complete {
        let covered = covered_paths(bundle);
        let (count, paths) = residue::uncovered(whole, listings, &covered);
        Residue {
            state: ResidueState::Provisional,
            paths,
            count,
            whole: Some(digest.to_owned()),
        }
    } else {
        Residue::default()
    };
    bundle.residue = next;
    if encode(bundle).is_err() {
        bundle.residue = Residue::default();
    }
}

/// Whether `residue` is known for `digest`: it has a state, and it was measured for that proof.
fn residue_known(residue: &Residue, digest: &str) -> bool {
    !matches!(residue.state, ResidueState::None) && residue.whole.as_deref() == Some(digest)
}

/// Whether each held version was recorded under the current unit-only environment.
pub(super) fn versions_hold_current_unit_env<'a>(
    current: Option<&str>,
    mut versions: impl Iterator<Item = Option<&'a str>>,
) -> bool {
    versions.all(|unit_env| unit_env == current)
}

/// Whether an input id names content that a proof verifies: a file, a link, a listing, an absence or an unreadable mark.
/// A stat-only read carries another id and checks metadata, not content (spec 3.8).
pub(crate) fn content_id(id: &str) -> bool {
    id == "a"
        || id == "u"
        || ["f:", "x:", "dl:", "l:"]
            .iter()
            .any(|prefix| id.starts_with(prefix))
}

/// Each path that some inputs name, with whether one of those names is a content read (spec 3.8).
pub(crate) fn reader_map<'a>(inputs: impl Iterator<Item = &'a Input>) -> BTreeMap<String, bool> {
    let mut out: BTreeMap<String, bool> = BTreeMap::new();
    for input in inputs {
        let content = content_id(&input.id);
        *out.entry(input.path.clone()).or_insert(false) |= content;
    }
    out
}

/// The readers of the versions in `versions`, read through the bundle's table.
fn bundle_readers<'a>(
    table: &[Input],
    versions: impl Iterator<Item = &'a UnitVersion>,
) -> BTreeMap<String, bool> {
    let len = table.len();
    reader_map(
        versions
            .flat_map(|version| undelta(&version.inputs, len).unwrap_or_default())
            .map(|index| &table[index as usize]),
    )
}

/// Whether a path that `removed` reads has lost its last reader in `now` (spec 3.8). A path with no reader left is lost,
/// and so is one whose last content reader is gone while only a stat-only read remains. Losing either makes the residue
/// unknown until a full run measures it again.
pub(crate) fn lost_reader(removed: &BTreeMap<String, bool>, now: &BTreeMap<String, bool>) -> bool {
    removed.iter().any(|(path, content)| match now.get(path) {
        None => true,
        Some(now_content) => *content && !now_content,
    })
}

/// The paths of `removed` that no reader in `now` covers, by the rule of [`lost_reader`]. Each path is judged alone.
fn losses(removed: &BTreeMap<String, bool>, now: &BTreeMap<String, bool>) -> Vec<String> {
    let mut lost = Vec::new();
    for (path, content) in removed {
        if lost_reader(&BTreeMap::from([(path.clone(), *content)]), now) {
            lost.push(path.clone());
        }
    }
    lost
}

/// The paths read by exact unit versions: what the units' own runs read (spec 3.8).
fn covered_paths(bundle: &SuiteBundleV1) -> BTreeSet<&str> {
    let len = bundle.table.len();
    bundle
        .units
        .values()
        .flatten()
        .filter(|version| version.exact)
        .filter_map(|version| undelta(&version.inputs, len))
        .flatten()
        .map(|index| bundle.table[index as usize].path.as_str())
        .collect()
}

/// What `start` decides for one invocation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Start {
    Pass(Pass),
    /// Another stoop holds the suite lock, so this run takes the first-run form.
    Busy,
    /// No pass: the bundle is missing, unreadable, another version or for another command, it
    /// holds a unit proof for this roster, or the suite is disabled.
    No,
}

/// What storing one unit's proof did.
#[allow(clippy::enum_variant_names)] // The variant names are the contract's (spec 3.4).
pub(crate) enum Stored {
    Stored,
    /// The bundle would exceed its budget, so the proof is not kept.
    OverBudget,
    /// The bundle was not written. The proof stays in memory, and the next write carries it.
    WriteFailed,
}

/// One launch's directory of list files (spec 3.7 and 4.7): `.<suite>-<pid>-<n>.scratch`, made under
/// the suite lock with mode 0700, and its files with mode 0600. Dropping it removes every entry the
/// launch left in it, then the directory, so a launch leaves nothing behind unless the process is killed.
/// The next pass or record that takes the suite lock clears what a kill left (`clear_temps`).
#[cfg(unix)]
pub(crate) struct Scratch {
    /// The suite directory, which holds the launch directory's entry.
    parent: std::os::fd::OwnedFd,
    name: String,
    dir: std::os::fd::OwnedFd,
    path: PathBuf,
}

#[cfg(unix)]
impl Scratch {
    fn create(area: &Area, suite: &str) -> io::Result<Scratch> {
        let name = format!(
            ".{suite}-{}-{}.scratch",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        at::mkdir(&area.dir, &name, 0o700)?;
        let dir = match at::open_dir(&area.dir, &name, false) {
            Ok(Some(dir)) => dir,
            Ok(None) => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "the launch directory vanished",
                ))
            }
            Err(error) => {
                let _ = at::rmdir(&area.dir, &name);
                return Err(error);
            }
        };
        Ok(Scratch {
            parent: area.dir.try_clone()?,
            path: area.path.join(&name),
            name,
            dir,
        })
    }

    /// Writes `bytes` to a new file named `file` in the directory, mode 0600, and returns its path.
    pub(crate) fn write(&mut self, file: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let mut handle = at::open_file(
            &self.dir,
            file,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?;
        handle.write_all(bytes)?;
        Ok(self.path.join(file))
    }
}

#[cfg(unix)]
impl Drop for Scratch {
    /// Removes every entry the launch left in its directory, whatever the runner wrote there, and then the
    /// directory. Nothing is followed: a link is removed as itself (`at::empty`).
    fn drop(&mut self) {
        at::empty(&self.dir);
        let _ = at::rmdir(&self.parent, &self.name);
    }
}

#[cfg(not(unix))]
pub(crate) struct Scratch {
    path: PathBuf,
    files: Vec<PathBuf>,
}

#[cfg(not(unix))]
impl Scratch {
    fn create(area: &Area, suite: &str) -> io::Result<Scratch> {
        let name = format!(
            ".{suite}-{}-{}.scratch",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let path = area.dir.join(name);
        fs::create_dir(&path)?;
        Ok(Scratch {
            path,
            files: Vec::new(),
        })
    }

    /// Writes `bytes` to a new file named `file` in the directory, private, and returns its path.
    pub(crate) fn write(&mut self, file: &str, bytes: &[u8]) -> io::Result<PathBuf> {
        let path = self.path.join(file);
        let mut handle = OpenOptions::new()
            .write(true)
            .create_new(true)
            .private()
            .open(&path)?;
        self.files.push(path.clone());
        handle.write_all(bytes)?;
        Ok(path)
    }
}

#[cfg(not(unix))]
impl Drop for Scratch {
    fn drop(&mut self) {
        for file in &self.files {
            let _ = fs::remove_file(file);
        }
        let _ = fs::remove_dir(&self.path);
    }
}

/// The state a kept pass holds before a record, which a refused record restores (spec 3.11).
type Snapshot = (
    BTreeMap<String, Vec<UnitVersion>>,
    Vec<Input>,
    BTreeMap<String, u32>,
    Residue,
    bool,
    BTreeSet<String>,
);

/// One attribution pass. It holds the suite lock until it is dropped, so no other stoop changes
/// the suite meanwhile, and it rewrites the bundle after each stored proof.
pub(crate) struct Pass {
    /// Set when a version write took the last reader of a path (spec 3.8). The residue is unknown until a full run
    /// measures it again.
    residue_lost: bool,
    /// The paths whose last content reader a write or a drop of this pass took. `settle_residue` decides whether a later
    /// write of the pass read them again (spec 3.8, item 1).
    lost_paths: BTreeSet<String>,
    area: Area,
    _lock: File,
    bundle: SuiteBundleV1,
    /// The table index of each input, by its serialized form, so each input is stored once.
    interned: BTreeMap<String, u32>,
    budget: u64,
    /// When the bundle was last written, and whether a proof is held that no write has stored yet.
    last_write: Option<Instant>,
    dirty: bool,
    /// The state a stopped run stores: `attribution` for a pass, `subset` for a run that keeps versions (spec 3.6).
    phase: &'static str,
    /// Whether the pass keeps the bundle's versions, as `keep` does. A kept pass compacts the table whenever it replaces
    /// a proof (spec 3.11). A clear pass starts with no versions, so it never replaces one.
    keep: bool,
    #[cfg(test)]
    writes: usize,
}

impl Pass {
    /// A new launch directory for one launch's list files, made under the suite lock (spec 3.7).
    pub(crate) fn scratch(&self) -> io::Result<Scratch> {
        Scratch::create(&self.area, &self.bundle.suite)
    }

    /// Replaces every member's version as one record. A singleton is exact; a shared launch is inexact.
    /// A refused record restores every member and the table before any write is made.
    pub(crate) fn record(
        &mut self,
        members: &[String],
        inputs: &[Input],
        outputs: &[Input],
        created: u64,
    ) -> Stored {
        let Some((last, others)) = members.split_last() else {
            return Stored::WriteFailed;
        };
        let mark = self.bundle.table.len();
        // Kept passes compact the table. A multi-member refusal must also restore every member in a clear pass.
        let snapshot = (self.keep || !others.is_empty()).then(|| {
            (
                self.bundle.units.clone(),
                self.bundle.table.clone(),
                self.interned.clone(),
                self.bundle.residue.clone(),
                self.residue_lost,
                self.lost_paths.clone(),
            )
        });
        let inputs = self.indices(inputs);
        let outputs = self.indices(outputs);
        let version = UnitVersion {
            created,
            exact: members.len() == 1,
            source: ResultSource::Exit,
            guard: self.bundle.guard_digest.clone(),
            unit_env: self.bundle.guard.unit_env.clone(),
            inputs: delta(&inputs),
            outputs: delta(&outputs),
        };
        let removed = bundle_readers(
            &self.bundle.table,
            members
                .iter()
                .flat_map(|unit| self.bundle.units.get(unit).into_iter().flatten()),
        );
        for member in others {
            self.bundle
                .units
                .insert(member.clone(), vec![version.clone()]);
        }
        let previous = self.bundle.units.insert(last.clone(), vec![version]);
        if self.keep {
            self.compact_table();
        }
        self.note_losses(&removed);
        let Ok(bytes) = serde_json::to_vec(&self.bundle) else {
            self.refuse(last, previous, mark, snapshot);
            return Stored::WriteFailed;
        };
        if bytes.len() as u64 > self.budget {
            self.refuse(last, previous, mark, snapshot);
            return Stored::OverBudget;
        }
        if !valid_bundle(&self.bundle, &self.bundle.suite) {
            self.refuse(last, previous, mark, snapshot);
            return Stored::WriteFailed;
        }
        self.dirty = true;
        if !self.due(Instant::now()) {
            return Stored::Stored;
        }
        match self.write(&bytes) {
            Ok(()) => Stored::Stored,
            Err(_) => Stored::WriteFailed,
        }
    }

    /// Whether a write is due: the first proof's is, and then at most one write per `FLUSH_INTERVAL`.
    fn due(&self, now: Instant) -> bool {
        match self.last_write {
            None => true,
            Some(last) => now.duration_since(last) >= FLUSH_INTERVAL,
        }
    }

    /// Writes the encoded bundle and records when, so the next write waits its interval.
    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        write_bytes(&self.area, &self.bundle.suite, bytes)?;
        self.last_write = Some(Instant::now());
        self.dirty = false;
        #[cfg(test)]
        {
            self.writes += 1;
        }
        Ok(())
    }

    /// The table index of each input, sorted and without repeats.
    fn indices(&mut self, inputs: &[Input]) -> Vec<u32> {
        let mut out: Vec<u32> = inputs.iter().map(|input| self.intern(input)).collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn intern(&mut self, input: &Input) -> u32 {
        let key = serde_json::to_string(input).expect("an input always serializes");
        if let Some(&index) = self.interned.get(&key) {
            return index;
        }
        let index =
            u32::try_from(self.bundle.table.len()).expect("the table is bounded by the budget");
        self.bundle.table.push(input.clone());
        self.interned.insert(key, index);
        index
    }

    /// Undoes a refused record (spec 3.11). A kept pass restores the state the record began with. A clear pass puts back
    /// the version the unit held, or none, and drops the table entries the proof added, as it always did.
    fn refuse(
        &mut self,
        unit: &str,
        previous: Option<Vec<UnitVersion>>,
        mark: usize,
        snapshot: Option<Snapshot>,
    ) {
        if let Some((units, table, interned, residue, lost, lost_paths)) = snapshot {
            self.bundle.units = units;
            self.bundle.table = table;
            self.interned = interned;
            self.bundle.residue = residue;
            self.residue_lost = lost;
            self.lost_paths = lost_paths;
            return;
        }
        match previous {
            Some(versions) => {
                self.bundle.units.insert(unit.to_owned(), versions);
            }
            None => {
                self.bundle.units.remove(unit);
            }
        }
        self.bundle.table.truncate(mark);
        self.interned.retain(|_, index| (*index as usize) < mark);
    }

    /// Rebuilds the table from the entries that the versions still index, and renumbers the interned indices to match
    /// (spec 3.11).
    fn compact_table(&mut self) {
        let renumber = compact(&mut self.bundle);
        self.interned = std::mem::take(&mut self.interned)
            .into_iter()
            .filter_map(|(key, index)| {
                renumber
                    .get(index as usize)
                    .copied()
                    .flatten()
                    .map(|new| (key, new))
            })
            .collect();
    }

    /// Notes the paths that `removed` read with content and that no version reads with content now (spec 3.8, item 1).
    /// The residue is unknown from here until `settle_residue` finds each of them read again.
    fn note_losses(&mut self, removed: &BTreeMap<String, bool>) {
        if !versions_hold_current_unit_env(
            self.bundle.guard.unit_env.as_deref(),
            self.bundle
                .units
                .values()
                .flatten()
                .map(|version| version.unit_env.as_deref()),
        ) {
            self.unsettle();
        }
        if removed.is_empty() {
            return;
        }
        let now = bundle_readers(
            &self.bundle.table,
            self.bundle
                .units
                .values()
                .flatten()
                .filter(|version| version.unit_env == self.bundle.guard.unit_env),
        );
        let lost = losses(removed, &now);
        if !lost.is_empty() {
            self.bundle.residue = Residue::default();
            self.residue_lost = true;
            self.lost_paths.extend(lost);
        }
    }

    /// Drops the versions of units that left the roster, and compacts the table (spec 3.11). A pass starts with no
    /// versions, so only a kept run has any to drop. Returns whether anything changed.
    fn prune(&mut self) -> bool {
        let units = self.bundle.units.len();
        let table = self.bundle.table.len();
        let roster = &self.bundle.roster.units;
        let dropped = bundle_readers(
            &self.bundle.table,
            self.bundle
                .units
                .iter()
                .filter(|(unit, _)| roster.binary_search(*unit).is_err())
                .flat_map(|(_, versions)| versions.iter()),
        );
        self.bundle
            .units
            .retain(|unit, _| roster.binary_search(unit).is_ok());
        self.compact_table();
        self.note_losses(&dropped);
        let changed = self.bundle.units.len() != units || self.bundle.table.len() != table;
        self.dirty |= changed;
        changed
    }

    /// The entries that the supplied versions name, as inputs and outputs, in table order.
    fn entries<'a>(
        &self,
        versions: impl IntoIterator<Item = &'a UnitVersion>,
    ) -> (Vec<Input>, Vec<Input>) {
        let len = self.bundle.table.len();
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        for version in versions {
            for index in undelta(&version.inputs, len).unwrap_or_default() {
                inputs.push(self.bundle.table[index as usize].clone());
            }
            for index in undelta(&version.outputs, len).unwrap_or_default() {
                outputs.push(self.bundle.table[index as usize].clone());
            }
        }
        (inputs, outputs)
    }

    /// The entries that `unit`'s stored versions name. Empty for a unit with no version.
    pub(crate) fn held_of(&self, unit: &str) -> (Vec<Input>, Vec<Input>) {
        self.bundle.units.get(unit).map_or_else(
            || (Vec::new(), Vec::new()),
            |versions| self.entries(versions),
        )
    }

    /// Every unit that holds a version, with the entries its versions name.
    pub(crate) fn held(&self) -> Vec<(String, Vec<Input>, Vec<Input>)> {
        self.bundle
            .units
            .iter()
            .map(|(unit, versions)| {
                let (inputs, outputs) = self.entries(versions);
                (unit.clone(), inputs, outputs)
            })
            .collect()
    }

    /// Only exact versions identify a particular unit as the owner of a path.
    pub(crate) fn held_owned(&self) -> Vec<(String, Vec<Input>, Vec<Input>)> {
        self.bundle
            .units
            .iter()
            .filter_map(|(unit, versions)| {
                let mut exact = versions.iter().filter(|version| version.exact).peekable();
                exact.peek()?;
                let (inputs, outputs) = self.entries(exact);
                Some((unit.clone(), inputs, outputs))
            })
            .collect()
    }

    /// The sorted unit names that hold at least one exact version.
    pub(crate) fn held_exact(&self) -> impl Iterator<Item = &str> {
        self.bundle.units.iter().filter_map(|(unit, versions)| {
            versions
                .iter()
                .any(|version| version.exact)
                .then_some(unit.as_str())
        })
    }

    /// Names the state a stopped run stores: `attribution` for a run that launches every unit, `subset` for one that
    /// launches some (spec 3.6).
    pub(crate) fn set_phase(&mut self, phase: &'static str) {
        self.phase = phase;
    }

    /// Stores the suite as disabled for `code` and `label`, under the lock this pass holds, at once: a run killed
    /// after this point keeps the state. The unit proofs held so far stay on disk, unread, until `forget --units`
    /// (spec 3.6). The state names the handle's phase.
    pub(crate) fn disable(&mut self, code: &str, label: &str) -> io::Result<()> {
        self.bundle.state = SuiteState::Disabled {
            code: code.to_owned(),
            phase: self.phase.to_owned(),
            label: label.to_owned(),
            at: now(),
        };
        let bytes = encode(&self.bundle)?;
        self.write(&bytes)
    }

    /// `disable` with no unit proof kept, for a pass whose proofs the budget could not hold (spec 3.6).
    pub(crate) fn disable_without_versions(&mut self, code: &str, label: &str) -> io::Result<()> {
        self.bundle.units.clear();
        self.bundle.table.clear();
        self.interned.clear();
        self.disable(code, label)
    }

    /// Removes the suite's bundle, so the suite holds no proof a later run could read. It is the fallback when the
    /// disabled state cannot be stored.
    pub(crate) fn remove_bundle(&mut self) {
        let _ = self.area.unlink(&bundle_name(&self.bundle.suite));
        self.dirty = false;
    }

    /// Marks the residue unknown in memory, before a proof that stats a changed input is written (spec 3.8, PR 86 review
    /// round 3). The pass's next write stores it, so a run killed before it settles leaves no known residue beside it.
    pub(crate) fn unsettle(&mut self) {
        if !matches!(self.bundle.residue.state, ResidueState::None) {
            self.bundle.residue = Residue::default();
            self.dirty = true;
        }
    }

    /// Stores the residue of the suite's whole proof when a pass ends (spec 3.8, point i). The proof is the one of
    /// `proofs` whose digest is the bundle's `whole`. Without it, the residue stays unknown.
    pub(crate) fn settle_residue(
        &mut self,
        proofs: &[Proof],
        listings: &[String],
        no_verdict: bool,
    ) {
        if !versions_hold_current_unit_env(
            self.bundle.guard.unit_env.as_deref(),
            self.bundle
                .units
                .values()
                .flatten()
                .map(|version| version.unit_env.as_deref()),
        ) {
            self.unsettle();
            return;
        }
        // When a split run may have lost coverage, its residue stays unknown. A stored version can read a path by stat
        // only, so measuring it as covered would let a later run skip without checking content. A switch-off pass keeps
        // main's residue, which is the switch-off parity rule.
        if no_verdict && self.keep {
            if !matches!(self.bundle.residue.state, ResidueState::None) {
                self.dirty = true;
            }
            self.bundle.residue = Residue::default();
            return;
        }
        // A write or a drop took the last reader of a path (spec 3.8, item 1). The residue stays unknown while a path that
        // it lost has no content reader in the final versions, where a kept version counts as much as a written one.
        if self.residue_lost {
            let readers = bundle_readers(&self.bundle.table, self.bundle.units.values().flatten());
            if self
                .lost_paths
                .iter()
                .any(|path| readers.get(path) != Some(&true))
            {
                return;
            }
            self.lost_paths.clear();
            self.residue_lost = false;
        }
        let Some(digest) = self.bundle.whole.clone() else {
            return;
        };
        let Some(proof) = proofs.iter().find(|proof| proof.digest() == digest) else {
            return;
        };
        store_residue(&mut self.bundle, &proof.inputs, &digest, listings);
        if !matches!(self.bundle.residue.state, ResidueState::None) {
            self.dirty = true;
        }
    }
}

impl Drop for Pass {
    /// Runs when the pass returns and when it unwinds. It writes the proofs that no write has stored yet. A signal
    /// or an abort does not run it (release builds abort on panic), so a pass ended that way keeps what its last
    /// write held. A write that fails here is ignored, as `record` ignores one.
    fn drop(&mut self) {
        if !self.dirty {
            return;
        }
        if let Ok(bytes) = encode(&self.bundle) {
            let _ = self.write(&bytes);
        }
    }
}

/// Starts an attribution pass for `pending` when its bundle is current, holds no unit proof for
/// the roster, and the suite lock is free. The bundle is checked again under the lock, and then
/// reset to the current roster and guard with no versions. Nothing is written here.
pub(crate) fn start(store: &Path, pending: &Pending, key: &str, guard: LaunchGuard) -> Start {
    start_with(store, pending, key, guard, || {})
}

/// `start`, with `after_open` called once the lock entry is open and before it is locked. Tests
/// use it to change the bundle between the unlocked check and the lock.
fn start_with(
    store: &Path,
    pending: &Pending,
    key: &str,
    guard: LaunchGuard,
    after_open: impl FnMut(),
) -> Start {
    let Ok(Some(area)) = Area::open(store, false) else {
        return Start::No;
    };
    let digest = digest_text("stoop whole key v1", key);
    if ready(&area, pending, &digest).is_err() {
        return Start::No;
    }
    let held = match lock_with(&area, &pending.suite, after_open) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Start::Busy,
        Err(_) => return Start::No,
    };
    clear_temps(&area, &pending.suite);
    let Ok(mut bundle) = ready(&area, pending, &digest) else {
        return Start::No;
    };
    if !area.writable(&pending.suite) {
        return Start::No;
    }
    bundle.guard_digest = guard.digest();
    bundle.guard = guard;
    bundle.policy.clone_from(&pending.policy);
    bundle.roster = Roster {
        source: pending.roster.source.clone(),
        units: pending.roster.units.clone(),
    };
    bundle.units.clear();
    bundle.table.clear();
    // The units the residue was measured against are cleared, so the pass measures the residue again at its end.
    let stored = !matches!(bundle.residue.state, ResidueState::None);
    bundle.residue = Residue::default();
    Start::Pass(Pass {
        residue_lost: false,
        lost_paths: BTreeSet::new(),
        area,
        _lock: held,
        bundle,
        interned: BTreeMap::new(),
        budget: MAX_BYTES,
        last_write: None,
        dirty: stored,
        phase: "attribution",
        keep: false,
        #[cfg(test)]
        writes: 0,
    })
}

/// What `keep` does under the suite lock (spec 3.10, E17 and E18).
#[allow(clippy::large_enum_variant)] // The handle stays inline, as `Start` keeps it, so a run makes no allocation for it.
pub(crate) enum Kept<T, D> {
    /// Another stoop holds the suite lock, so nothing is decided here.
    Busy,
    /// The bundle cannot be read, written or kept for this command.
    Unavailable,
    /// `decide` did not keep the decision. Nothing is written.
    Declined(D),
    /// The decision holds under the lock. The pass keeps the bundle's versions, and a run replaces only what it launches.
    Locked(Pass, T),
}

/// Under the suite lock, judges the bundle with `decide`. When it keeps the decision, returns a pass that keeps the
/// bundle's versions (spec 3.11). The checks are those of `start`, without the one that refuses a suite with a proof for
/// a unit, which a subset needs. `phase` names the state a stopped run stores (spec 3.6).
pub(crate) fn keep<T, D>(
    store: &Path,
    pending: &Pending,
    key: &str,
    guard: LaunchGuard,
    decide: impl FnOnce(&View) -> Result<T, D>,
) -> Kept<T, D> {
    let Ok(Some(area)) = Area::open(store, false) else {
        return Kept::Unavailable;
    };
    let held = match lock(&area, &pending.suite) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Kept::Busy,
        Err(_) => return Kept::Unavailable,
    };
    clear_temps(&area, &pending.suite);
    let Some(view) = view_in(&area, pending, key) else {
        return Kept::Unavailable;
    };
    let value = match decide(&view) {
        Ok(value) => value,
        Err(declined) => return Kept::Declined(declined),
    };
    if !area.writable(&pending.suite) {
        return Kept::Unavailable;
    }
    let Some(mut bundle) = bundle_for(&area, pending, key) else {
        return Kept::Unavailable;
    };
    if matches!(bundle.state, SuiteState::Disabled { .. }) {
        return Kept::Unavailable;
    }
    let stale_residue = !matches!(bundle.residue.state, ResidueState::None)
        && !versions_hold_current_unit_env(
            guard.unit_env.as_deref(),
            bundle
                .units
                .values()
                .flatten()
                .map(|version| version.unit_env.as_deref()),
        );
    if stale_residue {
        bundle.residue = Residue::default();
    }
    bundle.guard_digest = guard.digest();
    bundle.guard = guard;
    bundle.policy.clone_from(&pending.policy);
    bundle.roster = Roster {
        source: pending.roster.source.clone(),
        units: pending.roster.units.clone(),
    };
    let mut pass = Pass {
        residue_lost: false,
        lost_paths: BTreeSet::new(),
        area,
        _lock: held,
        interned: interned_of(&bundle.table),
        bundle,
        budget: MAX_BYTES,
        last_write: None,
        dirty: stale_residue,
        phase: "subset",
        keep: true,
        #[cfg(test)]
        writes: 0,
    };
    pass.prune();
    Kept::Locked(pass, value)
}

/// The table index of each entry, by its serialized form (see `Pass::intern`).
fn interned_of(table: &[Input]) -> BTreeMap<String, u32> {
    table
        .iter()
        .enumerate()
        .map(|(index, input)| {
            (
                serde_json::to_string(input).expect("an input always serializes"),
                u32::try_from(index).expect("the table is bounded"),
            )
        })
        .collect()
}

/// Whether a bundle was recorded for this command and provenance. A pass, `stoop explain` and the counts judge a
/// bundle with these tests, so they agree.
fn recorded(bundle: &SuiteBundleV1, digest: &str) -> bool {
    bundle.provenance == Provenance::current()
        && bundle.whole.is_some()
        && bundle.whole_key_digest == digest
}

/// The bundle as a pass needs it: current, recorded for this command, not disabled, and with no unit proof for any
/// unit of the roster. The refusal names the first condition that fails. A disabled suite is refused before the
/// rest of the bundle is judged, so its state holds whatever the command (spec 3.6).
fn ready(area: &Area, pending: &Pending, digest: &str) -> Result<SuiteBundleV1, Refusal> {
    let ReadBundle::Current(bundle) = read_bundle(area, &pending.suite) else {
        return Err(Refusal::NoBundle);
    };
    if bundle.generation != GENERATION {
        return Err(Refusal::NoBundle);
    }
    if matches!(bundle.state, SuiteState::Disabled { .. }) {
        return Err(Refusal::SuiteDisabled);
    }
    if !recorded(&bundle, digest) {
        return Err(Refusal::NoBundle);
    }
    let proven = pending.roster.units.iter().any(|unit| {
        bundle
            .units
            .get(unit)
            .is_some_and(|versions| !versions.is_empty())
    });
    if proven {
        return Err(Refusal::Proven);
    }
    Ok(bundle)
}

/// Check 8 of spec 3.1 without the lock, for `stoop explain`: `Ok` when `start` would find the
/// bundle ready. It reads the store and creates nothing.
pub(crate) fn probe(store: &Path, pending: &Pending, key: &str) -> Result<(), Refusal> {
    let Ok(Some(area)) = Area::open(store, false) else {
        return Err(Refusal::NoBundle);
    };
    ready(&area, pending, &digest_text("stoop whole key v1", key))?;
    area.writable_dir().then_some(()).ok_or(Refusal::Unwritable)
}

/// The label of a suite that the store holds disabled, for `stoop explain` to name (spec 3.12). `None` when the
/// suite is not disabled, or the store holds no current bundle for it.
pub(crate) fn disabled(store: &Path, id: &str) -> Option<String> {
    let Ok(Some(area)) = Area::open(store, false) else {
        return None;
    };
    let ReadBundle::Current(bundle) = read_bundle(&area, id) else {
        return None;
    };
    let generation = bundle.generation;
    match bundle.state {
        SuiteState::Disabled { label, .. } if generation == GENERATION => Some(label),
        _ => None,
    }
}

/// What `stoop explain` counts for a suite: the distinct inputs that the roster's unit proofs name,
/// and how many roster units hold one. Only a bundle that `ready` would accept counts, so a bundle
/// of another generation holds no proofs. The table also holds outputs, so its length is not the
/// count. Nothing is created.
pub(crate) fn counts(store: &Path, id: &str, units: &[String], key: &str) -> (usize, usize) {
    let Ok(Some(area)) = Area::open(store, false) else {
        return (0, 0);
    };
    let ReadBundle::Current(bundle) = read_bundle(&area, id) else {
        return (0, 0);
    };
    let current = bundle.generation == GENERATION && matches!(bundle.state, SuiteState::Ready);
    if !current || !recorded(&bundle, &digest_text("stoop whole key v1", key)) {
        return (0, 0);
    }
    let mut proven = 0;
    let mut inputs: Vec<u32> = Vec::new();
    for unit in units {
        let Some(versions) = bundle
            .units
            .get(unit)
            .filter(|versions| !versions.is_empty())
        else {
            continue;
        };
        proven += 1;
        for version in versions {
            inputs.extend(undelta(&version.inputs, bundle.table.len()).unwrap_or_default());
        }
    }
    inputs.sort_unstable();
    inputs.dedup();
    (inputs.len(), proven)
}

/// The residue of the whole command's proof for `key`, when the suite is not disabled and its current proof has one that
/// is known and not empty: its count and its first paths (spec 3.8). A disabled suite names no residue, because its
/// proofs count for nothing (spec 3.6). It reads the store and takes no lock, so `stoop explain` can call it.
pub(crate) fn known_residue(store: &Path, id: &str, key: &str) -> Option<(usize, Vec<String>)> {
    let Ok(Some(area)) = Area::open(store, false) else {
        return None;
    };
    let ReadBundle::Current(bundle) = read_bundle(&area, id) else {
        return None;
    };
    // A disabled suite names no residue: its proofs count for nothing (spec 3.6), as `counts` finds.
    if bundle.generation != GENERATION
        || !matches!(bundle.state, SuiteState::Ready)
        || !recorded(&bundle, &digest_text("stoop whole key v1", key))
        || !versions_hold_current_unit_env(
            bundle.guard.unit_env.as_deref(),
            bundle
                .units
                .values()
                .flatten()
                .map(|version| version.unit_env.as_deref()),
        )
    {
        return None;
    }
    let whole = bundle.whole.as_deref()?;
    (residue_known(&bundle.residue, whole) && bundle.residue.count > 0)
        .then(|| (bundle.residue.count, bundle.residue.paths.clone()))
}

/// A unit version as a decision reads it (spec 3.9): its stamp, its guard digest, and the table indices of its inputs
/// and outputs, in table order.
pub(crate) struct Version {
    pub(crate) created: u64,
    pub(crate) exact: bool,
    pub(crate) guard: String,
    pub(crate) unit_env: Option<String>,
    pub(crate) inputs: Vec<u32>,
    pub(crate) outputs: Vec<u32>,
}

/// A suite's bundle as one decision reads it (spec 3.9 and 3.10). A decision reads it without the suite lock, and
/// judges it again under the lock before it writes anything.
pub(crate) struct View {
    /// The digest of the whole proof the bundle records.
    pub(crate) whole: String,
    /// The label of the disabled state, when the suite is disabled.
    pub(crate) disabled: Option<String>,
    /// The table that the versions index.
    pub(crate) table: Vec<Input>,
    /// Each unit's versions, in unit order.
    pub(crate) units: BTreeMap<String, Vec<Version>>,
    /// The residue, when it is known for `whole`: its count and its first paths.
    pub(crate) residue: Option<(usize, Vec<String>)>,
    /// The roster that the whole proof was judged with (spec 3.10, PR 86 review round 5). Empty when no split run recorded it.
    pub(crate) whole_roster: Vec<String>,
}

impl View {
    /// The view of a bundle that `read_bundle` accepted. The view takes the bundle's table and versions, so nothing is
    /// copied. `None` only when an index lies outside the table.
    fn of(bundle: SuiteBundleV1) -> Option<View> {
        let whole = bundle.whole?;
        let len = bundle.table.len();
        let residue = (residue_known(&bundle.residue, &whole)
            && versions_hold_current_unit_env(
                bundle.guard.unit_env.as_deref(),
                bundle
                    .units
                    .values()
                    .flatten()
                    .map(|version| version.unit_env.as_deref()),
            ))
        .then_some((bundle.residue.count, bundle.residue.paths));
        let mut units = BTreeMap::new();
        for (unit, versions) in bundle.units {
            let views = versions
                .into_iter()
                .map(|version| {
                    Some(Version {
                        created: version.created,
                        exact: version.exact,
                        inputs: undelta(&version.inputs, len)?,
                        outputs: undelta(&version.outputs, len)?,
                        guard: version.guard,
                        unit_env: version.unit_env,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            units.insert(unit, views);
        }
        let disabled = match bundle.state {
            SuiteState::Ready => None,
            SuiteState::Disabled { label, .. } => Some(label),
        };
        Some(View {
            whole,
            disabled,
            table: bundle.table,
            units,
            residue,
            whole_roster: bundle.whole_roster,
        })
    }
}

/// The suite's bundle for a decision, read without the lock (spec 3.9). `None` when the bundle is absent, unreadable,
/// of another generation, or not recorded for this command, and the switch-off path decides then. A disabled suite has
/// a view, so that its decision can name the label.
pub(crate) fn view(store: &Path, pending: &Pending, key: &str) -> Option<View> {
    let Ok(Some(area)) = Area::open(store, false) else {
        return None;
    };
    view_in(&area, pending, key)
}

/// This command's bundle in `area`, when it is current and was recorded for this command. It takes no lock, so a caller
/// that writes holds the suite lock itself.
fn bundle_for(area: &Area, pending: &Pending, key: &str) -> Option<SuiteBundleV1> {
    let ReadBundle::Current(bundle) = read_bundle(area, &pending.suite) else {
        return None;
    };
    let digest = digest_text("stoop whole key v1", key);
    (bundle.generation == GENERATION && recorded(&bundle, &digest)).then_some(bundle)
}

/// This command's view of the bundle in `area`, as `bundle_for` reads it.
fn view_in(area: &Area, pending: &Pending, key: &str) -> Option<View> {
    View::of(bundle_for(area, pending, key)?)
}

/// What a write under the suite lock did (spec 3.10, E16).
pub(crate) enum Settled {
    /// The suite lock is busy, so nothing was written.
    Busy,
    /// `judge` did not confirm the skip under the lock, so nothing was written.
    Declined,
    /// The bundle was written.
    Written,
    /// The bundle could not be read or written, so nothing was written.
    Failed,
}

/// Under the suite lock, reads the bundle again and asks `judge` whether the suite still skips. When it does, the
/// versions of units that left the roster are dropped and the table is compacted (spec 3.11). A busy lock writes nothing.
pub(crate) fn drop_stale(
    store: &Path,
    pending: &Pending,
    key: &str,
    judge: impl FnOnce(&View) -> bool,
) -> Settled {
    let Ok(Some(area)) = Area::open(store, false) else {
        return Settled::Failed;
    };
    let _lock = match lock(&area, &pending.suite) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Settled::Busy,
        Err(_) => return Settled::Failed,
    };
    let Some(view) = view_in(&area, pending, key) else {
        return Settled::Failed;
    };
    if !judge(&view) {
        return Settled::Declined;
    }
    // The view takes the bundle it reads, so the write reads it again under the same lock and checks it the same way.
    let Some(mut bundle) = bundle_for(&area, pending, key) else {
        return Settled::Failed;
    };
    let removed = bundle_readers(
        &bundle.table,
        bundle
            .units
            .iter()
            .filter(|(unit, _)| pending.roster.units.binary_search(*unit).is_err())
            .flat_map(|(_, versions)| versions.iter()),
    );
    bundle
        .units
        .retain(|unit, _| pending.roster.units.binary_search(unit).is_ok());
    if !versions_hold_current_unit_env(
        pending.unit_env_digest.as_deref(),
        bundle
            .units
            .values()
            .flatten()
            .map(|version| version.unit_env.as_deref()),
    ) || (!removed.is_empty()
        && lost_reader(
            &removed,
            &bundle_readers(&bundle.table, bundle.units.values().flatten()),
        ))
    {
        bundle.residue = Residue::default();
    }
    compact(&mut bundle);
    match write_bundle(&area, &bundle) {
        Ok(()) => Settled::Written,
        Err(_) => Settled::Failed,
    }
}

/// Rebuilds the table from the entries that the versions still index, in table order, and renumbers the versions to it.
/// It returns where each old entry went: `None` for an entry that no version indexes (spec 3.11).
fn compact(bundle: &mut SuiteBundleV1) -> Vec<Option<u32>> {
    let len = bundle.table.len();
    let mut used: BTreeSet<u32> = BTreeSet::new();
    for version in bundle.units.values().flatten() {
        used.extend(undelta(&version.inputs, len).unwrap_or_default());
        used.extend(undelta(&version.outputs, len).unwrap_or_default());
    }
    let mut renumber: Vec<Option<u32>> = vec![None; len];
    let mut table = Vec::with_capacity(used.len());
    for (new, &old) in used.iter().enumerate() {
        renumber[old as usize] = Some(u32::try_from(new).expect("the table is bounded"));
        table.push(bundle.table[old as usize].clone());
    }
    for version in bundle.units.values_mut().flatten() {
        for indices in [&mut version.inputs, &mut version.outputs] {
            let renamed: Vec<u32> = undelta(indices.as_slice(), len)
                .unwrap_or_default()
                .into_iter()
                .filter_map(|index| renumber[index as usize])
                .collect();
            *indices = delta(&renamed);
        }
    }
    bundle.table = table;
    renumber
}

/// Stores the suite as disabled for a disagreement (spec 3.4 and 3.6): a full command failed while every unit's proof
/// held. It is written under the suite lock, and only for a current bundle that is not disabled already. `Ok(false)`
/// means that nothing was written. A suite lock that another run holds is `WouldBlock`, so the caller can wait and try
/// again.
pub(crate) fn disable_full(
    store: &Path,
    pending: &Pending,
    key: &str,
    label: &str,
) -> io::Result<bool> {
    let Some(area) = Area::open(store, false)? else {
        return Ok(false);
    };
    let _lock = lock(&area, &pending.suite)?;
    let ReadBundle::Current(mut bundle) = read_bundle(&area, &pending.suite) else {
        return Ok(false);
    };
    let digest = digest_text("stoop whole key v1", key);
    if bundle.generation != GENERATION
        || !recorded(&bundle, &digest)
        || matches!(bundle.state, SuiteState::Disabled { .. })
    {
        return Ok(false);
    }
    bundle.state = SuiteState::Disabled {
        code: "disagreement".to_owned(),
        phase: "full".to_owned(),
        label: label.to_owned(),
        at: now(),
    };
    write_bundle(&area, &bundle)?;
    Ok(true)
}

/// Under the suite lock, judges the bundle with `holds`. When it holds, stores the residue of `whole`, the whole proof's
/// inputs, as confirmed: it is measured against the versions that the bundle holds now (spec 3.8, point iii). A busy
/// lock, a bundle that does not hold, or a bundle that cannot be written leaves the residue as it was.
pub(crate) fn confirm(
    store: &Path,
    pending: &Pending,
    key: &str,
    proof_digest: &str,
    whole: &[Input],
    holds: impl FnOnce(&View) -> bool,
) -> Settled {
    let Ok(Some(area)) = Area::open(store, false) else {
        return Settled::Failed;
    };
    let _lock = match lock(&area, &pending.suite) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Settled::Busy,
        Err(_) => return Settled::Failed,
    };
    let Some(view) = view_in(&area, pending, key) else {
        return Settled::Failed;
    };
    if !versions_hold_current_unit_env(
        pending.unit_env_digest.as_deref(),
        view.units
            .values()
            .flatten()
            .map(|version| version.unit_env.as_deref()),
    ) {
        let Some(mut bundle) = bundle_for(&area, pending, key) else {
            return Settled::Failed;
        };
        bundle.residue = Residue::default();
        return match write_bundle(&area, &bundle) {
            Ok(()) => Settled::Declined,
            Err(_) => Settled::Failed,
        };
    }
    if !holds(&view) {
        return Settled::Declined;
    }
    let Some(mut bundle) = bundle_for(&area, pending, key) else {
        return Settled::Failed;
    };
    // The residue is labelled with the whole proof the bundle holds, so this run may label it only when that proof is the
    // one it measured (spec 3.8, point iii). Another proof means another run wrote the bundle: decline.
    if bundle.whole.as_deref() != Some(proof_digest) {
        return Settled::Declined;
    }
    let Some(digest) = bundle.whole.clone() else {
        return Settled::Failed;
    };
    let (count, paths) = residue::uncovered(whole, pending.listings(), &covered_paths(&bundle));
    bundle.residue = Residue {
        state: ResidueState::Confirmed,
        paths,
        count,
        whole: Some(digest),
    };
    match write_bundle(&area, &bundle) {
        Ok(()) => Settled::Written,
        Err(_) => Settled::Failed,
    }
}

/// Whether the suite's store can take a new entry, for `stoop explain` to predict a learning run (spec 3.10). An absent
/// store is not refused, because the run creates it. Nothing is created or written here: the check reads the directory's
/// write permission and makes no entry (PR 86 review round 2, c3).
pub(crate) fn writable(store: &Path) -> bool {
    match Area::open(store, false) {
        Ok(Some(area)) => area.writable_dir(),
        Ok(None) => true,
        Err(_) => false,
    }
}

/// Checked on read only: each version's indices must lie below the table and strictly increase.
/// A check on every write would make a pass quadratic in its indices.
fn valid_versions(bundle: &SuiteBundleV1) -> bool {
    let len = bundle.table.len();
    bundle.units.values().all(|versions| {
        versions.iter().all(|version| {
            undelta(&version.inputs, len).is_some() && undelta(&version.outputs, len).is_some()
        })
    })
}

/// Strictly increasing indices, stored as the first index and then each gap from the one before.
fn delta(indices: &[u32]) -> Vec<u32> {
    let mut previous = 0;
    indices
        .iter()
        .enumerate()
        .map(|(at, &index)| {
            let stored = if at == 0 { index } else { index - previous };
            previous = index;
            stored
        })
        .collect()
}

/// The indices a delta list holds, when each is below `len` and each gap after the first is
/// positive. Anything else is `None`.
fn undelta(deltas: &[u32], len: usize) -> Option<Vec<u32>> {
    let mut out: Vec<u32> = Vec::with_capacity(deltas.len());
    for &step in deltas {
        let index = match out.last() {
            None => step,
            Some(&previous) if step > 0 => previous.checked_add(step)?,
            Some(_) => return None,
        };
        if index as usize >= len {
            return None;
        }
        out.push(index);
    }
    Some(out)
}

/// Listing is informational. A damaged file is reported and left untouched, and so is a suite
/// whose lock is not a regular file.
pub(crate) fn list(store: &Path) -> Vec<(String, Option<String>)> {
    let area = match Area::open(store, false) {
        Ok(Some(area)) => area,
        Ok(None) => return Vec::new(),
        Err(error) => {
            return vec![(
                "suite\t-\tunreadable".to_owned(),
                Some(format!(
                    "stoop: cannot read the suite store: {}",
                    super::hook::safe(&error.to_string())
                )),
            )];
        }
    };
    let mut ids: Vec<String> = area
        .names()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|name| {
            let id = name.strip_suffix(".json")?;
            valid_suite_id(id).then(|| id.to_owned())
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .filter_map(|id| {
            let lock_refused = match area.stat(&lock_name(&id)) {
                Ok(Some(stat)) => !stat.regular,
                Ok(None) => false,
                Err(_) => true,
            };
            match read_bundle(&area, &id) {
                ReadBundle::Missing => None,
                ReadBundle::Unreadable => Some((
                    format!("suite\t{id}\tunreadable"),
                    Some(format!("stoop: cannot read suite bundle: {id}")),
                )),
                ReadBundle::Corrupt => Some((
                    format!("suite\t{id}\tunreadable"),
                    Some(format!("stoop: ignoring a corrupt suite bundle: {id}")),
                )),
                ReadBundle::OtherVersion => Some((format!("suite\t{id}\tnewer format"), None)),
                ReadBundle::Current(_) if lock_refused => Some((
                    format!("suite\t{id}\tunreadable"),
                    Some(format!("stoop: suite {id} has a link where its lock belongs")),
                )),
                ReadBundle::Current(bundle) => {
                    let status = match bundle.state {
                        SuiteState::Ready => "ready",
                        SuiteState::Disabled { .. } => "disabled",
                    };
                    let cwd = if bundle.origin.cwd.is_empty() {
                        "."
                    } else {
                        &bundle.origin.cwd
                    };
                    let proven = bundle
                        .units
                        .values()
                        .filter(|versions| !versions.is_empty())
                        .count();
                    Some((
                        format!(
                            "suite\t{id}\tdir {}\t{status}\tplatform {}-{}\t{} units\t{proven} proven",
                            super::hook::safe(cwd),
                            super::hook::safe(&bundle.provenance.os),
                            super::hook::safe(&bundle.provenance.arch),
                            bundle.roster.units.len()
                        ),
                        None,
                    ))
                }
            }
        })
        .collect()
}

/// Removes a suite's bundle and lock. `Ok(false)` when there is nothing to remove. A link or
/// special file where the suite's files belong is refused, and a busy suite is reported as
/// `WouldBlock`.
pub(crate) fn forget(store: &Path, id: &str) -> io::Result<bool> {
    if !valid_suite_id(id) {
        return Ok(false);
    }
    let Some(area) = Area::open(store, false)? else {
        return Ok(false);
    };
    let names = [bundle_name(id), lock_name(id)];
    let mut found = false;
    for name in &names {
        match area.stat(name)? {
            None => {}
            Some(stat) if stat.regular => found = true,
            Some(_) => {
                return Err(io::Error::other(
                    "a link or special file is in the suite store; it is not followed",
                ));
            }
        }
    }
    if !found {
        return Ok(false);
    }
    let _lock = lock(&area, id)?;
    for name in &names {
        match area.unlink(name) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_version_bytes_and_mixed_unit_env_stamps() {
        let main_bytes = r#"{"created":1,"exact":true,"source":{"kind":"exit"},"guard":"g","inputs":[],"outputs":[]}"#;
        let version: UnitVersion = serde_json::from_str(main_bytes).unwrap();
        assert_eq!(version.unit_env, None);
        assert_eq!(serde_json::to_string(&version).unwrap(), main_bytes);
        assert!(versions_hold_current_unit_env(
            None,
            [None, None].into_iter()
        ));
        assert!(!versions_hold_current_unit_env(
            Some("new"),
            [None].into_iter()
        ));
        assert!(!versions_hold_current_unit_env(
            None,
            [Some("old")].into_iter()
        ));
        assert!(!versions_hold_current_unit_env(
            Some("new"),
            [Some("new"), Some("old")].into_iter()
        ));
        assert!(versions_hold_current_unit_env(
            Some("new"),
            [Some("new"), Some("new")].into_iter()
        ));
    }

    // The same bytes are produced by the main-branch codec in the compatibility probe.
    const MAIN_UNSET_BUNDLE: &str = concat!(
        r#"{"v":1,"generation":2,"suite":"00000000000000000000000000000000","#,
        r#""provenance":{"os":"linux","arch":"x86_64","tracer":"ptrace-seccomp","version":1},"#,
        r#""origin":{"kind":"hook","cwd":"","scope":null,"invocation":"invocation"},"#,
        r#""whole_key_digest":"key-digest","whole":"p-1","policy":"policy","#,
        r#""guard":{"env":{},"env_excluded":[],"ignore":[]},"guard_digest":"guard","#,
        r#""roster":{"source":"filter","units":["tests/a.t"]},"whole_roster":["tests/a.t"],"#,
        r#""table":[{"path":"tests/a.t","id":"f:00","oid":null}],"#,
        r#""units":{"tests/a.t":[{"created":1,"exact":true,"source":{"kind":"exit"},"guard":"guard","inputs":[0],"outputs":[]}]},"#,
        r#""residue":{"state":"confirmed","paths":[],"count":0,"whole":"p-1"},"state":{"status":"ready"}}"#
    );

    #[test]
    fn a_main_written_unset_bundle_loads_and_keeps_its_exact_bytes() {
        let bundle: SuiteBundleV1 = serde_json::from_str(MAIN_UNSET_BUNDLE).unwrap();
        assert!(valid_bundle(&bundle, "00000000000000000000000000000000"));
        assert!(valid_versions(&bundle));
        assert!(bundle.guard.unit_env.is_none());
        assert!(bundle.units["tests/a.t"][0].unit_env.is_none());
        assert_eq!(encode(&bundle).unwrap(), MAIN_UNSET_BUNDLE.as_bytes());
        let view = View::of(bundle).unwrap();
        assert_eq!(view.residue, Some((0, Vec::new())));
        assert!(view.units["tests/a.t"][0].unit_env.is_none());
    }

    #[test]
    fn suite_ids_are_length_delimited_and_bind_every_field() {
        let words = vec![OsString::from("runner"), OsString::from("{changed:*.t}")];
        let id = suite_id(&words, "a", Some("scope"), Some("label"));
        assert_eq!(id.len(), 32);
        assert_ne!(id, suite_id(&words, "b", Some("scope"), Some("label")));
        assert_ne!(id, suite_id(&words, "a", Some("other"), Some("label")));
        assert_ne!(id, suite_id(&words, "a", Some("scope"), Some("other")));
        assert_ne!(
            suite_id(&["ab".into(), "c".into()], "", None, None),
            suite_id(&["a".into(), "bc".into()], "", None, None)
        );
    }

    #[test]
    fn unit_ids_and_roster_obey_the_bounds() {
        assert_eq!(MAX_UNITS, 4096);
        assert_eq!(MAX_UNIT_BYTES, 4096);
        assert_eq!(MAX_VERSIONS, 8);
        assert_eq!(MAX_BYTES, 8 * 1024 * 1024);
        for invalid in ["", "/a", "./a", "a/../b", "a//b", "a\nb", "a\0b"] {
            assert!(!valid_unit(invalid), "{invalid:?}");
        }
        assert!(valid_unit("tests/a.t"));
        assert!(valid_unit("pkg/sub/"));
        assert!(valid_unit(&"a".repeat(MAX_UNIT_BYTES)));
        assert!(!valid_unit(&"a".repeat(MAX_UNIT_BYTES + 1)));
        assert!(!valid_roster(&["b".into(), "a".into()]));
        assert!(!valid_roster(&["a".into(), "a".into()]));
    }

    #[test]
    fn bundle_round_trips_without_catalog_inputs() {
        let pending = pending(PendingSpec {
            argv: &["runner".into(), "{changed:*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "*.t",
            units: vec!["tests/a.t".into()],
            config: None,
            config_suite: None,
            unit_env: BTreeMap::new(),
            listings: Vec::new(),
        })
        .unwrap();
        let bundle = SuiteBundleV1 {
            v: VERSION,
            generation: GENERATION,
            suite: pending.suite,
            provenance: Provenance::current(),
            origin: pending.origin,
            whole_key_digest: "key".into(),
            whole: Some("p-123".into()),
            policy: pending.policy,
            guard: LaunchGuard {
                env: BTreeMap::new(),
                env_excluded: Vec::new(),
                ignore: Vec::new(),
                unit_env: None,
            },
            guard_digest: "guard".into(),
            roster: pending.roster,
            whole_roster: Vec::new(),
            table: Vec::new(),
            units: BTreeMap::new(),
            residue: Residue::default(),
            state: SuiteState::Ready,
        };
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let decoded: SuiteBundleV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(valid_bundle(&decoded, &bundle.suite));
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["roster"].get("inputs").is_none());
        assert!(
            json.get("whole_roster").is_none(),
            "a bundle no split run recorded keeps its bytes"
        );
        let mut bounded = decoded;
        let versions = (0..=MAX_VERSIONS)
            .map(|_| UnitVersion {
                created: 1,
                exact: true,
                source: ResultSource::Exit,
                guard: "guard".into(),
                unit_env: None,
                inputs: Vec::new(),
                outputs: Vec::new(),
            })
            .collect();
        bounded.units.insert("tests/a.t".into(), versions);
        assert!(!valid_bundle(&bounded, &bundle.suite));
        bounded.units.get_mut("tests/a.t").unwrap().pop();
        assert!(valid_bundle(&bounded, &bundle.suite));
        let suffix = "a".repeat(2050);
        bounded.roster.units = (0..MAX_UNITS)
            .map(|index| format!("{index:04}{suffix}"))
            .collect();
        assert!(valid_bundle(&bounded, &bundle.suite));
        let error = encode(&bounded).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(bounded.roster.units.len(), MAX_UNITS);
        bounded.roster.units.push("zzzz".into());
        assert!(!valid_bundle(&bounded, &bundle.suite));
    }
}

#[cfg(all(test, unix))]
mod lock_identity_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    /// A store with its suite area open and a lock file in place.
    fn scratch(name: &str) -> (std::path::PathBuf, Area) {
        let store = std::env::temp_dir().join(format!("stoop-lock-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&store);
        let area = Area::open(&store, true).unwrap().unwrap();
        fs::write(lock_file(&store), b"").unwrap();
        (store, area)
    }

    fn lock_file(store: &Path) -> std::path::PathBuf {
        store.join("units/v1").join(lock_name(ID))
    }

    fn replace_lock(store: &Path) {
        let path = lock_file(store);
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
    }

    fn held_identity(file: &File) -> (u64, u64) {
        let meta = file.metadata().unwrap();
        (meta.dev(), meta.ino())
    }

    fn path_identity(store: &Path) -> (u64, u64) {
        let meta = fs::symlink_metadata(lock_file(store)).unwrap();
        (meta.dev(), meta.ino())
    }

    #[test]
    fn a_lock_replaced_while_it_is_taken_is_not_trusted() {
        let (store, area) = scratch("replaced-once");
        let mut first = true;
        let file = lock_with(&area, ID, || {
            if std::mem::take(&mut first) {
                replace_lock(&store);
            }
        })
        .unwrap();
        assert_eq!(held_identity(&file), path_identity(&store));
        let _ = fs::remove_dir_all(&store);
    }

    #[test]
    fn a_lock_replaced_on_every_attempt_is_reported_busy() {
        let (store, area) = scratch("replaced-always");
        let result = lock_with(&area, ID, || replace_lock(&store));
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&store);
    }

    fn make_fifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let text = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `text` is NUL-terminated and lives for the call.
        assert_eq!(unsafe { libc::mkfifo(text.as_ptr(), 0o600) }, 0);
    }

    #[test]
    fn a_lock_that_is_not_a_regular_file_with_one_name_is_never_taken() {
        let (store, area) = scratch("one-name");
        let name = lock_name(ID);
        let path = lock_file(&store);
        assert!(area.lock_file(&name).is_ok());
        fs::remove_file(&path).unwrap();
        make_fifo(&path);
        assert!(area.lock_file(&name).is_err(), "a FIFO was taken");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(area.lock_file(&name).is_err(), "a directory was taken");
        fs::remove_dir(&path).unwrap();
        let spare = store.join("units/v1/spare");
        fs::write(&spare, b"").unwrap();
        fs::hard_link(&spare, &path).unwrap();
        assert!(
            area.lock_file(&name).is_err(),
            "a hard-linked file was taken"
        );
        let _ = fs::remove_dir_all(&store);
    }
}

#[cfg(test)]
mod presence_tests {
    use super::*;

    #[test]
    fn an_absent_label_and_an_empty_label_identify_different_suites() {
        let words = [OsString::from("runner")];
        assert_ne!(
            suite_id(&words, "", None, None),
            suite_id(&words, "", None, Some(""))
        );
        assert_ne!(
            suite_id(&words, "", None, None),
            suite_id(&words, "", Some(""), None)
        );
    }
}

#[cfg(all(test, unix))]
mod pass_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn input(path: &str) -> Input {
        Input {
            path: path.into(),
            id: "f:00".into(),
            oid: None,
            oid_basis: None,
        }
    }

    fn guard() -> LaunchGuard {
        LaunchGuard {
            env: BTreeMap::new(),
            env_excluded: Vec::new(),
            ignore: Vec::new(),
            unit_env: None,
        }
    }

    fn pending_for(units: &[&str]) -> Pending {
        pending_for_env(units, BTreeMap::new())
    }

    fn pending_for_env(units: &[&str], unit_env: BTreeMap<String, String>) -> Pending {
        pending(PendingSpec {
            argv: &["runner".into(), "{changed:*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "*.t",
            units: units.iter().map(|unit| unit.to_string()).collect(),
            config: None,
            config_suite: None,
            unit_env,
            listings: Vec::new(),
        })
        .unwrap()
    }

    fn store(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stoop-pass-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// The bundle that `start` accepts for `pending` under `key`: current and ready, with no unit proof.
    fn bundle_for(pending: Pending, key: &str) -> SuiteBundleV1 {
        SuiteBundleV1 {
            v: VERSION,
            generation: GENERATION,
            suite: pending.suite,
            provenance: Provenance::current(),
            origin: pending.origin,
            whole_key_digest: digest_text("stoop whole key v1", key),
            whole: Some("p-1".into()),
            policy: pending.policy,
            guard: guard(),
            guard_digest: "guard".into(),
            roster: pending.roster,
            whole_roster: Vec::new(),
            table: Vec::new(),
            units: BTreeMap::new(),
            residue: Residue::default(),
            state: SuiteState::Ready,
        }
    }

    /// Writes `bundle` into a new store and returns the store's directory.
    fn seed(name: &str, bundle: &SuiteBundleV1) -> PathBuf {
        let dir = store(name);
        let area = Area::open(&dir, true).unwrap().unwrap();
        write_bundle(&area, bundle).unwrap();
        dir
    }

    fn pass_of(start: Start) -> Pass {
        match start {
            Start::Pass(pass) => pass,
            Start::Busy => panic!("the suite lock was busy"),
            Start::No => panic!("no pass was started"),
        }
    }

    fn bundle_file(dir: &Path, id: &str) -> PathBuf {
        dir.join("units/v1").join(bundle_name(id))
    }

    fn version(inputs: Vec<u32>) -> UnitVersion {
        UnitVersion {
            created: 1,
            exact: true,
            source: ResultSource::Exit,
            guard: "g".into(),
            unit_env: None,
            inputs,
            outputs: Vec::new(),
        }
    }

    #[test]
    fn a_residue_is_never_measured_from_an_inexact_version() {
        let mut bundle = bundle_for(pending_for(&["tests/a.t", "tests/b.t"]), "key");
        bundle.table = vec![input("src/a"), input("src/b")];
        let exact = version(delta(&[0]));
        let mut inexact = version(delta(&[1]));
        inexact.exact = false;
        bundle.units.insert("tests/a.t".into(), vec![exact]);
        bundle.units.insert("tests/b.t".into(), vec![inexact]);

        let whole = vec![input("src/a"), input("src/b")];
        store_residue(&mut bundle, &whole, "p-1", &[]);
        assert!(
            matches!(bundle.residue.state, ResidueState::None),
            "a roster member with only an inexact proof cannot complete the residue"
        );

        bundle.units.get_mut("tests/b.t").unwrap()[0].exact = true;
        store_residue(&mut bundle, &whole, "p-1", &[]);
        assert!(matches!(bundle.residue.state, ResidueState::Provisional));
        assert_eq!(bundle.residue.count, 0);
    }

    #[test]
    fn confirm_counts_only_exact_versions() {
        let roster = ["tests/a.t", "tests/b.t"];
        let pending = pending_for(&roster);
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("src/exact"), input("src/inexact")];
        let mut inexact = version(delta(&[1]));
        inexact.exact = false;
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(delta(&[0]))]);
        bundle.units.insert("tests/b.t".into(), vec![inexact]);
        let dir = seed("confirm-exact-only", &bundle);
        let outcome = confirm(
            &dir,
            &pending,
            "key",
            "p-1",
            &[input("src/exact"), input("src/inexact")],
            |_| true,
        );
        assert!(matches!(outcome, Settled::Written));
        let residue = stored(&dir, pending.suite()).residue;
        assert!(matches!(residue.state, ResidueState::Confirmed));
        assert_eq!(residue.count, 1);
        assert_eq!(residue.paths, ["src/inexact"]);
        let _ = fs::remove_dir_all(dir);
    }

    fn mixed_env_bundle() -> SuiteBundleV1 {
        let roster = ["tests/a.t", "tests/b.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.guard.unit_env = Some("new".into());
        bundle.table = vec![input("src/shared")];
        let mut current = version(vec![0]);
        current.unit_env = Some("new".into());
        let mut old = version(vec![0]);
        old.unit_env = Some("old".into());
        bundle.units.insert(roster[0].into(), vec![current]);
        bundle.units.insert(roster[1].into(), vec![old]);
        bundle.residue = Residue {
            state: ResidueState::Confirmed,
            paths: Vec::new(),
            count: 0,
            whole: Some("p-1".into()),
        };
        bundle
    }

    #[test]
    fn unit_env_confirm_declines_mixed_versions_even_when_caller_claims_holds() {
        let roster = ["tests/a.t", "tests/b.t"];
        let pending = pending_for_env(&roster, BTreeMap::from([("MODE".into(), "new".into())]));
        let mut bundle = mixed_env_bundle();
        let digest = pending.unit_env_digest();
        bundle.guard.unit_env.clone_from(&digest);
        bundle.units.get_mut(roster[0]).unwrap()[0].unit_env = digest;
        let dir = seed("unit-env-confirm-mixed", &bundle);
        assert!(matches!(
            confirm(&dir, &pending, "key", "p-1", &[input("src/shared")], |_| {
                true
            }),
            Settled::Declined
        ));
        assert!(matches!(
            stored(&dir, pending.suite()).residue.state,
            ResidueState::None
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unit_env_switch_off_residue_rejects_mixed_versions() {
        let mut bundle = mixed_env_bundle();
        store_residue(&mut bundle, &[input("src/shared")], "p-1", &[]);
        assert!(matches!(bundle.residue.state, ResidueState::None));
    }

    #[test]
    fn unit_env_kept_pass_clears_residue_before_changing_guard() {
        let bundle = mixed_env_bundle();
        let pending = pending_for(&["tests/a.t", "tests/b.t"]);
        let dir = seed("unit-env-keep-mixed", &bundle);
        let launch_guard = LaunchGuard {
            unit_env: Some("new".into()),
            ..guard()
        };
        let pass = match keep(&dir, &pending, "key", launch_guard, |_| Ok::<(), ()>(())) {
            Kept::Locked(pass, ()) => pass,
            _ => panic!("the pass was not kept"),
        };
        assert!(matches!(pass.bundle.residue.state, ResidueState::None));
        assert!(pass.dirty);
        drop(pass);
        assert!(matches!(
            stored(&dir, pending.suite()).residue.state,
            ResidueState::None
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unit_env_note_losses_clears_mixed_residue_without_removed_paths() {
        let bundle = mixed_env_bundle();
        let pending = pending_for(&["tests/a.t", "tests/b.t"]);
        let dir = seed("unit-env-note-losses", &bundle);
        let launch_guard = LaunchGuard {
            unit_env: Some("new".into()),
            ..guard()
        };
        let mut pass = match keep(&dir, &pending, "key", launch_guard, |_| Ok::<(), ()>(())) {
            Kept::Locked(pass, ()) => pass,
            _ => panic!("the pass was not kept"),
        };
        pass.bundle.residue = mixed_env_bundle().residue;
        pass.note_losses(&BTreeMap::new());
        assert!(matches!(pass.bundle.residue.state, ResidueState::None));
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unit_env_settle_does_not_heal_a_loss_with_a_stale_reader() {
        let bundle = mixed_env_bundle();
        let pending = pending_for(&["tests/a.t", "tests/b.t"]);
        let dir = seed("unit-env-settle-mixed", &bundle);
        let launch_guard = LaunchGuard {
            unit_env: Some("new".into()),
            ..guard()
        };
        let mut pass = match keep(&dir, &pending, "key", launch_guard, |_| Ok::<(), ()>(())) {
            Kept::Locked(pass, ()) => pass,
            _ => panic!("the pass was not kept"),
        };
        pass.bundle.residue = mixed_env_bundle().residue;
        pass.residue_lost = true;
        pass.lost_paths.insert("src/shared".into());
        pass.settle_residue(&[], &[], false);
        assert!(matches!(pass.bundle.residue.state, ResidueState::None));
        assert!(pass.residue_lost);
        assert!(pass.lost_paths.contains("src/shared"));
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unit_env_view_and_known_residue_reject_mixed_versions() {
        let mut bundle = mixed_env_bundle();
        bundle.residue.paths = vec!["src/uncovered".into()];
        bundle.residue.count = 1;
        let pending = pending_for(&["tests/a.t", "tests/b.t"]);
        let dir = seed("unit-env-view-mixed", &bundle);
        assert!(View::of(bundle).unwrap().residue.is_none());
        assert!(known_residue(&dir, pending.suite(), "key").is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unit_env_learn_does_not_trust_confirmed_residue_with_a_stale_stamp() {
        with_inexact_engine_fixture("unit-env-learn-mixed", |judged, original, _| {
            let mut view = View {
                whole: original.whole.clone(),
                disabled: None,
                table: original.table.clone(),
                units: original
                    .units
                    .iter()
                    .map(|(unit, versions)| {
                        let copies = versions
                            .iter()
                            .map(|version| Version {
                                created: version.created,
                                exact: true,
                                guard: version.guard.clone(),
                                unit_env: None,
                                inputs: version.inputs.clone(),
                                outputs: version.outputs.clone(),
                            })
                            .collect();
                        (unit.clone(), copies)
                    })
                    .collect(),
                residue: Some((0, Vec::new())),
                whole_roster: original.whole_roster.clone(),
            };
            view.units.get_mut("tests/b.t").unwrap()[0].unit_env = Some("old".into());
            assert_eq!(
                super::super::engine::learn(judged, &view).unwrap(),
                ["tests/b.t"]
            );
            assert!(!super::super::engine::holds(judged, &view));
        });
    }

    #[test]
    fn unit_env_version_is_stamped_from_the_actual_launch_guard() {
        let roster = ["tests/a.t"];
        let pending = pending_for_env(&roster, BTreeMap::from([("MODE".into(), "pending".into())]));
        let dir = seed(
            "unit-env-version-stamp",
            &bundle_for(pending_for(&roster), "key"),
        );
        let launch_guard = LaunchGuard {
            unit_env: Some("actual-launch".into()),
            ..guard()
        };
        let mut pass = pass_of(start(&dir, &pending, "key", launch_guard));
        assert!(matches!(
            pass.record(&[roster[0].into()], &[input("src/shared")], &[], 1),
            Stored::Stored
        ));
        drop(pass);
        let bundle = stored(&dir, pending.suite());
        let version = &bundle.units[roster[0]][0];
        assert_eq!(version.unit_env.as_deref(), Some("actual-launch"));
        assert_eq!(version.guard, bundle.guard.digest());
        assert_ne!(version.unit_env, pending.unit_env_digest());
        let _ = fs::remove_dir_all(dir);
    }

    fn with_inexact_engine_fixture(
        name: &str,
        check: impl FnOnce(&super::super::engine::Judged<'_>, &View, &Path),
    ) {
        use super::super::engine::Judged;
        use crate::run::{Opts, RunCx};

        let dir = store(name);
        let root = dir.join("root");
        fs::create_dir_all(root.join("tests")).unwrap();
        for name in ["a.t", "b.t", "c.t", "shared"] {
            fs::write(root.join("tests").join(name), name).unwrap();
        }
        let opts = Opts::default();
        let rel_cwd = String::new();
        let scope = None;
        let store = crate::proof::Store::new(dir.join("proofs"));
        let hook = None;
        let full_reason = None;
        let salt = None;
        let cx = RunCx {
            o: &opts,
            cwd: &root,
            root: &root,
            rel_cwd: &rel_cwd,
            scope: &scope,
            store: &store,
            hook: &hook,
            full_reason: &full_reason,
            max_age: 0,
            bypass: false,
            explain: false,
            observe_runners: true,
            env_now: BTreeMap::new(),
            env_excluded: Vec::new(),
            salt: &salt,
            remote: None,
        };
        let ignore = crate::ignore::Ignore::new(
            &opts.ignore,
            Some(&root.join(".stoopignore")),
            &opts.transient,
        );
        let roster = ["tests/a.t", "tests/b.t", "tests/c.t"];
        let pending = pending_for(&roster);
        let guard = super::super::attribution::guard_of(&cx, &ignore, &pending).digest();
        let proof = whole_proof(&[]);
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(proof.digest());
        bundle.table = ["tests/a.t", "tests/b.t", "tests/shared", "tests/c.t"]
            .iter()
            .map(|path| Input {
                path: (*path).into(),
                id: crate::input::identify(&root.join(path), true, false).unwrap(),
                oid: None,
                oid_basis: None,
            })
            .collect();
        let mut grouped = version(delta(&[0, 1, 2]));
        grouped.exact = false;
        grouped.guard = guard.clone();
        let mut single = version(delta(&[3]));
        single.guard = guard;
        bundle.units.insert(roster[0].into(), vec![grouped.clone()]);
        bundle.units.insert(roster[1].into(), vec![grouped]);
        bundle.units.insert(roster[2].into(), vec![single]);
        let view = View::of(bundle).unwrap();
        let proofs = [proof];
        let judged = Judged::new(&cx, &pending, &proofs, 0);
        check(&judged, &view, &root);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn learn_relaunches_units_whose_valid_proofs_are_all_inexact() {
        with_inexact_engine_fixture("learn-inexact", |judged, view, root| {
            assert_eq!(
                super::super::engine::learn(judged, view).unwrap(),
                ["tests/a.t", "tests/b.t"]
            );
            fs::write(root.join("tests/c.t"), "changed").unwrap();
            assert_eq!(
                super::super::engine::learn(judged, view).unwrap(),
                ["tests/a.t", "tests/b.t", "tests/c.t"]
            );
        });
    }

    #[test]
    fn holds_is_false_while_a_unit_holds_only_an_inexact_proof() {
        with_inexact_engine_fixture("holds-inexact", |judged, view, _| {
            assert!(!super::super::engine::holds(judged, view));
        });
    }

    #[test]
    fn delta_round_trips_and_decoding_refuses_out_of_range_and_unordered_indices() {
        let indices = [0, 3, 4, 10];
        let stored = delta(&indices);
        assert_eq!(stored, [0, 3, 1, 6]);
        assert_eq!(undelta(&stored, 11), Some(indices.to_vec()));
        assert_eq!(undelta(&stored, 10), None, "an index past the table");
        assert_eq!(undelta(&[2, 0], 5), None, "a repeated index");
        assert_eq!(
            undelta(&[u32::MAX, 1], usize::MAX),
            None,
            "an overflowing gap"
        );
        assert_eq!(undelta(&[], 0), Some(Vec::new()));
    }

    #[test]
    fn a_version_index_past_the_table_makes_the_bundle_corrupt_on_read() {
        let pending = pending_for(&["tests/a.t"]);
        let id = pending.suite.clone();
        let mut bundle = bundle_for(pending, "key");
        bundle.table = vec![input("src/shared.src")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(vec![0, 1])]);
        let dir = store("damaged");
        let area = Area::open(&dir, true).unwrap().unwrap();
        write_bytes(&area, &id, &serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(matches!(read_bundle(&area, &id), ReadBundle::Corrupt));
        bundle.units.get_mut("tests/a.t").unwrap()[0] = version(vec![0]);
        write_bytes(&area, &id, &serde_json::to_vec(&bundle).unwrap()).unwrap();
        assert!(matches!(read_bundle(&area, &id), ReadBundle::Current(_)));
    }

    #[test]
    fn a_unit_keeps_one_version_and_each_input_is_stored_once() {
        let roster = ["tests/a.t", "tests/b.t"];
        let dir = seed("one-version", &bundle_for(pending_for(&roster), "key"));
        let id = pending_for(&roster).suite;
        let mut pass = pass_of(start(&dir, &pending_for(&roster), "key", guard()));
        let shared = input("src/shared.src");
        let setup = input("setup.src");
        let stored = |outcome: Stored| matches!(outcome, Stored::Stored);
        assert!(stored(pass.record(
            &["tests/a.t".to_owned()],
            &[shared.clone(), setup.clone(), shared.clone()],
            &[],
            1
        )));
        assert!(stored(pass.record(
            &["tests/b.t".to_owned()],
            std::slice::from_ref(&setup),
            &[],
            2
        )));
        assert!(stored(pass.record(
            &["tests/a.t".to_owned()],
            std::slice::from_ref(&setup),
            &[],
            3
        )));
        assert_eq!(pass.bundle.table.len(), 2, "shared and setup, once each");
        assert_eq!(pass.bundle.units["tests/a.t"].len(), 1);
        assert_eq!(pass.bundle.units["tests/a.t"][0].inputs, [1]);
        drop(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("the stored bundle is not current");
        };
        assert_eq!(stored.units.len(), 2);
        assert_eq!(stored.table.len(), 2);
    }

    /// I13: an over-budget pass keeps no unit proof, and its suite is stored disabled for it (spec 3.6).
    #[test]
    fn i13_an_over_budget_pass_disables_the_suite_and_keeps_no_unit() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        let dir = seed("budget", &bundle_for(pending_for(&roster), "key"));
        let before = fs::read(bundle_file(&dir, &id)).unwrap();
        let mut pass = pass_of(start(&dir, &pending_for(&roster), "key", guard()));
        pass.budget = before.len() as u64;
        assert!(matches!(
            pass.record(
                &["tests/a.t".to_owned()],
                &[input("src/shared.src")],
                &[],
                1
            ),
            Stored::OverBudget
        ));
        assert!(
            pass.bundle.units.is_empty(),
            "the dropped version left memory"
        );
        assert!(pass.bundle.table.is_empty());
        assert!(pass.interned.is_empty());
        pass.disable_without_versions("over_budget", "unit proofs exceed 8 MiB")
            .unwrap();
        drop(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("the bundle is not current after an over-budget pass");
        };
        assert!(stored.units.is_empty());
        assert!(stored.table.is_empty());
        let SuiteState::Disabled { code, label, .. } = stored.state else {
            panic!("the over-budget suite is not disabled");
        };
        assert_eq!(code, "over_budget");
        assert_eq!(label, "unit proofs exceed 8 MiB");
    }

    /// I16: a pass that stores nothing leaves no marker, so the same roster starts a pass again.
    #[test]
    fn i16_a_pass_that_stores_nothing_leaves_no_marker() {
        let roster = ["tests/a.t"];
        let dir = seed("no-marker", &bundle_for(pending_for(&roster), "key"));
        drop(pass_of(start(&dir, &pending_for(&roster), "key", guard())));
        assert!(
            matches!(
                start_after_release(&dir, &pending_for(&roster), "key"),
                Start::Pass(_)
            ),
            "the same roster starts a pass again"
        );
    }

    /// Takes the suite lock again after this test released it. Another test thread can fork a
    /// child that holds a copy of the lock descriptor until it execs, so the lock can stay held
    /// briefly. Busy is retried for up to 2 s; a lock still held after that fails the test.
    fn start_after_release(store: &std::path::Path, pending: &Pending, key: &str) -> Start {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match start(store, pending, key, guard()) {
                Start::Busy => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the suite lock stayed busy for 2 s after this test released it"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                other => return other,
            }
        }
    }

    #[test]
    fn start_takes_a_pass_only_when_every_precondition_holds() {
        let roster = ["tests/a.t"];
        let refused = |name: &str, edit: fn(&mut SuiteBundleV1)| {
            let mut bundle = bundle_for(pending_for(&roster), "key");
            edit(&mut bundle);
            let dir = seed(name, &bundle);
            assert!(
                matches!(
                    start(&dir, &pending_for(&roster), "key", guard()),
                    Start::No
                ),
                "{name}"
            );
        };
        let dir = seed("preconditions", &bundle_for(pending_for(&roster), "key"));
        // The key check comes before the first pass.
        assert!(matches!(
            start(&dir, &pending_for(&roster), "another key", guard()),
            Start::No
        ));
        assert!(matches!(
            start(&dir, &pending_for(&roster), "key", guard()),
            Start::Pass(_)
        ));
        let wider = ["tests/a.t", "tests/b.t"];
        assert!(
            matches!(
                start_after_release(&dir, &pending_for(&wider), "key"),
                Start::Pass(_)
            ),
            "a new roster for the same suite starts a pass"
        );
        assert!(matches!(
            start(&store("absent"), &pending_for(&roster), "key", guard()),
            Start::No
        ));
        refused("disabled", |bundle| {
            bundle.state = SuiteState::Disabled {
                code: "c".into(),
                phase: "p".into(),
                label: "l".into(),
                at: 1,
            }
        });
        refused("other provenance", |bundle| {
            bundle.provenance.version += 1;
        });
        refused("other generation", |bundle| bundle.generation = 0);
        refused("no whole proof", |bundle| bundle.whole = None);
        refused("a unit with a proof", |bundle| {
            bundle.table = vec![input("setup.src")];
            bundle
                .units
                .insert("tests/a.t".into(), vec![version(vec![0])]);
        });
    }

    #[test]
    fn start_reports_a_held_lock_as_busy_and_an_unreadable_bundle_as_no() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        let dir = seed("busy", &bundle_for(pending_for(&roster), "key"));
        let area = Area::open(&dir, false).unwrap().unwrap();
        let held = lock(&area, &id).unwrap();
        assert!(matches!(
            start(&dir, &pending_for(&roster), "key", guard()),
            Start::Busy
        ));
        drop(held);
        let file = bundle_file(&dir, &id);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
        assert!(matches!(
            start(&dir, &pending_for(&roster), "key", guard()),
            Start::No
        ));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            start_after_release(&dir, &pending_for(&roster), "key"),
            Start::Pass(_)
        ));
    }

    /// `count` unit names, in roster order.
    fn roster_of(count: usize) -> Vec<String> {
        (0..count)
            .map(|index| format!("tests/u{index:02}.t"))
            .collect()
    }

    fn pending_of(units: &[String]) -> Pending {
        pending(PendingSpec {
            argv: &["runner".into(), "{changed:*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "*.t",
            units: units.to_vec(),
            config: None,
            config_suite: None,
            unit_env: BTreeMap::new(),
            listings: Vec::new(),
        })
        .unwrap()
    }

    #[test]
    fn a_pass_writes_its_bundle_once_for_many_quick_proofs() {
        let units = roster_of(20);
        let dir = seed("coalesce", &bundle_for(pending_of(&units), "key"));
        let mut pass = pass_of(start(&dir, &pending_of(&units), "key", guard()));
        for unit in &units {
            assert!(matches!(
                pass.record(
                    std::slice::from_ref(unit),
                    &[input("src/shared.src")],
                    &[],
                    1
                ),
                Stored::Stored
            ));
        }
        // The first proof is written at once. The others wait for a second to pass or for the end.
        assert!(
            pass.writes <= 3,
            "{} writes for 20 quick proofs",
            pass.writes
        );
    }

    #[test]
    fn a_pass_writes_every_proof_it_holds_when_it_ends() {
        let units = roster_of(3);
        let id = pending_of(&units).suite;
        let dir = seed("final-flush", &bundle_for(pending_of(&units), "key"));
        let mut pass = pass_of(start(&dir, &pending_of(&units), "key", guard()));
        for unit in &units {
            pass.record(
                std::slice::from_ref(unit),
                &[input("src/shared.src")],
                &[],
                1,
            );
        }
        drop(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("the stored bundle is not current");
        };
        assert_eq!(
            stored.units.len(),
            3,
            "every proof held at the end is on disk"
        );
    }

    #[test]
    fn a_pass_killed_mid_run_leaves_a_current_bundle_with_its_first_proof() {
        let units = roster_of(3);
        let id = pending_of(&units).suite;
        let dir = seed("killed", &bundle_for(pending_of(&units), "key"));
        let mut pass = pass_of(start(&dir, &pending_of(&units), "key", guard()));
        pass.record(
            std::slice::from_ref(&units[0]),
            &[input("src/shared.src")],
            &[],
            1,
        );
        pass.record(
            std::slice::from_ref(&units[1]),
            &[input("src/shared.src")],
            &[],
            1,
        );
        // A kill ends the process without running the pass's end, so nothing more is written.
        std::mem::forget(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("a killed pass left a bundle that is not current");
        };
        assert!(stored.units.contains_key(&units[0]));
    }

    #[test]
    fn a_store_that_cannot_take_a_new_entry_starts_no_pass() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        let dir = seed("read-only", &bundle_for(pending_for(&roster), "key"));
        // The lock entry must exist, but no lock is taken. A flock taken here stays held by any
        // child that another test thread forks before it execs, and then `start` reports Busy.
        let area = Area::open(&dir, false).unwrap().unwrap();
        drop(area.lock_file(&lock_name(&id)).unwrap());
        let suite_dir = dir.join("units/v1");
        let _mode = ModeGuard::set(&suite_dir, 0o500);
        let started = start(&dir, &pending_for(&roster), "key", guard());
        assert!(
            matches!(started, Start::No),
            "a pass starts only when its proofs can be stored"
        );
    }

    #[test]
    fn a_held_lock_on_a_suite_with_unit_proofs_starts_no_pass_and_is_silent() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("setup.src")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(vec![0])]);
        let dir = seed("held-proven", &bundle);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let held = lock(&area, &id).unwrap();
        // Busy would print the busy line for a run that starts no pass.
        assert!(matches!(
            start(&dir, &pending_for(&roster), "key", guard()),
            Start::No
        ));
        drop(held);
    }

    #[test]
    fn the_bundle_is_checked_again_under_the_lock() {
        let roster = ["tests/a.t"];
        let pending = pending_for(&roster);
        let dir = seed("recheck", &bundle_for(pending_for(&roster), "key"));
        let mut proven = bundle_for(pending_for(&roster), "key");
        proven.table = vec![input("setup.src")];
        proven
            .units
            .insert("tests/a.t".into(), vec![version(vec![0])]);
        let started = start_with(&dir, &pending, "key", guard(), || {
            // Another stoop records a proof after this run's unlocked check and before its lock.
            let area = Area::open(&dir, false).unwrap().unwrap();
            write_bundle(&area, &proven).unwrap();
        });
        assert!(
            matches!(started, Start::No),
            "a proof recorded before the lock is seen under it"
        );
    }

    /// Sets a directory's mode for the length of a test, and restores it to private when the guard
    /// is dropped, so a failed assertion cannot leave the store unwritable.
    struct ModeGuard(PathBuf);

    impl ModeGuard {
        fn set(path: &Path, mode: u32) -> ModeGuard {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
            ModeGuard(path.to_path_buf())
        }
    }

    impl Drop for ModeGuard {
        fn drop(&mut self) {
            let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        }
    }

    /// A kill after a due write keeps every proof that write held. The second proof is written
    /// because a second has passed since the first write. The pass is then forgotten without
    /// running its end, as a kill does.
    #[test]
    fn a_kill_after_a_due_write_keeps_every_proof_it_held() {
        let units = roster_of(2);
        let id = pending_of(&units).suite;
        let dir = seed("due-write", &bundle_for(pending_of(&units), "key"));
        let mut pass = pass_of(start(&dir, &pending_of(&units), "key", guard()));
        assert!(matches!(
            pass.record(
                std::slice::from_ref(&units[0]),
                &[input("src/shared.src")],
                &[],
                1
            ),
            Stored::Stored
        ));
        std::thread::sleep(FLUSH_INTERVAL);
        assert!(matches!(
            pass.record(
                std::slice::from_ref(&units[1]),
                &[input("src/shared.src")],
                &[],
                1
            ),
            Stored::Stored
        ));
        std::mem::forget(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("a killed pass left a bundle that is not current");
        };
        assert!(stored.units.contains_key(&units[0]));
        assert!(
            stored.units.contains_key(&units[1]),
            "the due write held the second proof"
        );
    }

    /// A due write that fails keeps its proof held, so the end of the pass writes it. A failed
    /// write must not clear the dirty mark, or the proof is lost.
    #[test]
    fn a_failed_due_write_is_written_when_the_pass_ends() {
        let units = roster_of(2);
        let id = pending_of(&units).suite;
        let dir = seed("failed-write", &bundle_for(pending_of(&units), "key"));
        let suite_dir = dir.join("units/v1");
        let mut pass = pass_of(start(&dir, &pending_of(&units), "key", guard()));
        assert!(matches!(
            pass.record(
                std::slice::from_ref(&units[0]),
                &[input("src/shared.src")],
                &[],
                1
            ),
            Stored::Stored
        ));
        std::thread::sleep(FLUSH_INTERVAL);
        {
            // The due write cannot create its temporary entry, so it fails.
            let _mode = ModeGuard::set(&suite_dir, 0o500);
            assert!(matches!(
                pass.record(
                    std::slice::from_ref(&units[1]),
                    &[input("src/shared.src")],
                    &[],
                    1
                ),
                Stored::WriteFailed
            ));
        }
        drop(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("the bundle is not current after the pass ended");
        };
        assert!(
            stored.units.contains_key(&units[1]),
            "the proof whose due write failed is written at the end"
        );
    }

    /// A guard with the given lists, in the order given, and one environment entry.
    fn guard_with(excluded: &[&str], ignore: &[&str]) -> LaunchGuard {
        LaunchGuard {
            env: BTreeMap::from([("FOO".to_owned(), "a".to_owned())]),
            env_excluded: excluded.iter().map(|name| (*name).to_owned()).collect(),
            ignore: ignore.iter().map(|pattern| (*pattern).to_owned()).collect(),
            unit_env: None,
        }
    }
    #[test]
    fn a_guard_without_unit_env_keeps_mains_bytes_and_digest() {
        let guard = guard_with(&["A", "B"], &["x", "y"]);
        let canonical = r#"{"env":{"FOO":"a"},"env_excluded":["A","B"],"ignore":["x","y"]}"#;
        assert_eq!(serde_json::to_string(&guard).unwrap(), canonical);
        assert_eq!(
            guard.digest(),
            "7420774a68461eb228cb34965250da2d0985c267a614041bcecaebc09b089fb4"
        );
    }

    #[test]
    fn a_unit_env_digest_is_order_free_and_value_bound() {
        let make = |pairs: &[(&str, &str)]| {
            let env = pairs
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect();
            pending_for_env(&["tests/a.t"], env).unit_env_digest()
        };
        assert_eq!(make(&[]), None);
        let first = make(&[("B", "two"), ("A", "one")]);
        assert_eq!(first, make(&[("A", "one"), ("B", "two")]));
        assert_ne!(first, make(&[("A", "one"), ("B", "changed")]));
        assert_ne!(make(&[("A", "bc")]), make(&[("Ab", "c")]));
    }

    #[test]
    fn start_and_record_agree_with_a_unit_env() {
        let roster = ["tests/a.t"];
        let pending = pending_for_env(&roster, BTreeMap::from([("MODE".into(), "pass".into())]));
        let mut seeded = bundle_for(pending_for(&roster), "key");
        seeded.whole = Some("p-0".into());
        let dir = seed("unit-env-guard", &seeded);
        let guard = LaunchGuard {
            unit_env: pending.unit_env_digest(),
            ..guard()
        };
        let started = pass_of(start(&dir, &pending, "key", guard));
        let at_start = started.bundle.guard_digest.clone();
        drop(started);
        let proof = whole_proof(&[]);
        record(&dir, &pending, "key", "p-1", &proof, true);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, pending.suite()) else {
            panic!("record stored no bundle");
        };
        assert_eq!(stored.whole.as_deref(), Some("p-1"));
        assert_eq!(stored.guard_digest, at_start);
        assert_eq!(stored.guard.unit_env, pending.unit_env_digest());
    }

    #[test]
    fn a_guard_digest_ignores_the_order_and_repeats_of_its_lists() {
        let canonical = guard_with(&["A", "B"], &["x", "y"]).digest();
        assert_eq!(
            guard_with(&["B", "A"], &["y", "x"]).digest(),
            canonical,
            "order"
        );
        assert_eq!(
            guard_with(&["B", "A", "A"], &["y", "x", "y"]).digest(),
            canonical,
            "repeats"
        );
        assert_ne!(
            guard_with(&["A"], &["x", "y"]).digest(),
            canonical,
            "a name still counts"
        );
        assert_ne!(
            guard_with(&["A", "B"], &["x"]).digest(),
            canonical,
            "a pattern still counts"
        );
        let other_env = LaunchGuard {
            env: BTreeMap::from([("FOO".to_owned(), "b".to_owned())]),
            ..guard_with(&["A", "B"], &["x", "y"])
        };
        assert_ne!(
            other_env.digest(),
            canonical,
            "the environment still counts"
        );
    }

    #[test]
    fn start_and_record_store_the_digest_of_the_same_guard() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        // The seeded whole digest differs from the one recorded below, so the wait for record() ends only when
        // record() has stored its bundle.
        let mut seeded = bundle_for(pending_for(&roster), "key");
        seeded.whole = Some("p-0".into());
        let dir = seed("digest-agree", &seeded);
        let excluded = ["B", "A", "A"];
        let ignore = ["y", "x"];
        let started = pass_of(start(
            &dir,
            &pending_for(&roster),
            "key",
            guard_with(&excluded, &ignore),
        ));
        let at_start = started.bundle.guard_digest.clone();
        drop(started);
        let proof = || Proof {
            created: 1,
            argv: Vec::new(),
            cwd: None,
            scope: None,
            provenance: Some(Provenance::current()),
            env: BTreeMap::from([("FOO".to_owned(), "a".to_owned())]),
            inputs: Vec::new(),
            outputs: Vec::new(),
            removed: Vec::new(),
            ignore: Some(ignore.iter().map(|pattern| (*pattern).to_owned()).collect()),
            priors: None,
            unplannable: Vec::new(),
            probes: BTreeMap::new(),
            env_excluded: excluded.iter().map(|name| (*name).to_owned()).collect(),
        };
        // record() is best effort. A busy suite lock makes it return without writing, which happens while another
        // test thread's child still holds a copy of this suite's lock descriptor (see start_after_release). So it is
        // called again until the bundle carries the digest it records, within 2 s. Only then are the digests asserted.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let stored = loop {
            record(&dir, &pending_for(&roster), "key", "p-1", &proof(), true);
            let area = Area::open(&dir, false).unwrap().unwrap();
            if let ReadBundle::Current(bundle) = read_bundle(&area, &id) {
                if bundle.whole.as_deref() == Some("p-1") {
                    break bundle;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "record() stored no bundle within 2 s, so the suite lock stayed busy"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert_eq!(stored.guard_digest, at_start, "start and record agree");
        assert_eq!(
            at_start,
            guard_with(&excluded, &ignore).digest(),
            "start stores the guard's digest"
        );
    }

    /// A whole-command proof that reads `inputs`, with the fields `record` takes from it.
    fn whole_proof(inputs: &[&str]) -> Proof {
        Proof {
            created: 1,
            argv: Vec::new(),
            cwd: Some(String::new()),
            scope: None,
            provenance: Some(Provenance::current()),
            env: BTreeMap::new(),
            inputs: inputs.iter().map(|path| input(path)).collect(),
            outputs: Vec::new(),
            removed: Vec::new(),
            ignore: Some(Vec::new()),
            priors: None,
            unplannable: Vec::new(),
            probes: BTreeMap::new(),
            env_excluded: Vec::new(),
        }
    }

    /// The suite bundle stored in `dir` under `id`, which must be current.
    fn stored(dir: &Path, id: &str) -> SuiteBundleV1 {
        let area = Area::open(dir, false).unwrap().unwrap();
        match read_bundle(&area, id) {
            ReadBundle::Current(bundle) => bundle,
            _ => panic!("the suite bundle is not current"),
        }
    }

    /// Records `proof` for `roster` with `listings`, and calls record again while a busy suite lock keeps it from
    /// writing (see `start_after_release`). It returns once the bundle carries `digest` as its whole proof, and it
    /// fails when that takes more than 2 s.
    fn record_until_stored(
        dir: &Path,
        roster: &[&str],
        listings: &[&str],
        key: &str,
        digest: &str,
        proof: &Proof,
    ) {
        let id = pending_for(roster).suite().to_owned();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut pending = pending_for(roster);
            pending.listings = listings.iter().map(|path| (*path).to_owned()).collect();
            record(dir, &pending, key, digest, proof, true);
            let area = Area::open(dir, false).unwrap().unwrap();
            if let ReadBundle::Current(bundle) = read_bundle(&area, &id) {
                if bundle.whole.as_deref() == Some(digest) {
                    return;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "record() stored no bundle within 2 s, so the suite lock stayed busy"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// C19: a record keeps the versions of the roster's units only. A unit that left the roster is no longer a claim.
    #[test]
    fn a_record_keeps_the_versions_of_its_roster_only() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("src/a")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(vec![0])]);
        bundle
            .units
            .insert("tests/gone.t".into(), vec![version(vec![0])]);
        let dir = seed("prune", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        record_until_stored(
            &dir,
            &roster,
            &[],
            "key",
            "p-whole",
            &whole_proof(&["src/a"]),
        );
        let units = stored(&dir, &id).units;
        assert_eq!(units.keys().collect::<Vec<_>>(), [&"tests/a.t".to_owned()]);
    }

    /// Spec 3.8, point ii, as amended by PR 86 review round 2: a record of a new whole proof leaves its residue unknown,
    /// even when every roster unit holds a version. The versions held may be stale, so the residue is measured by completion
    /// against valid versions instead. The residue is the proof's inputs that neither a listing nor a unit version covers.
    #[test]
    fn a_record_leaves_the_residue_unknown_when_every_unit_holds_a_version() {
        let roster = ["tests/a.t", "tests/b.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("src/shared"), input("src/own")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(delta(&[0]))]);
        bundle
            .units
            .insert("tests/b.t".into(), vec![version(delta(&[0, 1]))]);
        let dir = seed("record-residue", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        let proof = whole_proof(&[".", "tests", "src/shared", "lint", "/usr/bin/od"]);
        record_until_stored(&dir, &roster, &[".", "tests"], "key", "p-whole", &proof);
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::None));
        assert_eq!(stored_residue.count, 0);
        assert!(stored_residue.paths.is_empty());
    }

    /// A roster unit without a version leaves the residue unknown, whatever the proof reads.
    #[test]
    fn a_record_leaves_the_residue_unknown_while_a_roster_unit_has_no_version() {
        let roster = ["tests/a.t", "tests/b.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("src/shared")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(delta(&[0]))]);
        let dir = seed("record-partial", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        record_until_stored(
            &dir,
            &roster,
            &[],
            "key",
            "p-whole",
            &whole_proof(&["lint"]),
        );
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::None));
        assert_eq!(stored_residue.count, 0);
        assert!(stored_residue.paths.is_empty());
        assert_eq!(stored_residue.whole, None);
    }

    /// A residue known for the proof a record stores is kept, not measured again (spec 3.8). The seeded bundle names
    /// another whole proof, so the wait in `record_until_stored` ends only once the record has written.
    #[test]
    fn a_record_keeps_a_residue_already_known_for_its_proof() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some("p-old".into());
        bundle.table = vec![input("src/shared")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(delta(&[0]))]);
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["kept".into()],
            count: 1,
            whole: Some("p-whole".into()),
        };
        let dir = seed("record-kept", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        let proof = whole_proof(&["src/shared", "lint"]);
        record_until_stored(&dir, &roster, &[], "key", "p-whole", &proof);
        let stored_residue = stored(&dir, &id).residue;
        assert_eq!(stored_residue.paths, ["kept"]);
        assert_eq!(stored_residue.count, 1);
    }

    /// Spec 3.8, point i: a pass that stores every unit proof settles the residue of the proof its bundle names.
    #[test]
    fn a_pass_settles_the_residue_of_the_proof_its_bundle_names() {
        let roster = ["tests/a.t", "tests/b.t"];
        let proof = whole_proof(&["src/shared", "lint"]);
        let digest = proof.digest();
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(digest.clone());
        let dir = seed("pass-residue", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        let mut pass = pass_of(start_after_release(&dir, &pending, "key"));
        let _ = pass.record(&["tests/a.t".to_owned()], &[input("src/shared")], &[], 1);
        let _ = pass.record(&["tests/b.t".to_owned()], &[input("src/shared")], &[], 1);
        pass.settle_residue(&[proof], &[], false);
        drop(pass);
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::Provisional));
        assert_eq!(stored_residue.paths, ["lint"]);
        assert_eq!(stored_residue.count, 1);
        assert_eq!(stored_residue.whole, Some(digest));
    }

    /// PR 86 review round 3, switch-off parity: a clear pass settles its residue as main does, also when its run has no
    /// verdict. Only a split pass leaves the residue unknown.
    #[test]
    fn a_switch_off_pass_settles_its_residue_even_without_a_verdict() {
        let roster = ["tests/a.t", "tests/b.t"];
        let proof = whole_proof(&["src/shared", "lint"]);
        let digest = proof.digest();
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(digest.clone());
        let dir = seed("pass-no-verdict", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        let mut pass = pass_of(start_after_release(&dir, &pending, "key"));
        let _ = pass.record(&["tests/a.t".to_owned()], &[input("src/shared")], &[], 1);
        let _ = pass.record(&["tests/b.t".to_owned()], &[input("src/shared")], &[], 1);
        pass.settle_residue(&[proof], &[], true);
        drop(pass);
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::Provisional));
        assert_eq!(stored_residue.paths, ["lint"]);
    }

    /// A pass whose only write came first still stores its residue at its end: a single unit is written at once, so
    /// the residue is persisted only if settling marks the pass dirty.
    #[test]
    fn a_pass_whose_only_write_came_first_still_stores_its_residue() {
        let roster = ["tests/a.t"];
        let proof = whole_proof(&["src/shared", "lint"]);
        let digest = proof.digest();
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(digest.clone());
        let dir = seed("pass-one-write", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        let mut pass = pass_of(start_after_release(&dir, &pending, "key"));
        let _ = pass.record(&["tests/a.t".to_owned()], &[input("src/shared")], &[], 1);
        pass.settle_residue(&[proof], &[], false);
        drop(pass);
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::Provisional));
        assert_eq!(stored_residue.paths, ["lint"]);
        assert_eq!(stored_residue.whole, Some(digest));
    }

    /// A residue measured before a pass is cleared when the pass starts, and the clearing is written even when the
    /// pass stores no unit proof.
    #[test]
    fn a_pass_clears_the_residue_it_started_with() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["stale".into()],
            count: 1,
            whole: Some("p-1".into()),
        };
        let dir = seed("pass-clears", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        drop(pass_of(start_after_release(&dir, &pending, "key")));
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::None));
        assert!(stored_residue.paths.is_empty());
    }

    /// `stoop explain` names a residue only when it is known for the suite's current proof and is not empty.
    #[test]
    fn known_residue_names_only_a_known_non_empty_residue_of_the_current_proof() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["lint".into()],
            count: 1,
            whole: Some("p-1".into()),
        };
        let dir = seed("known-residue", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        assert_eq!(
            known_residue(&dir, &id, "key"),
            Some((1, vec!["lint".to_owned()]))
        );
        assert_eq!(known_residue(&dir, &id, "other"), None, "another command");
        bundle.residue.whole = Some("p-2".into());
        write_bundle(&Area::open(&dir, false).unwrap().unwrap(), &bundle).unwrap();
        assert_eq!(known_residue(&dir, &id, "key"), None, "another proof");
        bundle.residue = Residue::default();
        write_bundle(&Area::open(&dir, false).unwrap().unwrap(), &bundle).unwrap();
        assert_eq!(known_residue(&dir, &id, "key"), None, "no residue");
    }

    /// A residue that does not match its own count reads as unknown. The rest of the bundle is kept, so a bundle an
    /// older binary rewrote does not turn corrupt (spec 3.8).
    #[test]
    fn a_residue_whose_count_does_not_match_its_paths_reads_as_unknown() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        let dir = seed("residue-mismatch", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["a".into()],
            count: 2,
            whole: Some("p-1".into()),
        };
        fs::write(bundle_file(&dir, &id), serde_json::to_vec(&bundle).unwrap()).unwrap();
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(read) = read_bundle(&area, &id) else {
            panic!("a residue that does not match its count makes the bundle corrupt");
        };
        assert!(matches!(read.residue.state, ResidueState::None));
        assert!(read.residue.paths.is_empty());
        assert_eq!(read.residue.count, 0);
    }

    /// Spec 3.8, resilience: an older binary keeps a residue but writes it back without its count. The residue then
    /// reads as unknown, and the units and a disabled state are kept.
    #[test]
    fn a_residue_without_a_count_keeps_the_units_and_the_disabled_state() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.table = vec![input("src/shared")];
        bundle
            .units
            .insert("tests/a.t".into(), vec![version(delta(&[0]))]);
        bundle.state = SuiteState::Disabled {
            code: "wrote_unit".into(),
            phase: "attribution".into(),
            label: "tests/a.t wrote tests/b.t".into(),
            at: 1,
        };
        let dir = seed("residue-no-count", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        let mut json = serde_json::to_value(&bundle).unwrap();
        json["residue"] =
            serde_json::json!({"state": "provisional", "paths": ["lint"], "whole": "p-1"});
        fs::write(bundle_file(&dir, &id), serde_json::to_vec(&json).unwrap()).unwrap();
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(read) = read_bundle(&area, &id) else {
            panic!("a residue without a count makes the bundle corrupt");
        };
        assert!(matches!(read.residue.state, ResidueState::None));
        assert_eq!(read.units.len(), 1);
        assert!(matches!(read.state, SuiteState::Disabled { .. }));
    }

    /// A residue that does not match its own count is never encoded, so every bundle this code writes is consistent.
    #[test]
    fn a_residue_that_does_not_match_its_count_is_not_encoded() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["a".into()],
            count: 2,
            whole: Some("p-1".into()),
        };
        assert!(encode(&bundle).is_err());
    }

    /// Spec 3.8: explain counts every path of a residue, and a bundle stores only the first `residue::STORED` of them.
    #[test]
    fn known_residue_reports_the_count_not_the_stored_paths() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        let kept: Vec<String> = (0..residue::STORED)
            .map(|n| format!("misc/{n:02}"))
            .collect();
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: kept.clone(),
            count: 40,
            whole: Some("p-1".into()),
        };
        let dir = seed("known-count", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        assert_eq!(known_residue(&dir, &id, "key"), Some((40, kept)));
    }

    /// Spec 3.6: a disabled suite names no residue, because its proofs count for nothing.
    #[test]
    fn known_residue_names_nothing_for_a_disabled_suite() {
        let roster = ["tests/a.t"];
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.state = SuiteState::Disabled {
            code: "wrote_unit".into(),
            phase: "attribution".into(),
            label: "tests/a.t wrote tests/b.t".into(),
            at: 1,
        };
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: vec!["lint".into()],
            count: 1,
            whole: Some("p-1".into()),
        };
        let dir = seed("known-disabled", &bundle);
        let id = pending_for(&roster).suite().to_owned();
        assert_eq!(known_residue(&dir, &id, "key"), None);
    }

    /// Spec 3.8: a pass settles the residue of its bundle's whole proof. When the proofs given hold no such proof, the
    /// residue stays unknown, so no covered residue carries a digest that nothing measured.
    #[test]
    fn a_pass_settles_nothing_without_its_whole_proof() {
        let roster = ["tests/a.t", "tests/b.t"];
        let measured = whole_proof(&["src/shared", "lint"]);
        let other = whole_proof(&["src/shared", "setup.src"]);
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(measured.digest());
        let dir = seed("pass-no-whole", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        let mut pass = pass_of(start_after_release(&dir, &pending, "key"));
        let _ = pass.record(&["tests/a.t".to_owned()], &[input("src/shared")], &[], 1);
        let _ = pass.record(&["tests/b.t".to_owned()], &[input("src/shared")], &[], 1);
        pass.settle_residue(&[other], &[], false);
        drop(pass);
        let stored_residue = stored(&dir, &id).residue;
        assert!(matches!(stored_residue.state, ResidueState::None));
        assert_eq!(stored_residue.count, 0);
        assert!(stored_residue.paths.is_empty());
        assert_eq!(stored_residue.whole, None);
    }

    /// Spec 3.8: the residue is the bundle's whole proof's, wherever that proof stands among the proofs given.
    #[test]
    fn a_pass_settles_its_whole_proof_among_others() {
        let roster = ["tests/a.t", "tests/b.t"];
        let measured = whole_proof(&["src/shared", "lint"]);
        let other = whole_proof(&["src/shared", "setup.src"]);
        let digest = measured.digest();
        let mut bundle = bundle_for(pending_for(&roster), "key");
        bundle.whole = Some(digest.clone());
        let dir = seed("pass-among", &bundle);
        let pending = pending_for(&roster);
        let id = pending.suite().to_owned();
        let mut pass = pass_of(start_after_release(&dir, &pending, "key"));
        let _ = pass.record(&["tests/a.t".to_owned()], &[input("src/shared")], &[], 1);
        let _ = pass.record(&["tests/b.t".to_owned()], &[input("src/shared")], &[], 1);
        pass.settle_residue(&[other, measured], &[], false);
        drop(pass);
        let stored_residue = stored(&dir, &id).residue;
        assert_eq!(stored_residue.paths, ["lint"]);
        assert_eq!(stored_residue.count, 1);
        assert_eq!(stored_residue.whole, Some(digest));
    }
}

/// M1 (ignored, a measurement). The cost of encoding, writing (with fsync and rename) and parsing a
/// full-roster bundle at 1, 2, 4 and 8 MiB. `stored` is encoding plus writing, the cost of one stored
/// proof that spec T1 judges. Run it in release:
/// `cargo test --release --bin stoop bundle_write_cost -- --ignored --nocapture`.
#[cfg(all(test, unix))]
mod cost_tests {
    use super::*;
    use std::time::Instant;

    fn base(units: &[String], table: Vec<Input>) -> SuiteBundleV1 {
        let pending = pending(PendingSpec {
            argv: &["runner".into(), "{changed:**/*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "**/*.t",
            units: units.to_vec(),
            config: None,
            config_suite: None,
            unit_env: BTreeMap::new(),
            listings: Vec::new(),
        })
        .unwrap();
        let entries = table.len().max(2);
        let units = pending
            .roster
            .units
            .iter()
            .enumerate()
            .map(|(index, unit)| {
                let mut pair = vec![
                    ((2 * index) % entries) as u32,
                    ((2 * index + 1) % entries) as u32,
                ];
                pair.sort_unstable();
                pair.dedup();
                let version = UnitVersion {
                    created: 1,
                    exact: true,
                    source: ResultSource::Exit,
                    guard: "guard".into(),
                    unit_env: None,
                    inputs: delta(&pair),
                    outputs: Vec::new(),
                };
                (unit.clone(), vec![version])
            })
            .collect();
        SuiteBundleV1 {
            v: VERSION,
            generation: GENERATION,
            suite: pending.suite,
            provenance: Provenance::current(),
            origin: pending.origin,
            whole_key_digest: "key".into(),
            whole: Some("p-1".into()),
            policy: pending.policy,
            guard: LaunchGuard {
                env: BTreeMap::new(),
                env_excluded: Vec::new(),
                ignore: Vec::new(),
                unit_env: None,
            },
            guard_digest: "guard".into(),
            roster: pending.roster,
            whole_roster: Vec::new(),
            table,
            units,
            residue: Residue::default(),
            state: SuiteState::Ready,
        }
    }

    /// A bundle of about `target` bytes: the full roster, and a table of long paths that carries
    /// the bulk. Each entry costs the same bytes, so the count is a division.
    fn sized(target: usize) -> SuiteBundleV1 {
        let roster: Vec<String> = (0..MAX_UNITS)
            .map(|index| format!("tests/unit-{index:05}.t"))
            .collect();
        let entry = |index: usize| Input {
            path: format!("src/generated/{index:08}/{}", "d".repeat(180)),
            id: "f:00".into(),
            oid: None,
            oid_basis: None,
        };
        let one = base(&roster, vec![entry(0), entry(1)]);
        let per = serde_json::to_vec(&entry(0)).unwrap().len() + 1;
        let fixed = serde_json::to_vec(&one).unwrap().len() - 2 * per;
        // The index digits grow with the table, so the estimate runs low: trim until it fits.
        let mut count = target.saturating_sub(fixed) / per;
        loop {
            let bundle = base(&roster, (0..count.max(2)).map(entry).collect());
            let size = serde_json::to_vec(&bundle).unwrap().len();
            if size <= target || count <= 2 {
                return bundle;
            }
            count -= (size - target) / per + 1;
        }
    }

    /// The value at fraction `p` of `samples`, in milliseconds.
    fn at(samples: &mut [f64], p: f64) -> f64 {
        samples.sort_by(|a, b| a.total_cmp(b));
        samples[((samples.len() - 1) as f64 * p).round() as usize]
    }

    #[test]
    #[ignore = "a measurement: cargo test --release --bin stoop bundle_write_cost -- --ignored --nocapture"]
    fn bundle_write_cost() {
        let dir = std::env::temp_dir().join(format!("stoop-m1-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let area = Area::open(&dir, true).unwrap().unwrap();
        for mib in [1usize, 2, 4, 8] {
            let target = (mib * 1024 * 1024).min(MAX_BYTES as usize - 4096);
            let bundle = sized(target);
            let id = bundle.suite.clone();
            let (mut encode_ms, mut write_ms, mut parse_ms) = (Vec::new(), Vec::new(), Vec::new());
            let mut stored_ms = Vec::new();
            let mut size = 0;
            for _ in 0..20 {
                let started = Instant::now();
                let bytes = encode(&bundle).unwrap();
                let encoded = Instant::now();
                write_bytes(&area, &id, &bytes).unwrap();
                let written = Instant::now();
                assert!(matches!(read_bundle(&area, &id), ReadBundle::Current(_)));
                let parsed = Instant::now();
                size = bytes.len();
                encode_ms.push((encoded - started).as_secs_f64() * 1e3);
                write_ms.push((written - encoded).as_secs_f64() * 1e3);
                stored_ms.push((written - started).as_secs_f64() * 1e3);
                parse_ms.push((parsed - written).as_secs_f64() * 1e3);
            }
            println!(
                "M1 size={size} stored_p50={:.2}ms stored_p95={:.2}ms encode_p50={:.2}ms encode_p95={:.2}ms write_p50={:.2}ms write_p95={:.2}ms parse_p50={:.2}ms parse_p95={:.2}ms",
                at(&mut stored_ms, 0.5),
                at(&mut stored_ms, 0.95),
                at(&mut encode_ms, 0.5),
                at(&mut encode_ms, 0.95),
                at(&mut write_ms, 0.5),
                at(&mut write_ms, 0.95),
                at(&mut parse_ms, 0.5),
                at(&mut parse_ms, 0.95),
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

/// The second judgment under the suite lock (spec 3.10, E16). A skip that drops versions is judged again under the lock,
/// and what the lock reads is what the run takes. The suite here is one the lock reads as disabled. Its roster is
/// `tests/a.t`, and it still holds a version of `tests/gone.t`, which a skip would drop.
#[cfg(all(test, unix))]
mod settle_tests {
    use super::super::engine::{self, Decision};
    use super::*;
    use crate::run::{Lookup, Opts, RunCx};

    fn input(path: &str) -> Input {
        Input {
            path: path.into(),
            id: "f:00".into(),
            oid: None,
            oid_basis: None,
        }
    }

    fn pending_for(units: &[&str]) -> Pending {
        pending(PendingSpec {
            argv: &["runner".into(), "{changed:*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "*.t",
            units: units.iter().map(|unit| unit.to_string()).collect(),
            config: None,
            config_suite: None,
            unit_env: BTreeMap::new(),
            listings: Vec::new(),
        })
        .unwrap()
    }

    fn version(index: u32) -> UnitVersion {
        UnitVersion {
            created: 1,
            exact: true,
            source: ResultSource::Exit,
            guard: "g".into(),
            unit_env: None,
            inputs: delta(&[index]),
            outputs: Vec::new(),
        }
    }

    /// Writes the suite under `dir`, and returns its pending roster and the bundle's file.
    fn locked_disabled(dir: &Path) -> (Pending, PathBuf) {
        let _ = fs::remove_dir_all(dir);
        let pending = pending_for(&["tests/a.t"]);
        let shape = pending_for(&["tests/a.t"]);
        let bundle = SuiteBundleV1 {
            v: VERSION,
            generation: GENERATION,
            suite: shape.suite,
            provenance: Provenance::current(),
            origin: shape.origin,
            whole_key_digest: digest_text("stoop whole key v1", "key"),
            whole: Some("p-1".into()),
            policy: shape.policy,
            guard: LaunchGuard {
                env: BTreeMap::new(),
                env_excluded: Vec::new(),
                ignore: Vec::new(),
                unit_env: None,
            },
            guard_digest: "guard".into(),
            roster: shape.roster,
            whole_roster: Vec::new(),
            table: vec![input("tests/a.t"), input("tests/gone.t")],
            units: BTreeMap::from([
                ("tests/a.t".to_owned(), vec![version(0)]),
                ("tests/gone.t".to_owned(), vec![version(1)]),
            ]),
            residue: Residue::default(),
            // A concurrent run disabled the suite after the unlocked decision.
            state: SuiteState::Disabled {
                code: "disagreement".into(),
                phase: "full".into(),
                label: "concurrent".into(),
                at: 1,
            },
        };
        let area = Area::open(dir, true).unwrap().unwrap();
        write_bundle(&area, &bundle).unwrap();
        let file = dir.join("units/v1").join(bundle_name(&pending.suite));
        (pending, file)
    }

    /// Runs the second judgment for `pending` on the store at `dir`, as a skip that drops versions does.
    fn settle_at(dir: &Path, pending: &Pending) -> Option<Decision> {
        let root = dir.join("root");
        fs::create_dir_all(&root).unwrap();
        let o = Opts::default();
        let rel_cwd = String::new();
        let scope = None;
        let store = crate::proof::Store::new(dir.join("proofs"));
        let hook = None;
        let full_reason = None;
        let salt = None;
        let cx = RunCx {
            o: &o,
            cwd: &root,
            root: &root,
            rel_cwd: &rel_cwd,
            scope: &scope,
            store: &store,
            hook: &hook,
            full_reason: &full_reason,
            max_age: 0,
            bypass: false,
            explain: false,
            observe_runners: true,
            env_now: BTreeMap::new(),
            env_excluded: Vec::new(),
            salt: &salt,
            remote: None,
        };
        let lookup = Lookup {
            proofs: Vec::new(),
            hit_idx: None,
            why: String::new(),
            t0: Instant::now(),
        };
        engine::settle(&cx, pending, &lookup, dir, "key", 0)
    }

    /// m39: a locked view that declines writes nothing, so the second judgment is what decides the drop.
    #[test]
    fn settle_writes_nothing_when_the_locked_view_declines() {
        let dir = std::env::temp_dir().join(format!("stoop-settle-writes-{}", std::process::id()));
        let (pending, file) = locked_disabled(&dir);
        let before = fs::read(&file).unwrap();
        settle_at(&dir, &pending);
        assert_eq!(
            fs::read(&file).unwrap(),
            before,
            "a declined settle writes nothing"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The sibling of m39: a declined settle returns the decision the lock reads, and the skip does not stand.
    #[test]
    fn settle_returns_the_decision_the_locked_view_reads() {
        let dir = std::env::temp_dir().join(format!("stoop-settle-returns-{}", std::process::id()));
        let (pending, _) = locked_disabled(&dir);
        assert!(
            matches!(settle_at(&dir, &pending), Some(Decision::Disabled(_))),
            "the locked decision replaces the skip"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(all(test, unix))]
mod keep_tests {
    use super::*;

    fn input(path: &str) -> Input {
        Input {
            path: path.into(),
            id: "f:00".into(),
            oid: None,
            oid_basis: None,
        }
    }

    fn guard() -> LaunchGuard {
        LaunchGuard {
            env: BTreeMap::new(),
            env_excluded: Vec::new(),
            ignore: Vec::new(),
            unit_env: None,
        }
    }

    fn pending_for(units: &[&str]) -> Pending {
        pending(PendingSpec {
            argv: &["runner".into(), "{changed:*.t}".into()],
            cwd: "",
            scope: None,
            label: None,
            source: "filter",
            filter: "*.t",
            units: units.iter().map(|unit| unit.to_string()).collect(),
            config: None,
            config_suite: None,
            unit_env: BTreeMap::new(),
            listings: Vec::new(),
        })
        .unwrap()
    }

    fn version(inputs: Vec<u32>) -> UnitVersion {
        UnitVersion {
            created: 1,
            exact: true,
            source: ResultSource::Exit,
            guard: "guard".into(),
            unit_env: None,
            inputs,
            outputs: Vec::new(),
        }
    }

    /// A bundle that `keep` accepts for `pending` under `key`, holding `units` over `table`.
    fn bundle_for(
        pending: Pending,
        key: &str,
        table: Vec<Input>,
        units: BTreeMap<String, Vec<UnitVersion>>,
    ) -> SuiteBundleV1 {
        SuiteBundleV1 {
            v: VERSION,
            generation: GENERATION,
            suite: pending.suite,
            provenance: Provenance::current(),
            origin: pending.origin,
            whole_key_digest: digest_text("stoop whole key v1", key),
            whole: Some("p-1".into()),
            policy: pending.policy,
            guard: guard(),
            guard_digest: "guard".into(),
            roster: pending.roster,
            whole_roster: Vec::new(),
            table,
            units,
            residue: Residue::default(),
            state: SuiteState::Ready,
        }
    }

    /// Writes `bundle` into a new store and returns the store's directory.
    fn seed(name: &str, bundle: &SuiteBundleV1) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stoop-keep-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let area = Area::open(&dir, true).unwrap().unwrap();
        write_bundle(&area, bundle).unwrap();
        dir
    }

    /// The pass that `keep` gives for `pending`, which keeps its bundle's versions.
    fn kept(dir: &Path, pending: &Pending) -> Pass {
        match keep(dir, pending, "key", guard(), |_| Ok::<(), ()>(())) {
            Kept::Locked(pass, ()) => pass,
            Kept::Busy => panic!("the suite lock was busy"),
            Kept::Unavailable => panic!("the bundle is not kept"),
            Kept::Declined(()) => panic!("the decision was declined"),
        }
    }

    fn paths(entries: &[Input]) -> Vec<String> {
        entries.iter().map(|entry| entry.path.clone()).collect()
    }

    fn record_group(
        pass: &mut Pass,
        members: &[String],
        inputs: &[Input],
        outputs: &[Input],
    ) -> Stored {
        pass.record(members, inputs, outputs, 2)
    }

    fn group_fixture(name: &str, first_reads: &str, second_reads: &str) -> (PathBuf, Pass) {
        let units = ["tests/a.t", "tests/b.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        held.insert("tests/b.t".to_owned(), vec![version(vec![1])]);
        let table = vec![input(first_reads), input(second_reads)];
        let mut bundle = bundle_for(pending_for(&units), "key", table, held);
        bundle.residue = Residue {
            state: ResidueState::Confirmed,
            paths: Vec::new(),
            count: 0,
            whole: Some("p-1".into()),
        };
        let dir = seed(name, &bundle);
        let pass = kept(&dir, &pending_for(&units));
        (dir, pass)
    }

    fn group_members() -> [String; 2] {
        ["tests/a.t".to_owned(), "tests/b.t".to_owned()]
    }

    #[test]
    fn owned_entries_name_only_exact_versions() {
        let (dir, mut pass) = group_fixture("owned-entries", "src/old-a", "src/old-b");
        let mut directory = input("shared-dir");
        directory.id = "d".into();
        let mut listing = input("shared-listing");
        listing.id = "dl:listing".into();
        assert!(matches!(
            record_group(
                &mut pass,
                &group_members(),
                &[input("src/group"), directory, listing],
                &[input("out/group")],
            ),
            Stored::Stored
        ));
        assert_eq!(pass.held().len(), 2);
        assert!(pass.held_owned().is_empty());

        assert!(matches!(
            pass.record(
                &["tests/a.t".to_owned()],
                &[input("src/owned")],
                &[input("out/owned")],
                3,
            ),
            Stored::Stored
        ));
        let inexact = pass.bundle.units["tests/b.t"][0].clone();
        pass.bundle
            .units
            .get_mut("tests/a.t")
            .unwrap()
            .push(inexact);
        let owned = pass.held_owned();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].0, "tests/a.t");
        assert_eq!(paths(&owned[0].1), ["src/owned"]);
        assert_eq!(paths(&owned[0].2), ["out/owned"]);
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_two_member_record_stores_identical_inexact_versions_in_one_write() {
        let (dir, mut pass) = group_fixture("group-write", "src/old-a", "src/old-b");
        let group_input = input("src/group");
        let output = input("out/group");
        assert!(matches!(
            record_group(&mut pass, &group_members(), &[group_input], &[output]),
            Stored::Stored
        ));
        assert_eq!(pass.writes, 1, "the group is stored in one write");
        let a = &pass.bundle.units["tests/a.t"][0];
        let b = &pass.bundle.units["tests/b.t"][0];
        assert!(!a.exact && !b.exact, "a grouped version is inexact");
        assert_eq!(
            serde_json::to_vec(a).unwrap(),
            serde_json::to_vec(b).unwrap()
        );
        let file = dir.join("units/v1").join(bundle_name(&pass.bundle.suite));
        let disk: SuiteBundleV1 = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
        assert_eq!(disk.units.len(), 2);
        assert!(!disk.units["tests/a.t"][0].exact && !disk.units["tests/b.t"][0].exact);
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refused_two_member_record_keeps_every_member_s_old_version() {
        let (dir, mut pass) = group_fixture("group-refused", "src/old-a", "src/old-b");
        let before = serde_json::to_vec(&pass.bundle).unwrap();
        let file = dir.join("units/v1").join(bundle_name(&pass.bundle.suite));
        let disk_before = fs::read(&file).unwrap();
        pass.budget = 1;
        assert!(matches!(
            record_group(&mut pass, &group_members(), &[input("src/group")], &[]),
            Stored::OverBudget
        ));
        assert_eq!(serde_json::to_vec(&pass.bundle).unwrap(), before);
        assert_eq!(fs::read(&file).unwrap(), disk_before);
        assert!(!pass.residue_lost);
        assert!(pass.lost_paths.is_empty());
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_refused_group_in_a_clear_pass_restores_prior_members_and_table() {
        let units = ["tests/a.t", "tests/b.t"];
        let dir = seed(
            "group-refused-clear",
            &bundle_for(pending_for(&units), "key", Vec::new(), BTreeMap::new()),
        );
        let pending = pending_for(&units);
        let mut pass = match start(&dir, &pending, "key", guard()) {
            Start::Pass(pass) => pass,
            _ => panic!("the clear pass did not start"),
        };
        assert!(matches!(
            pass.record(&["tests/a.t".to_owned()], &[input("src/old")], &[], 1),
            Stored::Stored
        ));
        let before = serde_json::to_vec(&pass.bundle).unwrap();
        pass.budget = 1;
        assert!(matches!(
            record_group(&mut pass, &group_members(), &[input("src/group")], &[]),
            Stored::OverBudget
        ));
        assert_eq!(serde_json::to_vec(&pass.bundle).unwrap(), before);
        assert_eq!(paths(&pass.held_of("tests/a.t").0), ["src/old"]);
        assert!(pass.held_of("tests/b.t").0.is_empty());
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_two_member_record_loses_no_reader_another_member_keeps() {
        let (dir, mut pass) = group_fixture("group-keeps-reader", "src/shared", "src/shared");
        assert!(matches!(
            record_group(&mut pass, &group_members(), &[input("src/shared")], &[]),
            Stored::Stored
        ));
        assert!(!pass.residue_lost);
        assert!(pass.lost_paths.is_empty());
        assert!(matches!(pass.bundle.residue.state, ResidueState::Confirmed));
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    fn assert_group_loses_last_reader(name: &str, first: &str, second: &str) {
        let (dir, mut pass) = group_fixture(name, first, second);
        assert!(matches!(
            record_group(&mut pass, &group_members(), &[input("src/group")], &[]),
            Stored::Stored
        ));
        assert!(pass.residue_lost);
        assert!(pass.lost_paths.contains("src/last-reader"));
        assert!(matches!(pass.bundle.residue.state, ResidueState::None));
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_two_member_record_marks_a_path_lost_when_its_last_reader_is_a_replaced_member() {
        assert_group_loses_last_reader("group-lost-first", "src/last-reader", "src/other");
    }

    #[test]
    fn a_two_member_record_loses_the_second_members_last_reader() {
        assert_group_loses_last_reader("group-lost-second", "src/other", "src/last-reader");
    }

    #[test]
    fn a_one_member_record_writes_the_bytes_it_wrote_before() {
        let (dir, mut pass) = group_fixture("single-record-bytes", "src/old-a", "src/old-b");
        assert!(matches!(
            pass.record(&["tests/a.t".to_owned()], &[input("src/old-a")], &[], 2),
            Stored::Stored
        ));
        let version = &pass.bundle.units["tests/a.t"][0];
        let expected = format!(
            "{{\"created\":2,\"exact\":true,\"source\":{{\"kind\":\"exit\"}},\"guard\":\"{}\",\"inputs\":[0],\"outputs\":[]}}",
            pass.bundle.guard_digest
        );
        assert_eq!(serde_json::to_string(version).unwrap(), expected);
        drop(pass);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_path_whose_last_content_reader_turns_stat_only_is_lost() {
        let content = BTreeMap::from([("src/a.src".to_owned(), true)]);
        let stat_only = BTreeMap::from([("src/a.src".to_owned(), false)]);
        let gone = BTreeMap::new();
        assert!(
            lost_reader(&content, &stat_only),
            "a content read turned stat-only is a loss"
        );
        assert!(
            lost_reader(&content, &gone),
            "a path with no reader left is a loss"
        );
        assert!(
            !lost_reader(&content, &content),
            "a path still read by content is not lost"
        );
        assert!(
            !lost_reader(&stat_only, &stat_only),
            "a stat-only path stays stat-only"
        );
        assert!(
            !lost_reader(&BTreeMap::new(), &gone),
            "no removed reader, no loss"
        );
    }

    #[test]
    fn a_path_another_unit_still_reads_is_not_lost() {
        let table = vec![input("src/shared.src")];
        let one = version(vec![0]);
        let other = version(vec![0]);
        let removed = bundle_readers(&table, std::iter::once(&one));
        let now = bundle_readers(&table, [&one, &other].into_iter());
        assert!(
            !lost_reader(&removed, &now),
            "the other unit still reads the path"
        );
    }

    #[test]
    fn an_inexact_version_still_counts_as_a_reader_for_loss_bookkeeping() {
        let table = vec![input("src/shared.src")];
        let exact = version(vec![0]);
        let mut inexact = version(vec![0]);
        inexact.exact = false;
        let removed = bundle_readers(&table, std::iter::once(&exact));
        let now = bundle_readers(&table, std::iter::once(&inexact));
        assert!(!lost_reader(&removed, &now));
    }

    #[test]
    fn only_content_ids_read_content() {
        assert!(content_id("f:1"));
        assert!(content_id("x:1"));
        assert!(content_id("dl:1"));
        assert!(content_id("a"));
        assert!(content_id("l:target"));
        assert!(content_id("u"));
        assert!(!content_id("d"));
        assert!(!content_id("s:1"));
        assert!(!content_id("stat:1"));
    }

    #[test]
    fn a_confirm_for_another_whole_proof_is_declined() {
        let units = ["tests/a.t", "tests/b.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        held.insert("tests/b.t".to_owned(), vec![version(vec![0])]);
        let mut bundle = bundle_for(pending_for(&units), "key", vec![input("src/a.src")], held);
        bundle.whole = Some("p-1".to_owned());
        let dir = seed("confirm-other-proof", &bundle);
        let pending = pending_for(&units);
        let outcome = confirm(&dir, &pending, "key", "p-2", &[input("src/a.src")], |_| {
            true
        });
        assert!(
            matches!(outcome, Settled::Declined),
            "a bundle that holds another proof declines"
        );
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, pending.suite()) else {
            panic!("the bundle is current")
        };
        assert!(
            matches!(stored.residue.state, ResidueState::None),
            "the residue is as it was"
        );
    }

    #[test]
    fn a_kept_pass_replaces_only_the_unit_it_proves_and_compacts_the_table() {
        let units = ["tests/a.t", "tests/b.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        held.insert("tests/b.t".to_owned(), vec![version(vec![1])]);
        let table = vec![input("src/a.src"), input("src/b.src")];
        let dir = seed(
            "replace",
            &bundle_for(pending_for(&units), "key", table, held),
        );
        let mut pass = kept(&dir, &pending_for(&units));
        assert!(matches!(
            pass.record(&["tests/a.t".to_owned()], &[input("src/c.src")], &[], 2),
            Stored::Stored
        ));
        assert_eq!(paths(&pass.held_of("tests/a.t").0), ["src/c.src"]);
        assert_eq!(paths(&pass.held_of("tests/b.t").0), ["src/b.src"]);
        assert_eq!(
            pass.bundle.table.len(),
            2,
            "the replaced proof's entry is compacted away"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_refused_record_keeps_the_version_the_unit_held() {
        let units = ["tests/a.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        let table = vec![input("src/a.src")];
        let dir = seed(
            "refused",
            &bundle_for(pending_for(&units), "key", table, held),
        );
        let mut pass = kept(&dir, &pending_for(&units));
        pass.budget = 1;
        assert!(matches!(
            pass.record(&["tests/a.t".to_owned()], &[input("src/c.src")], &[], 2),
            Stored::OverBudget
        ));
        assert_eq!(paths(&pass.held_of("tests/a.t").0), ["src/a.src"]);
        assert_eq!(
            pass.bundle.table.len(),
            1,
            "the refused proof's entry is gone"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn w20_shape_a_subset_that_drops_the_last_readers_loses_the_residue() {
        let units = ["tests/a.t", "tests/b.t", "tests/c.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        held.insert("tests/b.t".to_owned(), vec![version(vec![0])]);
        // c reads src/c.src, the runner-only test and its flag as data.
        held.insert("tests/c.t".to_owned(), vec![version(vec![0, 1, 1])]);
        let table = vec![
            input("src/c.src"),
            input("tests/z.u"),
            input("tests/z.flag"),
        ];
        let mut bundle = bundle_for(pending_for(&units), "key", table, held);
        // The residue is known and empty for the stored whole proof, as after a completion.
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: Vec::new(),
            count: 0,
            whole: Some("p-1".to_owned()),
        };
        let dir = seed("w20-shape", &bundle);
        let pending = pending_for(&units);
        let mut pass = kept(&dir, &pending);
        assert!(matches!(
            pass.record(&["tests/c.t".to_owned()], &[input("src/c.src")], &[], 2),
            Stored::Stored
        ));
        assert!(
            pass.residue_lost,
            "dropping the last readers of tests/z.u and tests/z.flag loses the residue"
        );
        drop(pass);
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, pending.suite()) else {
            panic!("the bundle is current")
        };
        assert!(
            matches!(stored.residue.state, ResidueState::None),
            "the residue on disk is unknown: the write must carry the reset, not the residue measured before it"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_kept_pass_drops_the_versions_of_units_that_left_the_roster() {
        let all = ["tests/a.t", "tests/gone.t"];
        let mut held = BTreeMap::new();
        held.insert("tests/a.t".to_owned(), vec![version(vec![0])]);
        held.insert("tests/gone.t".to_owned(), vec![version(vec![1])]);
        let table = vec![input("src/a.src"), input("src/gone.src")];
        let dir = seed("prune", &bundle_for(pending_for(&all), "key", table, held));
        let pass = kept(&dir, &pending_for(&["tests/a.t"]));
        assert!(!pass.bundle.units.contains_key("tests/gone.t"));
        assert_eq!(
            pass.bundle.table.len(),
            1,
            "the departed unit's entry is compacted away"
        );
        assert!(
            pass.dirty,
            "the pruned bundle is written when the pass ends"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A path that a dropped unit or a rewrite of this pass stops reading may still be read with content by the final
    /// versions. Each test below settles the residue against `proof`, and the bundle names the proof's digest.
    #[test]
    fn a_path_a_later_write_of_the_pass_reads_again_keeps_the_residue() {
        let units = ["tests/m5.t", "tests/m6.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/m5.t".to_owned(), vec![version(vec![0])]),
            ("tests/m6.t".to_owned(), vec![version(Vec::new())]),
        ]);
        let bundle = known_bundle(&units, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("reread", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        // m5 stops reading the grep binary, and m6 reads it again later in the same pass.
        assert!(matches!(
            pass.record(&["tests/m5.t".to_owned()], &[], &[], 2),
            Stored::Stored
        ));
        assert!(matches!(
            pass.record(
                &["tests/m6.t".to_owned()],
                &[input("/usr/bin/grep")],
                &[],
                3
            ),
            Stored::Stored
        ));
        pass.settle_residue(&[proof], &[], false);
        assert!(
            !matches!(pass.bundle.residue.state, ResidueState::None),
            "the final versions read the path with content, so the residue stays known"
        );
        assert_eq!(pass.bundle.residue.count, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// PR 86 review round 3: a split run that has no verdict (exit 125) leaves the residue unknown. Its stored versions
    /// may read a path by stat only, and a residue measured from them would let a later run skip on that proof.
    #[test]
    fn a_split_run_without_a_verdict_leaves_the_residue_unknown() {
        let units = ["tests/m5.t", "tests/m6.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/m5.t".to_owned(), vec![version(vec![0])]),
            ("tests/m6.t".to_owned(), vec![version(vec![0])]),
        ]);
        let bundle = known_bundle(&units, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("no-verdict", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        assert!(!matches!(pass.bundle.residue.state, ResidueState::None));
        pass.settle_residue(&[proof], &[], true);
        assert!(
            matches!(pass.bundle.residue.state, ResidueState::None),
            "a run with no verdict leaves the residue unknown"
        );
        assert!(
            pass.dirty,
            "the unknown residue is written when the pass ends"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A later write that reads the path only as a stat is no content reader, so the path stays lost.
    #[test]
    fn a_path_a_later_write_reads_only_as_a_stat_stays_lost() {
        let units = ["tests/m5.t", "tests/m6.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/m5.t".to_owned(), vec![version(vec![0])]),
            ("tests/m6.t".to_owned(), vec![version(Vec::new())]),
        ]);
        let bundle = known_bundle(&units, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("stat-reread", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        assert!(matches!(
            pass.record(&["tests/m5.t".to_owned()], &[], &[], 2),
            Stored::Stored
        ));
        let stat = Input {
            path: "/usr/bin/grep".into(),
            id: "s:00".into(),
            oid: None,
            oid_basis: None,
        };
        assert!(matches!(
            pass.record(&["tests/m6.t".to_owned()], &[stat], &[], 3),
            Stored::Stored
        ));
        pass.settle_residue(&[proof], &[], false);
        assert!(
            matches!(pass.bundle.residue.state, ResidueState::None),
            "a stat-only read does not give the path a content reader"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A loss that no later write of the pass heals keeps the residue unknown.
    #[test]
    fn a_path_lost_by_the_passes_last_write_keeps_the_residue_unknown() {
        let units = ["tests/m5.t", "tests/m6.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/m5.t".to_owned(), vec![version(vec![0])]),
            ("tests/m6.t".to_owned(), vec![version(Vec::new())]),
        ]);
        let bundle = known_bundle(&units, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("last-write", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        assert!(matches!(
            pass.record(&["tests/m5.t".to_owned()], &[], &[], 2),
            Stored::Stored
        ));
        pass.settle_residue(&[proof], &[], false);
        assert!(
            matches!(pass.bundle.residue.state, ResidueState::None),
            "nothing reads the path after the last write"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A version that a kept pass drops, because its unit left the roster, can hold the last reader of a path. That loss
    /// keeps the residue unknown, as a write's loss does.
    #[test]
    fn a_path_lost_by_a_dropped_version_keeps_the_residue_unknown() {
        let roster = ["tests/a.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/a.t".to_owned(), vec![version(Vec::new())]),
            ("tests/gone.t".to_owned(), vec![version(vec![0])]),
        ]);
        let bundle = known_bundle(&roster, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("dropped", &bundle);
        let mut pass = kept(&dir, &pending_for(&roster));
        pass.settle_residue(&[proof], &[], false);
        assert!(
            matches!(pass.bundle.residue.state, ResidueState::None),
            "the dropped version was the last reader of the path"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// A path that the rewritten unit stops reading, and that a unit the pass does not rewrite still reads with content,
    /// is not lost: the residue stays known.
    #[test]
    fn a_path_read_by_an_unrewritten_unit_is_not_lost_at_the_pass() {
        let units = ["tests/m5.t", "tests/m6.t"];
        let proof = proof_of(&["/usr/bin/grep"]);
        let held = BTreeMap::from([
            ("tests/m5.t".to_owned(), vec![version(vec![0])]),
            ("tests/m6.t".to_owned(), vec![version(vec![0])]),
        ]);
        let bundle = known_bundle(&units, vec![input("/usr/bin/grep")], held, &proof);
        let dir = seed("still-read", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        assert!(matches!(
            pass.record(&["tests/m5.t".to_owned()], &[], &[], 2),
            Stored::Stored
        ));
        assert!(
            matches!(pass.bundle.residue.state, ResidueState::Provisional),
            "m6 still reads the path, so the record does not reset the residue"
        );
        pass.settle_residue(&[proof], &[], false);
        assert!(!matches!(pass.bundle.residue.state, ResidueState::None));
        assert_eq!(pass.bundle.residue.count, 0);
        let _ = fs::remove_dir_all(&dir);
    }

    /// A whole-command proof that reads `inputs`, for settling a pass's residue.
    fn proof_of(inputs: &[&str]) -> Proof {
        Proof {
            created: 1,
            argv: Vec::new(),
            cwd: Some(String::new()),
            scope: None,
            provenance: Some(Provenance::current()),
            env: BTreeMap::new(),
            inputs: inputs.iter().map(|path| input(path)).collect(),
            outputs: Vec::new(),
            removed: Vec::new(),
            ignore: Some(Vec::new()),
            priors: None,
            unplannable: Vec::new(),
            probes: BTreeMap::new(),
            env_excluded: Vec::new(),
        }
    }

    /// A stored bundle for `units` over `table` whose residue is known and empty for `proof`.
    fn known_bundle(
        units: &[&str],
        table: Vec<Input>,
        held: BTreeMap<String, Vec<UnitVersion>>,
        proof: &Proof,
    ) -> SuiteBundleV1 {
        let mut bundle = bundle_for(pending_for(units), "key", table, held);
        bundle.whole = Some(proof.digest());
        bundle.residue = Residue {
            state: ResidueState::Provisional,
            paths: Vec::new(),
            count: 0,
            whole: Some(proof.digest()),
        };
        bundle
    }

    #[test]
    fn a_kept_pass_stores_the_subset_phase_when_it_is_disabled() {
        let units = ["tests/a.t"];
        let bundle = bundle_for(pending_for(&units), "key", Vec::new(), BTreeMap::new());
        let dir = seed("phase", &bundle);
        let mut pass = kept(&dir, &pending_for(&units));
        pass.disable("wrote_input", "tests/a.t wrote src/c.src")
            .unwrap();
        match &pass.bundle.state {
            SuiteState::Disabled { phase, .. } => assert_eq!(phase, "subset"),
            SuiteState::Ready => panic!("the suite is not disabled"),
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
