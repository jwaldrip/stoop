//! Bounded, local suite rosters. A bundle does not itself confer a proof hit.

use crate::input::Input;
use crate::proof::Proof;
#[cfg(not(unix))]
use crate::sys::Private;
use crate::trace::Provenance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
#[cfg(not(unix))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const VERSION: u32 = 1;
const GENERATION: u32 = 1;
const MAX_UNITS: usize = 4096;
const MAX_UNIT_BYTES: usize = 4096;
const MAX_VERSIONS: usize = 8;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// `forget --units` removes the lock file, so a process waiting on the old file can take a lock
/// that no other process contends for. A lock is trusted only while it is still the named entry.
const LOCK_ATTEMPTS: usize = 3;
/// The least time between two writes of a pass's bundle. A killed pass loses at most this much of
/// its proofs, and the units whose proofs are lost are attributed again on a later run.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct Origin {
    kind: String,
    cwd: String,
    scope: Option<String>,
    /// A digest of the argument words and the label, bound to the suite ID. The words themselves
    /// are never stored: a secret passed as an argument must not reach the suite store.
    invocation: String,
}

#[derive(Serialize, Deserialize)]
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
}

#[derive(Serialize, Deserialize)]
struct UnitVersion {
    created: u64,
    exact: bool,
    source: ResultSource,
    guard: String,
    inputs: Vec<u32>,
    outputs: Vec<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResultSource {
    Exit,
    Records,
    Receipt { decoder: String },
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResidueState {
    None,
    Provisional,
    Confirmed,
}

#[derive(Serialize, Deserialize)]
struct Residue {
    state: ResidueState,
    paths: Vec<String>,
    whole: Option<String>,
}

impl Default for Residue {
    fn default() -> Self {
        Self {
            state: ResidueState::None,
            paths: Vec::new(),
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
    table: Vec<Input>,
    #[serde(deserialize_with = "unique_map")]
    units: BTreeMap<String, Vec<UnitVersion>>,
    residue: Residue,
    state: SuiteState,
    /// The digest of the roster that an attribution pass found no unit evidence for. While it is
    /// the current roster, no pass starts, so a suite whose runner gives no evidence keeps the full
    /// form until its roster changes or `forget --units` removes the bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    no_evidence: Option<String>,
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
}

impl Pending {
    pub(crate) fn suite(&self) -> &str {
        &self.suite
    }

    pub(crate) fn units(&self) -> &[String] {
        &self.roster.units
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

fn suite_id(argv: &[OsString], cwd: &str, scope: Option<&str>, label: Option<&str>) -> String {
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

/// A digest of a roster's units, in order. It names the roster that a pass found no evidence for.
fn roster_digest(roster: &Roster) -> String {
    let mut hash = blake3::Hasher::new_derive_key("stoop roster units v1");
    for unit in &roster.units {
        field(&mut hash, unit.as_bytes());
    }
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
}

/// The caller supplies the catalog rebuilt for this invocation, never its listing inputs.
pub(crate) fn pending(spec: PendingSpec<'_>) -> Option<Pending> {
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
    } = spec;
    if units.is_empty() || units.len() > MAX_UNITS || !valid_roster(&units) {
        return None;
    }
    if argv.iter().any(|word| word.to_str().is_none()) {
        return None;
    }
    let mut hash = blake3::Hasher::new_derive_key("stoop suite policy v1");
    field(&mut hash, source.as_bytes());
    field(&mut hash, filter.as_bytes());
    field(&mut hash, config_suite.unwrap_or("").as_bytes());
    field(&mut hash, config.unwrap_or_default());
    Some(Pending {
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
        && bundle.units.len() <= MAX_UNITS
        && bundle
            .units
            .iter()
            .all(|(unit, versions)| valid_unit(unit) && versions.len() <= MAX_VERSIONS)
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

/// The suite directory `<store>/units/v1`. Every name below it is opened, renamed and removed
/// relative to this descriptor without following links, so a link in the suite path refuses the
/// access instead of leading it outside the store. The configured store directory itself may be a
/// link, because the user chose it.
pub(crate) struct Area {
    #[cfg(unix)]
    dir: std::os::fd::OwnedFd,
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
            Ok(Some(Area { dir }))
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
    let header: Header = match serde_json::from_slice(&bytes) {
        Ok(header) => header,
        Err(_) => return ReadBundle::Corrupt,
    };
    if header.v != u64::from(VERSION)
        || header
            .generation
            .as_ref()
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|generation| generation > u64::from(GENERATION))
    {
        return ReadBundle::OtherVersion;
    }
    match serde_json::from_slice::<SuiteBundleV1>(&bytes) {
        Ok(bundle) if valid_bundle(&bundle, id) && valid_versions(&bundle) => {
            ReadBundle::Current(bundle)
        }
        _ => ReadBundle::Corrupt,
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

fn clear_temps(area: &Area, id: &str) {
    let prefix = format!(".{id}-");
    for name in area.names().unwrap_or_default() {
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            let _ = area.unlink(&name);
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

/// Best effort only: no diagnostic or decision changes when a bundle cannot be saved.
pub(crate) fn record(store: &Path, pending: Pending, key: &str, digest: &str, proof: Proof) {
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
    let Some(provenance) = proof.provenance else {
        return;
    };
    let guard = LaunchGuard {
        env: proof.env,
        env_excluded: proof.env_excluded,
        ignore: proof.ignore.unwrap_or_default(),
    };
    let Ok(bytes) = serde_json::to_vec(&guard) else {
        return;
    };
    let guard_digest = blake3::hash(&bytes).to_hex().to_string();
    // A marker survives a full run of the same roster: the run stores a legacy proof, and the
    // roster is still silent.
    let no_evidence = previous
        .as_ref()
        .filter(|old| old.generation == GENERATION && old.provenance == provenance)
        .and_then(|old| old.no_evidence.clone())
        .filter(|digest| *digest == roster_digest(&pending.roster));
    let (table, units, residue, state) = match previous {
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
    let bundle = SuiteBundleV1 {
        v: VERSION,
        generation: GENERATION,
        suite: pending.suite,
        provenance,
        origin: pending.origin,
        whole_key_digest: digest_text("stoop whole key v1", key),
        whole: Some(digest.into()),
        policy: pending.policy,
        guard,
        guard_digest,
        roster: pending.roster,
        table,
        units,
        residue,
        state,
        no_evidence,
    };
    let _ = write_bundle(&area, &bundle);
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

/// One attribution pass. It holds the suite lock until it is dropped, so no other stoop changes
/// the suite meanwhile, and it rewrites the bundle after each stored proof.
pub(crate) struct Pass {
    area: Area,
    _lock: File,
    bundle: SuiteBundleV1,
    /// The table index of each input, by its serialized form, so each input is stored once.
    interned: BTreeMap<String, u32>,
    budget: u64,
    /// When the bundle was last written, and whether a proof is held that no write has stored yet.
    last_write: Option<Instant>,
    dirty: bool,
    #[cfg(test)]
    writes: usize,
}

impl Pass {
    /// Keeps one unit's proof as its only version, and writes the bundle with it. A version that
    /// would exceed the budget is dropped with the table entries it added.
    pub(crate) fn record(
        &mut self,
        unit: &str,
        inputs: &[Input],
        outputs: &[Input],
        created: u64,
    ) -> Stored {
        let mark = self.bundle.table.len();
        let inputs = self.indices(inputs);
        let outputs = self.indices(outputs);
        let version = UnitVersion {
            created,
            exact: true,
            source: ResultSource::Exit,
            guard: self.bundle.guard_digest.clone(),
            inputs: delta(&inputs),
            outputs: delta(&outputs),
        };
        self.bundle.units.insert(unit.to_owned(), vec![version]);
        let Ok(bytes) = serde_json::to_vec(&self.bundle) else {
            self.discard(unit, mark);
            return Stored::WriteFailed;
        };
        if bytes.len() as u64 > self.budget {
            self.discard(unit, mark);
            return Stored::OverBudget;
        }
        if !valid_bundle(&self.bundle, &self.bundle.suite) {
            self.discard(unit, mark);
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

    /// Drops what `record` added for `unit`, so memory matches what is stored.
    fn discard(&mut self, unit: &str, mark: usize) {
        self.bundle.units.remove(unit);
        self.bundle.table.truncate(mark);
        self.interned.retain(|_, index| (*index as usize) < mark);
    }
}

impl Drop for Pass {
    /// Writes what the pass still holds when it ends, however it ends: the proofs that no write has
    /// stored yet, or, when it stored none, the marker for its roster. A write that fails is ignored,
    /// as `record` ignores one.
    fn drop(&mut self) {
        if !self.dirty && !self.bundle.units.is_empty() {
            return;
        }
        self.bundle.no_evidence = self
            .bundle
            .units
            .is_empty()
            .then(|| roster_digest(&self.bundle.roster));
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
    if ready(&area, pending, &digest).is_none() {
        return Start::No;
    }
    let held = match lock_with(&area, &pending.suite, after_open) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Start::Busy,
        Err(_) => return Start::No,
    };
    clear_temps(&area, &pending.suite);
    let Some(mut bundle) = ready(&area, pending, &digest) else {
        return Start::No;
    };
    if !area.writable(&pending.suite) {
        return Start::No;
    }
    let Ok(bytes) = serde_json::to_vec(&guard) else {
        return Start::No;
    };
    bundle.guard_digest = blake3::hash(&bytes).to_hex().to_string();
    bundle.guard = guard;
    bundle.policy.clone_from(&pending.policy);
    bundle.roster = Roster {
        source: pending.roster.source.clone(),
        units: pending.roster.units.clone(),
    };
    bundle.units.clear();
    bundle.table.clear();
    bundle.no_evidence = None;
    Start::Pass(Pass {
        area,
        _lock: held,
        bundle,
        interned: BTreeMap::new(),
        budget: MAX_BYTES,
        last_write: None,
        dirty: false,
        #[cfg(test)]
        writes: 0,
    })
}

/// The bundle as a pass needs it: current, ready, recorded for this command, with no unit proof
/// for any unit of the roster, and not silent for this roster.
fn ready(area: &Area, pending: &Pending, digest: &str) -> Option<SuiteBundleV1> {
    let ReadBundle::Current(bundle) = read_bundle(area, &pending.suite) else {
        return None;
    };
    let proven = pending.roster.units.iter().any(|unit| {
        bundle
            .units
            .get(unit)
            .is_some_and(|versions| !versions.is_empty())
    });
    let silent = bundle.no_evidence.as_deref() == Some(roster_digest(&pending.roster).as_str());
    (bundle.generation == GENERATION
        && bundle.provenance == Provenance::current()
        && matches!(bundle.state, SuiteState::Ready)
        && bundle.whole.is_some()
        && bundle.whole_key_digest == digest
        && !proven
        && !silent)
        .then_some(bundle)
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
            },
            guard_digest: "guard".into(),
            roster: pending.roster,
            table: Vec::new(),
            units: BTreeMap::new(),
            residue: Residue::default(),
            state: SuiteState::Ready,
            no_evidence: None,
        };
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let decoded: SuiteBundleV1 = serde_json::from_slice(&bytes).unwrap();
        assert!(valid_bundle(&decoded, &bundle.suite));
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["roster"].get("inputs").is_none());
        let mut bounded = decoded;
        let versions = (0..=MAX_VERSIONS)
            .map(|_| UnitVersion {
                created: 1,
                exact: true,
                source: ResultSource::Exit,
                guard: "guard".into(),
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
            table: Vec::new(),
            units: BTreeMap::new(),
            residue: Residue::default(),
            state: SuiteState::Ready,
            no_evidence: None,
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
            inputs,
            outputs: Vec::new(),
        }
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
            "tests/a.t",
            &[shared.clone(), setup.clone(), shared.clone()],
            &[],
            1
        )));
        assert!(stored(pass.record(
            "tests/b.t",
            std::slice::from_ref(&setup),
            &[],
            2
        )));
        assert!(stored(pass.record(
            "tests/a.t",
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

    #[test]
    fn a_version_over_the_budget_is_dropped_and_leaves_only_the_marker() {
        let roster = ["tests/a.t"];
        let id = pending_for(&roster).suite;
        let dir = seed("budget", &bundle_for(pending_for(&roster), "key"));
        let before = fs::read(bundle_file(&dir, &id)).unwrap();
        let mut pass = pass_of(start(&dir, &pending_for(&roster), "key", guard()));
        pass.budget = before.len() as u64;
        assert!(matches!(
            pass.record("tests/a.t", &[input("src/shared.src")], &[], 1),
            Stored::OverBudget
        ));
        assert!(
            pass.bundle.units.is_empty(),
            "the dropped version left memory"
        );
        assert!(pass.bundle.table.is_empty());
        assert!(pass.interned.is_empty());
        drop(pass);
        // The dropped version is not on disk. The pass stored nothing, so the bundle carries the
        // marker for its roster, and that is the only change.
        let area = Area::open(&dir, false).unwrap().unwrap();
        let ReadBundle::Current(stored) = read_bundle(&area, &id) else {
            panic!("the bundle is not current after an over-budget pass");
        };
        assert!(stored.units.is_empty());
        assert!(stored.table.is_empty());
        assert_eq!(
            stored.no_evidence,
            Some(roster_digest(&pending_for(&roster).roster))
        );
    }

    #[test]
    fn a_pass_that_stores_no_proof_marks_its_roster_silent_until_the_roster_changes() {
        let roster = ["tests/a.t"];
        let dir = seed("marker", &bundle_for(pending_for(&roster), "key"));
        drop(pass_of(start(&dir, &pending_for(&roster), "key", guard())));
        assert!(
            matches!(
                start(&dir, &pending_for(&roster), "key", guard()),
                Start::No
            ),
            "the same roster is silent"
        );
        let wider = ["tests/a.t", "tests/b.t"];
        assert!(
            matches!(
                start_after_release(&dir, &pending_for(&wider), "key"),
                Start::Pass(_)
            ),
            "a new roster starts a pass"
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
        assert!(matches!(
            start(&dir, &pending_for(&roster), "key", guard()),
            Start::Pass(_)
        ));
        assert!(matches!(
            start(&dir, &pending_for(&roster), "another key", guard()),
            Start::No
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
                pass.record(unit, &[input("src/shared.src")], &[], 1),
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
            pass.record(unit, &[input("src/shared.src")], &[], 1);
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
        pass.record(&units[0], &[input("src/shared.src")], &[], 1);
        pass.record(&units[1], &[input("src/shared.src")], &[], 1);
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
        // The lock entry exists already, so only the new proof entry can be refused.
        let area = Area::open(&dir, false).unwrap().unwrap();
        drop(lock(&area, &id).unwrap());
        let suite_dir = dir.join("units/v1");
        fs::set_permissions(&suite_dir, fs::Permissions::from_mode(0o500)).unwrap();
        let started = start(&dir, &pending_for(&roster), "key", guard());
        fs::set_permissions(&suite_dir, fs::Permissions::from_mode(0o700)).unwrap();
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
}

/// M1 (ignored, a measurement). The cost of encoding, writing (with fsync and rename) and parsing a
/// full-roster bundle at 1, 2, 4 and 8 MiB. Run it in release:
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
            },
            guard_digest: "guard".into(),
            roster: pending.roster,
            table,
            units,
            residue: Residue::default(),
            state: SuiteState::Ready,
            no_evidence: None,
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
                parse_ms.push((parsed - written).as_secs_f64() * 1e3);
            }
            println!(
                "M1 size={size} encode_p50={:.2}ms encode_p95={:.2}ms write_p50={:.2}ms write_p95={:.2}ms parse_p50={:.2}ms parse_p95={:.2}ms",
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
