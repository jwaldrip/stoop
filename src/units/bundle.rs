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

const VERSION: u32 = 1;
const GENERATION: u32 = 1;
const MAX_UNITS: usize = 4096;
const MAX_UNIT_BYTES: usize = 4096;
const MAX_VERSIONS: usize = 8;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
/// `forget --units` removes the lock file, so a process waiting on the old file can take a lock
/// that no other process contends for. A lock is trusted only while it is still the named entry.
const LOCK_ATTEMPTS: usize = 3;
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
struct LaunchGuard {
    #[serde(deserialize_with = "unique_map")]
    env: BTreeMap<String, String>,
    env_excluded: Vec<String>,
    ignore: Vec<String>,
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

    /// Opens the lock entry, creating it if needed.
    fn lock_file(&self, name: &str) -> io::Result<File> {
        #[cfg(unix)]
        {
            at::open_file(&self.dir, name, libc::O_RDWR | libc::O_CREAT)
        }
        #[cfg(not(unix))]
        {
            let path = self.dir.join(name);
            refuse_link(&path)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .private()
                .open(path)
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

    /// Whether the open lock file is still the entry the name refers to. Windows offers no file
    /// identity through std, so the lock is trusted as opened there.
    fn same_entry(&self, file: &File, name: &str) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            match (file.metadata(), self.stat(name)) {
                (Ok(held), Ok(Some(named))) => (held.dev(), held.ino()) == named.id,
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
        Ok(bundle) if valid_bundle(&bundle, id) => ReadBundle::Current(bundle),
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
    let temp = format!(
        ".{}-{}-{}.tmp",
        bundle.suite,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let result = (|| {
        let mut file = area.create_temp(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        area.rename(&temp, &bundle_name(&bundle.suite))
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
    };
    let _ = write_bundle(&area, &bundle);
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
