//! Durable templates identify shell-erased hooks; they never confer a proof hit.

use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RECORDS: usize = 128;
const MAX_RECORD_BYTES: usize = 8192;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct Record {
    pub key: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub scope: Option<String>,
    pub label: Option<String>,
    pub created: u64,
}

#[derive(Default, Deserialize, Serialize)]
struct Catalog {
    version: u8,
    records: Vec<Record>,
}

fn path(store: &Path) -> PathBuf {
    store.join("hooks-v1.json")
}

/// What a damaged catalog means for this run.
pub(crate) enum Damage {
    /// Missing, corrupt or oversized: safe to replace with a fresh catalog.
    Replace(String),
    /// A catalog written by another stoop version, or one we cannot read: never overwritten.
    Keep(String),
}

fn read_catalog(store: &Path) -> Result<Catalog, Damage> {
    let file = match File::open(path(store)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Catalog {
                version: 1,
                records: Vec::new(),
            });
        }
        Err(error) => return Err(Damage::Keep(format!("cannot read it ({error})"))),
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes) {
        return Err(Damage::Keep(format!("cannot read it ({error})")));
    }
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(Damage::Replace("it is larger than the size limit".into()));
    }
    let catalog: Catalog = match serde_json::from_slice(&bytes) {
        Ok(catalog) => catalog,
        Err(error) => return Err(Damage::Replace(format!("it is not valid ({error})"))),
    };
    if catalog.version != 1 {
        return Err(Damage::Keep(format!(
            "it was written by another stoop version (catalog version {})",
            catalog.version
        )));
    }
    Ok(catalog)
}

fn lock(store: &Path) -> io::Result<File> {
    fs::create_dir_all(store)?;
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(store.join(".gitignore"))
    {
        Ok(mut file) => file.write_all(b"*\n")?,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(store.join("hooks-v1.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn write_catalog(store: &Path, catalog: &Catalog) -> io::Result<()> {
    let bytes = serde_json::to_vec(catalog).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook records exceed size limit",
        ));
    }
    write_bytes(store, &bytes)
}

fn write_bytes(store: &Path, bytes: &[u8]) -> io::Result<()> {
    let temp = store.join(format!(
        ".hooks-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path(store))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn current(record: &Record, now: u64, max_age: u64) -> bool {
    max_age == 0 || now.saturating_sub(record.created) <= max_age
}

pub(crate) fn records(store: &Path, now: u64, max_age: u64) -> io::Result<Vec<Record>> {
    Ok(read_catalog(store)?
        .records
        .into_iter()
        .filter(|record| current(record, now, max_age))
        .collect())
}

pub(crate) fn record(store: &Path, record: Record, now: u64, max_age: u64) -> io::Result<()> {
    if record.argv.len() > 128
        || serde_json::to_vec(&record)
            .map(|bytes| bytes.len() > MAX_RECORD_BYTES)
            .unwrap_or(true)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hook template exceeds size limit",
        ));
    }
    let _lock = lock(store).map_err(|error| {
        format!("stoop: cannot lock hook records ({error}); running the command as typed")
    })?;
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(_)) => Catalog {
            version: 1,
            records: Vec::new(),
        },
        Err(Damage::Keep(why)) => {
            return Err(format!(
                "stoop: hook records are kept as they are ({why}); running the command as typed"
            ));
        }
    };
    catalog
        .records
        .retain(|old| current(old, now, max_age) && old.key != record.key);
    catalog.records.push(record);
    while catalog.records.len() > MAX_RECORDS {
        catalog.records.remove(0);
    }
    loop {
        let bytes = serde_json::to_vec(&catalog).map_err(|error| {
            format!("stoop: cannot save hook records ({error}); running the command as typed")
        })?;
        if bytes.len() as u64 <= MAX_FILE_BYTES {
            return write_bytes(store, &bytes).map_err(|error| {
                format!("stoop: cannot save hook records ({error}); running the command as typed")
            });
        }
        if catalog.records.len() <= 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hook template exceeds catalog limit",
            ));
        }
        catalog.records.remove(0);
    }
}

/// Remove every template stored under `key`. Returns whether one was removed.
pub(crate) fn forget(store: &Path, key: &str) -> Result<bool, String> {
    if !path(store).exists() {
        return Ok(false);
    }
    let _lock = lock(store)?;
    let mut catalog = read_catalog(store)?;
    let before = catalog.records.len();
    catalog.records.retain(|record| record.key != key);
    if before == catalog.records.len() {
        return Ok(false);
    }
    write_catalog(store, &catalog)?;
    Ok(true)
}
