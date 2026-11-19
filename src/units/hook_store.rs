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

fn read_catalog(store: &Path) -> io::Result<Catalog> {
    let file = match File::open(path(store)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Catalog {
                version: 1,
                records: Vec::new(),
            });
        }
        Err(error) => return Err(error),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook records exceed size limit",
        ));
    }
    let catalog: Catalog = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if catalog.version != 1 || catalog.records.len() > MAX_RECORDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hook record catalog",
        ));
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
        || serde_json::to_vec(&record).map_err(io::Error::other)?.len() > MAX_RECORD_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "hook template exceeds size limit",
        ));
    }
    let _lock = lock(store)?;
    let mut catalog = read_catalog(store)?;
    catalog
        .records
        .retain(|old| current(old, now, max_age) && old.key != record.key);
    catalog.records.push(record);
    if catalog.records.len() > MAX_RECORDS {
        catalog.records.drain(..catalog.records.len() - MAX_RECORDS);
    }
    loop {
        let bytes = serde_json::to_vec(&catalog).map_err(io::Error::other)?;
        if bytes.len() as u64 <= MAX_FILE_BYTES {
            return write_bytes(store, &bytes);
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

pub(crate) fn forget(store: &Path, key: &str) -> io::Result<bool> {
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
