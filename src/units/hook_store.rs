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
    if catalog.records.len() > MAX_RECORDS {
        return Err(Damage::Replace(
            "it holds more records than the limit".into(),
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

/// Read the records that can be used. Damage yields no records plus one warning, so a
/// broken catalog costs at most the hook recognition it would have provided.
pub(crate) fn records(store: &Path, now: u64, max_age: u64) -> Result<Vec<Record>, String> {
    match read_catalog(store) {
        Ok(catalog) => Ok(catalog
            .records
            .into_iter()
            .filter(|record| current(record, now, max_age))
            .collect()),
        Err(Damage::Replace(why) | Damage::Keep(why)) => Err(format!(
            "stoop: hook records are unavailable ({why}); running the command as typed"
        )),
    }
}

/// Save one template. Any failure is returned as a warning; the caller still runs the command.
pub(crate) fn record(store: &Path, record: Record, now: u64, max_age: u64) -> Result<(), String> {
    if record.argv.len() > 128
        || serde_json::to_vec(&record)
            .map(|bytes| bytes.len() > MAX_RECORD_BYTES)
            .unwrap_or(true)
    {
        return Err(
            "stoop: hook template is too large to record; running the command as typed".into(),
        );
    }
    let _lock = lock(store).map_err(|error| {
        format!("stoop: cannot lock hook records ({error}); running the command as typed")
    })?;
    let mut repaired = None;
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(why)) => {
            repaired = Some(format!(
                "stoop: hook records were replaced because {why}; running the command as typed"
            ));
            Catalog {
                version: 1,
                records: Vec::new(),
            }
        }
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
            write_bytes(store, &bytes).map_err(|error| {
                format!("stoop: cannot save hook records ({error}); running the command as typed")
            })?;
            return match repaired {
                Some(note) => Err(note),
                None => Ok(()),
            };
        }
        if catalog.records.len() <= 1 {
            return Err(
                "stoop: hook templates exceed the catalog limit; running the command as typed"
                    .into(),
            );
        }
        catalog.records.remove(0);
    }
}

/// Remove every template stored under `key`. Returns whether one was removed.
pub(crate) fn forget(store: &Path, key: &str) -> Result<bool, String> {
    if !path(store).exists() {
        return Ok(false);
    }
    let _lock =
        lock(store).map_err(|error| format!("stoop: cannot lock hook records ({error})"))?;
    let mut catalog = match read_catalog(store) {
        Ok(catalog) => catalog,
        Err(Damage::Replace(why) | Damage::Keep(why)) => {
            return Err(format!("stoop: hook records are unavailable ({why})"));
        }
    };
    let before = catalog.records.len();
    catalog.records.retain(|record| record.key != key);
    if before == catalog.records.len() {
        return Ok(false);
    }
    write_catalog(store, &catalog)
        .map_err(|error| format!("stoop: cannot save hook records ({error})"))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn store(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "stoop-store-unit-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn template(key: &str, created: u64) -> Record {
        Record {
            key: key.into(),
            argv: vec!["./t".into(), "{changed}".into()],
            cwd: String::new(),
            scope: None,
            label: None,
            created,
        }
    }

    #[test]
    fn a_read_only_store_warns_that_the_full_command_runs() {
        let path = store("read-only");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
        let warning = record(&path, template("k", 0), 0, 0).unwrap_err();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(warning.contains("running the full command"), "{warning}");
        assert!(!warning.contains("as typed"), "{warning}");
    }

    #[test]
    fn the_catalog_keeps_at_most_128_records() {
        let path = store("cap");
        for i in 0..130 {
            record(&path, template(&format!("k{i}"), 0), 0, 0).unwrap();
        }
        let keys: Vec<String> = read_catalog(&path)
            .ok()
            .unwrap()
            .records
            .into_iter()
            .map(|record| record.key)
            .collect();
        assert_eq!(keys.len(), MAX_RECORDS);
        assert!(!keys.contains(&"k0".to_string()));
        assert!(keys.contains(&"k129".to_string()));
    }

    #[test]
    fn expired_templates_are_not_read() {
        let path = store("expiry");
        record(&path, template("old", 0), 0, 0).unwrap();
        assert!(records(&path, 1_000, 60).unwrap().is_empty());
    }
}
