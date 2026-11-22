//! Bounded, local suite rosters. A bundle does not itself confer a proof hit.

use crate::input::Input;
use crate::proof::Proof;
use crate::sys::Private;
use crate::trace::Provenance;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const VERSION: u32 = 1;
const GENERATION: u32 = 1;
const MAX_UNITS: usize = 4096;
const MAX_UNIT_BYTES: usize = 4096;
const MAX_VERSIONS: usize = 8;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
static NEXT: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize, Deserialize)]
struct Origin {
    kind: String,
    argv: Vec<String>,
    cwd: String,
    scope: Option<String>,
    label: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Roster {
    source: String,
    filter: String,
    units: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct LaunchGuard {
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
    whole_key: String,
    whole: Option<String>,
    policy: String,
    guard: LaunchGuard,
    guard_digest: String,
    roster: Roster,
    table: Vec<Input>,
    units: BTreeMap<String, Vec<UnitVersion>>,
    residue: Residue,
    state: SuiteState,
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

fn suite_id(argv: &[OsString], cwd: &str, scope: Option<&str>, label: Option<&str>) -> String {
    let mut hash = blake3::Hasher::new_derive_key("stoop suite id v1");
    field(&mut hash, b"hook");
    field(&mut hash, scope.unwrap_or("").as_bytes());
    field(&mut hash, cwd.as_bytes());
    for word in argv {
        field(&mut hash, word.as_encoded_bytes());
    }
    field(&mut hash, label.unwrap_or("").as_bytes());
    hash.finalize().to_hex()[..32].to_string()
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
    let words = argv
        .iter()
        .map(|word| word.to_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let mut hash = blake3::Hasher::new_derive_key("stoop suite policy v1");
    field(&mut hash, source.as_bytes());
    field(&mut hash, filter.as_bytes());
    field(&mut hash, config_suite.unwrap_or("").as_bytes());
    field(&mut hash, config.unwrap_or_default());
    Some(Pending {
        suite: suite_id(argv, cwd, scope, label),
        origin: Origin {
            kind: "hook".into(),
            argv: words,
            cwd: cwd.into(),
            scope: scope.map(str::to_owned),
            label: label.map(str::to_owned),
        },
        roster: Roster {
            source: source.into(),
            filter: filter.into(),
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

fn directory(store: &Path) -> PathBuf {
    store.join("units/v1")
}

fn bundle_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn lock_path(dir: &Path, id: &str) -> PathBuf {
    dir.join(format!("{id}.lock"))
}

// Keeping the bundle inline avoids a separate allocation on every successful read.
#[allow(clippy::large_enum_variant)]
enum ReadBundle {
    Missing,
    Corrupt,
    OtherVersion,
    Current(SuiteBundleV1),
}

#[derive(Deserialize)]
struct Header {
    v: u64,
    generation: Option<serde_json::Value>,
}

fn read_bundle(dir: &Path, id: &str) -> ReadBundle {
    let bytes = match super::config::read_regular_bounded(&bundle_path(dir, id), MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ReadBundle::Missing,
        Err(_) => return ReadBundle::Corrupt,
    };
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

fn lock(dir: &Path, id: &str) -> io::Result<File> {
    fs::create_dir_all(dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .private()
        .open(lock_path(dir, id))?;
    file.try_lock().map_err(io::Error::from)?;
    Ok(file)
}

fn clear_temps(dir: &Path, id: &str) {
    let prefix = format!(".{id}-");
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".tmp") {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn write_bundle(dir: &Path, bundle: &SuiteBundleV1) -> io::Result<()> {
    let bytes = serde_json::to_vec(bundle).map_err(io::Error::other)?;
    if bytes.len() as u64 > MAX_BYTES || !valid_bundle(bundle, &bundle.suite) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "suite bundle exceeds its bounds",
        ));
    }
    let temp = dir.join(format!(
        ".{}-{}-{}.tmp",
        bundle.suite,
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .private()
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temp, bundle_path(dir, &bundle.suite))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

/// Best effort only: no diagnostic or decision changes when a bundle cannot be saved.
pub(crate) fn record(store: &Path, pending: Pending, key: &str, digest: &str, proof: Proof) {
    let dir = directory(store);
    let Ok(_lock) = lock(&dir, &pending.suite) else {
        return;
    };
    clear_temps(&dir, &pending.suite);
    let previous = match read_bundle(&dir, &pending.suite) {
        ReadBundle::OtherVersion => return,
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
        whole_key: key.into(),
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
    let _ = write_bundle(&dir, &bundle);
}

/// Listing is informational; damaged files get one warning and remain untouched.
pub(crate) fn list(store: &Path) -> Vec<(String, Option<String>)> {
    let dir = directory(store);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            let id = name.strip_suffix(".json")?;
            valid_suite_id(id).then(|| id.to_owned())
        })
        .collect();
    ids.sort();
    ids.dedup();
    ids.into_iter()
        .filter_map(|id| match read_bundle(&dir, &id) {
            ReadBundle::Missing => None,
            ReadBundle::Corrupt => Some((
                format!("suite\t{id}\tunreadable"),
                Some(format!("stoop: ignoring a corrupt suite bundle: {id}")),
            )),
            ReadBundle::OtherVersion => Some((format!("suite\t{id}\tnewer format"), None)),
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
        })
        .collect()
}

/// The ID is a validated filename, not a path or a sanitized alias.
pub(crate) fn forget(store: &Path, id: &str) -> io::Result<bool> {
    if !valid_suite_id(id) {
        return Ok(false);
    }
    let dir = directory(store);
    let bundle = bundle_path(&dir, id);
    let lock_file = lock_path(&dir, id);
    if !bundle.exists() && !lock_file.exists() {
        return Ok(false);
    }
    let _lock = lock(&dir, id)?;
    match fs::remove_file(&bundle) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::remove_file(lock_file)?;
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
            whole_key: "hook-key".into(),
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
        let error = write_bundle(Path::new("/dev/null"), &bounded).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(bounded.roster.units.len(), MAX_UNITS);
        bounded.roster.units.push("zzzz".into());
        assert!(!valid_bundle(&bounded, &bundle.suite));
    }
}
