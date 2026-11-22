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

fn read_bundle(dir: &Path, id: &str) -> ReadBundle {
    let path = bundle_path(dir, id);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ReadBundle::Missing,
        Err(_) => return ReadBundle::Unreadable,
    };
    if !metadata.is_file() {
        return ReadBundle::Unreadable;
    }
    if metadata.len() > MAX_BYTES {
        return ReadBundle::Corrupt;
    }
    let bytes = match super::config::read_regular_bounded(&path, MAX_BYTES) {
        Ok(bytes) => bytes,
        // It grew past the limit after the check above.
        Err(error) if error.kind() == io::ErrorKind::InvalidData => return ReadBundle::Corrupt,
        Err(_) => return ReadBundle::Unreadable,
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
    lock_with(dir, id, || {})
}

fn lock_with(dir: &Path, id: &str, mut after_open: impl FnMut()) -> io::Result<File> {
    fs::create_dir_all(dir)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .private()
        .open(lock_path(dir, id))?;
    after_open();
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
            ReadBundle::Unreadable => Some((
                format!("suite\t{id}\tunreadable"),
                Some(format!("stoop: cannot read suite bundle: {id}")),
            )),
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
        let error = write_bundle(Path::new("/dev/null"), &bounded).unwrap_err();
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

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stoop-lock-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(lock_path(&dir, ID), b"").unwrap();
        dir
    }

    fn replace_lock(dir: &Path) {
        let path = lock_path(dir, ID);
        let _ = fs::remove_file(&path);
        fs::write(&path, b"").unwrap();
    }

    fn held_identity(file: &File) -> (u64, u64) {
        let meta = file.metadata().unwrap();
        (meta.dev(), meta.ino())
    }

    fn path_identity(dir: &Path) -> (u64, u64) {
        let meta = fs::symlink_metadata(lock_path(dir, ID)).unwrap();
        (meta.dev(), meta.ino())
    }

    #[test]
    fn a_lock_replaced_while_it_is_taken_is_not_trusted() {
        let dir = scratch("replaced-once");
        let mut first = true;
        let file = lock_with(&dir, ID, || {
            if std::mem::take(&mut first) {
                replace_lock(&dir);
            }
        })
        .unwrap();
        assert_eq!(held_identity(&file), path_identity(&dir));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_lock_replaced_on_every_attempt_is_reported_busy() {
        let dir = scratch("replaced-always");
        let result = lock_with(&dir, ID, || replace_lock(&dir));
        assert!(result.is_err());
        let _ = fs::remove_dir_all(&dir);
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
