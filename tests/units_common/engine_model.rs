//! Independent full/subset/skip prediction for the generated E3 fixture.
use super::{model_current_guard, model_identity, model_proof_digest, model_version_holds, Suite};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum ModelDecision {
    Full(&'static str),
    Subset(Vec<String>),
    Skip,
}

pub fn model_whole_proof(s: &Suite, bundle: &Value) -> Option<Value> {
    let whole = bundle["whole"].as_str()?;
    s.proofs()
        .into_iter()
        .find(|proof| model_proof_digest(proof) == whole)
}

fn entries<'a>(table: &'a [Value], version: &Value, field: &str) -> Option<Vec<&'a Value>> {
    let mut index = 0u64;
    version[field]
        .as_array()?
        .iter()
        .enumerate()
        .map(|(at, delta)| {
            let delta = delta.as_u64()?;
            index = if at == 0 {
                delta
            } else {
                index.checked_add(delta)?
            };
            table.get(index as usize)
        })
        .collect()
}

fn path(entry: &Value) -> Option<&str> {
    entry["path"].as_str()
}
fn id(entry: &Value) -> Option<&str> {
    entry["id"].as_str()
}
fn holds(s: &Suite, entry: &Value) -> bool {
    let (Some(path), Some(id)) = (path(entry), id(entry)) else {
        return false;
    };
    model_identity(s, path, id.starts_with("dl:")).as_deref() == Some(id)
}
fn regular_id(id: &str) -> bool {
    id.starts_with("f:") || id.starts_with("x:")
}

fn listing_holds(
    s: &Suite,
    listing: &Value,
    proof: &Value,
    bundle: &Value,
    roster: &[String],
    affected: &[String],
    guard: &str,
) -> bool {
    let (Some(dir), Some(id), Some(table), Some(units)) = (
        path(listing),
        id(listing),
        bundle["table"].as_array(),
        bundle["units"].as_object(),
    ) else {
        return false;
    };
    if holds(s, listing) {
        return true;
    }
    let Some(expected) = id.strip_prefix("dl:") else {
        return false;
    };
    let Ok(entries_now) = fs::read_dir(s.path(dir)) else {
        return false;
    };
    let Some(mut names): Option<Vec<Vec<u8>>> = entries_now
        .map(|entry| {
            entry
                .ok()
                .map(|entry| entry.file_name().as_bytes().to_vec())
        })
        .collect()
    else {
        return false;
    };
    let (Some(inputs), Some(outputs)) = (proof["inputs"].as_array(), proof["outputs"].as_array())
    else {
        return false;
    };
    let recorded: BTreeSet<&str> = inputs
        .iter()
        .chain(outputs)
        .filter(|entry| id_of(entry) != Some("a"))
        .filter_map(path)
        .collect();
    let whole_read: BTreeSet<&str> = inputs
        .iter()
        .filter(|entry| id_of(entry).is_some_and(regular_id))
        .filter_map(path)
        .collect();
    let under = |key: &str| Path::new(key).parent() == Some(Path::new(dir));
    let mut covered = BTreeSet::new();
    for unit in roster {
        let Some(versions) = units.get(unit).and_then(Value::as_array) else {
            continue;
        };
        for version in versions {
            let valid = model_version_holds(s, table, version, guard, None);
            if !valid && !affected.contains(unit) {
                continue;
            }
            let Some(reads) = entries(table, version, "inputs") else {
                return false;
            };
            for entry in reads {
                let (Some(key), Some(identity)) = (path(entry), id_of(entry)) else {
                    return false;
                };
                if !recorded.contains(key) && (affected.contains(unit) || regular_id(identity)) {
                    covered.insert(key.to_owned());
                }
            }
        }
    }
    let mut added = BTreeSet::new();
    if !matches!(dir, "" | ".") {
        for key in roster
            .iter()
            .filter(|unit| !whole_read.contains(unit.as_str()))
            .chain(covered.iter())
        {
            if under(key) && fs::symlink_metadata(s.path(key)).is_ok_and(|meta| meta.is_file()) {
                if let Some(name) = Path::new(key).file_name() {
                    added.insert(name.as_bytes().to_vec());
                }
            }
        }
    }
    let mut lost = BTreeSet::new();
    for key in units
        .iter()
        .filter(|(_, versions)| {
            versions
                .as_array()
                .is_some_and(|versions| !versions.is_empty())
        })
        .map(|(unit, _)| unit.as_str())
        .chain(whole_read.iter().copied())
    {
        if under(key) && model_identity(s, key, false).as_deref() == Some("a") {
            if let Some(name) = Path::new(key).file_name() {
                lost.insert(name.as_bytes().to_vec());
            }
        }
    }
    names.retain(|name| !added.contains(name));
    names.extend(lost);
    names.sort();
    let mut hash = blake3::Hasher::new();
    for name in names {
        hash.update(&(name.len() as u64).to_le_bytes());
        hash.update(&name);
    }
    hash.finalize().to_hex().as_str() == expected
}

fn id_of(entry: &Value) -> Option<&str> {
    id(entry)
}

/// Predict a run from the pre-step bundle and whole proof against the tree after the proposed operations.
pub fn engine_would_decide(
    s: &Suite,
    bundle: &Value,
    proof: Option<&Value>,
    roster: &[String],
    env: &[(&str, &str)],
    forced: bool,
) -> ModelDecision {
    if forced {
        return ModelDecision::Full("forced");
    }
    let (Some(proof), Some(table), Some(units), Some(guard)) = (
        proof,
        bundle["table"].as_array(),
        bundle["units"].as_object(),
        model_current_guard(s, bundle, env),
    ) else {
        return ModelDecision::Full("missing proof or bundle");
    };
    if bundle["state"]["status"] != "ready" {
        return ModelDecision::Full("disabled");
    }
    if bundle["residue"]["whole"] != bundle["whole"]
        || bundle["residue"]["state"] == "none"
        || bundle["residue"]["count"].as_u64() != Some(0)
    {
        return ModelDecision::Full("residue");
    }
    if bundle["guard_digest"].as_str() != Some(guard.as_str()) {
        return ModelDecision::Full("environment");
    }
    let (Some(inputs), Some(outputs), Some(whole_roster)) = (
        proof["inputs"].as_array(),
        proof["outputs"].as_array(),
        bundle["whole_roster"].as_array(),
    ) else {
        return ModelDecision::Full("missing whole proof data");
    };
    if roster.iter().any(|unit| {
        !whole_roster
            .iter()
            .any(|old| old.as_str() == Some(unit.as_str()))
    }) {
        return ModelDecision::Full("new roster");
    }
    for (unit, versions) in units {
        if !roster.contains(unit)
            && versions
                .as_array()
                .is_some_and(|versions| !versions.is_empty())
            && model_identity(s, unit, false).is_some_and(|identity| identity != "a")
        {
            return ModelDecision::Full("leftover unit");
        }
        if !roster.contains(unit)
            && versions
                .as_array()
                .is_some_and(|versions| !versions.is_empty())
            && inputs.iter().any(|entry| {
                path(entry) == Some(unit.as_str()) && id(entry).is_some_and(regular_id)
            })
        {
            return ModelDecision::Full("removed unit");
        }
    }
    let mut affected = Vec::new();
    let mut by_unit = Vec::new();
    let mut known_outputs = BTreeSet::new();
    for unit in roster {
        let versions = units.get(unit).and_then(Value::as_array);
        let mut reads = BTreeSet::new();
        let mut changed = BTreeSet::new();
        let mut valid = false;
        for version in versions.into_iter().flatten() {
            valid |= model_version_holds(s, table, version, &guard, None);
            let Some(version_inputs) = entries(table, version, "inputs") else {
                return ModelDecision::Full("invalid unit inputs");
            };
            for entry in version_inputs {
                let Some(key) = path(entry) else {
                    return ModelDecision::Full("invalid unit input");
                };
                reads.insert(key.to_owned());
                if !holds(s, entry) {
                    changed.insert(key.to_owned());
                }
            }
            let Some(version_outputs) = entries(table, version, "outputs") else {
                return ModelDecision::Full("invalid unit outputs");
            };
            known_outputs.extend(
                version_outputs
                    .into_iter()
                    .filter_map(path)
                    .map(str::to_owned),
            );
        }
        if !valid {
            affected.push(unit.clone());
        }
        if versions.is_some_and(|versions| !versions.is_empty()) {
            by_unit.push((reads, changed));
        }
    }
    if by_unit.is_empty() {
        return ModelDecision::Full("no unit proof");
    }
    let shared = by_unit[0]
        .0
        .iter()
        .filter(|key| by_unit.iter().all(|(reads, _)| reads.contains(*key)));
    for key in shared {
        if by_unit.iter().any(|(_, changed)| changed.contains(key))
            && inputs
                .iter()
                .find(|entry| path(entry) == Some(key.as_str()))
                .is_none_or(|entry| !holds(s, entry))
        {
            return ModelDecision::Full("shared input");
        }
    }
    if outputs
        .iter()
        .any(|entry| path(entry).is_none_or(|key| !known_outputs.contains(key) && !holds(s, entry)))
    {
        return ModelDecision::Full("whole output");
    }
    for entry in inputs {
        let (Some(key), Some(identity)) = (path(entry), id(entry)) else {
            return ModelDecision::Full("invalid whole input");
        };
        if Path::new(key).is_absolute() && !holds(s, entry) {
            return ModelDecision::Full("outside input");
        }
        if identity == "a" && !holds(s, entry) {
            let parent = Path::new(key).parent().and_then(Path::to_str).unwrap_or("");
            if !inputs.iter().chain(outputs).any(|item| {
                id(item).is_some_and(|value| value.starts_with("dl:"))
                    && (path(item) == Some(parent)
                        || (parent.is_empty() && path(item) == Some(".")))
            }) {
                return ModelDecision::Full("appeared outside listing");
            }
        }
        if identity == "d" && !Path::new(key).is_absolute() && !holds(s, entry) {
            return ModelDecision::Full("directory metadata");
        }
        if roster.iter().any(|unit| unit == key) && regular_id(identity) {
            let current = model_identity(s, key, false);
            if !current.as_deref().is_some_and(|now| {
                regular_id(now) && now.starts_with("x:") == identity.starts_with("x:")
            }) {
                return ModelDecision::Full("unit type");
            }
        }
    }
    if roster.iter().any(|unit| {
        !inputs
            .iter()
            .any(|entry| path(entry) == Some(unit.as_str()) && id(entry).is_some_and(regular_id))
    }) {
        return ModelDecision::Full("unit not read by whole");
    }
    for listing in inputs
        .iter()
        .chain(outputs)
        .filter(|entry| id(entry).is_some_and(|identity| identity.starts_with("dl:")))
    {
        if !listing_holds(s, listing, proof, bundle, roster, &affected, &guard) {
            return ModelDecision::Full("listing");
        }
    }
    if !affected.is_empty() {
        for (unit, versions) in units {
            for version in versions.as_array().into_iter().flatten() {
                let Some(reads) = entries(table, version, "inputs") else {
                    return ModelDecision::Full("invalid unit inputs");
                };
                if reads.iter().any(|entry| {
                    let Some(key) = path(entry) else { return true };
                    (roster.contains(unit) || key != unit)
                        && inputs.iter().any(|whole| {
                            path(whole) == Some(key) && id(whole).is_some_and(regular_id)
                        })
                        && model_identity(s, key, false).as_deref() == Some("a")
                }) {
                    return ModelDecision::Full("removed input");
                }
            }
        }
        return ModelDecision::Subset(affected);
    }
    if units.iter().any(|(unit, versions)| {
        !roster.contains(unit) && versions.as_array().is_some_and(|v| !v.is_empty())
    }) {
        return ModelDecision::Full("departed reader");
    }
    ModelDecision::Skip
}
