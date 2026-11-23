//! The decision engine (spec 3.9 and 3.10). With `STOOP_SPLIT` on, a changed run of a hooked suite decides from the unit
//! proofs in its bundle whether it may skip. W7-1 acts on one decision, a skip when no unit is affected. Every other
//! decision takes the full command, which is the switch-off path, with the reason the spec gives. Explain takes the same
//! decision without the suite lock and prints the same lines (spec 3.12). Nothing here writes, except `settle` and
//! `disagree`, which run under the suite lock.

use super::attribution;
use super::bundle::{self, LaunchGuard, Pending, Settled, Version, View};
use super::config::Config;
use super::hook::safe;
use super::residue;
use crate::ignore::Ignore;
use crate::input::{identify, par_map, Input};
use crate::pathutil::from_key;
use crate::proof::{now, Proof};
use crate::run::{Lookup, RunCx};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::path::Path;

/// How many affected units explain names before it counts the rest (spec 3.12).
const NAMED: usize = 20;

/// The reason of a unit that has no proof (spec 3.9).
const NEW: &str = "new";

/// The label of a suite that a full command disables when it fails while every unit's proof held (spec 3.4).
pub(crate) const DISAGREEMENT: &str = "the full command failed while every unit's proof held";

/// Whether the engine is on (spec 3.1). `None` when `STOOP_SPLIT` is unset. Otherwise it is on for a value that is not
/// empty, `0`, `false`, `no` or `off` once trimmed and lowercased, and off for a value that is not UTF-8.
pub(crate) fn switch() -> Option<bool> {
    std::env::var_os("STOOP_SPLIT").map(|value| on(&value))
}

fn on(value: &OsStr) -> bool {
    value.to_str().is_some_and(|text| {
        !matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "" | "0" | "false" | "no" | "off"
        )
    })
}

/// What the engine decides for one hooked run (spec 3.10). The first step that matches decides.
pub(crate) enum Decision {
    /// Steps E1 to E9: the switch-off path decides. An attribution pass starts when no unit has a proof yet.
    Legacy,
    /// Step E8 for a disabled suite: the full command runs, for this reason.
    Disabled(String),
    /// Steps E10 to E15, and E17 and E18 in W7-1: the full command runs. `None` keeps the legacy reason.
    Full(Option<String>),
    /// Step E16: no unit is affected, so the run skips.
    Skip(Skipped),
}

/// A skip, with the counts its line names (spec 3.12).
pub(crate) struct Skipped {
    /// The roster's units.
    pub(crate) units: usize,
    /// The distinct inputs that the units' proofs name.
    pub(crate) inputs: usize,
    /// Whether the bundle holds versions of units that left the roster. A skip drops them under the suite lock.
    pub(crate) drop: bool,
}

/// A decision with what explain prints for it.
pub(crate) struct Verdict {
    pub(crate) decision: Decision,
    /// The affected units with their reasons, in roster order. `None` when the decision came before step E13.
    pub(crate) affected: Option<Vec<(String, String)>>,
    /// Every roster unit holds its proof and the residue is covered. A full run then arms the disagreement check.
    pub(crate) clean: bool,
}

/// Decides a hooked run under the engine. `pending` is the roster the run took, or the roster explain names, and
/// `lookup` is the legacy lookup, which holds the whole proof. The decision reads the store and the tree, and writes
/// nothing.
pub(crate) fn decide(
    cx: &RunCx<'_>,
    config: &Config,
    lookup: &Lookup,
    pending: &Pending,
    store: &Path,
    key: &str,
    max_age: u64,
) -> Verdict {
    let forced = cx.full_reason.is_some();
    let Some(hook) = cx.hook.as_ref() else {
        return plain();
    };
    // Steps E1 to E7 are the switch-off path's screen. A run that refuses there keeps that path, and a forced run is
    // judged only for the disagreement check.
    let screened = attribution::screen(cx, hook, config, lookup, Ok(pending)).is_ok();
    if !screened && !forced {
        return plain();
    }
    let Some(view) = bundle::view(store, pending, key) else {
        return plain();
    };
    let judged = Judged::new(cx, pending, &lookup.proofs, max_age);
    let verdict = judge(&judged, &view);
    if forced {
        return Verdict {
            decision: Decision::Legacy,
            affected: None,
            clean: verdict.clean,
        };
    }
    verdict
}

/// The verdict of a run the switch-off path keeps: no engine decision, and nothing armed.
fn plain() -> Verdict {
    Verdict {
        decision: Decision::Legacy,
        affected: None,
        clean: false,
    }
}

/// What a decision reads besides the bundle: the roster, the candidate whole proofs, the environment now and the clock.
struct Judged<'a> {
    root: &'a Path,
    suite: &'a str,
    roster: &'a [String],
    proofs: &'a [Proof],
    guard: String,
    max_age: u64,
    now: u64,
}

impl<'a> Judged<'a> {
    fn new(
        cx: &'a RunCx<'_>,
        pending: &'a Pending,
        proofs: &'a [Proof],
        max_age: u64,
    ) -> Judged<'a> {
        Judged {
            root: cx.root.as_path(),
            suite: pending.suite(),
            roster: pending.units(),
            proofs,
            guard: guard_now(cx),
            max_age,
            now: now(),
        }
    }
}

/// The guard digest the run would record now (spec 3.6). It is built as `attribution::pass` builds its guard, so a
/// version and the whole proof agree on it.
fn guard_now(cx: &RunCx<'_>) -> String {
    let ignore = Ignore::new(
        &cx.o.ignore,
        Some(&cx.root.join(".stoopignore")),
        &cx.o.transient,
    );
    LaunchGuard {
        env: cx.env_now.clone(),
        env_excluded: cx.env_excluded.clone(),
        ignore: ignore.patterns(),
    }
    .digest()
}

/// The guard digest the whole proof records, which a version's guard is compared with.
fn whole_guard(proof: &Proof) -> String {
    LaunchGuard {
        env: proof.env.clone(),
        env_excluded: proof.env_excluded.clone(),
        ignore: proof.ignore.clone().unwrap_or_default(),
    }
    .digest()
}

/// Spec 3.10 from step E8 on, over the bundle a view holds. It reads the tree and the proofs and never the store, so
/// a run judges again under the suite lock before it writes.
fn judge(cx: &Judged<'_>, view: &View) -> Verdict {
    // E8: a disabled suite runs whole, and the reason names it.
    if let Some(label) = &view.disabled {
        return verdict(
            Decision::Disabled(format!("suite {} is disabled: {label}", cx.suite)),
            None,
            false,
        );
    }
    // E9: no roster unit has a proof yet, so the attribution pass decides.
    if cx.roster.iter().all(|unit| {
        view.units
            .get(unit)
            .is_none_or(|versions| versions.is_empty())
    }) {
        return verdict(Decision::Legacy, None, false);
    }
    let proof = cx.proofs.iter().find(|proof| proof.digest() == view.whole);
    let current = Current::of(cx.root, &checked(cx, view, proof));
    let affected = analyse(cx, view, &current);
    let covered = matches!(view.residue, Some((0, _)));
    let clean = affected.is_empty() && covered;
    // E10 to E12 come before the affected units are judged, so their verdicts carry none.
    let Some(proof) = proof else {
        return verdict(
            Decision::Full(Some("the last full run's proof is gone".to_owned())),
            None,
            clean,
        );
    };
    if let Some(reason) = leftover(cx, view) {
        return verdict(Decision::Full(Some(reason)), None, clean);
    }
    match &view.residue {
        Some((count, paths)) if *count > 0 => {
            return verdict(
                Decision::Full(Some(residue::reason(*count, paths))),
                None,
                clean,
            );
        }
        Some(_) => {}
        None => {
            return verdict(
                Decision::Full(Some(
                    "the full command has not been matched to its units yet".to_owned(),
                )),
                None,
                clean,
            );
        }
    }
    // E13 onward: the affected units are known, and explain shows them.
    let shown = Some(affected.clone());
    if whole_guard(proof) != cx.guard {
        return verdict(
            Decision::Full(Some(
                "the environment changed since the last full run".to_owned(),
            )),
            shown,
            clean,
        );
    }
    if let Some(path) = global_change(cx, view, proof, &current) {
        return verdict(
            Decision::Full(Some(format!(
                "{} changed and every unit reads it",
                safe(&path)
            ))),
            shown,
            clean,
        );
    }
    if let Some(reason) = output_missing(cx, view, proof, &current) {
        return verdict(Decision::Full(Some(reason)), shown, clean);
    }
    if affected.is_empty() {
        return verdict(Decision::Skip(skipped(cx, view)), shown, clean);
    }
    // E17 and E18: W7-1 has no subset, so the full command runs for the legacy reason.
    verdict(Decision::Full(None), shown, clean)
}

fn verdict(decision: Decision, affected: Option<Vec<(String, String)>>, clean: bool) -> Verdict {
    Verdict {
        decision,
        affected,
        clean,
    }
}

/// The inputs and outputs that a decision checks: those of each roster unit's versions, and those of the whole proof.
fn checked<'a>(cx: &Judged<'_>, view: &'a View, proof: Option<&'a Proof>) -> Vec<&'a Input> {
    let mut entries = Vec::new();
    for unit in cx.roster {
        for version in view.units.get(unit).into_iter().flatten() {
            entries.extend(
                version
                    .inputs
                    .iter()
                    .map(|&index| &view.table[index as usize]),
            );
            entries.extend(
                version
                    .outputs
                    .iter()
                    .map(|&index| &view.table[index as usize]),
            );
        }
    }
    if let Some(proof) = proof {
        entries.extend(proof.inputs.iter().chain(&proof.outputs));
    }
    entries
}

/// The current identity of each checked entry, keyed by path and by whether its recorded identity lists a directory.
/// `input::verify` uses the same key and the same identity, so a check here agrees with a check there.
struct Current(HashMap<(String, bool), Option<String>>);

impl Current {
    fn of(root: &Path, entries: &[&Input]) -> Current {
        let keys: Vec<(String, bool)> = entries
            .iter()
            .map(|input| key(input))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ids = par_map(&keys, |key| {
            let (path, listed) = key;
            identify(&from_key(root, path), !path.starts_with('/'), *listed)
        });
        Current(keys.into_iter().zip(ids).collect())
    }

    /// The current identity of `input`, or `None` when its path cannot be read.
    fn id(&self, input: &Input) -> Option<&str> {
        self.0.get(&key(input)).and_then(|id| id.as_deref())
    }

    /// Whether `input` is as it was recorded.
    fn holds(&self, input: &Input) -> bool {
        self.id(input) == Some(input.id.as_str())
    }

    /// Whether `input` is absent now.
    fn absent(&self, input: &Input) -> bool {
        self.id(input) == Some("a")
    }
}

fn key(input: &Input) -> (String, bool) {
    (input.path.clone(), input.id.starts_with("dl:"))
}

/// Step E13 (spec 3.9): the roster units whose proof no longer holds, each with its reason, in roster order. A unit
/// holds when one of its versions holds, and each version is judged against its own stamp, guard and entries.
fn analyse(cx: &Judged<'_>, view: &View, current: &Current) -> Vec<(String, String)> {
    let mut affected = Vec::new();
    for unit in cx.roster {
        let versions: Vec<Vec<String>> = view
            .units
            .get(unit)
            .into_iter()
            .flatten()
            .map(|version| version_reasons(cx, view, current, version))
            .collect();
        if versions.is_empty() {
            affected.push((unit.clone(), NEW.to_owned()));
        } else if versions.iter().all(|reasons| !reasons.is_empty()) {
            affected.push((unit.clone(), summary(&versions[0])));
        }
    }
    affected
}

/// Why one version no longer holds, in the order spec 3.9 gives: its age, its environment, its inputs and its outputs.
fn version_reasons(
    cx: &Judged<'_>,
    view: &View,
    current: &Current,
    version: &Version,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if cx.max_age > 0 && cx.now.saturating_sub(version.created) > cx.max_age {
        reasons.push("proof expired".to_owned());
    }
    if version.guard != cx.guard {
        reasons.push("the environment changed".to_owned());
    }
    for &index in &version.inputs {
        let input = &view.table[index as usize];
        if !current.holds(input) {
            reasons.push(format!("{} changed", safe(&input.path)));
        }
    }
    for &index in &version.outputs {
        let output = &view.table[index as usize];
        if !current.holds(output) {
            let verb = if current.absent(output) {
                "missing"
            } else {
                "changed"
            };
            reasons.push(format!("output {} {verb}", safe(&output.path)));
        }
    }
    reasons
}

/// The reason a unit prints: its first reason, and how many more it has (spec 3.9).
fn summary(reasons: &[String]) -> String {
    match reasons.split_first() {
        Some((first, [])) => first.clone(),
        Some((first, rest)) => format!("{first} (+{} more)", rest.len()),
        None => String::new(),
    }
}

/// Step E11 (spec 3.10): a unit with a version that left the roster while its file stays. The first in key order is
/// named.
fn leftover(cx: &Judged<'_>, view: &View) -> Option<String> {
    view.units.iter().find_map(|(unit, versions)| {
        let stays = !versions.is_empty()
            && cx.roster.binary_search(unit).is_err()
            && cx
                .root
                .join(unit)
                .symlink_metadata()
                .is_ok_and(|meta| meta.is_file());
        stays.then(|| {
            format!(
                "{} is no longer one of the units but still exists",
                safe(unit)
            )
        })
    })
}

/// Step E14, g2 (spec 3.10): a changed input that every roster unit with a proof reads, and whose current identity is not
/// the whole proof's. The first such path in path order is named.
fn global_change(cx: &Judged<'_>, view: &View, proof: &Proof, current: &Current) -> Option<String> {
    let proven: Vec<&Vec<Version>> = cx
        .roster
        .iter()
        .filter_map(|unit| view.units.get(unit))
        .filter(|versions| !versions.is_empty())
        .collect();
    if proven.is_empty() {
        return None;
    }
    let reads: Vec<BTreeSet<&str>> = proven
        .iter()
        .map(|versions| {
            versions
                .iter()
                .flat_map(|version| version.inputs.iter())
                .map(|&index| view.table[index as usize].path.as_str())
                .collect()
        })
        .collect();
    let mut shared: BTreeSet<&str> = reads.iter().flatten().copied().collect();
    shared.retain(|path| reads.iter().all(|read| read.contains(path)));
    shared.into_iter().find_map(|path| {
        let changed = proven
            .iter()
            .flat_map(|versions| versions.iter())
            .flat_map(|version| version.inputs.iter())
            .map(|&index| &view.table[index as usize])
            .any(|input| input.path == path && !current.holds(input));
        if !changed {
            return None;
        }
        let differs = match proof.inputs.iter().find(|input| input.path == path) {
            None => true,
            Some(input) => current.id(input) != Some(input.id.as_str()),
        };
        differs.then(|| path.to_owned())
    })
}

/// Step E15 (spec 3.10): an output of the whole proof that no roster unit's version lists must still hold.
fn output_missing(
    cx: &Judged<'_>,
    view: &View,
    proof: &Proof,
    current: &Current,
) -> Option<String> {
    let listed: BTreeSet<&str> = cx
        .roster
        .iter()
        .filter_map(|unit| view.units.get(unit))
        .flatten()
        .flat_map(|version| version.outputs.iter())
        .map(|&index| view.table[index as usize].path.as_str())
        .collect();
    proof.outputs.iter().find_map(|output| {
        if listed.contains(output.path.as_str()) || current.holds(output) {
            return None;
        }
        let verb = if current.absent(output) {
            "is missing"
        } else {
            "is changed"
        };
        Some(format!("output {} {verb}", safe(&output.path)))
    })
}

/// The counts a skip names, and whether it drops versions of units that left the roster (spec 3.10, E16).
fn skipped(cx: &Judged<'_>, view: &View) -> Skipped {
    let mut inputs: BTreeSet<u32> = BTreeSet::new();
    for unit in cx.roster {
        for version in view.units.get(unit).into_iter().flatten() {
            inputs.extend(version.inputs.iter().copied());
        }
    }
    let drop = view
        .units
        .iter()
        .any(|(unit, versions)| !versions.is_empty() && cx.roster.binary_search(unit).is_err());
    Skipped {
        units: cx.roster.len(),
        inputs: inputs.len(),
        drop,
    }
}

/// Settles a skip that drops versions (spec 3.10, E16). Under the suite lock the decision is judged again. When it still
/// skips, the versions go and the skip stands (`None`). When it does not, the decision the lock reads is returned for the
/// run to take. A busy lock leaves the skip standing without a write.
pub(crate) fn settle(
    cx: &RunCx<'_>,
    pending: &Pending,
    lookup: &Lookup,
    store: &Path,
    key: &str,
    max_age: u64,
) -> Option<Decision> {
    let judged = Judged::new(cx, pending, &lookup.proofs, max_age);
    let mut later = None;
    let settled = bundle::drop_stale(store, pending, key, |view| {
        let verdict = judge(&judged, view);
        let skips = matches!(verdict.decision, Decision::Skip(_));
        later = Some(verdict.decision);
        skips
    });
    match settled {
        Settled::Declined => later,
        Settled::Written | Settled::Busy | Settled::Failed => None,
    }
}

/// The skip line (spec 3.12). It keeps the key the legacy skip line keeps, so the MCP explain parser reads it.
pub(crate) fn skip_line(key: &str, skip: &Skipped) -> String {
    format!(
        "stoop: skip {key}: no tracked input changed ({} units, {} inputs)",
        skip.units, skip.inputs
    )
}

/// The lines explain prints after a full command's decision, for steps E10 to E18 (spec 3.12): the residue when it is known
/// and not empty (spec 3.8), the tracked line, and then the affected units. The decision line came first.
pub(crate) fn explain_after(
    store: &Path,
    id: &str,
    units: &[String],
    key: &str,
    affected: Option<&[(String, String)]>,
) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some((count, paths)) = bundle::known_residue(store, id, key) {
        lines.push(residue::line(count, &paths));
    }
    lines.push(attribution::tracked(store, id, units, key));
    for (unit, why) in affected.unwrap_or_default().iter().take(NAMED) {
        lines.push(format!("stoop: affected {}: {why}", safe(unit)));
    }
    let more = affected.map_or(0, <[_]>::len).saturating_sub(NAMED);
    if more > 0 {
        lines.push(format!("stoop: affected: (+{more} more)"));
    }
    lines
}

/// The disagreement check (spec 3.10, E1): a full command that fails while every unit's proof held disables the suite.
pub(crate) fn disagree(store: &Path, pending: &Pending, key: &str, quiet: bool) {
    let id = pending.suite();
    match bundle::disable_full(store, pending, key, DISAGREEMENT) {
        Ok(true) => {
            if !quiet {
                eprintln!(
                    "stoop: suite {id} disabled: {DISAGREEMENT}; run 'stoop forget --units {id}' after fixing it"
                );
            }
        }
        Ok(false) => {}
        Err(_) => {
            // The state could not be stored, so the suite's proofs go, as an attribution pass removes them.
            let removed = bundle::forget(store, id).is_ok();
            if !quiet {
                let rest = if removed {
                    "its unit proofs are removed"
                } else {
                    "its unit proofs could not be removed either"
                };
                eprintln!("stoop: suite {id} could not store that it is disabled; {rest}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_switch_is_on_for_a_value_that_is_not_falsy() {
        for value in ["1", "yes", "on", "x"] {
            assert!(on(OsStr::new(value)), "{value}");
        }
        for value in ["", "0", " FALSE ", "no", "Off"] {
            assert!(!on(OsStr::new(value)), "{value:?}");
        }
        #[cfg(unix)]
        assert!(!on(std::os::unix::ffi::OsStrExt::from_bytes(b"\xff")));
    }

    #[test]
    fn a_unit_names_its_first_reason_and_counts_the_rest() {
        assert_eq!(
            summary(&["tests/a.t changed".to_owned()]),
            "tests/a.t changed"
        );
        let reasons = [
            "proof expired".to_owned(),
            "the environment changed".to_owned(),
            "tests/a.t changed".to_owned(),
        ];
        assert_eq!(summary(&reasons), "proof expired (+2 more)");
    }

    #[test]
    fn explain_names_at_most_twenty_affected_units_and_counts_the_rest() {
        let affected: Vec<(String, String)> = (0..23)
            .map(|n| (format!("tests/{n:02}.t"), "new".to_owned()))
            .collect();
        let dir = std::env::temp_dir();
        let lines = explain_after(&dir, "0", &[], "key", Some(&affected));
        let named: Vec<&String> = lines
            .iter()
            .filter(|line| line.contains("affected tests/"))
            .collect();
        assert_eq!(named.len(), NAMED);
        assert_eq!(
            lines.last().map(String::as_str),
            Some("stoop: affected: (+3 more)")
        );
    }

    #[test]
    fn a_skip_line_keeps_the_key_at_its_start() {
        let skip = Skipped {
            units: 3,
            inputs: 7,
            drop: false,
        };
        assert_eq!(
            skip_line("key", &skip),
            "stoop: skip key: no tracked input changed (3 units, 7 inputs)"
        );
    }
}
