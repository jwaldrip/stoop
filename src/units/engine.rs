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
use crate::input::{identify, list_hash_of_names, par_map, Input};
use crate::pathutil::from_key;
use crate::proof::{now, Proof};
use crate::run::{Lookup, RunCx};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{Duration, Instant};
use std::{fs, io};

/// How many affected units explain names before it counts the rest (spec 3.12).
const NAMED: usize = 20;

/// The reason of a unit that has no proof (spec 3.9).
const NEW: &str = "new";

/// The label of a suite that a full command disables when it fails while every unit's proof held (spec 3.4).
pub(crate) const DISAGREEMENT: &str = "the full command failed while every unit's proof held";

/// How long a disagreement waits for a suite lock that another run holds (spec 3.10, E1), and the pause between tries.
const DISAGREE_WAIT: Duration = Duration::from_secs(2);
const DISAGREE_STEP: Duration = Duration::from_millis(20);

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
    let current = Current::of(cx.root, &checked(cx, view));
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
    if let Some(reason) = output_missing(cx, view, proof) {
        return verdict(Decision::Full(Some(reason)), shown, clean);
    }
    if affected.is_empty() {
        // E16 also needs every listing that the whole proof holds to be as it was (see `listings_change`).
        if let Some(reason) = listings_change(cx, view, proof) {
            return verdict(Decision::Full(Some(reason)), shown, clean);
        }
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

/// Step E16 for listings (spec 3.10). A skip also needs the listings that the whole proof holds to be as they were. The
/// residue leaves out the listings of the catalog walk, so a name that a walked directory gained or lost is seen by no
/// unit's proof, unless a unit lists that directory itself. The whole proof's own `dl:` entries see it. The first changed
/// directory in path order is named, as the legacy lookup names a changed input.
fn listings_change(cx: &Judged<'_>, view: &View, proof: &Proof) -> Option<String> {
    let mut entries: Vec<&Input> = proof
        .inputs
        .iter()
        .chain(&proof.outputs)
        .filter(|input| input.id.starts_with("dl:"))
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let moved = par_map(&entries, |input| {
        !listing_holds(cx.root, view, input, proof)
    });
    entries
        .iter()
        .zip(moved)
        .find_map(|(input, moved)| moved.then(|| format!("{} changed", safe(&input.path))))
}

/// Whether a listing that the whole proof records still holds (spec 3.10, E16). The current names must give the recorded
/// digest. If they do not, the difference may only be names that were lost. The candidate is the current names plus the
/// lost names, and it must give the recorded digest exactly, so an added name, a rename, or a lost name that the proof
/// never recorded is a change.
///
/// The lost names are the entries under this directory that are absent now, from two sources: the bundle's units with
/// versions (the former members of the roster), and the whole proof's own regular-file entries (`f:` and `x:`). A
/// non-unit name that the full command only listed was never opened or stat'ed, so the whole proof holds no entry for
/// it, and the bundle holds no version for it. A non-unit file that the full command did read is in the residue, which
/// E12 refuses before this check runs. So no non-unit name can be a lost name.
fn listing_holds(root: &Path, view: &View, recorded: &Input, proof: &Proof) -> bool {
    let (Some(digest), Some(mut names)) = (
        recorded.id.strip_prefix("dl:"),
        listed(&from_key(root, &recorded.path)),
    ) else {
        return false;
    };
    if list_hash_of_names(&mut names) == digest {
        return true;
    }
    let dir = Path::new(&recorded.path);
    let under = |key: &str| Path::new(key).parent() == Some(dir);
    let lost: BTreeSet<Vec<u8>> = view
        .units
        .iter()
        .filter(|(unit, versions)| !versions.is_empty() && under(unit.as_str()))
        .map(|(unit, _)| unit.as_str())
        .chain(
            proof
                .inputs
                .iter()
                .filter(|read| read.id.starts_with("f:") || read.id.starts_with("x:"))
                .filter(|read| under(read.path.as_str()))
                .map(|read| read.path.as_str()),
        )
        .filter(|key| is_absent(&from_key(root, key)))
        .filter_map(|key| {
            Path::new(key)
                .file_name()
                .map(|name| name.as_encoded_bytes().to_vec())
        })
        .collect();
    names.extend(lost);
    list_hash_of_names(&mut names) == digest
}

/// The entry names of a listed directory as `identify` reads them. An absent path lists as no names. `None` when the
/// path cannot be listed, or is not a directory now.
fn listed(dir: &Path) -> Option<Vec<Vec<u8>>> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => fs::read_dir(dir)
            .ok()?
            .map(|entry| Some(entry.ok()?.file_name().as_encoded_bytes().to_vec()))
            .collect(),
        Err(_) if is_absent(dir) => Some(Vec::new()),
        _ => None,
    }
}

/// Whether a path does not exist, which `identify` records as `a` inside the root.
fn is_absent(path: &Path) -> bool {
    fs::symlink_metadata(path).is_err_and(|error| {
        matches!(
            error.kind(),
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
        )
    })
}

/// The inputs and outputs that a decision checks: those of each roster unit's versions. The whole proof's entries are
/// not among them. E14 and E15 identify the whole proof's entries that they name, and only those.
fn checked<'a>(cx: &Judged<'_>, view: &'a View) -> Vec<&'a Input> {
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
    entries
}

/// The current identity of each checked entry, keyed by path and by whether its recorded identity lists a directory.
/// `input::verify` uses the same key and the same identity, so a check here agrees with a check there.
struct Current(HashMap<String, [Option<String>; 2]>);

impl Current {
    fn of(root: &Path, entries: &[&Input]) -> Current {
        let keys: Vec<(&str, bool)> = entries
            .iter()
            .map(|input| (input.path.as_str(), input.id.starts_with("dl:")))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let ids = par_map(&keys, |&(path, listed)| {
            identify(&from_key(root, path), !path.starts_with('/'), listed)
        });
        let mut map: HashMap<String, [Option<String>; 2]> = HashMap::new();
        for ((path, listed), id) in keys.into_iter().zip(ids) {
            map.entry(path.to_owned()).or_default()[usize::from(listed)] = id;
        }
        Current(map)
    }

    /// The current identity of `input`, or `None` when its path cannot be read.
    fn id(&self, input: &Input) -> Option<&str> {
        let listed = usize::from(input.id.starts_with("dl:"));
        self.0.get(input.path.as_str())?[listed].as_deref()
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
    // One pass finds the paths that every proven unit reads, and the paths whose recorded identity no longer holds for
    // some proven unit. The first shared path that changed, in path order, is named if its whole-proof entry differs.
    let mut readers: HashMap<&str, usize> = HashMap::new();
    let mut changed: BTreeSet<&str> = BTreeSet::new();
    for versions in &proven {
        let mut reads: BTreeSet<&str> = BTreeSet::new();
        for input in versions
            .iter()
            .flat_map(|version| version.inputs.iter())
            .map(|&index| &view.table[index as usize])
        {
            reads.insert(input.path.as_str());
            if !current.holds(input) {
                changed.insert(input.path.as_str());
            }
        }
        for path in reads {
            *readers.entry(path).or_insert(0) += 1;
        }
    }
    let shared: BTreeSet<&str> = readers
        .into_iter()
        .filter(|&(path, count)| count == proven.len() && changed.contains(path))
        .map(|(path, _)| path)
        .collect();
    shared.into_iter().find_map(|path| {
        // The whole proof's entry is identified here, and only for a path that changed (spec 3.10, E14).
        let differs = match proof.inputs.iter().find(|input| input.path == path) {
            None => true,
            Some(input) => Current::of(cx.root, &[input]).id(input) != Some(input.id.as_str()),
        };
        differs.then(|| path.to_owned())
    })
}

/// Step E15 (spec 3.10): an output of the whole proof that no roster unit's version lists must still hold. Only such an
/// output is identified.
fn output_missing(cx: &Judged<'_>, view: &View, proof: &Proof) -> Option<String> {
    let listed: BTreeSet<&str> = cx
        .roster
        .iter()
        .filter_map(|unit| view.units.get(unit))
        .flatten()
        .flat_map(|version| version.outputs.iter())
        .map(|&index| view.table[index as usize].path.as_str())
        .collect();
    proof.outputs.iter().find_map(|output| {
        if listed.contains(output.path.as_str()) {
            return None;
        }
        let current = Current::of(cx.root, &[output]);
        if current.holds(output) {
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
    // Each table entry counts once, however many versions list it.
    let mut counted = vec![false; view.table.len()];
    let mut inputs = 0;
    for unit in cx.roster {
        for version in view.units.get(unit).into_iter().flatten() {
            for &index in &version.inputs {
                let seen = &mut counted[index as usize];
                if !*seen {
                    *seen = true;
                    inputs += 1;
                }
            }
        }
    }
    let drop = view
        .units
        .iter()
        .any(|(unit, versions)| !versions.is_empty() && cx.roster.binary_search(unit).is_err());
    Skipped {
        units: cx.roster.len(),
        inputs,
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
/// The suite lock may be held by another run, so the write waits for it for up to `DISAGREE_WAIT`. A disagreement that
/// still cannot be stored is reported. When the state could not be written, the suite's proofs are removed, so that no
/// later run skips on them.
pub(crate) fn disagree(store: &Path, pending: &Pending, key: &str, quiet: bool) {
    let id = pending.suite();
    let deadline = Instant::now() + DISAGREE_WAIT;
    let outcome = loop {
        match bundle::disable_full(store, pending, key, DISAGREEMENT) {
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(DISAGREE_STEP);
            }
            outcome => break outcome,
        }
    };
    match outcome {
        Ok(true) => {
            if !quiet {
                eprintln!(
                    "stoop: suite {id} disabled: {DISAGREEMENT}; run 'stoop forget --units {id}' after fixing it"
                );
            }
        }
        Ok(false) => {}
        Err(error) => {
            let busy = error.kind() == io::ErrorKind::WouldBlock;
            if !busy {
                let _ = bundle::forget(store, id);
            }
            if !quiet {
                let why = if busy {
                    "the suite is busy"
                } else {
                    "its state could not be written"
                };
                eprintln!(
                    "stoop: could not record that the full command failed while every unit held ({why}); run 'stoop forget --units {id}' to be safe"
                );
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
