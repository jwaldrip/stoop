//! The decision engine (spec 3.9 and 3.10). With `STOOP_SPLIT` on, a changed run of a hooked suite decides from the unit
//! proofs in its bundle which units are affected. A run with none skips (E16). A run whose affected units are the whole
//! roster is an attribution pass that keeps versions (E17), and any other affected set is a subset, one launch per unit
//! (E18). Both run under the suite lock, which decides again before it launches (`subset`). Every other decision takes
//! the full command, which is the switch-off path, with the reason the spec gives. Explain takes the same decision
//! without the suite lock and prints the same lines (spec 3.12). Nothing here writes, except `disagree`, which runs
//! under the suite lock.

use super::attribution;
use super::bundle::{self, LaunchGuard, Pending, Version, View};
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
use std::time::{Duration, Instant};
use std::{fs, io};

/// How many affected units explain names before it counts the rest (spec 3.12).
pub(super) const NAMED: usize = 20;

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
    /// Steps E1 to E7: the switch-off path decides, with the reason it gives. A forced run, or a run whose screen refuses,
    /// keeps that path, which is the full command.
    Legacy,
    /// Step E8 for a disabled suite: the full command runs, for this reason.
    Disabled(String),
    /// Steps E10 to E15: the full command runs. `None` keeps the legacy reason.
    Full(Option<String>),
    /// Step E16: no unit is affected, so the run skips.
    Skip(Skipped),
    /// Step E17: every unit of the roster is affected, so the attribution pass runs and keeps versions.
    Pass(Plan),
    /// Step E18: some units are affected, so one launch runs for each of them, and the rest keep their proofs.
    Subset(Plan),
}

/// A skip, with the counts its line names (spec 3.12).
pub(crate) struct Skipped {
    /// The roster's units.
    pub(crate) units: usize,
    /// The distinct inputs that the units' proofs name.
    pub(crate) inputs: usize,
}

/// The affected set of a decision that launches units (spec 3.9, E17 and E18), in roster order.
pub(crate) struct Plan {
    /// The roster's units.
    pub(crate) units: usize,
    /// The distinct inputs that the roster's proofs name, which the subset header counts.
    pub(crate) inputs: usize,
    /// The affected units, in roster order.
    pub(crate) affected: Vec<Affected>,
}

/// One affected unit (spec 3.9): its reason, which the header and explain name, and the inputs that changed for its
/// proof, which `STOOP_CHANGED_INPUTS` names for its launch (spec 3.11). A unit that has no proof changed no input.
pub(crate) struct Affected {
    pub(crate) unit: String,
    pub(crate) why: String,
    pub(crate) changed: Vec<String>,
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

/// The verdict of a locked run that keeps the full command for no engine reason: the legacy path decides (spec 3.10).
pub(super) fn unrun() -> Verdict {
    Verdict {
        decision: Decision::Full(None),
        affected: None,
        clean: false,
    }
}

/// What a decision reads besides the bundle: the roster, the candidate whole proofs, the environment now and the clock.
pub(super) struct Judged<'a> {
    root: &'a Path,
    suite: &'a str,
    roster: &'a [String],
    proofs: &'a [Proof],
    guard: String,
    max_age: u64,
    now: u64,
}

impl<'a> Judged<'a> {
    pub(super) fn new(
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
    // E9: no roster unit has a proof yet. The full command decides the verdict, and its passing run learns the unit
    // proofs (spec 3.10, completion; issue #84). No attribution pass may decide here: its verdict is not the full one.
    if cx.roster.iter().all(|unit| {
        view.units
            .get(unit)
            .is_none_or(|versions| versions.is_empty())
    }) {
        return verdict(Decision::Full(None), None, false);
    }
    let proof = cx.proofs.iter().find(|proof| proof.digest() == view.whole);
    // The roster's entries and the whole proof's inputs are identified together, so each path is read once.
    let entries: Vec<&Input> = checked(cx, view)
        .into_iter()
        .chain(proof.iter().flat_map(|proof| proof.inputs.iter()))
        .collect();
    let current = Current::of(cx.root, &entries);
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
    // The roster rule (PR 86 review round 4): the units the decision trusts must be the units the whole command runs.
    if let Some(reason) = roster_change(cx, view, proof) {
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
    let shown = Some(pairs(&affected));
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
    // The whole proof's inputs (PR 86 review round 4): a change to any of them takes the full form, whichever unit reads it.
    if let Some(reason) = whole_change(cx, proof, &current) {
        return verdict(Decision::Full(Some(reason)), shown, clean);
    }
    if affected.is_empty() {
        return verdict(Decision::Skip(skipped(cx, view)), shown, clean);
    }
    // E17 and E18: the affected units launch one at a time. Units that are all affected make the attribution pass.
    let whole = affected.len() == cx.roster.len();
    let plan = Plan {
        units: cx.roster.len(),
        inputs: skipped(cx, view).inputs,
        affected,
    };
    verdict(
        if whole {
            Decision::Pass(plan)
        } else {
            Decision::Subset(plan)
        },
        shown,
        clean,
    )
}

/// The decision of a locked run that launches units (spec 3.10). `Ok` carries the plan for E17 and E18. `Err` carries
/// the verdict of every other decision, which the run takes as it stands.
pub(super) fn judge_units(cx: &Judged<'_>, view: &View) -> Result<Plan, Box<Verdict>> {
    let verdict = judge(cx, view);
    match verdict.decision {
        Decision::Pass(plan) | Decision::Subset(plan) => Ok(plan),
        decision => Err(Box::new(Verdict {
            decision,
            affected: verdict.affected,
            clean: verdict.clean,
        })),
    }
}

/// Completion (spec 3.10, W7-3), judged under the suite lock after a recorded full run. The run learns when the residue
/// it left is unknown or not empty, and then launches each roster unit with no valid version, in roster order. It
/// declines when the suite is disabled or the residue is known and empty, so no learning is needed.
pub(super) fn learn(cx: &Judged<'_>, view: &View) -> Result<Vec<String>, &'static str> {
    if view.disabled.is_some() {
        return Err("the suite is disabled");
    }
    // The residue that completion measures belongs to the whole proof the bundle holds. A bundle that holds another proof
    // was written by another run, so this run learns nothing (spec 3.10, PR 86 review round 1).
    if !cx.proofs.iter().any(|proof| proof.digest() == view.whole) {
        return Err("the bundle holds another whole proof");
    }
    let wanted = view.residue.as_ref().is_none_or(|(count, _)| *count > 0);
    if !wanted {
        return Err("the residue is known and empty");
    }
    let current = Current::of(cx.root, &checked(cx, view));
    Ok(analyse(cx, view, &current)
        .into_iter()
        .map(|affected| affected.unit)
        .collect())
}

/// Whether every roster unit holds a valid version now, which lets the residue be confirmed (spec 3.8, point iii).
pub(super) fn holds(cx: &Judged<'_>, view: &View) -> bool {
    let current = Current::of(cx.root, &checked(cx, view));
    analyse(cx, view, &current).is_empty()
}

fn verdict(decision: Decision, affected: Option<Vec<(String, String)>>, clean: bool) -> Verdict {
    Verdict {
        decision,
        affected,
        clean,
    }
}

/// The reason and unit of each affected unit, as explain names them.
fn pairs(affected: &[Affected]) -> Vec<(String, String)> {
    affected
        .iter()
        .map(|affected| (affected.unit.clone(), affected.why.clone()))
        .collect()
}

/// The roster rule (PR 86 review round 4). The units the decision trusts must be the units the whole command runs, and
/// the whole command must read each of them through its own file. A departed unit, a roster unit with no proof and a
/// roster unit that the whole command does not read each take the full form, and each is named. A departed unit whose
/// path still exists is named by `leftover` before this check (E11).
fn roster_change(cx: &Judged<'_>, view: &View, proof: &Proof) -> Option<String> {
    if let Some(reason) = view.units.iter().find_map(|(unit, versions)| {
        (!versions.is_empty() && cx.roster.binary_search(unit).is_err()).then(|| {
            format!(
                "{} left the roster since its proof was recorded",
                safe(unit)
            )
        })
    }) {
        return Some(reason);
    }
    cx.roster.iter().find_map(|unit| {
        if view
            .units
            .get(unit)
            .is_none_or(|versions| versions.is_empty())
        {
            return Some(format!("{} has no unit proof yet", safe(unit)));
        }
        let read = proof.inputs.iter().any(|input| {
            input.path == *unit && (input.id.starts_with("f:") || input.id.starts_with("x:"))
        });
        (!read).then(|| format!("the full command does not read {}", safe(unit)))
    })
}

/// The whole proof's inputs must hold (spec 3.10, PR 86 review round 4). The whole command read each of them, and a
/// unit's read cannot tell its use from the runner's own, so a change to one takes the full form. The one exception is
/// the content of a roster unit's own regular file: that unit's own run is the use the trace premise allows, and its
/// proof covers the change. Inputs are judged in path order, and the first difference is named as `input::verify`
/// words it.
fn whole_change(cx: &Judged<'_>, proof: &Proof, current: &Current) -> Option<String> {
    let mut inputs: Vec<&Input> = proof.inputs.iter().collect();
    inputs.sort_by(|a, b| a.path.cmp(&b.path));
    inputs.into_iter().find_map(|input| {
        if current.holds(input) {
            return None;
        }
        let own_content = cx.roster.binary_search(&input.path).is_ok()
            && (input.id.starts_with("f:") || input.id.starts_with("x:"))
            && is_regular(cx.root, &input.path);
        if own_content {
            return None;
        }
        let why = match current.id(input) {
            None => "unreadable",
            Some("a") => "removed",
            Some(_) if input.id == "a" => "appeared",
            Some(_) => "changed",
        };
        Some(format!("{} {why}", safe(&input.path)))
    })
}

/// Whether a root-relative key is a regular file now. A link is judged as a link, not by its target (spec 3.10, rv32).
fn is_regular(root: &Path, key: &str) -> bool {
    fs::symlink_metadata(from_key(root, key)).is_ok_and(|meta| meta.is_file())
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
fn analyse(cx: &Judged<'_>, view: &View, current: &Current) -> Vec<Affected> {
    let mut affected = Vec::new();
    for unit in cx.roster {
        let judged: Vec<(Vec<String>, Vec<String>)> = view
            .units
            .get(unit)
            .into_iter()
            .flatten()
            .map(|version| version_reasons(cx, view, current, version))
            .collect();
        if judged.is_empty() {
            affected.push(Affected {
                unit: unit.clone(),
                why: NEW.to_owned(),
                changed: Vec::new(),
            });
        } else if judged.iter().all(|(reasons, _)| !reasons.is_empty()) {
            let mut changed: Vec<String> = judged
                .iter()
                .flat_map(|(_, changed)| changed.iter().cloned())
                .collect();
            changed.sort();
            changed.dedup();
            affected.push(Affected {
                unit: unit.clone(),
                why: summary(&judged[0].0),
                changed,
            });
        }
    }
    affected
}

/// Why one version no longer holds, in the order spec 3.9 gives: its age, its environment, its inputs and its outputs.
/// It also returns the inputs that changed, as root-relative keys (spec 3.11).
fn version_reasons(
    cx: &Judged<'_>,
    view: &View,
    current: &Current,
    version: &Version,
) -> (Vec<String>, Vec<String>) {
    let mut reasons = Vec::new();
    let mut changed = Vec::new();
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
            changed.push(input.path.clone());
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
    (reasons, changed)
}

/// The reason a unit prints: its first reason, and how many more it has (spec 3.9).
fn summary(reasons: &[String]) -> String {
    match reasons.split_first() {
        Some((first, [])) => first.clone(),
        Some((first, rest)) => format!("{first} (+{} more)", rest.len()),
        None => String::new(),
    }
}

/// Step E11 (spec 3.10): a unit with a version that left the roster while its path still exists, whatever its type (a
/// file, a directory or a link). A path that is gone is a removed unit (E16). The first in key order is named.
fn leftover(cx: &Judged<'_>, view: &View) -> Option<String> {
    view.units.iter().find_map(|(unit, versions)| {
        let stays = !versions.is_empty()
            && cx.roster.binary_search(unit).is_err()
            && cx.root.join(unit).symlink_metadata().is_ok();
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

/// The counts a skip names (spec 3.12). A skip never drops a version: a version of a unit that left the roster takes
/// the full form before any skip (`judge`).
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
    Skipped {
        units: cx.roster.len(),
        inputs,
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

/// The line explain prints for a full command whose passing run learns the unit proofs (spec 3.12, W7-3). It reads the
/// suite as it stands and writes nothing. A unit with no version leaves the residue unknown after the run, so the line is
/// exact for that case. Otherwise the current residue stands in for the residue that the run measures afterwards.
pub(crate) fn learn_line(
    cx: &RunCx<'_>,
    config: &Config,
    pending: &Pending,
    lookup: &Lookup,
    store: &Path,
    key: &str,
    max_age: u64,
) -> Option<String> {
    let hook = cx.hook.as_ref()?;
    // An untraced run learns nothing. `screen` names that refusal first, so this reads no environment variable itself.
    if let Err(attribution::Refusal::Off) =
        attribution::screen(cx, hook, config, lookup, Ok(pending))
    {
        return None;
    }
    attribution::roster_screen(cx, hook, config, pending).ok()?;
    if !bundle::writable(store) {
        return None;
    }
    let judged = Judged::new(cx, pending, &[], max_age);
    // A changed run records its whole proof, which leaves the residue unknown unless the bundle already holds a known
    // residue for that same proof (`record`, PR 86 review round 2). Completion then learns each unit without a valid
    // version, whatever the residue was before the run. Explain cannot tell the same-proof case before the run, so it
    // names those units here.
    let lacking = match bundle::view(store, pending, key) {
        None => pending.units().len(),
        Some(view) => {
            if view.disabled.is_some() {
                return None;
            }
            let current = Current::of(cx.root, &checked(&judged, &view));
            analyse(&judged, &view, &current).len()
        }
    };
    (lacking > 0).then(|| {
        format!(
            "stoop: if the full command passes, would launch {lacking} units without a current proof, one launch each"
        )
    })
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
    use std::collections::BTreeMap;

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
        };
        assert_eq!(
            skip_line("key", &skip),
            "stoop: skip key: no tracked input changed (3 units, 7 inputs)"
        );
    }

    /// A skip counts the roster's inputs only (spec 3.12). A unit that left the roster adds none. Killed by counting
    /// every table entry.
    #[test]
    fn a_skip_counts_only_the_roster_units_inputs() {
        let table = vec![
            input("tests/a.t", "f:1"),
            input("src/shared.src", "f:2"),
            input("tests/gone.t", "f:3"),
            input("src/gone.src", "f:4"),
        ];
        let units = vec![
            ("tests/a.t", vec![version(1_000, vec![0, 1])]),
            ("tests/gone.t", vec![version(1_000, vec![2, 3])]),
        ];
        let (view, _) = view_of(units, table);
        let roster = vec!["tests/a.t".to_owned()];
        let skip = skipped(&judged(&roster, 0), &view);
        assert_eq!((skip.units, skip.inputs), (1, 2));
        assert_eq!(
            skip_line("key", &skip),
            "stoop: skip key: no tracked input changed (1 units, 2 inputs)"
        );
    }

    fn input(path: &str, id: &str) -> Input {
        Input {
            path: path.to_owned(),
            id: id.to_owned(),
            oid: None,
            oid_basis: None,
        }
    }

    /// A view whose table is `table` and whose units are `units`, with every table entry as it is now on disk.
    fn view_of(units: Vec<(&str, Vec<Version>)>, table: Vec<Input>) -> (View, Current) {
        let current = Current(
            table
                .iter()
                .map(|entry| (entry.path.clone(), [Some(entry.id.clone()), None]))
                .collect(),
        );
        let view = View {
            whole: "whole".to_owned(),
            disabled: None,
            table,
            units: units
                .into_iter()
                .map(|(unit, versions)| (unit.to_owned(), versions))
                .collect(),
            residue: None,
        };
        (view, current)
    }

    fn version(created: u64, inputs: Vec<u32>) -> Version {
        Version {
            created,
            guard: "g".to_owned(),
            inputs,
            outputs: Vec::new(),
        }
    }

    fn judged<'a>(roster: &'a [String], max_age: u64) -> Judged<'a> {
        Judged {
            root: Path::new("."),
            suite: "suite",
            roster,
            proofs: &[],
            guard: "g".to_owned(),
            max_age,
            now: 1_000,
        }
    }

    fn proof_of(inputs: Vec<Input>) -> Proof {
        Proof {
            created: 1,
            argv: Vec::new(),
            cwd: None,
            scope: None,
            provenance: None,
            env: BTreeMap::new(),
            inputs,
            outputs: Vec::new(),
            removed: Vec::new(),
            ignore: None,
            priors: None,
            unplannable: Vec::new(),
            probes: BTreeMap::new(),
            env_excluded: Vec::new(),
        }
    }

    /// Every input the whole proof holds must hold, whichever unit reads it (PR 86 review round 4). A changed input of
    /// the full command takes the full form, so no unit's read can excuse it.
    #[test]
    fn a_changed_whole_proof_input_takes_the_full_form() {
        let table = vec![input("tests/a.t", "f:1"), input("src/shared.src", "f:2")];
        let (_, mut current) =
            view_of(vec![("tests/a.t", vec![version(1_000, vec![0, 1])])], table);
        let roster = vec!["tests/a.t".to_owned()];
        let proof = proof_of(vec![
            input("tests/a.t", "f:1"),
            input("src/shared.src", "f:2"),
        ]);
        current
            .0
            .insert("src/shared.src".to_owned(), [Some("f:9".to_owned()), None]);
        assert_eq!(
            whole_change(&judged(&roster, 0), &proof, &current).as_deref(),
            Some("src/shared.src changed")
        );
    }

    /// The reason names how the input changed, as `input::verify` words it.
    #[test]
    fn a_whole_proof_input_names_how_it_changed() {
        let roster: Vec<String> = Vec::new();
        let cx = judged(&roster, 0);
        let proof = proof_of(vec![
            input("src/a.src", "f:1"),
            input("src/b.src", "a"),
            input("src/c.src", "f:3"),
        ]);
        let mut current = Current(HashMap::new());
        current.0.insert("src/a.src".to_owned(), [None, None]);
        current
            .0
            .insert("src/b.src".to_owned(), [Some("f:4".to_owned()), None]);
        current
            .0
            .insert("src/c.src".to_owned(), [Some("a".to_owned()), None]);
        assert_eq!(
            whole_change(&cx, &proof, &current).as_deref(),
            Some("src/a.src unreadable")
        );
        current
            .0
            .insert("src/a.src".to_owned(), [Some("f:1".to_owned()), None]);
        assert_eq!(
            whole_change(&cx, &proof, &current).as_deref(),
            Some("src/b.src appeared")
        );
        current
            .0
            .insert("src/b.src".to_owned(), [Some("a".to_owned()), None]);
        assert_eq!(
            whole_change(&cx, &proof, &current).as_deref(),
            Some("src/c.src removed")
        );
    }

    /// A roster unit's own regular file may change in content, because its own proof covers it (spec 3.10, PR 86
    /// review round 4). The same file as a link is a change.
    #[cfg(unix)]
    #[test]
    fn a_roster_units_own_file_may_change_in_content_but_not_in_kind() {
        let dir = std::env::temp_dir().join(format!("stoop-engine-own-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("tests")).unwrap();
        let roster = vec!["tests/a.t".to_owned()];
        let cx = Judged {
            root: dir.as_path(),
            ..judged(&roster, 0)
        };
        let proof = proof_of(vec![input("tests/a.t", "f:1")]);
        let mut current = Current(HashMap::new());
        fs::write(dir.join("tests/a.t"), "changed\n").unwrap();
        current
            .0
            .insert("tests/a.t".to_owned(), [Some("f:2".to_owned()), None]);
        assert_eq!(whole_change(&cx, &proof, &current), None);
        fs::remove_file(dir.join("tests/a.t")).unwrap();
        std::os::unix::fs::symlink("elsewhere", dir.join("tests/a.t")).unwrap();
        current
            .0
            .insert("tests/a.t".to_owned(), [Some("f:2".to_owned()), None]);
        assert_eq!(
            whole_change(&cx, &proof, &current).as_deref(),
            Some("tests/a.t changed")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The roster rule (PR 86 review round 4): a departed unit whose path is gone, a roster unit with no proof and a
    /// roster unit that the full command does not read each take the full form, and each is named.
    #[test]
    fn the_roster_rule_names_each_unit_the_full_command_must_run() {
        let roster = vec!["tests/a.t".to_owned(), "tests/b.t".to_owned()];
        let read = proof_of(vec![input("tests/a.t", "f:1"), input("tests/b.t", "f:3")]);
        let (view, _) = view_of(
            vec![
                ("tests/a.t", vec![version(1_000, vec![0])]),
                ("tests/gone.t", vec![version(1_000, vec![1])]),
            ],
            vec![input("tests/a.t", "f:1"), input("tests/gone.t", "f:2")],
        );
        assert_eq!(
            roster_change(&judged(&roster, 0), &view, &read).as_deref(),
            Some("tests/gone.t left the roster since its proof was recorded")
        );
        let (view, _) = view_of(
            vec![("tests/a.t", vec![version(1_000, vec![0])])],
            vec![input("tests/a.t", "f:1")],
        );
        assert_eq!(
            roster_change(&judged(&roster, 0), &view, &read).as_deref(),
            Some("tests/b.t has no unit proof yet")
        );
        let (view, _) = view_of(
            vec![
                ("tests/a.t", vec![version(1_000, vec![0])]),
                ("tests/b.t", vec![version(1_000, vec![0])]),
            ],
            vec![input("tests/a.t", "f:1")],
        );
        assert_eq!(
            roster_change(
                &judged(&roster, 0),
                &view,
                &proof_of(vec![input("tests/a.t", "f:1")])
            )
            .as_deref(),
            Some("the full command does not read tests/b.t")
        );
        assert_eq!(roster_change(&judged(&roster, 0), &view, &read), None);
    }

    /// A unit whose own file the whole proof records only as absent is not read by the whole command (PR 86 review round
    /// 4): the roster rule needs a regular file or an executable in the whole proof.
    #[test]
    fn a_unit_whose_own_file_the_whole_proof_records_as_absent_is_not_read() {
        let roster = vec!["tests/a.t".to_owned()];
        let (view, _) = view_of(
            vec![("tests/a.t", vec![version(1_000, vec![0])])],
            vec![input("tests/a.t", "f:1")],
        );
        let stat_only = proof_of(vec![input("tests/a.t", "a")]);
        assert_eq!(
            roster_change(&judged(&roster, 0), &view, &stat_only).as_deref(),
            Some("the full command does not read tests/a.t")
        );
    }

    #[test]
    fn learn_declines_a_bundle_that_holds_another_whole_proof() {
        let table = vec![input("tests/a.t", "f:1")];
        let (view, _) = view_of(vec![("tests/a.t", vec![version(1_000, vec![0])])], table);
        let roster = vec!["tests/a.t".to_owned(), "tests/b.t".to_owned()];
        assert!(learn(&judged(&roster, 0), &view).is_err());
    }

    #[test]
    fn learn_declines_when_the_residue_is_known_and_empty() {
        let roster = vec!["tests/a.t".to_owned()];
        let (mut view, _) = view_of(Vec::new(), Vec::new());
        let proof = Proof {
            created: 1,
            argv: Vec::new(),
            cwd: None,
            scope: None,
            provenance: None,
            env: BTreeMap::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            removed: Vec::new(),
            ignore: None,
            priors: None,
            unplannable: Vec::new(),
            probes: BTreeMap::new(),
            env_excluded: Vec::new(),
        };
        view.whole = proof.digest();
        let proofs = [proof];
        let cx = Judged {
            proofs: &proofs,
            ..judged(&roster, 0)
        };
        view.residue = Some((0, Vec::new()));
        assert_eq!(learn(&cx, &view), Err("the residue is known and empty"));
        view.residue = None;
        assert!(learn(&cx, &view).is_ok());
    }

    #[test]
    fn a_residue_is_confirmed_only_when_every_roster_unit_holds_a_version() {
        let table = vec![input("tests/a.t", "f:1")];
        let (view, _) = view_of(vec![("tests/a.t", vec![version(1_000, vec![0])])], table);
        let roster = vec!["tests/a.t".to_owned(), "tests/b.t".to_owned()];
        assert!(!holds(&judged(&roster, 0), &view));
    }
}
