//! The decision engine (spec 3.9 and 3.10). With `STOOP_SPLIT` on, a changed run of a hooked suite decides from the unit
//! proofs in its bundle which units are affected. A run with none skips (E16). A run whose affected units are the whole
//! roster is an attribution pass that keeps versions (E17), and any other affected set is a subset, one launch per unit
//! (E18). Both run under the suite lock, which decides again before it launches (`subset`). Every other decision takes
//! the full command, which is the switch-off path, with the reason the spec gives. Explain takes the same decision
//! without the suite lock and prints the same lines (spec 3.12). Nothing here writes, except `settle` and `disagree`,
//! which run under the suite lock.

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
use std::collections::{BTreeMap, BTreeSet, HashMap};
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
    /// Steps E1 to E9: the switch-off path decides. An attribution pass starts when no unit has a proof yet.
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
    /// Whether the bundle holds versions of units that left the roster. A skip drops them under the suite lock.
    pub(crate) drop: bool,
}

/// The affected set of a decision that launches units (spec 3.9, E17 and E18), in roster order.
pub(crate) struct Plan {
    /// The roster's units.
    pub(crate) units: usize,
    /// The distinct inputs that the roster's proofs name, which the subset header counts.
    pub(crate) inputs: usize,
    /// The affected units, in roster order.
    pub(crate) affected: Vec<Affected>,
    /// The names that the listing check excused through the affected units' stored proofs (spec 3.10). Each needs a new
    /// proof of this run that reads it by content, or the run has no verdict.
    pub(crate) excused: Vec<Excused>,
}

/// One affected unit (spec 3.9): its reason, which the header and explain name, and the inputs that changed for its
/// proof, which `STOOP_CHANGED_INPUTS` names for its launch (spec 3.11). A unit that has no proof changed no input.
pub(crate) struct Affected {
    pub(crate) unit: String,
    pub(crate) why: String,
    pub(crate) changed: Vec<String>,
}

/// A name that an affected unit's stored proof named, and that the listing of a directory in the whole proof holds as an
/// added name (spec 3.10, rv32 and rv34). `units` are the affected units whose stored proofs named it.
pub(crate) struct Excused {
    pub(crate) path: String,
    pub(crate) units: Vec<String>,
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
    // E16 to E18 each need every listing that the whole proof holds to be as it was (see `listings_change`).
    let excused = match listings_change(cx, view, &current, proof, &affected) {
        Ok(excused) => excused,
        Err(reason) => return verdict(Decision::Full(Some(reason)), shown, clean),
    };
    if affected.is_empty() {
        return verdict(Decision::Skip(skipped(cx, view)), shown, clean);
    }
    // E17 and E18: the affected units launch one at a time. Units that are all affected make the attribution pass.
    let whole = affected.len() == cx.roster.len();
    let plan = Plan {
        units: cx.roster.len(),
        inputs: skipped(cx, view).inputs,
        affected,
        excused,
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
pub(super) fn judge_units(cx: &Judged<'_>, view: &View) -> Result<Plan, Verdict> {
    let verdict = judge(cx, view);
    match verdict.decision {
        Decision::Pass(plan) | Decision::Subset(plan) => Ok(plan),
        decision => Err(Verdict {
            decision,
            affected: verdict.affected,
            clean: verdict.clean,
        }),
    }
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

/// The listing check of spec 3.10, which runs before the skip (E16) and before a subset or an attribution pass (E17 and
/// E18). Every listing that the whole proof holds must be as it was, or its difference must be excused as `listing_holds`
/// allows. The residue leaves out the listings of the catalog walk, so a name that a walked directory gained or lost is
/// seen by no unit's proof, unless a unit lists that directory itself. The whole proof's own `dl:` entries see it. The
/// first directory that is not excused is named in path order, as the legacy lookup names a changed input. When every
/// difference is excused, the names that the stored proofs of affected units excused are returned, so that the run can
/// see a new proof read each one by content (spec 3.10, rv34).
fn listings_change(
    cx: &Judged<'_>,
    view: &View,
    current: &Current,
    proof: &Proof,
    affected: &[Affected],
) -> Result<Vec<Excused>, String> {
    let mut entries: Vec<&Input> = proof
        .inputs
        .iter()
        .chain(&proof.outputs)
        .filter(|input| input.id.starts_with("dl:"))
        .collect();
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    // A run usually finds every listing as it was, and then no excuse is read.
    let same = par_map(&entries, |input| listing_matches(cx.root, input));
    if same.iter().all(|&same| same) {
        return Ok(Vec::new());
    }
    let recorded: BTreeSet<&str> = proof
        .inputs
        .iter()
        .chain(&proof.outputs)
        .filter(|input| input.id != "a")
        .map(|input| input.path.as_str())
        .collect();
    let valid = covered_reads(cx, view, current, &recorded);
    let rerun = rerun_reads(view, affected, &recorded);
    let mut covered = valid.clone();
    covered.extend(rerun.keys().cloned());
    let moved = par_map(&entries, |input| {
        !listing_holds(cx.root, view, cx.roster, input, proof, &covered)
    });
    if let Some(reason) = entries
        .iter()
        .zip(moved)
        .find_map(|(input, moved)| moved.then(|| format!("{} changed", safe(&input.path))))
    {
        return Err(reason);
    }
    // The root never excuses a name, so only names under a listed directory can be excused. A name is excused here
    // when no valid proof reads it, the whole proof did not hold it, and it is a regular file now.
    let dirs: BTreeSet<&str> = entries
        .iter()
        .map(|input| input.path.as_str())
        .filter(|dir| !matches!(*dir, "" | "."))
        .collect();
    Ok(rerun
        .into_iter()
        .filter(|(path, _)| {
            !valid.contains(path)
                && !recorded.contains(path.as_str())
                && Path::new(path)
                    .parent()
                    .and_then(Path::to_str)
                    .is_some_and(|dir| dirs.contains(dir))
                && is_regular(cx.root, path)
        })
        .map(|(path, units)| Excused { path, units })
        .collect())
}

/// Whether the names that a listing holds now give the digest that the whole proof records for it (spec 3.10, E16).
fn listing_matches(root: &Path, recorded: &Input) -> bool {
    match (
        recorded.id.strip_prefix("dl:"),
        listed(&from_key(root, &recorded.path)),
    ) {
        (Some(digest), Some(mut names)) => list_hash_of_names(&mut names) == digest,
        _ => false,
    }
}

/// The paths that a valid version of a roster unit reads by content, and that the whole proof did not hold as present
/// (spec 3.10, E16). A file such as a unit's flag can appear after the whole proof. The unit's version verified its
/// identity, so the unit's own proof covers the file. A version that does not hold covers nothing, and neither does a
/// unit that has left the roster.
fn covered_reads(
    cx: &Judged<'_>,
    view: &View,
    current: &Current,
    recorded: &BTreeSet<&str>,
) -> BTreeSet<String> {
    let mut reads = BTreeSet::new();
    for unit in cx.roster {
        for version in view.units.get(unit).into_iter().flatten() {
            if !version_reasons(cx, view, current, version).0.is_empty() {
                continue;
            }
            for &index in &version.inputs {
                let input = &view.table[index as usize];
                let content = input.id.starts_with("f:") || input.id.starts_with("x:");
                if content && !recorded.contains(input.path.as_str()) {
                    reads.insert(input.path.clone());
                }
            }
        }
    }
    reads
}

/// The paths that the stored versions of an affected roster unit name, and that the whole proof did not hold as present,
/// each with the affected units that name it (spec 3.10, E17 and E18). The unit launches in this run, and its new proof
/// decides what it reads, so a path is named whatever its kind: a flag file that the unit stats as absent is covered when
/// it appears (spec 3.10, flag files and S9). Every version of an affected unit is stale, and none is required to hold.
fn rerun_reads(
    view: &View,
    affected: &[Affected],
    recorded: &BTreeSet<&str>,
) -> BTreeMap<String, Vec<String>> {
    let mut reads: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for changed in affected {
        for version in view.units.get(&changed.unit).into_iter().flatten() {
            for &index in &version.inputs {
                let input = &view.table[index as usize];
                if !recorded.contains(input.path.as_str()) {
                    let units = reads.entry(input.path.clone()).or_default();
                    if !units.contains(&changed.unit) {
                        units.push(changed.unit.clone());
                    }
                }
            }
        }
    }
    reads
}

/// Whether a root-relative key is a regular file now. A link is judged as a link, not by its target (spec 3.10, rv32).
fn is_regular(root: &Path, key: &str) -> bool {
    fs::symlink_metadata(from_key(root, key)).is_ok_and(|meta| meta.is_file())
}

/// Whether a listing that the whole proof records still holds (spec 3.10, E16, as amended for STOP 4 and for files a
/// unit reads). The current names must give the recorded digest. If they do not, the difference must be explained
/// exactly, by three kinds of name:
///
/// - Lost names: the entries under this directory that are absent now, from two sources: the bundle's units with
///   versions (the former members of the roster), and the whole proof's own regular-file
///   entries (`f:` and `x:`).
/// - Added units: roster units under this directory that the whole proof never read, so they did not exist when it was
///   recorded. Each is valid or affected, and an affected unit launches in this run, so each is covered either way.
/// - Added files: files under this directory that a valid unit proof reads, or that an affected unit names as an input,
///   and that the whole proof does not hold (`covered_reads` and `rerun_reads`).
///
/// The root never excuses an added name. The candidate is the current names without the added names, plus the lost
/// names. It must give the recorded digest exactly, so any other added or removed name is a change.
fn listing_holds(
    root: &Path,
    view: &View,
    roster: &[String],
    recorded: &Input,
    proof: &Proof,
    covered: &BTreeSet<String>,
) -> bool {
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
    // Every entry that the whole proof read by content or by stat. A unit that existed when the proof was recorded read
    // its own file, so its path is among these.
    let read_entries: BTreeSet<&str> = proof
        .inputs
        .iter()
        .filter(|read| read.id.starts_with("f:") || read.id.starts_with("x:"))
        .map(|read| read.path.as_str())
        .collect();
    // The root never excuses an added name. Elsewhere, a roster unit that the whole proof never read did not exist when
    // the proof was recorded. Each roster unit is either valid or affected, and an affected unit launches in this run, so
    // each such unit is excused here. `judge` runs this check before both the skip and the subset.
    let excused = !matches!(recorded.path.as_str(), "" | ".");
    let added: BTreeSet<Vec<u8>> = roster
        .iter()
        .filter(|unit| excused && under(unit.as_str()) && !read_entries.contains(unit.as_str()))
        .map(String::as_str)
        .chain(covered.iter().map(String::as_str))
        .filter(|path| excused && under(path))
        .filter_map(|path| {
            Path::new(path)
                .file_name()
                .map(|name| name.as_encoded_bytes().to_vec())
        })
        .collect();
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
    // An added name is excused only while it is a regular file now (rv32): a directory, a link or another type is a change.
    let regular = regular_names(&from_key(root, &recorded.path));
    let mut candidate: Vec<Vec<u8>> = names
        .into_iter()
        .filter(|name| !(added.contains(name) && regular.contains(name)))
        .collect();
    candidate.extend(lost);
    list_hash_of_names(&mut candidate) == digest
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

/// The names of the regular files in a directory now, by each entry's own type, so a link is not one (spec 3.10, rv32).
fn regular_names(dir: &Path) -> BTreeSet<Vec<u8>> {
    let Ok(entries) = fs::read_dir(dir) else {
        return BTreeSet::new();
    };
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let regular = entry.file_type().ok()?.is_file();
            regular.then(|| entry.file_name().as_encoded_bytes().to_vec())
        })
        .collect()
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

    #[test]
    fn a_file_a_valid_roster_version_reads_is_covered() {
        let table = vec![input("tests/a.t", "f:1"), input("tests/a.flag", "f:2")];
        let (view, current) = view_of(vec![("tests/a.t", vec![version(1_000, vec![0, 1])])], table);
        let roster = vec!["tests/a.t".to_owned()];
        let covered = covered_reads(&judged(&roster, 0), &view, &current, &BTreeSet::new());
        assert!(covered.contains("tests/a.flag"), "{covered:?}");
    }

    #[test]
    fn a_file_read_only_by_an_expired_version_is_not_covered() {
        let table = vec![input("tests/a.t", "f:1"), input("tests/a.flag", "f:2")];
        let versions = vec![version(1_000, vec![0]), version(1, vec![0, 1])];
        let (view, current) = view_of(vec![("tests/a.t", versions)], table);
        let roster = vec!["tests/a.t".to_owned()];
        let covered = covered_reads(&judged(&roster, 100), &view, &current, &BTreeSet::new());
        assert!(!covered.contains("tests/a.flag"), "{covered:?}");
    }

    #[test]
    fn a_file_read_only_by_a_version_of_a_unit_that_left_the_roster_is_not_covered() {
        let table = vec![input("tests/b.t", "f:1"), input("tests/a.flag", "f:2")];
        let units = vec![
            ("tests/a.t", vec![version(1_000, vec![1])]),
            ("tests/b.t", vec![version(1_000, vec![0])]),
        ];
        let (view, current) = view_of(units, table);
        let roster = vec!["tests/b.t".to_owned()];
        let covered = covered_reads(&judged(&roster, 0), &view, &current, &BTreeSet::new());
        assert!(!covered.contains("tests/a.flag"), "{covered:?}");
    }
}
