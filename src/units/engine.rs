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
use super::expand;
use super::hook::{safe, Base, FileMode, Hook};
use super::residue;
use crate::ignore::Ignore;
use crate::input::{identify, list_hash_of_names, par_map, Input};
use crate::pathutil::from_key;
use crate::proof::{now, Proof};
use crate::run::{Lookup, RunCx, HOOK_ENV};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
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
    /// The whole proof's content inputs that changed and that no kept version reads, in path order (spec 3.10, PR 86
    /// review round 2). A new proof of this run must read each by content, or the run has no verdict.
    pub(crate) uncovered: Vec<String>,
    /// Whether the subset runs as one grouped launch of all its affected units (spec 5.1).
    pub(crate) grouped: bool,
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
    let judged = Judged::new(cx, pending, &lookup.proofs, max_age).grouping(cx, store);
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
    unit_env: &'a BTreeMap<String, String>,
    unit_env_digest: Option<String>,
    max_age: u64,
    now: u64,
    /// The grouped launch of this decision, when grouping is on and the hook takes it (spec 5.1).
    group: Option<Group>,
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
            guard: guard_now(cx, pending),
            unit_env: pending.unit_env(),
            unit_env_digest: pending.unit_env_digest(),
            max_age,
            now: now(),
            group: None,
        }
    }

    /// The grouped form of this decision, when `STOOP_SPLIT_GROUP` is on and the hook takes that form (spec 5.1). `store`
    /// names the list paths that the fit check counts.
    pub(super) fn grouping(mut self, cx: &RunCx<'_>, store: &Path) -> Judged<'a> {
        if !grouped() {
            return self;
        }
        let Some(hook) = cx.hook.as_ref() else {
            return self;
        };
        if !expand::groups(hook) {
            return self;
        }
        self.group = Some(Group {
            hook: hook.clone(),
            cwd: cx.cwd.clone(),
            env: std::env::vars_os()
                .filter(|(name, _)| {
                    !HOOK_ENV
                        .iter()
                        .any(|var| name.as_os_str() == OsStr::new(var))
                        && !name
                            .to_str()
                            .is_some_and(|name| self.unit_env.contains_key(name))
                })
                .chain(
                    self.unit_env
                        .iter()
                        .map(|(name, value)| (OsString::from(name), OsString::from(value))),
                )
                .collect(),
            stand_in: bundle::scratch_path_max(store, self.suite),
            arg_max: expand::arg_max(),
        });
        self
    }
}

/// What a decision needs to check that a grouped launch fits the command line (spec 6): the hook, the cwd, the environment
/// the launch inherits without the five hook variables it replaces, the length a list path takes, and the argument limit.
struct Group {
    hook: Hook,
    cwd: PathBuf,
    env: Vec<(OsString, OsString)>,
    stand_in: usize,
    arg_max: usize,
}

impl Group {
    /// Whether the grouped launch of `affected` fits the command line (spec 6): its argv, and its environment with each list
    /// path at the stand-in length.
    fn fits(&self, root: &Path, affected: &[Affected]) -> bool {
        let members: Vec<String> = affected
            .iter()
            .map(|affected| affected.unit.clone())
            .collect();
        let stand_in = self.stand_in;
        let list = |_: FileMode, _: Base| Some(OsString::from("x".repeat(stand_in)));
        let Some(many) = expand::launch_many(&self.hook, &members, root, &self.cwd, &list) else {
            return false;
        };
        let inputs = expand::inputs_text(
            root,
            &self.cwd,
            affected.iter().flat_map(|affected| affected.changed.iter()),
        );
        let mut env = self.env.clone();
        env.extend(expand::exports(&many.value, &inputs, stand_in));
        expand::fits(&many.argv, &env, self.arg_max)
    }
}

/// Whether grouped launches are on (spec 5.1): the engine is on, and `STOOP_SPLIT_GROUP` holds a true value.
fn grouped() -> bool {
    switch() == Some(true) && std::env::var_os("STOOP_SPLIT_GROUP").is_some_and(|value| on(&value))
}

/// The guard digest the run would record now (spec 3.6). It is built as `attribution::pass` builds its guard, so a
/// version and the whole proof agree on it.
fn guard_now(cx: &RunCx<'_>, pending: &Pending) -> String {
    let ignore = Ignore::new(
        &cx.o.ignore,
        Some(&cx.root.join(".stoopignore")),
        &cx.o.transient,
    );
    LaunchGuard {
        env: cx.env_now.clone(),
        env_excluded: cx.env_excluded.clone(),
        ignore: ignore.patterns(),
        unit_env: pending.unit_env_digest(),
    }
    .digest()
}

/// The guard digest the whole proof records, which a version's guard is compared with.
fn whole_guard(proof: &Proof, unit_env: Option<String>) -> String {
    LaunchGuard {
        env: proof.env.clone(),
        env_excluded: proof.env_excluded.clone(),
        ignore: proof.ignore.clone().unwrap_or_default(),
        unit_env,
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
    if whole_guard(proof, cx.unit_env_digest.clone()) != cx.guard {
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
    // E17 and E18 (spec 3.10, PR 86 review round 2, option B): a changed input that only units which left the roster read
    // has no reader that a launch of this run could check. The full command decides it, before any launch.
    if let Some(path) = departed_only_change(cx, view, proof, &affected) {
        return verdict(
            Decision::Full(Some(format!(
                "{} changed and only units that left the roster read it",
                safe(&path)
            ))),
            shown,
            clean,
        );
    }
    // A missing roster member that the full command read can also be used by the runner outside that unit. No listing
    // or deleted-input excuse can establish otherwise, even if another unit still reads all of its other inputs.
    if let Some((unit, _)) = view.units.iter().find(|(unit, versions)| {
        !versions.is_empty()
            && cx.roster.binary_search(unit).is_err()
            && proof.inputs.iter().any(|input| {
                input.path == **unit && (input.id.starts_with("f:") || input.id.starts_with("x:"))
            })
    }) {
        return verdict(
            Decision::Full(Some(format!(
                "{} was removed after the full command read it",
                safe(unit)
            ))),
            shown,
            clean,
        );
    }
    // An outside-root input may also drive the full runner outside any unit. Unlike root-relative unit data, there is
    // no tracked directory listing to expose a change there, so the whole proof must still hold for that input.
    if let Some(input) = proof
        .inputs
        .iter()
        .filter(|input| Path::new(&input.path).is_absolute())
        .find(|input| {
            let held = if let Some(id) = current.id(input) {
                id == input.id
            } else {
                identify(
                    &from_key(cx.root, &input.path),
                    false,
                    input.id.starts_with("dl:"),
                )
                .as_deref()
                    == Some(input.id.as_str())
            };
            !held
        })
    {
        return verdict(
            Decision::Full(Some(format!(
                "{} changed outside the repository",
                safe(&input.path)
            ))),
            shown,
            clean,
        );
    }
    // An appeared input in a directory the full proof never listed has no listing change to account for the runner's
    // use of the name. Do not let a unit's read alone excuse that appearance.
    if let Some(input) = proof
        .inputs
        .iter()
        .filter(|input| input.id == "a")
        .find(|input| {
            let appeared = match current.id(input) {
                Some(id) => id != "a",
                None => {
                    identify(&from_key(cx.root, &input.path), true, false).as_deref() != Some("a")
                }
            };
            if !appeared {
                return false;
            }
            let parent = Path::new(&input.path)
                .parent()
                .and_then(Path::to_str)
                .unwrap_or("");
            !proof.inputs.iter().chain(&proof.outputs).any(|entry| {
                entry.id.starts_with("dl:")
                    && (entry.path == parent || (parent.is_empty() && entry.path == "."))
            })
        })
    {
        return verdict(
            Decision::Full(Some(format!(
                "{} appeared in an unlisted directory",
                safe(&input.path)
            ))),
            shown,
            clean,
        );
    }
    // A directory that the full command recorded as metadata (`d`) is read by no unit's run, and a catalog listing does
    // not cover a metadata read. Its presence and type must hold (PR 86 review round 5, R5a).
    let dirs: Vec<&Input> = proof
        .inputs
        .iter()
        .filter(|input| input.id == "d" && !Path::new(&input.path).is_absolute())
        .collect();
    let now = Current::of(cx.root, &dirs);
    if let Some(input) = dirs.iter().find(|input| !now.holds(input)) {
        return verdict(
            Decision::Full(Some(format!(
                "{} changed, and the full command read it as a directory",
                safe(&input.path)
            ))),
            shown,
            clean,
        );
    }
    // A roster unit's own file may change its content, which that unit's run covers. The full command also reads the
    // execute bit and the file type outside any unit's run, so a change in either takes the full form (round 5).
    let owns: Vec<&Input> = proof
        .inputs
        .iter()
        .filter(|input| {
            cx.roster.binary_search(&input.path).is_ok()
                && (input.id.starts_with("f:") || input.id.starts_with("x:"))
        })
        .collect();
    // A unit's version usually reads its own file, so `current` holds that file's identity already. Only the rest is
    // identified here.
    let unseen: Vec<&Input> = owns
        .iter()
        .copied()
        .filter(|input| current.id(input).is_none())
        .collect();
    let fresh = Current::of(cx.root, &unseen);
    if let Some(input) = owns.iter().find(|input| {
        let id = current.id(input).or_else(|| fresh.id(input));
        !id.is_some_and(|id| {
            (id.starts_with("f:") || id.starts_with("x:"))
                && id.starts_with("x:") == input.id.starts_with("x:")
        })
    }) {
        return verdict(
            Decision::Full(Some(format!(
                "{} changed its type or its execute bit",
                safe(&input.path)
            ))),
            shown,
            clean,
        );
    }
    // A roster unit that the last full run was not judged with is new to the suite. Its file can be one that the runner
    // only checks by a stat, and a stat records the same identity as a read, so no identity shows that the unit was on
    // the roster. Only the roster that the whole proof recorded decides it (round 5, R5b).
    if let Some(unit) = cx
        .roster
        .iter()
        .find(|unit| view.whole_roster.binary_search(unit).is_err())
    {
        return verdict(
            Decision::Full(Some(format!(
                "{} was not on the roster of the last full run",
                safe(unit)
            ))),
            shown,
            clean,
        );
    }
    // A unit the last full command did not read has not been judged by that command. Its own successful launch cannot
    // account for runner policy that rejects the new unit, even when an old unit recorded the path as absent.
    if let Some(unit) = cx.roster.iter().find(|unit| {
        !proof
            .inputs
            .binary_search_by(|input| input.path.as_str().cmp(unit.as_str()))
            .ok()
            .is_some_and(|index| {
                let id = &proof.inputs[index].id;
                id.starts_with("f:") || id.starts_with("x:")
            })
    }) {
        return verdict(
            Decision::Full(Some(format!(
                "{} has not been read by the full command",
                safe(unit)
            ))),
            shown,
            clean,
        );
    }
    // E16 to E18 each need every listing that the whole proof holds to be as it was (see `listings_change`).
    let excused = match listings_change(cx, view, &current, proof, &affected) {
        Ok(excused) => excused,
        Err(reason) => return verdict(Decision::Full(Some(reason)), shown, clean),
    };
    if affected.is_empty() {
        let skip = skipped(cx, view);
        // A skip that drops the versions of units that left the roster takes the full form when those versions hold the
        // last reader of a path (spec 3.8, E16). The full run measures the residue again, without them.
        if skip.drop && units_that_left_held_a_reader(cx, view) {
            return verdict(
                Decision::Full(Some(
                    "the units that left the roster read files that no unit reads now".to_owned(),
                )),
                shown,
                clean,
            );
        }
        return verdict(Decision::Skip(skip), shown, clean);
    }
    // A deleted input that a stored version of a roster unit reads takes the full form before any launch (PR 86 review
    // round 3). No launch can vouch for an absence it does not read by content.
    if let Some(path) = absent_reader_change(cx, view, proof) {
        return verdict(
            Decision::Full(Some(format!(
                "{} was removed, and a unit's stored proof reads it",
                safe(&path)
            ))),
            shown,
            clean,
        );
    }
    // E17 and E18: the affected units launch one at a time. Units that are all affected make the attribution pass.
    // A subset of two or more units runs as one grouped launch when grouping is on and that launch fits the command line
    // (spec 5.1, 6). A launch that does not fit takes the full form, and the reason says so.
    let whole = affected.len() == cx.roster.len();
    let uncovered = uncovered_changes(cx, view, &current, proof);
    let as_group = !whole && affected.len() >= 2 && cx.group.is_some();
    if as_group
        && !cx
            .group
            .as_ref()
            .is_some_and(|group| group.fits(cx.root, &affected))
    {
        return verdict(
            Decision::Full(Some(format!(
                "the {} affected units do not fit on the command line",
                affected.len()
            ))),
            shown,
            clean,
        );
    }
    let plan = Plan {
        units: cx.roster.len(),
        inputs: skipped(cx, view).inputs,
        affected,
        excused,
        uncovered,
        grouped: as_group,
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

/// Completion after a recorded full run learns every unit without a valid exact version, in roster order.
/// It declines when the suite is disabled or the residue is known and empty.
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
    let mut units: Vec<String> = analyse(cx, view, &current)
        .into_iter()
        .map(|affected| affected.unit)
        .collect();
    let mut inexact = inexact_only(cx, view, &current).peekable();
    if inexact.peek().is_some() {
        units.extend(inexact.cloned());
        units.sort_unstable();
    }
    Ok(units)
}

/// Whether every roster unit holds a valid exact version, which lets the residue be confirmed.
pub(super) fn holds(cx: &Judged<'_>, view: &View) -> bool {
    let current = Current::of(cx.root, &checked(cx, view));
    analyse(cx, view, &current).is_empty() && inexact_only(cx, view, &current).next().is_none()
}

/// Units with a valid inexact version, but no valid exact version, in roster order.
fn inexact_only<'a>(
    cx: &'a Judged<'_>,
    view: &'a View,
    current: &'a Current,
) -> impl Iterator<Item = &'a String> + 'a {
    cx.roster.iter().filter(|unit| {
        view.units.get(*unit).is_some_and(|versions| {
            let valid =
                |version: &Version| version_reasons(cx, view, current, version).0.is_empty();
            versions.iter().any(|version| !version.exact)
                && !versions.iter().filter(|version| version.exact).any(valid)
                && versions.iter().filter(|version| !version.exact).any(valid)
        })
    })
}

/// Whether the versions of the units that left the roster hold the last reader of a path that the roster's units no
/// longer read (spec 3.8). The view holds what each version reads.
fn units_that_left_held_a_reader(cx: &Judged<'_>, view: &View) -> bool {
    let readers = |in_roster: bool| {
        bundle::reader_map(
            view.units
                .iter()
                .filter(|(unit, _)| cx.roster.binary_search(*unit).is_ok() == in_roster)
                .flat_map(|(_, versions)| versions.iter())
                .flat_map(|version| {
                    version
                        .inputs
                        .iter()
                        .map(|&index| &view.table[index as usize])
                }),
        )
    };
    let removed = readers(false);
    !removed.is_empty() && bundle::lost_reader(&removed, &readers(true))
}

/// The whole proof's content inputs that a subset or an attribution pass must see covered (spec 3.10, PR 86 review round
/// 2). A kept version is a roster unit's valid version, and it holds the identity of each path it reads by content, so
/// such an input is covered. An input that no kept version reads, and whose identity moved since the whole proof, is
/// uncovered: only a new proof of this run can vouch for it. A deleted input is not one. Its readers are affected, or
/// they departed, and the loss is taken in full at the next run (spec 3.8, item 1).
fn uncovered_changes(
    cx: &Judged<'_>,
    view: &View,
    current: &Current,
    proof: &Proof,
) -> Vec<String> {
    let kept: BTreeSet<&str> = cx
        .roster
        .iter()
        .filter_map(|unit| view.units.get(unit))
        .flatten()
        .filter(|version| version_reasons(cx, view, current, version).0.is_empty())
        .flat_map(|version| version.inputs.iter())
        .map(|&index| &view.table[index as usize])
        .filter(|input| bundle::content_id(&input.id))
        .map(|input| input.path.as_str())
        .collect();
    let inputs: Vec<&Input> = proof
        .inputs
        .iter()
        .filter(|input| bundle::content_id(&input.id) && !input.id.starts_with("dl:"))
        .filter(|input| !kept.contains(input.path.as_str()))
        .collect();
    let fresh = Current::of(cx.root, &inputs);
    let mut paths: Vec<String> = inputs
        .iter()
        .filter(|&&input| !fresh.holds(input) && !fresh.absent(input))
        .map(|&input| input.path.clone())
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// The first changed whole-proof input, in path order, that only units which left the roster read by content (spec 3.10,
/// PR 86 review round 2). A roster version, valid or stale, that reads an input keeps it out: the after-launch rule checks
/// an input that an affected unit's stored version reads. An unchanged input is not a change, and a deleted input is not
/// one either: its readers are affected or departed, and the next run takes the loss in full.
fn departed_only_change(
    cx: &Judged<'_>,
    view: &View,
    proof: &Proof,
    affected: &[Affected],
) -> Option<String> {
    if affected.is_empty() {
        return None;
    }
    // Each path, with whether a roster version reads it by content, and whether a departed version does.
    let mut readers: BTreeMap<&str, (bool, bool)> = BTreeMap::new();
    for (unit, versions) in &view.units {
        let roster = cx.roster.binary_search(unit).is_ok();
        for version in versions {
            for &index in &version.inputs {
                let input = &view.table[index as usize];
                if bundle::content_id(&input.id) {
                    let (live, gone) = readers.entry(input.path.as_str()).or_default();
                    if roster {
                        *live = true;
                    } else {
                        *gone = true;
                    }
                }
            }
        }
    }
    let inputs: Vec<&Input> = proof
        .inputs
        .iter()
        .filter(|input| bundle::content_id(&input.id) && !input.id.starts_with("dl:"))
        .filter(|input| {
            readers
                .get(input.path.as_str())
                .is_some_and(|&(live, gone)| gone && !live)
        })
        .collect();
    let fresh = Current::of(cx.root, &inputs);
    let mut paths: Vec<String> = inputs
        .iter()
        .filter(|input| !fresh.holds(input) && !fresh.absent(input))
        .map(|input| input.path.clone())
        .collect();
    paths.sort();
    paths.into_iter().next()
}

/// The first changed whole-proof input that is absent now, and that a stored version of any unit reads, live or departed (PR 86
/// review round 3). A launch does not vouch for an absence unless it reads the path by content, and a failed open is no
/// content read. A unit that still lists the path may also stop listing it in this step. The full command decides it.
fn absent_reader_change(cx: &Judged<'_>, view: &View, proof: &Proof) -> Option<String> {
    // A departed unit's own file is not checked here: the full command no longer runs that unit, so its absence changes
    // no verdict. Its other inputs, and every input of a unit still in the roster, are checked.
    let live: BTreeSet<&str> = view
        .units
        .iter()
        .flat_map(|(unit, versions)| {
            let roster = cx.roster.binary_search(unit).is_ok();
            versions
                .iter()
                .flat_map(|version| version.inputs.iter())
                .map(|&index| view.table[index as usize].path.as_str())
                .filter(move |path| roster || *path != unit.as_str())
        })
        .collect();
    let inputs: Vec<&Input> = proof
        .inputs
        .iter()
        .filter(|input| bundle::content_id(&input.id) && !input.id.starts_with("dl:"))
        .filter(|input| live.contains(input.path.as_str()))
        .collect();
    let fresh = Current::of(cx.root, &inputs);
    let mut paths: Vec<String> = inputs
        .iter()
        .filter(|input| !fresh.holds(input) && fresh.absent(input))
        .map(|input| input.path.clone())
        .collect();
    paths.sort();
    paths.into_iter().next()
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
    // A name is excused here only in a listed directory whose listing changed, when no valid proof reads it, the whole
    // proof did not hold it, and it is a regular file now. Where a listing holds, none of its names appeared (rv43).
    let changed: BTreeSet<&str> = entries
        .iter()
        .zip(&same)
        .filter(|(input, held)| !**held && !matches!(input.path.as_str(), "" | "."))
        .map(|(input, _)| input.path.as_str())
        .collect();
    Ok(rerun
        .into_iter()
        .filter(|(path, _)| {
            !valid.contains(path)
                && !recorded.contains(path.as_str())
                && Path::new(path)
                    .parent()
                    .and_then(Path::to_str)
                    .is_some_and(|dir| changed.contains(dir))
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
/// - Added files: regular files under this directory that a valid unit proof reads, or that an affected unit's stored proof
///   names, and that the whole proof does not hold (`covered_reads` and `rerun_reads`). A directory or a link is never
///   excused (rv32). A name that only a stored proof names is checked after the launches (`unread_excuses`, rv34).
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

/// The entry names of a listed directory as `identify` reads them. `None` when the path is absent, cannot be listed,
/// or is not a directory now.
fn listed(dir: &Path) -> Option<Vec<Vec<u8>>> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => fs::read_dir(dir)
            .ok()?
            .map(|entry| Some(entry.ok()?.file_name().as_encoded_bytes().to_vec()))
            .collect(),
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
    let (lacking, has_inexact) = match bundle::view(store, pending, key) {
        None => (pending.units().len(), false),
        Some(view) => {
            if view.disabled.is_some() {
                return None;
            }
            let current = Current::of(cx.root, &checked(&judged, &view));
            let inexact = inexact_only(&judged, &view, &current).count();
            (
                analyse(&judged, &view, &current).len() + inexact,
                inexact > 0,
            )
        }
    };
    learning_line(lacking, has_inexact)
}

fn learning_line(lacking: usize, has_inexact: bool) -> Option<String> {
    (lacking > 0).then(|| {
        if has_inexact {
            format!(
                "stoop: if the full command passes, would launch {lacking} units without a current exact proof, one launch each"
            )
        } else {
            format!(
                "stoop: if the full command passes, would launch {lacking} units without a current proof, one launch each"
            )
        }
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

    /// A skip counts the roster's inputs only (spec 3.12). A unit that left the roster adds none, though its versions
    /// still make the skip drop them (E16). Killed by counting every table entry.
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
        assert_eq!((skip.units, skip.inputs, skip.drop), (1, 2, true));
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
            whole_roster: Vec::new(),
        };
        (view, current)
    }

    fn version(created: u64, inputs: Vec<u32>) -> Version {
        Version {
            created,
            exact: true,
            guard: "g".to_owned(),
            inputs,
            outputs: Vec::new(),
        }
    }

    fn judged<'a>(roster: &'a [String], max_age: u64) -> Judged<'a> {
        static EMPTY: std::sync::LazyLock<BTreeMap<String, String>> =
            std::sync::LazyLock::new(BTreeMap::new);
        Judged {
            root: Path::new("."),
            suite: "suite",
            roster,
            proofs: &[],
            guard: "g".to_owned(),
            unit_env: &EMPTY,
            unit_env_digest: None,
            max_age,
            now: 1_000,
            group: None,
        }
    }

    #[test]
    fn a_version_with_another_unit_env_digest_is_invalid() {
        let guard = |unit_env: &str| {
            LaunchGuard {
                env: BTreeMap::new(),
                env_excluded: Vec::new(),
                ignore: Vec::new(),
                unit_env: Some(unit_env.to_owned()),
            }
            .digest()
        };
        let (view, current) = view_of(Vec::new(), Vec::new());
        let mut cx = judged(&[], 0);
        cx.guard = guard("old overlay");
        let mut saved = version(1_000, Vec::new());
        saved.guard = cx.guard.clone();
        assert!(version_reasons(&cx, &view, &current, &saved).0.is_empty());
        cx.guard = guard("new overlay");
        assert_eq!(
            version_reasons(&cx, &view, &current, &saved).0,
            ["the environment changed"]
        );
    }

    fn inexact_version(inputs: Vec<u32>) -> Version {
        let mut version = version(1_000, inputs);
        version.exact = false;
        version
    }

    fn identity_matrix_view() -> (View, Current, Vec<String>) {
        let entries = [
            ("tests/a.t", "f:a"),
            ("tests/b.t", "x:b"),
            ("dir", "d"),
            ("listed", "dl:one"),
            ("absent", "a"),
            ("/outside-root", "f:outside"),
            ("link", "l:target"),
            ("unreadable", "u"),
            ("output", "f:out"),
        ];
        let table: Vec<Input> = entries.iter().map(|(path, id)| input(path, id)).collect();
        let mut values = HashMap::new();
        for entry in &table {
            let mut slots = [None, None];
            slots[usize::from(entry.id.starts_with("dl:"))] = Some(entry.id.clone());
            values.insert(entry.path.clone(), slots);
        }
        let group = || {
            let mut version = inexact_version((0..8).collect());
            version.outputs = vec![8];
            version
        };
        let roster = vec!["tests/a.t".to_owned(), "tests/b.t".to_owned()];
        let (view, _) = view_of(
            vec![("tests/a.t", vec![group()]), ("tests/b.t", vec![group()])],
            table,
        );
        (view, Current(values), roster)
    }

    #[test]
    fn an_inexact_version_holds_while_every_input_of_its_launch_holds() {
        let (view, current, roster) = identity_matrix_view();
        let cx = judged(&roster, 0);
        assert!(analyse(&cx, &view, &current).is_empty());
        assert_eq!(
            inexact_only(&cx, &view, &current)
                .cloned()
                .collect::<Vec<_>>(),
            roster
        );
    }

    #[test]
    fn an_inexact_version_is_affected_by_an_input_only_another_member_read() {
        let (view, mut current, roster) = identity_matrix_view();
        let cx = judged(&roster, 0);
        for entry in &view.table {
            let slot = usize::from(entry.id.starts_with("dl:"));
            current.0.get_mut(&entry.path).unwrap()[slot] = None;
            let affected: Vec<String> = analyse(&cx, &view, &current)
                .into_iter()
                .map(|unit| unit.unit)
                .collect();
            assert_eq!(affected, roster, "changed identity {}", entry.path);
            current.0.get_mut(&entry.path).unwrap()[slot] = Some(entry.id.clone());
        }
    }

    #[test]
    fn a_valid_exact_version_avoids_reproof_but_a_stale_one_does_not() {
        let table = vec![input("tests/a.t", "f:1")];
        let mut stale = version(1_000, vec![0]);
        stale.guard = "old".to_owned();
        let (mut view, current) = view_of(
            vec![("tests/a.t", vec![inexact_version(vec![0]), stale])],
            table,
        );
        let roster = vec!["tests/a.t".to_owned()];
        let cx = judged(&roster, 0);
        assert_eq!(inexact_only(&cx, &view, &current).count(), 1);
        view.units
            .get_mut("tests/a.t")
            .unwrap()
            .push(version(1_000, vec![0]));
        assert_eq!(inexact_only(&cx, &view, &current).count(), 0);
    }

    #[test]
    fn the_learn_line_names_inexact_units_with_the_exact_proof_wording() {
        assert_eq!(
            learning_line(2, true).as_deref(),
            Some("stoop: if the full command passes, would launch 2 units without a current exact proof, one launch each")
        );
        assert_eq!(
            learning_line(2, false).as_deref(),
            Some("stoop: if the full command passes, would launch 2 units without a current proof, one launch each")
        );
        assert_eq!(learning_line(0, true), None);
    }

    #[test]
    fn a_valid_inexact_version_still_covers_a_listing_name() {
        let table = vec![input("tests/a.t", "f:1"), input("tests/b.flag", "x:2")];
        let (view, current) = view_of(
            vec![("tests/a.t", vec![inexact_version(vec![0, 1])])],
            table,
        );
        let roster = vec!["tests/a.t".to_owned()];
        let covered = covered_reads(&judged(&roster, 0), &view, &current, &BTreeSet::new());
        assert!(covered.contains("tests/b.flag"));
    }

    #[test]
    fn listing_coverage_uses_the_same_identity_kinds_for_inexact_versions() {
        let (view, current, roster) = identity_matrix_view();
        let covered = covered_reads(&judged(&roster, 0), &view, &current, &BTreeSet::new());
        for path in ["tests/a.t", "tests/b.t", "/outside-root"] {
            assert!(covered.contains(path), "{path}");
        }
        for path in ["dir", "listed", "absent", "link", "unreadable", "output"] {
            assert!(!covered.contains(path), "{path}");
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

    fn test_proof(inputs: Vec<Input>) -> Proof {
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

    #[test]
    fn uncovered_changes_do_not_ask_a_launch_to_read_a_deleted_file() {
        let missing = format!(".stoop-missing-test-input-{}", std::process::id());
        assert!(!Path::new(&missing).exists());
        let proof = test_proof(vec![input(&missing, "f:old")]);
        let (view, current) = view_of(Vec::new(), Vec::new());
        assert!(uncovered_changes(&judged(&[], 0), &view, &current, &proof).is_empty());
    }

    #[test]
    fn a_skip_cannot_drop_the_last_reader_of_a_whole_input() {
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let root =
            std::env::temp_dir().join(format!("stoop-skip-last-reader-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let root = Scratch(root);
        fs::write(root.0.join("live.t"), "live").unwrap();
        fs::write(root.0.join("only.dat"), "data").unwrap();
        let live = input(
            "live.t",
            &identify(&root.0.join("live.t"), true, false).unwrap(),
        );
        let only = input(
            "only.dat",
            &identify(&root.0.join("only.dat"), true, false).unwrap(),
        );
        let proof = test_proof(vec![live.clone(), only.clone()]);
        let guard = whole_guard(&proof, None);
        let (mut view, _) = view_of(
            vec![
                ("live.t", vec![version(1_000, vec![0])]),
                ("gone.t", vec![version(1_000, vec![1])]),
            ],
            vec![live, only],
        );
        for versions in view.units.values_mut() {
            for version in versions {
                version.guard = guard.clone();
            }
        }
        view.whole = proof.digest();
        view.residue = Some((0, Vec::new()));
        view.whole_roster = vec!["live.t".to_owned()];
        let roster = vec!["live.t".to_owned()];
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(matches!(
            judge(&cx, &view).decision,
            Decision::Full(Some(reason)) if reason.contains("units that left the roster read files")
        ));
    }

    /// A scratch folder with the given files, removed when the test ends.
    struct TreeDir(std::path::PathBuf);

    impl TreeDir {
        fn new(name: &str, files: &[(&str, &str)]) -> TreeDir {
            let root = std::env::temp_dir().join(format!("stoop-r5-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            for (path, body) in files {
                fs::write(root.join(path), body).unwrap();
            }
            TreeDir(root)
        }

        fn entry(&self, path: &str) -> Input {
            input(path, &identify(&self.0.join(path), true, false).unwrap())
        }
    }

    impl Drop for TreeDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_inexact_kept_version_covers_a_changed_whole_input() {
        let root = TreeDir::new("inexact-kept", &[("shared", "new")]);
        let (mut view, _) = view_of(
            vec![("a.t", vec![inexact_version(vec![0])])],
            vec![root.entry("shared")],
        );
        let roster = vec!["a.t".to_owned()];
        let cx = Judged {
            root: &root.0,
            ..judged(&roster, 0)
        };
        let proof = test_proof(vec![input("shared", "f:old")]);
        let current = Current::of(&root.0, &[&view.table[0]]);
        assert!(uncovered_changes(&cx, &view, &current, &proof).is_empty());
        view.units.clear();
        assert_eq!(uncovered_changes(&cx, &view, &current, &proof), ["shared"]);
    }

    #[test]
    fn an_inexact_version_still_marks_a_deleted_input_as_read() {
        let root = TreeDir::new("inexact-absent", &[]);
        let (view, _) = view_of(
            vec![("a.t", vec![inexact_version(vec![0])])],
            vec![input("missing", "f:old")],
        );
        let roster = vec!["a.t".to_owned()];
        let cx = Judged {
            root: &root.0,
            ..judged(&roster, 0)
        };
        let proof = test_proof(vec![input("missing", "f:old")]);
        assert_eq!(
            absent_reader_change(&cx, &view, &proof).as_deref(),
            Some("missing")
        );
    }

    #[test]
    fn an_inexact_live_reader_still_covers_a_departed_readers_path() {
        let root = TreeDir::new("inexact-departed", &[("shared", "new")]);
        let table = vec![input("shared", "f:old")];
        let (mut view, _) = view_of(
            vec![
                ("a.t", vec![inexact_version(vec![0])]),
                ("gone.t", vec![version(1_000, vec![0])]),
            ],
            table,
        );
        let roster = vec!["a.t".to_owned()];
        let cx = Judged {
            root: &root.0,
            ..judged(&roster, 0)
        };
        let proof = test_proof(vec![input("shared", "f:old")]);
        let affected = vec![Affected {
            unit: "a.t".to_owned(),
            why: "changed".to_owned(),
            changed: Vec::new(),
        }];
        assert!(!units_that_left_held_a_reader(&cx, &view));
        assert_eq!(departed_only_change(&cx, &view, &proof, &affected), None);
        view.units.remove("a.t");
        assert!(units_that_left_held_a_reader(&cx, &view));
        assert_eq!(
            departed_only_change(&cx, &view, &proof, &affected).as_deref(),
            Some("shared")
        );
    }

    #[test]
    fn inexact_versions_still_participate_in_the_global_input_guard() {
        let root = TreeDir::new("inexact-global", &[("shared", "new")]);
        let (view, _) = view_of(
            vec![
                ("a.t", vec![inexact_version(vec![0])]),
                ("b.t", vec![inexact_version(vec![0])]),
            ],
            vec![input("shared", "f:old")],
        );
        let roster = vec!["a.t".to_owned(), "b.t".to_owned()];
        let cx = Judged {
            root: &root.0,
            ..judged(&roster, 0)
        };
        let proof = test_proof(vec![input("shared", "f:old")]);
        let current = Current::of(&root.0, &[&view.table[0]]);
        assert_eq!(
            global_change(&cx, &view, &proof, &current).as_deref(),
            Some("shared")
        );
    }

    #[test]
    fn an_inexact_version_still_attributes_its_output_to_the_unit() {
        let root = TreeDir::new("inexact-output", &[]);
        let mut group = inexact_version(Vec::new());
        group.outputs.push(0);
        let (mut view, _) = view_of(vec![("a.t", vec![group])], vec![input("output", "f:old")]);
        let roster = vec!["a.t".to_owned()];
        let cx = Judged {
            root: &root.0,
            ..judged(&roster, 0)
        };
        let mut proof = test_proof(Vec::new());
        proof.outputs.push(input("output", "f:old"));
        assert_eq!(output_missing(&cx, &view, &proof), None);
        view.units.clear();
        assert_eq!(
            output_missing(&cx, &view, &proof).as_deref(),
            Some("output output is missing")
        );
    }

    #[test]
    fn an_inexact_affected_version_supplies_listing_excuses() {
        let (view, _, _) = identity_matrix_view();
        let affected = vec![Affected {
            unit: "tests/a.t".to_owned(),
            why: "changed".to_owned(),
            changed: Vec::new(),
        }];
        let reads = rerun_reads(&view, &affected, &BTreeSet::new());
        for entry in &view.table[..8] {
            assert_eq!(
                reads.get(&entry.path).unwrap(),
                &["tests/a.t"],
                "{}",
                entry.path
            );
        }
    }

    #[test]
    fn r6_listed_directory_must_exist_for_whole_and_unit_proofs() {
        let root = TreeDir::new("listed-shapes", &[]);
        let dir = root.0.join("policy");
        fs::create_dir(&dir).unwrap();
        let listing = input("policy", &identify(&dir, true, true).unwrap());
        let (view, _) = view_of(Vec::new(), vec![listing.clone()]);
        let cx = Judged {
            root: &root.0,
            ..judged(&[], 0)
        };
        let check = |holds| {
            let current = Current::of(&root.0, &[&listing]);
            assert_eq!(listing_matches(&root.0, &listing), holds);
            assert_eq!(current.holds(&listing), holds);
            let input_version = version(1_000, vec![0]);
            let mut output_version = version(1_000, Vec::new());
            output_version.outputs.push(0);
            for version in [&input_version, &output_version] {
                assert_eq!(
                    version_reasons(&cx, &view, &current, version).0.is_empty(),
                    holds
                );
            }
            for output in [false, true] {
                let mut proof = test_proof(if output {
                    Vec::new()
                } else {
                    vec![listing.clone()]
                });
                if output {
                    proof.outputs.push(listing.clone());
                }
                assert_eq!(
                    listings_change(&cx, &view, &current, &proof, &[]).is_ok(),
                    holds,
                    "whole proof output={output}"
                );
            }
        };
        check(true);
        fs::remove_dir(&dir).unwrap();
        check(false);
        fs::write(&dir, "not a directory").unwrap();
        check(false);
        fs::remove_file(&dir).unwrap();
        #[cfg(unix)]
        {
            fs::create_dir(root.0.join("target")).unwrap();
            std::os::unix::fs::symlink("target", &dir).unwrap();
            check(false);
            fs::remove_file(&dir).unwrap();
        }
        fs::create_dir(&dir).unwrap();
        check(true);
    }

    #[test]
    fn r6_listing_excuses_require_the_directory_to_exist() {
        let root = TreeDir::new("listed-excuses", &[]);
        let dir = root.0.join("policy");
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("old.flag"), "old").unwrap();
        let listing = input("policy", &identify(&dir, true, true).unwrap());
        let proof = test_proof(vec![root.entry("policy/old.flag")]);
        let (view, _) = view_of(Vec::new(), Vec::new());
        let covered = BTreeSet::new();
        fs::remove_file(dir.join("old.flag")).unwrap();
        assert!(listing_holds(
            &root.0,
            &view,
            &[],
            &listing,
            &proof,
            &covered
        ));
        fs::remove_dir(&dir).unwrap();
        assert!(!listing_holds(
            &root.0,
            &view,
            &[],
            &listing,
            &proof,
            &covered
        ));
        fs::create_dir(&dir).unwrap();
        assert!(listing_holds(
            &root.0,
            &view,
            &[],
            &listing,
            &proof,
            &covered
        ));
        fs::write(dir.join("old.flag"), "old").unwrap();
        fs::write(dir.join("new.flag"), "new").unwrap();
        let covered = BTreeSet::from(["policy/new.flag".to_owned()]);
        assert!(listing_holds(
            &root.0,
            &view,
            &[],
            &listing,
            &proof,
            &covered
        ));
    }

    /// The proof and view of two units, `live.t` and `other.t`, that one full run judged together over `root`. Each unit's
    /// version reads its own file. The test changes the tree or the view after this.
    fn two_units_judged(root: &TreeDir, extra: Vec<Input>) -> (Proof, View, Vec<String>) {
        let live = root.entry("live.t");
        let other = root.entry("other.t");
        let mut inputs = vec![live.clone(), other.clone()];
        inputs.extend(extra);
        inputs.sort_by(|a, b| a.path.cmp(&b.path));
        let proof = test_proof(inputs);
        let guard = whole_guard(&proof, None);
        let (mut view, _) = view_of(
            vec![
                ("live.t", vec![version(1_000, vec![0])]),
                ("other.t", vec![version(1_000, vec![1])]),
            ],
            vec![live, other],
        );
        for versions in view.units.values_mut() {
            for version in versions {
                version.guard = guard.clone();
            }
        }
        view.whole = proof.digest();
        view.residue = Some((0, Vec::new()));
        view.whole_roster = vec!["live.t".to_owned(), "other.t".to_owned()];
        (proof, view, vec!["live.t".to_owned(), "other.t".to_owned()])
    }

    #[test]
    fn r6_a_roster_file_not_read_by_the_whole_command_takes_the_full_form() {
        let root = TreeDir::new("unread-roster", &[("live.t", "live"), ("other.t", "other")]);
        let (mut proof, mut view, roster) = two_units_judged(&root, Vec::new());
        proof.inputs.retain(|input| input.path != "other.t");
        view.whole = proof.digest();
        let guard = whole_guard(&proof, None);
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(matches!(
            judge(&cx, &view).decision,
            Decision::Full(Some(reason)) if reason.contains("other.t has not been read by the full command")
        ));
    }

    #[test]
    fn r5_a_directory_the_full_command_read_as_metadata_takes_the_full_form_when_it_changes() {
        let root = TreeDir::new("metadata", &[("live.t", "live"), ("other.t", "other")]);
        // The full command stat'd `policy`, which is a directory then. It is gone now.
        let (proof, view, roster) = two_units_judged(&root, vec![input("policy", "d")]);
        let guard = whole_guard(&proof, None);
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(
            matches!(
                judge(&cx, &view).decision,
                Decision::Full(Some(reason)) if reason.contains("read it as a directory")
            ),
            "a catalog listing does not cover a metadata read"
        );
    }

    #[test]
    fn r5_a_roster_unit_the_last_full_run_was_not_judged_with_takes_the_full_form() {
        let root = TreeDir::new("roster", &[("live.t", "live"), ("other.t", "other")]);
        let (proof, mut view, roster) = two_units_judged(&root, Vec::new());
        let recorded = proof
            .inputs
            .iter()
            .find(|input| input.path == "other.t")
            .unwrap();
        assert!(recorded.id.starts_with("f:"));
        assert!(view.whole_roster.iter().any(|unit| unit == "other.t"));
        // `other.t` was not on the roster of the full run, even though the full command had read its file.
        view.whole_roster = vec!["live.t".to_owned()];
        let guard = whole_guard(&proof, None);
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(matches!(
            judge(&cx, &view).decision,
            Decision::Full(Some(reason)) if reason.contains("was not on the roster of the last full run")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn r5_an_own_file_that_gains_an_execute_bit_takes_the_full_form() {
        use std::os::unix::fs::PermissionsExt;
        let root = TreeDir::new("bit", &[("live.t", "live"), ("other.t", "other")]);
        let (proof, view, roster) = two_units_judged(&root, Vec::new());
        fs::set_permissions(root.0.join("live.t"), fs::Permissions::from_mode(0o755)).unwrap();
        let guard = whole_guard(&proof, None);
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(matches!(
            judge(&cx, &view).decision,
            Decision::Full(Some(reason)) if reason.contains("its execute bit")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn r6_own_file_type_changed_after_roster_discovery_takes_the_full_form() {
        for kind in ["directory", "link"] {
            let root = TreeDir::new(
                &format!("own-type-{kind}"),
                &[("live.t", "live"), ("other.t", "other")],
            );
            let (proof, view, roster) = two_units_judged(&root, Vec::new());
            let path = root.0.join("live.t");
            fs::remove_file(&path).unwrap();
            if kind == "directory" {
                fs::create_dir(&path).unwrap();
            } else {
                std::os::unix::fs::symlink("other.t", &path).unwrap();
            }
            let guard = whole_guard(&proof, None);
            let proofs = [proof];
            let cx = Judged {
                root: &root.0,
                proofs: &proofs,
                guard,
                ..judged(&roster, 0)
            };
            assert!(
                matches!(
                    judge(&cx, &view).decision,
                    Decision::Full(Some(reason)) if reason.contains("changed its type or its execute bit")
                ),
                "{kind}"
            );
        }
    }

    #[test]
    fn r5_an_own_file_content_change_stays_a_subset() {
        let root = TreeDir::new("content", &[("live.t", "live"), ("other.t", "other")]);
        let (proof, view, roster) = two_units_judged(&root, Vec::new());
        fs::write(root.0.join("live.t"), "changed").unwrap();
        let guard = whole_guard(&proof, None);
        let proofs = [proof];
        let cx = Judged {
            root: &root.0,
            proofs: &proofs,
            guard,
            ..judged(&roster, 0)
        };
        assert!(matches!(judge(&cx, &view).decision, Decision::Subset(_)));
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
