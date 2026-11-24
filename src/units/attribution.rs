//! The attribution pass (spec 3.1 to 3.7). A changed run of a hooked suite launches each unit of its roster
//! once, in roster order, under one traced launch each. The launches are `launch_each`, which a subset run
//! shares (spec 3.10, E17 and E18). Each launch is judged by the independence checks in `launch` (spec 3.3): one
//! that breaks a check stops the pass and disables the suite. `stoop explain` asks the same checks, through `screen`
//! and `explain_lines`, so it predicts the decision made here.

use super::bundle::{self, LaunchGuard, Pass, Pending, Scratch, Start, Stored};
use super::config::Config;
use super::engine::Excused;
use super::expand;
use super::hook::{safe, Base, FileMode, Hook};
use super::independence::{Named, Roster, Violation, Written};
use super::launch::{self, Observed, SkippedUnit, Verdict};
use super::policy;
use super::residue;
use crate::ignore::Ignore;
use crate::input::Input;
use crate::pathutil::to_key;
use crate::proof::now;
use crate::run::{self, How, Lookup, Outcome, RunCx};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;

/// The output the pass names when it disables a suite for an over-budget set of proofs (spec 3.6).
pub(super) const OVER_BUDGET: &str = "unit proofs exceed 8 MiB";

/// Runs the attribution pass when every condition of spec 3.1 holds. `None` leaves the run to the legacy path,
/// which then runs exactly as it did before this module existed.
pub(crate) fn pass(
    cx: &RunCx<'_>,
    config: &Config,
    lookup: &Lookup,
    pending: &Pending,
    store: &Path,
    key: &str,
) -> Option<Outcome> {
    let hook = cx.hook.as_ref()?;
    // Checks 1 to 7 are decided by `screen`, which `stoop explain` calls too.
    let pending = screen(cx, hook, config, lookup, Ok(pending)).ok()?;
    // 8 and 9: the bundle is checked without the lock, then again under it. The store's unit folder is
    // excluded by its literal name, wherever the store sits, so no trace of it becomes an input (spec 4.7).
    let ignore = ignore_for(cx, store);
    let guard = guard_of(cx, &ignore);
    let quiet = cx.o.quiet;
    let mut bundle_pass: Pass = match bundle::start(store, pending, key, guard) {
        Start::Pass(bundle_pass) => bundle_pass,
        Start::Busy => {
            say(
                quiet,
                format!(
                    "stoop: suite {} is busy in another stoop; running the full command",
                    pending.suite()
                ),
            );
            return None;
        }
        Start::No => return None,
    };
    let units = pending.units();
    say(
        quiet,
        format!(
            "stoop: attribution pass: {} units, one launch each",
            units.len()
        ),
    );
    let real_root = std::fs::canonicalize(cx.root).unwrap_or_else(|_| cx.root.clone());
    let roster = Roster::new(units);
    let ran = launch_each(
        cx,
        hook,
        &ignore,
        &mut bundle_pass,
        units,
        &roster,
        &mut Named::default(),
        &[],
        &HashMap::new(),
        &real_root,
    );
    for name in run::HOOK_ENV {
        std::env::set_var(name, "");
    }
    let status = finish(&mut bundle_pass, lookup, pending, &ran, units.len(), quiet);
    Some(Outcome {
        status,
        key: key.to_owned(),
        how: How::Units,
    })
}

/// The ignore set a run's launches are judged with: the command's own rules, with the store's unit folder excluded
/// (spec 4.7). A version's guard is taken from the same set, through `guard_of`.
pub(super) fn ignore_for(cx: &RunCx<'_>, store: &Path) -> Ignore {
    let mut ignore = Ignore::new(
        &cx.o.ignore,
        Some(&cx.root.join(".stoopignore")),
        &cx.o.transient,
    );
    for folder in store_folders(cx.root, store) {
        ignore.exclude_folder(&folder);
    }
    ignore
}

/// The guard that a version and a whole proof are judged against, for the ignore set of `ignore_for` (spec 3.6).
pub(super) fn guard_of(cx: &RunCx<'_>, ignore: &Ignore) -> LaunchGuard {
    LaunchGuard {
        env: cx.env_now.clone(),
        env_excluded: cx.env_excluded.clone(),
        ignore: ignore.patterns(),
    }
}

/// A skipped unit whose proof a run's own writes broke (spec 3.7). `dir` is set for the listing level, which names the
/// directory whose entries the launch changed. The file level names the path that the launch wrote.
pub(super) struct Breach {
    writer: String,
    key: String,
    dir: Option<String>,
    skipped: String,
}

impl Breach {
    fn line(&self) -> String {
        match &self.dir {
            None => format!(
                "stoop: this run has no verdict (exit 125): {} changed {}, which skipped unit {} reads",
                safe(&self.writer),
                safe(&self.key),
                safe(&self.skipped)
            ),
            Some(dir) => {
                let shown = if dir.is_empty() { "." } else { dir };
                format!(
                    "stoop: this run has no verdict (exit 125): {} changed the entries of {}, which skipped unit {} lists",
                    safe(&self.writer),
                    safe(shown),
                    safe(&self.skipped)
                )
            }
        }
    }
}

/// A name that an affected unit's stored proof named, which the listing check excused, and that no new proof of this run
/// reads by content (spec 3.10, rv34). Nothing covers the name after the run, so the run has no verdict.
pub(super) struct Unread {
    path: String,
    units: Vec<String>,
}

impl Unread {
    fn line(&self) -> String {
        format!(
            "stoop: this run has no verdict (exit 125): {} appeared, and no unit's new proof reads it; earlier proofs of {} named it",
            safe(&self.path),
            safe(&self.units.join(", "))
        )
    }
}

/// What a loop of launches came to (spec 3.7, 3.11).
pub(super) struct Ran {
    /// The first nonzero launch status, in launch order.
    pub(super) status: i32,
    /// The launches that ran.
    pub(super) ran: usize,
    /// Whether a planned unit was not launched at all, so the run has no verdict from it.
    pub(super) unlaunched: bool,
    /// The launches whose proofs the bundle's budget refused.
    pub(super) over_budget: usize,
    /// The first launch that broke an independence check, by its index in the launch list, and what it broke.
    pub(super) stopped: Option<(usize, Violation)>,
    /// The skipped units whose proofs the run's writes broke (spec 3.7): at most one per level.
    pub(super) breaches: Vec<Breach>,
    /// The units whose new proof this run stored, with the keys their launches read by content (spec 3.10, rv34, rv38).
    pub(super) proven: BTreeMap<String, BTreeSet<String>>,
    /// The excused names that no new proof of this run reads by content (spec 3.10, rv34).
    pub(super) unread: Vec<Unread>,
    /// The changed inputs of the whole proof that no kept version and no new proof of this run reads by content (spec
    /// 3.10, PR 86 review round 2). Nothing covers them after the run, so the run has no verdict.
    pub(super) uncovered: Vec<String>,
    /// The first unit whose launch failed, in launch order. A learning run names it as the disagreement (spec 3.10).
    pub(super) failed: Option<String>,
}

/// The launches of a pass or a subset, one traced launch per unit in `units` order (spec 3.3, 3.7, 3.11). Each launch
/// is judged, and its proof replaces the unit's version when it holds. `named` holds the names the bundle's versions give,
/// and `skipped` the units that are not launched, so a launch that breaks one of them is seen. `changed` gives each
/// launched unit its changed inputs, which the launch exports as `STOOP_CHANGED_INPUTS` (spec 3.11).
#[allow(clippy::too_many_arguments)]
pub(super) fn launch_each(
    cx: &RunCx<'_>,
    hook: &Hook,
    ignore: &Ignore,
    pass: &mut Pass,
    units: &[String],
    roster: &Roster,
    named: &mut Named,
    skipped: &[SkippedUnit],
    changed: &HashMap<String, Vec<String>>,
    real_root: &Path,
) -> Ran {
    let quiet = cx.o.quiet;
    let forms = expand::list_forms(hook);
    let mut written = Written::default();
    let mut ran = Ran {
        status: 0,
        ran: 0,
        unlaunched: false,
        over_budget: 0,
        stopped: None,
        breaches: Vec::new(),
        proven: BTreeMap::new(),
        unread: Vec::new(),
        uncovered: Vec::new(),
        failed: None,
    };
    let mut listing_breach: Option<Breach> = None;
    for (index, unit) in units.iter().enumerate() {
        let unit_name = safe(unit);
        // The launch's list files live in its own folder, which is removed when this iteration ends.
        let mut folder = match pass.scratch() {
            Ok(folder) => folder,
            Err(error) => {
                not_launched(quiet, &unit_name, &error);
                ran.unlaunched = true;
                continue;
            }
        };
        let inputs = changed_inputs(cx, changed.get(unit));
        let lists = match Lists::write(&mut folder, cx.root, cx.cwd, unit, &forms, &inputs) {
            Ok(lists) => lists,
            Err(error) => {
                not_launched(quiet, &unit_name, &error);
                ran.unlaunched = true;
                continue;
            }
        };
        let Some(launch) = expand::launch(hook, unit, cx.root, cx.cwd, &|mode, base| {
            lists.get(mode, base)
        }) else {
            let why = "its arguments cannot be expanded";
            not_launched(quiet, &unit_name, &why);
            ran.unlaunched = true;
            continue;
        };
        std::env::set_var("STOOP_CHANGED", &launch.value);
        std::env::set_var("STOOP_UNITS", &launch.value);
        std::env::set_var("STOOP_CHANGED_FILE", &lists.changed);
        // Above 64 KiB the variable is unset, and the list file carries the list (spec 3.11, rv31). The kernel refuses one
        // environment string over 128 KiB, so a longer export would stop the launch from starting.
        if inputs.len() <= CHANGED_INPUTS_ENV_MAX {
            std::env::set_var("STOOP_CHANGED_INPUTS", &inputs);
        } else {
            std::env::remove_var("STOOP_CHANGED_INPUTS");
        }
        std::env::set_var("STOOP_CHANGED_INPUTS_FILE", &lists.inputs);
        // The root listing before the launch, which the root guard compares with the one after it (spec 3.5).
        let root_before = launch::root_names(cx.root);
        let unit_status =
            match run::launch_traced(cx, &launch.argv, ignore, real_root, false, false, false) {
                // A trace that fails before the command starts has run nothing. The unit runs once
                // untraced and keeps no proof. It is never retried traced, because that could run it
                // a second time.
                Err(error) => {
                    say(
                        quiet,
                        format!(
                            "stoop: not traced ({}); running {unit_name} without a proof",
                            safe(&error.to_string())
                        ),
                    );
                    ran.ran += 1;
                    run::plain(&launch.argv, &[])
                }
                Ok(trace) => {
                    ran.ran += 1;
                    let observed = Observed::of(&trace, cx.root, real_root, ignore);
                    let context = launch::Context {
                        root: cx.root,
                        real_root,
                        ignore,
                        roster,
                        members: std::slice::from_ref(unit),
                        written: &written,
                        named,
                        root_before: &root_before,
                    };
                    match launch::judge(&context, &trace, &observed) {
                        Verdict::Proven(kept) => {
                            let (old_inputs, old_outputs) = pass.held_of(unit);
                            let stored =
                                pass.record(&launch.unit, &kept.inputs, &kept.outputs, now());
                            if matches!(stored, Stored::Stored) {
                                ran.proven.insert(unit.clone(), observed.content.clone());
                            }
                            match stored {
                                Stored::OverBudget => ran.over_budget += 1,
                                Stored::Stored | Stored::WriteFailed => {
                                    named.forget(unit, &paths(&old_inputs), &paths(&old_outputs));
                                    named.store(unit, &paths(&kept.inputs), &paths(&kept.outputs));
                                }
                            }
                        }
                        Verdict::Failed => {}
                        Verdict::Unrecorded(why) => say(
                            quiet,
                            format!("stoop: not recorded for {unit_name}: {}", safe(&why)),
                        ),
                        Verdict::Coupled(violation) => {
                            if let Violation::NeverRan { .. } = violation {
                                say(
                                    quiet,
                                    format!(
                                        "stoop: no proof for {unit_name}: the launch never read it"
                                    ),
                                );
                            }
                            ran.stopped = Some((index, violation));
                        }
                    }
                    // The listing level of the 125 rule, judged while the trace is still here (spec 3.7).
                    if listing_breach.is_none() {
                        listing_breach = launch::listing(skipped, cx.root, real_root, &trace).map(
                            |(skip, key, dir)| Breach {
                                writer: unit.clone(),
                                key,
                                dir: Some(dir),
                                skipped: skip,
                            },
                        );
                    }
                    written.add(&observed.writes, unit);
                    trace.status
                }
            };
        // The first nonzero status in roster order. A failing unit never stops the pass (spec 3.9).
        ran.status = keep(ran.status, unit_status);
        if unit_status != 0 && ran.failed.is_none() {
            ran.failed = Some(unit.clone());
        }
        if ran.stopped.is_some() {
            break;
        }
    }
    // The file level of the 125 rule: a launch wrote a path that a skipped unit names (spec 3.7).
    ran.breaches.extend(file_breach(skipped, &written));
    ran.breaches.extend(listing_breach);
    ran
}

/// The first skipped unit whose input, output or own file this run wrote, in roster order (spec 3.7). The writer is the
/// first launch that wrote the path.
fn file_breach(skipped: &[SkippedUnit], written: &Written) -> Option<Breach> {
    skipped.iter().find_map(|skip| {
        skip.paths.iter().find_map(|path| {
            written.writer(path).map(|writer| Breach {
                writer: writer.to_owned(),
                key: path.clone(),
                dir: None,
                skipped: skip.unit.clone(),
            })
        })
    })
}

/// The largest changed-inputs list that `STOOP_CHANGED_INPUTS` exports whole, in bytes (spec 3.11, rv31). Above it the
/// variable is unset and the list file carries the list.
const CHANGED_INPUTS_ENV_MAX: usize = 64 * 1024;

/// The changed inputs of one launch, as `STOOP_CHANGED_INPUTS` holds them (spec 3.11): the cwd-relative paths of the
/// changed keys inside the root, sorted, one per line. A pass has none, so its text is empty.
fn changed_inputs(cx: &RunCx<'_>, keys: Option<&Vec<String>>) -> OsString {
    let mut paths: Vec<OsString> = keys
        .into_iter()
        .flatten()
        .filter(|key| !key.starts_with('/'))
        .map(|key| {
            let path = expand::render(cx.root, cx.cwd, key, Base::Cwd);
            if path.is_empty() {
                OsString::from(".")
            } else {
                path
            }
        })
        .collect();
    paths.sort();
    paths.dedup();
    let mut text = OsString::new();
    for (index, path) in paths.iter().enumerate() {
        if index > 0 {
            text.push("\n");
        }
        text.push(path);
    }
    text
}

/// Settles a run's launches once they end (spec 3.6 to 3.8, 3.11, 3.12): the residue of the whole command, the state
/// a stopped run stores, and the exit status. `planned` is the number of launches the run planned.
pub(super) fn finish(
    pass: &mut Pass,
    lookup: &Lookup,
    pending: &Pending,
    ran: &Ran,
    planned: usize,
    quiet: bool,
) -> i32 {
    // The residue of the whole command, measured now that the run has launched every unit it could (spec 3.8).
    pass.settle_residue(&lookup.proofs, pending.listings());
    let id = pending.suite();
    // The state a stopped run stores is decided by `disabling` (spec 3.6). It is stored under the lock this run holds.
    if let Some(Disabling {
        code,
        label,
        keep_units,
    }) = disabling(
        ran.stopped.as_ref().map(|(_, violation)| violation),
        ran.over_budget > 0,
    ) {
        let stored = if keep_units {
            pass.disable(code, &label)
        } else {
            pass.disable_without_versions(code, &label)
        };
        if stored.is_ok() {
            say(
                quiet,
                format!(
                    "stoop: suite {id} disabled: {label}; run 'stoop forget --units {id}' after fixing it"
                ),
            );
        } else {
            // The state could not be stored, so no proof may stay usable under an enabled suite.
            pass.remove_bundle();
            say(
                quiet,
                format!(
                    "stoop: suite {id} could not store that it is disabled; its unit proofs are removed"
                ),
            );
        }
    }
    // A run with no failing launch has no verdict when a unit was not launched, when it stopped before its last
    // launch, or when a skipped unit's proof no longer holds because of the run's writes (spec 3.7). A stop says how
    // far it got (spec 3.12).
    let stopped_early = matches!(&ran.stopped, Some((index, _)) if index + 1 < planned);
    if ran.status == 0 {
        if stopped_early {
            say(
                quiet,
                format!(
                    "stoop: this run has no verdict (exit 125): only {} of {planned} launches ran",
                    ran.ran
                ),
            );
        }
        for breach in &ran.breaches {
            say(quiet, breach.line());
        }
        for unread in &ran.unread {
            say(quiet, unread.line());
        }
        for path in &ran.uncovered {
            say(
                quiet,
                format!(
                    "stoop: this run has no verdict (exit 125): {} changed, and no unit's new proof reads it",
                    safe(path)
                ),
            );
        }
    }
    let no_verdict = ran.unlaunched
        || stopped_early
        || !ran.breaches.is_empty()
        || !ran.unread.is_empty()
        || !ran.uncovered.is_empty();
    exit_status(ran.status, no_verdict)
}

/// The excused names that no new proof of this run reads by content (spec 3.10, rv34, rv38). A unit counts only when this
/// run stored its new proof and its launch read the name's content. A stat is not a read, so a name only stat'ed is unread.
pub(super) fn unread_excuses(
    excused: &[Excused],
    proven: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<Unread> {
    excused
        .iter()
        .filter(|excused| {
            !excused.units.iter().any(|unit| {
                proven
                    .get(unit)
                    .is_some_and(|read| read.contains(&excused.path))
            })
        })
        .map(|excused| Unread {
            path: excused.path.clone(),
            units: excused.units.clone(),
        })
        .collect()
}

/// The changed inputs that no new proof of this run reads by content (spec 3.10, PR 86 review round 2). Only a launch can
/// cover an input that the kept versions do not read, so an input stays uncovered when no launched unit read it.
pub(super) fn uncovered_inputs(
    uncovered: &[String],
    proven: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<String> {
    uncovered
        .iter()
        .filter(|path| !proven.values().any(|read| read.contains(path.as_str())))
        .cloned()
        .collect()
}

/// The paths of a list of inputs or outputs, in their order.
fn paths(entries: &[Input]) -> Vec<String> {
    entries.iter().map(|entry| entry.path.clone()).collect()
}

/// Why a changed run of a hooked suite starts no attribution pass (spec 3.1). The run and
/// `stoop explain` decide with the same checks, in the same order, and print the same text. The
/// run's last check, the suite lock, has no reason here: explain takes no lock, so it could never
/// print one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The run is forced to the full command: `STOOP_FULL`, a default branch, a verification run, or
    /// a configuration that is invalid or not independent.
    Forced,
    /// The whole command's proof still holds, so the run launches nothing.
    Unchanged,
    /// An option keeps the suite whole: `--no-record`, `--allow-network`, `--probe`, `--ignore` or
    /// `--ignore-env`.
    Options,
    /// `STOOP_OFF` turns tracing off, so the run is the full command without a trace.
    Off,
    /// The filter selects no unit.
    NoUnits,
    /// The roster cannot be recorded: an argument is not UTF-8, a unit name is not valid, or there
    /// are more units than a bundle holds.
    Unrecordable,
    /// No earlier run left a proof for the command.
    NoProof,
    /// A CI job keeps the full command, and a CI reader never writes a suite.
    Ci,
    /// Splitting is turned off by `enabled = false`, at the top level or on the suite.
    Disabled,
    /// The hook uses a form one unit cannot stand for: `{changed-inputs}`, or a list with a join.
    Form,
    /// A unit's text holds the separator of a joined placeholder.
    Join,
    /// A unit's absolute path holds a newline, which a newline list cannot name.
    Line,
    /// The suite has no current record of an earlier full run.
    NoBundle,
    /// The suite directory cannot take a new entry, so a pass could not store its first proof.
    Unwritable,
    /// A unit of the roster already has a proof.
    Proven,
    /// The suite is disabled: a launch of an earlier pass broke an independence check, or its proofs were
    /// over budget. `stoop forget --units` clears the state (spec 3.6).
    SuiteDisabled,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Forced => "the run is forced to the full command",
            Self::Unchanged => "the whole command's proof still holds",
            Self::Options => {
                "--no-record, --allow-network, --probe, --ignore or --ignore-env keeps the full command"
            }
            Self::Off => "STOOP_OFF turns tracing off, so the run is the full command",
            Self::NoUnits => "the filter selects no unit",
            Self::Unrecordable => {
                "the roster cannot be recorded: an argument is not UTF-8, a unit name is not valid, or there are more than 4,096 units"
            }
            Self::NoProof => {
                "no earlier run left a proof for this command, so the first run is the full command"
            }
            Self::Ci => "CI is set, so the run keeps the full command",
            Self::Disabled => "splitting is turned off by enabled = false",
            Self::Form => {
                "the hook uses a form a single unit cannot stand for ({changed-inputs}, or a list with a join)"
            }
            Self::Join => "a unit's text contains the separator of a joined placeholder",
            Self::Line => "a unit's absolute path holds a newline, which a newline list cannot name",
            Self::NoBundle => "the suite has no current record of an earlier full run",
            Self::Unwritable => "the suite store cannot take a new entry",
            Self::Proven => "a unit of the roster already has a proof",
            Self::SuiteDisabled => "the suite is disabled",
        })
    }
}

/// A hooked suite as one invocation names it: its roster as the filter and discovery give it, and
/// the record a pass would write for that roster, or the refusal that keeps the record from being
/// made.
pub(crate) struct Suite {
    /// The suite's ID, which names its bundle and its lock.
    pub(crate) id: String,
    /// The roster, in catalog order.
    pub(crate) units: Vec<String>,
    /// The record a pass would write for the roster, or the refusal that keeps it from being made.
    pub(crate) pending: Result<Pending, Refusal>,
}

/// Spec 3.1, checks 1 to 7: the decisions taken before the store is read or the lock is taken. The
/// run and `stoop explain` both call it, so they cannot disagree on these checks.
pub(crate) fn screen<'p>(
    cx: &RunCx<'_>,
    hook: &Hook,
    config: &Config,
    lookup: &Lookup,
    pending: Result<&'p Pending, Refusal>,
) -> Result<&'p Pending, Refusal> {
    // STOOP_OFF makes the run untraced before it looks at anything else. Explain names it first, even
    // when the whole command's proof still holds or the full form is forced.
    if run::env_switch("STOOP_OFF", true) {
        return Err(Refusal::Off);
    }
    // 1 and 2: a forced full run, and a whole-command proof that still holds.
    if cx.full_reason.is_some() {
        return Err(Refusal::Forced);
    }
    if lookup.hit_idx.is_some() {
        return Err(Refusal::Unchanged);
    }
    let pending = pending?;
    // 3: with no legacy proof at all, the first run is the full command.
    if lookup.proofs.is_empty() {
        return Err(Refusal::NoProof);
    }
    // 4 to 7: a CI job, an opted-out suite, and a roster that cannot be launched as units keep the full command.
    roster_screen(cx, hook, config, pending)?;
    Ok(pending)
}

/// Spec 3.1, checks 4 to 7. `screen` runs them for an attribution pass, and a learning run after its full command runs
/// them too (spec 3.10, completion), without the first-run gates that `screen` applies.
pub(crate) fn roster_screen(
    cx: &RunCx<'_>,
    hook: &Hook,
    config: &Config,
    pending: &Pending,
) -> Result<(), Refusal> {
    if policy::ci() {
        return Err(Refusal::Ci);
    }
    if config.splitting_disabled(&hook.original, cx.rel_cwd) {
        return Err(Refusal::Disabled);
    }
    if !expand::supported(hook) {
        return Err(Refusal::Form);
    }
    if !expand::expands(hook, pending.units(), cx.root, cx.cwd) {
        return Err(Refusal::Join);
    }
    if !expand::lines_fit(hook, pending.units(), cx.root, cx.cwd) {
        return Err(Refusal::Line);
    }
    Ok(())
}

/// The two lines `stoop explain` adds to a suite's decision (spec 4.16): the tracked counts, then
/// whether a changed run would start a pass, or the reason it would not. It reads the store and
/// takes no lock. Nothing is written, created or launched.
pub(crate) fn explain_lines(
    cx: &RunCx<'_>,
    config: &Config,
    lookup: &Lookup,
    suite: Option<&Suite>,
    store: &Path,
    key: &str,
) -> Option<Vec<String>> {
    let suite = suite?;
    let hook = cx.hook.as_ref()?;
    let decision = screen(
        cx,
        hook,
        config,
        lookup,
        suite.pending.as_ref().map_err(|refusal| *refusal),
    )
    .and_then(|pending| bundle::probe(store, pending, key).map(|()| pending.units().len()));
    let residue_text = bundle::known_residue(store, &suite.id, key)
        .map(|(count, paths)| residue::line(count, &paths));
    let tracked = tracked(store, &suite.id, &suite.units, key);
    let decision = match decision {
        Ok(launches) => format!("stoop: would run an attribution pass: {launches} launches"),
        Err(Refusal::SuiteDisabled) => match bundle::disabled(store, &suite.id) {
            Some(label) => format!(
                "stoop: no attribution pass: suite {} disabled: {label}; run 'stoop forget --units {}' after fixing it",
                suite.id, suite.id
            ),
            None => format!("stoop: no attribution pass: {}", Refusal::SuiteDisabled),
        },
        Err(refusal) => format!("stoop: no attribution pass: {refusal}"),
    };
    Some(
        residue_text
            .into_iter()
            .chain([tracked, decision])
            .collect(),
    )
}

/// The tracked line `stoop explain` prints for a suite: its roster's units, the inputs their proofs name, and how many of
/// them hold a proof (spec 4.16). It reads the store and takes no lock.
pub(crate) fn tracked(store: &Path, id: &str, units: &[String], key: &str) -> String {
    let (inputs, proven) = bundle::counts(store, id, units, key);
    let total = units.len();
    format!(
        "stoop: tracked {total} units, {inputs} inputs; {proven} proven, {} without a proof (suite {id})",
        total - proven
    )
}

/// One line for the operator, unless `--quiet` asks for none.
fn say(quiet: bool, line: String) {
    if !quiet {
        eprintln!("{line}");
    }
}

/// Says why a unit was not launched. Such a unit has no status, so the run has no verdict unless a launch fails
/// (spec 3.7). One line for the operator says why, unless `--quiet` asks for none.
///
/// Three branches reach this, and they set the same flag. The launch directory cannot be made when its name is already
/// taken or the suite directory refuses a new entry. The name comes from a counter that the bundle's writes share, and
/// I10 pins the taken-name case. The list files cannot be written into the directory this iteration has just made, so
/// only an I/O error reaches that branch. The arguments cannot be expanded only if `screen` had not run `expands` on
/// the same units, and it always has, so that branch is a guard for a later change to `screen`.
fn not_launched(quiet: bool, unit: &str, why: &dyn fmt::Display) {
    say(quiet, format!("stoop: not launched for {unit}: {why}"));
}

/// The first nonzero status in catalog order, so a failing unit never stops the pass (spec 3.9).
fn keep(status: i32, unit: i32) -> i32 {
    if status == 0 {
        unit
    } else {
        status
    }
}

/// What a pass stores when it stops (spec 3.6): the suite's state, and whether the unit proofs it holds are kept.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Disabling {
    code: &'static str,
    label: String,
    keep_units: bool,
}

/// The state a pass stores when it stops. A breach disables the suite and keeps the unit proofs it holds. A pass
/// whose unit proofs exceed the budget disables it with none. A breach is why the pass stopped, so it takes
/// precedence over the budget.
fn disabling(stopped: Option<&Violation>, over_budget: bool) -> Option<Disabling> {
    match (stopped, over_budget) {
        (Some(violation), _) => Some(Disabling {
            code: violation.code(),
            label: violation.label(),
            keep_units: true,
        }),
        (None, true) => Some(Disabling {
            code: "over_budget",
            label: OVER_BUDGET.to_owned(),
            keep_units: false,
        }),
        (None, false) => None,
    }
}

/// The exit status of a run (spec 3.7). A failing launch is a verdict, so its status wins, even 125. Without one, the
/// run has no verdict when `no_verdict` holds, and it exits 125; otherwise it exits 0.
fn exit_status(failure: i32, no_verdict: bool) -> i32 {
    if failure != 0 {
        failure
    } else if no_verdict {
        125
    } else {
        0
    }
}

/// The store's unit folder, excluded from every launch's inputs (spec 4.7): its absolute path, and its
/// root-relative key when the store sits inside the root. Each is excluded by its literal text, so a
/// store name that the ignore-line parser would read as a comment, a glob or with trimmed spaces is still
/// its own folder. A pattern with a slash matches only that folder and what it holds, so a folder that
/// merely shares the store's name is still an input.
fn store_folders(root: &Path, store: &Path) -> Vec<String> {
    let folder = store.join("units").join("v1");
    let absolute = folder.to_string_lossy().into_owned();
    let key = to_key(root, &folder);
    if key == absolute {
        vec![absolute]
    } else {
        vec![absolute, key]
    }
}

/// The files one launch names (spec 3.7, 4.12). `changed` is the newline list of the unit's cwd-relative
/// path, which `STOOP_CHANGED_FILE` names and `{changed:file}` reads. `inputs` holds the launch's changed
/// inputs, which `STOOP_CHANGED_INPUTS_FILE` names. `others` holds the other list forms the hook names, once each.
struct Lists {
    changed: OsString,
    inputs: OsString,
    others: Vec<(FileMode, Base, OsString)>,
}

impl Lists {
    /// Writes the launch's files into its folder, and returns their paths.
    fn write(
        folder: &mut Scratch,
        root: &Path,
        cwd: &Path,
        unit: &str,
        forms: &[(FileMode, Base)],
        inputs: &OsStr,
    ) -> io::Result<Lists> {
        let changed = write_form(folder, root, cwd, unit, FileMode::File, Base::Cwd)?;
        let mut others: Vec<(FileMode, Base, OsString)> = Vec::new();
        for &(mode, base) in forms {
            let named = (mode, base) == (FileMode::File, Base::Cwd);
            if named || others.iter().any(|(m, b, _)| *m == mode && *b == base) {
                continue;
            }
            let path = write_form(folder, root, cwd, unit, mode, base)?;
            others.push((mode, base, path));
        }
        let inputs = folder
            .write("inputs", inputs.as_encoded_bytes())?
            .into_os_string();
        Ok(Lists {
            changed,
            inputs,
            others,
        })
    }

    /// The path of the list file a form reads.
    fn get(&self, mode: FileMode, base: Base) -> Option<OsString> {
        if (mode, base) == (FileMode::File, Base::Cwd) {
            return Some(self.changed.clone());
        }
        self.others
            .iter()
            .find(|(m, b, _)| *m == mode && *b == base)
            .map(|(_, _, path)| path.clone())
    }
}

/// Writes one unit's list in a form into the launch's folder, and returns its path.
fn write_form(
    folder: &mut Scratch,
    root: &Path,
    cwd: &Path,
    unit: &str,
    mode: FileMode,
    base: Base,
) -> io::Result<OsString> {
    let bytes = expand::list_bytes(root, cwd, unit, mode, base);
    Ok(folder
        .write(expand::list_name(mode, base), &bytes)?
        .into_os_string())
}

#[cfg(all(test, unix))]
mod tests {
    use super::super::independence::unit_evidence;
    use super::super::independence::Violation;
    use super::{disabling, exit_status, Disabling};
    use crate::trace::{Touch, Trace};
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    const READ: Touch = Touch {
        listed: false,
        read: true,
        content: true,
    };
    const STAT: Touch = Touch {
        listed: false,
        read: true,
        content: false,
    };

    fn trace(entries: &[(PathBuf, Touch)]) -> Trace {
        let mut trace = Trace::default();
        for (path, touch) in entries {
            trace.touched.insert(path.clone(), *touch);
        }
        trace
    }

    /// A root with `tests/a.t`, `tests/b.t`, a directory link `alias` to `tests`, and a file link
    /// `link.t` to `tests/a.t`.
    fn tree(name: &str) -> (PathBuf, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("stoop-evidence-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("tests")).unwrap();
        fs::write(dir.join("tests/a.t"), b"a").unwrap();
        fs::write(dir.join("tests/b.t"), b"b").unwrap();
        symlink(dir.join("tests"), dir.join("alias")).unwrap();
        symlink(dir.join("tests/a.t"), dir.join("link.t")).unwrap();
        let real = fs::canonicalize(&dir).unwrap();
        (dir, real)
    }

    #[test]
    fn a_content_read_of_the_units_own_name_is_evidence() {
        let (dir, real) = tree("lexical");
        let trace = trace(&[(dir.join("tests/a.t"), READ)]);
        assert!(unit_evidence(&dir, &real, &trace, "tests/a.t"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_read_through_a_symlinked_directory_is_evidence() {
        let (dir, real) = tree("parent");
        let trace = trace(&[(dir.join("alias/a.t"), READ)]);
        assert!(unit_evidence(&dir, &real, &trace, "tests/a.t"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_read_through_a_symlinked_file_name_is_not_evidence() {
        let (dir, real) = tree("leaf");
        let trace = trace(&[(dir.join("link.t"), READ)]);
        assert!(!unit_evidence(&dir, &real, &trace, "tests/a.t"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stat_is_never_evidence() {
        let (dir, real) = tree("stat");
        let trace = trace(&[(dir.join("tests/a.t"), STAT)]);
        assert!(!unit_evidence(&dir, &real, &trace, "tests/a.t"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_content_read_of_another_file_is_not_evidence() {
        let (dir, real) = tree("other");
        let trace = trace(&[(dir.join("tests/b.t"), READ), (dir.join("src.src"), READ)]);
        assert!(!unit_evidence(&dir, &real, &trace, "tests/a.t"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_over_budget_pass_disables_the_suite_and_keeps_no_unit() {
        assert_eq!(
            disabling(None, true),
            Some(Disabling {
                code: "over_budget",
                label: "unit proofs exceed 8 MiB".to_owned(),
                keep_units: false,
            })
        );
    }

    #[test]
    fn a_pass_with_no_breach_and_no_overflow_stores_no_state() {
        assert_eq!(disabling(None, false), None);
    }

    #[test]
    fn a_breach_keeps_its_units_and_takes_precedence_over_an_overflow() {
        let breach = Violation::WroteUnit {
            writer: "tests/a.t".to_owned(),
            unit: "tests/b.t".to_owned(),
        };
        let expected = Some(Disabling {
            code: "wrote_unit",
            label: "tests/a.t wrote tests/b.t".to_owned(),
            keep_units: true,
        });
        assert_eq!(disabling(Some(&breach), false), expected.clone());
        assert_eq!(disabling(Some(&breach), true), expected);
    }

    #[test]
    fn a_failing_launch_keeps_its_status_after_a_unit_was_not_launched() {
        assert_eq!(exit_status(1, true), 1);
        assert_eq!(exit_status(2, true), 2);
        assert_eq!(exit_status(1, false), 1);
        // A failing launch that itself exits 125 keeps 125 as its own status.
        assert_eq!(exit_status(125, true), 125);
    }

    #[test]
    fn a_run_with_no_failure_has_no_verdict_when_a_unit_was_not_launched_or_it_stopped() {
        assert_eq!(exit_status(0, false), 0);
        assert_eq!(exit_status(0, true), 125);
    }
}
