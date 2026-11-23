//! The subset run (spec 3.10, E17 and E18; 3.11 and 3.12). A changed run of a hooked suite whose affected units are
//! not the whole roster launches each affected unit once, in roster order, and keeps the proof of every other unit.
//! A run whose affected units are the whole roster is the attribution pass, which keeps its versions as well. Both
//! take the suite lock and decide again under it (spec 3.10), then launch through `attribution::launch_each`, which
//! judges every launch. Explain names the decision and the first launch it would make, and launches nothing.

use super::attribution;
use super::bundle::{self, Kept, Pass, Pending};
use super::engine::{self, Judged, Plan, Verdict, NAMED};
use super::expand;
use super::hook::{render, safe, Hook};
use super::independence::{Named, Roster};
use super::launch::SkippedUnit;
use crate::ignore::Ignore;
use crate::input::Input;
use crate::run::{self, How, Lookup, Outcome, RunCx};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::path::Path;

/// What a decision that launches units came to (spec 3.10): the run's outcome, or the verdict that the suite lock
/// reads when it no longer keeps the launches. A verdict is taken as the run's decision.
pub(crate) enum Attempt {
    Ran(Outcome),
    Decided(Verdict),
}

/// What a run's launches share: the run's context, its hook, the ignore set its launches are judged with, the legacy
/// lookup, the roster the run took, and the whole command's key.
struct Frame<'a, 'b> {
    cx: &'a RunCx<'b>,
    hook: &'a Hook,
    ignore: &'a Ignore,
    lookup: &'a Lookup,
    pending: &'a Pending,
    key: &'a str,
}

/// Decides again under the suite lock, and launches the affected units when the decision still holds (spec 3.10, E17 and
/// E18). A busy lock gives the full command, with the busy line. Only the units the locked decision names are launched.
pub(crate) fn execute(
    cx: &RunCx<'_>,
    lookup: &Lookup,
    pending: &Pending,
    store: &Path,
    key: &str,
    max_age: u64,
) -> Attempt {
    let Some(hook) = cx.hook.as_ref() else {
        return Attempt::Decided(engine::unrun());
    };
    let ignore = attribution::ignore_for(cx, store);
    let guard = attribution::guard_of(cx, &ignore);
    let judged = Judged::new(cx, pending, &lookup.proofs, max_age);
    match bundle::keep(store, pending, key, guard, |view| {
        engine::judge_units(&judged, view)
    }) {
        Kept::Busy => {
            if !cx.o.quiet {
                eprintln!(
                    "stoop: suite {} is busy in another stoop; running the full command",
                    pending.suite()
                );
            }
            Attempt::Decided(engine::unrun())
        }
        Kept::Unavailable => Attempt::Decided(engine::unrun()),
        Kept::Declined(verdict) => Attempt::Decided(verdict),
        Kept::Locked(pass, plan) => {
            let frame = Frame {
                cx,
                hook,
                ignore: &ignore,
                lookup,
                pending,
                key,
            };
            Attempt::Ran(launch(&frame, pass, &plan))
        }
    }
}

/// Launches the units of `plan` in roster order, one traced launch each, under the lock that `pass` holds (spec 3.11).
/// It prints the run's header first (spec 3.12), and settles the run once its launches end (spec 3.7, 3.8).
fn launch(frame: &Frame<'_, '_>, mut pass: Pass, plan: &Plan) -> Outcome {
    let cx = frame.cx;
    let quiet = cx.o.quiet;
    let units = frame.pending.units();
    let planned = plan.affected.len();
    if planned == units.len() {
        pass.set_phase("attribution");
        say(
            quiet,
            format!(
                "stoop: attribution pass: {} units, one launch each",
                units.len()
            ),
        );
    } else {
        say(quiet, header(plan));
    }
    let real_root = std::fs::canonicalize(cx.root).unwrap_or_else(|_| cx.root.clone());
    let roster = Roster::new(units);
    let launched: Vec<String> = plan
        .affected
        .iter()
        .map(|affected| affected.unit.clone())
        .collect();
    // Every unit's stored entries name a path, so a launch that writes one of them is seen, including the entries of a
    // unit that is launched later (spec 3.8, 3.11).
    let mut named = Named::default();
    for (unit, inputs, outputs) in pass.held() {
        named.store(&unit, &paths(&inputs), &paths(&outputs));
    }
    let skipped = skipped_units(&pass, units, &launched);
    // An attribution pass names no changed input: each of its launches sees an empty STOOP_CHANGED_INPUTS (spec 3.11).
    let changed: HashMap<String, Vec<String>> = if planned == units.len() {
        HashMap::new()
    } else {
        plan.affected
            .iter()
            .map(|affected| (affected.unit.clone(), affected.changed.clone()))
            .collect()
    };
    let mut ran = attribution::launch_each(
        cx,
        frame.hook,
        frame.ignore,
        &mut pass,
        &launched,
        &roster,
        &mut named,
        &skipped,
        &changed,
        &real_root,
    );
    for name in run::HOOK_ENV {
        std::env::set_var(name, "");
    }
    ran.unread = attribution::unread_excuses(&pass, &plan.excused, &ran.proven);
    let status = attribution::finish(&mut pass, frame.lookup, frame.pending, &ran, planned, quiet);
    Outcome {
        status,
        key: frame.key.to_owned(),
        how: How::Units,
    }
}

/// The subset header (spec 3.12): the roster's units and inputs, the number of launches and the cause of the first one,
/// then the launched units, at most twenty of them.
pub(crate) fn header(plan: &Plan) -> String {
    let names: Vec<String> = plan
        .affected
        .iter()
        .take(NAMED)
        .map(|affected| safe(&affected.unit))
        .collect();
    let cause = plan
        .affected
        .first()
        .map_or_else(String::new, |affected| affected.why.clone());
    let mut line = format!(
        "stoop: tracked {} units, {} inputs; run {} ({cause}): {}",
        plan.units,
        plan.inputs,
        plan.affected.len(),
        names.join(", ")
    );
    let more = plan.affected.len().saturating_sub(NAMED);
    if more > 0 {
        line.push_str(&format!(" (+{more} more)"));
    }
    line
}

/// The decision line `stoop explain` prints for a decision that launches units (spec 3.12). A pass names its launches,
/// and a subset names its count and the argv of its first launch. The argv has no list file: a placeholder names it.
pub(crate) fn decision_line(cx: &RunCx<'_>, key: &str, plan: &Plan, whole: bool) -> String {
    if whole {
        return format!(
            "stoop: would run {key} (attribution pass): {} launches, one unit each",
            plan.affected.len()
        );
    }
    let launches = plan.affected.len();
    let Some(hook) = cx.hook.as_ref() else {
        return format!("stoop: would run {key}");
    };
    let first = plan
        .affected
        .first()
        .map_or("", |affected| affected.unit.as_str());
    let argv = expand::launch(hook, first, cx.root, cx.cwd, &|_, _| {
        Some(OsString::from("<list>"))
    })
    .map_or_else(String::new, |launch| render(&launch.argv));
    let more = if launches > 1 {
        format!(" (+{} more)", launches - 1)
    } else {
        String::new()
    };
    format!(
        "stoop: would run {key} ({launches} of {} units affected, one launch each): argv {argv}{more}",
        plan.units
    )
}

/// The units a run keeps without launching: the roster's units that are not launched, each with what its proof names
/// (spec 3.7). Every such unit holds a proof, because a unit without one is affected.
fn skipped_units(pass: &Pass, units: &[String], launched: &[String]) -> Vec<SkippedUnit> {
    let launched: BTreeSet<&str> = launched.iter().map(String::as_str).collect();
    units
        .iter()
        .filter(|unit| !launched.contains(unit.as_str()))
        .map(|unit| {
            let (inputs, outputs) = pass.held_of(unit);
            let mut paths = vec![unit.clone()];
            paths.extend(self::paths(&inputs));
            paths.extend(self::paths(&outputs));
            SkippedUnit {
                unit: unit.clone(),
                listed: inputs
                    .iter()
                    .filter(|input| input.id.starts_with("dl:"))
                    .map(|input| input.path.clone())
                    .collect(),
                paths,
            }
        })
        .collect()
}

/// The paths of a list of inputs or outputs, in their order.
fn paths(entries: &[Input]) -> Vec<String> {
    entries.iter().map(|entry| entry.path.clone()).collect()
}

/// One line for the operator, unless `--quiet` asks for none.
fn say(quiet: bool, line: String) {
    if !quiet {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::super::engine::Affected;
    use super::*;

    #[test]
    fn the_header_names_the_cause_and_at_most_twenty_units() {
        let affected: Vec<Affected> = (0..23)
            .map(|n| Affected {
                unit: format!("tests/{n:02}.t"),
                why: "new".into(),
                changed: Vec::new(),
            })
            .collect();
        let line = header(&Plan {
            units: 30,
            inputs: 7,
            affected,
            excused: Vec::new(),
        });
        assert!(
            line.starts_with(
                "stoop: tracked 30 units, 7 inputs; run 23 (new): tests/00.t, tests/01.t"
            ),
            "{line}"
        );
        assert!(line.ends_with("tests/19.t (+3 more)"), "{line}");
    }
}
