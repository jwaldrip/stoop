//! The attribution pass (spec 3.1 to 3.7). A changed run of a hooked suite launches each unit of its roster
//! once, in roster order, under one traced launch each. Each launch is judged by the independence checks in
//! `launch` (spec 3.3): one that breaks a check stops the pass and disables the suite. Nothing is skipped on
//! the strength of a unit proof yet, so every run that does not dispatch is the legacy path, unchanged.
//! `stoop explain` asks the same checks, through `screen` and `probe`, so it predicts the decision made here.

use super::bundle::{self, LaunchGuard, Pass, Pending, Scratch, Start, Stored};
use super::config::Config;
use super::expand;
use super::hook::{safe, Base, FileMode, Hook};
use super::independence::{Named, Roster, Violation, Written};
use super::launch::{self, Observed, Verdict};
use super::policy;
use crate::ignore::Ignore;
use crate::input::Input;
use crate::pathutil::to_key;
use crate::proof::now;
use crate::run::{self, How, Lookup, Outcome, RunCx};
use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::Path;

/// The output the pass names when it disables a suite for an over-budget set of proofs (spec 3.6).
const OVER_BUDGET: &str = "unit proofs exceed 8 MiB";

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
    let mut ignore = Ignore::new(
        &cx.o.ignore,
        Some(&cx.root.join(".stoopignore")),
        &cx.o.transient,
    );
    for folder in store_folders(cx.root, store) {
        ignore.exclude_folder(&folder);
    }
    let guard = LaunchGuard {
        env: cx.env_now.clone(),
        env_excluded: cx.env_excluded.clone(),
        ignore: ignore.patterns(),
    };
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
    let forms = expand::list_forms(hook);
    let roster = Roster::new(units);
    // What this run's launches have written, and what the proofs stored so far name (spec 3.3).
    let mut written = Written::default();
    let mut named = Named::default();
    let mut status = 0;
    let mut ran = 0;
    let mut over_budget = 0;
    // The first launch that breaks an independence check, by its roster index, and what it breaks.
    let mut stopped: Option<(usize, Violation)> = None;
    for (index, unit) in units.iter().enumerate() {
        let unit_name = safe(unit);
        // The launch's list files live in its own folder, which is removed when this iteration ends.
        let mut folder = match bundle_pass.scratch() {
            Ok(folder) => folder,
            Err(error) => {
                status = keep(status, not_launched(quiet, &unit_name, &error));
                continue;
            }
        };
        let lists = match Lists::write(&mut folder, cx.root, cx.cwd, unit, &forms) {
            Ok(lists) => lists,
            Err(error) => {
                status = keep(status, not_launched(quiet, &unit_name, &error));
                continue;
            }
        };
        let Some(launch) = expand::launch(hook, unit, cx.root, cx.cwd, &|mode, base| {
            lists.get(mode, base)
        }) else {
            let why = "its arguments cannot be expanded";
            status = keep(status, not_launched(quiet, &unit_name, &why));
            continue;
        };
        std::env::set_var("STOOP_CHANGED", &launch.value);
        std::env::set_var("STOOP_UNITS", &launch.value);
        std::env::set_var("STOOP_CHANGED_FILE", &lists.changed);
        std::env::set_var("STOOP_CHANGED_INPUTS", "");
        std::env::set_var("STOOP_CHANGED_INPUTS_FILE", &lists.inputs);
        // The root listing before the launch, which the root guard compares with the one after it (spec 3.5).
        let root_before = launch::root_names(cx.root);
        let unit_status =
            match run::launch_traced(cx, &launch.argv, &ignore, &real_root, false, false, false) {
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
                    ran += 1;
                    run::plain(&launch.argv, &[])
                }
                Ok(trace) => {
                    ran += 1;
                    let observed = Observed::of(&trace, cx.root, &real_root, &ignore);
                    let context = launch::Context {
                        root: cx.root,
                        real_root: &real_root,
                        ignore: &ignore,
                        roster: &roster,
                        members: std::slice::from_ref(unit),
                        written: &written,
                        named: &named,
                        root_before: &root_before,
                    };
                    match launch::judge(&context, &trace, &observed) {
                        Verdict::Proven(kept) => {
                            let stored = bundle_pass.record(
                                &launch.unit,
                                &kept.inputs,
                                &kept.outputs,
                                now(),
                            );
                            match stored {
                                Stored::OverBudget => over_budget += 1,
                                Stored::Stored | Stored::WriteFailed => {
                                    named.store(unit, &paths(&kept.inputs), &paths(&kept.outputs))
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
                            stopped = Some((index, violation));
                        }
                    }
                    written.add(&observed.writes, unit);
                    trace.status
                }
            };
        // The first nonzero status in roster order. A failing unit never stops the pass (spec 3.9).
        status = keep(status, unit_status);
        if stopped.is_some() {
            break;
        }
    }
    for name in run::HOOK_ENV {
        std::env::set_var(name, "");
    }
    let id = pending.suite();
    // A violation disables the suite and keeps the proofs it already holds. An over-budget pass disables it with
    // none (spec 3.6). Either way the state is stored under the lock this pass holds.
    let disabling = match &stopped {
        Some((_, violation)) => Some((violation.code(), violation.label(), true)),
        None if over_budget > 0 => Some(("over_budget", OVER_BUDGET.to_owned(), false)),
        None => None,
    };
    if let Some((code, label, keep_units)) = disabling {
        let stored = if keep_units {
            bundle_pass.disable(code, &label)
        } else {
            bundle_pass.disable_without_versions(code, &label)
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
            bundle_pass.remove_bundle();
            say(
                quiet,
                format!(
                    "stoop: suite {id} could not store that it is disabled; its unit proofs are removed"
                ),
            );
        }
    }
    // A run that stopped before its last launch has no verdict when nothing failed (spec 3.7). It says how far it
    // got (spec 3.12).
    let planned = units.len();
    if status == 0 && matches!(&stopped, Some((index, _)) if index + 1 < planned) {
        say(
            quiet,
            format!(
                "stoop: this run has no verdict (exit 125): only {ran} of {planned} launches ran"
            ),
        );
        status = 125;
    }
    Some(Outcome {
        status,
        key: key.to_owned(),
        how: How::Units,
    })
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
fn screen<'p>(
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
    // 4 and 5: a CI job and an opted-out suite keep the full command.
    if policy::ci() {
        return Err(Refusal::Ci);
    }
    if config.splitting_disabled(&hook.original, cx.rel_cwd) {
        return Err(Refusal::Disabled);
    }
    // 6 and 7: every placeholder must stand for one unit, and every unit of the roster must expand.
    if !expand::supported(hook) {
        return Err(Refusal::Form);
    }
    if !expand::expands(hook, pending.units(), cx.root, cx.cwd) {
        return Err(Refusal::Join);
    }
    if !expand::lines_fit(hook, pending.units(), cx.root, cx.cwd) {
        return Err(Refusal::Line);
    }
    Ok(pending)
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
    let (inputs, proven) = bundle::counts(store, &suite.id, &suite.units, key);
    let total = suite.units.len();
    let tracked = format!(
        "stoop: tracked {total} units, {inputs} inputs; {proven} proven, {} without a proof (suite {})",
        total - proven,
        suite.id
    );
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
    Some(vec![tracked, decision])
}

/// One line for the operator, unless `--quiet` asks for none.
fn say(quiet: bool, line: String) {
    if !quiet {
        eprintln!("{line}");
    }
}

/// The status of a unit that was not launched: 125, the status of a run that stoop could not carry
/// out. One line for the operator says why, unless `--quiet` asks for none.
fn not_launched(quiet: bool, unit: &str, why: &dyn fmt::Display) -> i32 {
    say(quiet, format!("stoop: not launched for {unit}: {why}"));
    125
}

/// The first nonzero status in catalog order, so a failing unit never stops the pass (spec 3.9).
fn keep(status: i32, unit: i32) -> i32 {
    if status == 0 {
        unit
    } else {
        status
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
/// path, which `STOOP_CHANGED_FILE` names and `{changed:file}` reads. `inputs` is empty, for
/// `STOOP_CHANGED_INPUTS_FILE`. `others` holds the other list forms the hook names, once each.
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
        let inputs = folder.write("inputs", &[])?.into_os_string();
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
}
