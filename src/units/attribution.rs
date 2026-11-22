//! The attribution pass (spec 3.1 to 3.4). A changed run of a hooked suite launches each unit of its
//! roster once, in roster order, under one traced launch each. A launch that exits 0 and read its
//! own file stores that unit's proof. Nothing is skipped on the strength of a unit proof yet, so
//! every run that does not dispatch is the legacy path, unchanged.

use super::bundle::{self, LaunchGuard, Pass, Pending, Start, Stored};
use super::config::Config;
use super::expand;
use super::hook::safe;
use super::policy;
use crate::ignore::Ignore;
use crate::pathutil::{to_key, Physical};
use crate::proof::now;
use crate::run::{self, assemble, How, Lookup, Outcome, RunCx};
use crate::trace::Trace;
use std::path::Path;

/// Runs the attribution pass when every condition of spec 3.1 holds. `None` leaves the run to the
/// legacy path, which then runs exactly as it did before this module existed.
pub(crate) fn pass(
    cx: &RunCx<'_>,
    config: &Config,
    lookup: &Lookup,
    pending: &Pending,
    store: &Path,
    key: &str,
) -> Option<Outcome> {
    let hook = cx.hook.as_ref()?;
    // 1 and 2: a forced full run and a whole-command hit are decided by the legacy path.
    if cx.full_reason.is_some() || lookup.hit_idx.is_some() {
        return None;
    }
    // 3: with no legacy proof at all, the first-run form runs.
    if lookup.proofs.is_empty() {
        return None;
    }
    // 4 and 5: a CI job and an opted-out suite keep the first-run form.
    if policy::ci() || config.splitting_disabled(&hook.original, cx.rel_cwd) {
        return None;
    }
    // 6 and 7: every placeholder must expand to one unit, for every unit of the roster.
    if !expand::supported(hook) {
        return None;
    }
    let launches = expand::launches(hook, pending.units(), cx.root, cx.cwd)?;
    // 8 and 9: the bundle is checked without the lock, then again under it.
    let ignore = Ignore::new(
        &cx.o.ignore,
        Some(&cx.root.join(".stoopignore")),
        &cx.o.transient,
    );
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
    say(
        quiet,
        format!(
            "stoop: attribution pass: {} units, one launch each",
            launches.len()
        ),
    );
    let real_root = std::fs::canonicalize(cx.root).unwrap_or_else(|_| cx.root.clone());
    let mut status = 0;
    let mut over_budget = 0;
    for launch in &launches {
        std::env::set_var("STOOP_CHANGED", &launch.value);
        std::env::set_var("STOOP_UNITS", &launch.value);
        let unit = safe(&launch.unit);
        let unit_status =
            match run::launch_traced(cx, &launch.argv, &ignore, &real_root, false, false, false) {
                // A trace that fails before the command starts has run nothing. The unit runs once
                // untraced and keeps no proof. It is never retried traced, because that could run it
                // a second time.
                Err(error) => {
                    say(
                        quiet,
                        format!(
                            "stoop: not traced ({}); running {unit} without a proof",
                            safe(&error.to_string())
                        ),
                    );
                    run::plain(&launch.argv, &[])
                }
                Ok(trace) if trace.status != 0 => trace.status,
                Ok(trace) if !unit_evidence(cx.root, &real_root, &trace, &launch.unit) => {
                    say(
                        quiet,
                        format!("stoop: no proof for {unit}: the launch never read it"),
                    );
                    0
                }
                Ok(trace) => {
                    match assemble(cx.root, &real_root, &trace, &ignore) {
                        Ok(kept) => {
                            let stored = bundle_pass.record(
                                &launch.unit,
                                &kept.inputs,
                                &kept.outputs,
                                now(),
                            );
                            if let Stored::OverBudget = stored {
                                over_budget += 1;
                            }
                        }
                        Err(why) => say(
                            quiet,
                            format!("stoop: not recorded for {unit}: {}", safe(&why.to_string())),
                        ),
                    }
                    0
                }
            };
        // The first nonzero status in catalog order. A failing unit never stops the pass.
        if status == 0 {
            status = unit_status;
        }
    }
    for name in run::HOOK_ENV {
        std::env::set_var(name, "");
    }
    if over_budget > 0 {
        say(
            quiet,
            format!(
                "stoop: suite {}: unit proofs exceed 8 MiB; {over_budget} units left without a proof",
                pending.suite()
            ),
        );
    }
    Some(Outcome {
        status,
        key: key.to_owned(),
        how: How::Units,
    })
}

/// One line for the operator, unless `--quiet` asks for none.
fn say(quiet: bool, line: String) {
    if !quiet {
        eprintln!("{line}");
    }
}

/// Whether the launch read the unit's own file: a content read of it under the name the unit has,
/// or through a directory the launch reached by a link. A stat does not count. Neither does a read
/// through a link whose own name differs from the unit, which is the conservative choice. The
/// mapping is the one `build_inputs` uses for the same paths.
pub(crate) fn unit_evidence(root: &Path, real_root: &Path, trace: &Trace, unit: &str) -> bool {
    let mut phys = Physical::new(root, real_root);
    trace.touched.iter().any(|(lex, touch)| {
        touch.content
            && (to_key(root, lex) == unit
                || physical_key(&mut phys, lex).is_some_and(|key| key == unit))
    })
}

/// The repository-relative name of the entry that `lex` names once its parent directories are
/// resolved. A link as the last component is not followed, so it keeps its own name.
fn physical_key(phys: &mut Physical, lex: &Path) -> Option<String> {
    let location = phys.locate(lex)?;
    let rel = phys.repo_rel(&location.path)?;
    rel.to_str().map(str::to_owned)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::trace::Touch;
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
