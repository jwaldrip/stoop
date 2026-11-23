//! One traced unit launch, judged (spec 3.3 to 3.5). `judge` decides what the launch proves or what it breaks.
//! The checks run in the order of spec 3.3, so the first breach found is the one reported. A pass runs a launch per
//! unit, and a subset runs its affected units the same way. `listing` checks what a launch did to the listings of the
//! units a subset skipped (spec 3.7).

use super::independence::{self, Named, Roster, Violation, Written};
use crate::ignore::Ignore;
use crate::pathutil::{from_key, to_key};
use crate::run::{assemble_with, Assembled, RootListing};
use crate::trace::Trace;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::Path;

/// The facts about one launch that the checks need, read once from its trace.
pub(crate) struct Observed {
    /// The exit status of the launch. With no check failing, the status is the launch's verdict (spec 3.7).
    pub(crate) status: i32,
    /// The keys the launch wrote, in scope and not ignored (spec 3.3, step 1).
    pub(crate) writes: BTreeSet<String>,
    /// The keys the launch read by content (spec 3.3, step 2).
    content: BTreeSet<String>,
    /// Whether the launch listed the root and that listing is recorded (spec 3.5).
    root_listed: bool,
    /// The top-level names that the launch wrote or created, which the root guard does not count (spec 3.5).
    own_names: BTreeSet<OsString>,
}

impl Observed {
    pub(crate) fn of(trace: &Trace, root: &Path, real_root: &Path, ignore: &Ignore) -> Observed {
        Observed {
            status: trace.status,
            writes: trace.keys.values().cloned().collect(),
            content: independence::content_keys(root, real_root, trace),
            root_listed: !ignore.is_ignored("")
                && trace
                    .touched
                    .iter()
                    .any(|(lex, touch)| touch.listed && to_key(root, lex).is_empty()),
            own_names: top_names(trace, root, real_root),
        }
    }
}

/// What a launch is judged against: the roster, the unit or units it runs, what the run has recorded so far,
/// and the root listing taken before the launch.
pub(crate) struct Context<'a> {
    pub(crate) root: &'a Path,
    pub(crate) real_root: &'a Path,
    pub(crate) ignore: &'a Ignore,
    pub(crate) roster: &'a Roster,
    pub(crate) members: &'a [String],
    pub(crate) written: &'a Written,
    pub(crate) named: &'a Named,
    pub(crate) root_before: &'a io::Result<BTreeSet<OsString>>,
}

/// What one launch proves, or what it breaks (spec 3.3).
pub(crate) enum Verdict {
    /// The launch's proof: its assembled inputs and outputs, exact when it runs one unit.
    Proven(Assembled),
    /// The launch failed, so it keeps no proof. The pass goes on, and the status is the failure's.
    Failed,
    /// The launch cannot be recorded for this reason, which names what changed or could not be listed. No
    /// proof is kept, and the pass goes on.
    Unrecorded(String),
    /// The launch breaks an independence check, so its suite is disabled with this violation.
    Coupled(Violation),
}

/// Judges one traced launch in the order of spec 3.3. Checks (a) and (b) apply whatever the status is, so a
/// failing launch cannot hide a coupling.
pub(crate) fn judge(cx: &Context<'_>, trace: &Trace, observed: &Observed) -> Verdict {
    // Step 2: check (b), a content read of another unit's file.
    if let Some(violation) = independence::read_unit(cx.roster, cx.members, &observed.content) {
        return Verdict::Coupled(violation);
    }
    // Step 3: check (a), the writer side.
    if let Some(violation) = independence::wrote(cx.roster, cx.members, &observed.writes, cx.named)
    {
        return Verdict::Coupled(violation);
    }
    // Step 4: a failure is a verdict of its own.
    if observed.status != 0 {
        return Verdict::Failed;
    }
    // Step 5: check (c), an exit of 0 comes with a read of each member's own file.
    if let Some(violation) = independence::never_ran(cx.members, cx.root, cx.real_root, trace) {
        return Verdict::Coupled(violation);
    }
    // Step 6: the root guard (spec 3.5).
    if let Err(why) = root_guard(cx, observed) {
        return Verdict::Unrecorded(why);
    }
    // Step 7: assembly, which names what could not be read or what changed while the command ran.
    let kept = match assemble_with(cx.root, cx.real_root, trace, cx.ignore, RootListing::Record) {
        Ok(kept) => kept,
        Err(why) => return Verdict::Unrecorded(why.to_string()),
    };
    // Step 8: check (a), the reader side.
    if let Some(violation) = independence::read_written(&kept.inputs, cx.written, cx.members) {
        return Verdict::Coupled(violation);
    }
    // Step 9: the launch's proof.
    Verdict::Proven(kept)
}

/// Check 6 (spec 3.5). When the launch listed the root and that listing is recorded, the root's names are the same
/// before and after the launch, apart from the names the launch wrote or created itself. A launch that wrote a
/// top-level entry is otherwise not compared against the root (`identity::skip`), which is the gap this closes.
fn root_guard(cx: &Context<'_>, observed: &Observed) -> Result<(), String> {
    if !observed.root_listed {
        return Ok(());
    }
    let before = cx
        .root_before
        .as_ref()
        .map_err(|_| "the root could not be listed before the command ran".to_owned())?;
    let after = root_names(cx.root)
        .map_err(|_| "the root could not be listed after the command ran".to_owned())?;
    let outside = |names: &BTreeSet<OsString>| -> BTreeSet<OsString> {
        names
            .iter()
            .filter(|name| !observed.own_names.contains(*name))
            .cloned()
            .collect()
    };
    if outside(before) == outside(&after) {
        Ok(())
    } else {
        Err(". changed while the command ran".to_owned())
    }
}

/// The names of the entries in a directory, as a sorted set. The pass takes one of the root before each traced
/// launch, and one after the launch when the launch listed the root.
pub(crate) fn root_names(root: &Path) -> io::Result<BTreeSet<OsString>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        names.insert(entry?.file_name());
    }
    Ok(names)
}

/// The first component under the root of each path that the launch wrote, created or wrote into. Trace keys are
/// already root-relative. `trace.written` is not filtered by ignore rules, so an ignored name the launch wrote
/// still counts as its own.
fn top_names(trace: &Trace, root: &Path, real_root: &Path) -> BTreeSet<OsString> {
    let mut names = BTreeSet::new();
    for path in trace.written.iter().chain(&trace.created_dirs) {
        let relative = path
            .strip_prefix(root)
            .or_else(|_| path.strip_prefix(real_root));
        if let Some(first) = relative.ok().and_then(|rel| rel.components().next()) {
            names.insert(first.as_os_str().to_owned());
        }
    }
    for key in trace.keys.values() {
        if let Some(first) = Path::new(key).components().next() {
            names.insert(first.as_os_str().to_owned());
        }
    }
    names
}

/// A unit that a subset keeps without launching it, with what its proof names (spec 3.7). `listed` holds the
/// directories its listings name, root-relative with "" for the root. `paths` holds every path its proof names,
/// and the unit's own file, which a launch must not write.
pub(crate) struct SkippedUnit {
    pub(crate) unit: String,
    pub(crate) listed: Vec<String>,
    pub(crate) paths: Vec<String>,
}

/// The listing level of the 125 rule (spec 3.7). A key that this launch changed, whose parent directory a skipped
/// unit lists, leaves that unit's proof broken without a write to any file it names. A key counts as changed when the
/// run created it or removed it, judged by its prior in the trace, and a directory the run created counts as changed.
/// Returns the first changed key in key order, with the directory it changed and the skipped unit that lists it.
pub(crate) fn listing(
    skipped: &[SkippedUnit],
    root: &Path,
    real_root: &Path,
    trace: &Trace,
) -> Option<(String, String, String)> {
    if skipped.iter().all(|skip| skip.listed.is_empty()) {
        return None;
    }
    let mut changed: BTreeSet<String> = trace
        .keys
        .values()
        .filter(|key| !key.starts_with('/') && entry_changed(root, trace, key))
        .cloned()
        .collect();
    changed.extend(
        trace
            .created_dirs
            .iter()
            .filter_map(|dir| key_under(root, real_root, dir)),
    );
    for key in &changed {
        let parent = Path::new(key)
            .parent()
            .map_or_else(String::new, |parent| parent.to_string_lossy().into_owned());
        for skip in skipped {
            if let Some(dir) = skip.listed.iter().find(|listed| **listed == parent) {
                return Some((skip.unit.clone(), key.clone(), dir.clone()));
            }
        }
    }
    None
}

/// Whether the run changed the entry at `key`: it was absent and now exists, or it existed and is gone. A key with no
/// recorded prior counts as changed, which is the conservative reading.
fn entry_changed(root: &Path, trace: &Trace, key: &str) -> bool {
    let exists = fs::symlink_metadata(from_key(root, key)).is_ok();
    match trace.priors.get(key).map(String::as_str) {
        Some("a") => exists,
        Some(_) => !exists,
        None => true,
    }
}

/// The root-relative key of a path the run created, when it lies under the root.
fn key_under(root: &Path, real_root: &Path, path: &Path) -> Option<String> {
    let relative = path
        .strip_prefix(root)
        .or_else(|_| path.strip_prefix(real_root))
        .ok()?;
    relative.to_str().map(str::to_owned)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::trace::Trace;
    use std::path::PathBuf;

    fn skipped(unit: &str, listed: &[&str]) -> SkippedUnit {
        SkippedUnit {
            unit: unit.into(),
            listed: listed.iter().map(|dir| dir.to_string()).collect(),
            paths: vec![unit.into()],
        }
    }

    /// A fresh root that holds the files `names` lists, under a name of its own.
    fn root(name: &str, names: &[&str]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stoop-listing-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for file in names {
            let path = dir.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"x").unwrap();
        }
        dir
    }

    #[test]
    fn a_new_entry_in_the_root_is_a_breach_for_a_skipped_unit_that_lists_the_root() {
        let dir = root("new-root", &["new.top"]);
        let mut trace = Trace::default();
        trace
            .keys
            .insert(PathBuf::from("new.top"), "new.top".into());
        trace.priors.insert("new.top".into(), "a".into());
        let found = listing(&[skipped("tests/c.t", &[""])], &dir, &dir, &trace);
        assert_eq!(
            found,
            Some(("tests/c.t".into(), "new.top".into(), "".into()))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_the_run_removed_from_a_listed_directory_is_a_breach() {
        let dir = root("gone", &[]);
        let mut trace = Trace::default();
        trace
            .keys
            .insert(PathBuf::from("tests/gone.t"), "tests/gone.t".into());
        trace.priors.insert("tests/gone.t".into(), "f:00".into());
        let found = listing(&[skipped("tests/c.t", &["tests"])], &dir, &dir, &trace);
        assert_eq!(
            found,
            Some(("tests/c.t".into(), "tests/gone.t".into(), "tests".into()))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_the_run_created_is_a_changed_entry() {
        let dir = root("created", &["tests2/x"]);
        let mut trace = Trace::default();
        trace.created_dirs.push(dir.join("tests2"));
        let found = listing(&[skipped("tests/c.t", &[""])], &dir, &dir, &trace);
        assert_eq!(
            found,
            Some(("tests/c.t".into(), "tests2".into(), "".into()))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_change_outside_the_listed_directories_is_not_a_breach() {
        let dir = root("elsewhere", &["src/new.src"]);
        let mut trace = Trace::default();
        trace
            .keys
            .insert(PathBuf::from("src/new.src"), "src/new.src".into());
        trace.priors.insert("src/new.src".into(), "a".into());
        let found = listing(&[skipped("tests/c.t", &["tests"])], &dir, &dir, &trace);
        assert_eq!(found, None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_entry_that_is_as_it_was_is_not_a_breach() {
        let dir = root("same", &["tests/a.t"]);
        let mut trace = Trace::default();
        trace
            .keys
            .insert(PathBuf::from("tests/a.t"), "tests/a.t".into());
        trace.priors.insert("tests/a.t".into(), "f:00".into());
        let found = listing(&[skipped("tests/c.t", &["tests"])], &dir, &dir, &trace);
        assert_eq!(found, None);
        let _ = fs::remove_dir_all(&dir);
    }
}
