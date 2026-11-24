//! The independence checks of one traced unit launch (spec 3.3 and 3.4). A proof is stored only when its
//! launch reads no other unit's file, writes nothing that a unit's own file or another unit's proof names,
//! and reads its own file when it exits 0. Each check names what it found in the words of spec 3.4, so a
//! disabled suite says why. The checks are pure over one launch's trace and the record of its run, so a
//! pass, a subset and a completion share them.

use super::hook::safe;
use crate::input::Input;
use crate::pathutil::{to_key, Physical};
use crate::trace::Trace;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

/// The units of a suite, as a set for membership. Roster order is the caller's concern.
pub(crate) struct Roster {
    names: HashSet<String>,
}

impl Roster {
    pub(crate) fn new(units: &[String]) -> Roster {
        Roster {
            names: units.iter().cloned().collect(),
        }
    }

    pub(crate) fn contains(&self, unit: &str) -> bool {
        self.names.contains(unit)
    }
}

/// A breach of an independence check. A launch that makes one is not recorded, and it disables its suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    /// The launch of `writer` wrote `path`, which the proof of `reader` names as an input.
    WroteInput {
        writer: String,
        path: String,
        reader: String,
    },
    /// The launch of `writer` wrote the file of `unit`, a unit of the roster.
    WroteUnit { writer: String, unit: String },
    /// The launch of `writer` and the proof of `other` both write `path`, which that proof names as an output.
    WroteOutput {
        writer: String,
        other: String,
        path: String,
    },
    /// The launch of `reader` read the file of `unit`, another unit of the roster.
    ReadUnit { reader: String, unit: String },
    /// The launch of `unit` exited 0 without reading its own file.
    NeverRan { unit: String },
}

impl Violation {
    /// The code the suite's state carries.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::WroteInput { .. } => "wrote_input",
            Self::WroteUnit { .. } => "wrote_unit",
            Self::WroteOutput { .. } => "wrote_output",
            Self::ReadUnit { .. } => "read_unit",
            Self::NeverRan { .. } => "never_ran",
        }
    }

    /// The sentence that names the breach, through `safe` so that it prints as text.
    pub(crate) fn label(&self) -> String {
        let text = match self {
            Self::WroteInput {
                writer,
                path,
                reader,
            } => format!("{writer} wrote {path}, which {reader} reads"),
            Self::WroteUnit { writer, unit } => format!("{writer} wrote {unit}"),
            Self::WroteOutput {
                writer,
                other,
                path,
            } => format!("{writer} and {other} both write {path}"),
            Self::ReadUnit { reader, unit } => format!("{reader} read {unit}"),
            Self::NeverRan { unit } => format!("{unit} exited 0 without reading it"),
        };
        safe(&text)
    }
}

/// Every key that the launches of one run have written so far, each with the first unit whose launch wrote it.
#[derive(Default)]
pub(crate) struct Written {
    keys: BTreeMap<String, String>,
}

impl Written {
    pub(crate) fn add(&mut self, keys: &BTreeSet<String>, unit: &str) {
        for key in keys {
            self.keys
                .entry(key.clone())
                .or_insert_with(|| unit.to_owned());
        }
    }

    /// The unit whose launch wrote `key` first in this run, if one did.
    pub(crate) fn writer(&self, key: &str) -> Option<&str> {
        self.keys.get(key).map(String::as_str)
    }
}

/// The inputs and outputs that the proofs stored so far in this run name, each with the units that name it,
/// in the order they were stored.
#[derive(Default)]
pub(crate) struct Named {
    inputs: HashMap<String, Vec<String>>,
    outputs: HashMap<String, Vec<String>>,
}

impl Named {
    pub(crate) fn store(&mut self, unit: &str, inputs: &[String], outputs: &[String]) {
        for path in inputs {
            self.inputs
                .entry(path.clone())
                .or_default()
                .push(unit.to_owned());
        }
        for path in outputs {
            self.outputs
                .entry(path.clone())
                .or_default()
                .push(unit.to_owned());
        }
    }

    /// Forgets the names one unit's stored proof gave, when that proof is replaced (spec 3.11). A name that a
    /// different unit still gives stays.
    pub(crate) fn forget(&mut self, unit: &str, inputs: &[String], outputs: &[String]) {
        for (names, paths) in [(&mut self.inputs, inputs), (&mut self.outputs, outputs)] {
            for path in paths {
                if let Some(units) = names.get_mut(path) {
                    units.retain(|named| named.as_str() != unit);
                }
            }
        }
    }
}

/// Check (b): the launch read, by content, the file of a roster unit that is not one of its members. `content`
/// holds the keys the launch read (see `content_keys`). The first such unit in key order is named.
pub(crate) fn read_unit(
    roster: &Roster,
    members: &[String],
    content: &BTreeSet<String>,
) -> Option<Violation> {
    let reader = members.first()?;
    content
        .iter()
        .find(|key| roster.contains(key.as_str()) && !members.contains(*key))
        .map(|unit| Violation::ReadUnit {
            reader: reader.clone(),
            unit: unit.clone(),
        })
}

/// Check (a), writer side: the launch wrote a roster unit's file, or a path that the proof of another unit names
/// as an input or as an output. Each class is checked over the whole write set before the next one is tried.
pub(crate) fn wrote(
    roster: &Roster,
    members: &[String],
    writes: &BTreeSet<String>,
    named: &Named,
) -> Option<Violation> {
    let writer = members.first()?;
    if let Some(unit) = writes.iter().find(|key| roster.contains(key.as_str())) {
        return Some(Violation::WroteUnit {
            writer: writer.clone(),
            unit: unit.clone(),
        });
    }
    for path in writes {
        if let Some(reader) = named
            .inputs
            .get(path)
            .and_then(|units| first_other(units, members))
        {
            return Some(Violation::WroteInput {
                writer: writer.clone(),
                path: path.clone(),
                reader,
            });
        }
    }
    for path in writes {
        if let Some(other) = named
            .outputs
            .get(path)
            .and_then(|units| first_other(units, members))
        {
            return Some(Violation::WroteOutput {
                writer: writer.clone(),
                other,
                path: path.clone(),
            });
        }
    }
    None
}

/// The first unit that names a path and is not one of `members`.
fn first_other(units: &[String], members: &[String]) -> Option<String> {
    units.iter().find(|unit| !members.contains(*unit)).cloned()
}

/// Check (a), reader side: an input of the launch that an earlier launch of this run wrote. The inputs are the
/// assembled ones, in path order, so the first such input is named.
pub(crate) fn read_written(
    inputs: &[Input],
    written: &Written,
    members: &[String],
) -> Option<Violation> {
    let reader = members.first()?;
    inputs.iter().find_map(|input| {
        let writer = written
            .writer(&input.path)
            .filter(|writer| !members.iter().any(|member| member.as_str() == *writer))?;
        Some(Violation::WroteInput {
            writer: writer.to_owned(),
            path: input.path.clone(),
            reader: reader.clone(),
        })
    })
}

/// Check (c): a launch that exits 0 must have read the own file of every member. The first member without one is
/// named. Evidence is `unit_evidence`'s: a content read, and a stat never counts.
pub(crate) fn never_ran(
    members: &[String],
    root: &Path,
    real_root: &Path,
    trace: &Trace,
) -> Option<Violation> {
    members
        .iter()
        .find(|unit| !unit_evidence(root, real_root, trace, unit))
        .map(|unit| Violation::NeverRan { unit: unit.clone() })
}

/// The keys that the launch read by content. Each touched entry that the run opened for content adds two keys:
/// the one its name gives and the one its physical location gives. A link as the last component is not followed,
/// so it keeps its own name. This is the mapping `build_inputs` uses for the same paths.
pub(crate) fn content_keys(root: &Path, real_root: &Path, trace: &Trace) -> BTreeSet<String> {
    let mut phys = Physical::new(root, real_root);
    let mut keys = BTreeSet::new();
    for (lex, touch) in &trace.touched {
        if touch.content {
            keys.insert(to_key(root, lex));
            keys.extend(physical_key(&mut phys, lex));
        }
    }
    keys
}

/// The repository-relative name of the entry that `lex` names once its parent directories are resolved. A link
/// as the last component is not followed, so it keeps its own name.
fn physical_key(phys: &mut Physical, lex: &Path) -> Option<String> {
    let location = phys.locate(lex)?;
    let rel = phys.repo_rel(&location.path)?;
    rel.to_str().map(str::to_owned)
}

/// Whether the launch read the unit's own file: a content read of it under the name the unit has, or through a
/// directory the launch reached by a link. A stat does not count. Neither does a read through a link whose own
/// name differs from the unit, which is the conservative choice.
pub(crate) fn unit_evidence(root: &Path, real_root: &Path, trace: &Trace, unit: &str) -> bool {
    content_keys(root, real_root, trace).contains(unit)
}
