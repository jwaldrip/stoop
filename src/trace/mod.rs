//! Observing what a command reads and writes.

use crate::ignore::Ignore;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Where the tracer records what the run's writes replace: repository paths under `root`.
/// Keys are relative to `real_root`, the canonical path of `root`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct Scope<'a> {
    pub root: &'a Path,
    pub real_root: PathBuf,
    pub ignore: &'a Ignore,
    /// Attribute evidence observed once before the traced command starts.
    pub oid_epoch: Option<Arc<crate::oid_attrs::Epoch>>,
}

/// What the run did with a path it looked at.
#[derive(Clone, Copy, Default)]
pub struct Touch {
    /// Its entries were listed (getdents).
    pub listed: bool,
    /// The run looked at what the path holds: opened it for reading, executed it, or ran
    /// stat, access or readlink on it. Decides whether a write must record content.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub read: bool,
    /// The run opened this path for content or executed it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub content: bool,
}
use serde::{Deserialize, Serialize};

pub const UNAVAILABLE: &str = "tracing needs Linux x86-64 or arm64 (ptrace and seccomp)";
const TRACER: &str = "ptrace-seccomp";
pub(crate) mod identity;
pub(crate) mod version;
use version::TRACER_VERSION;

pub fn supported() -> bool {
    cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Provenance {
    pub os: String,
    pub arch: String,
    pub tracer: String,
    pub version: u32,
}

impl Provenance {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
            tracer: TRACER.into(),
            version: TRACER_VERSION,
        }
    }

    pub fn is_current(&self) -> bool {
        supported()
            && self.os == std::env::consts::OS
            && self.arch == std::env::consts::ARCH
            && self.tracer == TRACER
            && self.version == TRACER_VERSION
    }
}
/// One successful exec, linked to the process image that launched it.
/// This bounded, in-memory observation is diagnostic only and is never part of a proof.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct ExecEvent {
    pub parent: Option<usize>,
    pub requested: PathBuf,
    pub argv: Vec<OsString>,
    pub executable: PathBuf,
    pub effective_argv: Vec<OsString>,
    pub cwd: PathBuf,
}

/// The destination stat at a successful rename exit, verified against the source at entry.
#[derive(Clone, Debug)]
pub struct AtomicLanding {
    pub stat: identity::FileStat,
}

#[derive(Default)]
pub struct Trace {
    /// Every path the process tree looked at, lexically resolved.
    pub touched: HashMap<PathBuf, Touch>,
    /// First observations are present only for Linux runs with a recording scope.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub seen: Option<HashMap<PathBuf, identity::Observation>>,
    /// First getdents observations.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub listings: HashMap<PathBuf, identity::ListSeen>,
    /// Paths and inodes that the run may have modified.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub footprint: identity::Footprint,
    /// Transient verified atomic replacements, keyed by the destination's existing proof key.
    pub atomic_landings: BTreeMap<String, AtomicLanding>,
    /// Direct writable opens whose content prior was bound to a confirmed read.
    pub bound_priors: BTreeSet<String>,
    /// Repository symlinks whose targets passed through a proc magic link at entry.
    pub magic_links: HashSet<PathBuf>,
    /// Paths the run wrote, renamed, removed or created, as the run named them.
    /// These are outputs, not inputs.
    pub written: HashSet<PathBuf>,
    /// Directories the run created. Everything below one is an output too.
    pub created_dirs: Vec<PathBuf>,
    /// Reasons the observation may be incomplete. A run with any is never recorded.
    pub unsound: Vec<String>,
    /// Exit status of the command (128 + signal when killed).
    pub status: i32,
    /// Each in-scope physical path the run wrote, to its key.
    pub keys: HashMap<PathBuf, String>,
    /// State of each in-scope key before the run first wrote it.
    pub priors: BTreeMap<String, String>,
    /// Blob ids captured in the same read as each content prior.
    pub prior_oids: BTreeMap<String, String>,
    /// Attribute state under which each content prior's blob id was calculated.
    pub prior_oid_bases: BTreeMap<String, crate::oid_attrs::OidBasis>,
    /// The shared pre-run attribute snapshot, absent when Git evidence is unsafe.
    pub oid_epoch: Option<Arc<crate::oid_attrs::Epoch>>,
    /// Unit tests can construct synthetic traces without ever starting a command.
    #[cfg(test)]
    pub(crate) oid_epoch_captured: bool,
    /// Git attributes or repository metadata may have changed during the run.
    pub oid_attrs_changed: bool,
    /// Reasons the planner cannot replay this run (at most 16, deduplicated). Not fatal.
    pub unplannable: Vec<String>,
    /// Successful execs, present only for an ordinary, traced `stoop run`.
    pub execs: Option<Vec<ExecEvent>>,
}

impl Trace {
    pub fn is_output(&self, p: &Path) -> bool {
        self.written.contains(p) || self.created_dirs.iter().any(|d| p.starts_with(d))
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub use linux::run;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn run(
    _argv: &[std::ffi::OsString],
    _cwd: &Path,
    _allow_network: bool,
    _scope: Option<&Scope<'_>>,
    _observe_execs: bool,
) -> std::io::Result<Trace> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        UNAVAILABLE,
    ))
}

#[cfg(all(
    test,
    not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
))]
mod tests {
    use super::*;

    #[test]
    fn a_linux_proof_is_never_current_where_tracing_is_unavailable() {
        let linux = Provenance {
            os: "linux".into(),
            arch: "x86_64".into(),
            tracer: TRACER.into(),
            version: TRACER_VERSION,
        };
        assert!(!linux.is_current());
        assert!(!Provenance::current().is_current());
    }
}
