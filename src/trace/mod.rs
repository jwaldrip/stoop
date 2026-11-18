//! Observing what a command reads and writes.

use crate::ignore::Ignore;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Where the tracer records what the run's writes replace: repository paths under `root`.
/// Keys are relative to `real_root`, the canonical path of `root`.
pub struct Scope<'a> {
    pub root: &'a Path,
    pub real_root: PathBuf,
    pub ignore: &'a Ignore,
}

/// What the run did with a path it looked at.
#[derive(Clone, Copy, Default)]
pub struct Touch {
    /// Its entries were listed (getdents).
    pub listed: bool,
    /// The run looked at what the path holds: opened it for reading, executed it, or ran
    /// stat, access or readlink on it. Decides whether a write must record content.
    pub read: bool,
}

#[derive(Default)]
pub struct Trace {
    /// Every path the process tree looked at, lexically resolved.
    pub touched: HashMap<PathBuf, Touch>,
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
    /// Reasons the planner cannot replay this run (at most 16, deduplicated). Not fatal.
    pub unplannable: Vec<String>,
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

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub fn run(
    _argv: &[String],
    _cwd: &Path,
    _allow_network: bool,
    _scope: Option<&Scope<'_>>,
) -> std::io::Result<Trace> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "tracing needs Linux (ptrace and seccomp)",
    ))
}
