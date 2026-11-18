//! Observing what a command reads.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub const UNAVAILABLE: &str = "tracing needs Linux x86-64 or arm64 (ptrace and seccomp)";
const TRACER: &str = "ptrace-seccomp";
// Increment when a change to the tracer invalidates existing observations.
const TRACER_VERSION: u32 = 1;

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

#[derive(Default)]
pub struct Trace {
    /// Every path the process tree looked at; the flag is "its entries were listed".
    pub touched: HashMap<PathBuf, bool>,
    /// Paths the run wrote, renamed, removed or created. These are outputs, not inputs.
    pub written: HashSet<PathBuf>,
    /// Directories the run created. Everything below one is an output too.
    pub created_dirs: Vec<PathBuf>,
    /// Reasons the observation may be incomplete. A run with any is never recorded.
    pub unsound: Vec<String>,
    /// Exit status of the command (128 + signal when killed).
    pub status: i32,
}

impl Trace {
    pub fn is_output(&self, p: &std::path::Path) -> bool {
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
    _cwd: &std::path::Path,
    _allow_network: bool,
) -> std::io::Result<Trace> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        UNAVAILABLE,
    ))
}
