//! Where the server may work. Every directory a call runs in is canonical and inside the root.

use crate::plan;
use crate::run;
use std::path::{Path, PathBuf};

/// The project root: `--root` if given, else the nearest ancestor of the start directory that
/// holds a `.git`, as `stoop run` chooses it.
pub fn server_root(explicit: Option<&Path>) -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("no working directory: {e}"))?;
    let start = match explicit {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => cwd.join(path),
        None => run::find_root(&cwd),
    };
    let root = std::fs::canonicalize(&start).map_err(|e| {
        format!(
            "cannot use {} as the root: {e}",
            plan::output::escape(&start.display().to_string())
        )
    })?;
    if !root.is_dir() {
        return Err(format!(
            "{} is not a directory",
            plan::output::escape(&root.display().to_string())
        ));
    }
    Ok(root)
}

/// The directory a call runs in: `cwd` (relative to the root, or absolute) resolved through
/// symlinks, which must be a directory inside `root`. The default is the root itself.
pub fn confine(root: &Path, cwd: Option<&str>) -> Result<PathBuf, String> {
    let requested = match cwd {
        None | Some("") => root.to_path_buf(),
        Some(path) if Path::new(path).is_absolute() => PathBuf::from(path),
        Some(path) => root.join(path),
    };
    let shown = plan::output::escape(cwd.unwrap_or("."));
    let real = std::fs::canonicalize(&requested)
        .map_err(|e| format!("cwd {shown} cannot be used: {e}"))?;
    if !real.is_dir() {
        return Err(format!("cwd {shown} is not a directory"));
    }
    if !real.starts_with(root) {
        return Err(format!("cwd {shown} is outside the project root"));
    }
    Ok(real)
}

/// A path for an argument of the `stoop` command line, as text.
pub fn as_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
