//! Read-only unit catalog and the directory listings that define it.

use super::filter::Filter;
use crate::ignore::Ignore;
use crate::input::{self, Input};
use std::collections::HashSet;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

const MAX_UNITS: usize = 4096;
const MAX_DIRS: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct UnitId(pub String);

#[allow(dead_code)]
pub(crate) struct Catalog {
    pub units: Vec<UnitId>,
    pub inputs: Vec<Input>,
}

struct GitInventory {
    files: HashSet<String>,
    ignored_dirs: HashSet<String>,
    prefix: String,
}

/// A valid Git record uses root-relative UTF-8 paths and no control characters.
fn parse_git_records(bytes: &[u8], directories: bool) -> Result<Vec<String>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let Some(bytes) = bytes.strip_suffix(&[0]) else {
        return Err("Git inventory is not NUL terminated".into());
    };
    bytes
        .split(|&byte| byte == 0)
        .map(|raw| {
            let text = std::str::from_utf8(raw).map_err(|_| "Git inventory is not UTF-8")?;
            let path = if directories {
                text.strip_suffix('/').unwrap_or(text)
            } else {
                text
            };
            if path.is_empty()
                || Path::new(path).is_absolute()
                || path.starts_with('/')
                || path.chars().any(char::is_control)
                || path.split('/').any(|part| matches!(part, "" | "." | ".."))
                || (path.len() >= 2
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && path.as_bytes()[1] == b':')
                || (!directories && text.ends_with('/'))
            {
                return Err("Git inventory contains an invalid path".into());
            }
            Ok(text.to_string())
        })
        .collect()
}

impl GitInventory {
    fn from_outputs(
        root: &Path,
        repo: &Path,
        files: &[u8],
        ignored: &[u8],
    ) -> Result<Self, String> {
        let files: HashSet<_> = parse_git_records(files, false)?.into_iter().collect();
        let ignored = parse_git_records(ignored, true)?;
        let ignored_dirs: HashSet<String> = ignored
            .iter()
            .filter(|path| path.ends_with('/'))
            .cloned()
            .collect();
        let ignored_files: HashSet<&str> = ignored
            .iter()
            .filter(|path| !path.ends_with('/'))
            .map(String::as_str)
            .collect();
        for file in &files {
            if ignored_files.contains(file.as_str())
                || file
                    .match_indices('/')
                    .any(|(at, _)| ignored_dirs.contains(&file[..=at]))
            {
                return Err("Git inventory disagrees with its ignored paths".into());
            }
        }
        let relative = root
            .strip_prefix(repo)
            .map_err(|_| "selected root is outside the Git worktree")?;
        let mut components = Vec::new();
        for component in relative.components() {
            let component = component
                .as_os_str()
                .to_str()
                .ok_or("Git root path is not UTF-8")?;
            components.push(component);
        }
        let prefix = if components.is_empty() {
            String::new()
        } else {
            format!("{}/", components.join("/"))
        };
        Ok(Self {
            files,
            ignored_dirs,
            prefix,
        })
    }

    fn includes(&self, path: &str) -> bool {
        self.files.contains(&format!("{}{path}", self.prefix))
    }

    fn prunes(&self, path: &str) -> bool {
        let path = format!("{}{path}/", self.prefix);
        self.ignored_dirs.contains(&path)
            || path
                .match_indices('/')
                .any(|(at, _)| self.ignored_dirs.contains(&path[..=at]))
    }
}

fn git_available() -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| {
        #[cfg(windows)]
        let names = ["git.exe", "git"];
        #[cfg(not(windows))]
        let names = ["git", "git"];
        names.iter().any(|name| {
            std::fs::metadata(dir.join(name)).is_ok_and(|metadata| {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
                }
                #[cfg(not(unix))]
                {
                    metadata.is_file()
                }
            })
        })
    })
}

fn inventory(root: &Path) -> Result<Option<GitInventory>, String> {
    let Some(repo) = root.ancestors().find(|dir| dir.join(".git").exists()) else {
        return Ok(None);
    };
    if !git_available() {
        return Ok(None);
    }
    let files =
        crate::gitprobe::unit_files(repo).ok_or("Git unit inventory failed or exceeded 64 MiB")?;
    let ignored = crate::gitprobe::ignored_unit_dirs(repo)
        .ok_or("Git ignored-directory inventory failed or exceeded 64 MiB")?;
    GitInventory::from_outputs(root, repo, &files, &ignored).map(Some)
}

pub(crate) fn discover(
    root: &Path,
    ignore: &Ignore,
    filter: &Filter,
    default: Option<&Filter>,
) -> Result<Catalog, String> {
    discover_with_limits(root, ignore, filter, default, MAX_UNITS, MAX_DIRS)
}

pub(crate) fn explain(
    root: &Path,
    ignore: &Ignore,
    inline: Option<&Filter>,
    configured: Option<(&Filter, &str)>,
) -> String {
    if let Some(filter) = inline.or(configured.map(|(filter, _)| filter)) {
        let default = configured.map(|(filter, _)| filter);
        return match discover(root, ignore, filter, default) {
            Ok(catalog) => {
                let source = if inline.is_some() {
                    "inline".to_string()
                } else {
                    format!(
                        ".stoop.toml suite {}",
                        super::hook::safe(configured.unwrap().1)
                    )
                };
                format!(
                    "stoop: tracked {} units; filter '{}' ({source})",
                    catalog.units.len(),
                    super::hook::safe(filter.text())
                )
            }
            Err(reason) => format!("stoop: no unit universe: {}", super::hook::safe(&reason)),
        };
    }
    let patterns = ["**/*.test.*", "**/*_test.*", "**/test_*.py", "**/*_spec.*"];
    let candidates = Filter::inline(&patterns.join("|"));
    match discover(root, ignore, &candidates, None) {
        Ok(catalog) => {
            let suggestion = patterns.iter().find(|pattern| {
                let filter = Filter::inline(pattern);
                catalog
                    .units
                    .iter()
                    .any(|unit| filter.matches(&unit.0, false))
            });
            match suggestion {
                Some(pattern) => format!(
                    "stoop: no unit universe: add a filter, for example '{{changed:{pattern}}}'"
                ),
                None => "stoop: no unit universe: add a filter or configure suite units".into(),
            }
        }
        Err(reason) => format!("stoop: no unit universe: {}", super::hook::safe(&reason)),
    }
}

fn discover_with_limits(
    root: &Path,
    ignore: &Ignore,
    filter: &Filter,
    default: Option<&Filter>,
    max_units: usize,
    max_dirs: usize,
) -> Result<Catalog, String> {
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot read root: {error}"))?;
    let git = inventory(&root)?;
    let mut pending = vec![(root.clone(), String::new())];
    let mut units = Vec::new();
    let mut inputs = Vec::new();
    while let Some((directory, key)) = pending.pop() {
        if inputs.len() >= max_dirs {
            return Err(format!("more than {max_dirs} walked directories"));
        }
        let before = input::list_hash(&directory).ok_or("cannot read a directory listing")?;
        let entries = std::fs::read_dir(&directory)
            .map_err(|error| format!("cannot walk a directory: {error}"))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read a directory entry: {error}"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if name == ".git" || name == ".stoop" {
                continue;
            }
            let child = if key.is_empty() {
                name.to_string()
            } else {
                format!("{key}/{name}")
            };
            if ignore.is_ignored(&child) {
                continue;
            }
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect a directory entry: {error}"))?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                if !git.as_ref().is_some_and(|git| git.prunes(&child)) {
                    pending.push((entry.path(), child));
                }
            } else if kind.is_file() {
                if git.as_ref().is_some_and(|git| !git.includes(&child)) {
                    continue;
                }
                if child.len() > 4096 {
                    return Err("a unit path cannot be represented".into());
                }
                let matches = if filter.exclusion_only() {
                    default.is_some_and(|base| base.matches(&child, false))
                        && filter.matches(&child, false)
                } else {
                    filter.matches(&child, false)
                };
                if !matches {
                    continue;
                }
                if child.len() > 4096
                    || child.chars().any(|c| c == '\0' || c == '\n')
                    || child.split('/').any(|part| matches!(part, "" | "." | ".."))
                {
                    return Err("a unit path cannot be represented".into());
                }
                if units.len() >= max_units {
                    return Err(format!("more than {max_units} units"));
                }
                units.push(UnitId(child));
            }
        }
        let after = input::list_hash(&directory).ok_or("cannot recheck a directory listing")?;
        if before != after {
            return Err("a directory changed while its units were listed".into());
        }
        inputs.push(Input {
            path: if key.is_empty() { ".".to_string() } else { key },
            id: format!("dl:{after}"),
            oid: None,
            oid_basis: None,
        });
    }
    units.sort();
    inputs.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(Catalog { units, inputs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stoop-universe-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn malformed_git_records_and_disagreement_refuse_the_universe() {
        let root = Path::new("/");
        for bad in [
            &b"not-terminated"[..],
            b"\0",
            b"../bad\0",
            b"/absolute\0",
            b"a/./b\0",
            b"a/../b\0",
            b"a\nb\0",
            b"\xff\0",
        ] {
            assert!(
                GitInventory::from_outputs(root, root, bad, b"").is_err(),
                "{bad:?}"
            );
            assert!(
                GitInventory::from_outputs(root, root, b"", bad).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            GitInventory::from_outputs(root, root, b"ignored/tracked.t\0", b"ignored/\0").is_err()
        );
        assert!(GitInventory::from_outputs(root, root, b"ignored.t\0", b"ignored.t\0").is_err());
    }

    #[test]
    fn empty_directories_are_catalog_inputs_and_their_listing_changes() {
        let dir = Dir::new();
        fs::create_dir(dir.0.join("empty")).unwrap();
        let ignore = Ignore::new(&[], None, &[]);
        let filter = Filter::inline("**/*.t");
        let before = discover(&dir.0, &ignore, &filter, None).unwrap();
        let empty = before
            .inputs
            .iter()
            .find(|input| input.path == "empty")
            .unwrap();
        assert_eq!(
            empty.id,
            format!("dl:{}", input::list_hash(&dir.0.join("empty")).unwrap())
        );
        fs::write(dir.0.join("empty/new.t"), b"x").unwrap();
        let after = discover(&dir.0, &ignore, &filter, None).unwrap();
        assert_ne!(
            empty.id,
            after
                .inputs
                .iter()
                .find(|input| input.path == "empty")
                .unwrap()
                .id
        );
        assert_eq!(after.units, vec![UnitId("empty/new.t".into())]);
    }

    #[test]
    fn exact_unit_and_directory_limits_refuse_the_next_item() {
        let dir = Dir::new();
        fs::create_dir(dir.0.join("a")).unwrap();
        fs::write(dir.0.join("a/one.t"), b"1").unwrap();
        fs::write(dir.0.join("a/two.t"), b"2").unwrap();
        let ignore = Ignore::new(&[], None, &[]);
        let filter = Filter::inline("**/*.t");
        assert_eq!(
            discover_with_limits(&dir.0, &ignore, &filter, None, 2, 2)
                .unwrap()
                .units
                .len(),
            2
        );
        assert!(discover_with_limits(&dir.0, &ignore, &filter, None, 1, 2).is_err());
        assert!(discover_with_limits(&dir.0, &ignore, &filter, None, 2, 1).is_err());
    }
}
