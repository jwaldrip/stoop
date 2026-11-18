//! Evidence that hashing raw working-tree bytes is safe for Git object IDs.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::{Command, Stdio};

const ATTRS: [&str; 7] = [
    "text",
    "eol",
    "filter",
    "ident",
    "working-tree-encoding",
    "export-subst",
    "crlf",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidBasis {
    pub text: String,
    pub eol: String,
    pub filter: String,
    pub ident: String,
    pub working_tree_encoding: String,
    pub export_subst: String,
    pub crlf: String,
    pub autocrlf: String,
}

// Preserve standard Git configuration selectors, which change the effective
// attributes, but remove repository redirection, alternate attribute sources,
// tracing, and every other inherited Git execution override.
pub(crate) fn git(root: &Path) -> Option<Command> {
    let root = root.canonicalize().ok()?;
    let mut command = Command::new("git");
    for (key, _) in std::env::vars_os() {
        let name = key.as_os_str().as_bytes();
        if !name.starts_with(b"GIT_") {
            continue;
        }
        let config = matches!(
            name,
            b"GIT_CONFIG_COUNT"
                | b"GIT_CONFIG_PARAMETERS"
                | b"GIT_CONFIG_GLOBAL"
                | b"GIT_CONFIG_SYSTEM"
                | b"GIT_CONFIG_NOSYSTEM"
        ) || name.starts_with(b"GIT_CONFIG_KEY_")
            || name.starts_with(b"GIT_CONFIG_VALUE_");
        if !config || cfg!(test) {
            command.env_remove(key);
        }
    }
    if let Some(parent) = root.parent() {
        // Do not discover a repository above the supplied root.
        command.env(
            "GIT_CEILING_DIRECTORIES",
            std::env::join_paths([parent]).ok()?,
        );
    }
    command
        .current_dir(&root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ]);
    #[cfg(test)]
    command
        .env("HOME", &root)
        .env("XDG_CONFIG_HOME", root.join(".git/stoop-test-home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    Some(command)
}

fn autocrlf(root: &Path) -> Option<String> {
    let out = git(root)?
        .args(["config", "--null", "--get", "core.autocrlf"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return (out.status.code() == Some(1) && out.stdout.is_empty()).then(|| "unset".to_owned());
    }
    let value = out.stdout.strip_suffix(&[0])?;
    if value.contains(&0) {
        return None;
    }
    let value = std::str::from_utf8(value).ok()?;
    // These are Git's documented false spellings. Reject all other values,
    // including its special `input` mode and valueless boolean settings.
    if value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off")
        || value == "0"
    {
        Some(value.to_owned())
    } else {
        None
    }
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn query(root: &Path, paths: &[&str], all: bool) -> Option<Vec<u8>> {
    let mut command = git(root)?;
    command.args(["check-attr", "-z", "--stdin"]);
    if all {
        command.arg("--all");
    } else {
        command.args(ATTRS);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    // Git can write while it is still reading paths. Write concurrently with
    // draining stdout so a large batch cannot deadlock on full pipes.
    std::thread::scope(|scope| {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for path in paths {
                stdin.write_all(path.as_bytes())?;
                stdin.write_all(&[0])?;
            }
            Ok(())
        });
        let out = child.wait_with_output().ok()?;
        writer.join().ok()?.ok()?;
        out.status.success().then_some(out.stdout)
    })
}

fn fields(bytes: &[u8]) -> Option<impl Iterator<Item = &[u8]>> {
    // An empty --all response is valid: no attributes apply to any path.
    let (bytes, count) = if bytes.is_empty() {
        (bytes, 0)
    } else {
        (bytes.strip_suffix(&[0])?, usize::MAX)
    };
    Some(bytes.split(|b| *b == 0).take(count))
}

// The explicit query must return exactly one record per requested path and
// attribute, even when a path has no attributes in the --all query.
fn named<'a>(paths: &[&'a str], bytes: &[u8]) -> Option<HashMap<&'a str, bool>> {
    let mut states: HashMap<&str, (u8, bool)> = paths
        .iter()
        .copied()
        .map(|path| (path, (0, true)))
        .collect();
    let mut fields = fields(bytes)?;
    while let Some(path) = fields.next() {
        let path = std::str::from_utf8(path).ok()?;
        let attr = fields.next()?;
        let value = fields.next()?;
        let index = ATTRS.iter().position(|name| name.as_bytes() == attr)?;
        let (seen, safe) = states.get_mut(path)?;
        let bit = 1u8 << index;
        if *seen & bit != 0 {
            return None;
        }
        *seen |= bit;
        *safe &= value == b"unspecified";
    }
    if states
        .values()
        .any(|(seen, _)| *seen != (1 << ATTRS.len()) - 1)
    {
        return None;
    }
    Some(
        states
            .into_iter()
            .map(|(path, (_, safe))| (path, safe))
            .collect(),
    )
}

fn reject_present(states: &mut HashMap<&str, bool>, bytes: &[u8]) -> Option<()> {
    let mut seen = HashSet::new();
    let mut fields = fields(bytes)?;
    while let Some(path) = fields.next() {
        let path = std::str::from_utf8(path).ok()?;
        let attr = fields.next()?;
        let _value = fields.next()?;
        if attr.is_empty() || !seen.insert((path, attr)) {
            return None;
        }
        let safe = states.get_mut(path)?;
        if ATTRS.iter().any(|name| name.as_bytes() == attr) {
            *safe = false;
        }
    }
    Some(())
}

fn check_paths<'a>(
    root: &Path,
    paths: impl IntoIterator<Item = &'a str>,
) -> HashMap<String, OidBasis> {
    let mut unique = HashSet::new();
    let paths: Vec<_> = paths
        .into_iter()
        .filter(|path| valid_path(path) && unique.insert(*path))
        .collect();
    if paths.is_empty() {
        return HashMap::new();
    }
    let Some(autocrlf) = autocrlf(root) else {
        return HashMap::new();
    };
    let Some(report) = query(root, &paths, false) else {
        return HashMap::new();
    };
    let Some(mut states) = named(&paths, &report) else {
        return HashMap::new();
    };
    let Some(report) = query(root, &paths, true) else {
        return HashMap::new();
    };
    if reject_present(&mut states, &report).is_none() {
        return HashMap::new();
    }
    states
        .into_iter()
        .filter(|(_, safe)| *safe)
        .map(|(path, _)| {
            // `check-attr` prints an actual value named "unspecified" or
            // "unset" identically to an attribute state. The --all query is
            // needed to distinguish absence from such values. We also reject
            // explicitly unset attributes because that output is ambiguous.
            let unspecified = || "unspecified".to_owned();
            (
                path.to_owned(),
                OidBasis {
                    text: unspecified(),
                    eol: unspecified(),
                    filter: unspecified(),
                    ident: unspecified(),
                    working_tree_encoding: unspecified(),
                    export_subst: unspecified(),
                    crlf: unspecified(),
                    autocrlf: autocrlf.clone(),
                },
            )
        })
        .collect()
}

/// Evidence for a single repository-relative UTF-8 path, if conversion is absent.
#[cfg(any(target_os = "linux", test))]
pub fn check(root: &Path, path: &str) -> Option<OidBasis> {
    check_paths(root, [path]).remove(path)
}

/// Check a batch with one config read and batched Git attribute queries.
pub fn check_many(root: &Path, paths: &[String]) -> HashMap<String, OidBasis> {
    check_paths(root, paths.iter().map(String::as_str))
}

/// An unknown or nonempty directory may hide an attribute source.
#[cfg(any(target_os = "linux", test))]
pub fn directory_removal_invalidates(path: &Path) -> bool {
    !std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Repo(PathBuf);

    impl Repo {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "stoop-oid-attrs-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            let repo = Self(path);
            repo.git(&["init", "-q"]);
            repo
        }

        fn git(&self, args: &[&str]) {
            let out = git(&self.0)
                .unwrap()
                .args(args)
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .unwrap();
            assert!(out.status.success(), "fixture git failed");
        }

        fn write(&self, path: &str, contents: &str) {
            let path = self.0.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
    }

    impl Drop for Repo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn directory_removal_requires_proven_empty() {
        let repo = Repo::new();
        let dir = repo.0.join("nested");
        assert!(directory_removal_invalidates(&dir));
        fs::create_dir(&dir).unwrap();
        assert!(!directory_removal_invalidates(&dir));
        fs::write(dir.join(".gitattributes"), "* text\n").unwrap();
        assert!(directory_removal_invalidates(&dir));
    }

    #[test]
    fn defaults_and_exact_autocrlf_state() {
        let repo = Repo::new();
        let default = check(&repo.0, "plain.txt").unwrap();
        assert_eq!(
            default,
            OidBasis {
                text: "unspecified".into(),
                eol: "unspecified".into(),
                filter: "unspecified".into(),
                ident: "unspecified".into(),
                working_tree_encoding: "unspecified".into(),
                export_subst: "unspecified".into(),
                crlf: "unspecified".into(),
                autocrlf: "unset".into(),
            }
        );
        for value in ["false", "FALSE", "off", "no", "0"] {
            repo.git(&["config", "--local", "core.autocrlf", value]);
            assert_eq!(check(&repo.0, "plain.txt").unwrap().autocrlf, value);
        }
        for value in ["true", "input", "yes", "on", "1", "garbage"] {
            repo.git(&["config", "--local", "core.autocrlf", value]);
            assert!(check(&repo.0, "plain.txt").is_none());
        }
        repo.git(&["config", "--local", "--unset-all", "core.autocrlf"]);
        assert_eq!(check(&repo.0, "plain.txt").unwrap().autocrlf, "unset");
    }

    #[test]
    fn explicit_conversion_attributes_are_never_admitted() {
        let repo = Repo::new();
        for attr in [
            "text",
            "text=auto",
            "-text",
            "eol=lf",
            "eol=crlf",
            "-eol",
            "ident",
            "-ident",
            "filter=driver",
            "-filter",
            "working-tree-encoding=UTF-16LE",
            "-working-tree-encoding",
            "export-subst",
            "-export-subst",
            "crlf",
            "-crlf",
            "crlf=input",
        ] {
            repo.write(".gitattributes", &format!("* {attr}\n"));
            assert!(check(&repo.0, "file.txt").is_none(), "accepted {attr}");
        }
        repo.write(".gitattributes", "* !text\n");
        assert!(check(&repo.0, "file.txt").is_some());
    }

    #[test]
    fn literal_state_names_cannot_hide_filter_drivers() {
        let repo = Repo::new();
        for name in ["unset", "unspecified"] {
            let key = format!("filter.{name}.clean");
            let marker = repo.0.join(format!("driver-{name}"));
            let driver = format!("touch {}", marker.display());
            repo.git(&["config", "--local", &key, &driver]);
            repo.write(".gitattributes", &format!("* filter={name}\n"));
            assert!(check(&repo.0, "file.txt").is_none());
            assert!(!marker.exists());
        }
    }

    #[test]
    fn worktree_nested_info_and_configured_attribute_files_apply() {
        let repo = Repo::new();
        repo.write(".gitattributes", "*.root text\n");
        repo.write("nested/.gitattributes", "*.nested ident\n");
        repo.write(".git/info/attributes", "*.info filter=driver\n");
        repo.write(
            "custom-attributes",
            "*.global working-tree-encoding=UTF-16LE\n",
        );
        let attr_path = repo.0.join("custom-attributes");
        repo.git(&[
            "config",
            "--local",
            "core.attributesFile",
            attr_path.to_str().unwrap(),
        ]);
        for path in [
            "file.root",
            "nested/file.nested",
            "file.info",
            "file.global",
        ] {
            assert!(check(&repo.0, path).is_none(), "accepted {path}");
        }
        assert!(check(&repo.0, "other.txt").is_some());
    }

    #[test]
    fn batch_handles_odd_names_duplicates_and_unsafe_paths() {
        let repo = Repo::new();
        repo.write(".gitattributes", "*.converted filter=driver\n");
        let names = [
            "--leading option",
            "line\nfeed\t'quoted'\\name",
            "accent-é.txt",
            "normal.converted",
            "../outside",
            "/absolute",
            "bad\0name",
            "--leading option",
        ];
        let paths: Vec<_> = names.iter().map(|s| (*s).to_owned()).collect();
        let result = check_many(&repo.0, &paths);
        assert_eq!(result.len(), 3);
        for path in &names[..3] {
            assert!(result.contains_key(*path));
        }
        for path in &names[3..7] {
            assert!(!result.contains_key(*path));
        }
    }

    #[test]
    fn rejects_failed_git_and_parent_repository_discovery() {
        let repo = Repo::new();
        fs::create_dir(repo.0.join("child")).unwrap();
        assert!(check(&repo.0.join("child"), "file").is_none());
        assert!(check(&repo.0.join("missing"), "file").is_none());
        repo.write(".git/config", "[broken\n");
        assert!(check(&repo.0, "file").is_none());
    }

    fn named_report(path: &str) -> Vec<u8> {
        let mut report = Vec::new();
        for attr in ATTRS {
            report.extend_from_slice(path.as_bytes());
            report.push(0);
            report.extend_from_slice(attr.as_bytes());
            report.push(0);
            report.extend_from_slice(b"unspecified\0");
        }
        report
    }

    #[test]
    fn malformed_missing_duplicate_and_unexpected_records_fail_closed() {
        let paths = ["one"];
        let report = named_report("one");
        assert_eq!(named(&paths, &report).unwrap().get("one"), Some(&true));
        assert!(named(&paths, &report[..report.len() - 1]).is_none());
        assert!(named(&paths, &report[0..report.len() - 5]).is_none());
        assert!(named(&paths, &named_report("other")).is_none());
        let mut duplicate = report.clone();
        duplicate.extend_from_slice(b"one\0text\0unspecified\0");
        assert!(named(&paths, &duplicate).is_none());
        let mut unknown = report.clone();
        unknown.extend_from_slice(b"one\0unknown\0unspecified\0");
        assert!(named(&paths, &unknown).is_none());

        for invalid in [
            b"other\0custom\0value\0".as_slice(),
            b"one\0custom\0value".as_slice(),
            b"one\0custom\0value\0one\0custom\0value\0".as_slice(),
        ] {
            let mut states = named(&paths, &report).unwrap();
            assert!(reject_present(&mut states, invalid).is_none());
        }
        let mut states = named(&paths, &report).unwrap();
        reject_present(&mut states, b"one\0filter\0unspecified\0").unwrap();
        assert_eq!(states.get("one"), Some(&false));
    }
}
