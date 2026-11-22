//! Exclusion list. Patterns come from `.stoopignore`, `--ignore`, and defaults.
//!
//! - `name` (no slash): matches any path component called `name`, anywhere.
//! - `a/b` (slash): matches that path, or anything below it, from the root.
//! - `/abs/path`: the same for a path outside the root.
//! - `*` matches within a component, `**` across components, `?` one character.
//!
//! Transient patterns (a CI step's script file, which has a new name on every run)
//! exclude paths like any other, but are never stored with a proof: a proof must
//! describe the same repository state whichever temporary name the run used.

use std::path::Path;

pub struct Ignore {
    rules: Vec<Rule>,
    /// Folders excluded by their literal text (`exclude_folder`). Never stored with a proof.
    folders: Vec<Vec<u8>>,
    /// The patterns a proof stores: defaults, file lines and flags, never transient ones.
    patterns: Vec<String>,
}

struct Rule {
    pat: Vec<u8>,
    anchored: bool,
}

const DEFAULTS: &[&str] = &[
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/tmp",
    "/var/run",
    "/etc/resolv.conf",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/mtab",
    ".stoop",
];

impl Ignore {
    pub fn new(extra: &[String], file: Option<&Path>, transient: &[String]) -> Ignore {
        let mut rules = Vec::new();
        let mut patterns = Vec::new();
        let mut add = |s: &str, stored: bool| {
            let s = s.trim().trim_end_matches('/');
            if s.is_empty() || s.starts_with('#') {
                return;
            }
            if stored {
                patterns.push(s.to_string());
            }
            rules.push(Rule {
                pat: s.as_bytes().to_vec(),
                anchored: s.contains('/'),
            });
        };
        for d in DEFAULTS {
            add(d, true);
        }
        if let Some(f) = file {
            if let Ok(text) = std::fs::read_to_string(f) {
                for line in text.lines() {
                    add(line, true);
                }
            }
        }
        for e in extra {
            add(e, true);
        }
        for t in transient {
            add(t, false);
        }
        Ignore {
            rules,
            folders: Vec::new(),
            patterns,
        }
    }

    /// `key` is the root-relative or absolute text from `pathutil::to_key`.
    pub fn is_ignored(&self, key: &str) -> bool {
        let k = key.as_bytes();
        self.rules.iter().any(|r| r.matches(key))
            || self.folders.iter().any(|folder| {
                k.starts_with(folder) && (k.len() == folder.len() || k[folder.len()] == b'/')
            })
    }

    /// Excludes a folder and everything below it, matched by its literal text: no trimming, comment or
    /// glob handling, so `#cache`, ` c?che ` and `c?che` are each matched under their own name. Like a
    /// transient pattern, it is never stored with a proof. An empty folder excludes nothing.
    pub fn exclude_folder(&mut self, folder: &str) {
        if !folder.is_empty() {
            self.folders.push(folder.as_bytes().to_vec());
        }
    }

    /// The patterns a proof records. Transient patterns are excluded.
    pub fn patterns(&self) -> Vec<String> {
        self.patterns.clone()
    }
}

impl Rule {
    fn matches(&self, key: &str) -> bool {
        let k = key.as_bytes();
        if self.anchored {
            // The pattern names a path; it also covers everything below it.
            for (i, &b) in k.iter().enumerate() {
                if b == b'/' && i > 0 && glob(&self.pat, &k[..i]) {
                    return true;
                }
            }
            glob(&self.pat, k)
        } else {
            k.split(|&b| b == b'/').any(|c| glob(&self.pat, c))
        }
    }
}

pub fn glob(p: &[u8], s: &[u8]) -> bool {
    // Iterative matcher with backtracking on the last `*` / `**`.
    let (mut pi, mut si) = (0usize, 0usize);
    // (pattern index after the star, string index to retry from, star crosses '/')
    let mut star: Option<(usize, usize, bool)> = None;
    while si < s.len() {
        if pi < p.len() {
            match p[pi] {
                b'*' => {
                    let cross = p.get(pi + 1) == Some(&b'*');
                    pi += if cross { 2 } else { 1 };
                    star = Some((pi, si, cross));
                    continue;
                }
                b'?' if s[si] != b'/' => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                c if c != b'?' && c == s[si] => {
                    pi += 1;
                    si += 1;
                    continue;
                }
                _ => {}
            }
        }
        match star {
            Some((spi, ssi, cross)) if cross || s[ssi] != b'/' => {
                star = Some((spi, ssi + 1, cross));
                pi = spi;
                si = ssi + 1;
            }
            _ => return false,
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ig(rules: &[&str]) -> Ignore {
        Ignore::new(
            &rules.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            None,
            &[],
        )
    }

    #[test]
    fn component_names_match_anywhere() {
        let i = ig(&["node_modules"]);
        assert!(i.is_ignored("node_modules/x/y.js"));
        assert!(i.is_ignored("app/node_modules/x"));
        assert!(!i.is_ignored("app/src/modules.js"));
    }

    #[test]
    fn slash_patterns_are_anchored_and_cover_children() {
        let i = ig(&["app/dist"]);
        assert!(i.is_ignored("app/dist"));
        assert!(i.is_ignored("app/dist/a.js"));
        assert!(!i.is_ignored("other/app/dist/a.js"));
    }

    #[test]
    fn globs() {
        let i = ig(&["*.log", "docs/**/gen"]);
        assert!(i.is_ignored("a/b/x.log"));
        assert!(!i.is_ignored("a/b/x.txt"));
        assert!(i.is_ignored("docs/a/b/gen/file"));
        assert!(!i.is_ignored("docs/a/b/other/file"));
    }

    #[test]
    fn defaults_cover_volatile_system_paths() {
        let i = ig(&[]);
        assert!(i.is_ignored("/proc/self/maps"));
        assert!(i.is_ignored("/etc/resolv.conf"));
        assert!(i.is_ignored(".stoop/proofs/x.json"));
        assert!(!i.is_ignored("/etc/passwd"));
        assert!(!i.is_ignored("src/main.rs"));
    }

    #[test]
    fn transient_patterns_exclude_but_are_never_stored() {
        let i = Ignore::new(&["target".to_string()], None, &["step-7f3.sh".to_string()]);
        assert!(i.is_ignored("step-7f3.sh"));
        assert!(i.is_ignored("target/debug/x"));
        let stored = i.patterns();
        assert!(stored.iter().any(|p| p == "target"));
        assert!(stored.iter().any(|p| p == "/tmp"));
        assert!(!stored.iter().any(|p| p.contains("step-7f3")));
    }

    #[test]
    fn an_excluded_folder_is_matched_by_its_literal_text() {
        let mut i = ig(&[]);
        i.exclude_folder("#cache/units/v1");
        i.exclude_folder(" c?che /units/v1");
        i.exclude_folder("c?che/units/v1");
        i.exclude_folder("/work/#store/units/v1");
        assert!(i.is_ignored("#cache/units/v1"));
        assert!(i.is_ignored("#cache/units/v1/.x.scratch/changed"));
        assert!(!i.is_ignored("#cache/units/v10/x"));
        assert!(i.is_ignored(" c?che /units/v1/x"));
        assert!(i.is_ignored("c?che/units/v1/x"));
        assert!(!i.is_ignored("cache/units/v1/x"));
        assert!(!i.is_ignored("c?che/units/v1x"));
        assert!(i.is_ignored("/work/#store/units/v1/x"));
        assert!(i.patterns().iter().all(|p| !p.contains("units/v1")));
    }
}
