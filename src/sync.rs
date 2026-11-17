//! Sharing proofs between CI runs, jobs and machines through the repository's own
//! git remote. Nothing to host: every CI provider already has a remote and the
//! credentials to talk to it.
//!
//! Each proof file is stored as a blob and pointed at by `refs/stoop/<key>`. Custom
//! refs fetch fine into shallow clones and are ignored by branch and tag listings.
//!
//! Sync never fails a step. A remote that is down, slow or refuses the push leaves
//! the run exactly as it would be without sync, with a warning.

use crate::proof::{now, Store};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

pub struct Remote {
    remote: String,
    repo: PathBuf,
    /// Writing needs an explicit yes: only trusted runs (the default branch) should
    /// publish proofs, because a proof is a claim that lets later runs skip checks.
    pub write: bool,
}

/// `refs/stoop/<key>`. Dots become underscores so the name is always a valid ref.
fn ref_name(key: &str) -> String {
    format!("refs/stoop/{}", key.replace('.', "_"))
}

impl Remote {
    /// `git` or `git:<remote>`; the remote defaults to `origin`.
    pub fn from_spec(spec: &str, repo: &Path, write: bool) -> Result<Remote, String> {
        let (kind, rest) = match spec.split_once(':') {
            Some((k, r)) => (k, Some(r)),
            None => (spec, None),
        };
        if kind != "git" {
            return Err(format!(
                "unknown sync backend {spec:?}; use `git` or `git:<remote>`"
            ));
        }
        Ok(Remote {
            remote: rest
                .filter(|r| !r.is_empty())
                .unwrap_or("origin")
                .to_string(),
            repo: repo.to_path_buf(),
            write,
        })
    }

    fn git(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Output, String> {
        let mut c = Command::new("git");
        c.arg("-C")
            .arg(&self.repo)
            // Give up on a stalled connection instead of holding up the step.
            .args([
                "-c",
                "http.lowSpeedLimit=1000",
                "-c",
                "http.lowSpeedTime=20",
            ])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().map_err(|e| format!("cannot run git: {e}"))?;
        if let (Some(bytes), Some(mut si)) = (stdin, child.stdin.take()) {
            si.write_all(bytes).map_err(|e| e.to_string())?;
        }
        child.wait_with_output().map_err(|e| e.to_string())
    }

    fn ok(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let out = self.git(args, stdin)?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(err
                .lines()
                .next()
                .unwrap_or("git failed")
                .trim()
                .to_string())
        }
    }

    /// Fetch this key's proofs from the remote and merge them into the local store.
    /// Returns how many proofs were new. A key the remote does not have is not an error.
    pub fn pull(&self, store: &Store, key: &str) -> Result<usize, String> {
        let r = ref_name(key);
        let spec = format!("+{r}:{r}");
        let out = self.git(
            &["fetch", "--quiet", "--no-tags", &self.remote, &spec],
            None,
        )?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("couldn't find remote ref") {
                return Ok(0);
            }
            return Err(err
                .lines()
                .next()
                .unwrap_or("fetch failed")
                .trim()
                .to_string());
        }
        let blob = self.ok(&["cat-file", "blob", &r], None)?;
        store.import(key, &blob).map_err(|e| e.to_string())
    }

    /// Fetch every proof the remote has. Run once at the start of a job so that each
    /// step finds its proof locally and never waits on the network.
    pub fn pull_all(&self, store: &Store) -> Result<usize, String> {
        self.ok(
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                &self.remote,
                "+refs/stoop/*:refs/stoop/*",
            ],
            None,
        )
        .or_else(|e| {
            if e.contains("couldn't find remote ref") {
                Ok(Vec::new())
            } else {
                Err(e)
            }
        })?;
        let refs = self.ok(
            &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
            None,
        )?;
        let mut added = 0;
        for r in String::from_utf8_lossy(&refs).lines() {
            let blob = self.ok(&["cat-file", "blob", r], None)?;
            if let Some(key) = Store::key_of(&blob) {
                added += store.import(&key, &blob).map_err(|e| e.to_string())?;
            }
        }
        Ok(added)
    }

    /// Publish this key's proofs. Only with `write`.
    pub fn push(&self, store: &Store, key: &str) -> Result<(), String> {
        if !self.write {
            return Ok(());
        }
        let bytes = store.export(key).ok_or("no local proof to publish")?;
        let sha =
            String::from_utf8_lossy(&self.ok(&["hash-object", "-w", "--stdin"], Some(&bytes))?)
                .trim()
                .to_string();
        let r = ref_name(key);
        self.ok(&["update-ref", &r, &sha], None)?;
        let spec = format!("+{r}:{r}");
        self.ok(&["push", "--quiet", &self.remote, &spec], None)?;
        Ok(())
    }

    /// Delete remote proofs whose newest entry is older than `max_age` seconds.
    pub fn prune(&self, max_age: u64) -> Result<usize, String> {
        if !self.write {
            return Err("pruning needs --sync-write".into());
        }
        let listing = self.ok(&["ls-remote", &self.remote, "refs/stoop/*"], None)?;
        let refs: Vec<String> = String::from_utf8_lossy(&listing)
            .lines()
            .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
            .collect();
        if refs.is_empty() {
            return Ok(0);
        }
        self.ok(
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                &self.remote,
                "+refs/stoop/*:refs/stoop/*",
            ],
            None,
        )?;
        let mut removed = 0;
        for r in refs {
            let blob = self.ok(&["cat-file", "blob", &r], None)?;
            let newest = Store::newest_created(&blob).unwrap_or(0);
            if now().saturating_sub(newest) > max_age {
                self.ok(&["push", "--quiet", &self.remote, "--delete", &r], None)?;
                let _ = self.ok(&["update-ref", "-d", &r], None);
                removed += 1;
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_parsing() {
        let s = Remote::from_spec("git", Path::new("."), false).unwrap();
        assert_eq!(s.remote, "origin");
        let s = Remote::from_spec("git:upstream", Path::new("."), true).unwrap();
        assert_eq!(s.remote, "upstream");
        assert!(s.write);
        assert!(Remote::from_spec("s3://bucket", Path::new("."), false).is_err());
    }

    #[test]
    fn ref_names_are_valid_refs() {
        assert_eq!(ref_name("sh-abc.def"), "refs/stoop/sh-abc_def");
        assert!(!ref_name("a..b").contains(".."));
    }
}
