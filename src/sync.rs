//! Sharing proofs between CI runs, jobs and machines through the repository's own
//! git remote. Nothing to host: every CI provider already has a remote and the
//! credentials to talk to it.
//!
//! Each proof file is stored as a blob and pointed at by `refs/stoop/<key>`. Custom
//! refs fetch fine into shallow clones and are ignored by branch and tag listings.
//!
//! Sync never fails a step. A remote that is down, slow or refuses the push leaves
//! the run exactly as it would be without sync, with a warning.

use crate::job::JobStore;
use crate::proof::{now, Store};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod bounded;
#[allow(unused_imports)]
pub use bounded::{Failure, Limits, Operation, Snapshot};

pub struct Remote {
    remote: String,
    repo: PathBuf,
    /// Writing needs an explicit yes: only trusted runs (the default branch) should
    /// publish proofs, because a proof is a claim that lets later runs skip checks.
    pub write: bool,
}

/// `refs/stoop/<key>`. Dots become underscores so the name is always a valid ref.
pub fn ref_name(key: &str) -> String {
    format!("refs/stoop/{}", key.replace('.', "_"))
}

fn legacy_exit(op: &str, status: std::process::ExitStatus) -> String {
    if let Some(code) = status.code() {
        return format!("git {op} failed with exit status {code}");
    }
    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        return format!("git {op} ended by signal {signal}");
    }
    format!("unexpected output from git {op}")
}

impl Remote {
    /// `git` or `git:<remote>`; the remote defaults to `origin`.
    pub fn from_spec(spec: &str, repo: &Path, write: bool) -> Result<Remote, String> {
        let (kind, rest) = match spec.split_once(':') {
            Some((k, r)) => (k, Some(r)),
            None => (spec, None),
        };
        if kind != "git" {
            return Err("unknown sync backend; use `git` or `git:<remote>`".into());
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
        #[cfg(test)]
        c.env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file");
        let op = args.first().copied().unwrap_or("operation");
        let mut child = c.spawn().map_err(|_| format!("cannot run git {op}"))?;
        if let (Some(bytes), Some(mut si)) = (stdin, child.stdin.take()) {
            if si.write_all(bytes).is_err() {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("unexpected output from git {op}"));
            }
        }
        child
            .wait_with_output()
            .map_err(|_| format!("cannot wait for git {op}"))
    }

    fn ok(&self, args: &[&str], stdin: Option<&[u8]>) -> Result<Vec<u8>, String> {
        let out = self.git(args, stdin)?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(legacy_exit(
                args.first().copied().unwrap_or("operation"),
                out.status,
            ))
        }
    }

    /// Fetch this key's proofs from the remote and merge them into the local store.
    /// Returns how many proofs were new. A key the remote does not have is not an error.
    pub fn pull(&self, store: &Store, key: &str) -> Result<usize, String> {
        Ok(self.pull_proof_snapshot(store, key)?.1)
    }

    pub fn pull_proof_snapshot(
        &self,
        store: &Store,
        key: &str,
    ) -> Result<(Option<String>, usize), String> {
        match self.pull_job(key)? {
            Some((oid, blob)) => {
                let added = store.import(key, &blob).map_err(|e| e.to_string())?;
                Ok((Some(oid), added))
            }
            None => Ok((None, 0)),
        }
    }

    /// Fetch every proof the remote has. Run once at the start of a job so that each
    /// step finds its proof locally and never waits on the network.
    pub fn pull_all(&self, store: &Store, jobs: &JobStore) -> Result<usize, String> {
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
        let refs = self.ok(
            &["for-each-ref", "--format=%(refname)", "refs/stoop/"],
            None,
        )?;
        let mut added = 0;
        for r in String::from_utf8_lossy(&refs).lines() {
            let blob = self.ok(&["cat-file", "blob", r], None)?;
            if let Some(key) = Store::key_of(&blob) {
                added += store.import(&key, &blob).map_err(|e| e.to_string())?;
            } else if let Some(key) = JobStore::key_of(&blob) {
                added += jobs.import(&key, &blob).map_err(|e| e.to_string())?;
            }
        }
        Ok(added)
    }

    pub fn pull_job(&self, key: &str) -> Result<Option<(String, Vec<u8>)>, String> {
        let r = ref_name(key);
        let spec = format!("+{r}:{r}");
        let out = self.git(
            &["fetch", "--quiet", "--no-tags", &self.remote, &spec],
            None,
        )?;
        if !out.status.success() {
            let error = String::from_utf8_lossy(&out.stderr);
            if error.contains("couldn't find remote ref") {
                return Ok(None);
            }
            return Err(legacy_exit("fetch", out.status));
        }
        let oid = String::from_utf8(self.ok(&["rev-parse", "--verify", &r], None)?)
            .map_err(|e| e.to_string())?
            .trim()
            .to_string();
        let blob = self.ok(&["cat-file", "blob", &oid], None)?;
        Ok(Some((oid, blob)))
    }

    pub fn push_job(
        &self,
        key: &str,
        bytes: &[u8],
        expected: Option<&str>,
        proof: Option<(&Store, &str, Option<&str>)>,
    ) -> Result<(), String> {
        if !self.write {
            return Ok(());
        }
        let mut objects = vec![(key, bytes.to_vec())];
        if let Some((store, proof_key, _)) = proof {
            objects.push((
                proof_key,
                store.export(proof_key).ok_or("no local proof to publish")?,
            ));
        }
        let mut specs = Vec::new();
        for (key, bytes) in objects {
            let sha =
                String::from_utf8_lossy(&self.ok(&["hash-object", "-w", "--stdin"], Some(&bytes))?)
                    .trim()
                    .to_string();
            specs.push(format!("{sha}:{}", ref_name(key)));
        }
        let lease = format!(
            "--force-with-lease={}:{}",
            ref_name(key),
            expected.unwrap_or("")
        );
        let proof_lease = proof.map(|(_, proof_key, expected)| {
            format!(
                "--force-with-lease={}:{}",
                ref_name(proof_key),
                expected.unwrap_or("")
            )
        });
        let mut args = vec!["push", "--quiet", "--atomic", &lease];
        if let Some(lease) = &proof_lease {
            args.push(lease);
        }
        args.push(&self.remote);
        args.extend(specs.iter().map(String::as_str));
        self.ok(&args, None)?;
        Ok(())
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
            let newest = Store::newest_created(&blob)
                .or_else(|| JobStore::newest_created(&blob))
                .unwrap_or(0);
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

    #[test]
    fn targeted_fetch_refuses_unlisted_and_deleted_refs() {
        let base = std::env::temp_dir().join(format!("stoop-b7-refs-{}", std::process::id()));
        let local = base.join("local");
        let remote = base.join("remote.git");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::create_dir_all(&remote).unwrap();
        let git = |dir: &Path, args: &[&str]| {
            let out = Command::new("git")
                .current_dir(dir)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_ALLOW_PROTOCOL", "file")
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap().trim().to_string()
        };
        git(&local, &["init", "-q"]);
        git(&remote, &["init", "--bare", "-q"]);
        git(
            &local,
            &["remote", "add", "origin", remote.to_str().unwrap()],
        );
        let blob = base.join("blob");
        std::fs::write(&blob, b"fixture").unwrap();
        let oid = git(&remote, &["hash-object", "-w", blob.to_str().unwrap()]);
        let name = "refs/stoop/job-test";
        git(&remote, &["update-ref", name, &oid]);
        let client = Remote::from_spec("git", &local, false).unwrap();
        let snapshot = client.snapshot(Limits::PLAN).unwrap();
        assert!(snapshot.contains(name));
        git(&remote, &["update-ref", "refs/stoop/job-other", &oid]);
        assert_eq!(
            snapshot.fetch(&["refs/stoop/job-other".into()], |_, _| Ok(())),
            Err(Failure::NotListed.to_string())
        );
        let local_other = Command::new("git")
            .current_dir(&local)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_ALLOW_PROTOCOL", "file")
            .args(["rev-parse", "--verify", "refs/stoop/job-other"])
            .output()
            .unwrap();
        assert!(!local_other.status.success(), "unlisted ref was fetched");
        git(&remote, &["update-ref", "-d", name]);
        assert_eq!(
            snapshot.fetch(&[name.into()], |_, _| Ok(())),
            Err(Failure::Exit(Operation::Fetch, 128).to_string())
        );
        let raced = Remote::from_spec("git", &local, false).unwrap();
        let raced_snapshot = raced.snapshot(Limits::PLAN).unwrap();
        assert!(raced_snapshot.contains("refs/stoop/job-other"));
        std::fs::write(&blob, b"changed").unwrap();
        let changed = git(&remote, &["hash-object", "-w", blob.to_str().unwrap()]);
        git(&remote, &["update-ref", "refs/stoop/job-other", &changed]);
        assert_eq!(
            raced_snapshot.fetch(&["refs/stoop/job-other".into()], |_, _| Ok(())),
            Err(Failure::Changed.to_string())
        );
        let dotted_key = "sh-name.with.dot";
        let dotted_ref = ref_name(dotted_key);
        std::fs::write(&blob, r#"{"v":2,"key":"sh-name.with.dot","proofs":[]}"#).unwrap();
        let dotted_oid = git(&remote, &["hash-object", "-w", blob.to_str().unwrap()]);
        git(&remote, &["update-ref", &dotted_ref, &dotted_oid]);
        let dotted = Remote::from_spec("git", &local, false).unwrap();
        let dotted_snapshot = dotted.snapshot(Limits::PLAN).unwrap();
        assert!(dotted_snapshot.contains(&dotted_ref));
        let mut seen = false;
        dotted_snapshot
            .fetch(std::slice::from_ref(&dotted_ref), |name, bytes| {
                assert_eq!(name, dotted_ref);
                assert_eq!(Store::key_of(bytes).as_deref(), Some(dotted_key));
                seen = true;
                Ok(())
            })
            .unwrap();
        assert!(seen);
        std::fs::remove_dir_all(base).unwrap();
    }
}
