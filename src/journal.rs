use crate::gha::{context::GhCtx, resolve, workflow};
use crate::job::{JobRecord, JobStore, RecordStatus, StepHow, StepRecord};
use crate::plan::spec::StepSpec;
use crate::proof::{now, Store};
use crate::run::{self, How, Outcome};
use crate::sync::Remote;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Serialize, Deserialize)]
pub struct Journal {
    path: PathBuf,
    key: String,
    expected: Vec<String>,
    record: JobRecord,
    blocked: bool,
    /// Workspace the action lookups run in, so git reads its credentials.
    #[serde(default)]
    root: PathBuf,
    /// `uses:` references checked at journal creation and before each publication.
    #[serde(default)]
    refs: Vec<String>,
    #[serde(default)]
    resolved: bool,
}

impl Journal {
    pub fn open(root: &Path, matrix: Option<&str>) -> Result<Option<Self>, String> {
        if !run::env_flag("GITHUB_ACTIONS") {
            return Ok(None);
        }
        let Some(temp) = run::env_str("RUNNER_TEMP") else {
            return Ok(None);
        };
        let started = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or_else(|_| now().saturating_mul(1000));
        let path = PathBuf::from(temp).join("stoop/journal.json");
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            return serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("invalid journal: {e}"));
        }
        let repository = run::env_str("GITHUB_REPOSITORY").ok_or("missing GITHUB_REPOSITORY")?;
        let workflow_ref =
            run::env_str("GITHUB_WORKFLOW_REF").ok_or("missing GITHUB_WORKFLOW_REF")?;
        let job_workflow_ref = run::env_str("STOOP_JOB_WORKFLOW_REF");
        if job_workflow_ref
            .as_ref()
            .is_some_and(|value| value != &workflow_ref)
        {
            return Err("job workflow ref differs from caller workflow ref".into());
        }
        let name = workflow_ref
            .strip_prefix(&format!("{repository}/"))
            .ok_or("workflow repository differs")?;
        let (workflow_path, _) = name.rsplit_once('@').ok_or("invalid workflow ref")?;
        if workflow_path.starts_with('-')
            || workflow_path
                .split('/')
                .any(|part| part == ".." || part.is_empty())
        {
            return Err("invalid workflow path".into());
        }
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["show", &format!("HEAD:{workflow_path}")])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err("cannot read committed workflow".into());
        }
        let text = std::str::from_utf8(&output.stdout).map_err(|e| e.to_string())?;
        let workflow = workflow::parse(workflow_path, text)?;
        let cx = GhCtx::from_env()?;
        let job = run::env_str("GITHUB_JOB").ok_or("missing GITHUB_JOB")?;
        let spec = workflow::job_spec(&workflow, &cx, &job, matrix);
        if let Some(blocked) = spec.blocked {
            return Err(blocked.detail);
        }
        let key = spec.key.ok_or("job has no key")?;
        let refs = spec.actions.clone();
        if run::env_flag("STOOP_STRICT_ACTIONS") {
            resolve::require_pinned(&refs)?;
        }
        let (actions, failures) = resolve::resolve_all(&refs, &resolve::Git::from_env(root));
        if !failures.is_empty() {
            return Err(format!("action resolution at journal open failed: {}", failures.join("; ")));
        }
        let expected = spec
            .steps
            .into_iter()
            .filter_map(|s| match s {
                StepSpec::Traced { key, .. } => Some(key),
                _ => None,
            })
            .collect();
        let head = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());
        let commit = head.filter(|h| run::env_str("GITHUB_SHA").as_ref() == Some(h));
        let mut host = BTreeMap::new();
        for (env, key) in [
            ("RUNNER_OS", "os"),
            ("RUNNER_ARCH", "arch"),
            ("ImageOS", "image_os"),
            ("ImageVersion", "image_version"),
        ] {
            if let Some(value) = run::env_str(env) {
                host.insert(key.into(), value);
            }
        }
        if let Ok(output) = Command::new("uname").arg("-r").output() {
            if output.status.success() {
                host.insert(
                    "kernel".into(),
                    String::from_utf8_lossy(&output.stdout).trim().into(),
                );
            }
        }
        let run = match (
            run::env_str("GITHUB_RUN_ID"),
            run::env_str("GITHUB_RUN_ATTEMPT"),
        ) {
            (Some(id), Some(attempt)) => Some(format!("{id}/{attempt}")),
            _ => return Err("missing run identity".into()),
        };
        Ok(Some(Self {
            path,
            key,
            expected,
            blocked: false,
            root: root.to_path_buf(),
            refs,
            resolved: true,
            record: JobRecord {
                created: 0,
                started,
                status: Some(RecordStatus::Running),
                failed: None,
                actions,
                commit,
                host,
                event_path: run::env_str("GITHUB_EVENT_PATH"),
                run,
                steps: Vec::new(),
                attest: None,
                workflow_ref: Some(workflow_ref),
                job_workflow_ref,
            },
        }))
    }

    fn save(&self) -> Result<(), String> {
        std::fs::create_dir_all(self.path.parent().ok_or("invalid journal path")?)
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
        std::fs::rename(tmp, &self.path).map_err(|e| e.to_string())
    }

    pub fn before(&mut self, key: &str) -> Result<(), String> {
        if !self.blocked
            && self
                .expected
                .get(self.record.steps.len())
                .map(String::as_str)
                != Some(key)
        {
            self.blocked = true;
            eprintln!("stoop: job record not written: step {}'s script does not match the workflow as stoop reads it", self.record.steps.len() + 1);
        }
        self.save()
    }
    pub fn eligible(&self) -> bool {
        !self.blocked
    }
    /// Recheck the open-time evidence before every publication. Missing or failed
    /// lookups cannot establish equality, including journals from older versions.
    fn check_actions(&self, resolver: &dyn resolve::Resolver) -> Result<(), String> {
        if !self.resolved {
            return Err("action resolution at journal open is missing".into());
        }
        if run::env_flag("STOOP_STRICT_ACTIONS") {
            resolve::require_pinned(&self.refs)?;
        }
        let (actions, failures) = resolve::resolve_all(&self.refs, resolver);
        if !failures.is_empty() {
            return Err(format!("action resolution before publication failed: {}", failures.join("; ")));
        }
        if actions != self.record.actions {
            return Err("action resolution changed between journal open and publication".into());
        }
        Ok(())
    }

    pub fn after(
        &mut self,
        outcome: &Outcome,
        jobs: &JobStore,
        proofs: &Store,
        remote: Option<&Remote>,
    ) -> Result<(), String> {
        if self.blocked {
            return self.save();
        }
        let publish_proof = match &outcome.how {
            How::Skipped { proof } | How::Recorded { proof } => {
                self.record.steps.push(StepRecord {
                    key: outcome.key.clone(),
                    proof: proof.clone(),
                    how: if matches!(outcome.how, How::Skipped { .. }) {
                        StepHow::Skipped
                    } else {
                        StepHow::Ran
                    },
                });
                self.record.status = Some(if self.record.steps.len() == self.expected.len() {
                    RecordStatus::Passed
                } else {
                    RecordStatus::Running
                });
                matches!(outcome.how, How::Recorded { .. })
            }
            How::Failed => {
                self.record.status = Some(RecordStatus::Failed);
                self.record.failed = Some(outcome.key.clone());
                false
            }
            How::Unrecorded(reason) => {
                let _ = reason;
                self.blocked = true;
                self.save()?;
                return Ok(());
            }
            How::Untraced if outcome.status != 0 => {
                self.record.status = Some(RecordStatus::Failed);
                self.record.failed = Some(outcome.key.clone());
                false
            }
            How::Untraced => {
                self.blocked = true;
                self.save()?;
                return Ok(());
            }
        };
        if let Some(remote) = remote.filter(|r| r.write) {
            let git = resolve::Git::from_env(&self.root);
            if let Err(reason) = self.check_actions(&git) {
                self.blocked = true;
                self.save()?;
                return Err(reason);
            }
            let timestamp = now().max(self.record.created.saturating_add(1));
            self.record.created = timestamp;
            if publish_proof && run::env_str(run::SALT_VAR).is_none() {
                eprintln!("stoop: sync: publishing environment hashes without {}. In a public repository set it from a repository secret so low-entropy values cannot be guessed offline.", run::SALT_VAR);
            }
            let mut last_error = String::new();
            for _ in 0..3 {
                let snapshot = match remote.pull_job(&self.key) {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        last_error = error;
                        break;
                    }
                };
                let proof_oid = if publish_proof {
                    match remote.pull_proof_snapshot(proofs, &outcome.key) {
                        Ok((oid, _)) => oid,
                        Err(error) => {
                            last_error = error;
                            break;
                        }
                    }
                } else {
                    None
                };
                let bytes = JobStore::merge_remote(
                    &self.key,
                    snapshot.as_ref().map(|(_, bytes)| bytes.as_slice()),
                    self.record.clone(),
                )
                .map_err(|e| e.to_string())?;
                match remote.push_job(
                    &self.key,
                    &bytes,
                    snapshot.as_ref().map(|(oid, _)| oid.as_str()),
                    publish_proof.then_some((proofs, outcome.key.as_str(), proof_oid.as_deref())),
                ) {
                    Ok(()) => {
                        jobs.import(&self.key, &bytes).map_err(|e| e.to_string())?;
                        return self.save();
                    }
                    Err(error) => last_error = error,
                }
            }
            self.blocked = true;
            self.save()?;
            return Err(last_error);
        } else {
            self.save()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gha::resolve::fake::Fake;

    const A: &str = "1111111111111111111111111111111111111111";

    fn journal(refs: &[&str]) -> Journal {
        Journal {
            path: PathBuf::from("unused.json"),
            key: "job-x".into(),
            expected: vec![],
            blocked: false,
            root: PathBuf::new(),
            refs: refs.iter().map(|s| s.to_string()).collect(),
            resolved: false,
            record: JobRecord {
                created: 0,
                started: 0,
                status: None,
                failed: None,
                actions: BTreeMap::new(),
                commit: None,
                host: BTreeMap::new(),
                event_path: None,
                run: None,
                steps: vec![],
                attest: None,
                workflow_ref: None,
                job_workflow_ref: None,
            },
        }
    }

    #[test]
    fn publication_requires_open_and_publish_resolutions_to_match() {
        let fake = Fake::new();
        fake.set("actions/checkout@v4", Ok(A));
        let mut j = journal(&["actions/checkout@v4"]);
        let (actions, failures) = resolve::resolve_all(&j.refs, &fake);
        assert!(failures.is_empty());
        j.record.actions = actions;
        j.resolved = true;
        let j: Journal = serde_json::from_str(&serde_json::to_string(&j).unwrap()).unwrap();
        assert!(j.check_actions(&fake).is_ok());
        fake.set("actions/checkout@v4", Ok("2222222222222222222222222222222222222222"));
        assert!(j.check_actions(&fake).unwrap_err().contains("changed"));
        fake.set("actions/checkout@v4", Err("unavailable"));
        assert!(j.check_actions(&fake).unwrap_err().contains("failed"));
    }

    #[test]
    fn old_journal_without_open_evidence_cannot_publish() {
        let j = journal(&["actions/checkout@v4"]);
        let fake = Fake::new();
        assert!(j.check_actions(&fake).unwrap_err().contains("missing"));
        assert_eq!(fake.calls(), 0);
    }
}
