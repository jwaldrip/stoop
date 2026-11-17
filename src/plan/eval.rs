//! Symbolically evaluate step proofs without executing repository code.
use super::spec::{Code, Decision, Evidence, JobSpec, StepSpec};
use crate::gittree::{Entry, GitTree};
use crate::job::{JobRecord, JobStore};
use crate::proof::{Proof, Store};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct PlanCtx<'a> {
    pub tree: &'a mut GitTree,
    pub proofs: &'a Store,
    pub jobs: &'a JobStore,
    pub now: u64,
    pub max_age: u64,
    /// Raw values of known GitHub variables, not their recorded hashes.
    pub github_vars: BTreeMap<String, String>,
    /// Identity of the current run's event payload, if readable.
    pub event: Option<String>,
    pub explain: bool,
}

fn decision(code: Code, detail: String) -> Decision {
    Decision {
        skip: false,
        code,
        detail,
        evidence: None,
        mismatches: Vec::new(),
    }
}

fn valid_path(p: &str) -> bool {
    p == "."
        || (!p.is_empty()
            && !p.starts_with('/')
            && p.split('/').all(|s| !s.is_empty() && s != "." && s != ".."))
}

#[derive(Clone)]
enum State {
    Absent,
    Dir,
    File(String),
    Link(String),
}

struct VirtualTree<'a> {
    tree: &'a mut GitTree,
    overlay: BTreeMap<String, Option<String>>,
    erased: BTreeSet<String>,
}
impl VirtualTree<'_> {
    fn direct(&mut self, p: &str, hidden: bool) -> Result<State, String> {
        if let Some(value) = self.overlay.get(p) {
            return match value {
                None => Ok(State::Absent),
                Some(id) if id == "d" || id.starts_with("dl:") => Ok(State::Dir),
                Some(id) if id.starts_with("f:") => Ok(State::File(id.clone())),
                Some(id) if id.starts_with("l:") => Ok(State::Link(id.clone())),
                _ => Err(format!("invalid output identity for {p}")),
            };
        }
        if hidden
            || self
                .erased
                .iter()
                .any(|e| p == e || p.starts_with(&format!("{e}/")))
        {
            return Ok(State::Absent);
        }
        if p == "." || p == ".git" {
            return Ok(State::Dir);
        }
        match self.tree.entry(p).cloned() {
            Some(Entry::Tree | Entry::Gitlink) => Ok(State::Dir),
            Some(Entry::Blob(oid)) => Ok(State::File(format!(
                "f:{}",
                blake3::hash(self.tree.blob(&oid)?).to_hex()
            ))),
            Some(Entry::Link(oid)) => Ok(State::Link(format!(
                "l:{}",
                String::from_utf8_lossy(self.tree.blob(&oid)?)
            ))),
            None => Ok(State::Absent),
        }
    }
    fn state(&mut self, p: &str) -> Result<State, String> {
        if !valid_path(p) {
            return Err(format!("invalid path {p}"));
        }
        if p == "." {
            return Ok(State::Dir);
        }
        let mut hidden = false;
        let mut prefix = String::new();
        let parts: Vec<_> = p.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            match self.direct(&prefix, hidden)? {
                State::Absent => hidden = true,
                State::Dir => {}
                State::File(_) => return Ok(State::Absent),
                State::Link(_) => {
                    return Err(format!("cannot evaluate a path through symlink {prefix}"))
                }
            }
        }
        let state = self.direct(p, hidden)?;
        if matches!(state, State::Absent) {
            let pre = format!("{p}/");
            if self
                .overlay
                .range(pre.clone()..)
                .take_while(|(k, _)| k.starts_with(&pre))
                .any(|(_, v)| v.is_some())
            {
                return Ok(State::Dir);
            }
        }
        Ok(state)
    }
    fn id(&mut self, p: &str, expected: &str) -> Result<String, String> {
        let state = self.state(p)?;
        match state {
            State::Absent => Ok("a".into()),
            State::File(id) | State::Link(id) => Ok(id),
            State::Dir if expected.starts_with("dl:") => {
                let prefix = if p == "." {
                    String::new()
                } else {
                    format!("{p}/")
                };
                let mut names = BTreeSet::new();
                for path in self.tree.paths().chain(self.overlay.keys()) {
                    if let Some(rest) = path.strip_prefix(&prefix) {
                        if let Some(name) = rest.split('/').next().filter(|s| !s.is_empty()) {
                            names.insert(name.to_string());
                        }
                    }
                }
                if p == "." {
                    names.insert(".git".into());
                }
                let mut hash = blake3::Hasher::new();
                for name in names {
                    let child = format!("{prefix}{name}");
                    if !matches!(self.state(&child)?, State::Absent) {
                        hash.update(&(name.len() as u64).to_le_bytes());
                        hash.update(name.as_bytes());
                    }
                }
                Ok(format!("dl:{}", hash.finalize().to_hex()))
            }
            State::Dir => Ok("d".into()),
        }
    }
}

fn known_github(name: &str) -> bool {
    matches!(
        name,
        "GITHUB_REF"
            | "GITHUB_REF_NAME"
            | "GITHUB_REF_TYPE"
            | "GITHUB_REF_PROTECTED"
            | "GITHUB_SHA"
            | "GITHUB_EVENT_NAME"
            | "GITHUB_REPOSITORY"
            | "GITHUB_REPOSITORY_ID"
            | "GITHUB_REPOSITORY_OWNER"
            | "GITHUB_REPOSITORY_OWNER_ID"
            | "GITHUB_ACTOR"
            | "GITHUB_ACTOR_ID"
            | "GITHUB_TRIGGERING_ACTOR"
            | "GITHUB_HEAD_REF"
            | "GITHUB_BASE_REF"
            | "GITHUB_WORKFLOW"
            | "GITHUB_WORKFLOW_REF"
            | "GITHUB_WORKFLOW_SHA"
            | "GITHUB_RUN_ID"
            | "GITHUB_RUN_NUMBER"
            | "GITHUB_RUN_ATTEMPT"
            | "GITHUB_SERVER_URL"
            | "GITHUB_API_URL"
            | "GITHUB_GRAPHQL_URL"
            | "GITHUB_RETENTION_DAYS"
            | "GITHUB_WORKSPACE"
            | "GITHUB_JOB"
            | "CI"
    )
}

pub fn decide(spec: &JobSpec, ctx: &mut PlanCtx<'_>) -> Decision {
    let Some(key) = &spec.key else {
        return decision(Code::Blocked, "job has no key".into());
    };
    let records = ctx.jobs.load(key);
    if records.is_empty() {
        return decision(Code::NoRecord, "no job record".into());
    }
    let mut newest = None;
    for record in &records {
        let result = evaluate(spec, ctx, record);
        if result.skip {
            return result;
        }
        if newest.is_none() {
            newest = Some(result);
        }
    }
    newest.expect("nonempty records")
}

fn evaluate(spec: &JobSpec, ctx: &mut PlanCtx<'_>, record: &JobRecord) -> Decision {
    let steps: Vec<_> = spec
        .steps
        .iter()
        .filter_map(|s| match s {
            StepSpec::Traced {
                index,
                key,
                max_age,
            } => Some((*index, key, *max_age)),
            _ => None,
        })
        .collect();
    if steps.is_empty()
        || steps.len() != record.steps.len()
        || steps
            .iter()
            .zip(&record.steps)
            .any(|((_, key, _), r)| *key != &r.key)
    {
        return decision(
            Code::Incomplete,
            "record does not match traced steps".into(),
        );
    }
    let mut proofs: Vec<Proof> = Vec::new();
    for ((index, key, age), saved) in steps.iter().zip(&record.steps) {
        let Some(proof) = ctx
            .proofs
            .load(key)
            .into_iter()
            .find(|p| p.digest() == saved.proof)
        else {
            return decision(Code::ProofMissing, format!("step {index}: proof missing"));
        };
        if proof.ignore.is_none() {
            return decision(Code::OldProof, format!("step {index}: old proof"));
        }
        let max_age = age.unwrap_or(ctx.max_age);
        if max_age != 0 && ctx.now.saturating_sub(proof.created) > max_age {
            return decision(Code::Expired, format!("step {index}: proof expired"));
        }
        if proof.created > ctx.now {
            return decision(
                Code::Expired,
                format!("step {index}: proof is from the future"),
            );
        }
        if !proof.probes.is_empty() {
            return decision(
                Code::Probe,
                format!("step {index}: probe cannot be evaluated"),
            );
        }
        proofs.push(proof);
    }
    let mut evidence = Evidence {
        run: record.run.clone(),
        created: record.created,
        commit: record.commit.clone(),
        steps: steps.len(),
        inputs: 0,
        hashed: 0,
        by_diff: 0,
        overlay: 0,
        assumed_outside: 0,
        assumed_env: Vec::new(),
    };
    let mut assumed_env = BTreeSet::new();
    let mut tree = VirtualTree {
        tree: ctx.tree,
        overlay: BTreeMap::new(),
        erased: BTreeSet::new(),
    };
    for ((index, _, _), proof) in steps.iter().zip(&proofs) {
        for input in &proof.inputs {
            evidence.inputs += 1;
            if Path::new(&input.path).is_absolute() {
                if record.event_path.as_deref() == Some(&input.path) {
                    if ctx.event.as_deref() != Some(input.id.as_str()) {
                        return decision(
                            Code::InputChanged,
                            format!("step {index}: event payload changed"),
                        );
                    }
                } else {
                    evidence.assumed_outside += 1;
                }
                continue;
            }
            let actual = match tree.id(&input.path, &input.id) {
                Ok(id) if input.id != "u" && !input.id.starts_with("dlx:") => id,
                Ok(_) => {
                    return decision(
                        Code::InputChanged,
                        format!("step {index}: unsupported input {}", input.path),
                    )
                }
                Err(err) => {
                    return decision(
                        Code::InputChanged,
                        format!("step {index}: {}: {err}", input.path),
                    )
                }
            };
            if tree.overlay.contains_key(&input.path)
                || tree.overlay.keys().any(|p| {
                    input.path.starts_with(&format!("{p}/"))
                        || p.starts_with(&format!("{}/", input.path))
                })
            {
                evidence.overlay += 1;
            } else if input.id.starts_with("f:") {
                evidence.hashed += 1;
            }
            if actual != input.id {
                let why = if actual == "a" {
                    "removed"
                } else if input.id == "a" {
                    "appeared"
                } else {
                    "changed"
                };
                let mut result = decision(
                    Code::InputChanged,
                    format!(
                        "step {index}: {} {why}; setup or cache files need .stoopignore",
                        input.path
                    ),
                );
                result
                    .mismatches
                    .push((*index, input.path.clone(), why.into()));
                return result;
            }
        }
        for (name, hash) in &proof.env {
            if known_github(name) {
                let value = if name == "GITHUB_JOB" {
                    Some(&spec.job)
                } else {
                    ctx.github_vars.get(name)
                };
                if value
                    .map(|v| blake3::hash(v.as_bytes()).to_hex().to_string())
                    .as_deref()
                    != Some(hash)
                {
                    return decision(
                        Code::EnvChanged,
                        format!("step {index}: {name} changed or unavailable"),
                    );
                }
            } else {
                assumed_env.insert(name.clone());
            }
        }
        for out in &proof.outputs {
            if !valid_path(&out.path)
                || out.path == "."
                || !(out.id == "d"
                    || out.id.starts_with("f:")
                    || out.id.starts_with("l:")
                    || out.id.starts_with("dl:"))
            {
                return decision(
                    Code::InputChanged,
                    format!("step {index}: invalid output {}", out.path),
                );
            }
            if out.id != "d" && !out.id.starts_with("dl:") {
                tree.erased.insert(out.path.clone());
                let prefix = format!("{}/", out.path);
                tree.overlay.retain(|p, _| !p.starts_with(&prefix));
            }
            tree.overlay.insert(out.path.clone(), Some(out.id.clone()));
        }
        for path in &proof.removed {
            if !valid_path(path) || path == "." {
                return decision(
                    Code::InputChanged,
                    format!("step {index}: invalid removal {path}"),
                );
            }
            tree.erased.insert(path.clone());
            let prefix = format!("{path}/");
            tree.overlay.retain(|p, _| !p.starts_with(&prefix));
            tree.overlay.insert(path.clone(), None);
        }
    }
    evidence.assumed_env = assumed_env.into_iter().collect();
    Decision {
        skip: true,
        code: Code::Proved,
        detail: "all inputs match".into(),
        evidence: Some(evidence),
        mismatches: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Input;
    use crate::job::{StepHow, StepRecord};
    use std::fs;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture {
        root: std::path::PathBuf,
        tree: GitTree,
        proofs: Store,
        jobs: JobStore,
        spec: JobSpec,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "stoop-plan-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("dir")).unwrap();
            fs::write(root.join("dir/a"), b"tracked").unwrap();
            for args in [
                &["init", "-q"][..],
                &["add", "."][..],
                &[
                    "-c",
                    "user.name=test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-qm",
                    "init",
                ][..],
            ] {
                assert!(Command::new("git")
                    .current_dir(&root)
                    .args(args)
                    .status()
                    .unwrap()
                    .success());
            }
            let tree = GitTree::load(&root, "HEAD").unwrap();
            let proofs = Store::new(root.join("store"));
            let jobs = JobStore::new(root.join("store"));
            let spec = JobSpec {
                workflow: "ci".into(),
                path: "ci.yml".into(),
                job: "test".into(),
                leg: None,
                key: Some("job-test".into()),
                runs_on: serde_json::Value::Null,
                needs: vec![],
                if_text: None,
                steps: vec![],
                blocked: None,
            };
            Self {
                root,
                tree,
                proofs,
                jobs,
                spec,
            }
        }
        fn install(&mut self, proofs: Vec<Proof>) {
            let mut records = vec![];
            for (index, proof) in proofs.into_iter().enumerate() {
                let key = format!("sh-{index}");
                self.spec.steps.push(StepSpec::Traced {
                    index: index + 1,
                    key: key.clone(),
                    max_age: None,
                });
                records.push(StepRecord {
                    key: key.clone(),
                    proof: proof.digest(),
                    how: StepHow::Ran,
                });
                self.proofs.save(&key, proof).unwrap();
            }
            self.jobs
                .save(
                    "job-test",
                    JobRecord {
                        created: 100,
                        commit: None,
                        host: BTreeMap::new(),
                        event_path: None,
                        run: Some("1/1".into()),
                        steps: records,
                        attest: None,
                    },
                )
                .unwrap();
        }
        fn decide(&mut self, vars: BTreeMap<String, String>) -> Decision {
            decide(
                &self.spec,
                &mut PlanCtx {
                    tree: &mut self.tree,
                    proofs: &self.proofs,
                    jobs: &self.jobs,
                    now: 100,
                    max_age: 50,
                    github_vars: vars,
                    event: None,
                    explain: false,
                },
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn file_id(bytes: &[u8]) -> String {
        format!("f:{}", blake3::hash(bytes).to_hex())
    }
    fn input(path: &str, id: &str) -> Input {
        Input {
            path: path.into(),
            id: id.into(),
        }
    }
    fn proof(inputs: Vec<Input>) -> Proof {
        Proof {
            created: 90,
            argv: vec![],
            env: BTreeMap::new(),
            inputs,
            outputs: vec![],
            removed: vec![],
            ignore: Some(vec![]),
            probes: BTreeMap::new(),
        }
    }
    #[test]
    fn skips_when_every_input_matches() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn names_the_changed_path() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"old"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::InputChanged);
        assert_eq!(d.mismatches[0], (1, "dir/a".into(), "changed".into()));
    }
    #[test]
    fn overlay_feeds_later_step() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.outputs.push(input("dir/a", &file_id(b"generated")));
        f.install(vec![
            first,
            proof(vec![input("dir/a", &file_id(b"generated"))]),
        ]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Proved);
        assert_eq!(d.evidence.unwrap().overlay, 1);
    }
    #[test]
    fn removed_path_reads_absent() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.removed.push("dir/a".into());
        f.install(vec![first, proof(vec![input("dir/a", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn untracked_recorded_file_runs() {
        let mut f = Fixture::new();
        fs::write(f.root.join("cache"), b"cached").unwrap();
        f.install(vec![proof(vec![input("cache", &file_id(b"cached"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::InputChanged);
        assert!(d.detail.contains(".stoopignore"));
    }
    #[test]
    fn expired_runs() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.created = 1;
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
    }
    #[test]
    fn probe_runs() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.probes.insert("do-not-run".into(), "hash".into());
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Probe);
    }
    #[test]
    fn missing_digest_runs() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        f.proofs.save("sh-0", proof(vec![input("x", "a")])).unwrap();
        fs::remove_file(f.root.join("store/proofs/sh-0.json")).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::ProofMissing);
    }
    #[test]
    fn old_format_runs() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.ignore = None;
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::OldProof);
    }
    #[test]
    fn github_var_mismatch_runs() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.env.insert(
            "GITHUB_REF".into(),
            blake3::hash(b"old").to_hex().to_string(),
        );
        f.install(vec![p]);
        assert_eq!(
            f.decide(BTreeMap::from([("GITHUB_REF".into(), "new".into())]))
                .code,
            Code::EnvChanged
        );
    }
    #[test]
    fn outside_and_env_are_assumed_and_counted() {
        let mut f = Fixture::new();
        let mut p = proof(vec![input("/outside", "f:any")]);
        p.env.insert("HOME".into(), "hash".into());
        f.install(vec![p]);
        let e = f.decide(BTreeMap::new()).evidence.unwrap();
        assert_eq!(e.assumed_outside, 1);
        assert_eq!(e.assumed_env, vec!["HOME"]);
    }
    #[test]
    fn falls_back_to_older_record() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        let mut r = f.jobs.load("job-test").remove(0);
        r.created = 101;
        r.run = Some("2/1".into());
        r.steps[0].proof = "missing".into();
        f.jobs.save("job-test", r).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn removed_directory_does_not_resurrect_tracked_children() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.removed.push("dir".into());
        let mut second = proof(vec![]);
        second.outputs.push(input("dir/new", &file_id(b"new")));
        f.install(vec![
            first,
            second,
            proof(vec![
                input("dir/a", "a"),
                input("dir/new", &file_id(b"new")),
            ]),
        ]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn listing_matches_runtime_and_overlay() {
        let mut f = Fixture::new();
        let initial = crate::input::identify(&f.root.join("dir"), true, true).unwrap();
        let mut first = proof(vec![input("dir", &initial)]);
        first.removed.push("dir/a".into());
        first.outputs.push(input("dir/b", &file_id(b"new")));
        fs::remove_file(f.root.join("dir/a")).unwrap();
        fs::write(f.root.join("dir/b"), b"new").unwrap();
        let after = crate::input::identify(&f.root.join("dir"), true, true).unwrap();
        f.install(vec![first, proof(vec![input("dir", &after)])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn event_payload_must_match() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input(
            "/tmp/event.json",
            &file_id(b"old"),
        )])]);
        let mut record = f.jobs.load("job-test").remove(0);
        record.event_path = Some("/tmp/event.json".into());
        f.jobs.save("job-test", record).unwrap();
        let d = decide(
            &f.spec,
            &mut PlanCtx {
                tree: &mut f.tree,
                proofs: &f.proofs,
                jobs: &f.jobs,
                now: 100,
                max_age: 50,
                github_vars: BTreeMap::new(),
                event: Some(file_id(b"new")),
                explain: false,
            },
        );
        assert_eq!(d.code, Code::InputChanged);
    }
    #[test]
    fn symlink_ancestor_is_not_assumed_absent() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        symlink("dir", f.root.join("link")).unwrap();
        assert!(Command::new("git")
            .current_dir(&f.root)
            .args(["add", "link"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .current_dir(&f.root)
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "link"
            ])
            .status()
            .unwrap()
            .success());
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link/missing", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
    }
}
