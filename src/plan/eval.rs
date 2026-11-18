//! Symbolically evaluate step proofs without executing repository code.
use super::spec::{Code, Decision, Evidence, JobSpec, RecordCheck, StepSpec};
use crate::gittree::{Entry, GitTree};
use crate::job::{JobRecord, JobStore, RecordStatus};
use crate::proof::{Proof, Store};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct PlanCtx<'a> {
    pub tree: &'a mut GitTree,
    pub proofs: &'a Store,
    pub jobs: &'a JobStore,
    pub check: &'a dyn RecordCheck,
    pub now: u64,
    pub max_age: u64,
    /// Raw values of known GitHub variables, not their recorded hashes.
    pub github_vars: BTreeMap<String, String>,
    pub salt: Option<String>,
    pub event_path: Option<String>,
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
            && !p.contains('\u{fffd}')
            && !p.chars().any(char::is_control)
            && !p.starts_with('/')
            && p.split('/').all(|s| !s.is_empty() && s != "." && s != ".."))
}

#[derive(Clone)]
enum Identity {
    Object(String, bool),
    Recorded(String),
}

#[derive(Clone)]
enum State {
    Absent,
    Dir,
    File(Identity),
    Link(Identity),
}

struct VirtualTree<'a> {
    tree: &'a mut GitTree,
    overlay: BTreeMap<String, Option<String>>,
    erased: BTreeSet<String>,
}
impl VirtualTree<'_> {
    fn erased_at(&self, path: &str) -> bool {
        self.erased.contains(path)
            || path
                .match_indices('/')
                .any(|(i, _)| self.erased.contains(&path[..i]))
    }
    fn remove_descendants(&mut self, path: &str) {
        let prefix = format!("{path}/");
        let keys: Vec<_> = self
            .overlay
            .range(prefix.clone()..)
            .take_while(|(key, _)| key.starts_with(&prefix))
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.overlay.remove(&key);
        }
    }
    fn overlay_affects(&self, path: &str) -> bool {
        self.overlay.contains_key(path)
            || path
                .match_indices('/')
                .any(|(i, _)| self.overlay.contains_key(&path[..i]))
            || {
                let prefix = format!("{path}/");
                self.overlay
                    .range(prefix.clone()..)
                    .next()
                    .is_some_and(|(p, _)| p.starts_with(&prefix))
            }
    }
    fn direct(&mut self, p: &str, hidden: bool) -> Result<State, String> {
        if let Some(value) = self.overlay.get(p) {
            return match value {
                None => Ok(State::Absent),
                Some(id) if id == "d" || id.starts_with("dl:") => Ok(State::Dir),
                Some(id) if id.starts_with("f:") || id.starts_with("x:") => {
                    Ok(State::File(Identity::Recorded(id.clone())))
                }
                Some(id) if id.starts_with("l:") => Ok(State::Link(Identity::Recorded(id.clone()))),
                _ => Err(format!("invalid output identity for {p}")),
            };
        }
        if hidden || self.erased_at(p) {
            return Ok(State::Absent);
        }
        if p == "." || p == ".git" {
            return Ok(State::Dir);
        }
        match self.tree.entry(p).cloned() {
            Some(Entry::Tree | Entry::Gitlink) => Ok(State::Dir),
            Some(Entry::Blob { oid, exec, .. }) => Ok(State::File(Identity::Object(oid, exec))),
            Some(Entry::Link { oid }) => Ok(State::Link(Identity::Object(oid, false))),
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
        if p.split('/').any(|part| part == ".git") {
            return Err("git metadata is not represented by the commit tree".into());
        }
        let state = self.state(p)?;
        match state {
            State::Absent => Ok("a".into()),
            State::File(Identity::Recorded(id)) | State::Link(Identity::Recorded(id)) => Ok(id),
            State::File(Identity::Object(oid, exec))
                if expected.starts_with("f:") || expected.starts_with("x:") =>
            {
                if let Some(reason) = self
                    .tree
                    .conversion(p)
                    .map_err(|e| format!("git: {}", e.0))?
                {
                    return Err(format!("conversion: checkout converts {p} ({reason})"));
                }
                self.tree
                    .file_id(&oid, exec)
                    .map_err(|e| format!("git: {}", e.0))
            }
            State::File(Identity::Object(_, exec)) => Ok(if exec { "xk" } else { "fk" }.into()),
            State::Link(Identity::Object(oid, _)) => Ok(format!(
                "l:{}",
                self.tree
                    .link_target(&oid)
                    .map_err(|e| format!("git: {}", e.0))?
            )),
            State::Dir if expected.starts_with("dl:") => {
                let prefix = if p == "." {
                    Vec::new()
                } else {
                    format!("{p}/").into_bytes()
                };
                let mut names = self.tree.child_names_raw(if p == "." { "" } else { p });
                let overlay_prefix = String::from_utf8(prefix.clone()).expect("UTF-8 path");
                for (path, _) in self
                    .overlay
                    .range(overlay_prefix.clone()..)
                    .take_while(|(path, _)| path.starts_with(&overlay_prefix))
                {
                    let rest = &path.as_bytes()[prefix.len()..];
                    if let Some(name) = rest.split(|b| *b == b'/').next().filter(|s| !s.is_empty())
                    {
                        names.insert(name.to_vec());
                    }
                }
                if p == "." {
                    names.insert(b".git".to_vec());
                }
                let mut hash = blake3::Hasher::new();
                for name in names {
                    let mut child = prefix.clone();
                    child.extend_from_slice(&name);
                    let present = match std::str::from_utf8(&child) {
                        Ok(child) => !matches!(self.state(child)?, State::Absent),
                        Err(_) => !self.erased_at(p),
                    };
                    if present {
                        hash.update(&(name.len() as u64).to_le_bytes());
                        hash.update(&name);
                    }
                }
                Ok(format!("dl:{}", hash.finalize().to_hex()))
            }
            State::Dir => Ok("d".into()),
        }
    }
}

fn known_github(name: &str) -> bool {
    name == "GITHUB_JOB" || crate::gha::context::VERIFIED_VARS.contains(&name)
}

/// Recorder semantics older than this floor may produce unsound plan proofs.
/// When recorder changes make earlier proofs unsound, bump this floor and
/// `TRACER_VERSION` together. This is not the planner runner's runtime version.
const MIN_PLANNABLE_RECORDER_VERSION: u32 = 4;

/// Resolve only runner labels whose platform is known without executing the job.
fn declared_platform(runs_on: &serde_json::Value) -> Option<(&'static str, &'static str)> {
    let label = runs_on.as_str().or_else(|| {
        let labels = runs_on.as_array()?;
        (labels.len() == 1).then(|| labels[0].as_str()).flatten()
    })?;
    match label {
        "ubuntu-latest" | "ubuntu-22.04" | "ubuntu-24.04" | "ubuntu-26.04" => {
            Some(("linux", "x86_64"))
        }
        "ubuntu-latest-arm" | "ubuntu-22.04-arm" | "ubuntu-24.04-arm" | "ubuntu-26.04-arm" => {
            Some(("linux", "aarch64"))
        }
        "macos-latest" | "macos-13" | "macos-14" | "macos-15" | "macos-26" => Some(("macos", "")),
        "windows-latest" | "windows-2022" | "windows-2025" => Some(("windows", "")),
        _ => None,
    }
}

fn proof_platform(proof: &Proof, spec: &JobSpec, record: &JobRecord) -> Result<(), &'static str> {
    let p = proof.provenance.as_ref().ok_or("proof lacks provenance")?;
    if p.version < MIN_PLANNABLE_RECORDER_VERSION {
        return Err("recorder too old: re-record");
    }
    if p.os != "linux"
        || p.tracer != "ptrace-seccomp"
        || !matches!(p.arch.as_str(), "x86_64" | "aarch64")
    {
        return Err("proof uses an unsupported platform or tracer");
    }
    if let Some((os, arch)) = declared_platform(&spec.runs_on) {
        if p.os != os || p.arch != arch {
            return Err("proof platform differs from declared runner");
        }
        return Ok(());
    }
    let os = record
        .host
        .get("os")
        .or_else(|| record.host.get("RUNNER_OS"));
    let arch = record
        .host
        .get("arch")
        .or_else(|| record.host.get("RUNNER_ARCH"));
    let matches_os = os.is_some_and(|value| value.eq_ignore_ascii_case(&p.os));
    let matches_arch = arch.is_some_and(|value| {
        value.eq_ignore_ascii_case(&p.arch)
            || (p.arch == "x86_64" && value.eq_ignore_ascii_case("X64"))
            || (p.arch == "aarch64" && value.eq_ignore_ascii_case("ARM64"))
    });
    if !matches_os || !matches_arch {
        return Err("proof platform differs from recorded runner or runner platform is unknown");
    }
    Ok(())
}

fn sort_records(records: &mut [JobRecord]) {
    records.sort_by(|a, b| b.retention_key().cmp(&a.retention_key()));
}

pub fn decide(spec: &JobSpec, ctx: &mut PlanCtx<'_>) -> Decision {
    if let Some(blocked) = &spec.blocked {
        return decision(Code::Blocked, blocked.detail.clone());
    }
    let Some(key) = &spec.key else {
        return decision(Code::Blocked, "job has no key".into());
    };
    let mut records = ctx.jobs.load(key);
    sort_records(&mut records);
    if records.is_empty() {
        return decision(Code::NoRecord, "no job record".into());
    }
    let mut newest = None;
    for record in &records {
        if record.started == 0 {
            if ctx.explain {
                eprintln!(
                    "stoop: record {}: legacy record has no start time",
                    super::output::escape(record.run.as_deref().unwrap_or("unknown"))
                );
            }
            if newest.is_none() {
                newest = Some(decision(
                    Code::Incomplete,
                    "legacy record has no start time".into(),
                ));
            }
            continue;
        }
        let result = match record.status {
            Some(RecordStatus::Failed) => {
                if ctx.explain {
                    eprintln!(
                        "stoop: record {}: failed at step {}; earlier records no longer count",
                        super::output::escape(record.run.as_deref().unwrap_or("unknown")),
                        super::output::escape(record.failed.as_deref().unwrap_or("unknown"))
                    );
                }
                return decision(
                    Code::Stale,
                    format!(
                        "run {} failed at step {}; earlier records no longer count",
                        record.run.as_deref().unwrap_or("unknown"),
                        record.failed.as_deref().unwrap_or("unknown")
                    ),
                );
            }
            Some(RecordStatus::Passed) => {
                let result = evaluate(spec, ctx, record);
                if result.skip {
                    match ctx.check.check(spec, record) {
                        Ok(()) => result,
                        Err((code, reason)) => {
                            decision(code, format!("{reason}; the record would otherwise prove"))
                        }
                    }
                } else {
                    result
                }
            }
            _ => decision(Code::Incomplete, "record has not passed".into()),
        };
        if ctx.explain && !result.skip {
            eprintln!(
                "stoop: record {}: {}",
                super::output::escape(record.run.as_deref().unwrap_or("unknown")),
                super::output::escape(&result.detail)
            );
            for (step, path, why) in &result.mismatches {
                eprintln!(
                    "stoop: step {step}: {}: {}",
                    super::output::escape(path),
                    super::output::escape(why)
                );
            }
        }
        if result.code == Code::Error {
            return result;
        }
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
    if record
        .event_path
        .as_deref()
        .is_none_or(|path| !Path::new(path).is_absolute())
    {
        return decision(
            Code::Incomplete,
            "record has no absolute event payload path".into(),
        );
    }
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
        let loaded = ctx.proofs.load(key);
        let has_legacy = loaded.iter().any(|p| p.provenance.is_none());
        let empty = loaded.is_empty();
        let Some(proof) = loaded.into_iter().find(|p| p.digest() == saved.proof) else {
            if (empty && ctx.proofs.export(key).is_some()) || has_legacy {
                return decision(
                    Code::ProofPlatform,
                    format!("step {index}: proof lacks provenance"),
                );
            }
            return decision(Code::ProofMissing, format!("step {index}: proof missing"));
        };
        if let Err(reason) = proof_platform(&proof, spec, record) {
            return decision(Code::ProofPlatform, format!("step {index}: {reason}"));
        }
        if proof.ignore.is_none() {
            return decision(Code::OldProof, format!("step {index}: old proof"));
        }
        if ctx.max_age == 0 {
            return decision(Code::Error, "plan maximum age must be positive".into());
        }
        let max_age = age
            .filter(|a| *a != 0)
            .unwrap_or(ctx.max_age)
            .min(ctx.max_age);
        if ctx.now.saturating_sub(proof.created) > max_age {
            return decision(Code::Expired, format!("step {index}: proof expired"));
        }
        if proof.created > ctx.now.saturating_add(300) {
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
        priors: 0,
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
            if input.path.contains('\u{fffd}')
                || input.path.chars().any(char::is_control)
                || !(input.id == "a"
                    || input.id == "d"
                    || input.id.starts_with("dl:")
                    || input.id.starts_with("l:")
                    || input.id.starts_with("f:")
                    || input.id.starts_with("x:"))
            {
                return decision(
                    Code::Unplannable,
                    format!("step {index}: unsupported input {}", input.path),
                );
            }
            evidence.inputs += 1;
            if Path::new(&input.path).is_absolute() {
                if record.event_path.as_deref() == Some(&input.path)
                    || ctx.event_path.as_deref() == Some(&input.path)
                {
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
                Ok(id) => id,
                Err(err) => {
                    return decision(
                        if err.starts_with("git:") {
                            Code::Error
                        } else {
                            Code::Unplannable
                        },
                        format!("step {index}: {}: {err}", input.path),
                    )
                }
            };
            if tree.overlay_affects(&input.path) {
                evidence.overlay += 1;
            } else if input.id.starts_with("f:") || input.id.starts_with("x:") {
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
                    spec.job.as_str()
                } else {
                    ctx.github_vars.get(name).map(String::as_str).unwrap_or("")
                };
                if &crate::run::env_hash(name, value, ctx.salt.as_deref()) != hash {
                    return decision(
                        Code::EnvChanged,
                        format!("step {index}: {name} changed or unavailable"),
                    );
                }
            } else {
                assumed_env.insert(name.clone());
            }
        }
        if let Some(reason) = proof.unplannable.first() {
            return decision(Code::Unplannable, format!("step {index}: {reason}"));
        }
        if proof.priors.is_none() && (!proof.outputs.is_empty() || !proof.removed.is_empty()) {
            let path = proof
                .outputs
                .first()
                .map(|p| p.path.as_str())
                .or_else(|| proof.removed.first().map(String::as_str))
                .unwrap();
            return decision(
                Code::Unplannable,
                format!("recorded without prior states, and it wrote {path}"),
            );
        }
        for out in &proof.outputs {
            if !valid_path(&out.path)
                || out.path == "."
                || !(out.id == "d"
                    || out.id.starts_with("f:")
                    || out.id.starts_with("x:")
                    || out.id.starts_with("l:")
                    || out.id.starts_with("dl:"))
            {
                return decision(
                    Code::Unplannable,
                    format!("step {index}: invalid output {}", out.path),
                );
            }
        }
        for path in &proof.removed {
            if !valid_path(path) || path == "." {
                return decision(
                    Code::Unplannable,
                    format!("step {index}: invalid removal {path}"),
                );
            }
        }
        if let Some(priors) = &proof.priors {
            let prior_paths: BTreeSet<&str> = priors.iter().map(|p| p.path.as_str()).collect();
            let output_paths: BTreeSet<&str> =
                proof.outputs.iter().map(|p| p.path.as_str()).collect();
            let changed_paths: BTreeSet<&str> = proof
                .outputs
                .iter()
                .map(|p| p.path.as_str())
                .chain(proof.removed.iter().map(String::as_str))
                .collect();
            for path in proof
                .outputs
                .iter()
                .map(|i| &i.path)
                .chain(proof.removed.iter())
            {
                if !prior_paths.contains(path.as_str()) {
                    return decision(
                        Code::Unplannable,
                        format!("output {path} has no prior state"),
                    );
                }
            }
            for prior in priors {
                if prior.id == "a" && changed_paths.contains(prior.path.as_str()) {
                    let parent = prior.path.rsplit_once('/').map_or(".", |(p, _)| p);
                    let parent_named = if output_paths.contains(prior.path.as_str()) {
                        output_paths.contains(parent)
                    } else {
                        prior_paths.contains(parent)
                    };
                    if !parent_named && !matches!(tree.state(parent), Ok(State::Dir)) {
                        let why = format!("parent of {} is not a directory", prior.path);
                        let mut result = decision(Code::PriorChanged, why.clone());
                        result.mismatches.push((*index, prior.path.clone(), why));
                        return result;
                    }
                }
                evidence.priors += 1;
                let actual = match tree.id(&prior.path, &prior.id) {
                    Ok(id) => id,
                    Err(err) => {
                        return decision(
                            if err.starts_with("git:") {
                                Code::Error
                            } else {
                                Code::Unplannable
                            },
                            err,
                        )
                    }
                };
                let expected = prior.id.as_str();
                let actual_kind = if actual == "a" {
                    "absent"
                } else if actual == "d" {
                    "dir"
                } else if actual.starts_with("l:") {
                    "link"
                } else {
                    "file"
                };
                let prior_kind = if expected == "a" {
                    "absent"
                } else if expected == "d" {
                    "dir"
                } else if expected.starts_with("l:") {
                    "link"
                } else if expected == "fk"
                    || expected == "xk"
                    || expected.starts_with("f:")
                    || expected.starts_with("x:")
                {
                    "file"
                } else {
                    return decision(Code::Unplannable, format!("invalid prior {}", prior.path));
                };
                let exec = |id: &str| id == "xk" || id.starts_with("x:");
                let why = if actual_kind != prior_kind {
                    Some(format!("prior {prior_kind} now {actual_kind}"))
                } else if prior_kind == "link" && actual != expected {
                    Some("prior link target changed".into())
                } else if prior_kind == "file" && exec(&actual) != exec(expected) {
                    Some("prior exec bit changed".into())
                } else if prior_kind == "file"
                    && expected != "fk"
                    && expected != "xk"
                    && actual != expected
                {
                    Some("prior content changed".into())
                } else {
                    None
                };
                if let Some(why) = why {
                    let mut result = decision(Code::PriorChanged, format!("{}: {why}", prior.path));
                    result.mismatches.push((*index, prior.path.clone(), why));
                    return result;
                }
                if expected == "d" {
                    if tree.tree.has_non_utf8_below(&prior.path) {
                        return decision(
                            Code::Unplannable,
                            format!("{} contains a non-UTF-8 entry", prior.path),
                        );
                    }
                    let prefix = format!("{}/", prior.path);
                    let mut children = tree.tree.below(&prior.path);
                    children.extend(
                        tree.overlay
                            .range(prefix.clone()..)
                            .take_while(|(p, _)| p.starts_with(&prefix))
                            .map(|(p, _)| p.clone()),
                    );
                    children.sort();
                    children.dedup();
                    for child in children {
                        match tree.state(&child) {
                            Ok(State::Absent) => continue,
                            Ok(_) => {}
                            Err(err) => return decision(Code::Unplannable, err),
                        }
                        if !prior_paths.contains(child.as_str()) {
                            let why = "entry the run never saw".to_string();
                            let mut result =
                                decision(Code::PriorChanged, format!("{child}: {why}"));
                            result.mismatches.push((*index, child, why));
                            return result;
                        }
                    }
                }
            }
        }
        for out in &proof.outputs {
            if out.id != "d" && !out.id.starts_with("dl:") {
                tree.erased.insert(out.path.clone());
                tree.remove_descendants(&out.path);
            }
            tree.overlay.insert(out.path.clone(), Some(out.id.clone()));
        }
        for path in &proof.removed {
            tree.erased.insert(path.clone());
            tree.remove_descendants(path);
            tree.overlay.insert(path.clone(), None);
        }
    }
    evidence.assumed_env = assumed_env.into_iter().collect();
    Decision {
        skip: true,
        code: Code::Proved,
        detail: "repository inputs match; outside inputs and environment are assumed".into(),
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
    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .current_dir(root)
            .env("HOME", root)
            .env("XDG_CONFIG_HOME", root.join(".git/stoop-test-home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    struct Accept;
    impl RecordCheck for Accept {
        fn check(&self, _: &JobSpec, _: &JobRecord) -> Result<(), (Code, String)> {
            Ok(())
        }
    }
    struct Trusted;
    impl RecordCheck for Trusted {
        fn check(&self, _: &JobSpec, r: &JobRecord) -> Result<(), (Code, String)> {
            if r.attest.as_deref() == Some("trusted") {
                Ok(())
            } else {
                Err((Code::Unattested, "untrusted".into()))
            }
        }
    }
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
                git(&root, args);
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
                runs_on: serde_json::json!("ubuntu-latest"),
                needs: vec![],
                if_text: None,
                steps: vec![],
                blocked: None,
                actions: vec![],
                images: vec![],
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
            let listed = Command::new("git")
                .current_dir(&self.root)
                .env("HOME", &self.root)
                .env("XDG_CONFIG_HOME", self.root.join(".git/stoop-test-home"))
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(["ls-tree", "-r", "-t", "-z", "HEAD"])
                .output()
                .unwrap();
            assert!(listed.status.success());
            let mut states: BTreeMap<String, String> = BTreeMap::new();
            for entry in listed.stdout.split(|b| *b == 0).filter(|b| !b.is_empty()) {
                let Some(tab) = entry.iter().position(|b| *b == b'\t') else {
                    continue;
                };
                let Ok(path) = std::str::from_utf8(&entry[tab + 1..]) else {
                    continue;
                };
                let id = match &entry[..6] {
                    b"040000" => "d",
                    b"100755" => "xk",
                    b"100644" => "fk",
                    _ => "l:unknown",
                };
                states.insert(path.into(), id.into());
            }
            for (index, mut proof) in proofs.into_iter().enumerate() {
                if proof.priors.as_ref().is_some_and(Vec::is_empty) {
                    let paths: Vec<String> = proof
                        .outputs
                        .iter()
                        .map(|o| o.path.clone())
                        .chain(proof.removed.iter().cloned())
                        .collect();
                    let mut priors = Vec::new();
                    for path in paths {
                        let id = states.get(&path).cloned().unwrap_or_else(|| "a".into());
                        if id == "d" {
                            let prefix = format!("{path}/");
                            for (child, child_id) in states
                                .range(prefix.clone()..)
                                .take_while(|(p, _)| p.starts_with(&prefix))
                            {
                                priors.push(input(child, child_id));
                            }
                        }
                        priors.push(input(&path, &id));
                    }
                    proof.priors = Some(priors);
                }
                for out in &proof.outputs {
                    if out.id != "d" {
                        let pre = format!("{}/", out.path);
                        states.retain(|p, _| !p.starts_with(&pre));
                    }
                    states.insert(out.path.clone(), out.id.clone());
                }
                for path in &proof.removed {
                    let pre = format!("{path}/");
                    states.retain(|p, _| p != path && !p.starts_with(&pre));
                }
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
                        started: 100,
                        status: Some(RecordStatus::Passed),
                        failed: None,
                        actions: BTreeMap::new(),
                        commit: None,
                        host: BTreeMap::new(),
                        event_path: Some("/tmp/event.json".into()),
                        run: Some("1/1".into()),
                        steps: records,
                        attest: None,
                        workflow_ref: None,
                        job_workflow_ref: None,
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
                    check: &Accept,
                    salt: None,
                    event_path: None,
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
            cwd: Some(String::new()),
            scope: None,
            provenance: Some(crate::trace::Provenance {
                os: "linux".into(),
                arch: "x86_64".into(),
                tracer: "ptrace-seccomp".into(),
                version: MIN_PLANNABLE_RECORDER_VERSION,
            }),
            env: BTreeMap::new(),
            inputs,
            outputs: vec![],
            removed: vec![],
            ignore: Some(vec![]),
            priors: Some(vec![]),
            unplannable: vec![],
            probes: BTreeMap::new(),
        }
    }

    #[test]
    fn proof_platform_is_bound_to_declared_or_recorded_job_platform() {
        let cases = [
            (
                "ubuntu-24.04-arm",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                None,
                Code::ProofPlatform,
            ),
            ("ubuntu-latest", None, None, Code::ProofPlatform),
            (
                "custom-runner",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                Some(("Linux", "X64")),
                Code::Proved,
            ),
            (
                "custom-runner",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                Some(("Linux", "ARM64")),
                Code::ProofPlatform,
            ),
            (
                "macos-latest",
                Some(("macos", "aarch64", "unsupported")),
                None,
                Code::ProofPlatform,
            ),
            (
                "custom-runner",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                None,
                Code::ProofPlatform,
            ),
            (
                "ubuntu-latest",
                Some(("linux", "x86_64", "unknown")),
                None,
                Code::ProofPlatform,
            ),
            (
                "windows-latest",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                None,
                Code::ProofPlatform,
            ),
            (
                "custom-runner",
                Some(("linux", "x86_64", "ptrace-seccomp")),
                Some(("Windows", "X64")),
                Code::ProofPlatform,
            ),
            (
                "custom-runner",
                Some(("linux", "riscv64", "ptrace-seccomp")),
                Some(("Linux", "riscv64")),
                Code::ProofPlatform,
            ),
            (
                "custom-runner",
                Some(("windows", "x86_64", "ptrace-seccomp")),
                Some(("Windows", "X64")),
                Code::ProofPlatform,
            ),
        ];
        for (label, provenance, host, expected) in cases {
            let mut f = Fixture::new();
            f.spec.runs_on = serde_json::json!(label);
            let mut p = proof(vec![]);
            p.provenance = provenance.map(|(os, arch, tracer)| crate::trace::Provenance {
                os: os.into(),
                arch: arch.into(),
                tracer: tracer.into(),
                version: MIN_PLANNABLE_RECORDER_VERSION,
            });
            f.install(vec![p]);
            if let Some((os, arch)) = host {
                let mut record = f.jobs.load("job-test").remove(0);
                record.host.insert("os".into(), os.into());
                record.host.insert("arch".into(), arch.into());
                f.jobs.save("job-test", record).unwrap();
            }
            let result = f.decide(BTreeMap::new());
            assert_eq!(result.code, expected, "{label}: {}", result.detail);
        }
    }

    #[test]
    fn older_recorder_semantics_are_not_plannable() {
        for (version, expected) in [(3, Code::ProofPlatform), (4, Code::Proved)] {
            let mut f = Fixture::new();
            let mut p = proof(vec![]);
            p.provenance.as_mut().unwrap().version = version;
            f.install(vec![p]);
            let result = f.decide(BTreeMap::new());
            assert_eq!(
                result.code, expected,
                "version {version}: {}",
                result.detail
            );
            if version == 3 {
                assert!(result.detail.contains("recorder too old: re-record"));
            }
        }
    }

    #[test]
    fn older_recorder_is_blocked_on_custom_runner_host_fallback() {
        for (version, expected) in [(3, Code::ProofPlatform), (4, Code::Proved)] {
            let mut f = Fixture::new();
            f.spec.runs_on = serde_json::json!("custom-runner");
            let mut p = proof(vec![]);
            p.provenance.as_mut().unwrap().version = version;
            f.install(vec![p]);
            let mut record = f.jobs.load("job-test").remove(0);
            record.host.insert("os".into(), "Linux".into());
            record.host.insert("arch".into(), "X64".into());
            f.jobs.save("job-test", record).unwrap();
            let result = f.decide(BTreeMap::new());
            assert_eq!(
                result.code, expected,
                "version {version}: {}",
                result.detail
            );
            if version == 3 {
                assert!(result.detail.contains("recorder too old: re-record"));
            }
        }
    }

    #[test]
    fn recorder_semantics_floor_tracks_the_production_tracer_version() {
        assert_eq!(
            MIN_PLANNABLE_RECORDER_VERSION,
            crate::trace::version::TRACER_VERSION
        );
    }

    #[test]
    fn legacy_proof_with_old_digest_reports_missing_provenance() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.provenance = None;
        f.install(vec![p.clone()]);
        let mut raw = serde_json::to_value(&p).unwrap();
        raw.as_object_mut().unwrap().remove("provenance");
        let file = serde_json::json!({"v": 1, "key": "sh-0", "proofs": [raw]});
        fs::write(
            f.root.join("store/proofs/sh-0.json"),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[0].proof = "p-old-digest".into();
        f.jobs.save("job-test", record).unwrap();
        let result = f.decide(BTreeMap::new());
        assert_eq!(result.code, Code::ProofPlatform, "{}", result.detail);
        assert!(
            result.detail.contains("proof lacks provenance"),
            "{}",
            result.detail
        );
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
        let old = proof(vec![input("dir/a", &file_id(b"old"))]);
        f.install(vec![old]);
        f.proofs
            .save("sh-0", proof(vec![input("dir/a", &file_id(b"tracked"))]))
            .unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[0].proof = "p-missing".into();
        f.jobs.save("job-test", record).unwrap();
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
        second.outputs.push(input("dir", "d"));
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
                check: &Accept,
                salt: None,
                event_path: None,
            },
        );
        assert_eq!(d.code, Code::InputChanged);
    }
    #[test]
    fn symlink_ancestor_is_not_assumed_absent() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        symlink("dir", f.root.join("link")).unwrap();
        git(&f.root, &["add", "link"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "link",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link/missing", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn incomplete_step_count_key_and_empty_are_rejected() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        f.spec.steps.push(StepSpec::Traced {
            index: 2,
            key: "sh-1".into(),
            max_age: None,
        });
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
        f.spec.steps.pop();
        f.spec.steps[0] = StepSpec::Traced {
            index: 1,
            key: "other".into(),
            max_age: None,
        };
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
        f.spec.steps.clear();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps.clear();
        f.jobs.save("job-test", record).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
    }
    #[test]
    fn step_max_age_and_future_are_rejected() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        f.spec.steps[0] = StepSpec::Traced {
            index: 1,
            key: "sh-0".into(),
            max_age: Some(5),
        };
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
        let mut p = proof(vec![input("x", "a")]);
        p.created = 401;
        f.proofs.save("sh-0", p.clone()).unwrap();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[0].proof = p.digest();
        f.jobs.save("job-test", record).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
    }
    #[test]
    fn git_metadata_runs_and_github_job_is_pinned() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input(".git/config", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        replace_first(&mut f, proof(vec![input("dir/.git/config", "a")]));
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        let mut p = proof(vec![]);
        p.env.insert(
            "GITHUB_JOB".into(),
            blake3::hash(b"plan").to_hex().to_string(),
        );
        p.env.insert(
            "GITHUB_REF".into(),
            blake3::hash(b"main").to_hex().to_string(),
        );
        f.proofs.save("sh-0", p.clone()).unwrap();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[0].proof = p.digest();
        f.jobs.save("job-test", record).unwrap();
        let vars = BTreeMap::from([
            ("GITHUB_JOB".into(), "plan".into()),
            ("GITHUB_REF".into(), "main".into()),
        ]);
        assert_eq!(f.decide(vars.clone()).code, Code::EnvChanged);
        p.env.insert(
            "GITHUB_JOB".into(),
            blake3::hash(b"test").to_hex().to_string(),
        );
        f.proofs.save("sh-0", p.clone()).unwrap();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[0].proof = p.digest();
        f.jobs.save("job-test", record).unwrap();
        assert_eq!(f.decide(vars).code, Code::Proved);
    }
    #[test]
    fn missing_event_path_is_incomplete_and_matching_event_passes() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input(
            "/tmp/event.json",
            &file_id(b"event"),
        )])]);
        let mut record = f.jobs.load("job-test").remove(0);
        record.event_path = None;
        f.jobs.save("job-test", record.clone()).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
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
                event: Some(file_id(b"event")),
                explain: false,
                check: &Accept,
                salt: None,
                event_path: None,
            },
        );
        assert_eq!(d.code, Code::Proved);
    }
    #[test]
    fn trust_defaults_to_reject_and_older_trusted_record_can_pass() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut record = f.jobs.load("job-test").remove(0);
        record.attest = Some("trusted".into());
        f.jobs.save("job-test", record.clone()).unwrap();
        record.created = 101;
        record.run = Some("2/1".into());
        record.attest = None;
        f.jobs.save("job-test", record).unwrap();
        let mut ctx = PlanCtx {
            tree: &mut f.tree,
            proofs: &f.proofs,
            jobs: &f.jobs,
            now: 100,
            max_age: 50,
            github_vars: BTreeMap::new(),
            event: None,
            explain: false,
            check: &super::super::spec::Unverified,
            salt: None,
            event_path: None,
        };
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::Unattested);
        ctx.check = &Trusted;
        assert_eq!(
            decide(&f.spec, &mut ctx).evidence.unwrap().run.as_deref(),
            Some("1/1")
        );
        f.spec.blocked = Some(super::super::spec::Blocker {
            step: None,
            detail: "blocked".into(),
        });
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::Blocked);
    }
    #[test]
    fn removal_discards_prior_overlay_children() {
        let mut f = Fixture::new();
        let mut a = proof(vec![]);
        a.outputs = vec![input("gen", "d"), input("gen/x", &file_id(b"x"))];
        let mut b = proof(vec![]);
        b.removed.push("gen".into());
        b.priors = Some(vec![input("gen", "d"), input("gen/x", "fk")]);
        f.install(vec![a, b, proof(vec![input("gen/x", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn tree_requires_repository_root_and_commit() {
        let f = Fixture::new();
        assert!(GitTree::load(&f.root.join("dir"), "HEAD").is_err());
        assert!(GitTree::load(&f.root, "HEAD:dir").is_err());
    }
    #[test]
    fn partial_clone_listing_does_not_read_blobs() {
        let mut f = Fixture::new();
        git(&f.root, &["config", "remote.origin.promisor", "true"]);
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let id = crate::input::identify(&f.root.join("dir"), true, true).unwrap();
        f.install(vec![proof(vec![input("dir", &id)])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Proved);
        assert_eq!(f.tree.blob_reads(), 0);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_preserve_listing_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let mut f = Fixture::new();
        let name = std::ffi::OsString::from_vec(vec![b'z', 255]);
        fs::write(f.root.join("dir").join(name), b"x").unwrap();
        git(&f.root, &["add", "dir"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "raw",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let id = crate::input::identify(&f.root.join("dir"), true, true).unwrap();
        f.install(vec![proof(vec![input("dir", &id)])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn newest_failure_is_reported() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"old"))])]);
        let mut newer = f.jobs.load("job-test").remove(0);
        newer.created = 101;
        newer.run = Some("2/1".into());
        newer.steps[0].proof = "missing".into();
        f.jobs.save("job-test", newer).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::ProofMissing);
    }
    #[test]
    fn implicit_overlay_directory_exists() {
        let mut f = Fixture::new();
        let mut virtual_tree = VirtualTree {
            tree: &mut f.tree,
            overlay: BTreeMap::from([("gen/x".into(), Some(file_id(b"x")))]),
            erased: BTreeSet::new(),
        };
        assert!(matches!(virtual_tree.state("gen"), Ok(State::Dir)));
    }
    #[test]
    fn exact_age_limit_is_enforced() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        f.spec.steps[0] = StepSpec::Traced {
            index: 1,
            key: "sh-0".into(),
            max_age: Some(9),
        };
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
    }
    #[test]
    fn replaced_directory_cannot_resurrect_children() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.outputs.push(input("dir", &file_id(b"file")));
        let mut second = proof(vec![]);
        second.outputs.push(input("dir", "d"));
        f.install(vec![first, second, proof(vec![input("dir/a", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn malformed_output_path_is_rejected() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.outputs.push(input("../escape", &file_id(b"x")));
        f.install(vec![first]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    fn replace_first(f: &mut Fixture, p: Proof) {
        f.proofs.save("sh-0", p.clone()).unwrap();
        let mut r = f.jobs.load("job-test").remove(0);
        r.steps[0].proof = p.digest();
        f.jobs.save("job-test", r).unwrap();
    }
    #[test]
    fn inplace_rewrite_checks_its_prior() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.outputs.push(input("dir/a", &file_id(b"new")));
        p.priors = Some(vec![input("dir/a", &file_id(b"old"))]);
        f.install(vec![p.clone()]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::PriorChanged);
        assert_eq!(
            d.mismatches[0],
            (1, "dir/a".into(), "prior content changed".into())
        );
        p.priors = Some(vec![input("dir/a", &file_id(b"tracked"))]);
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn mkdir_needs_the_path_absent_and_prior_coverage() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.outputs.push(input("dir", "d"));
        p.priors = Some(vec![input("dir", "a")]);
        f.install(vec![p.clone()]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
        p.priors = Some(vec![input("dir", "d")]);
        replace_first(&mut f, p.clone());
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::PriorChanged);
        assert_eq!(d.mismatches[0].2, "entry the run never saw");
        p.priors = Some(vec![input("dir", "d"), input("dir/a", "fk")]);
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn interim_rules_and_unplannable_reason() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.priors = None;
        f.install(vec![p.clone()]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        p.outputs.push(input("new", &file_id(b"x")));
        replace_first(&mut f, p.clone());
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        p.priors = Some(vec![]);
        replace_first(&mut f, p.clone());
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        p.unplannable.push("renamed the directory x to y".into());
        replace_first(&mut f, p);
        assert!(f
            .decide(BTreeMap::new())
            .detail
            .contains("renamed the directory"));
    }
    #[test]
    fn record_status_orders_and_retires() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut r = f.jobs.load("job-test").remove(0);
        r.started = 101;
        r.created = 101;
        r.run = Some("2/1".into());
        r.status = Some(RecordStatus::Failed);
        r.failed = Some("sh-0".into());
        f.jobs.save("job-test", r.clone()).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Stale);
        r.status = Some(RecordStatus::Running);
        f.jobs.save("job-test", r.clone()).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        r.status = None;
        f.jobs.save("job-test", r.clone()).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        r.status = Some(RecordStatus::Passed);
        f.jobs.save("job-test", r).unwrap();
        assert_eq!(
            f.decide(BTreeMap::new()).evidence.unwrap().run.as_deref(),
            Some("2/1")
        );
    }
    #[test]
    fn age_ceiling_and_clock_skew() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.created = 49;
        f.install(vec![p.clone()]);
        for age in [Some(0), Some(500)] {
            f.spec.steps[0] = StepSpec::Traced {
                index: 1,
                key: "sh-0".into(),
                max_age: age,
            };
            assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
        }
        p.created = 400;
        replace_first(&mut f, p.clone());
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        p.created = 401;
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Expired);
    }
    #[test]
    fn plan_event_path_and_salted_environment() {
        let mut f = Fixture::new();
        let mut p = proof(vec![input("/tmp/plan-event", &file_id(b"event"))]);
        p.env.insert(
            "GITHUB_REF".into(),
            crate::run::env_hash("GITHUB_REF", "", Some("salt")),
        );
        f.install(vec![p]);
        let mut ctx = PlanCtx {
            tree: &mut f.tree,
            proofs: &f.proofs,
            jobs: &f.jobs,
            check: &Accept,
            now: 100,
            max_age: 50,
            github_vars: BTreeMap::new(),
            salt: Some("salt".into()),
            event_path: Some("/tmp/plan-event".into()),
            event: Some(file_id(b"bad")),
            explain: false,
        };
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::InputChanged);
        ctx.event = Some(file_id(b"event"));
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::Proved);
        ctx.salt = None;
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::EnvChanged);
    }
    #[test]
    fn exec_bit_is_part_of_the_id() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        let hash = blake3::hash(b"tracked").to_hex().to_string();
        let mut p = proof(vec![input("dir/a", &crate::input::file_id(true, &hash))]);
        f.install(vec![p.clone()]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
        fs::set_permissions(f.root.join("dir/a"), fs::Permissions::from_mode(0o755)).unwrap();
        git(&f.root, &["add", "dir/a"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "mode",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        p.inputs[0].id = crate::input::file_id(false, &hash);
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
    }
    #[test]
    fn checkout_conversion_attributes_are_checked_at_commit() {
        for (attribute, blocked) in [
            ("text eol=crlf", true),
            ("ident", true),
            ("filter=lfs", true),
            ("working-tree-encoding=UTF-16", true),
            ("text=auto", false),
            ("eol=lf", false),
        ] {
            let mut f = Fixture::new();
            fs::write(
                f.root.join(".gitattributes"),
                format!("dir/a {attribute}\n"),
            )
            .unwrap();
            git(&f.root, &["add", ".gitattributes"]);
            git(
                &f.root,
                &[
                    "-c",
                    "user.name=test",
                    "-c",
                    "user.email=test@example.com",
                    "commit",
                    "-qm",
                    "attributes",
                ],
            );
            f.tree = GitTree::load(&f.root, "HEAD").unwrap();
            f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
            let d = f.decide(BTreeMap::new());
            assert_eq!(
                d.code,
                if blocked {
                    Code::Unplannable
                } else {
                    Code::Proved
                },
                "{attribute}: {}",
                d.detail
            );
        }
    }
    #[test]
    fn same_blob_is_read_once_and_missing_blob_is_error() {
        let mut f = Fixture::new();
        fs::write(f.root.join("dir/b"), b"tracked").unwrap();
        git(&f.root, &["add", "dir/b"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "same",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![
            input("dir/a", &file_id(b"tracked")),
            input("dir/b", &file_id(b"tracked")),
        ])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        assert_eq!(f.tree.blob_reads(), 1);
        let Entry::Blob { oid, .. } = f.tree.entry("dir/a").unwrap().clone() else {
            panic!("blob expected")
        };
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        fs::remove_file(f.root.join(".git/objects").join(&oid[..2]).join(&oid[2..])).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Error);
    }
    #[test]
    fn prior_mismatch_words() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        symlink("dir/a", f.root.join("link")).unwrap();
        git(&f.root, &["add", "link"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "link",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.outputs.push(input("dir/a", &file_id(b"new")));
        p.priors = Some(vec![input("dir/a", "a")]);
        f.install(vec![p.clone()]);
        for (path, expected, why) in [
            ("dir/a", "a", "prior absent now file"),
            ("missing", "fk", "prior file now absent"),
            ("dir", "fk", "prior file now dir"),
            ("dir/a", "d", "prior dir now file"),
            ("dir/a", "xk", "prior exec bit changed"),
            ("dir/a", "f:wrong", "prior content changed"),
            ("link", "l:other", "prior link target changed"),
        ] {
            p.outputs = vec![input(path, &file_id(b"new"))];
            p.priors = Some(vec![input(path, expected)]);
            replace_first(&mut f, p.clone());
            let d = f.decide(BTreeMap::new());
            assert_eq!(d.code, Code::PriorChanged);
            assert_eq!(d.mismatches[0].2, why);
        }
    }
    #[test]
    fn status_less_and_running_only_are_incomplete() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut r = f.jobs.load("job-test").remove(0);
        for status in [None, Some(RecordStatus::Running)] {
            r.status = status;
            f.jobs.save("job-test", r.clone()).unwrap();
            assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
        }
    }
    #[test]
    fn many_name_listing_matches_runtime_without_blob_reads() {
        let mut f = Fixture::new();
        for n in 0..2000 {
            fs::write(f.root.join("dir").join(format!("f{n:04}")), b"data").unwrap();
        }
        git(&f.root, &["add", "dir"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "listing",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let id = crate::input::identify(&f.root.join("dir"), true, true).unwrap();
        f.install(vec![proof(vec![input("dir", &id)])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        assert_eq!(f.tree.blob_reads(), 0);
    }
    #[test]
    fn k_m12_output_under_a_file_ancestor() {
        let mut f = Fixture::new();
        fs::write(f.root.join("build"), b"file").unwrap();
        git(&f.root, &["add", "build"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "file",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.outputs.push(input("build/out", &file_id(b"ok")));
        p.priors = Some(vec![input("build/out", "a")]);
        f.install(vec![p, proof(vec![input("build/out", &file_id(b"ok"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::PriorChanged);
        assert!(d.detail.contains("parent of build/out is not a directory"));
        let mut p = proof(vec![]);
        p.outputs.push(input("build/out", &file_id(b"ok")));
        p.priors = Some(vec![input("build/out", "a"), input("build", "fk")]);
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
        let mut virtual_tree = VirtualTree {
            tree: &mut f.tree,
            overlay: BTreeMap::from([("build/out".into(), Some(file_id(b"ok")))]),
            erased: BTreeSet::new(),
        };
        assert!(matches!(virtual_tree.state("build/out"), Ok(State::Absent)));
    }
    #[test]
    fn k_n06_order_is_by_start_and_equal_failure_wins() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut passed = f.jobs.load("job-test").remove(0);
        passed.started = 100;
        passed.created = 500;
        f.jobs.save("job-test", passed.clone()).unwrap();
        let mut failed = passed;
        failed.started = 101;
        failed.created = 200;
        failed.run = Some("2/1".into());
        failed.status = Some(RecordStatus::Failed);
        f.jobs.save("job-test", failed.clone()).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Stale);
        failed.started = 100;
        f.jobs.save("job-test", failed).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Stale);
    }
    #[test]
    fn a_passing_run_after_the_failure_proves() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut failed = f.jobs.load("job-test").remove(0);
        failed.started = 90;
        failed.run = Some("2/1".into());
        failed.status = Some(RecordStatus::Failed);
        f.jobs.save("job-test", failed).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn k_n10_missing_plan_payload_mismatches() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("/tmp/event.json", &file_id(b"{}"))])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
    }
    #[test]
    fn k_n15_interim_refuses_removals() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut p = proof(vec![]);
        p.removed.push("dir/a".into());
        p.priors = None;
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn k_n17_removal_needs_a_prior() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut p = proof(vec![]);
        p.removed.push("dir/a".into());
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn k_n24_removed_dir_with_unnamed_overlay_entry() {
        let mut f = Fixture::new();
        let mut a = proof(vec![]);
        a.outputs.push(input("dir/new", &file_id(b"x")));
        a.priors = Some(vec![input("dir/new", "a")]);
        let mut b = proof(vec![]);
        b.removed = vec!["dir/a".into(), "dir".into()];
        b.priors = Some(vec![input("dir", "d"), input("dir/a", "fk")]);
        f.install(vec![a, b]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
    }
    #[test]
    fn k_n26_non_utf8_below_removed_dir() {
        use std::os::unix::ffi::OsStringExt;
        let mut f = Fixture::new();
        let oid = Command::new("git")
            .current_dir(&f.root)
            .env("HOME", &f.root)
            .env("XDG_CONFIG_HOME", f.root.join(".git/stoop-test-home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["hash-object", "-w", "dir/a"])
            .output()
            .unwrap();
        assert!(oid.status.success());
        let mut cache = b"100644,".to_vec();
        cache.extend_from_slice(oid.stdout.trim_ascii());
        cache.extend_from_slice(b",dir/z\xff");
        let output = Command::new("git")
            .current_dir(&f.root)
            .env("HOME", &f.root)
            .env("XDG_CONFIG_HOME", f.root.join(".git/stoop-test-home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["update-index", "--add", "--cacheinfo"])
            .arg(std::ffi::OsString::from_vec(cache))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "raw",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.removed.push("dir".into());
        p.priors = Some(vec![input("dir", "d"), input("dir/a", "fk")]);
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn k_n30_kind_only_prior_keeps_the_exec_bit() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        fs::set_permissions(f.root.join("dir/a"), fs::Permissions::from_mode(0o755)).unwrap();
        git(&f.root, &["add", "dir/a"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "mode",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.outputs.push(input("dir/a", &file_id(b"new")));
        p.priors = Some(vec![input("dir/a", "fk")]);
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
    }
    #[test]
    fn k_g05_large_attributes_file() {
        let mut f = Fixture::new();
        let mut attrs = vec![b'#'; 1024 * 1024 + 1];
        attrs.extend_from_slice(b"\n*.sh text eol=crlf\n");
        fs::write(f.root.join(".gitattributes"), attrs).unwrap();
        fs::write(f.root.join("test.sh"), b"echo ok\n").unwrap();
        git(&f.root, &["add", ".gitattributes", "test.sh"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "attrs",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("test.sh", &file_id(b"echo ok\n"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Unplannable);
        assert!(d.detail.contains("eol=crlf"));
    }
    #[test]
    fn k_m02c_step_age_zero_is_the_ceiling() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        f.spec.steps[0] = StepSpec::Traced {
            index: 1,
            key: "sh-0".into(),
            max_age: Some(0),
        };
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn k_m23_root_listing_has_git() {
        let mut f = Fixture::new();
        let id = crate::input::identify(&f.root, true, true).unwrap();
        f.install(vec![proof(vec![input(".", &id)])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn k_m30_unreadable_input_is_unplannable() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", "u")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn parent_deleted_after_recording_cannot_prove() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.outputs.push(input("build/out", &file_id(b"ok")));
        p.priors = Some(vec![input("build/out", "a")]);
        f.install(vec![p, proof(vec![input("build/out", &file_id(b"ok"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::PriorChanged);
        assert!(d.detail.contains("parent of build/out is not a directory"));
    }
    #[test]
    fn attributes_use_runner_macro_and_case_sensitive_patterns() {
        let mut f = Fixture::new();
        fs::write(
            f.root.join(".git/info/attributes"),
            b"[attr]winscript text eol=crlf\n",
        )
        .unwrap();
        fs::write(f.root.join(".gitattributes"), b"dir/a winscript\n").unwrap();
        git(&f.root, &["add", ".gitattributes"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "attrs",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Unplannable);
        assert!(d.detail.contains("eol=crlf"));
        fs::write(f.root.join(".git/info/attributes"), b"").unwrap();
        fs::write(
            f.root.join(".gitattributes"),
            b"dir/a text eol=crlf\ndir/A !eol\n",
        )
        .unwrap();
        git(&f.root, &["config", "core.ignorecase", "true"]);
        git(&f.root, &["add", ".gitattributes"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "case",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Unplannable);
        assert!(d.detail.contains("eol=crlf"));
    }
    #[test]
    fn invalid_input_identifiers_and_lossy_keys_are_rejected() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        for (path, id) in [
            ("dir/a", "file"),
            ("dir/\u{fffd}", "a"),
            ("/outside", "unknown"),
        ] {
            replace_first(&mut f, proof(vec![input(path, id)]));
            assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        }
    }
    #[test]
    fn unverified_detail_reports_would_otherwise_prove() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut ctx = PlanCtx {
            tree: &mut f.tree,
            proofs: &f.proofs,
            jobs: &f.jobs,
            check: &super::super::spec::Unverified,
            now: 100,
            max_age: 50,
            github_vars: BTreeMap::new(),
            salt: None,
            event_path: None,
            event: None,
            explain: false,
        };
        let d = decide(&f.spec, &mut ctx);
        assert_eq!(d.code, Code::Unattested);
        assert!(d.detail.contains("would otherwise prove"));
        ctx.max_age = 0;
        assert_eq!(decide(&f.spec, &mut ctx).code, Code::Error);
    }
    #[test]
    fn ten_thousand_outputs_and_removals_are_linear() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut p = proof(vec![]);
        for i in 0..5000 {
            let out = format!("out-{i:05}");
            let removed = format!("removed-{i:05}");
            p.outputs.push(input(&out, &file_id(b"x")));
            p.removed.push(removed.clone());
            p.priors
                .as_mut()
                .unwrap()
                .extend([input(&out, "a"), input(&removed, "a")]);
        }
        replace_first(&mut f, p);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn git_error_does_not_fall_through_to_older_record() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut newer = f.jobs.load("job-test").remove(0);
        let p = proof(vec![input("dir/a", &file_id(b"tracked"))]);
        f.proofs.save("sh-0", p.clone()).unwrap();
        newer.started = 101;
        newer.created = 101;
        newer.run = Some("2/1".into());
        newer.steps[0].proof = p.digest();
        f.jobs.save("job-test", newer).unwrap();
        let Entry::Blob { oid, .. } = f.tree.entry("dir/a").unwrap().clone() else {
            panic!("missing blob")
        };
        fs::remove_file(f.root.join(".git/objects").join(&oid[..2]).join(&oid[2..])).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Error);
    }
    #[test]
    fn nonregular_attributes_are_unplannable() {
        use std::os::unix::fs::symlink;
        let mut f = Fixture::new();
        symlink("dir/a", f.root.join(".gitattributes")).unwrap();
        git(&f.root, &["add", ".gitattributes"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "attrs",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Unplannable);
        assert!(d.detail.contains("not a regular file"));
    }
    #[test]
    fn k3_n06c_equal_started_failed_lower_run_id() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut passed = f.jobs.load("job-test").remove(0);
        passed.started = 100;
        passed.run = Some("5/1".into());
        f.jobs.save("job-test", passed.clone()).unwrap();
        let mut failed = passed;
        failed.run = Some("3/1".into());
        failed.status = Some(RecordStatus::Failed);
        f.jobs.save("job-test", failed).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Stale);
    }
    #[test]
    fn k3_p04_removed_temp_file_parent() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.removed.push("tmp/scratch".into());
        p.priors = Some(vec![input("tmp/scratch", "a")]);
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
    }
    #[test]
    fn k3_e02_legacy_record_never_proves() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let mut record = f.jobs.load("job-test").remove(0);
        record.started = 0;
        f.jobs.save("job-test", record).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Incomplete);
    }
    #[test]
    fn k3_i03_lossy_prior_and_output_keys() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.outputs.push(input("x\u{fffd}", &file_id(b"x")));
        p.priors = Some(vec![input("x\u{fffd}", "a")]);
        f.install(vec![p]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
    }
    #[test]
    fn k3_o02_invalid_output_id() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        for id in ["u", "a", "fk"] {
            let mut p = proof(vec![]);
            p.outputs.push(input("out", id));
            p.priors = Some(vec![input("out", "a")]);
            replace_first(&mut f, p);
            assert_eq!(f.decide(BTreeMap::new()).code, Code::Unplannable);
        }
    }
    #[test]
    fn k3_pf3_sibling_prefix_in_erased() {
        let mut f = Fixture::new();
        fs::write(f.root.join("a"), b"a").unwrap();
        fs::write(f.root.join("ab"), b"ab").unwrap();
        git(&f.root, &["add", "a", "ab"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "files",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.removed.push("a".into());
        p.priors = Some(vec![input("a", "fk")]);
        f.install(vec![p, proof(vec![input("ab", "a")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
    }
    #[test]
    fn k3_pf6_sibling_prefix_in_present_descendant() {
        let mut f = Fixture::new();
        let mut a = proof(vec![]);
        a.outputs.push(input("ab", &file_id(b"x")));
        a.priors = Some(vec![input("ab", "a")]);
        f.install(vec![a, proof(vec![input("a", "d")])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::InputChanged);
        fs::create_dir(f.root.join("a")).unwrap();
        fs::write(f.root.join("a/.keep"), b"").unwrap();
        git(&f.root, &["add", "a"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "add a",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
        fs::remove_dir_all(f.root.join("a")).unwrap();
        git(&f.root, &["add", "-A", "a"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "remove a",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut p = proof(vec![]);
        p.outputs.push(input("a/out", &file_id(b"o")));
        p.priors = Some(vec![input("a/out", "a")]);
        f.proofs.save("sh-1", p.clone()).unwrap();
        let mut record = f.jobs.load("job-test").remove(0);
        record.steps[1].proof = p.digest();
        f.jobs.save("job-test", record).unwrap();
        assert_eq!(f.decide(BTreeMap::new()).code, Code::PriorChanged);
    }
    #[test]
    fn k3_g15_pf5_removal_next_to_prefix_siblings() {
        let mut f = Fixture::new();
        fs::create_dir_all(f.root.join("D")).unwrap();
        fs::create_dir_all(f.root.join("D-old")).unwrap();
        fs::write(f.root.join("D/a"), b"a").unwrap();
        fs::write(f.root.join("D-old/b"), b"b").unwrap();
        git(&f.root, &["add", "D", "D-old"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "dirs",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut a = proof(vec![]);
        a.outputs.push(input("D2", &file_id(b"x")));
        a.priors = Some(vec![input("D2", "a")]);
        let mut b = proof(vec![]);
        b.removed = vec!["D/a".into(), "D".into()];
        b.priors = Some(vec![input("D", "d"), input("D/a", "fk")]);
        f.install(vec![a, b]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn k3_pf4_overlay_sibling_survives() {
        let mut f = Fixture::new();
        fs::write(f.root.join("a"), b"a").unwrap();
        git(&f.root, &["add", "a"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "file",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let mut a = proof(vec![]);
        a.outputs.push(input("ab", &file_id(b"x")));
        a.priors = Some(vec![input("ab", "a")]);
        let mut b = proof(vec![]);
        b.removed.push("a".into());
        b.priors = Some(vec![input("a", "fk")]);
        f.install(vec![a, b, proof(vec![input("ab", &file_id(b"x"))])]);
        assert_eq!(f.decide(BTreeMap::new()).code, Code::Proved);
    }
    #[test]
    fn global_attributes_macro_is_checked() {
        let mut f = Fixture::new();
        let home = f.root.join(".git/macro-home");
        let attrs = home.join(".config/git/attributes");
        fs::create_dir_all(attrs.parent().unwrap()).unwrap();
        fs::write(&attrs, b"[attr]winscript text eol=crlf\n").unwrap();
        fs::write(f.root.join(".gitattributes"), b"dir/a winscript\n").unwrap();
        git(&f.root, &["add", ".gitattributes"]);
        git(
            &f.root,
            &[
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@e",
                "commit",
                "-qm",
                "attrs",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.tree.set_test_home(home);
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        let d = f.decide(BTreeMap::new());
        assert_eq!(d.code, Code::Unplannable);
        assert!(d.detail.contains("eol=crlf"));
    }
    #[test]
    fn composite_checks_attestation_action_movement_and_signed_age() {
        use crate::attest::tests as a;
        use crate::gha::resolve::{ActionCheck, Resolver};
        use crate::plan::Composite;
        use std::cell::{Cell, RefCell};
        struct Local(RefCell<String>, Cell<usize>);
        impl Resolver for Local {
            fn commit(&self, _: &str, _: &str, _: &str) -> Result<String, String> {
                self.1.set(self.1.get() + 1);
                Ok(self.0.borrow().clone())
            }
            fn action_tree(&self, _: &str, _: &str, _: &str, _: std::time::Instant) -> Result<std::rc::Rc<crate::gha::actions::Tree>, String> {
                Ok(std::rc::Rc::new(crate::gha::actions::fixture_tree()))
            }
            fn runner_copy(&self, _: &str, _: &str, _: &str, _: std::time::Instant) -> Result<crate::gha::actions::Tree, String> {
                Ok(crate::gha::actions::fixture_tree())
            }
        }
        let mut f = Fixture::new();
        let mut p = proof(vec![input("dir/a", &file_id(b"tracked"))]);
        p.created = a::NOW;
        f.install(vec![p.clone()]);
        f.spec.steps.insert(
            0,
            StepSpec::Neutral {
                index: 1,
                what: "actions/checkout@v4".into(),
            },
        );
        f.spec.key = Some(a::JOB.into());
        f.spec.path = a::PATH.into();
        f.spec.actions = vec!["example/tool@v1".into()];
        let mut record = a::record();
        record.steps[0].key = "sh-0".into();
        record.steps[0].proof = p.digest();
        let verifier = a::verifier();
        let resolver = Local(
            RefCell::new("1111111111111111111111111111111111111111".into()),
            Cell::new(0),
        );
        record.actions = crate::gha::actions::capture(&f.spec.actions, &resolver, false).unwrap();
        resolver.1.set(0);
        let evaluate = |f: &mut Fixture, record: &JobRecord, resolver: &Local| {
            f.jobs.save(a::JOB, record.clone()).unwrap();
            let actions = ActionCheck::new(resolver);
            let check = Composite {
                verifier: &verifier,
                actions: &actions,
                proofs: &f.proofs,
                now: a::NOW,
                ceiling: a::CEILING,
            };
            decide(
                &f.spec,
                &mut PlanCtx {
                    tree: &mut f.tree,
                    proofs: &f.proofs,
                    jobs: &f.jobs,
                    check: &check,
                    now: a::NOW,
                    max_age: a::CEILING,
                    github_vars: BTreeMap::new(),
                    salt: None,
                    event_path: None,
                    event: None,
                    explain: false,
                },
            )
        };
        let d = evaluate(&mut f, &record, &resolver);
        assert_eq!(d.code, Code::Unattested);
        assert!(d.detail.contains("would otherwise prove"));
        assert_eq!(
            resolver.1.get(),
            0,
            "unattested records must not resolve actions"
        );
        record.attest = Some(a::signed(&record, |_| {}, "test-key-1", a::KEY_1));
        assert_eq!(evaluate(&mut f, &record, &resolver).code, Code::Proved);
        *resolver.0.borrow_mut() = "2222222222222222222222222222222222222222".into();
        let d = evaluate(&mut f, &record, &resolver);
        assert_eq!(d.code, Code::ActionMoved);
        assert!(d.detail.contains("would otherwise prove"));
        *resolver.0.borrow_mut() = "1111111111111111111111111111111111111111".into();
        assert_eq!(evaluate(&mut f, &record, &resolver).code, Code::Proved);
        if let StepSpec::Traced { max_age, .. } = &mut f.spec.steps[1] {
            *max_age = Some(60);
        }
        record.attest = Some(a::signed(
            &record,
            |claims| {
                claims["iat"] = serde_json::json!(a::NOW - 120);
                claims["nbf"] = serde_json::json!(a::NOW - 120);
            },
            "test-key-1",
            a::KEY_1,
        ));
        assert_eq!(evaluate(&mut f, &record, &resolver).code, Code::Expired);
        if let StepSpec::Traced { max_age, .. } = &mut f.spec.steps[1] {
            *max_age = None;
        }
        record.attest = Some(a::signed(&record, |_| {}, "test-key-1", a::KEY_1));
        let mut newer = record.clone();
        newer.run = Some("124/1".into());
        newer.started = a::NOW * 1000;
        *resolver.0.borrow_mut() = "2222222222222222222222222222222222222222".into();
        newer.actions = crate::gha::actions::capture(&f.spec.actions, &resolver, false).unwrap();
        *resolver.0.borrow_mut() = "1111111111111111111111111111111111111111".into();
        newer.attest = Some(a::signed(
            &newer,
            |claims| claims["run_id"] = serde_json::json!("124"),
            "test-key-1",
            a::KEY_1,
        ));
        f.jobs.save(a::JOB, newer).unwrap();
        let reverted = evaluate(&mut f, &record, &resolver);
        assert_eq!(reverted.code, Code::Proved);
        assert_eq!(reverted.evidence.unwrap().run.as_deref(), Some("123/1"));
        let mut failed = record.clone();
        failed.run = Some("125/1".into());
        failed.started = (a::NOW - 60) * 1000;
        failed.status = Some(RecordStatus::Failed);
        failed.failed = Some("sh-0".into());
        failed.attest = Some(a::signed(
            &failed,
            |claims| claims["run_id"] = serde_json::json!("125"),
            "test-key-1",
            a::KEY_1,
        ));
        f.jobs.save(a::JOB, failed).unwrap();
        record.started = (a::NOW + 1_000_000) * 1000;
        record.attest = Some(a::signed(
            &record,
            |claims| {
                claims["iat"] = serde_json::json!(a::NOW - 1000);
                claims["nbf"] = serde_json::json!(a::NOW - 1000);
            },
            "test-key-1",
            a::KEY_1,
        ));
        assert_eq!(evaluate(&mut f, &record, &resolver).code, Code::Stale);
    }
}
