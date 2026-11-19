//! Symbolically evaluate step proofs without executing repository code.
use super::spec::{Code, Decision, Evidence, JobSpec, RecordCheck, StepSpec};
use crate::gittree::{Entry, GitTree};
use crate::input::Input;
use crate::job::{JobRecord, JobStore, RecordStatus};
use crate::proof::{Proof, Store};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) fn steps_match<'a>(
    mut expected: impl Iterator<Item = &'a str>,
    saved: &[crate::job::StepRecord],
) -> bool {
    if saved.is_empty() {
        return false;
    }
    for step in saved {
        if expected.next() != Some(step.key.as_str()) {
            return false;
        }
    }
    expected.next().is_none()
}

/// Whether recorded git blob ids may decide a content comparison (`stoop plan --prefilter`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prefilter {
    /// Let a recorded blob id decide when every check passes; hash the rest.
    On,
    /// Hash every content comparison.
    Off,
    /// Evaluate each record both ways; any difference runs the job with an error.
    Check,
}
pub struct PlanCtx<'a> {
    pub tree: &'a mut GitTree,
    pub proofs: &'a Store,
    pub jobs: &'a JobStore,
    pub check: &'a dyn RecordCheck,
    pub now: u64,
    pub max_age: u64,
    /// Raw values of known GitHub variables, not their recorded hashes.
    pub github_vars: BTreeMap<String, String>,
    pub salt: Option<Vec<u8>>,
    pub event_path: Option<String>,
    /// Identity of the current run's event payload, if readable.
    pub event: Option<String>,
    pub explain: bool,
    /// Whether recorded git blob ids may decide content comparisons.
    pub prefilter: Prefilter,
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
    /// The id of `input.path` at rev, for comparison with the recorded `input.id`. A content
    /// comparison decides from git blob ids when `shortcut` is set and every check passes, and
    /// otherwise reads or hashes the blob, as before blob ids existed.
    fn compare(&mut self, input: &Input, shortcut: bool) -> Result<Answer, String> {
        let p = input.path.as_str();
        let expected = input.id.as_str();
        if p.split('/').any(|part| part == ".git") {
            return Err("git metadata is not represented by the commit tree".into());
        }
        let state = self.state(p)?;
        Ok(match state {
            State::Absent => Answer::plain("a".into()),
            State::File(Identity::Recorded(id)) | State::Link(Identity::Recorded(id)) => {
                Answer::plain(id)
            }
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
                match shortcut.then(|| file_by_oid(input, &oid, exec)) {
                    Some(Ok(id)) => Answer::compared(id, Content::Oid, None),
                    attempt => {
                        let id = self
                            .tree
                            .file_id(&oid, exec)
                            .map_err(|e| format!("git: {}", e.0))?;
                        Answer::compared(id, Content::Hashed, attempt.and_then(Result::err))
                    }
                }
            }
            State::File(Identity::Object(_, exec)) => {
                Answer::plain(if exec { "xk" } else { "fk" }.into())
            }
            State::Link(Identity::Object(oid, _)) if expected.starts_with("l:") => {
                match shortcut.then(|| link_by_oid(expected, &oid)) {
                    Some(Ok(id)) => Answer::compared(id, Content::Oid, None),
                    attempt => {
                        let target = self
                            .tree
                            .link_target(&oid)
                            .map_err(|e| format!("git: {}", e.0))?;
                        Answer::compared(
                            format!("l:{target}"),
                            Content::Hashed,
                            attempt.and_then(Result::err),
                        )
                    }
                }
            }
            State::Link(Identity::Object(oid, _)) => {
                let target = self
                    .tree
                    .link_target(&oid)
                    .map_err(|e| format!("git: {}", e.0))?;
                Answer::plain(format!("l:{target}"))
            }
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
                Answer::plain(format!("dl:{}", hash.finalize().to_hex()))
            }
            State::Dir => Answer::plain("d".into()),
        })
    }
}

/// Whether `s` is exactly `len` lowercase hexadecimal digits.
fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decide a file comparison from git blob ids, or name the reason the blob must be read. The
/// recorded `oid` and the tree's blob id describe the same bytes: the recorder took both from one
/// read of the file, and the tree's blob is what checkout writes once no conversion applies at
/// either end. Equal ids therefore mean the step would read the same bytes at rev.
fn file_by_oid(input: &Input, tree_oid: &str, exec: bool) -> Result<String, &'static str> {
    let oid = input.oid.as_deref().ok_or("oid-unavailable")?;
    let basis = input.oid_basis.as_ref().ok_or("oid-unavailable")?;
    if !basis.allows_oid() {
        return Err("conversion");
    }
    let recorded = oid
        .strip_prefix("sha1:")
        .filter(|hex| lower_hex(hex, 40))
        .filter(|_| lower_hex(tree_oid, 40));
    let Some(recorded) = recorded else {
        return Err("object-format");
    };
    let hash = input.id.get(2..).unwrap_or("");
    if !lower_hex(hash, 64) {
        return Err("id-malformed");
    }
    if input.id.starts_with("x:") != exec {
        return Err("mode");
    }
    if recorded == tree_oid {
        Ok(crate::input::file_id(exec, hash))
    } else {
        Ok(format!("{}:git-{tree_oid}", if exec { "x" } else { "f" }))
    }
}

/// Decide a symbolic link from its recorded target. A link's blob is its target's bytes, and
/// checkout applies no conversion to links, so the blob id follows from the target. Text that
/// the recorder decoded lossily (U+FFFD) is not those bytes, so the blob is read instead.
fn link_by_oid(recorded: &str, tree_oid: &str) -> Result<String, &'static str> {
    if !lower_hex(tree_oid, 40) {
        return Err("object-format");
    }
    let target = &recorded["l:".len()..];
    if target.contains('\u{fffd}') {
        return Err("oid-unavailable");
    }
    if crate::input::blob_oid(target.as_bytes(), false) == tree_oid {
        Ok(recorded.to_owned())
    } else {
        Ok(format!("l:\0{tree_oid}"))
    }
}

/// Count one comparison, and under `--explain` say how blob ids decided it.
fn count(
    evidence: &mut Evidence,
    notes: &mut Vec<String>,
    explain: bool,
    step: usize,
    path: &str,
    answer: &Answer,
) {
    match answer.content {
        Some(Content::Oid) => {
            evidence.by_oid += 1;
            if explain {
                notes.push(format!("step {step}: {path}: matched by blob id"));
            }
        }
        Some(Content::Hashed) => evidence.hashed += 1,
        None => {}
    }
    if let Some(reason) = answer.declined {
        *evidence.declined.entry(reason).or_default() += 1;
        if explain && reason != "oid-unavailable" {
            notes.push(format!("step {step}: {path}: blob id not used: {reason}"));
        }
    }
}

/// How a content comparison was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Content {
    /// From recorded and tree blob ids, with no blob read.
    Oid,
    /// From the blob's content hash, read or cached.
    Hashed,
}

/// One compared path's id at rev, its comparison route when it compared content, and the stable
/// reason blob ids were not used, when they were a candidate.
struct Answer {
    id: String,
    content: Option<Content>,
    declined: Option<&'static str>,
}

impl Answer {
    fn plain(id: String) -> Self {
        Self {
            id,
            content: None,
            declined: None,
        }
    }
    fn compared(id: String, content: Content, declined: Option<&'static str>) -> Self {
        Self {
            id,
            content: Some(content),
            declined,
        }
    }
}

fn known_github(name: &str) -> bool {
    name == "GITHUB_JOB" || crate::gha::context::VERIFIED_VARS.contains(&name)
}

use crate::trace::version::MIN_PLANNABLE_RECORDER_VERSION;

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
                let outcome = evaluate_record(spec, ctx, record);
                if ctx.explain {
                    explain_counts(record, &outcome);
                }
                let result = outcome.decision;
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

/// One record's evaluation: its decision, the counters behind it, and its `--explain` lines.
struct Outcome {
    decision: Decision,
    counts: Evidence,
    notes: Vec<String>,
}

/// Evaluate one record in the mode the context selects. `check` evaluates both ways and fails
/// the record when the two disagree.
fn evaluate_record(spec: &JobSpec, ctx: &mut PlanCtx<'_>, record: &JobRecord) -> Outcome {
    match ctx.prefilter {
        Prefilter::On => run(spec, ctx, record, true),
        Prefilter::Off => run(spec, ctx, record, false),
        Prefilter::Check => {
            let on = run(spec, ctx, record, true);
            let off = run(spec, ctx, record, false);
            let (a, b) = (&on.decision, &off.decision);
            if a.skip != b.skip
                || a.code != b.code
                || a.detail != b.detail
                || a.mismatches != b.mismatches
            {
                let detail = format!(
                    "object-id shortcut disagrees with hashing on record {}: {} vs {}",
                    record.run.as_deref().unwrap_or("unknown"),
                    code_name(&a.code),
                    code_name(&b.code)
                );
                return Outcome {
                    decision: decision(Code::Error, detail),
                    ..on
                };
            }
            on
        }
    }
}

/// Evaluate one record once, with or without blob ids, and count what it read.
fn run(spec: &JobSpec, ctx: &mut PlanCtx<'_>, record: &JobRecord, shortcut: bool) -> Outcome {
    let mut counts = Evidence::new(record);
    let mut notes = Vec::new();
    let before = ctx.tree.blob_reads();
    let mut result = evaluate(spec, ctx, record, shortcut, &mut counts, &mut notes);
    counts.blob_reads = ctx.tree.blob_reads() - before;
    if result.skip {
        counts.record_digest = spec
            .key
            .as_deref()
            .and_then(|key| crate::attest::digest(key, record).ok());
        counts.proofs = record.steps.iter().map(|step| step.proof.clone()).collect();
        result.evidence = Some(counts.clone());
    }
    Outcome {
        decision: result,
        counts,
        notes,
    }
}

fn code_name(code: &Code) -> String {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The `--explain` lines for one evaluated record: its counters, why blob ids were not used,
/// and each comparison they decided.
fn explain_counts(record: &JobRecord, outcome: &Outcome) {
    let c = &outcome.counts;
    let run = super::output::escape(record.run.as_deref().unwrap_or("unknown"));
    eprintln!(
        "stoop: record {run}: {} inputs, {} priors: {} by object id, {} hashed ({} blob reads), {} from earlier steps",
        c.inputs, c.priors, c.by_oid, c.hashed, c.blob_reads, c.overlay
    );
    if !c.declined.is_empty() {
        let reasons: Vec<String> = c
            .declined
            .iter()
            .map(|(reason, n)| format!("{reason} {n}"))
            .collect();
        eprintln!(
            "stoop: record {run}: blob ids not used: {}",
            reasons.join(", ")
        );
    }
    for note in &outcome.notes {
        eprintln!("stoop: {}", super::output::escape(note));
    }
}

fn evaluate(
    spec: &JobSpec,
    ctx: &mut PlanCtx<'_>,
    record: &JobRecord,
    shortcut: bool,
    evidence: &mut Evidence,
    notes: &mut Vec<String>,
) -> Decision {
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
    if !steps_match(steps.iter().map(|(_, key, _)| key.as_str()), &record.steps) {
        return decision(
            Code::Incomplete,
            "record does not match traced steps".into(),
        );
    }
    let mut proofs: Vec<Proof> = Vec::new();
    for ((index, key, age), saved) in steps.iter().zip(&record.steps) {
        let loaded = ctx.proofs.load(key);
        let has_legacy = loaded.iter().any(|p| p.provenance.is_none());
        let Some(proof) = loaded.into_iter().find(|p| p.digest() == saved.proof) else {
            if has_legacy {
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
    evidence.steps = steps.len();
    let mut assumed_env = BTreeSet::new();
    let explain = ctx.explain;
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
            let answer = match tree.compare(input, shortcut) {
                Ok(answer) => answer,
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
            } else {
                count(evidence, notes, explain, *index, &input.path, &answer);
            }
            let actual = answer.id;
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
        // The recorder left these names out, so the planner checks no value for them. A name in
        // both lists would be counted and excluded at once, which no recorder writes.
        if let Some(name) = proof
            .env_excluded
            .iter()
            .find(|name| proof.env.contains_key(*name))
        {
            return decision(
                Code::Unplannable,
                format!("step {index}: {name} is both counted and excluded in its proof"),
            );
        }
        // A learned name is excluded only while its value looks like an identifier now. The planner
        // cannot see that value, so it cannot replay the exclusion.
        if let Some(name) = proof.env_excluded.iter().find(|name| {
            crate::volatile::curated_reason(name.as_str(), &crate::volatile::all_markers())
                .is_none()
        }) {
            return decision(
                Code::Unplannable,
                format!(
                    "step {index}: {name} was learned, so the planner cannot check its exclusion"
                ),
            );
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
                let answer = match tree.compare(prior, shortcut) {
                    Ok(answer) => answer,
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
                count(evidence, notes, explain, *index, &prior.path, &answer);
                let actual = answer.id;
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
        evidence: None,
        mismatches: Vec::new(),
    }
}

#[cfg(all(test, unix))]
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
            Self::new_with(&["init", "-q"])
        }
        fn new_with(init: &[&str]) -> Self {
            let root = std::env::temp_dir().join(format!(
                "stoop-plan-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("dir")).unwrap();
            fs::write(root.join("dir/a"), b"tracked").unwrap();
            for args in [
                init,
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
                    prefilter: Prefilter::On,
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
            oid: None,
            oid_basis: None,
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
            env_excluded: vec![],
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
        let current = crate::trace::version::TRACER_VERSION;
        for (version, expected) in [(current - 1, Code::ProofPlatform), (current, Code::Proved)] {
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
            if version < current {
                assert!(result.detail.contains("recorder too old: re-record"));
            }
        }
    }

    #[test]
    fn older_recorder_is_blocked_on_custom_runner_host_fallback() {
        let current = crate::trace::version::TRACER_VERSION;
        for (version, expected) in [(current - 1, Code::ProofPlatform), (current, Code::Proved)] {
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
            if version < current {
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
    fn older_proof_files_are_missing_even_with_a_matching_digest() {
        let mut f = Fixture::new();
        let p = proof(vec![]);
        f.install(vec![p.clone()]);
        for version in [0, 1, 2, 3] {
            let file = serde_json::json!({"v": version, "key": "sh-0", "proofs": [p]});
            fs::write(
                f.root.join("store/proofs/sh-0.json"),
                serde_json::to_vec(&file).unwrap(),
            )
            .unwrap();
            let result = f.decide(BTreeMap::new());
            assert_eq!(result.code, Code::ProofMissing, "{}", result.detail);
            assert!(result.detail.contains("proof missing"), "{}", result.detail);
        }
    }

    #[test]
    fn proof_without_provenance_and_old_digest_reports_missing_provenance() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.provenance = None;
        f.install(vec![p]);
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
    fn proved_evidence_binds_record_and_proofs_in_step_order() {
        let mut f = Fixture::new();
        let mut proofs = vec![
            proof(vec![input("absent", "a")]),
            proof(vec![input("dir/a", &file_id(b"tracked"))]),
        ];
        if proofs[0].digest() < proofs[1].digest() {
            proofs.swap(0, 1);
        }
        f.install(proofs);
        let record = f.jobs.load("job-test").remove(0);
        let expected: Vec<_> = record.steps.iter().map(|step| step.proof.clone()).collect();
        assert!(
            expected[0] > expected[1],
            "fixture must distinguish step order from sorted order"
        );
        let mut decision = f.decide(BTreeMap::new());
        let evidence = decision.evidence.as_ref().unwrap();
        assert_eq!(
            evidence.record_digest.as_deref(),
            Some(crate::attest::digest("job-test", &record).unwrap().as_str())
        );
        assert_eq!(evidence.proofs, expected);
        decision.skip = false;
        decision.code = Code::InputChanged;
        let json = crate::plan::output::job("test", true, &decision, Some("job-test"));
        assert!(json["legs"][0]["record"].is_null());
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
                prefilter: Prefilter::On,
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
                prefilter: Prefilter::On,
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
            prefilter: Prefilter::On,
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
            crate::run::env_hash("GITHUB_REF", "", Some(&b"salt"[..])),
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
            salt: Some(b"salt".to_vec()),
            event_path: Some("/tmp/plan-event".into()),
            event: Some(file_id(b"bad")),
            explain: false,
            prefilter: Prefilter::On,
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
    fn the_planner_never_assumes_a_name_the_recorder_excluded() {
        let mut f = Fixture::new();
        // A name the recorder left out is not an input: the planner neither checks its value nor
        // lists it among the environment it assumes.
        let mut p = proof(vec![]);
        p.env_excluded = vec!["CI_COMMIT_SHA".into()];
        f.install(vec![p]);
        let decision = f.decide(BTreeMap::new());
        assert_eq!(decision.code, Code::Proved, "{}", decision.detail);
        let assumed = decision.evidence.unwrap().assumed_env;
        assert!(
            !assumed.contains(&"CI_COMMIT_SHA".to_string()),
            "{assumed:?}"
        );
    }
    #[test]
    fn a_name_both_counted_and_excluded_makes_the_proof_unplannable() {
        let mut f = Fixture::new();
        let mut p = proof(vec![]);
        p.env.insert("CI_COMMIT_SHA".into(), "abc".into());
        p.env_excluded = vec!["CI_COMMIT_SHA".into()];
        f.install(vec![p]);
        let decision = f.decide(BTreeMap::new());
        assert_eq!(decision.code, Code::Unplannable, "{}", decision.detail);
        assert!(
            decision.detail.contains("both counted and excluded"),
            "{}",
            decision.detail
        );
    }
    #[test]
    fn the_planner_refuses_a_proof_that_excluded_a_learned_name() {
        let mut f = Fixture::new();
        // A learned name is excluded only while its value looks like an identifier. The planner
        // cannot see that value, so it refuses to replay such an exclusion.
        let mut p = proof(vec![]);
        p.env_excluded = vec!["VOLATILE_LEARNED_NAME".into()];
        f.install(vec![p]);
        let decision = f.decide(BTreeMap::new());
        assert_eq!(decision.code, Code::Unplannable, "{}", decision.detail);
        assert!(decision.detail.contains("learned"), "{}", decision.detail);
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
            prefilter: Prefilter::On,
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
            fn action_tree(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: std::time::Instant,
            ) -> Result<std::rc::Rc<crate::gha::actions::Tree>, String> {
                Ok(std::rc::Rc::new(crate::gha::actions::fixture_tree()))
            }
            fn runner_copy(
                &self,
                _: &str,
                _: &str,
                _: &str,
                _: std::time::Instant,
            ) -> Result<crate::gha::actions::Tree, String> {
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
                    prefilter: Prefilter::On,
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
    fn clean_basis() -> crate::oid_attrs::OidBasis {
        crate::oid_attrs::OidBasis {
            text: "unspecified".into(),
            eol: "unspecified".into(),
            filter: "unspecified".into(),
            ident: "unspecified".into(),
            working_tree_encoding: "unspecified".into(),
            export_subst: "unspecified".into(),
            crlf: "unspecified".into(),
            autocrlf: "unset".into(),
        }
    }
    /// An input the recorder would write for a regular file it read once.
    fn with_oid(path: &str, id: &str, oid: &str) -> Input {
        Input {
            path: path.into(),
            id: id.into(),
            oid: Some(oid.into()),
            oid_basis: Some(clean_basis()),
        }
    }
    fn git_stdout(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(root)
            .env("HOME", root)
            .env("XDG_CONFIG_HOME", root.join(".git/stoop-test-home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .trim_end()
            .to_owned()
    }
    /// The `sha1:` blob id git gives `bytes`, as the recorder writes it.
    fn blob_oid_of(root: &Path, bytes: &[u8]) -> String {
        use std::io::Write;
        let mut child = Command::new("git")
            .current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .args(["hash-object", "--no-filters", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(bytes).unwrap();
        let output = child.wait_with_output().unwrap();
        format!("sha1:{}", String::from_utf8(output.stdout).unwrap().trim())
    }
    /// The `sha1:` blob id of `path` at HEAD, as git's tree names it.
    fn tree_oid(root: &Path, path: &str) -> String {
        let hex = git_stdout(root, &["rev-parse", &format!("HEAD:{path}")]);
        format!("sha1:{hex}")
    }
    fn commit_all(root: &Path, message: &str) {
        git(root, &["add", "-A"]);
        git(
            root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                message,
            ],
        );
    }
    /// Delete a loose blob, so that reading it would need a fetch.
    fn drop_loose_blob(root: &Path, oid: &str) {
        let hex = oid.trim_start_matches("sha1:");
        let (dir, file) = hex.split_at(2);
        fs::remove_file(root.join(".git/objects").join(dir).join(file)).unwrap();
    }
    fn outcome(f: &mut Fixture, prefilter: Prefilter) -> Outcome {
        let record = f.jobs.load("job-test").remove(0);
        evaluate_record(
            &f.spec,
            &mut PlanCtx {
                tree: &mut f.tree,
                proofs: &f.proofs,
                jobs: &f.jobs,
                now: 100,
                max_age: 50,
                github_vars: BTreeMap::new(),
                check: &Accept,
                salt: None,
                event_path: None,
                event: None,
                explain: false,
                prefilter,
            },
            &record,
        )
    }

    #[test]
    fn blob_id_match_proves_without_reading_blobs() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (1, 0, 0)
        );
    }
    #[test]
    fn blob_id_match_needs_no_blob_in_a_blobless_clone() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        drop_loose_blob(&f.root, &oid);
        git(&f.root, &["config", "remote.origin.promisor", "true"]);
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(o.counts.by_oid, 1);
        assert_eq!(f.tree.blob_reads(), 0);
        assert_eq!(f.tree.fetched_objects(), 0);
    }
    #[test]
    fn blob_id_mismatch_is_changed_without_reading_blobs_in_either_mode() {
        let mut f = Fixture::new();
        let old = blob_oid_of(&f.root, b"old");
        f.install(vec![proof(vec![with_oid("dir/a", &file_id(b"old"), &old)])]);
        let on = outcome(&mut f, Prefilter::On);
        assert_eq!(on.decision.code, Code::InputChanged);
        assert_eq!(
            on.decision.mismatches,
            vec![(1, "dir/a".to_string(), "changed".to_string())]
        );
        assert_eq!((on.counts.by_oid, on.counts.blob_reads), (1, 0));
        let off = outcome(&mut f, Prefilter::Off);
        assert_eq!(off.decision.code, Code::InputChanged);
        assert_eq!(off.counts.by_oid, 0);
    }
    #[test]
    fn null_oid_falls_back_to_hashing() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![input("dir/a", &file_id(b"tracked"))])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 1, 1)
        );
        assert_eq!(o.counts.declined.get("oid-unavailable"), Some(&1));
    }
    #[test]
    fn oid_without_basis_and_basis_without_oid_fall_back() {
        for (with_oid_value, with_basis) in [(true, false), (false, true)] {
            let mut f = Fixture::new();
            let oid = tree_oid(&f.root, "dir/a");
            let recorded = Input {
                path: "dir/a".into(),
                id: file_id(b"tracked"),
                oid: with_oid_value.then(|| oid.clone()),
                oid_basis: with_basis.then(clean_basis),
            };
            f.install(vec![proof(vec![recorded])]);
            let o = outcome(&mut f, Prefilter::On);
            assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
            assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 1));
            assert_eq!(o.counts.declined.get("oid-unavailable"), Some(&1));
        }
    }
    #[test]
    fn conversion_at_rev_is_unplannable_before_blob_ids() {
        let mut f = Fixture::new();
        fs::write(f.root.join(".gitattributes"), "dir/a text eol=crlf\n").unwrap();
        commit_all(&f.root, "attributes");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Unplannable, "{}", o.decision.detail);
        assert!(
            o.decision.detail.contains("eol=crlf"),
            "{}",
            o.decision.detail
        );
        assert_eq!(o.counts.by_oid, 0);
    }
    #[test]
    fn recorded_conversion_or_autocrlf_falls_back_to_hashing() {
        type BasisEdit = fn(&mut crate::oid_attrs::OidBasis);
        let cases: [(&str, BasisEdit); 5] = [
            ("eol", |b| b.eol = "crlf".into()),
            ("text", |b| b.text = "set".into()),
            ("filter", |b| b.filter = "lfs".into()),
            ("autocrlf input", |b| b.autocrlf = "input".into()),
            ("autocrlf true", |b| b.autocrlf = "true".into()),
        ];
        for (name, change) in cases {
            let mut f = Fixture::new();
            let oid = tree_oid(&f.root, "dir/a");
            let mut basis = clean_basis();
            change(&mut basis);
            let recorded = Input {
                path: "dir/a".into(),
                id: file_id(b"tracked"),
                oid: Some(oid),
                oid_basis: Some(basis),
            };
            f.install(vec![proof(vec![recorded])]);
            let o = outcome(&mut f, Prefilter::On);
            assert_eq!(
                o.decision.code,
                Code::Proved,
                "{name}: {}",
                o.decision.detail
            );
            assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 1), "{name}");
            assert_eq!(o.counts.declined.get("conversion"), Some(&1), "{name}");
        }
    }
    #[test]
    fn exec_bit_mismatch_with_equal_blob_id_is_changed() {
        use std::os::unix::fs::PermissionsExt;
        let cases = [("dir/a", "x:"), ("dir/run", "f:")];
        for (path, prefix) in cases {
            let mut f = Fixture::new();
            fs::write(f.root.join("dir/run"), b"tracked").unwrap();
            fs::set_permissions(f.root.join("dir/run"), fs::Permissions::from_mode(0o755)).unwrap();
            commit_all(&f.root, "exec");
            f.tree = GitTree::load(&f.root, "HEAD").unwrap();
            let oid = tree_oid(&f.root, path);
            let hash = &file_id(b"tracked")[2..];
            f.install(vec![proof(vec![with_oid(
                path,
                &format!("{prefix}{hash}"),
                &oid,
            )])]);
            let o = outcome(&mut f, Prefilter::On);
            assert_eq!(o.decision.code, Code::InputChanged, "{path}");
            assert_eq!(
                o.decision.mismatches,
                vec![(1, path.to_string(), "changed".to_string())],
                "{path}"
            );
            assert_eq!(
                (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
                (0, 1, 1),
                "{path}"
            );
            assert_eq!(o.counts.declined.get("mode"), Some(&1), "{path}");
        }
    }
    #[test]
    fn symlink_blob_id_is_derived_from_the_recorded_target() {
        let mut f = Fixture::new();
        std::os::unix::fs::symlink("dir/a", f.root.join("link")).unwrap();
        commit_all(&f.root, "link");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link", "l:dir/a")])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (1, 0, 0)
        );
    }
    #[test]
    fn symlink_with_another_target_is_changed_without_reading() {
        let mut f = Fixture::new();
        std::os::unix::fs::symlink("dir/a", f.root.join("link")).unwrap();
        commit_all(&f.root, "link");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link", "l:dir/other")])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::InputChanged, "{}", o.decision.detail);
        assert_eq!((o.counts.by_oid, o.counts.blob_reads), (1, 0));
    }
    #[test]
    fn symlink_target_with_replacement_character_reads_the_blob() {
        use std::os::unix::ffi::OsStrExt;
        let mut f = Fixture::new();
        let target = std::ffi::OsStr::from_bytes(b"d\xffr");
        std::os::unix::fs::symlink(target, f.root.join("link")).unwrap();
        commit_all(&f.root, "lossy link");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link", "l:d\u{fffd}r")])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 1, 1)
        );
        assert_eq!(o.counts.declined.get("oid-unavailable"), Some(&1));
    }
    #[test]
    fn gitlink_entry_is_never_compared_by_blob_id() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        let hex = oid.trim_start_matches("sha1:").to_owned();
        let cacheinfo = format!("160000,{hex},sub");
        git(
            &f.root,
            &["update-index", "--add", "--cacheinfo", cacheinfo.as_str()],
        );
        git(
            &f.root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                "gitlink",
            ],
        );
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![with_oid(
            "sub",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::InputChanged, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 0, 0)
        );
    }
    #[test]
    fn sha256_repository_never_uses_blob_ids() {
        let mut f = Fixture::new_with(&["init", "-q", "--object-format=sha256"]);
        let sha1 = format!("sha1:{}", "0123456789abcdef0123456789abcdef01234567");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &sha1,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 1, 1)
        );
        assert_eq!(o.counts.declined.get("object-format"), Some(&1));
    }
    #[test]
    fn missing_entry_and_renamed_path_are_removed_without_reading() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "gone/file",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::InputChanged);
        assert_eq!(
            o.decision.mismatches[0],
            (1, "gone/file".to_string(), "removed".to_string())
        );
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 0, 0)
        );
        let mut g = Fixture::new();
        git(&g.root, &["mv", "dir/a", "dir/b"]);
        commit_all(&g.root, "rename");
        g.tree = GitTree::load(&g.root, "HEAD").unwrap();
        let moved = tree_oid(&g.root, "dir/b");
        g.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &moved,
        )])]);
        let r = outcome(&mut g, Prefilter::On);
        assert_eq!(r.decision.code, Code::InputChanged);
        assert_eq!(r.decision.mismatches[0].2, "removed");
        assert_eq!((r.counts.by_oid, r.counts.blob_reads), (0, 0));
    }
    #[test]
    fn foreign_or_malformed_recorded_oids_fall_back_to_hashing() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let cases = [
            ("sha256 tag", format!("sha256:{}", "0".repeat(64))),
            ("uppercase", format!("sha1:{}", hex.to_uppercase())),
            ("truncated", format!("sha1:{}", &hex[..38])),
            ("bare hex", hex.to_owned()),
        ];
        for (name, oid) in cases {
            let mut f = Fixture::new();
            f.install(vec![proof(vec![with_oid(
                "dir/a",
                &file_id(b"tracked"),
                &oid,
            )])]);
            let o = outcome(&mut f, Prefilter::On);
            assert_eq!(
                o.decision.code,
                Code::Proved,
                "{name}: {}",
                o.decision.detail
            );
            assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 1), "{name}");
            assert_eq!(o.counts.declined.get("object-format"), Some(&1), "{name}");
        }
    }
    #[test]
    fn malformed_content_id_is_not_shortcut() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid("dir/a", "f:not-hex", &oid)])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::InputChanged);
        assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 1));
        assert_eq!(o.counts.declined.get("id-malformed"), Some(&1));
    }
    #[test]
    fn prior_blob_ids_are_compared_without_reads() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        let mut p = proof(vec![]);
        p.outputs = vec![input("dir/a", &file_id(b"new"))];
        p.priors = Some(vec![with_oid("dir/a", &file_id(b"tracked"), &oid)]);
        f.install(vec![p]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (
                o.counts.priors,
                o.counts.by_oid,
                o.counts.hashed,
                o.counts.blob_reads
            ),
            (1, 1, 0, 0)
        );
    }
    #[test]
    fn changed_prior_blob_id_is_prior_changed_without_reads() {
        let mut f = Fixture::new();
        let old = blob_oid_of(&f.root, b"old");
        let mut p = proof(vec![]);
        p.outputs = vec![input("dir/a", &file_id(b"new"))];
        p.priors = Some(vec![with_oid("dir/a", &file_id(b"old"), &old)]);
        f.install(vec![p]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::PriorChanged, "{}", o.decision.detail);
        assert!(
            o.decision.detail.contains("prior content changed"),
            "{}",
            o.decision.detail
        );
        assert_eq!((o.counts.by_oid, o.counts.blob_reads), (1, 0));
    }
    #[test]
    fn overlay_paths_ignore_blob_ids() {
        let mut f = Fixture::new();
        let mut first = proof(vec![]);
        first.outputs.push(input("dir/a", &file_id(b"generated")));
        let wrong = blob_oid_of(&f.root, b"other");
        f.install(vec![
            first,
            proof(vec![with_oid("dir/a", &file_id(b"generated"), &wrong)]),
        ]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.overlay, o.counts.by_oid, o.counts.hashed),
            (1, 0, 0)
        );
    }
    #[test]
    fn inconsistent_pair_is_outside_the_domain_and_check_flags_it() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"other"),
            &oid,
        )])]);
        assert_eq!(outcome(&mut f, Prefilter::On).decision.code, Code::Proved);
        assert_eq!(
            outcome(&mut f, Prefilter::Off).decision.code,
            Code::InputChanged
        );
        let check = outcome(&mut f, Prefilter::Check).decision;
        assert_eq!(check.code, Code::Error, "{}", check.detail);
        assert!(check.detail.contains("disagrees"), "{}", check.detail);
    }
    #[test]
    fn check_mode_accepts_a_consistent_record() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::Check);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(o.counts.by_oid, 1);
    }
    #[test]
    fn off_mode_hashes_every_comparison() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::Off);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!(
            (o.counts.by_oid, o.counts.hashed, o.counts.blob_reads),
            (0, 1, 1)
        );
        assert!(o.counts.declined.is_empty());
    }
    #[test]
    fn recorded_file_id_against_a_tree_link_takes_the_existing_path() {
        let mut f = Fixture::new();
        std::os::unix::fs::symlink("dir/a", f.root.join("link")).unwrap();
        commit_all(&f.root, "link");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "link",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::InputChanged, "{}", o.decision.detail);
        assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 0));
    }
    #[test]
    fn sha256_repository_never_derives_link_blob_ids() {
        let mut f = Fixture::new_with(&["init", "-q", "--object-format=sha256"]);
        std::os::unix::fs::symlink("dir/a", f.root.join("link")).unwrap();
        commit_all(&f.root, "link");
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![input("link", "l:dir/a")])]);
        let o = outcome(&mut f, Prefilter::On);
        assert_eq!(o.decision.code, Code::Proved, "{}", o.decision.detail);
        assert_eq!((o.counts.by_oid, o.counts.hashed), (0, 1));
        assert_eq!(o.counts.declined.get("object-format"), Some(&1));
    }
    #[test]
    fn explain_notes_name_each_blob_id_match_and_decline() {
        let mut f = Fixture::new();
        f.install(vec![proof(vec![])]);
        let record = f.jobs.load("job-test").remove(0);
        let mut evidence = Evidence::new(&record);
        let mut notes = Vec::new();
        let compared = |id: &str, content, declined| Answer::compared(id.into(), content, declined);
        count(
            &mut evidence,
            &mut notes,
            true,
            2,
            "dir/a",
            &compared("f:x", Content::Oid, None),
        );
        count(
            &mut evidence,
            &mut notes,
            true,
            2,
            "dir/b",
            &compared("f:y", Content::Hashed, Some("mode")),
        );
        count(
            &mut evidence,
            &mut notes,
            true,
            2,
            "dir/c",
            &compared("f:z", Content::Hashed, Some("oid-unavailable")),
        );
        assert_eq!(
            notes,
            vec![
                "step 2: dir/a: matched by blob id".to_string(),
                "step 2: dir/b: blob id not used: mode".to_string(),
            ]
        );
        assert_eq!((evidence.by_oid, evidence.hashed), (1, 2));
        assert_eq!(evidence.declined.get("mode"), Some(&1));
        assert_eq!(evidence.declined.get("oid-unavailable"), Some(&1));
    }
    /// Check compares where the two modes stop, not only their codes. Both refuse this record
    /// with `input-changed`. On trusts the blob id of `dir/a` and reaches `nope`, which is absent.
    /// Off hashes `dir/a` first and finds it changed. Check must report that the modes disagree.
    #[test]
    fn check_refuses_when_the_modes_stop_at_different_inputs() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![
            with_oid("dir/a", &file_id(b"old"), &oid),
            input("nope", &file_id(b"gone")),
        ])]);
        let on = outcome(&mut f, Prefilter::On).decision;
        let off = outcome(&mut f, Prefilter::Off).decision;
        assert_eq!(on.code, Code::InputChanged, "{}", on.detail);
        assert_eq!(off.code, Code::InputChanged, "{}", off.detail);
        assert_eq!(
            on.mismatches,
            vec![(1, "nope".to_string(), "removed".to_string())]
        );
        assert_eq!(
            off.mismatches,
            vec![(1, "dir/a".to_string(), "changed".to_string())]
        );
        let check = outcome(&mut f, Prefilter::Check).decision;
        assert_eq!(check.code, Code::Error, "{}", check.detail);
        assert!(check.detail.contains("disagrees"), "{}", check.detail);
    }
    /// Check also compares the step where each mode stopped. The two refuse with the same detail
    /// and the same path, so only the step tells them apart. Step 1 holds a prior whose blob id
    /// matches the tree but whose content id does not: On trusts it and moves on, and Off hashes
    /// it and stops there. Step 2 names other bytes, where On stops.
    #[test]
    fn check_refuses_when_the_modes_stop_at_different_steps() {
        let mut f = Fixture::new();
        let tree = tree_oid(&f.root, "dir/a");
        let other = blob_oid_of(&f.root, b"other");
        let mut first = proof(vec![]);
        first.priors = Some(vec![with_oid("dir/a", &file_id(b"old"), &tree)]);
        let mut second = proof(vec![]);
        second.priors = Some(vec![with_oid("dir/a", &file_id(b"tracked"), &other)]);
        f.install(vec![first, second]);
        let on = outcome(&mut f, Prefilter::On).decision;
        let off = outcome(&mut f, Prefilter::Off).decision;
        assert_eq!(on.code, Code::PriorChanged, "{}", on.detail);
        assert_eq!(off.code, Code::PriorChanged, "{}", off.detail);
        assert_eq!(on.detail, off.detail);
        assert_eq!(
            on.mismatches,
            vec![(2, "dir/a".to_string(), "prior content changed".to_string())]
        );
        assert_eq!(
            off.mismatches,
            vec![(1, "dir/a".to_string(), "prior content changed".to_string())]
        );
        let check = outcome(&mut f, Prefilter::Check).decision;
        assert_eq!(check.code, Code::Error, "{}", check.detail);
        assert!(check.detail.contains("disagrees"), "{}", check.detail);
    }
    /// Counts describe one evaluation. A pass that reads no blob reports none, even when an
    /// earlier pass on the same tree read one.
    #[test]
    fn blob_reads_are_counted_per_pass_on_a_shared_tree() {
        let mut f = Fixture::new();
        let oid = tree_oid(&f.root, "dir/a");
        f.install(vec![proof(vec![with_oid(
            "dir/a",
            &file_id(b"tracked"),
            &oid,
        )])]);
        let off = outcome(&mut f, Prefilter::Off);
        assert_eq!(
            (off.counts.by_oid, off.counts.hashed, off.counts.blob_reads),
            (0, 1, 1)
        );
        let on = outcome(&mut f, Prefilter::On);
        assert_eq!(on.decision.code, Code::Proved, "{}", on.decision.detail);
        assert_eq!(
            (on.counts.by_oid, on.counts.hashed, on.counts.blob_reads),
            (1, 0, 0)
        );
    }
    /// The modes can fail at different inputs. `dir/a` matches its blob by id, so On never reads
    /// it and fails at `dir/c`, whose blob is missing. Off reads `dir/a` first and fails there.
    /// Both return `error` with no mismatch, so only the detail tells them apart.
    #[test]
    fn check_refuses_when_the_modes_fail_at_different_inputs() {
        let mut f = Fixture::new();
        fs::write(f.root.join("dir/c"), b"c").unwrap();
        commit_all(&f.root, "second file");
        let a = tree_oid(&f.root, "dir/a");
        let c = tree_oid(&f.root, "dir/c");
        drop_loose_blob(&f.root, &a);
        drop_loose_blob(&f.root, &c);
        f.tree = GitTree::load(&f.root, "HEAD").unwrap();
        f.install(vec![proof(vec![
            with_oid("dir/a", &file_id(b"tracked"), &a),
            input("dir/c", &file_id(b"c")),
        ])]);
        let on = outcome(&mut f, Prefilter::On).decision;
        let off = outcome(&mut f, Prefilter::Off).decision;
        assert_eq!(on.code, Code::Error, "{}", on.detail);
        assert_eq!(off.code, Code::Error, "{}", off.detail);
        assert!(on.detail.contains("dir/c"), "{}", on.detail);
        assert!(off.detail.contains("dir/a"), "{}", off.detail);
        let check = outcome(&mut f, Prefilter::Check).decision;
        assert_eq!(check.code, Code::Error, "{}", check.detail);
        assert!(check.detail.contains("disagrees"), "{}", check.detail);
    }
    fn commit_index(root: &Path, message: &str) {
        git(
            root,
            &[
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.com",
                "commit",
                "-qm",
                message,
            ],
        );
    }
    /// A xorshift generator, so a corpus run reproduces from its seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }
    /// The repository shapes the corpus draws records from.
    #[derive(Clone, Copy, Debug)]
    enum Corpus {
        Plain,
        Links,
        Attributes,
        Gitlink,
    }
    fn corpus_fixture(kind: Corpus) -> Fixture {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new();
        let root = f.root.clone();
        fs::write(root.join("dir/b"), b"run").unwrap();
        fs::set_permissions(root.join("dir/b"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(root.join("top.txt"), b"top\n").unwrap();
        match kind {
            Corpus::Plain | Corpus::Gitlink => {}
            Corpus::Links => {
                std::os::unix::fs::symlink("dir/a", root.join("link")).unwrap();
                std::os::unix::fs::symlink("dir", root.join("dirlink")).unwrap();
                let lossy = std::ffi::OsStr::from_bytes(b"d\xffr");
                std::os::unix::fs::symlink(lossy, root.join("weird")).unwrap();
            }
            Corpus::Attributes => {
                fs::write(
                    root.join(".gitattributes"),
                    "conv.txt eol=crlf\n*.m conv\n[attr]conv eol=crlf\n",
                )
                .unwrap();
                fs::write(root.join("conv.txt"), b"conv\n").unwrap();
                fs::write(root.join("m1.m"), b"m\n").unwrap();
            }
        }
        if matches!(kind, Corpus::Gitlink) {
            git(&root, &["add", "dir", "top.txt"]);
            let sha = git_stdout(&root, &["rev-parse", "HEAD:dir/a"]);
            let info = format!("160000,{sha},sub");
            git(
                &root,
                &["update-index", "--add", "--cacheinfo", info.as_str()],
            );
            commit_index(&root, "corpus");
        } else {
            commit_all(&root, "corpus");
        }
        f.tree = GitTree::load(&root, "HEAD").unwrap();
        f
    }
    fn corpus_paths(f: &Fixture) -> Vec<String> {
        let mut paths = f.tree.below("");
        paths.extend(
            [
                "missing/x",
                "top.txt/x",
                "dir/a/x",
                "sub/inside",
                "dirlink/a",
                "nope",
                "new/file",
            ]
            .map(str::to_owned),
        );
        paths
    }
    /// The input a recorder would write for the path as it stands at HEAD.
    fn exact_input(f: &Fixture, path: &str) -> Input {
        let plain = |id: String| Input {
            path: path.into(),
            id,
            oid: None,
            oid_basis: None,
        };
        match f.tree.entry(path).cloned() {
            Some(Entry::Blob { oid, exec }) => {
                let bytes = fs::read(f.root.join(path)).unwrap();
                let hash = blake3::hash(&bytes).to_hex().to_string();
                Input {
                    path: path.into(),
                    id: crate::input::file_id(exec, &hash),
                    oid: Some(format!("sha1:{oid}")),
                    oid_basis: Some(clean_basis()),
                }
            }
            Some(Entry::Link { .. }) => {
                let target = fs::read_link(f.root.join(path)).unwrap();
                plain(format!("l:{}", target.to_string_lossy()))
            }
            Some(Entry::Tree | Entry::Gitlink) => plain("d".into()),
            None => plain("a".into()),
        }
    }
    /// Make `input` the record of `bytes` as the recorder would write them.
    fn set_content(input: &mut Input, bytes: &[u8]) {
        let exec = input.id.starts_with("x:");
        input.id = crate::input::file_id(exec, &blake3::hash(bytes).to_hex());
        input.oid = Some(format!("sha1:{}", crate::input::blob_oid(bytes, false)));
        input.oid_basis = Some(clean_basis());
    }
    /// One input drawn from the categories the planner must handle. `exact` keeps it exact.
    fn random_input(rng: &mut Rng, f: &Fixture, paths: &[String], exact: bool) -> Input {
        let path = paths[rng.below(paths.len())].clone();
        let mut input = exact_input(f, &path);
        let content = input.id.starts_with("f:") || input.id.starts_with("x:");
        let category = if exact { 0 } else { rng.below(12) };
        match category {
            1 if content => {
                let mut bytes = fs::read(f.root.join(&path)).unwrap();
                bytes.push(b'!');
                set_content(&mut input, &bytes);
            }
            2 if content => {
                let mut bytes = fs::read(f.root.join(&path)).unwrap();
                if let Some(first) = bytes.first_mut() {
                    *first ^= 1;
                }
                set_content(&mut input, &bytes);
            }
            3 if content => {
                input.id = if input.id.starts_with("x:") {
                    format!("f:{}", &input.id[2..])
                } else {
                    format!("x:{}", &input.id[2..])
                };
            }
            4 => {
                input.oid = None;
                input.oid_basis = None;
            }
            5 => input.oid_basis = None,
            6 => {
                input.oid = input
                    .oid
                    .take()
                    .map(|o| o.trim_start_matches("sha1:").into())
            }
            7 if content => input.id = "f:zz".into(),
            8 => input.id = "a".into(),
            9 => input.id = "d".into(),
            10 => {
                if let Some(id) = crate::input::identify(&f.root.join(&path), true, true) {
                    input.id = id;
                    input.oid = None;
                    input.oid_basis = None;
                }
            }
            11 if input.id.starts_with("l:") => input.id = "l:other".into(),
            _ => {}
        }
        input
    }
    /// Proofs for one record: one to three steps, with outputs and priors on some of them.
    fn random_record(rng: &mut Rng, f: &Fixture, paths: &[String]) -> Vec<Proof> {
        let exact = rng.below(2) == 0;
        let mut proofs = Vec::new();
        for _ in 0..1 + rng.below(3) {
            let count = 5 + rng.below(36);
            let mut inputs = Vec::with_capacity(count);
            for _ in 0..count {
                inputs.push(random_input(rng, f, paths, exact));
            }
            let mut step = proof(inputs);
            let mut priors = Vec::new();
            if rng.below(4) == 0 {
                let out: &str = ["top.txt", "dir/b", "new/file"][rng.below(3)];
                step.outputs.push(Input {
                    path: out.into(),
                    id: file_id(b"generated"),
                    oid: None,
                    oid_basis: None,
                });
                priors.push(exact_input(f, out));
            }
            for _ in 0..rng.below(3) {
                priors.push(random_input(rng, f, paths, exact));
            }
            step.priors = Some(priors);
            proofs.push(step);
        }
        proofs
    }
    /// Save `proofs` as one record of `job`, one uniquely keyed step per proof, and return the
    /// traced steps that plan it.
    fn save_record(f: &Fixture, job: &str, proofs: Vec<Proof>) -> Vec<StepSpec> {
        let mut steps = Vec::new();
        let mut records = Vec::new();
        for (index, proof) in proofs.into_iter().enumerate() {
            let key = format!("{job}-{index}");
            steps.push(StepSpec::Traced {
                index: index + 1,
                key: key.clone(),
                max_age: None,
            });
            records.push(StepRecord {
                key: key.clone(),
                proof: proof.digest(),
                how: StepHow::Ran,
            });
            f.proofs.save(&key, proof).unwrap();
        }
        f.jobs
            .save(
                job,
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
        steps
    }
    /// The fields that decide what a plan says. Evidence counters are compared separately.
    fn plan_key(d: &Decision) -> (bool, Code, String, Vec<(usize, String, String)>) {
        (
            d.skip,
            d.code.clone(),
            d.detail.clone(),
            d.mismatches.clone(),
        )
    }
    /// Plan `spec` in `prefilter` mode on a freshly loaded tree.
    fn plan(f: &Fixture, spec: &JobSpec, prefilter: Prefilter) -> Decision {
        let mut tree = GitTree::load(&f.root, "HEAD").unwrap();
        decide(
            spec,
            &mut PlanCtx {
                tree: &mut tree,
                proofs: &f.proofs,
                jobs: &f.jobs,
                check: &Accept,
                now: 100,
                max_age: 50,
                github_vars: BTreeMap::new(),
                salt: None,
                event_path: None,
                event: None,
                explain: false,
                prefilter,
            },
        )
    }
    /// The equivalence property (spec 3.4) over generated records. Each record plans the same
    /// with blob ids as with hashing, Check agrees with both, and the counters account for every
    /// content comparison once. The seed prints on failure, and `STOOP_EQUIV_CASES` raises the
    /// count. Half the records are exact, so the corpus reaches proved decisions too.
    #[test]
    fn equivalence_corpus() {
        let cases: usize = std::env::var("STOOP_EQUIV_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(400)
            .max(4);
        let seed: u64 = 0x5EED_1234_ABCD_0001;
        let mut rng = Rng(seed);
        let mut proved = 0;
        for kind in [
            Corpus::Plain,
            Corpus::Links,
            Corpus::Attributes,
            Corpus::Gitlink,
        ] {
            let f = corpus_fixture(kind);
            let paths = corpus_paths(&f);
            for case in 0..cases / 4 {
                let job = format!("job-corpus-{}-{case}", format!("{kind:?}").to_lowercase());
                let proofs = random_record(&mut rng, &f, &paths);
                let steps = save_record(&f, &job, proofs);
                let spec = JobSpec {
                    key: Some(job.clone()),
                    steps,
                    ..f.spec.clone()
                };
                let why = format!("seed {seed:#x}, {kind:?}, case {case}");
                let on = plan(&f, &spec, Prefilter::On);
                let off = plan(&f, &spec, Prefilter::Off);
                let check = plan(&f, &spec, Prefilter::Check);
                assert_eq!(plan_key(&on), plan_key(&off), "{why}");
                assert_eq!(plan_key(&check), plan_key(&on), "{why}");
                if let (Some(a), Some(b)) = (&on.evidence, &off.evidence) {
                    proved += 1;
                    assert_eq!(a.hashed + a.by_oid, b.hashed, "{why}");
                    assert_eq!(b.by_oid, 0, "{why}");
                    assert_eq!(
                        (a.steps, a.inputs, a.priors, a.overlay, a.assumed_outside),
                        (b.steps, b.inputs, b.priors, b.overlay, b.assumed_outside),
                        "{why}"
                    );
                    assert_eq!(
                        (&a.assumed_env, &a.record_digest, &a.proofs),
                        (&b.assumed_env, &b.record_digest, &b.proofs),
                        "{why}"
                    );
                }
            }
        }
        assert!(
            proved >= cases / 8,
            "seed {seed:#x}: only {proved} proved records in {cases}"
        );
    }
}
