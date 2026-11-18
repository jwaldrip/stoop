//! The decision: skip, or run and learn.

use crate::ignore::Ignore;
use crate::input::{identify, par_map, verify, Input};
use crate::pathutil::{absolutize, to_key, Physical};
use crate::proof::{now, sanitize, Proof, Store};
use crate::sync::Remote;
use crate::trace::{self, Trace};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Default)]
pub struct Opts {
    pub key: Option<String>,
    pub root: Option<PathBuf>,
    pub store: Option<PathBuf>,
    pub env: Vec<String>,
    pub ignore: Vec<String>,
    /// Patterns for paths that exist for one run only, such as a CI step's script file. They
    /// exclude like any other pattern, but a proof never stores them.
    pub transient: Vec<String>,
    pub no_record: bool,
    pub quiet: bool,
    /// Environment variables exempted from the whole-environment input.
    pub ignore_env: Vec<String>,
    /// Record runs that used the network (their results are invisible to a file trace).
    pub allow_network: bool,
    /// Extra text searched for runner variable names (a CI step's script body).
    pub mention: String,
    /// External state to verify: commands whose output must be unchanged for a skip.
    pub probes: Vec<String>,
    /// Share proofs through a git remote: `git` or `git:<remote>`.
    pub sync: Option<String>,
    /// Publish proofs to that remote. Off by default; for trusted runs only.
    pub sync_write: bool,
    /// Seconds a proof stays valid; 0 means forever. Default: 7 days.
    pub max_age: Option<u64>,
    pub defer_push: bool,
    pub argv: Vec<String>,
}

/// Nearest ancestor holding a `.git`, else the working directory.
pub fn find_root(cwd: &Path) -> PathBuf {
    let mut d = cwd;
    loop {
        if d.join(".git").exists() {
            return d.to_path_buf();
        }
        match d.parent() {
            Some(p) => d = p,
            None => return cwd.to_path_buf(),
        }
    }
}

fn default_key(argv: &[String], rel_cwd: &str) -> String {
    let mut h = blake3::Hasher::new();
    for a in argv {
        h.update(a.as_bytes());
        h.update(&[0]);
    }
    h.update(rel_cwd.as_bytes());
    let base = Path::new(&argv[0])
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "cmd".into());
    format!("{}-{}", sanitize(&base), &h.finalize().to_hex()[..16])
}

/// The environment counts as an input, because a variable read never shows up in
/// a file trace. The runner's own per-run bookkeeping is exempt unless the command
/// text names it, as are variables that differ on every start of the same machine.
pub fn ambient_env(mention: &str, ignore: &[String]) -> Vec<String> {
    const NOISY_PREFIX: &[&str] = &["GITHUB_", "RUNNER_", "ACTIONS_", "INPUT_", "STOOP_"];
    const ALWAYS_SKIP: &[&str] = &[
        "_",
        "PWD",
        "OLDPWD",
        "SHLVL",
        "TERM",
        "HOSTNAME",
        "INVOCATION_ID",
        "JOURNAL_STREAM",
        "SSH_AUTH_SOCK",
        "XDG_RUNTIME_DIR",
    ];
    let mut names: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .filter(|k| {
            if ALWAYS_SKIP.contains(&k.as_str()) || ignore.contains(k) {
                return false;
            }
            !NOISY_PREFIX.iter().any(|p| k.starts_with(p)) || mention.contains(k.as_str())
        })
        .collect();
    names.sort();
    names
}

/// Run each probe and hash what it prints. `None` if any fails: an external fact that
/// could not be established is never assumed unchanged.
pub fn run_probes(probes: &[String], cwd: &Path, quiet: bool) -> Option<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for p in probes {
        let res = Command::new("sh")
            .arg("-c")
            .arg(p)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        match res {
            Ok(o) if o.status.success() => {
                out.insert(p.clone(), blake3::hash(&o.stdout).to_hex().to_string());
            }
            Ok(o) => {
                if !quiet {
                    eprintln!("stoop: probe `{p}` failed ({})", o.status);
                }
                return None;
            }
            Err(e) => {
                if !quiet {
                    eprintln!("stoop: cannot run probe `{p}`: {e}");
                }
                return None;
            }
        }
    }
    Some(out)
}

/// A secret that keys the environment hashes stored in proofs. Proofs published to a
/// git remote are readable by anyone who can read the repository, and an unsalted hash
/// of a low-entropy value (a short token, a boolean flag) can be guessed offline. With
/// the salt set, hashes are keyed with it and carry the `s:` prefix; whoever checks a
/// proof needs the same salt, so runs without the secret (fork pull requests) simply
/// cannot match and the command runs. The salt itself is never hashed in.
pub const SALT_VAR: &str = "STOOP_ENV_SALT";

pub fn env_hash(name: &str, value: &str, salt: Option<&str>) -> String {
    match salt {
        Some(salt) => {
            let key = blake3::derive_key("stoop env hash v1", salt.as_bytes());
            let mut h = blake3::Hasher::new_keyed(&key);
            h.update(name.as_bytes());
            h.update(&[0]);
            h.update(value.as_bytes());
            format!("s:{}", h.finalize().to_hex())
        }
        None => blake3::hash(value.as_bytes()).to_hex().to_string(),
    }
}

fn env_hashes(names: &[String], salt: Option<&str>) -> BTreeMap<String, String> {
    names
        .iter()
        .map(|n| {
            (
                n.clone(),
                env_hash(n, &std::env::var(n).unwrap_or_default(), salt),
            )
        })
        .collect()
}

/// A proof stops counting after this long. It bounds what a file trace cannot see
/// (the clock above all): a test that depends on today's date is wrong for at most this long.
pub const DEFAULT_MAX_AGE: u64 = 7 * 86_400;

/// An on/off environment switch. Empty, `0`, `false`, `no` and `off` are off. That
/// matters for the common CI idiom `X: ${{ cond && '1' || '' }}`, which sets the
/// variable to an empty string when the condition is false: merely being set must
/// not turn on something that publishes proofs.
pub fn env_flag(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || matches!(v.as_str(), "0" | "false" | "no" | "off"))
        }
        Err(_) => false,
    }
}

/// A string environment variable; empty counts as unset.
pub fn env_str(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// "90s", "30m", "12h", "7d", or a bare number of seconds. "0" means never expire.
pub fn parse_age(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some('s') => (&s[..s.len() - 1], 1),
        Some('m') => (&s[..s.len() - 1], 60),
        Some('h') => (&s[..s.len() - 1], 3600),
        Some('d') => (&s[..s.len() - 1], 86_400),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("cannot read {s:?} as a duration (try 90s, 30m, 12h, 7d)"))
}

fn ago(created: u64) -> String {
    let s = now().saturating_sub(created);
    match s {
        0..=89 => format!("{s}s ago"),
        90..=5399 => format!("{}m ago", s / 60),
        5400..=129_599 => format!("{}h ago", s / 3600),
        _ => format!("{}d ago", s / 86_400),
    }
}

fn plain(argv: &[String]) -> i32 {
    match std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
    {
        Ok(s) => {
            use std::os::unix::process::ExitStatusExt;
            s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
        }
        Err(e) => {
            eprintln!("stoop: cannot run {}: {e}", argv[0]);
            127
        }
    }
}

pub enum How {
    Skipped { proof: String },
    Recorded { proof: String },
    Unrecorded(String),
    Failed,
    Untraced,
}

pub struct Outcome {
    pub status: i32,
    pub key: String,
    pub how: How,
}

pub fn run(o: Opts, explain: bool) -> i32 {
    run_outcome(o, explain).status
}

pub fn run_outcome(o: Opts, explain: bool) -> Outcome {
    let key = o.key.clone().unwrap_or_default();
    if o.argv.is_empty() {
        eprintln!("stoop: no command given");
        return Outcome {
            status: 2,
            key,
            how: How::Untraced,
        };
    }
    if env_flag("STOOP_OFF") && !explain {
        return Outcome {
            status: plain(&o.argv),
            key,
            how: How::Untraced,
        };
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let root = o
        .root
        .clone()
        .map(|r| absolutize(&cwd, &r))
        .unwrap_or_else(|| find_root(&cwd));
    let rel_cwd = to_key(&root, &cwd);
    let key = o
        .key
        .as_deref()
        .map(sanitize)
        .unwrap_or_else(|| default_key(&o.argv, &rel_cwd));
    let store = Store::new(
        o.store
            .clone()
            .or_else(|| env_str("STOOP_STORE").map(PathBuf::from))
            .unwrap_or_else(|| root.join(".stoop")),
    );
    let full = env_flag("STOOP_FULL");
    let max_age = o
        .max_age
        .or_else(|| {
            std::env::var("STOOP_MAX_AGE")
                .ok()
                .and_then(|v| parse_age(&v).ok())
        })
        .unwrap_or(DEFAULT_MAX_AGE);
    let mut env_names = ambient_env(
        &format!("{} {}", o.argv.join(" "), o.mention),
        &o.ignore_env,
    );
    env_names.extend(o.env.iter().cloned());
    env_names.sort();
    env_names.dedup();
    let salt = env_str(SALT_VAR);
    let env_now = env_hashes(&env_names, salt.as_deref());

    let remote = o
        .sync
        .clone()
        .or_else(|| env_str("STOOP_SYNC"))
        .and_then(|spec| {
            let write = o.sync_write || env_flag("STOOP_SYNC_WRITE");
            match Remote::from_spec(&spec, &root, write) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!("stoop: sync: {e}");
                    None
                }
            }
        });

    // 1. Is there a proof whose inputs all still match?
    let t0 = Instant::now();
    let mut proofs = store.load(&key);
    let mut pulled = false;
    let mut probe_now: Option<Option<BTreeMap<String, String>>> = None;
    let mut why;
    let mut hit_idx: Option<usize>;
    loop {
        why = String::from("no proof yet");
        hit_idx = None;
        for (i, p) in proofs.iter().enumerate() {
            let expired = max_age > 0 && now().saturating_sub(p.created) > max_age;
            let diffs: Vec<(String, &'static str)> = if expired {
                vec![("proof".to_string(), "expired")]
            } else if p.env != env_now {
                vec![("env".to_string(), "changed")]
            } else {
                let mut d: Vec<(String, &'static str)> = verify(&root, &p.inputs, explain)
                    .into_iter()
                    .map(|m| (m.path, m.why))
                    .collect();
                if d.is_empty() {
                    // Inputs match, but a skip also needs what the run produced to be in place.
                    d = verify(&root, &p.outputs, explain)
                        .into_iter()
                        .map(|m| {
                            (
                                format!("output {}", m.path),
                                if m.why == "removed" { "missing" } else { m.why },
                            )
                        })
                        .collect();
                }
                d
            };
            let mut diffs = diffs;
            if diffs.is_empty() && (!p.probes.is_empty() || !o.probes.is_empty()) {
                // External state is checked last: it can be slow, and files rule most proofs out first.
                let fresh = probe_now.get_or_insert_with(|| run_probes(&o.probes, &cwd, o.quiet));
                match fresh {
                    None => diffs.push(("probe".to_string(), "failed")),
                    Some(m) if *m != p.probes => {
                        let which = m
                            .keys()
                            .chain(p.probes.keys())
                            .find(|k| m.get(*k) != p.probes.get(*k))
                            .cloned()
                            .unwrap_or_else(|| "probe".to_string());
                        diffs.push((format!("probe `{which}`"), "changed"));
                    }
                    Some(_) => {}
                }
            }
            if diffs.is_empty() {
                hit_idx = Some(i);
                break;
            }
            if i == 0 {
                let first = &diffs[0];
                let more = if diffs.len() > 1 {
                    format!(" (+{} more)", diffs.len() - 1)
                } else {
                    String::new()
                };
                why = format!("{} {}{}", first.0, first.1, more);
            }
            if explain {
                eprintln!("proof {} ({}):", i + 1, ago(p.created));
                for (path, w) in diffs.iter().take(20) {
                    eprintln!("  {w}: {path}");
                }
            }
        }
        // A miss with a remote configured: someone else may already have proved this.
        if hit_idx.is_some() || pulled || remote.is_none() {
            break;
        }
        pulled = true;
        match remote.as_ref().map(|r| r.pull(&store, &key)) {
            Some(Ok(0)) | None => break,
            Some(Ok(_)) => proofs = store.load(&key),
            Some(Err(e)) => {
                eprintln!("stoop: sync: could not fetch proofs ({e}); continuing");
                break;
            }
        }
    }
    let hit: Option<&Proof> = hit_idx.map(|i| &proofs[i]);
    if let Some(p) = hit {
        if !full {
            if !o.quiet {
                eprintln!(
                    "stoop: skip {key}: {} inputs unchanged since {} ({}ms)",
                    p.inputs.len(),
                    ago(p.created),
                    t0.elapsed().as_millis()
                );
            }
            return Outcome {
                status: 0,
                key,
                how: How::Skipped { proof: p.digest() },
            };
        }
        why = "STOOP_FULL is set".into();
    }
    if explain {
        eprintln!("stoop: would run {key}: {why}");
        return Outcome {
            status: 1,
            key,
            how: How::Untraced,
        };
    }
    if !o.quiet {
        eprintln!("stoop: run {key}: {why}");
    }

    // 2. Run it, watched. Anything that stops the watch from working just runs the command.
    let probes_before = if o.probes.is_empty() {
        Some(BTreeMap::new())
    } else {
        run_probes(&o.probes, &cwd, o.quiet)
    };
    // Declaring a probe is declaring the external dependency, so network use is accepted.
    // The ignore set and the scope are fixed before the run: priors are recorded against them.
    let ignore = Ignore::new(&o.ignore, Some(&root.join(".stoopignore")), &o.transient);
    let real_root = std::fs::canonicalize(&root).unwrap_or_else(|_| root.clone());
    let scope = (!o.no_record).then(|| trace::Scope {
        root: &root,
        real_root: real_root.clone(),
        ignore: &ignore,
    });
    let trace = match trace::run(
        &o.argv,
        &cwd,
        o.allow_network || !o.probes.is_empty(),
        scope.as_ref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            if !o.quiet {
                eprintln!("stoop: not traced ({e}); running without a proof");
            }
            return Outcome {
                status: plain(&o.argv),
                key,
                how: How::Untraced,
            };
        }
    };
    let status = trace.status;
    if status != 0 {
        return Outcome {
            status,
            key,
            how: How::Failed,
        };
    }
    if o.no_record {
        return Outcome {
            status,
            key,
            how: How::Unrecorded("recording disabled".into()),
        };
    }
    // The external state the command saw must still be what it was when it finished.
    let probes = match probes_before {
        None => {
            if !o.quiet {
                eprintln!("stoop: not recorded: a probe failed before the run, so the external state is unknown");
            }
            return Outcome {
                status,
                key,
                how: How::Unrecorded("probe failed".into()),
            };
        }
        Some(before) => {
            if !o.probes.is_empty()
                && run_probes(&o.probes, &cwd, o.quiet).as_ref() != Some(&before)
            {
                if !o.quiet {
                    eprintln!("stoop: not recorded: a probe changed while the command ran");
                }
                return Outcome {
                    status,
                    key,
                    how: How::Unrecorded("probe changed".into()),
                };
            }
            before
        }
    };

    // 3. It passed: write down what it read, what it wrote, and what each written path held before.
    let mut phys = Physical::new(&root, &real_root);
    let written: BTreeSet<String> = trace.keys.values().cloned().collect();
    match build_inputs(&root, &mut phys, &trace, &ignore, &written) {
        Ok((inputs, read_reasons)) => {
            let n = inputs.len();
            let (outputs, removed, write_reasons) = build_outputs(&real_root, &written);
            let proof = Proof {
                created: now(),
                argv: o.argv.clone(),
                env: env_now,
                inputs,
                outputs,
                probes,
                removed,
                ignore: Some(ignore.patterns()),
                priors: Some(build_priors(&trace)),
                unplannable: merge_reasons(
                    &trace.unplannable,
                    read_reasons.into_iter().chain(write_reasons).collect(),
                ),
            };
            let digest = proof.digest();
            if let Some(r) = remote.as_ref().filter(|r| r.write) {
                // Fold in anything other runs published since we looked, so a push never
                // drops their proofs.
                if let Err(e) = r.pull(&store, &key) {
                    eprintln!("stoop: sync: could not refresh from the remote ({e}); continuing");
                }
            }
            let saved = match store.save(&key, proof) {
                Ok(()) => {
                    if !o.quiet {
                        eprintln!("stoop: recorded {n} inputs for {key}");
                    }
                    true
                }
                Err(e) => {
                    eprintln!("stoop: could not save proof: {e}");
                    false
                }
            };
            if let Some(r) = remote
                .as_ref()
                .filter(|r| saved && r.write && !o.defer_push)
            {
                if salt.is_none() {
                    // Hashes of every variable go into a file other people can fetch. An
                    // unsalted hash of a low-entropy secret can be guessed offline.
                    eprintln!(
                        "stoop: sync: publishing environment hashes without {SALT_VAR}. In a public repository set it from a repository secret so low-entropy values cannot be guessed offline."
                    );
                }
                match r.push(&store, &key) {
                    Ok(()) if !o.quiet => eprintln!("stoop: published {key} to the remote"),
                    Ok(()) => {}
                    Err(e) => eprintln!("stoop: sync: could not publish ({e}); continuing"),
                }
            }
            return Outcome {
                status,
                key,
                how: if saved {
                    How::Recorded { proof: digest }
                } else {
                    How::Unrecorded("could not save proof".into())
                },
            };
        }
        Err(why) => {
            if !o.quiet {
                eprintln!("stoop: not recorded: {why}");
            }
        }
    }
    Outcome {
        status,
        key,
        how: How::Unrecorded("inputs could not be recorded".into()),
    }
}

/// What the run left behind inside the repository, read once it finished: one entry for each
/// in-scope path it wrote. Still there is an output. Gone again is removed, and the planner
/// removes it with the step. Unreadable or special is a reason the planner cannot replay.
pub fn build_outputs(
    real_root: &Path,
    written: &BTreeSet<String>,
) -> (Vec<Input>, Vec<String>, Vec<String>) {
    let keys: Vec<&String> = written.iter().collect();
    let ids = par_map(&keys, |k| {
        identify(&real_root.join(k.as_str()), true, false)
    });
    let mut outputs = Vec::new();
    let mut removed = Vec::new();
    let mut reasons = Vec::new();
    for (key, id) in keys.into_iter().zip(ids) {
        match id {
            None => reasons.push(format!("it left {key} unreadable")),
            Some(id) if id == "u" => reasons.push(format!("it left {key} unreadable")),
            Some(id) if id == "a" => removed.push(key.clone()),
            Some(id) => outputs.push(Input {
                path: key.clone(),
                id,
            }),
        }
    }
    if written.contains(".stoopignore") {
        reasons.push("it wrote .stoopignore, which the proof's ignore set was read from".into());
    }
    (outputs, removed, reasons)
}

/// The state of each in-scope path before the run first wrote it, sorted by path.
pub fn build_priors(trace: &Trace) -> Vec<Input> {
    trace
        .priors
        .iter()
        .map(|(path, id)| Input {
            path: path.clone(),
            id: id.clone(),
        })
        .collect()
}

/// The proof's reasons: the tracer's first, then the rest, deduplicated and capped at 16.
fn merge_reasons(first: &[String], more: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for why in first.iter().cloned().chain(more) {
        if out.len() < 16 && !out.contains(&why) {
            out.push(why);
        }
    }
    out
}

/// What the run read, as comparable inputs, or why it cannot be trusted. A read of a path the
/// run wrote is not an input: it reads the run's own output. A read through a link or a
/// symlinked directory is also recorded under the key of the file it reached, so a change to
/// that file is seen. The second value holds reasons the planner cannot replay the run.
pub fn build_inputs(
    root: &Path,
    phys: &mut Physical,
    trace: &Trace,
    ignore: &Ignore,
    written: &BTreeSet<String>,
) -> Result<(Vec<Input>, Vec<String>), String> {
    if let Some(u) = trace.unsound.first() {
        return Err(u.clone());
    }
    // Symlink targets are serialized as text too. Refuse rather than serialize lossy bytes.
    for path in trace.keys.keys().chain(trace.touched.keys()) {
        let in_repo = path.starts_with(root) || path.starts_with(phys.real());
        if in_repo
            && std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
            && std::fs::read_link(path).is_ok_and(|target| target.to_str().is_none())
        {
            return Err("it used a repository symlink with a non-UTF-8 target".into());
        }
    }
    let real_root = phys.real().to_path_buf();
    phys.prefetch(
        trace
            .touched
            .keys()
            .filter_map(|p| p.parent().map(Path::to_path_buf)),
    );
    let mut reasons: Vec<String> = Vec::new();
    let mut reads_git = false;
    // (path to identify, key, inside the root, entries listed)
    let mut cands: Vec<(PathBuf, String, bool, bool)> = Vec::new();
    for (lex, touch) in &trace.touched {
        let inside = lex.starts_with(root);
        let key = to_key(root, lex);
        let physical = phys.locate(lex).map(|l| l.path);
        // The same entry reached under its physical name, when that differs from the spelled one.
        if let Some(pp) = &physical {
            if let Some(rel) = phys.repo_rel(pp) {
                match rel.to_str() {
                    None => {
                        return Err(
                            "it used a path in the repository that is not valid UTF-8".into()
                        )
                    }
                    Some(pkey) if pkey != key => {
                        if rel.components().any(|c| c.as_os_str() == ".git") {
                            if !ignore.is_ignored(pkey) {
                                reads_git = true;
                            }
                        } else if ignore.is_ignored(pkey) {
                        } else if written.contains(pkey) {
                            reasons.push(format!("it read {pkey} through {key} and also wrote it"));
                        } else {
                            cands.push((pp.clone(), pkey.to_string(), true, touch.listed));
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        // A lexical key containing `..` does not describe kernel resolution across a
        // symlink. The physical candidate above is the only faithful repository key.
        if lex
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            continue;
        }
        if key.is_empty() || ignore.is_ignored(&key) {
            continue;
        }
        if inside
            && lex
                .strip_prefix(root)
                .ok()
                .and_then(|r| r.to_str())
                .is_none()
        {
            return Err("it used a path in the repository that is not valid UTF-8".into());
        }
        let written_physically = physical
            .as_deref()
            .and_then(|pp| phys.repo_rel(pp))
            .and_then(|r| r.to_str())
            .is_some_and(|k| written.contains(k));
        if trace.is_output(lex) || written_physically {
            continue;
        }
        if inside && key.split('/').any(|c| c == ".git") {
            reads_git = true;
            continue;
        }
        cands.push((lex.clone(), key, inside, touch.listed));
    }
    let mut out: Vec<Input> = Vec::with_capacity(cands.len());
    let mut seen: HashSet<String> = HashSet::new();
    let ids = par_map(&cands, |(p, _, inside, listed)| {
        identify(p, *inside, *listed)
    });
    for ((_, key, _, _), id) in cands.iter().zip(ids) {
        if let Some(id) = id {
            if seen.insert(key.clone()) {
                out.push(Input {
                    path: key.clone(),
                    id,
                });
            }
        }
    }
    // A symlink hides a second file: record where it points, whether or not the link is
    // ignored (an alias under an ignored /tmp can point into the repository).
    for lex in trace.touched.keys() {
        if !std::fs::symlink_metadata(lex).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        let Ok(target) = std::fs::canonicalize(lex) else {
            continue;
        };
        let link_key = to_key(root, lex);
        match target.strip_prefix(&real_root) {
            Ok(rel) if !rel.as_os_str().is_empty() => {
                let Some(tkey) = rel.to_str() else {
                    return Err("it used a path in the repository that is not valid UTF-8".into());
                };
                if rel.components().any(|c| c.as_os_str() == ".git") {
                    if !ignore.is_ignored(tkey) {
                        reads_git = true;
                    }
                    continue;
                }
                if ignore.is_ignored(tkey) {
                    continue;
                }
                if written.contains(tkey) {
                    reasons.push(format!(
                        "it read {tkey} through {link_key} and also wrote it"
                    ));
                    continue;
                }
                if let Some(id) = identify(&target, true, false) {
                    if seen.insert(tkey.to_string()) {
                        out.push(Input {
                            path: tkey.to_string(),
                            id,
                        });
                    }
                }
            }
            _ => {
                let tk = to_key(root, &target);
                if ignore.is_ignored(&link_key) || ignore.is_ignored(&tk) {
                    continue;
                }
                if let Some(id) = identify(&target, false, false) {
                    if seen.insert(tk.clone()) {
                        out.push(Input { path: tk, id });
                    }
                }
            }
        }
    }
    if reads_git {
        return Err("it reads .git, so a skip could hide a history change (add `.git` to .stoopignore if that read cannot change the result)".into());
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((out, reasons))
}

#[cfg(test)]
mod flag_tests {
    #[test]
    fn env_hash_matches_env_hashes() {
        let names = vec![
            "STOOP_S0B_ENV_PRESENT".to_string(),
            "STOOP_S0B_ENV_ABSENT".to_string(),
        ];
        std::env::set_var(&names[0], "value");
        std::env::remove_var(&names[1]);
        for salt in [None, Some("secret salt")] {
            let actual = super::env_hashes(&names, salt);
            assert_eq!(actual[&names[0]], super::env_hash(&names[0], "value", salt));
            assert_eq!(actual[&names[1]], super::env_hash(&names[1], "", salt));
            let expected = match salt {
                None => blake3::hash(b"value").to_hex().to_string(),
                Some(salt) => {
                    let key = blake3::derive_key("stoop env hash v1", salt.as_bytes());
                    let mut h = blake3::Hasher::new_keyed(&key);
                    h.update(names[0].as_bytes());
                    h.update(&[0]);
                    h.update(b"value");
                    format!("s:{}", h.finalize().to_hex())
                }
            };
            assert_eq!(actual[&names[0]], expected);
        }
        std::env::remove_var(&names[0]);
    }
    #[test]
    fn env_flag_truthiness() {
        const NAME: &str = "STOOP_S0_TEST_FLAG";
        for value in ["", "0", "false", "no", "off", " FALSE ", "Off"] {
            std::env::set_var(NAME, value);
            assert!(!super::env_flag(NAME), "{value:?}");
        }
        for value in ["1", "true", "yes", "anything"] {
            std::env::set_var(NAME, value);
            assert!(super::env_flag(NAME), "{value:?}");
        }
        std::env::remove_var(NAME);
        assert!(!super::env_flag(NAME));
    }
}
