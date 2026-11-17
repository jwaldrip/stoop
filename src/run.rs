//! The decision: skip, or run and learn.

use crate::ignore::Ignore;
use crate::input::{identify, par_map, verify, Input};
use crate::pathutil::{absolutize, to_key};
use crate::proof::{now, sanitize, Proof, Store};
use crate::sync::Remote;
use crate::trace::{self, Trace};
use std::collections::BTreeMap;
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

fn env_hashes(names: &[String]) -> BTreeMap<String, String> {
    names
        .iter()
        .map(|n| {
            let v = std::env::var(n).unwrap_or_default();
            (n.clone(), blake3::hash(v.as_bytes()).to_hex().to_string())
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

/// Exit code for `run` is the command's. For `explain` it is 0 when the
/// command would be skipped and 1 when it would run.
pub fn run(o: Opts, explain: bool) -> i32 {
    if o.argv.is_empty() {
        eprintln!("stoop: no command given");
        return 2;
    }
    if env_flag("STOOP_OFF") && !explain {
        return plain(&o.argv);
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
    let env_now = env_hashes(&env_names);

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
            return 0;
        }
        why = "STOOP_FULL is set".into();
    }
    if explain {
        eprintln!("stoop: would run {key}: {why}");
        return 1;
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
    let trace = match trace::run(&o.argv, &cwd, o.allow_network || !o.probes.is_empty()) {
        Ok(t) => t,
        Err(e) => {
            if !o.quiet {
                eprintln!("stoop: not traced ({e}); running without a proof");
            }
            return plain(&o.argv);
        }
    };
    let status = trace.status;
    if status != 0 || o.no_record {
        return status;
    }
    // The external state the command saw must still be what it was when it finished.
    let probes = match probes_before {
        None => {
            if !o.quiet {
                eprintln!("stoop: not recorded: a probe failed before the run, so the external state is unknown");
            }
            return status;
        }
        Some(before) => {
            if !o.probes.is_empty()
                && run_probes(&o.probes, &cwd, o.quiet).as_ref() != Some(&before)
            {
                if !o.quiet {
                    eprintln!("stoop: not recorded: a probe changed while the command ran");
                }
                return status;
            }
            before
        }
    };

    // 3. It passed: write down what it read.
    let ignore = Ignore::new(&o.ignore, Some(&root.join(".stoopignore")));
    match build_inputs(&root, &trace, &ignore) {
        Ok(inputs) => {
            let n = inputs.len();
            let outputs = build_outputs(&root, &trace, &ignore);
            let proof = Proof {
                created: now(),
                argv: o.argv.clone(),
                env: env_now,
                inputs,
                outputs,
                probes,
                removed: Vec::new(),
                ignore: None,
            };
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
            if let Some(r) = remote.as_ref().filter(|r| saved && r.write) {
                match r.push(&store, &key) {
                    Ok(()) if !o.quiet => eprintln!("stoop: published {key} to the remote"),
                    Ok(()) => {}
                    Err(e) => eprintln!("stoop: sync: could not publish ({e}); continuing"),
                }
            }
        }
        Err(why) => {
            if !o.quiet {
                eprintln!("stoop: not recorded: {why}");
            }
        }
    }
    status
}

/// What the run left behind inside the repository: created or rewritten files and
/// directories that still exist. Ignored paths are exempt, which is how a report
/// file nobody needs is kept from blocking skips.
pub fn build_outputs(root: &Path, trace: &Trace, ignore: &Ignore) -> Vec<Input> {
    let mut paths: Vec<(PathBuf, String)> = trace
        .written
        .iter()
        .filter(|p| p.starts_with(root))
        .map(|p| (p.clone(), to_key(root, p)))
        .filter(|(_, k)| {
            !k.is_empty() && !ignore.is_ignored(k) && !k.split('/').any(|c| c == ".git")
        })
        .collect();
    paths.sort();
    let ids = par_map(&paths, |(p, _)| identify(p, true, false));
    paths
        .into_iter()
        .zip(ids)
        .filter_map(|((_, key), id)| match id {
            // Gone again (a temp file): not an output. Unreadable: leave it out.
            Some(id) if id != "a" && id != "u" => Some(Input { path: key, id }),
            _ => None,
        })
        .collect()
}

/// Turn what the tracer saw into comparable inputs, or say why it cannot be trusted.
pub fn build_inputs(root: &Path, trace: &Trace, ignore: &Ignore) -> Result<Vec<Input>, String> {
    if let Some(u) = trace.unsound.first() {
        return Err(u.clone());
    }
    let mut cands: Vec<(PathBuf, String, bool, bool)> = Vec::new(); // (path, key, listed, inside)
    let mut reads_git = false;
    for (path, &listed) in &trace.touched {
        let inside = path.starts_with(root);
        let key = to_key(root, path);
        if key.is_empty() || ignore.is_ignored(&key) || trace.is_output(path) {
            continue;
        }
        if inside && key.split('/').any(|c| c == ".git") {
            reads_git = true;
            continue;
        }
        cands.push((path.clone(), key, listed, inside));
    }
    if reads_git {
        return Err("it reads .git, so a skip could hide a history change (add `.git` to .stoopignore if that read cannot change the result)".into());
    }
    let ids = par_map(&cands, |(p, _, listed, inside)| {
        let id = identify(p, *inside, *listed);
        // A symlink hides a second file; record where it points too.
        let target = match id.as_deref() {
            Some(s) if s.starts_with("l:") => std::fs::canonicalize(p).ok(),
            _ => None,
        };
        let tid = target
            .as_ref()
            .and_then(|t| identify(t, t.starts_with(root), false));
        (id, target, tid)
    });
    let mut out: Vec<Input> = Vec::with_capacity(cands.len());
    let mut seen = std::collections::HashSet::new();
    for ((_, key, _, _), (id, target, tid)) in cands.iter().zip(ids) {
        if let Some(id) = id {
            if seen.insert(key.clone()) {
                out.push(Input {
                    path: key.clone(),
                    id,
                });
            }
        }
        if let (Some(t), Some(tid)) = (target, tid) {
            let tk = to_key(root, &t);
            if !ignore.is_ignored(&tk) && !trace.is_output(&t) && seen.insert(tk.clone()) {
                out.push(Input { path: tk, id: tid });
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

#[cfg(test)]
mod flag_tests {
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
