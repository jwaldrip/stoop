mod attest;
#[allow(dead_code)]
mod gha;
#[allow(dead_code)]
mod gitprobe;
#[allow(dead_code)]
mod gittree;
mod ignore;
mod input;
#[allow(dead_code)]
mod job;
mod journal;
mod oid_attrs;
mod pathutil;
#[allow(dead_code)]
mod plan;
mod proof;
mod run;
mod stepkey;
mod sync;
mod trace;
mod volatile;

use run::Opts;
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

const HELP: &str = "\
stoop: run only what matters.

Wrap a command. If everything it read last time it passed is unchanged, it is
skipped. Otherwise it runs, and what it reads is recorded. No input lists.

USAGE
  stoop run [options] -- <command> [args...]    skip or run (the default)
  stoop explain [options] -- <command> [args...] say what would run and why
  stoop sh <script> [args...]                   shell mode for CI (see below)
  stoop ls [--store DIR]                        list recorded proofs
  stoop forget [--volatile] <key> [--store DIR]  drop a proof (--volatile: what was learned)
  stoop plan [options]                          plan experimental job skips
  stoop pull | prune [--sync git[:remote]]       fetch or expire shared proofs

OPTIONS
  --key NAME        name the proof (default: derived from the command)
  --root DIR        repository root (default: nearest directory with .git)
  --store DIR       where proofs live (default: <root>/.stoop, or $STOOP_STORE)
  --env NAME        also require this variable (the whole environment already counts)
  --ignore-env NAME exempt a variable that changes without mattering
  --no-learn-volatile  do not learn variables that change on every run (see BLIND SPOTS)
  --allow-network   record runs that used the network (see BLIND SPOTS)
  --max-age DUR     a proof stops counting after DUR (default 7d; 0 = never)
  --probe CMD       external state to verify: CMD's output must match for a skip
                    (repeatable; declares that a networked step is covered)
  --sync SPEC       share proofs through the git remote (see SHARING PROOFS)
  --sync-write      publish proofs to the remote (trusted runs only)
  --ignore PATTERN  paths whose reads do not count (also .stoopignore)
  --no-record       check and run, but never write a proof (untrusted jobs)
  --allow-id-token  allow names in STOOP_PASS_ENV; runs untraced and unrecorded
  --literal         treat placeholders as ordinary text (no changed-unit hooks)
  --quiet           print nothing about the decision

ENVIRONMENT
  STOOP_FULL=1      never skip; still record (nightly runs)
  STOOP_OFF=1       do not trace or skip anything
                    (switches: empty, 0, false, no and off mean off; anything else is on)
  STOOP_PASS_ENV    comma- or space-separated OIDC request variable names to pass;
                    requires --allow-id-token and disables proof use for the run
  STOOP_LEARN_VOLATILE=0  same as --no-learn-volatile (empty, 0, false, no and off mean off)

GITHUB ACTIONS
  Put this at the top of a workflow and every `run:` step is wrapped:
    defaults:
      run:
        shell: stoop sh {0}

SHARING PROOFS
  --sync git[:REMOTE]  fetch proofs from the repository's git remote on a miss
                       (refs/stoop/<key>); no server to host. Or set STOOP_SYNC.
  --sync-write         publish proofs to it. Off by default: only trusted runs
                       (the default branch) should write. Or STOOP_SYNC_WRITE=1.
  stoop pull           fetch every published proof once, at the start of a job
  stoop prune          delete published proofs older than --max-age (needs write)
  Without push access, cache the `.stoop/` directory with the CI's own cache.

BLIND SPOTS
  stoop sees files, not behavior. It cannot see the network, the clock, or
  randomness. Runs that use the network are not recorded (--allow-network
  overrides). Proofs expire (--max-age) and STOOP_FULL=1 re-proves everything,
  which bounds what the clock can hide. Output the command writes inside the
  repository must still be in place for a skip; list throwaway output in
  .stoopignore.
  Variables that change on every run (a timestamp, a per-job id) are learned after four
  runs and then ignored, unless the command text names them. A curated list covers the
  common CI and terminal ones. A variable that really changes what a command does, and
  takes a new value on every run, would be ignored too. `stoop forget --volatile KEY`
  resets what was learned for a key; `--env NAME` counts a name again.
";

fn main() {
    run::capture_id_token_env();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    std::process::exit(real_main(args));
}

fn real_main(mut args: Vec<OsString>) -> i32 {
    let Some(first) = args.first() else {
        print!("{HELP}");
        return 0;
    };
    let cmd = match first.to_str() {
        Some("-h") | Some("--help") | Some("help") => {
            print!("{HELP}");
            return 0;
        }
        Some("--version") | Some("-V") | Some("version") => {
            println!("stoop {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Some(c @ ("run" | "explain" | "sh" | "ls" | "forget" | "pull" | "prune" | "plan")) => {
            let c = c.to_string();
            args.remove(0);
            c
        }
        _ => "run".to_string(),
    };
    if cmd == "plan" {
        return plan::cmd(&args);
    }
    let (mut o, rest) = match parse(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("stoop: {e}\n\n{HELP}");
            return 2;
        }
    };
    if matches!(cmd.as_str(), "run" | "explain" | "sh") {
        match run::parse_pass_env(
            std::env::var_os("STOOP_PASS_ENV").as_deref(),
            o.allow_id_token,
        ) {
            Ok(names) => o.pass_env = names,
            Err(error) => {
                eprintln!("stoop: {error}");
                return 2;
            }
        }
    }
    match cmd.as_str() {
        "ls" => {
            let store = store_for(&o);
            for proof in store.list() {
                let dirs = proof
                    .dirs
                    .iter()
                    .map(|dir| format!("{dir:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let platforms = proof
                    .platforms
                    .iter()
                    .map(|platform| format!("{platform:?}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ignored = proof
                    .ignored
                    .iter()
                    .map(|name| run::safe(name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let ignores = if ignored.is_empty() {
                    String::new()
                } else {
                    format!("\tignores {ignored}")
                };
                println!(
                    "{}\t{} proofs\t{} inputs\tcreated {}\tdir {dirs}\tplatform {platforms}{ignores}",
                    proof.key, proof.count, proof.inputs, proof.created
                );
            }
            for (key, n, created, steps) in jobs_for(&o).list() {
                println!("{key}\t{n} records\t{steps} steps\tcreated {created}");
            }
            match run::volatile_listing(&o) {
                Ok(lines) => {
                    for line in lines {
                        println!("{line}");
                    }
                }
                Err(error) => eprintln!("{error}"),
            }
            0
        }
        "forget" => {
            let Some(key) = rest.first() else {
                eprintln!("stoop: forget needs a key");
                return 2;
            };
            // A proof is named by text. A word that is not UTF-8 names no proof, so none is removed.
            let Some(key) = proof_name(key) else {
                eprintln!(
                    "stoop: no proof named {}",
                    run::safe(&key.to_string_lossy())
                );
                return 1;
            };
            let key = key.as_str();
            if o.volatile_forget {
                return match run::forget_volatile(&o, &proof::sanitize(key)) {
                    Ok(true) => 0,
                    Ok(false) => {
                        eprintln!("stoop: nothing was learned under {key}");
                        1
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        1
                    }
                };
            }
            let hook = run::forget_hook_records(&o, &proof::sanitize(key));
            if let Err(warning) = &hook {
                eprintln!("{warning}");
            }
            let result = if key.starts_with("job-") {
                jobs_for(&o).forget(&proof::sanitize(key))
            } else {
                store_for(&o).forget(&proof::sanitize(key))
            };
            match result {
                Ok(true) => 0,
                Ok(false) if matches!(hook, Ok(true)) => 0,
                Ok(false) => {
                    eprintln!("stoop: no proof named {key}");
                    1
                }
                Err(e) => {
                    eprintln!("stoop: {e}");
                    1
                }
            }
        }
        "pull" => match sync_for(&o) {
            Err(e) => {
                eprintln!("stoop: {e}");
                2
            }
            Ok(r) => match r.pull_all(&store_for(&o), &jobs_for(&o)) {
                Ok(n) => {
                    if !o.quiet {
                        eprintln!("stoop: pulled {n} new proofs");
                    }
                    0
                }
                // Sync never fails a job: a remote that is down means a cold run, not a red build.
                Err(e) => {
                    eprintln!("stoop: sync: could not pull proofs ({e}); continuing");
                    0
                }
            },
        },
        "prune" => match sync_for(&o) {
            Err(e) => {
                eprintln!("stoop: {e}");
                2
            }
            Ok(r) => {
                let age = o.max_age.unwrap_or(run::DEFAULT_MAX_AGE);
                match r.prune(age) {
                    Ok(n) => {
                        eprintln!("stoop: removed {n} expired proofs from the remote");
                        0
                    }
                    Err(e) => {
                        eprintln!("stoop: {e}");
                        1
                    }
                }
            }
        },
        "sh" => {
            let Some(script) = rest.first() else {
                eprintln!("stoop: sh needs a script path");
                return 2;
            };
            shell_mode(&mut o, script, &rest[1..])
        }
        c => {
            o.argv = rest;
            run::run(o, c == "explain")
        }
    }
}

fn sync_for(o: &Opts) -> Result<sync::Remote, String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = run::root_for(o, &cwd);
    let spec = o
        .sync
        .clone()
        .or_else(|| run::env_str("STOOP_SYNC"))
        .ok_or("no remote configured: pass --sync git[:remote] or set STOOP_SYNC")?;
    let write = o.sync_write || run::env_flag("STOOP_SYNC_WRITE");
    sync::Remote::from_spec(&spec, &root, write)
}

fn store_for(o: &Opts) -> proof::Store {
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = run::root_for(o, &cwd);
    proof::Store::new(run::store_for(o, &cwd, &root))
}

fn jobs_for(o: &Opts) -> job::JobStore {
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = run::root_for(o, &cwd);
    job::JobStore::new(run::store_for(o, &cwd, &root))
}

fn parse(args: &[OsString]) -> Result<(Opts, Vec<OsString>), String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        // A word that is not UTF-8 is an ordinary word, unless it begins with "-": that marks an
        // option, which stoop refuses as an unknown option.
        let Some(a) = args[i].to_str() else {
            if args[i].as_encoded_bytes().starts_with(b"-") {
                return Err(format!(
                    "unknown option {}",
                    run::safe(&args[i].to_string_lossy())
                ));
            }
            break;
        };
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with("--") {
            break;
        }
        let mut val = |name: &str| -> Result<String, String> {
            i += 1;
            let raw = args.get(i).ok_or_else(|| format!("{name} needs a value"))?;
            raw.to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("{name} needs a UTF-8 value"))
        };
        match a {
            "--key" => o.key = Some(val("--key")?),
            "--root" => o.root = Some(PathBuf::from(val("--root")?)),
            "--store" => o.store = Some(PathBuf::from(val("--store")?)),
            "--env" => o.env.push(val("--env")?),
            "--ignore" => o.ignore.push(val("--ignore")?),
            "--no-record" => o.no_record = true,
            "--allow-id-token" => o.allow_id_token = true,
            "--literal" => o.literal = true,
            "--allow-network" => o.allow_network = true,
            "--ignore-env" => o.ignore_env.push(val("--ignore-env")?),
            "--no-learn-volatile" => o.no_learn_volatile = true,
            "--volatile" => o.volatile_forget = true,
            "--max-age" => o.max_age = Some(run::parse_age(&val("--max-age")?)?),
            "--probe" => o.probes.push(val("--probe")?),
            "--sync" => o.sync = Some(val("--sync")?),
            "--sync-write" => o.sync_write = true,
            "--quiet" => o.quiet = true,
            _ => return Err(format!("unknown option {a}")),
        }
        i += 1;
    }
    Ok((o, args[i..].to_vec()))
}

/// `stoop sh {0}`: GitHub Actions hands over a script file for each `run:` step.
/// The file's name changes every time, so the key comes from its contents, and
/// the file itself is not an input.
fn shell_mode(o: &mut Opts, script: &OsStr, rest: &[OsString]) -> i32 {
    let body = match std::fs::read(script) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "stoop: cannot read {}: {e}",
                run::safe(&script.to_string_lossy())
            );
            return 2;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = run::root_for(o, &cwd);
    let matrix = match stepkey::canonical_matrix(&std::env::var("STOOP_MATRIX").unwrap_or_default())
    {
        Ok(matrix) => matrix,
        Err(error) => {
            eprintln!("stoop: invalid STOOP_MATRIX: {error}");
            None
        }
    };
    o.key = Some(stepkey::sh_key(
        &body,
        &std::env::var("GITHUB_WORKFLOW").unwrap_or_default(),
        &std::env::var("GITHUB_JOB").unwrap_or_default(),
        &pathutil::cwd_key(&root, &cwd),
        rest,
        matrix.as_deref(),
    ));
    o.shell_key = true;
    o.transient.push(script.to_string_lossy().into_owned());
    o.transient
        .push(pathutil::to_key(&root, std::path::Path::new(script)));
    o.mention = String::from_utf8_lossy(&body).into_owned();
    let mut argv: Vec<OsString> = ["bash", "--noprofile", "--norc", "-eo", "pipefail"]
        .into_iter()
        .map(OsString::from)
        .collect();
    argv.push(script.to_os_string());
    argv.extend(rest.iter().cloned());
    o.argv = argv;
    let blocked =
        run::env_str("RUNNER_TEMP").map(|t| PathBuf::from(t).join("stoop/journal.blocked"));
    if !o.pass_env.is_empty() {
        if run::env_switch("GITHUB_ACTIONS", true) {
            if let Some(path) = &blocked {
                let result =
                    std::fs::create_dir_all(path.parent().expect("journal marker has a parent"))
                        .and_then(|()| std::fs::write(path, b"OIDC request credentials passed"));
                if let Err(error) = result {
                    eprintln!("stoop: cannot block job journal before passing OIDC request credentials: {error}");
                    return 2;
                }
            }
        }
        return run::run_outcome(std::mem::take(o), false).status;
    }
    let remote = sync_for(o).ok();
    let mut journal = if blocked.as_ref().is_some_and(|p| p.exists()) {
        None
    } else {
        match journal::Journal::open(
            &root,
            matrix.as_deref(),
            remote.as_ref().is_some_and(|r| r.write),
        ) {
            Ok(journal) => journal,
            Err(error) => {
                eprintln!("stoop: job record not written: {error}");
                if let Some(path) = &blocked {
                    if let Some(parent) = path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                        let _ = std::fs::write(path, b"blocked");
                    }
                }
                None
            }
        }
    };
    let journal_error = journal
        .as_mut()
        .and_then(|j| j.before(o.key.as_deref().unwrap_or_default()).err());
    if let Some(error) = journal_error {
        eprintln!("stoop: journal: {error}; continuing");
        journal = None;
    }
    let proofs = store_for(o);
    let jobs = jobs_for(o);
    o.defer_push =
        journal.as_ref().is_some_and(|j| j.eligible()) && remote.as_ref().is_some_and(|r| r.write);
    let o = std::mem::take(o);
    let outcome = run::run_outcome(o, false);
    if let Some(journal) = &mut journal {
        if let Err(error) = journal.after(&outcome, &jobs, &proofs, remote.as_ref()) {
            eprintln!("stoop: journal: {error}; continuing");
        }
    }
    outcome.status
}

/// The name of a proof is text. A name that is not UTF-8 names no proof, so none is removed.
fn proof_name(key: &OsStr) -> Option<String> {
    key.to_str().map(str::to_owned)
}

#[cfg(test)]
mod forget_name_tests {
    use super::proof_name;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn a_non_utf8_proof_name_names_no_proof() {
        assert_eq!(proof_name(OsStr::new("cat-1")), Some("cat-1".to_string()));
        assert_eq!(proof_name(OsStr::from_bytes(b"\xff")), None);
    }
}
