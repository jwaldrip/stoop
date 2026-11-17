mod ignore;
mod input;
mod pathutil;
mod proof;
mod run;
mod trace;

use run::Opts;
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
  stoop forget <key> [--store DIR]              drop a proof

OPTIONS
  --key NAME        name the proof (default: derived from the command)
  --root DIR        repository root (default: nearest directory with .git)
  --store DIR       where proofs live (default: <root>/.stoop, or $STOOP_STORE)
  --env NAME        also require this variable (the whole environment already counts)
  --ignore-env NAME exempt a variable that changes without mattering
  --allow-network   record runs that used the network (see BLIND SPOTS)
  --max-age DUR     a proof stops counting after DUR (default 7d; 0 = never)
  --probe CMD       external state to verify: CMD's output must match for a skip
                    (repeatable; declares that a networked step is covered)
  --ignore PATTERN  paths whose reads do not count (also .stoopignore)
  --no-record       check and run, but never write a proof (untrusted jobs)
  --quiet           print nothing about the decision

ENVIRONMENT
  STOOP_FULL=1      never skip; still record (nightly runs)
  STOOP_OFF=1       do not trace or skip anything

GITHUB ACTIONS
  Put this at the top of a workflow and every `run:` step is wrapped:
    defaults:
      run:
        shell: stoop sh {0}

BLIND SPOTS
  stoop sees files, not behavior. It cannot see the network, the clock, or
  randomness. Runs that use the network are not recorded (--allow-network
  overrides). Proofs expire (--max-age) and STOOP_FULL=1 re-proves everything,
  which bounds what the clock can hide. Output the command writes inside the
  repository must still be in place for a skip; list throwaway output in
  .stoopignore.
";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(real_main(args));
}

fn real_main(mut args: Vec<String>) -> i32 {
    let cmd = match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{HELP}");
            return 0;
        }
        Some("--version") | Some("-V") | Some("version") => {
            println!("stoop {}", env!("CARGO_PKG_VERSION"));
            return 0;
        }
        Some(c @ ("run" | "explain" | "sh" | "ls" | "forget")) => {
            let c = c.to_string();
            args.remove(0);
            c
        }
        Some(_) => "run".to_string(),
    };
    let (mut o, rest) = match parse(&args) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("stoop: {e}\n\n{HELP}");
            return 2;
        }
    };
    match cmd.as_str() {
        "ls" => {
            let store = store_for(&o);
            for (key, n, created, inputs) in store.list() {
                println!("{key}\t{n} proofs\t{inputs} inputs\tcreated {created}");
            }
            0
        }
        "forget" => {
            let Some(key) = rest.first() else {
                eprintln!("stoop: forget needs a key");
                return 2;
            };
            match store_for(&o).forget(&proof::sanitize(key)) {
                Ok(true) => 0,
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

fn store_for(o: &Opts) -> proof::Store {
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = o.root.clone().unwrap_or_else(|| run::find_root(&cwd));
    proof::Store::new(
        o.store
            .clone()
            .or_else(|| std::env::var_os("STOOP_STORE").map(PathBuf::from))
            .unwrap_or_else(|| root.join(".stoop")),
    )
}

fn parse(args: &[String]) -> Result<(Opts, Vec<String>), String> {
    let mut o = Opts::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if !a.starts_with("--") {
            break;
        }
        let mut val = |name: &str| -> Result<String, String> {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match a {
            "--key" => o.key = Some(val("--key")?),
            "--root" => o.root = Some(PathBuf::from(val("--root")?)),
            "--store" => o.store = Some(PathBuf::from(val("--store")?)),
            "--env" => o.env.push(val("--env")?),
            "--ignore" => o.ignore.push(val("--ignore")?),
            "--no-record" => o.no_record = true,
            "--allow-network" => o.allow_network = true,
            "--ignore-env" => o.ignore_env.push(val("--ignore-env")?),
            "--max-age" => o.max_age = Some(run::parse_age(&val("--max-age")?)?),
            "--probe" => o.probes.push(val("--probe")?),
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
fn shell_mode(o: &mut Opts, script: &str, rest: &[String]) -> i32 {
    let body = match std::fs::read(script) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("stoop: cannot read {script}: {e}");
            return 2;
        }
    };
    let cwd = std::env::current_dir().unwrap_or_default();
    let root = o.root.clone().unwrap_or_else(|| run::find_root(&cwd));
    let mut h = blake3::Hasher::new();
    h.update(&body);
    for v in ["GITHUB_WORKFLOW", "GITHUB_JOB"] {
        h.update(std::env::var(v).unwrap_or_default().as_bytes());
        h.update(&[0]);
    }
    h.update(pathutil::to_key(&root, &cwd).as_bytes());
    o.key = Some(format!("sh-{}", &h.finalize().to_hex()[..20]));
    o.ignore.push(script.to_string());
    o.ignore
        .push(pathutil::to_key(&root, std::path::Path::new(script)));
    o.mention = String::from_utf8_lossy(&body).into_owned();
    let mut argv = vec![
        "bash".to_string(),
        "--noprofile".into(),
        "--norc".into(),
        "-eo".into(),
        "pipefail".into(),
        script.to_string(),
    ];
    argv.extend(rest.iter().cloned());
    o.argv = argv;
    let o = std::mem::take(o);
    run::run(o, false)
}
