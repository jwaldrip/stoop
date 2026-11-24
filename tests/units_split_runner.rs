//! Seeded models of a hooked suite whose changes include renames, re-added units and runner-only tests (issue #84, W7-3).
//! Each step applies one or more operations, then runs the subject (`STOOP_SPLIT=1`) and the runner run directly, and
//! their verdicts must agree. Runner-only tests (`tests/*.u`) are named by no hook, so the full command runs them and
//! no unit does. The first changed run of a suite with no unit proof is checked too: nothing exempts it.
mod units_common;

use std::fs;
use std::process::Output;
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// The pinned hook under `env`, with the engine on.
fn split(s: &Suite, env: &[(&str, &str)]) -> Output {
    let mut all = vec![SPLIT];
    all.extend_from_slice(env);
    s.hook(&all)
}

/// The argument words of each launch since the log was cleared.
fn launched(s: &Suite) -> Vec<String> {
    s.launches()
        .iter()
        .map(|launch| launch.args.join(" "))
        .collect()
}

fn count_from_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// A small deterministic generator, so that a failing seed reproduces.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn draw(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.draw() % n.max(1) as u64) as usize
    }
}

#[derive(Clone, Debug)]
enum Op {
    /// A unit or runner-only test's flag becomes `fail`, `ok`, or is removed.
    Flag(String, &'static str),
    /// A source file's content changes.
    Source(usize),
    /// A unit's listed sources are rewritten.
    Rewrite(String),
    /// A new unit.
    Add(String),
    /// A deleted unit's name comes back.
    Readd(String),
    Delete(String),
    /// A unit is renamed, with its flag.
    Rename(String, String),
    AddRunnerOnly(String),
    DeleteRunnerOnly(String),
    /// The setup file, which every unit reads.
    Setup,
    Noop,
}

struct World {
    units: Vec<String>,
    deleted: Vec<String>,
    runner_only: Vec<String>,
    next: usize,
    revision: usize,
}

/// One to three distinct sources, one per line.
fn sources_line(rng: &mut Rng) -> String {
    let count = 1 + rng.below(3);
    let mut picked: Vec<usize> = Vec::new();
    while picked.len() < count {
        let source = rng.below(4);
        if !picked.contains(&source) {
            picked.push(source);
        }
    }
    picked.iter().map(|n| format!("src/s{n}\n")).collect()
}

/// The flag file that the fake runner reads for a test: the same path with `.flag` in place of its extension.
fn flag_of(path: &str) -> String {
    format!("{}.flag", path.rsplit_once('.').unwrap().0)
}

impl World {
    fn start(s: &Suite, rng: &mut Rng) -> World {
        for unit in ["tests/a.t", "tests/b.t", "tests/c.t"] {
            s.remove(unit);
        }
        s.remove("e2e/x.u");
        for n in 0..4 {
            s.write(&format!("src/s{n}"), "source\n");
        }
        let mut world = World {
            units: Vec::new(),
            deleted: Vec::new(),
            runner_only: Vec::new(),
            next: 0,
            revision: 0,
        };
        for _ in 0..6 {
            let name = world.fresh("t");
            s.write(&name, &sources_line(rng));
            world.units.push(name);
        }
        world.units.sort();
        world
    }

    fn fresh(&mut self, ext: &str) -> String {
        let name = format!("tests/m{}.{ext}", self.next);
        self.next += 1;
        name
    }

    fn pick(&mut self, rng: &mut Rng, runner_only: bool) -> Op {
        let units = self.units.len();
        let choice = rng.below(if runner_only { 17 } else { 14 });
        match choice {
            0..=2 => {
                let kind = ["fail", "ok", "removed"][choice];
                let pool: Vec<String> = self
                    .units
                    .iter()
                    .chain(&self.runner_only)
                    .cloned()
                    .collect();
                Op::Flag(pool[rng.below(pool.len())].clone(), kind)
            }
            3 | 4 => Op::Source(rng.below(4)),
            5 => Op::Rewrite(self.units[rng.below(units)].clone()),
            6 if units < 9 => Op::Add(self.fresh("t")),
            7 if units > 2 => Op::Delete(self.units[rng.below(units)].clone()),
            8 if !self.deleted.is_empty() && units < 9 => {
                Op::Readd(self.deleted[rng.below(self.deleted.len())].clone())
            }
            9 | 10 => {
                let from = self.units[rng.below(units)].clone();
                Op::Rename(from, self.fresh("t"))
            }
            11 => Op::Setup,
            14 | 15 if self.runner_only.len() < 3 => Op::AddRunnerOnly(self.fresh("u")),
            16 if !self.runner_only.is_empty() => {
                Op::DeleteRunnerOnly(self.runner_only[rng.below(self.runner_only.len())].clone())
            }
            _ => Op::Noop,
        }
    }

    fn apply(&mut self, s: &Suite, rng: &mut Rng, op: &Op) {
        match op {
            Op::Flag(path, kind) => {
                let flag = flag_of(path);
                match *kind {
                    "fail" => s.write(&flag, "fail\n"),
                    "ok" => s.write(&flag, "ok\n"),
                    _ => {
                        if s.path(&flag).exists() {
                            s.remove(&flag);
                        }
                    }
                }
            }
            Op::Source(n) => {
                self.revision += 1;
                s.write(
                    &format!("src/s{n}"),
                    &format!("revision {}\n", self.revision),
                );
            }
            Op::Rewrite(path) => s.write(path, &sources_line(rng)),
            Op::Add(path) | Op::Readd(path) => {
                s.write(path, &sources_line(rng));
                self.deleted.retain(|gone| gone != path);
                self.units.push(path.clone());
                self.units.sort();
            }
            Op::Delete(path) => {
                s.remove(path);
                self.units.retain(|unit| unit != path);
                self.deleted.push(path.clone());
            }
            Op::Rename(from, to) => {
                fs::rename(s.path(from), s.path(to)).unwrap();
                if s.path(&flag_of(from)).exists() {
                    fs::rename(s.path(&flag_of(from)), s.path(&flag_of(to))).unwrap();
                }
                self.units.retain(|unit| unit != from);
                self.deleted.push(from.clone());
                self.units.push(to.clone());
                self.units.sort();
            }
            Op::AddRunnerOnly(path) => {
                s.write(path, &sources_line(rng));
                self.runner_only.push(path.clone());
            }
            Op::DeleteRunnerOnly(path) => {
                s.remove(path);
                if s.path(&flag_of(path)).exists() {
                    s.remove(&flag_of(path));
                }
                self.runner_only.retain(|other| other != path);
            }
            Op::Setup => {
                self.revision += 1;
                s.write("setup.src", &format!("setup {}\n", self.revision));
            }
            Op::Noop => {}
        }
    }
}

/// Runs one seeded sequence. Every step's subject verdict must equal the runner's, its status is never 2 or 125, and
/// every launched argument is a unit of the roster.
fn run_world(seed: u64, steps: usize, runner_only: bool) -> Result<(), String> {
    let s = Suite::new();
    let mut rng = Rng::new(seed);
    let mut world = World::start(&s, &mut rng);
    let env: Vec<(&str, &str)> = if runner_only {
        vec![("T_U", "1")]
    } else {
        Vec::new()
    };
    let cold = split(&s, &env);
    if code(&cold) != 0 {
        return Err(format!(
            "seed {seed}: the cold run failed: {}",
            stderr(&cold)
        ));
    }
    let mut log: Vec<String> = Vec::new();
    for step in 1..=steps {
        let count = 1 + rng.below(3);
        let mut ops = Vec::new();
        for _ in 0..count {
            let op = world.pick(&mut rng, runner_only);
            world.apply(&s, &mut rng, &op);
            ops.push(op);
        }
        log.push(format!("step {step}: {ops:?}"));
        s.clear_log();
        let subject = split(&s, &env);
        let launches = launched(&s);
        s.clear_log();
        let oracle = s.direct(&s.root, &[], &env);
        let report = |why: &str| {
            format!(
                "{why}\nseed {seed}, step {step}\noperations:\n  {}\nsubject exit {}, oracle exit {}, launches {launches:?}\nsubject stderr:\n{}",
                log.join("\n  "),
                code(&subject),
                code(&oracle),
                stderr(&subject)
            )
        };
        let subject_code = code(&subject);
        if subject_code == 2 || subject_code == 125 {
            return Err(report("a status of 2 or 125"));
        }
        if (subject_code == 0) != (code(&oracle) == 0) {
            return Err(report("WRONG VERDICT"));
        }
        if let Some(bad) = launches
            .iter()
            .find(|launch| !launch.is_empty() && !world.units.contains(launch))
        {
            return Err(report(&format!("a launch named {bad}, not a roster unit")));
        }
    }
    Ok(())
}

/// Seeds come from `STOOP_RUNNER_FIRST` (1 by default) for `STOOP_RUNNER_SEEDS` (4 by default), and steps from
/// `STOOP_RUNNER_STEPS` (30). Every failing seed is reported, and the first one is shown in full.
fn check_range(runner_only: bool) {
    let first = count_from_env("STOOP_RUNNER_FIRST", 1) as u64;
    let seeds = count_from_env("STOOP_RUNNER_SEEDS", 4) as u64;
    let steps = count_from_env("STOOP_RUNNER_STEPS", 30);
    let mut failures = Vec::new();
    for seed in first..first + seeds {
        if let Err(why) = run_world(seed, steps, runner_only) {
            failures.push(why);
        }
    }
    assert!(
        failures.is_empty(),
        "{} failing seeds; first:\n{}",
        failures.len(),
        failures.first().cloned().unwrap_or_default()
    );
}

/// The renames and re-added units, with the default hook (no runner-only tests).
#[test]
fn model_readds_and_renames_give_the_full_runs_verdict() {
    check_range(false);
}

/// The same operations with runner-only tests that the hook does not name, which the full command runs under `T_U=1`.
#[test]
fn model_runner_only_tests_give_the_full_runs_verdict() {
    check_range(true);
}
