//! Seeded models of a hooked suite whose changes include renames, re-added units and runner-only tests (issue #84, W7-3).
//! Each step applies one or more operations, then runs the subject (`STOOP_SPLIT=1`) and the runner run directly, and
//! their verdicts must agree. Runner-only tests (`tests/*.u`) are named by no hook, so the full command runs them and
//! no unit does. The first changed run of a suite with no unit proof is checked too: nothing exempts it.
//! These tests drive the stoop binary and the fake runner under the tracer, so they run on Linux x86-64 and arm64
//! only, as `units_split.rs` does.
#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod units_common;

use std::fs;
use std::process::Output;
use units_common::*;

/// The switch that turns the engine on (spec 3.1).
const SPLIT: (&str, &str) = ("STOOP_SPLIT", "1");

fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

/// The fake runner with one more reading (PR 86 review round 3): a listed line `stat:P` stats `P` and reads no content.
fn stat_runner() -> String {
    let fixture = include_str!("fixtures/hook/t");
    let anchor = "cat \"$ROOT/$line\"";
    assert_eq!(fixture.matches(anchor).count(), 1);
    fixture.replace(
        anchor,
        "case $line in\nstat:*) test -e \"$ROOT/${line#stat:}\" ;;\n*) cat \"$ROOT/$line\" ;;\nesac",
    )
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
    /// A unit's first listed source is stat-read instead of read (PR 86 review round 3): its line gains `stat:`.
    StatLine(String),
    /// A source file is removed, and each unit that lists it stops listing it in the same step (PR 86 review round 3).
    DropSource(usize),
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
            12 if units > 0 => Op::StatLine(self.units[rng.below(units)].clone()),
            13 => Op::DropSource(rng.below(4)),
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
            Op::StatLine(path) => {
                let body = fs::read_to_string(s.path(path)).unwrap_or_default();
                let stated: String = body
                    .lines()
                    .enumerate()
                    .map(|(index, line)| {
                        if index == 0 && !line.starts_with("stat:") {
                            format!("stat:{line}\n")
                        } else {
                            format!("{line}\n")
                        }
                    })
                    .collect();
                s.write(path, &stated);
            }
            Op::DropSource(n) => {
                let source = format!("src/s{n}");
                for unit in &self.units {
                    let body = fs::read_to_string(s.path(unit)).unwrap_or_default();
                    if body.lines().any(|line| line == source) {
                        let kept: String = body
                            .lines()
                            .filter(|line| *line != source)
                            .map(|line| format!("{line}\n"))
                            .collect();
                        s.write(unit, &kept);
                    }
                }
                if s.path(&source).exists() {
                    s.remove(&source);
                }
            }
            Op::Noop => {}
        }
    }
}

/// The sources that each unit lists, one per line, for the units whose files exist now. The model reads them before and
/// after each step, so its own history shows which unit stopped reading a path (PR 86 review round 2).
fn listings(
    s: &Suite,
    units: &[String],
) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
    units
        .iter()
        .filter_map(|unit| {
            let text = std::fs::read_to_string(s.path(unit)).ok()?;
            let lines: std::collections::BTreeSet<String> = text
                .lines()
                .filter(|line| !line.is_empty())
                .map(str::to_owned)
                .collect();
            Some((unit.clone(), lines))
        })
        .collect()
}

/// The path that a designed no-verdict line names, when the run printed exactly that line (PR 86 review round 2).
fn no_verdict_path(out: &std::process::Output) -> Option<String> {
    stderr(out).lines().find_map(|line| {
        let rest = line.strip_prefix("stoop: this run has no verdict (exit 125): ")?;
        let named = rest.strip_suffix(", and no unit's new proof reads it")?;
        named.strip_suffix(" changed").map(str::to_owned)
    })
}

/// Runs one seeded sequence. Every step's subject verdict must equal the runner's, and its status is never 2. A status of
/// 125 is accepted only as the designed no-verdict: the exact line, and an affected unit that stopped reading the path in
/// that step (PR 86 review round 2). Every launched argument is a unit of the roster.
fn run_world(seed: u64, steps: usize, runner_only: bool) -> Result<(), String> {
    let s = Suite::new();
    let mut rng = Rng::new(seed);
    let mut world = World::start(&s, &mut rng);
    s.executable("t", &stat_runner());
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
    let mut no_verdicts = 0usize;
    // An unchanged retry after a no-verdict (PR 86 review round 3): half the time, the step after a 125 applies nothing.
    let mut last_125 = false;
    for step in 1..=steps {
        let before = listings(&s, &world.units);
        let forced_noop = last_125 && rng.below(2) == 0;
        let count = if forced_noop { 1 } else { 1 + rng.below(3) };
        let mut ops = Vec::new();
        for _ in 0..count {
            let op = if forced_noop {
                Op::Noop
            } else {
                world.pick(&mut rng, runner_only)
            };
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
        last_125 = subject_code == 125;
        if subject_code == 2 {
            return Err(report("a status of 2"));
        }
        if subject_code == 125 {
            // The designed no-verdict (PR 86 review round 2): an affected unit stopped reading a changed source, and no
            // new proof reads it. The line must be exact, and this step's own listings must show that stop.
            let Some(path) = no_verdict_path(&subject) else {
                return Err(report("a status of 125 without the no-verdict line"));
            };
            let after = listings(&s, &world.units);
            let stopped = world.units.iter().any(|unit| {
                launches.contains(unit)
                    && after.get(unit).is_some_and(|new| {
                        // A launched unit that reads the path by stat only now, or that stopped listing it (PR 86 round 3).
                        new.contains(&format!("stat:{path}"))
                            || (before.get(unit).is_some_and(|old| old.contains(&path))
                                && !new.contains(&path))
                    })
            });
            if !stopped {
                return Err(report(&format!(
                    "the no-verdict line names {path}, which no launched unit stopped reading"
                )));
            }
            no_verdicts += 1;
            println!("NO VERDICT ACCEPTED (x02 shape): seed {seed}, step {step}, {path}");
            if no_verdicts * 3 > steps {
                return Err(report("too many no-verdicts in one sequence"));
            }
        } else if (subject_code == 0) != (code(&oracle) == 0) {
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

/// The two seeds of the PR 82 reviewer's model whose first changed runs gave the wrong verdict before the fix: seed 2059
/// at step 30 and seed 2091 at step 14 (issue #84). The default range does not reach them, so they run by name.
#[test]
fn model_seeds_that_found_issue_84_agree_with_the_runner() {
    for seed in [2059, 2091] {
        if let Err(why) = run_world(seed, 30, true) {
            panic!("{why}");
        }
    }
}
