#!/usr/bin/env python3
"""Run named round-four mutant killers against the checked-out product revision."""
import pathlib
import subprocess

MUTANTS = [
    ("r4a-stat-unread", "src/units/attribution.rs", "        || stat_unread\n", "        || false\n", "r4_a_head_failing_excuser_takes_the_full_form"),
    ("r4b-removed-unit", "src/units/engine.rs", "if let Some((unit, _)) = view.units.iter().find(|(unit, versions)| {\n        !versions.is_empty()", "if let Some((unit, _)) = view.units.iter().find(|(unit, versions)| {\n        false && !versions.is_empty()", "r4_b_head_departed_unit_required_by_the_runner_takes_the_full_form"),
    ("b11-outside-input", "src/units/engine.rs", ".filter(|input| Path::new(&input.path).is_absolute())", ".filter(|_| false)", "t1_an_outside_root_input_change_beside_an_own_file_edit_takes_the_full_form"),
    ("d2-unlisted-appearance", "src/units/engine.rs", ".filter(|input| input.id == \"a\")\n        .find(|input| {", ".filter(|_| false)\n        .find(|input| {", "t1_an_absent_input_that_appears_in_an_unlisted_directory_takes_the_full_form"),
    ("e2-new-unit", "src/units/engine.rs", "if let Some(unit) = cx.roster.iter().find(|unit| {\n        !proof", "if let Some(unit) = cx.roster.iter().find(|unit| {\n        false && !proof", "r5c_a_new_unit_that_the_runner_policy_rejects_takes_the_full_form"),
]

def test(name):
    result = subprocess.run(["cargo", "test", "--test", "units_review_r2", "--", "--exact", name], capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr

for mutant, path, old, new, name in MUTANTS:
    rc, output = test(name)
    if rc != 0 or f"test {name} ... ok" not in output:
        raise SystemExit(f"BASELINE FAILED {mutant} / {name}\n{output}")
    target = pathlib.Path(path)
    original = target.read_text()
    if original.count(old) != 1:
        raise SystemExit(f"MUTANT ANCHOR {mutant}: expected one, got {original.count(old)}")
    try:
        target.write_text(original.replace(old, new, 1))
        rc, output = test(name)
        if rc != 101 or f"test {name} ... FAILED" not in output:
            raise SystemExit(f"MUTANT SURVIVED OR DID NOT COMPILE {mutant} / {name} (exit {rc})\n{output}")
        print(f"KILLED {mutant} by {name}", flush=True)
    finally:
        target.write_text(original)
