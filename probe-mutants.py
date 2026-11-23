#!/usr/bin/env python3
"""Single-site mutants of the W7-1 engine, each run against the decision tests.

A mutant is one or more exact, unique text substitutions. A substitution that does not match exactly once marks the
mutant BROKEN, which is not a kill. A mutant that does not compile is COMPILE, which is not a kill either. A mutant is
KILLED when at least one of its named tests fails, and SURVIVED when none does. The source is restored after each run.
This file lives only on a probe branch and is never merged.
"""
import os
import pathlib
import re
import subprocess

ENGINE = "src/units/engine.rs"
RUN = "src/run.rs"
MAIN = "src/main.rs"

# (id, what it breaks, file, [(old, new)], tests that must fail)
MUTANTS = [
    ("m01", "a changed unit output is ignored", ENGINE,
     [("    for &index in &version.outputs {", "    for &index in version.outputs.iter().take(0) {")],
     ["t8_a_deleted_unit_output_is_not_a_skip"]),
    ("m02", "an output only the full form writes is not checked (E15)", ENGINE,
     [("    proof.outputs.iter().find_map(|output| {", "    proof.outputs.iter().take(0).find_map(|output| {")],
     ["t9_an_output_only_the_full_form_writes_is_checked"]),
    ("m03", "the residue gate is removed (E12, known and non-empty)", ENGINE,
     [("        Some((count, paths)) if *count > 0 => {", "        Some((count, paths)) if *count > 0 && false => {")],
     ["t4_residue_takes_the_full_form_and_names_it"]),
    ("m04", "an unknown residue counts as covered", ENGINE,
     [("        None => {", "        _ if false => {"), ("        Some(_) => {}", "        Some(_) => {}\n        _ => {}")],
     ["t5_a_failing_unit_leaves_the_residue_unmatched"]),
    ("m05", "g1 (the environment of the whole proof) is removed", ENGINE,
     [("    if whole_guard(proof) != cx.guard {", "    if false && whole_guard(proof) != cx.guard {")],
     ["t7_a_new_environment_variable_takes_the_full_form"]),
    ("m06", "g2 (a change every unit reads) is removed", ENGINE,
     [("    if let Some(path) = global_change(cx, view, proof, &current) {",
       "    if let Some(path) = global_change(cx, view, proof, &current).filter(|_| false) {")],
     ["t6_a_change_every_unit_reads_takes_the_full_form"]),
    ("m07", "a unit with no proof is treated as held", ENGINE,
     [("            affected.push((unit.clone(), NEW.to_owned()));", "            let _ = NEW;")],
     ["t10_a_new_unit_is_not_skipped"]),
    ("m08", "E11 (a unit that left the roster but stays) is removed", ENGINE,
     [("    if let Some(reason) = leftover(cx, view) {", "    if let Some(reason) = leftover(cx, view).filter(|_| false) {")],
     ["t11_a_unit_that_leaves_the_roster_while_its_file_stays_is_named"]),
    ("m09", "explain takes the lock and decides from a busy suite", ENGINE,
     [("    let Some(view) = bundle::view(store, pending, key) else {",
       "    if matches!(bundle::drop_stale(store, pending, key, |_| false), Settled::Busy) {\n"
       "        return plain();\n    }\n    let Some(view) = bundle::view(store, pending, key) else {")],
     ["t14_explain_writes_nothing_launches_nothing_and_takes_no_lock"]),
    ("m10", "the switch is on when STOOP_SPLIT is unset", ENGINE,
     [('    std::env::var_os("STOOP_SPLIT").map(|value| on(&value))',
       '    std::env::var_os("STOOP_SPLIT").map(|value| on(&value)).or(Some(true))')],
     ["t3_the_switch_off_keeps_the_full_form"]),
    ("m11", "a unit skip reports as ran", MAIN,
     [('        run::How::UnitsSkipped => ("skipped", "units", true),', '        run::How::UnitsSkipped => ("ran", "units", true),')],
     ["t17_a_skip_reports_units_on_the_status_descriptor"]),
    ("m12", "the disagreement check is removed", RUN,
     [("            units::engine::disagree(&volatile_store, pending, &outcome.key, o.quiet);",
       "            let _ = (&volatile_store, pending, &outcome.key, o.quiet);")],
     ["t15_a_failing_full_run_against_held_proofs_disables_the_suite"]),
    ("m13", "the disagreement check ignores the affected units", RUN,
     [("    let armed = clean && (forced || engine_full);", "    let armed = forced || engine_full;")],
     ["t16_a_failing_forced_run_with_an_affected_unit_does_not_disable"]),
    ("m14", "a skip keeps the versions of units that left the roster", RUN,
     [("        Some(units::engine::Decision::Skip(skip)) if skip.drop && !explain => match &pending {",
       "        Some(units::engine::Decision::Skip(skip)) if false && skip.drop && !explain => match &pending {")],
     ["t19_a_skip_drops_the_proof_of_a_unit_that_was_removed"]),
    ("m15", "a version made under another environment is not checked (own)", ENGINE,
     [("    if version.guard != cx.guard {", "    if false && version.guard != cx.guard {")],
     ["t18_a_unit_proof_made_under_another_environment_is_affected"]),
    ("m16", "the maximum age of a proof is not checked (own)", ENGINE,
     [("    if cx.max_age > 0 && cx.now.saturating_sub(version.created) > cx.max_age {",
       "    if false && cx.max_age > 0 && cx.now.saturating_sub(version.created) > cx.max_age {")],
     ["an_expired_unit_proof_is_affected"]),
    ("m17", "g2 uses the union of the units' reads, not their intersection (own)", ENGINE,
     [("    shared.retain(|path| reads.iter().all(|read| read.contains(path)));",
       "    shared.retain(|path| reads.iter().any(|read| read.contains(path)));")],
     ["t20_a_change_that_not_every_unit_reads_is_not_global"]),
    ("m18", "a changed input does not make its unit affected (own)", ENGINE,
     [("        if !current.holds(input) {", "        if false && !current.holds(input) {")],
     ["t6_a_change_every_unit_reads_takes_the_full_form", "t21_explain_names_only_the_affected_units"]),
    ("m19", "a disabled suite is not refused (E8, own)", ENGINE,
     [("    if let Some(label) = &view.disabled {", "    if let Some(label) = &view.disabled.as_ref().filter(|_| false) {")],
     ["t12_a_disabled_suite_takes_the_full_form_and_names_it"]),
    ("m20", "a suite with no proofs yet is judged as full, not left to the pass (E9, own)", ENGINE,
     [("        return verdict(Decision::Legacy, None, false);", "        return verdict(Decision::Full(None), None, false);")],
     ["t13_explain_and_the_run_agree_in_every_state"]),
    ("m21", "the engine's reason does not replace the legacy reason (own)", RUN,
     [("        lookup.why = reason;", "        let _ = reason;")],
     ["t7_a_new_environment_variable_takes_the_full_form"]),
    ("m22", "explain does not judge through the engine (own)", RUN,
     [("    let verdict = split", "    let verdict = (split && !explain)")],
     ["t21_explain_names_only_the_affected_units"]),
    ("m23", "the value off counts as on (own)", ENGINE,
     [('"" | "0" | "false" | "no" | "off"', '"" | "0" | "false" | "no"')],
     ["t3_the_switch_off_keeps_the_full_form"]),
    ("m24", "the skip line drops the key (own)", ENGINE,
     [('"stoop: skip {key}: no tracked input changed', '"stoop: skip: no tracked input changed')],
     ["t1_an_unchanged_run_after_a_pass_skips"]),
    ("m25", "the disagreement check ignores whether the residue is covered (own)", ENGINE,
     [("    let clean = affected.is_empty() && covered;", "    let clean = affected.is_empty();")],
     ["t22_a_failing_forced_run_with_a_residue_does_not_disable"]),
]


def apply(path, pairs):
    text = pathlib.Path(path).read_text()
    for old, new in pairs:
        count = text.count(old)
        if count != 1:
            return f"anchor matches {count} times: {old.strip()[:70]!r}"
        text = text.replace(old, new)
    pathlib.Path(path).write_text(text)
    return None


def main():
    env = dict(os.environ, CARGO_INCREMENTAL="0")
    selected = os.environ.get("MUTANTS", "")
    ids = set(selected.split()) if selected else None
    results = []
    for ident, what, path, pairs, expect in MUTANTS:
        if ids and ident not in ids:
            continue
        broken = apply(path, pairs)
        if broken:
            results.append(f"{ident} BROKEN: {broken}")
            subprocess.run(["git", "checkout", "--", path], check=False)
            continue
        try:
            run = subprocess.run(
                ["cargo", "test", "--test", "units_decide", "--", "--test-threads=1"],
                capture_output=True, text=True, env=env, timeout=1800,
            )
            log = run.stdout + run.stderr
            if "error[E" in log or "could not compile" in log:
                results.append(f"{ident} COMPILE: {what}")
                continue
            failing = set(re.findall(r"^test (\S+) \.\.\. FAILED$", log, re.M))
            killed_by = [test for test in expect if test in failing]
            verdict = "KILLED" if killed_by else "SURVIVED"
            results.append(
                f"{ident} {verdict}: {what}; named {killed_by or expect}; "
                f"failing {sorted(failing)}"
            )
        finally:
            subprocess.run(["git", "checkout", "--", path], check=False)
    for line in results:
        print(f"MUTANT {line}")


if __name__ == "__main__":
    main()
