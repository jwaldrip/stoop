#!/usr/bin/env python3
"""W7-3 mutation matrix, PR 86 review round 1. Each mutant patches the tree in place: every patch's anchor must occur
exactly once. Every named killer runs once on the unpatched tree first and must pass there (a killer that does not pass
there is UNUSABLE and never counted). A mutant is KILLED when a usable killer FAILS under it. Files are restored from git
after each mutant, including when a mutant cannot be applied."""
import re
import subprocess
import sys

ENGINE = "src/units/engine.rs"
SUBSET = "src/units/subset.rs"
RUN = "src/run.rs"
BUNDLE = "src/units/bundle.rs"
ATTR = "src/units/attribution.rs"
UNIT = "bin"
C = "units_completion"
R = "units_review_w7_3"
S = "units_split"
SR = "units_split_runner"
D = "units_decide"
RL = "run::units::bundle::keep_tests::"
RE = "run::units::engine::tests::"


def k(binary, name):
    return (binary, name)


MUTANTS = [
    {"id": "M1", "name": "completion removed",
     "patches": [(RUN, "            if split {\n                units::subset::learn(", "            if false {\n                units::subset::learn(")],
     "killers": [k(C, "c1_a_failing_full_run_learns_nothing_and_the_fixed_one_learns_every_unit")]},
    {"id": "M2", "name": "completion changes the status",
     "patches": [(SUBSET, "    if !disabled && complete {", "    if disabled {\n        std::process::exit(1);\n    }\n    if !disabled && complete {")],
     "killers": [k(C, "c2_a_unit_that_fails_alone_while_the_full_command_passes_disables_the_suite")]},
    {"id": "M3", "name": "a failed completion launch does not disable",
     "patches": [(SUBSET, "    if let Some(unit) = &ran.failed {", "    if let Some(unit) = &ran.failed.as_ref().filter(|_| false) {")],
     "killers": [k(C, "c2_a_unit_that_fails_alone_while_the_full_command_passes_disables_the_suite")]},
    {"id": "M4", "name": "completion runs in CI",
     "patches": [(ATTR, "    if policy::ci() {\n        return Err(Refusal::Ci);\n    }\n    if config.splitting_disabled", "    if policy::ci() && false {\n        return Err(Refusal::Ci);\n    }\n    if config.splitting_disabled")],
     "killers": [k(C, "c5_a_ci_run_never_completes")]},
    {"id": "M5", "name": "completion re-runs units with valid versions",
     "patches": [(ENGINE, "    Ok(analyse(cx, view, &current)\n        .into_iter()\n        .map(|affected| affected.unit)\n        .collect())", "    let _ = analyse(cx, view, &current);\n    Ok(cx.roster.to_vec())")],
     "killers": [k(C, "c7_a_completion_relaunches_only_the_units_without_a_valid_proof")]},
    {"id": "M6", "name": "E9 still replaces the full command under the switch (two sites)",
     "patches": [(ENGINE, "    }) {\n        return verdict(Decision::Full(None), None, false);", "    }) {\n        return verdict(Decision::Legacy, None, false);"),
                 (RUN, "    if !engine_full && !split {", "    if !engine_full {")],
     "killers": [k(C, "c4_the_first_changed_run_takes_the_full_form_when_no_unit_holds_a_proof"),
                 k(SR, "model_seeds_that_found_issue_84_agree_with_the_runner")]},
    {"id": "M7", "name": "residue confirmed without every unit holding a version",
     "patches": [(ENGINE, "    analyse(cx, view, &current).is_empty()\n}", "    let _ = analyse(cx, view, &current);\n    true\n}")],
     "killers": [k(UNIT, RE + "a_residue_is_confirmed_only_when_every_roster_unit_holds_a_version")]},
    {"id": "M8", "name": "explain predicts a different launch count",
     "patches": [(ENGINE, "            analyse(&judged, &view, &current).len()", "            analyse(&judged, &view, &current).len() + 1")],
     "killers": [k(C, "c7_a_completion_relaunches_only_the_units_without_a_valid_proof")]},
    {"id": "M9", "name": "a busy lock is not silent at completion",
     "patches": [(SUBSET, "        Kept::Busy | Kept::Unavailable | Kept::Declined(_) => return,", "        Kept::Busy => {\n            say(cx.o.quiet, \"stoop: busy\".to_owned());\n            return;\n        }\n        Kept::Unavailable | Kept::Declined(_) => return,")],
     "killers": [k(C, "c6_a_busy_suite_lock_stops_completion_silently")]},
    {"id": "M10", "name": "a completion violation does not disable",
     "patches": [(SUBSET, "    if let Some((_, violation)) = &ran.stopped {", "    if let Some((_, violation)) = &ran.stopped.as_ref().filter(|_| false) {")],
     "killers": [k(C, "c8_a_completion_violation_disables_the_suite")]},
    {"id": "M11", "name": "completion runs with the switch off",
     "patches": [(RUN, "            if split {\n                units::subset::learn(", "            if true {\n                units::subset::learn(")],
     "killers": [k(C, "c9_the_switch_off_learns_nothing_after_a_full_run")]},
    {"id": "M12", "name": "failing full runs are recorded, so completion learns after one",
     "patches": [(RUN, "    if status != 0 {\n        return Outcome {\n            status,\n            key,\n            how: How::Failed,", "    if status != 0 && false {\n        return Outcome {\n            status,\n            key,\n            how: How::Failed,")],
     "killers": [k(C, "c1_a_failing_full_run_learns_nothing_and_the_fixed_one_learns_every_unit")]},
    {"id": "M13", "name": "completion launches no unit",
     "patches": [(SUBSET, "    let ran = attribution::launch_each(\n        cx,\n        hook,\n        &ignore,\n        &mut pass,\n        &units,", "    let units: Vec<String> = Vec::new();\n    let ran = attribution::launch_each(\n        cx,\n        hook,\n        &ignore,\n        &mut pass,\n        &units,")],
     "killers": [k(C, "c1_a_failing_full_run_learns_nothing_and_the_fixed_one_learns_every_unit"),
                 k(C, "c7_a_completion_relaunches_only_the_units_without_a_valid_proof")]},
    {"id": "M14", "name": "explain under STOOP_OFF predicts a learning run",
     "patches": [(ENGINE, "        return None;\n    }\n    attribution::roster_screen(cx, hook, config, pending).ok()?;", "    }\n    attribution::roster_screen(cx, hook, config, pending).ok()?;")],
     "killers": [k(C, "c11_explain_under_stoop_off_predicts_no_learning")]},
    {"id": "N1", "name": "confirm without the every-unit-valid check (residue labelled confirmed with a stale unit)",
     "patches": [(SUBSET, "engine::holds(&judged, view)", "{ let _ = (&judged, view); true }")],
     "killers": [k(R, "w03b_a_stale_unit_unrecorded_at_completion_leaves_the_residue_unconfirmed"),
                 k(UNIT, RE + "a_residue_is_confirmed_only_when_every_roster_unit_holds_a_version")]},
    {"id": "N2", "name": "explain predicts learning on a whole-command hit (runs_full gate dropped)",
     "patches": [(RUN, "if explain && split && !o.quiet && runs_full && records {", "if explain && split && !o.quiet && (runs_full || true) && records {")],
     "killers": [k(R, "w11_a_whole_command_hit_predicts_no_learning"),
                 k(C, "c3_explain_predicts_the_completion_launches_and_the_run_makes_them"),
                 k(C, "c5_a_ci_run_never_completes")]},
    {"id": "N3", "name": "explain predicts learning for a disabled suite",
     "patches": [(ENGINE, "            if view.disabled.is_some() {\n                return None;\n            }\n", "            let _ = view.disabled.is_some();\n")],
     "killers": [k(R, "w01_a_completion_disagreement_disables_and_the_next_change_is_full"),
                 k(C, "c2_a_unit_that_fails_alone_while_the_full_command_passes_disables_the_suite")]},
    {"id": "N5", "name": "completion learns even when the residue is known and empty",
     "patches": [(ENGINE, "    if !wanted {\n        return Err(\"the residue is known and empty\");\n    }\n", "    let _ = wanted;\n")],
     "killers": [k(S, "s5_a_setup_change_runs_full_and_the_next_change_is_a_subset"),
                 k(R, "w08_explain_predicts_the_completion_in_every_full_state"),
                 k(UNIT, RE + "learn_declines_when_the_residue_is_known_and_empty")]},
    {"id": "N6", "name": "completion's writer-side check does not know the held proofs of units it does not relaunch",
     "patches": [(SUBSET, "        named.store(&unit, &paths(&inputs), &paths(&outputs));\n    }\n    let ran = attribution::launch_each(\n        cx,\n        hook,\n        &ignore,",
                  "        let _ = (&unit, &inputs, &outputs);\n    }\n    let ran = attribution::launch_each(\n        cx,\n        hook,\n        &ignore,")],
     "killers": [k(R, "w12_a_completion_write_into_a_valid_units_input_disables"),
                 k(C, "c8_a_completion_violation_disables_the_suite")]},
    {"id": "N7", "name": "the completion phase is not stored (a disabled completion reads as subset)",
     "patches": [(SUBSET, "    pass.set_phase(\"completion\");\n", "")],
     "killers": [k(C, "c2_a_unit_that_fails_alone_while_the_full_command_passes_disables_the_suite"),
                 k(C, "c8_a_completion_violation_disables_the_suite"),
                 k(R, "w01_a_completion_disagreement_disables_and_the_next_change_is_full"),
                 k(R, "w02_a_completion_launch_that_never_reads_its_unit_disables")]},
    {"id": "N8", "name": "E9 keeps the legacy decision at the engine (explain line only; the run.rs gate stays)",
     "patches": [(ENGINE, "        return verdict(Decision::Full(None), None, false);\n    }\n    let proof = cx.proofs", "        return verdict(Decision::Legacy, None, false);\n    }\n    let proof = cx.proofs")],
     "killers": [k(C, "c12_explain_with_a_bundle_and_no_unit_proof_names_the_full_form"),
                 k(C, "c3_explain_predicts_the_completion_launches_and_the_run_makes_them"),
                 k(C, "c4_the_first_changed_run_takes_the_full_form_when_no_unit_holds_a_proof"),
                 k(R, "w07_ci_one_never_learns_and_explain_agrees"),
                 k(SR, "model_seeds_that_found_issue_84_agree_with_the_runner")]},
    {"id": "N9", "name": "the run.rs switch gate on the attribution pass removed (only the gate half of M6)",
     "patches": [(RUN, "    if !engine_full && !split {", "    if !engine_full {")],
     "killers": [k(C, "c4_the_first_changed_run_takes_the_full_form_when_no_unit_holds_a_proof"),
                 k(SR, "model_seeds_that_found_issue_84_agree_with_the_runner"),
                 k(D, "explain_before_any_unit_proof_prints_what_the_switch_off_prints"),
                 k(R, "w07_ci_one_never_learns_and_explain_agrees")]},
    {"id": "M15", "name": "a skip that drops the last readers of a path is not taken as the full form (residue stays confirmed after a version is dropped)",
     "patches": [(ENGINE, "        if skip.drop && units_that_left_held_a_reader(cx, view) {", "        if false {")],
     "killers": [k(UNIT, RE + "a_skip_cannot_drop_the_last_reader_of_a_whole_input"),
                 k(R, "w21_a_runner_only_test_a_deleted_unit_read_keeps_the_full_verdict")]},
    {"id": "M16", "name": "readers counted by stat (a stat-only read counts as a content read)",
     "patches": [(BUNDLE, "        Some(now_content) => *content && !now_content,", "        Some(_) => false,")],
     "killers": [k(UNIT, RL + "a_path_whose_last_content_reader_turns_stat_only_is_lost")]},
    {"id": "M17", "name": "residue unknown only after a drop, not after a subset replacement (the record path keeps the residue)",
     "patches": [(BUNDLE, "            self.bundle.residue = Residue::default();\n            self.residue_lost = true;", "            let _ = removed.len();")],
     "killers": [k(R, "w20_a_runner_only_test_that_a_unit_stopped_reading_keeps_the_full_verdict")]},
    {"id": "M18", "name": "every input id counts as content",
     "patches": [(BUNDLE, "    id == \"a\"\n        || id == \"u\"\n", "    !id.is_empty()\n        || id == \"u\"\n")],
     "killers": [k(UNIT, RL + "only_content_ids_read_content"),
                 k(UNIT, RL + "a_path_whose_last_content_reader_turns_stat_only_is_lost")]},
    {"id": "M19", "name": "confirm labels the residue without the digest check",
     "patches": [(BUNDLE, "    if bundle.whole.as_deref() != Some(proof_digest) {\n        return Settled::Declined;\n    }", "    let _ = proof_digest;")],
     "killers": [k(UNIT, RL + "a_confirm_for_another_whole_proof_is_declined")]},
    {"id": "M20", "name": "learn without the whole-proof check",
     "patches": [(ENGINE, "    if !cx.proofs.iter().any(|proof| proof.digest() == view.whole) {\n        return Err(\"the bundle holds another whole proof\");\n    }", "    let _ = cx.proofs.len();")],
     "killers": [k(UNIT, RE + "learn_declines_a_bundle_that_holds_another_whole_proof")]},
    {"id": "M21", "name": "a lost residue is re-measured at pass end (the final check is skipped, so the residue is known again)",
     "patches": [(BUNDLE, "            {\n                return;\n            }\n            self.lost_paths.clear();", "            {\n                let _ = readers.len();\n            }\n            self.lost_paths.clear();")],
     "killers": [k(UNIT, RL + "a_path_lost_by_the_passes_last_write_keeps_the_residue_unknown"), k(UNIT, RL + "a_path_lost_by_a_dropped_version_keeps_the_residue_unknown")]},
    {"id": "M22", "name": "the skip counts every table entry, not only the roster units' inputs",
     "patches": [(ENGINE, "        units: cx.roster.len(),\n        inputs,\n", "        units: cx.roster.len(),\n        inputs: view.table.len(),\n")],
     "killers": [k(UNIT, RE + "a_skip_counts_only_the_roster_units_inputs")]},
    {"id": "M23", "name": "sticky loss: a lost path never heals (the rule before this change)",
     "patches": [(BUNDLE, "                .any(|path| readers.get(path) != Some(&true))", "                .any(|_| true)")],
     "killers": [k(UNIT, RL + "a_path_a_later_write_of_the_pass_reads_again_keeps_the_residue")]},
    {"id": "M24", "name": "a write's own loss is not evaluated, so the pass's last write loses nothing",
     "patches": [(BUNDLE, "        self.note_losses(&removed);", "        let _ = removed.len();")],
     "killers": [k(UNIT, RL + "a_path_lost_by_the_passes_last_write_keeps_the_residue_unknown")]},
    {"id": "M25", "name": "a stat-only later read counts as a content reader",
     "patches": [(BUNDLE, "readers.get(path) != Some(&true)", "!readers.contains_key(path)")],
     "killers": [k(UNIT, RL + "a_path_a_later_write_reads_only_as_a_stat_stays_lost")]},
    {"id": "M26", "name": "the final check sees no version, so a later write never heals a loss",
     "patches": [(BUNDLE, "let readers = bundle_readers(&self.bundle.table, self.bundle.units.values().flatten());", "let readers = bundle_readers(&self.bundle.table, self.bundle.units.values().take(0).flatten());")],
     "killers": [k(UNIT, RL + "a_path_a_later_write_of_the_pass_reads_again_keeps_the_residue"), k(UNIT, RL + "a_path_read_by_an_unrewritten_unit_is_not_lost_at_the_pass")]},
    {"id": "M27", "name": "a version that a kept pass drops for a unit that left the roster records no loss",
     "patches": [(BUNDLE, "        self.note_losses(&dropped);", "        let _ = dropped.len();")],
     "killers": [k(UNIT, RL + "a_path_lost_by_a_dropped_version_keeps_the_residue_unknown")]},
    {"id": "M29", "name": "a write's check ignores the kept versions, so an unrewritten unit's read does not count",
     "patches": [(BUNDLE, "        let now = bundle_readers(&self.bundle.table, self.bundle.units.values().flatten());", "        let now = bundle_readers(&self.bundle.table, self.bundle.units.values().take(0).flatten());")],
     "killers": [k(UNIT, RL + "a_path_read_by_an_unrewritten_unit_is_not_lost_at_the_pass")]},
]


def run_tests(binary, names):
    results = {}
    for name in names:
        if binary == UNIT:
            command = ["cargo", "test", "--bin", "stoop", "--", "--exact", name]
        else:
            command = ["cargo", "test", "--test", binary, "--", "--exact", name]
        proc = subprocess.run(command, capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        if re.search(rf"^test {re.escape(name)} \.\.\. ok$", out, re.M):
            results[name] = "PASS"
        elif re.search(rf"^test {re.escape(name)} \.\.\. FAILED$", out, re.M):
            results[name] = "FAILED"
        elif re.search(r"^error(\[E\d+\])?: ", out, re.M):
            results[name] = "BUILD"
        else:
            results[name] = "NOTFOUND"
    return results


def main():
    killers = sorted({key for mutant in MUTANTS for key in mutant["killers"]})
    baseline = {}
    for binary, name in killers:
        baseline[(binary, name)] = run_tests(binary, [name])[name]
        print(f"baseline {baseline[(binary, name)]:9} {binary} {name}", flush=True)
        if baseline[(binary, name)] != "PASS":
            raise SystemExit(f"baseline failed: {binary} {name}: {baseline[(binary, name)]}")
    rows = []
    problems = []
    for mutant in MUTANTS:
        originals = {}
        applied = True
        try:
            for path, old, new in mutant["patches"]:
                text = open(path, encoding="utf-8").read()
                originals.setdefault(path, text)
                if text.count(old) != 1:
                    applied = False
                    problems.append(mutant["id"])
                    rows.append((mutant["id"], "INVALID", mutant["name"], [f"{text.count(old)} matches in {path}"]))
                    break
                open(path, "w", encoding="utf-8").write(text.replace(old, new))
            if not applied:
                continue
            usable = [key for key in mutant["killers"] if baseline[key] == "PASS"]
            detail = [f"UNUSABLE baseline={baseline[key]} {key[1]}" for key in mutant["killers"] if key not in usable]
            killed = False
            for binary, name in usable:
                status = run_tests(binary, [name])[name]
                detail.append(f"{status} {binary} {name}")
                print(f"{mutant['id']} {binary} {name}: {status}", flush=True)
                if status in ("BUILD", "NOTFOUND"):
                    problems.append(f"{mutant['id']}: {status} {binary} {name}")
                if status == "FAILED":
                    killed = True
            verdict = "KILLED" if killed else ("UNTESTED" if not usable else "SURVIVED")
            if verdict != "KILLED" and not (mutant["id"] == "N9" and verdict == "SURVIVED"):
                problems.append(f"{mutant['id']}: {verdict}")
            rows.append((mutant["id"], verdict, mutant["name"], detail))
        finally:
            for path, text in originals.items():
                open(path, "w", encoding="utf-8").write(text)
    print("\nW7-3 REVIEW ROUND 1 MUTANT MATRIX")
    for mid, verdict, name, detail in rows:
        print(f"{mid:4} {verdict:9} {name}")
        for line in detail:
            print(f"        {line}")
    killed_count = sum(1 for row in rows if row[1] == "KILLED")
    print(f"\nSUMMARY {killed_count} of {len(MUTANTS)} killed; problems: {problems or 'none'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
