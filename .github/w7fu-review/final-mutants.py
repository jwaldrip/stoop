#!/usr/bin/env python3
"""Apply one review mutant and print the regression that must kill it."""
from pathlib import Path
import sys

r2 = Path("tests/units_review_r2.rs")
common = Path("tests/units_common/mod.rs")
model = Path("tests/units_common/engine_model.rs")
replacement = '''                        fs::read_to_string(s.path(&flag)).is_ok_and(|content| {
                            e3_valid_flag_reader(
                                &after_stored,
                                &s,
                                &candidates,
                                &flag,
                                &content,
                                &env,
                                None,
                            )
                        })'''
old_reader_against_post = '''                        previous_flag.is_some_and(|content| {
                            let old_id = format!("f:{}", blake3::hash(content.as_bytes()).to_hex());
                            e3_valid_flag_reader(
                                &stored, &s, &candidates, &flag, content, &env,
                                Some((&flag, &old_id)),
                            )
                        })'''
mutants = {
    "FU1-ignore-runner-file": (r2, "if &current != previous {", "if current.1.as_ref() != previous.1.as_ref() {", "r10_runner_change_requires_different_file_or_flag_bytes"),
    "FU2-ignore-runner-flag": (r2, "if &current != previous {", "if current.0.as_ref() != previous.0.as_ref() {", "r10_runner_change_requires_different_file_or_flag_bytes"),
    "FU3-old-proof-as-current": (r2, "|| evidence.held_current_content)", "|| evidence.stored_content)", "r10_current_held_reader_does_not_excuse_a_stale_first_skip"),
    "FU4-unrelated-failure-sticky": (r2, "divergence.failing.contains(test)\n                && !divergence.changed.contains(test)", "!divergence.changed.contains(test)", "r10_mixed_failure_rejects_unexplained_or_changed_runners"),
    "FU5-changed-failure-sticky": (r2, "divergence.failing.contains(test)\n                && !divergence.changed.contains(test)", "divergence.failing.contains(test)", "r10_mixed_failure_rejects_unexplained_or_changed_runners"),
    "FU6-unchanged-flag-origin": (r2, "} else if evidence.flag_flipped\n        && ((", "} else if true\n        && ((", "r10_current_held_reader_does_not_excuse_a_stale_first_skip"),
    "FU7-no-current-content-reader": (r2, "if !evidence.runner_only || !evidence.current_content {", "if !evidence.runner_only {", "r10_current_held_reader_does_not_excuse_a_stale_first_skip"),
    "FU8-non-runner-gap": (r2, "if !evidence.runner_only || !evidence.current_content {", "if !evidence.current_content {", "e3_gap_accepts_only_the_two_owner_approved_shapes"),
    "FU9-independent-policy-sticky": (r2, "        && policy_failures.is_empty()\n", "", "r8_sticky_rejects_independent_policy_and_runner_edits"),
    "FU10-ignore-guard": (common, 'if version["guard"].as_str() != Some(guard) {', 'if false && version["guard"].as_str() != Some(guard) {', "r11_reader_rejects_a_stale_guard_in_every_proof_based_exemption"),
    "FU11-ignore-inputs": (common, 'if current.as_deref() != Some(id) {', 'if field == "outputs" && current.as_deref() != Some(id) {', "r11_reader_rejects_a_stale_input_in_every_proof_based_exemption"),
    "FU12-ignore-outputs": (common, 'if current.as_deref() != Some(id) {', 'if field == "inputs" && current.as_deref() != Some(id) {', "r11_reader_rejects_a_stale_output_in_every_proof_based_exemption"),
    "FU13-unvalidated-sticky": (r2, "if evidence.sticky_reader_valid\n        && previous", "if previous", "r11_reader_rejects_a_stale_guard_in_every_proof_based_exemption"),
    "FU14-stale-proof-for-e5": (r2, "evidence.appeared_test_content.then_some(E3Gap::E5)", "(evidence.appeared_test_content || evidence.stored_content).then_some(E3Gap::E5)", "r11_reader_rejects_a_stale_guard_in_every_proof_based_exemption"),
    "FU15-ignore-forced": (model, "    if forced {\n", "    if false && forced {\n", "r12_forced_run_rejects_the_simulated_skip"),
    "FU16-ignore-roster": (model, "    if roster.iter().any(|unit| {\n        !whole_roster", "    if false && roster.iter().any(|unit| {\n        !whole_roster", "r12_new_roster_rejects_the_simulated_skip"),
    "FU17-old-reader-on-post-tree": (r2, replacement, old_reader_against_post, "r11x_a_same_step_source_edit_preserves_a_genuine_launched_w22"),
    "FU18-ignore-environment": (model, 'if bundle["guard_digest"].as_str() != Some(guard.as_str()) {', 'if false && bundle["guard_digest"].as_str() != Some(guard.as_str()) {', "r12_environment_change_rejects_the_simulated_skip"),
    "FU19-ignore-shared-input": (model, 'return ModelDecision::Full("shared input");', 'continue;', "r12_shared_input_change_rejects_the_simulated_skip"),
    "FU20-no-replacement-proof": (r2, replacement, replacement.replace("&after_stored,", "&stored,"), "r11x_a_same_step_source_edit_preserves_a_genuine_launched_w22"),
    "FU21-ignore-required-launches": (r2, "if units != &launched_units {", "if false && units != &launched_units {", "r12_mixed_failures_need_the_second_reader_to_launch"),
}
name = sys.argv[1]
source, old, new, killer = mutants[name]
text = source.read_text()
if text.count(old) != 1:
    raise SystemExit(f"{name}: expected one anchor, found {text.count(old)}")
source.write_text(text.replace(old, new, 1))
print(killer)
