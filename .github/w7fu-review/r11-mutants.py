#!/usr/bin/env python3
"""Apply one E3 mutant; the workflow requires its named regression to fail."""
from pathlib import Path
import sys

r2 = Path("tests/units_review_r2.rs")
common = Path("tests/units_common/mod.rs")
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
}
name = sys.argv[1]
source, old, new, killer = mutants[name]
text = source.read_text()
if text.count(old) != 1:
    raise SystemExit(f"{name}: expected one anchor, found {text.count(old)}")
source.write_text(text.replace(old, new, 1))
print(killer)
