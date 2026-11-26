#!/usr/bin/env python3
"""Apply one W7 follow-up model mutant; the workflow checks its named killer."""
from pathlib import Path
import sys

source = Path("tests/units_review_r2.rs")
mutants = {
    "FU1-ignore-runner-file": (
        "if &current != previous {",
        "if current.1.as_ref() != previous.1.as_ref() {",
        "r10_runner_change_requires_different_file_or_flag_bytes",
    ),
    "FU2-ignore-runner-flag": (
        "if &current != previous {",
        "if current.0.as_ref() != previous.0.as_ref() {",
        "r10_runner_change_requires_different_file_or_flag_bytes",
    ),
    "FU3-old-proof-as-current": (
        "|| evidence.held_current_content)",
        "|| evidence.stored_content)",
        "r10_current_held_reader_does_not_excuse_a_stale_first_skip",
    ),
    "FU4-unrelated-failure-sticky": (
        "divergence.failing.contains(test)\n                && !divergence.changed.contains(test)",
        "!divergence.changed.contains(test)",
        "r10_mixed_failure_rejects_unexplained_or_changed_runners",
    ),
    "FU5-changed-failure-sticky": (
        "divergence.failing.contains(test)\n                && !divergence.changed.contains(test)",
        "divergence.failing.contains(test)",
        "r10_mixed_failure_rejects_unexplained_or_changed_runners",
    ),
    "FU6-unchanged-flag-origin": (
        "} else if evidence.flag_flipped\n        && ((",
        "} else if true\n        && ((",
        "r10_current_held_reader_does_not_excuse_a_stale_first_skip",
    ),
    "FU7-no-current-content-reader": (
        "if !evidence.runner_only || !evidence.current_content {",
        "if !evidence.runner_only {",
        "r10_current_held_reader_does_not_excuse_a_stale_first_skip",
    ),
    "FU8-non-runner-gap": (
        "if !evidence.runner_only || !evidence.current_content {",
        "if !evidence.current_content {",
        "e3_gap_accepts_only_the_two_owner_approved_shapes",
    ),
    "FU9-independent-policy-sticky": (
        "        && policy_failures.is_empty()\n",
        "",
        "r8_sticky_rejects_independent_policy_and_runner_edits",
    ),
}
name = sys.argv[1]
old, new, killer = mutants[name]
text = source.read_text()
if text.count(old) != 1:
    raise SystemExit(f"{name}: expected one anchor, found {text.count(old)}")
source.write_text(text.replace(old, new, 1))
print(killer)
