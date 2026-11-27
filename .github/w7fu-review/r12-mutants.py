#!/usr/bin/env python3
"""Apply one E3 decision mutant and name the regression that must kill it."""
from pathlib import Path
import sys

model = Path("tests/units_common/engine_model.rs")
e3 = Path("tests/units_review_r2.rs")
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
    "FU15-ignore-forced": (model, "    if forced {\n", "    if false && forced {\n", "r12_forced_run_rejects_the_simulated_skip"),
    "FU16-ignore-roster": (model, "    if roster.iter().any(|unit| {\n        !whole_roster", "    if false && roster.iter().any(|unit| {\n        !whole_roster", "r12_new_roster_rejects_the_simulated_skip"),
    "FU17-old-reader-on-post-tree": (e3, replacement, old_reader_against_post, "r11x_a_same_step_source_edit_preserves_a_genuine_launched_w22"),
    "FU18-ignore-environment": (model, 'if bundle["guard_digest"].as_str() != Some(guard.as_str()) {', 'if false && bundle["guard_digest"].as_str() != Some(guard.as_str()) {', "r12_environment_change_rejects_the_simulated_skip"),
    "FU19-ignore-shared-input": (model, 'return ModelDecision::Full("shared input");', 'continue;', "r12_shared_input_change_rejects_the_simulated_skip"),
    "FU20-no-replacement-proof": (e3, replacement, replacement.replace("&after_stored,", "&stored,"), "r11x_a_same_step_source_edit_preserves_a_genuine_launched_w22"),
    "FU21-ignore-required-launches": (e3, "if units != &launched_units {", "if false && units != &launched_units {", "r12_mixed_failures_need_the_second_reader_to_launch"),
}
name = sys.argv[1]
source, old, new, killer = mutants[name]
text = source.read_text()
if text.count(old) != 1:
    raise SystemExit(f"{name}: expected one anchor, found {text.count(old)}")
source.write_text(text.replace(old, new, 1))
print(killer)
