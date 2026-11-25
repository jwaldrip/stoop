#!/usr/bin/env python3
"""Applies one named mutant to the tree. Each mutant must match exactly once, or the job fails loudly."""
import pathlib
import sys

MUTANTS = {
    "m1-rule-removed": (
        "src/units/subset.rs",
        "ran.uncovered = attribution::uncovered_inputs(&plan.uncovered, &ran.proven);",
        "ran.uncovered = Vec::new();",
    ),
    "m2-absent-exemption-dropped": (
        "src/units/engine.rs",
        ".filter(|&&input| !fresh.holds(input) && !fresh.absent(input))",
        ".filter(|&&input| !fresh.holds(input))",
    ),
    "m3-stale-versions-count-as-kept": (
        "src/units/engine.rs",
        ".filter(|version| version_reasons(cx, view, current, version).0.is_empty())",
        ".filter(|_version| true)",
    ),
    "m4-record-measures-stale": (
        "src/units/bundle.rs",
        "        if !residue_known(&bundle.residue, digest) {\n            bundle.residue = Residue::default();\n        }",
        "        store_residue(&mut bundle, &proof.inputs, digest, pending.listings());",
    ),
    "m5-no-verdict-line-missing": (
        "src/units/attribution.rs",
        "        for path in &ran.uncovered {",
        "        for path in Vec::<String>::new().iter() {",
    ),
    "m6-no-verdict-not-raised": (
        "src/units/attribution.rs",
        "|| !ran.uncovered.is_empty();",
        "|| false;",
    ),
    "m7-explain-writes": (
        "src/units/bundle.rs",
        "Ok(Some(area)) => area.writable_dir(),",
        'Ok(Some(area)) => area.writable("x"),',
    ),
    "m8-units-how-legacy": (
        "src/main.rs",
        '("skipped", "units", true)',
        '("skipped", "legacy", true)',
    ),
    "m9-departed-reader-rule-removed": (
        "src/units/engine.rs",
        "    if let Some(path) = departed_only_change(cx, view, proof, &affected) {",
        "    if let Some(path) = None::<String> {",
    ),
    "m10-affected-readers-count-as-departed": (
        "src/units/engine.rs",
        "    for (unit, versions) in &view.units {\n        let roster = cx.roster.binary_search(unit).is_ok();",
        "    for (unit, versions) in &view.units {\n        let roster = cx.roster.binary_search(unit).is_ok() && !affected.iter().any(|changed| changed.unit == *unit);",
    ),
    "m11-unchanged-inputs-trigger": (
        "src/units/engine.rs",
        ".filter(|input| !fresh.holds(input) && !fresh.absent(input))",
        ".filter(|input| !fresh.absent(input))",
    ),
    "m12-pre-launch-skipped-for-e17": (
        "src/units/engine.rs",
        "    if let Some(path) = departed_only_change(cx, view, proof, &affected) {",
        "    if let Some(path) = departed_only_change(cx, view, proof, &affected).filter(|_| affected.len() != cx.roster.len()) {",
    ),
    "m13-gate-removed": ("src/units/bundle.rs", "    if !split {", "    if true {"),
    "m14-gate-inverted": ("src/units/bundle.rs", "    if !split {", "    if split {"),
    "r3-m1-residue-reset-removed": (
        "src/units/bundle.rs",
        "        if no_verdict && self.keep {",
        "        if false && no_verdict && self.keep {",
    ),
    "r3-m2-absent-reader-rule-removed": (
        "src/units/engine.rs",
        "    if let Some(path) = absent_reader_change(cx, view, proof) {",
        "    if let Some(path) = None::<String> {",
    ),
}


def main() -> None:
    name = sys.argv[1]
    path, old, new = MUTANTS[name]
    target = pathlib.Path(path)
    text = target.read_text(encoding="utf-8")
    found = text.count(old)
    if found != 1:
        raise SystemExit(f"mutant {name}: expected one match in {path}, found {found}")
    target.write_text(text.replace(old, new), encoding="utf-8")
    print(f"applied {name} to {path}")


if __name__ == "__main__":
    main()
