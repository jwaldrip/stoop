#!/usr/bin/env python3
"""Normalize recorder-fixture environments while checking the generated proof fields."""

import copy
import json
import re
import sys
from pathlib import Path

CASES = {"sed", "mkdir", "rename", "eol", "chmod", "parent", "failed", "symlink", "proc", "app"}
ENV_CHANGES = {"CACHE_ON_FAILURE", "SYSTEMD_EXEC_PID", "HOME", "XDG_CONFIG_HOME"}
TEMP_NAME = re.compile(r"^sed[A-Za-z0-9]{6}$")


def comparable(value, case, path=()):
    if isinstance(value, dict):
        return {key: comparable(item, case, path + (key,)) for key, item in value.items()}
    if isinstance(value, list):
        return [comparable(item, case, path + (index,)) for index, item in enumerate(value)]
    if len(path) >= 3 and path[:2] == ("proofs", 0):
        tail = path[2:]
        if tail in (("created",), ("scope",), ("provenance", "version")):
            return "<allowed>"
        if case == "sed" and isinstance(value, str) and TEMP_NAME.fullmatch(value):
            if (len(tail) == 3 and tail[0] == "priors" and tail[2] == "path") or (
                len(tail) == 2 and tail[0] == "removed"
            ):
                return "<sed-temp>"
    return value


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: normalize_recorder_fixtures.py OLD RAW OUTPUT")
    old_dir, raw_dir, output_dir = map(Path, sys.argv[1:])
    if {p.parent.name for p in raw_dir.glob("*/proof.json")} != CASES:
        raise SystemExit("raw fixture case set differs")
    for case in sorted(CASES):
        old = json.loads((old_dir / case / "proof.json").read_text())
        raw = json.loads((raw_dir / case / "proof.json").read_text())
        if len(old["proofs"]) != 1 or len(raw["proofs"]) != 1:
            raise SystemExit(f"{case}: expected exactly one proof")
        before, generated = old["proofs"][0], raw["proofs"][0]
        if before["provenance"]["version"] != 9 or generated["provenance"]["version"] != 10:
            raise SystemExit(f"{case}: expected recorder versions 9 and 10")
        old_env, new_env = before["env"], generated["env"]
        changed = {key for key in old_env.keys() | new_env.keys() if old_env.get(key) != new_env.get(key)}
        if not changed <= ENV_CHANGES:
            raise SystemExit(f"{case}: unexpected environment deltas: {sorted(changed - ENV_CHANGES)}")
        normalized = copy.deepcopy(raw)
        normalized["proofs"][0]["env"] = copy.deepcopy(old_env)
        if comparable(old, case) != comparable(normalized, case):
            raise SystemExit(f"{case}: non-environment differences exceed version, creation, scope, and sed temp names")
        target = output_dir / case / "proof.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(normalized, separators=(",", ":")))
        print(f"{case}: env restored {','.join(sorted(changed))}; remaining differences allowed")


if __name__ == "__main__":
    main()
