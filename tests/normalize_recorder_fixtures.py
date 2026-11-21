#!/usr/bin/env python3
"""Normalize recorder-fixture environments while checking the generated proof fields."""

import copy
import json
import re
import sys
from pathlib import Path

CASES = {"sed", "mkdir", "rename", "eol", "chmod", "parent", "failed", "symlink", "proc", "app"}
ENV_CHANGES = {
    "CACHE_ON_FAILURE", "GOROOT_1_24_X64", "GOROOT_1_27_X64", "HCA_CLOUD_PROVIDER",
    "HOME", "ImageVersion", "SGX_AESM_ADDR", "SYSTEMD_EXEC_PID", "XDG_CONFIG_HOME",
}
TEMP_NAME = re.compile(r"^sed[A-Za-z0-9]{6}$")
CONTENT_ID = re.compile(r"^[fx]:[0-9a-f]{64}$")


def runner_system_file(item):
    path = item["path"]
    return path.startswith(("/etc/", "/usr/", "/lib")) and bool(CONTENT_ID.fullmatch(item["id"]))


def sed_temp(proof):
    priors = [item["path"] for item in proof["priors"] if TEMP_NAME.fullmatch(item["path"])]
    removed = [path for path in proof["removed"] if TEMP_NAME.fullmatch(path)]
    if len(priors) != 1 or priors != removed:
        raise SystemExit("sed: temporary prior and removal do not name the same source")
    return priors[0]


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
        if before["provenance"]["version"] != 10 or generated["provenance"]["version"] != 11:
            raise SystemExit(f"{case}: expected recorder versions 10 and 11")
        old_env, new_env = before["env"], generated["env"]
        changed = {key for key in old_env.keys() | new_env.keys() if old_env.get(key) != new_env.get(key)}
        if not changed <= ENV_CHANGES:
            raise SystemExit(f"{case}: unexpected environment deltas: {sorted(changed - ENV_CHANGES)}")
        normalized = copy.deepcopy(raw)
        normalized["proofs"][0]["env"] = copy.deepcopy(old_env)
        system_restored = []
        old_inputs = {item["path"]: item for item in before["inputs"]}
        for item in normalized["proofs"][0]["inputs"]:
            previous = old_inputs.get(item["path"])
            if (previous and runner_system_file(item) and runner_system_file(previous)
                    and item["id"][:2] == previous["id"][:2] and item["id"] != previous["id"]):
                item["id"] = previous["id"]
                system_restored.append(item["path"])
        comparison = copy.deepcopy(normalized)
        if case == "sed":
            old_prior = [item for item in before["priors"] if item["path"] == "config.txt"]
            new_prior = [item for item in generated["priors"] if item["path"] == "config.txt"]
            promoted = [item for item in generated["inputs"] if item["path"] == "config.txt"]
            if len(old_prior) != 1 or new_prior != old_prior or promoted not in ([], old_prior):
                raise SystemExit("sed: any added config.txt input must equal its prior")
            sed_temp(before)
            sed_temp(generated)
            comparison["proofs"][0]["inputs"] = [
                item for item in comparison["proofs"][0]["inputs"] if item["path"] != "config.txt"
            ]
        if comparable(old, case) != comparable(comparison, case):
            raise SystemExit(f"{case}: differences exceed version, creation, scope, sed temp names, and the exact sed prior input")
        target = output_dir / case / "proof.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(normalized, separators=(",", ":")))
        path_env = changed & {"HOME", "XDG_CONFIG_HOME"}
        sed_names = int(case == "sed" and sed_temp(before) != sed_temp(generated))
        print(
            f"{case}: env={len(changed)} ({','.join(sorted(changed))}); "
            f"path_env={len(path_env)}; system_input_ids={len(system_restored)} "
            f"({','.join(system_restored)}); created={int(before['created'] != generated['created'])}; "
            f"scope={int(before['scope'] != generated['scope'])}; version=1; "
            f"sed_temp_prior={sed_names}; sed_temp_removed={sed_names}; "
            f"sed_prior_input={len(promoted) if case == 'sed' else 0}"
        )


if __name__ == "__main__":
    main()
