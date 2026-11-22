#!/usr/bin/env python3
"""Normalize recorder-fixture environments while checking the generated proof fields."""

import copy
import json
import re
import sys
from pathlib import Path

CASES = {"sed", "mkdir", "rename", "eol", "chmod", "parent", "failed", "symlink", "proc", "app"}
NEW_CASE = "sed-exec"
ENV_CHANGES = {
    "CACHE_ON_FAILURE", "GOROOT_1_24_X64", "GOROOT_1_27_X64", "HCA_CLOUD_PROVIDER",
    "HOME", "ImageVersion", "SGX_AESM_ADDR", "SYSTEMD_EXEC_PID", "XDG_CONFIG_HOME",
}
TEMP_NAME = re.compile(r"^sed[A-Za-z0-9]{6}$")
CONTENT_ID = re.compile(r"^[fx]:[0-9a-f]{64}$")


def environment_changes(before, after):
    if not all(
        isinstance(env, dict) and all(isinstance(key, str) and isinstance(value, str)
                                      for key, value in env.items())
        for env in (before, after)
    ):
        raise SystemExit("environment keys and values must be strings")
    missing = object()
    return {
        key for key in before.keys() | after.keys()
        if before.get(key, missing) != after.get(key, missing)
    }


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
        if case in ("sed", NEW_CASE) and isinstance(value, str) and TEMP_NAME.fullmatch(value):
            if (len(tail) == 3 and tail[0] == "priors" and tail[2] == "path") or (
                len(tail) == 2 and tail[0] == "removed"
            ):
                return "<sed-temp>"
    return value


def single_tracee_sed(old_dir, raw_dir, output_dir):
    """Compare the single-tracee sed recording to its previously committed proof."""
    reference_document = json.loads((old_dir / NEW_CASE / "proof.json").read_text())
    if len(reference_document["proofs"]) != 1:
        raise SystemExit(f"{NEW_CASE}: expected exactly one reference proof")
    reference = reference_document["proofs"][0]
    raw = json.loads((raw_dir / NEW_CASE / "proof.json").read_text())
    if len(raw["proofs"]) != 1:
        raise SystemExit(f"{NEW_CASE}: expected exactly one proof")
    generated = raw["proofs"][0]
    if raw["key"] != NEW_CASE or reference_document["key"] != NEW_CASE:
        raise SystemExit(f"{NEW_CASE}: unexpected proof key")
    if generated["provenance"]["version"] != 12:
        raise SystemExit(f"{NEW_CASE}: expected recorder version 12")
    if generated["argv"] != ["sh", "-c", "exec sed -i s/foo/bar/ config.txt"]:
        raise SystemExit(f"{NEW_CASE}: the recording is not the single-tracee exec form")
    changed = environment_changes(reference["env"], generated["env"])
    if not changed <= ENV_CHANGES:
        raise SystemExit(f"{NEW_CASE}: unexpected environment deltas: {sorted(changed - ENV_CHANGES)}")
    prior = [item for item in generated["priors"] if item["path"] == "config.txt"]
    reference_prior = [item for item in reference["priors"] if item["path"] == "config.txt"]
    if len(reference_prior) != 1 or prior != reference_prior:
        raise SystemExit(f"{NEW_CASE}: config.txt prior differs from the reference")
    output = [item for item in generated["outputs"] if item["path"] == "config.txt"]
    reference_output = [item for item in reference["outputs"] if item["path"] == "config.txt"]
    if len(reference_output) != 1 or output != reference_output:
        raise SystemExit(f"{NEW_CASE}: config.txt output differs from the reference")
    promoted = [item for item in generated["inputs"] if item["path"] == "config.txt"]
    if promoted != prior:
        raise SystemExit(f"{NEW_CASE}: the promoted config.txt input must equal its prior")
    if [item for item in reference["inputs"] if item["path"] == "config.txt"] != reference_prior:
        raise SystemExit(f"{NEW_CASE}: reference input must equal its prior")
    sed_temp(reference)
    sed_temp(generated)
    normalized = copy.deepcopy(raw)
    normalized["proofs"][0]["env"] = copy.deepcopy(reference["env"])
    old_inputs = {item["path"]: item for item in reference["inputs"]}
    for item in normalized["proofs"][0]["inputs"]:
        previous = old_inputs.get(item["path"])
        if (previous and runner_system_file(item) and runner_system_file(previous)
                and item["id"][:2] == previous["id"][:2] and item["id"] != previous["id"]):
            item["id"] = previous["id"]
    expected = comparable(reference_document, NEW_CASE)
    actual = comparable(normalized, NEW_CASE)
    if actual != expected:
        raise SystemExit(f"{NEW_CASE}: remaining proof fields differ from the reference")
    canonical = copy.deepcopy(reference_document)
    canonical["proofs"][0]["provenance"]["version"] = generated["provenance"]["version"]
    target = output_dir / NEW_CASE / "proof.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(canonical, separators=(",", ":")))
    print(f"{NEW_CASE}: promoted config.txt input {promoted[0]['id']}")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: normalize_recorder_fixtures.py OLD RAW OUTPUT")
    old_dir, raw_dir, output_dir = map(Path, sys.argv[1:])
    raw_cases = {p.parent.name for p in raw_dir.glob("*/proof.json")}
    if raw_cases == {NEW_CASE}:
        single_tracee_sed(old_dir, raw_dir, output_dir)
        return
    if raw_cases != CASES | {NEW_CASE}:
        raise SystemExit("raw fixture case set differs")
    for case in sorted(CASES):
        old = json.loads((old_dir / case / "proof.json").read_text())
        raw = json.loads((raw_dir / case / "proof.json").read_text())
        if len(old["proofs"]) != 1 or len(raw["proofs"]) != 1:
            raise SystemExit(f"{case}: expected exactly one proof")
        before, generated = old["proofs"][0], raw["proofs"][0]
        if before["provenance"]["version"] != 11 or generated["provenance"]["version"] != 12:
            raise SystemExit(f"{case}: expected recorder versions 11 and 12")
        old_env, new_env = before["env"], generated["env"]
        changed = environment_changes(old_env, new_env)
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
        if case == "sed":
            old_prior = [item for item in before["priors"] if item["path"] == "config.txt"]
            new_prior = [item for item in generated["priors"] if item["path"] == "config.txt"]
            promoted = [item for item in generated["inputs"] if item["path"] == "config.txt"]
            if len(old_prior) != 1 or new_prior != old_prior:
                raise SystemExit("sed: the generated config.txt prior differs from the committed one")
            if promoted not in ([], old_prior):
                raise SystemExit("sed: any added config.txt input must equal its prior")
            sed_temp(before)
            sed_temp(generated)
        if comparable(old, case) != comparable(normalized, case):
            raise SystemExit(f"{case}: differences exceed version, creation, scope and sed temp names")
        canonical = copy.deepcopy(old)
        canonical["proofs"][0]["provenance"]["version"] = generated["provenance"]["version"]
        target = output_dir / case / "proof.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(canonical, separators=(",", ":")))
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
    single_tracee_sed(old_dir, raw_dir, output_dir)


if __name__ == "__main__":
    main()
