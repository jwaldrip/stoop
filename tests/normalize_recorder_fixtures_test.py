#!/usr/bin/env python3
"""Regression controls for the real single-tracee sed fixture normalizer."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import normalize_recorder_fixtures as normalizer

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "recorder"


class SingleTraceeSed(unittest.TestCase):
    def setUp(self):
        self.original = json.loads((FIXTURES / "sed-exec" / "proof.json").read_text())
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raw = Path(self.tmp.name) / "raw"
        self.out = Path(self.tmp.name) / "out"
        (self.raw / "sed-exec").mkdir(parents=True)

    def normalize(self, proof):
        (self.raw / "sed-exec" / "proof.json").write_text(json.dumps(proof))
        normalizer.single_tracee_sed(FIXTURES, self.raw, self.out)

    def test_real_recording_is_accepted(self):
        self.normalize(self.original)
        self.assertTrue((self.out / "sed-exec" / "proof.json").exists())

    def test_altered_output_digest_is_rejected(self):
        changed = copy.deepcopy(self.original)
        output = next(x for x in changed["proofs"][0]["outputs"] if x["path"] == "config.txt")
        output["id"] = "f:" + "0" * 64
        with self.assertRaisesRegex(SystemExit, "output"):
            self.normalize(changed)
        self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_matching_but_altered_prior_and_input_are_rejected(self):
        changed = copy.deepcopy(self.original)
        proof = changed["proofs"][0]
        for name in ("priors", "inputs"):
            entry = next(x for x in proof[name] if x["path"] == "config.txt")
            entry["id"] = "f:" + "0" * 64
        with self.assertRaisesRegex(SystemExit, "prior"):
            self.normalize(changed)
        self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_unrelated_proof_field_is_rejected(self):
        changed = copy.deepcopy(self.original)
        changed["proofs"][0]["unexpected_field"] = "must not disappear"
        with self.assertRaisesRegex(SystemExit, "proof"):
            self.normalize(changed)
        self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_other_recorded_fields_remain_checked(self):
        def extra_input(proof):
            proof["inputs"].append({"path": "extra", "id": "a", "oid": None})

        def extra_output(proof):
            proof["outputs"].append({"path": "extra", "id": "a", "oid": None})

        def extra_removal(proof):
            proof["removed"].append("extra")

        def changed_ignore(proof):
            proof["ignore"].append("extra")

        def changed_environment(proof):
            proof["env"]["PATH"] = "changed"

        for mutate in (
            extra_input, extra_output, extra_removal, changed_ignore, changed_environment,
        ):
            with self.subTest(mutation=mutate.__name__):
                changed = copy.deepcopy(self.original)
                mutate(changed["proofs"][0])
                with self.assertRaises(SystemExit):
                    self.normalize(changed)
                self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_unapproved_null_environment_entry_is_rejected(self):
        changed = copy.deepcopy(self.original)
        changed["proofs"][0]["env"]["UNAPPROVED_REVIEW_SENTINEL"] = None
        with self.assertRaisesRegex(SystemExit, "environment"):
            self.normalize(changed)
        self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_approved_environment_entries_must_be_strings(self):
        for value in (None, 0, False, [], {}):
            with self.subTest(value=value):
                changed = copy.deepcopy(self.original)
                changed["proofs"][0]["env"]["HOME"] = value
                with self.assertRaisesRegex(SystemExit, "environment"):
                    self.normalize(changed)
                self.assertFalse((self.out / "sed-exec" / "proof.json").exists())

    def test_missing_environment_key_is_a_difference(self):
        self.assertEqual(normalizer.environment_changes({}, {"EXTRA": "value"}), {"EXTRA"})
        self.assertEqual(normalizer.environment_changes({"EXTRA": "value"}, {}), {"EXTRA"})
        with self.assertRaisesRegex(SystemExit, "environment"):
            normalizer.environment_changes({}, {"EXTRA": None})


if __name__ == "__main__":
    unittest.main()
