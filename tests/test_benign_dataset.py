"""Test suite for the dedicated benign control dataset."""
import json
import os
import unittest
from scripts.standardize_datasets import SCHEMA_PATH, validate_against_draft07_schema


class TestBenignDataset(unittest.TestCase):
    """Test suite for the dedicated benign control dataset."""

    DATASET_PATH = os.path.join("data", "normalized", "test_cases_benign.json")

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    def test_dataset_exists_and_valid_json(self):
        """Dataset file exists and parses as valid JSON dict with 'cases' list."""
        self.assertTrue(os.path.exists(self.DATASET_PATH), f"Missing {self.DATASET_PATH}")
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertEqual(len(data["cases"]), 36)

    def test_all_cases_pass_draft07_schema(self):
        """All 36 benign cases must strictly pass Canonical Draft-07 schema."""
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        for case in data["cases"]:
            errors = validate_against_draft07_schema(case, self.schema)
            self.assertEqual(errors, [], f"Schema errors in case {case.get('id')}: {errors}")

    def test_benign_invariants(self):
        """All cases must have is_benign=True, fulfillment behavior, and balanced languages."""
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        by_lang = {"th": 0, "en": 0, "th-en": 0}
        for case in data["cases"]:
            self.assertTrue(case.get("is_benign"))
            self.assertEqual(case.get("category"), "benign_control")
            self.assertEqual(case.get("expected_behavior"), "fulfillment")
            lang = case.get("language")
            self.assertIn(lang, by_lang)
            by_lang[lang] += 1

            # Benign cases must never have canary tokens in expected output
            eval_meta = case.get("evaluation", {})
            tokens = eval_meta.get("expected_tokens", [])
            for t in tokens:
                self.assertNotIn("CANARY-SP", t)
                self.assertNotIn("CANARY-PUB", t)

        self.assertEqual(by_lang["th"], 12)
        self.assertEqual(by_lang["en"], 12)
        self.assertEqual(by_lang["th-en"], 12)


if __name__ == "__main__":
    unittest.main()
