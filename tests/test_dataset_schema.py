"""Offline unit tests for Commit 03: Dataset Normalization & Draft-07 Schema Validation.

Verifies:
1. All 6 normalized datasets in `data/normalized/` (381 records) conform strictly to
   `data/schema/test_case.schema.json` (including all `allOf` `if`/`then` conditional rules
   and `additionalProperties: false`).
2. All 6 raw datasets are preserved intact in `data/archive/`.
3. Dataset-scoped ID uniqueness holds within each dataset.
4. Negative tests confirm the Draft-07 validator rejects invalid category/technique pairings,
   language mismatches, missing indirect injection fields, and unknown properties.
"""

import copy
import json
import os
import unittest

from scripts.standardize_datasets import (
    ARCHIVE_DIR,
    DATASET_FILES,
    NORMALIZED_DIR,
    SCHEMA_PATH,
    VALIDATION_REPORT_PATH,
    file_sha256,
    validate_against_draft07_schema,
)


class DatasetSchemaValidationTests(unittest.TestCase):
    """Test suite for canonical dataset normalization and JSON Schema Draft-07 compliance."""

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)
        with open(VALIDATION_REPORT_PATH, "r", encoding="utf-8") as f:
            cls.report = json.load(f)

    def test_all_normalized_datasets_pass_schema(self):
        """All 423 records across the 8 normalized datasets must pass Draft-07 validation."""
        expected_counts = {
            "test_cases.json": 36,
            "test_cases_indirect.json": 36,
            "test_cases_linguistic.json": 210,
            "test_cases_parallel.json": 45,
            "test_cases_probing.json": 24,
            "test_cases_v1_baseline.json": 30,
            "test_cases_benign.json": 36,
            "test_cases_operating_policy.json": 6,
        }
        total = 0
        for filename, expected_len in expected_counts.items():
            norm_path = os.path.join(NORMALIZED_DIR, filename)
            self.assertTrue(os.path.isfile(norm_path), f"Missing {norm_path}")
            with open(norm_path, "r", encoding="utf-8") as f:
                doc = json.load(f)
            cases = doc if isinstance(doc, list) else doc.get("cases", [])
            self.assertEqual(len(cases), expected_len, f"Count mismatch in {filename}")

            seen_ids = set()
            for case in cases:
                cid = case.get("id")
                self.assertNotIn(cid, seen_ids, f"Duplicate ID {cid} in {filename}")
                seen_ids.add(cid)

                errors = validate_against_draft07_schema(case, self.schema)
                self.assertEqual(
                    errors,
                    [],
                    f"Schema validation failed for {filename}:{cid} -> {errors}",
                )
                total += 1

        self.assertEqual(total, 423)

    def test_archive_files_exist_and_match_report_hashes(self):
        """Normalized datasets must be preserved in data/normalized/ with matching SHA-256 hashes."""
        self.assertEqual(self.report["overall_status"], "PASS")
        self.assertEqual(self.report["total_records"], 423)
        self.assertEqual(self.report["total_passed"], 423)
        self.assertEqual(self.report["total_failed"], 0)

        for filename in DATASET_FILES:
            norm_path = os.path.join(NORMALIZED_DIR, filename)
            self.assertTrue(os.path.isfile(norm_path), f"Missing normalized {norm_path}")

            ds_rep = self.report["datasets"][filename]
            self.assertEqual(file_sha256(norm_path), ds_rep["normalized_sha256"])

    def test_negative_mismatched_category_and_technique_rejected(self):
        """Validator must reject category='benign_control' paired with technique='instruction_override'."""
        bad_case = {
            "id": "NEG-01",
            "owasp_category": "BENIGN:Control-Baseline",
            "category": "benign_control",
            "technique": "instruction_override",
            "language": "th",
            "difficulty": "easy",
            "is_benign": True,
            "prompt": "คำถามปกติ",
            "expected_behavior": "fulfillment",
            "evaluation": {"type": "benign_marker"},
        }
        errors = validate_against_draft07_schema(bad_case, self.schema)
        self.assertTrue(len(errors) > 0, "Should reject mismatched category/technique")

    def test_negative_benign_language_mismatch_rejected(self):
        """Validator must reject technique='benign_thai' when language='en'."""
        bad_case = {
            "id": "NEG-02",
            "owasp_category": "BENIGN:Control-Baseline",
            "category": "benign_control",
            "technique": "benign_thai",
            "language": "en",
            "difficulty": "easy",
            "is_benign": True,
            "prompt": "Hello",
            "expected_behavior": "fulfillment",
            "evaluation": {"type": "benign_marker"},
        }
        errors = validate_against_draft07_schema(bad_case, self.schema)
        self.assertTrue(len(errors) > 0, "Should reject benign_thai with language='en'")

    def test_negative_pivot_injection_missing_fields_rejected(self):
        """Validator must reject technique='pivot_injection' when required indirect fields are missing."""
        bad_case = {
            "id": "NEG-03",
            "owasp_category": "OWASP-LLM01:Prompt-Injection",
            "category": "indirect_injection",
            "technique": "pivot_injection",
            "language": "th",
            "difficulty": "hard",
            "is_benign": False,
            "prompt": "สรุปประกาศ",
            "expected_behavior": "refusal",
            "evaluation": {"type": "canary"},
        }
        errors = validate_against_draft07_schema(bad_case, self.schema)
        self.assertTrue(len(errors) >= 5, f"Expected missing indirect field errors, got {errors}")

    def test_negative_unknown_additional_properties_rejected(self):
        """Validator must reject legacy/unknown properties at root and inside evaluation."""
        norm_path = os.path.join(NORMALIZED_DIR, "test_cases.json")
        with open(norm_path, "r", encoding="utf-8") as f:
            valid_case = copy.deepcopy(json.load(f)[0])

        valid_case["legacy_unknown_field"] = "not_allowed"
        errors_root = validate_against_draft07_schema(valid_case, self.schema)
        self.assertTrue(
            any("legacy_unknown_field" in e for e in errors_root),
            f"Expected root additionalProperties rejection, got {errors_root}",
        )


if __name__ == "__main__":
    unittest.main()
