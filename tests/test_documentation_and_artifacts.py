"""Unit test verifying documentation, pre-registration artifacts, and release metadata."""

import csv
import json
import os
import unittest


class TestDocumentationAndArtifacts(unittest.TestCase):
    def test_pyproject_version_bumped_to_v2(self):
        pyproject_path = "pyproject.toml"
        self.assertTrue(os.path.exists(pyproject_path))
        with open(pyproject_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('version = "2.1.0"', content)

    def test_pre_registration_document_specifications(self):
        prereg_path = os.path.join("docs", "benchmark", "PRE_REGISTRATION.md")
        self.assertTrue(os.path.exists(prereg_path), f"Missing {prereg_path}")
        with open(prereg_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("preregistration-v2.0", content)
        self.assertIn("SESOI", content)
        self.assertIn("0.10", content)
        self.assertIn("Benjamini-Hochberg", content)
        self.assertIn("data/normalized/test_cases_parallel_v2.json", content)

    def test_results_artifacts_exist_and_conform(self):
        jsonl_path = os.path.join("results", "published", "benchmark_v2_static.jsonl")
        csv_path = os.path.join("results", "published", "benchmark_v2_summary.csv")

        self.assertTrue(os.path.exists(jsonl_path), f"Missing {jsonl_path}")
        self.assertTrue(os.path.exists(csv_path), f"Missing {csv_path}")

        # Check JSONL
        with open(jsonl_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        self.assertGreaterEqual(len(lines), 100)
        sample = json.loads(lines[0])
        self.assertIn("scenario_id", sample)
        self.assertIn("language", sample)
        self.assertIn("defense_tier", sample)
        self.assertIn("verdict", sample)
        self.assertIn("prompt", sample)
        self.assertIn("raw_response", sample)
        self.assertIn("tool_calls", sample)
        self.assertIn("temperature", sample)
        self.assertIn("seed", sample)
        self.assertIn("model_version", sample)

        # Check CSV
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        self.assertGreater(len(rows), 0)
        expected_cols = {
            "model_id", "model_name", "defense_tier", "language",
            "asr_pct", "attempt_rate_pct", "frr_pct", "des_pct",
            "paired_delta_th_en", "p_adjusted_fdr",
        }
        self.assertTrue(expected_cols.issubset(set(reader.fieldnames or [])))

    def test_limitations_and_readme_sober_standards(self):
        with open("README.md", "r", encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("Benchmark v2.0.0", readme)
        self.assertIn("Dataset A", readme)
        self.assertIn("Attempt vs. Leak Decoupling", readme)
        self.assertIn("actions/workflows/tests.yml/badge.svg", readme)

        with open("LIMITATIONS.md", "r", encoding="utf-8") as f:
            limitations = f.read()
        self.assertIn("Attempt Rate", limitations)
        self.assertIn("Leak Rate", limitations)
        self.assertIn("SESOI", limitations)

    def test_security_md_exists_and_covers_boundaries(self):
        security_path = "SECURITY.md"
        self.assertTrue(os.path.exists(security_path), f"Missing {security_path}")
        with open(security_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("Vulnerability", content)
        self.assertIn("Threat Model Boundaries", content)
        self.assertIn("Synthetic Sandboxed Environment", content)
        self.assertIn("Multimodal", content)
        self.assertIn("Safe Harbor", content)


if __name__ == "__main__":
    unittest.main()
