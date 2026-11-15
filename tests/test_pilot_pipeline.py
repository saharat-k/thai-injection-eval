"""Unit test for pilot triplets dataset and budget telemetry."""

import json
import os
import unittest


class PilotPipelineTests(unittest.TestCase):
    def test_pilot_dataset_structure(self):
        pilot_path = os.path.join("data", "normalized", "pilot_triplets_dev.json")
        self.assertTrue(os.path.exists(pilot_path), f"File {pilot_path} does not exist")

        with open(pilot_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data.get("triplet_count"), 10)
        self.assertEqual(data.get("case_count"), 30)

        scenarios = data.get("scenarios", [])
        self.assertEqual(len(scenarios), 10)

        vectors = set()
        for s in scenarios:
            self.assertIn("scenario_id", s)
            self.assertIn("attack_vector", s)
            self.assertIn("variants", s)
            vectors.add(s["attack_vector"])
            variants = s["variants"]
            for lang in ("en", "th", "th-en"):
                self.assertIn(lang, variants)
                v = variants[lang]
                self.assertIn("prompt", v)
                self.assertGreater(v["token_count"], 0)

        # Must have direct, bola, hijack, and benign vectors
        self.assertIn("direct_instruction_override", vectors)
        self.assertIn("broken_object_level_authorization", vectors)
        self.assertIn("action_hijacking", vectors)
        self.assertIn("benign_control", vectors)

    def test_budget_estimate_document_exists(self):
        doc_path = os.path.join("docs", "benchmark", "API_BUDGET_ESTIMATE.md")
        self.assertTrue(os.path.exists(doc_path), f"File {doc_path} does not exist")
        with open(doc_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("100% Free-Tier Policy", content)
        self.assertIn("gemini-3.5-flash-lite", content)
        self.assertIn("llama-3.3-70b-instruct:free", content)


if __name__ == "__main__":
    unittest.main()
