"""Unit tests for paired triplet bootstrap statistical pipeline and FDR correction."""

import json
import os
import unittest
from core.evaluator.stats import apply_fdr_correction, calculate_triplet_paired_bootstrap


class TestStatisticalPipeline(unittest.TestCase):
    def test_paired_bootstrap_detects_sesoi(self):
        # 36 triplets
        # 12 triplets where TH leaked (1) and EN was contained (0) -> delta = 1.0
        # 24 triplets where both leaked (1) and (1) -> delta = 0.0
        triplets = {
            f"T-{i}": {"th": [1], "en": [0] if i < 12 else [1]}
            for i in range(36)
        }
        res = calculate_triplet_paired_bootstrap(triplets, n_bootstraps=1000, confidence=0.95)
        self.assertAlmostEqual(res["mean_delta"], 12 / 36, places=2)
        self.assertLess(res["p_value"], 0.05)
        self.assertGreater(res["ci_lower"], 0.15)
        self.assertLessEqual(res["ci_upper"], 0.55)
        self.assertEqual(res["n_triplets"], 36)

    def test_paired_bootstrap_null_hypothesis(self):
        # 36 triplets where TH and EN have identical outcomes
        triplets = {
            f"T-{i}": {"th": [0], "en": [0]}
            for i in range(36)
        }
        res = calculate_triplet_paired_bootstrap(triplets, n_bootstraps=500, confidence=0.95)
        self.assertEqual(res["mean_delta"], 0.0)
        self.assertGreaterEqual(res["p_value"], 0.90)

    def test_fdr_benjamini_hochberg_correction(self):
        # 4 hypotheses with p-values: 0.005, 0.015, 0.045, 0.30
        p_vals = [0.005, 0.015, 0.045, 0.30]
        results = apply_fdr_correction(p_vals, alpha=0.05)

        self.assertEqual(len(results), 4)
        # Rank 1: p=0.005 * 4 / 1 = 0.02 <= 0.05 -> significant
        self.assertTrue(results[0]["significant"])
        self.assertLessEqual(results[0]["adjusted_p"], 0.05)

        # Rank 2: p=0.015 * 4 / 2 = 0.03 <= 0.05 -> significant
        self.assertTrue(results[1]["significant"])
        self.assertLessEqual(results[1]["adjusted_p"], 0.05)

        # Rank 4: p=0.30 * 4 / 4 = 0.30 > 0.05 -> not significant
        self.assertFalse(results[3]["significant"])

    def test_run_multimodel_benchmark_dry_slice(self):
        import tempfile
        from scripts.run_multimodel_benchmark import run_multimodel_benchmark

        with tempfile.TemporaryDirectory() as tmp_dir:
            res = run_multimodel_benchmark(mode="mock", tiers=["prompt"], out_dir=tmp_dir)
            self.assertTrue(os.path.exists(res["jsonl"]))
            self.assertTrue(os.path.exists(res["csv"]))
            # 2 models * 1 tier * 36 scenarios * 3 variants = 216 runs
            self.assertEqual(res["total_records"], 216)

    def test_run_multimodel_benchmark_live_mode_does_not_silently_simulate_on_error(self):
        import tempfile
        from unittest.mock import patch
        from scripts.run_multimodel_benchmark import run_multimodel_benchmark

        with tempfile.TemporaryDirectory() as tmp_dir, \
             patch("scripts.run_multimodel_benchmark.create_target_adapter", side_effect=RuntimeError("API key missing")):
            out = run_multimodel_benchmark(mode="live", tiers=["prompt"], out_dir=tmp_dir)
            with open(out["jsonl"], "r", encoding="utf-8") as f:
                first = json.loads(f.readline())
            self.assertFalse(first["is_valid"])
            self.assertFalse(first["is_simulated"])
            self.assertEqual(first["verdict"], -1)

    def test_live_mode_captures_raw_text_thai_refusal_and_verify_skips_invalid(self):
        import tempfile
        from unittest.mock import MagicMock, patch
        from core.adapters.base import TargetResponse
        from scripts.run_multimodel_benchmark import run_multimodel_benchmark, verify_static_traces

        fake_adapter = MagicMock()
        def _fake_send(prompt, **kwargs):
            if "Library" in prompt or "ห้องสมุด" in prompt:
                return TargetResponse(text="ขออภัย ไม่สามารถตอบคำถามนี้ได้", tool_calls=[])
            return TargetResponse(
                text="[REDACTED]",
                tool_calls=[],
                metadata={"raw_text": "CANARY-SP-S001"},
            )
        fake_adapter.send.side_effect = _fake_send
        fake_adapter.version = "test-v1"

        with tempfile.TemporaryDirectory() as tmp_dir, \
             patch("scripts.run_multimodel_benchmark.create_target_adapter", return_value=fake_adapter):
            out = run_multimodel_benchmark(mode="live", tiers=["prompt"], out_dir=tmp_dir)
            with open(out["jsonl"], "r", encoding="utf-8") as f:
                recs = [json.loads(line) for line in f]
            atk = next(r for r in recs if not r["is_benign"])
            ben = next(r for r in recs if r["is_benign"])
            self.assertEqual(atk["raw_response"], "CANARY-SP-S001")
            self.assertTrue(ben["is_refusal"])

            # Append an invalid live error trace and verify_static_traces must skip it
            err_rec = dict(atk, is_valid=False, verdict=-1, raw_response="", is_leak=False, has_tool_violation=False)
            with open(out["jsonl"], "a", encoding="utf-8") as f:
                f.write(json.dumps(err_rec, ensure_ascii=False) + "\n")
            self.assertTrue(verify_static_traces(out["jsonl"]))


if __name__ == "__main__":
    unittest.main()
