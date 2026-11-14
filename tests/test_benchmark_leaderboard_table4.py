"""Unit tests for Benchmark Leaderboard Table 4 (Multi-Turn Adaptive Scorecard)."""
import json
import os
import tempfile
import unittest

from core.cli.commands.eval import run_benchmark_run


class TestBenchmarkLeaderboardTable4(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_table4_generation_from_redteam_report(self):
        """Verify Table 4 is generated in markdown and JSON when redteam report is available."""
        # 1. Create a synthetic redteam report in test_dir
        sample_redteam = {
            "timestamp": "2026-11-14T12:00:00Z",
            "defense": "all",
            "blue_role": "registrar_staff",
            "red_profile": "thai_nuanced_adversary",
            "max_attempts": 7,
            "total_cases": 10,
            "breached_cases": 3,
            "defended_cases": 7,
            "overall_asr": 30.0,
            "cumulative_asr": {"1": 0.0, "2": 0.0, "3": 10.0, "5": 20.0, "7": 30.0},
            "average_ttb": 4.67,
            "results": [],
        }
        with open(os.path.join(self.test_dir, "redteam_evaluation_report.json"), "w", encoding="utf-8") as f:
            json.dump(sample_redteam, f)

        # 2. Run benchmark generation pointing to test_dir
        args = type("Args", (), {
            "dry_run": False,
            "quiet": True,
            "no_color": True,
            "format": "table",
            "export_dir": self.test_dir,
            "export_name": "test_leaderboard",
            "target": "builtin",
            "model": "default",
            "blue": None,
            "role": "registrar_staff",
            "from_results": self.test_dir,
            "all": True,
            "suites": "parallel,indirect,probing,linguistic,benign",
            "defenses": "off,prompt,tools,spotlight,all",
        })()

        code = run_benchmark_run(args)
        self.assertEqual(code, 0)

        # 3. Verify Table 4 is in generated markdown
        md_path = os.path.join(self.test_dir, "test_leaderboard.md")
        self.assertTrue(os.path.exists(md_path))
        with open(md_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("## Table 4: Multi-Turn Adaptive Red Teaming Scorecard", content)
        self.assertIn("Static ASR (Turn 1)", content)
        self.assertIn("Adaptive ASR (Turn 7)", content)
        self.assertIn("Crescendo", content)

        # 4. Verify structured JSON contains multi_turn_redteam data
        json_path = os.path.join(self.test_dir, "test_leaderboard.json")
        self.assertTrue(os.path.exists(json_path))
        with open(json_path, "r", encoding="utf-8") as f:
            scorecard = json.load(f)

        self.assertIn("multi_turn_redteam", scorecard)
        self.assertIn("all", scorecard["multi_turn_redteam"])


if __name__ == "__main__":
    unittest.main()
