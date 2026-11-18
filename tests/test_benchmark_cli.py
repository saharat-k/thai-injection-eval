"""Test CLI argument parsing and dry-run execution for indirect and unified benchmark."""
import unittest
from core.cli.app import build_parser
from core.cli.commands.eval import run_eval_run


class TestBenchmarkCLI(unittest.TestCase):
    """Test CLI argument parsing and dry-run execution for indirect and unified benchmark."""

    def setUp(self):
        self.parser = build_parser()

    def test_indirect_eval_flag_parsed(self):
        """CLI parser accepts --indirect flag under eval run."""
        args = self.parser.parse_args(["eval", "run", "--indirect", "--dry-run"])
        self.assertTrue(getattr(args, "indirect", False))
        self.assertTrue(getattr(args, "dry_run", False))

    def test_indirect_dry_run_executes_cleanly(self):
        """eval run --indirect --dry-run returns exit code 0 without network calls."""
        args = self.parser.parse_args(["eval", "run", "--indirect", "--dry-run", "--quiet"])
        ret = run_eval_run(args)
        self.assertEqual(ret, 0)

    def test_benchmark_run_command_parsed(self):
        """CLI parser accepts benchmark run subcommand with --all and --dry-run."""
        args = self.parser.parse_args(["benchmark", "run", "--all", "--dry-run", "--quiet"])
        self.assertEqual(args.command, "benchmark")
        self.assertEqual(args.subcommand, "run")
        self.assertTrue(args.all)
        self.assertTrue(args.dry_run)

    def test_doctor_checks_benign_dataset(self):
        """thai-eval doctor includes test_cases_benign.json in diagnostics."""
        from core.cli.commands.doctor import run_diagnostics
        diag = run_diagnostics()
        components = [c["component"] for c in diag["checks"]]
        self.assertIn("Benchmark Datasets", components)

    def test_benign_eval_flag_parsed_and_dry_run(self):
        """eval run --benign --dry-run parses and executes cleanly with exit code 0."""
        args = self.parser.parse_args(["eval", "run", "--benign", "--dry-run", "--quiet"])
        self.assertTrue(getattr(args, "benign", False))
        ret = run_eval_run(args)
        self.assertEqual(ret, 0)

    def test_benchmark_run_from_results_generates_3_tables(self):
        """benchmark run --from-results generates research leaderboard with 3 tables."""
        import tempfile
        import os
        from core.cli.commands.eval import run_benchmark_run

        with tempfile.TemporaryDirectory() as tmp_dir:
            args = self.parser.parse_args([
                "benchmark", "run",
                "--from-results", tmp_dir,
                "--export-dir", tmp_dir,
                "--quiet",
            ])
            ret = run_benchmark_run(args)
            self.assertEqual(ret, 0)

            md_path = os.path.join(tmp_dir, "benchmark_leaderboard.md")
            self.assertTrue(os.path.exists(md_path))
            with open(md_path, "r", encoding="utf-8") as f:
                content = f.read()

            self.assertIn("Table 1: Executive Defense Scorecard", content)
            self.assertIn("Table 2: Cross-Lingual Vulnerability Breakdown", content)
            self.assertIn("Table 3: Threat Category & PDPA Sensitivity Breakdown", content)
            self.assertIn("Wilson", content)
            self.assertIn("Defense Efficiency Score", content)

    def test_benchmark_run_without_from_results_executes_evaluator_and_uses_unified_des(self):
        import json
        import os
        import tempfile
        from unittest.mock import MagicMock, patch
        from core.adapters.base import TargetResponse
        from core.cli.commands.eval import run_benchmark_run

        fake_adapter = MagicMock()
        fake_adapter.send.return_value = TargetResponse(text="ข้อมูลหลักสูตร CS101", tool_calls=[])
        fake_adapter.get_info.return_value = {"type": "mock"}
        with tempfile.TemporaryDirectory() as tmp_dir, \
             patch("core.cli.commands.eval.create_target_adapter", return_value=fake_adapter):
            args = self.parser.parse_args([
                "benchmark", "run", "--suites", "parallel", "--defenses", "tools",
                "--limit", "2", "--export-dir", tmp_dir, "--quiet",
            ])
            ret = run_benchmark_run(args)
            self.assertEqual(ret, 0)
            self.assertGreater(fake_adapter.send.call_count, 0)
            with open(os.path.join(tmp_dir, "benchmark_leaderboard.json"), encoding="utf-8") as f:
                scorecard = json.load(f)
            self.assertEqual(scorecard.get("data_source"), "live_execution")

    def test_benchmark_run_populates_table3_for_parallel_and_ignores_stale_jsons(self):
        import json
        import os
        import tempfile
        from unittest.mock import MagicMock, patch
        from core.adapters.base import TargetResponse
        from core.cli.commands.eval import run_benchmark_run

        fake_adapter = MagicMock()
        fake_adapter.send.return_value = TargetResponse(text="ข้อมูลทั่วไป", tool_calls=[])
        fake_adapter.get_info.return_value = {"type": "mock"}
        with tempfile.TemporaryDirectory() as tmp_dir, \
             patch("core.cli.commands.eval.create_target_adapter", return_value=fake_adapter):
            with open(os.path.join(tmp_dir, "stale_old_report.json"), "w", encoding="utf-8") as sf:
                json.dump({
                    "results": [{"defense": "tools", "is_benign": False, "success": 1}] * 50,
                }, sf)

            args = self.parser.parse_args([
                "benchmark", "run", "--suites", "parallel", "--defenses", "tools",
                "--limit", "2", "--export-dir", tmp_dir, "--quiet",
            ])
            ret = run_benchmark_run(args)
            self.assertEqual(ret, 0)
            with open(os.path.join(tmp_dir, "benchmark_leaderboard.json"), encoding="utf-8") as f:
                sc = json.load(f)
            td = sc["tier_data"]["tools"]
            self.assertEqual(td["attack_total"], 2)
            self.assertGreater(td["llm01_tot"], 0)
            self.assertGreater(td["sec24_tot"], 0)


if __name__ == "__main__":
    unittest.main()
