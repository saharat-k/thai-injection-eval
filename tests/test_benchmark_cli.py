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


if __name__ == "__main__":
    unittest.main()
