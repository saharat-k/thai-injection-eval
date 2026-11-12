import unittest
from core.cli.app import build_parser


class TestCLIModelFlags(unittest.TestCase):
    def test_redteam_run_accepts_blue_and_red_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "redteam", "run",
            "--blue", "gemini-3.5-flash-lite",
            "--red", "openrouter:openrouter/free",
            "--limit", "1",
        ])
        self.assertEqual(args.blue, "gemini-3.5-flash-lite")
        self.assertEqual(args.red, "openrouter:openrouter/free")

    def test_redteam_run_model_flag_alias(self):
        parser = build_parser()
        args = parser.parse_args([
            "redteam", "run",
            "--model", "gemini-3.5-flash-lite",
            "--red", "openrouter:openrouter/free",
            "--limit", "1",
        ])
        self.assertEqual(args.model, "gemini-3.5-flash-lite")

    def test_eval_run_accepts_blue_and_red_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "eval", "run",
            "--blue", "gemini-3.5-flash-lite",
            "--red", "openrouter:openrouter/free",
        ])
        self.assertEqual(args.blue, "gemini-3.5-flash-lite")
        self.assertEqual(args.red, "openrouter:openrouter/free")

    def test_benchmark_run_accepts_blue_and_red_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "benchmark", "run",
            "--blue", "gemini-3.5-flash-lite",
            "--red", "openrouter:openrouter/free",
        ])
        self.assertEqual(args.blue, "gemini-3.5-flash-lite")
        self.assertEqual(args.red, "openrouter:openrouter/free")
        self.assertEqual(args.model, "gemini-3.5-flash-lite")

    def test_long_flag_aliases(self):
        parser = build_parser()
        args = parser.parse_args([
            "redteam", "run",
            "--blue-model", "gemini-3.5-flash-lite",
            "--red-model", "openrouter:openrouter/free",
        ])
        self.assertEqual(args.blue, "gemini-3.5-flash-lite")
        self.assertEqual(args.model, "gemini-3.5-flash-lite")
        self.assertEqual(args.red, "openrouter:openrouter/free")

    def test_redteam_run_accepts_mutator_and_turns(self):
        parser = build_parser()
        args = parser.parse_args([
            "redteam", "run",
            "--turns", "5",
            "--mutator", "zero_width",
            "--dry-run",
        ])
        self.assertEqual(args.attempts, 5)
        self.assertEqual(args.mutator, "zero_width")
        self.assertTrue(args.dry_run)

    def test_redteam_cli_tree_strategy_flags(self):
        parser = build_parser()
        args = parser.parse_args([
            "redteam", "run",
            "--strategy", "tree",
            "--beam-width", "2",
            "--branch-factor", "3",
            "--dry-run",
        ])
        self.assertEqual(args.strategy, "tree")
        self.assertEqual(args.beam_width, 2)
        self.assertEqual(args.branch_factor, 3)

    def test_chat_parser_tree_and_mutator_flags(self):
        parser = build_parser()
        args = parser.parse_args(["chat", "--attack-type", "tree", "--mutator", "zero_width"])
        self.assertEqual(args.attack_type, "tree")
        self.assertEqual(args.mutator, "zero_width")

    def test_manual_parser_tree_and_mutator_flags(self):
        parser = build_parser()
        args = parser.parse_args(["manual", "--attack-type", "tree", "--mutator", "homoglyph"])
        self.assertEqual(args.attack_type, "tree")
        self.assertEqual(args.mutator, "homoglyph")


