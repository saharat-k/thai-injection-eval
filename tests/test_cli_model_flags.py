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

    def test_attack_command_short_flags_positional_target_and_preset_override(self):
        parser = build_parser()
        args = parser.parse_args([
            "attack", "TH-1", "-P", "stealth", "-n", "2", "-d", "prompt",
            "-t", "policy_puppetry,variation_selector", "-m", "thai_digits", "--dry-run",
        ])
        from core.cli.commands.redteam import _resolve_attack_presets, _apply_positional_attack_target
        _apply_positional_attack_target(args)
        _resolve_attack_presets(args)
        self.assertEqual(args.case, "TH-1")
        self.assertEqual(args.strategy, "crescendo")      # from stealth preset
        self.assertTrue(args.backtrack)                   # from stealth preset
        self.assertEqual(args.attempts, 2)                # explicit -n overrides preset 5
        self.assertEqual(args.defense, "prompt")
        self.assertEqual(args.technique, "policy_puppetry,variation_selector")
        self.assertEqual(args.mutator, "thai_digits")

    def test_attack_positional_json_target_and_presets(self):
        from core.cli.commands.redteam import _resolve_attack_presets, _apply_positional_attack_target
        parser = build_parser()

        args_json = parser.parse_args(["attack", "data/normalized/test_cases.json", "-P", "aggressive", "--dry-run"])
        _apply_positional_attack_target(args_json)
        _resolve_attack_presets(args_json)
        self.assertEqual(args_json.cases, "data/normalized/test_cases.json")
        self.assertIsNone(args_json.case)
        self.assertEqual(args_json.strategy, "tree")
        self.assertEqual(args_json.technique, "auto")
        self.assertEqual(args_json.beam_width, 2)
        self.assertEqual(args_json.branch_factor, 3)

        args_quick = parser.parse_args(["attack", "-P", "quick"])
        _resolve_attack_presets(args_quick)
        self.assertEqual(args_quick.strategy, "template")
        self.assertEqual(args_quick.technique, "auto")
        self.assertEqual(args_quick.attempts, 3)

        args_sweep = parser.parse_args(["attack", "-P", "sweep"])
        _resolve_attack_presets(args_sweep)
        self.assertEqual(args_sweep.technique, "core")
        self.assertEqual(args_sweep.strategy, "template")

    def test_mutator_choices_shared_across_commands(self):
        from core.cli.app import MUTATOR_CHOICES
        expected = (
            "none", "zero_width", "homoglyph", "code_switch", "thai_number_words",
            "thai_digits", "arithmetic_split", "caesar_shift", "base64", "hex",
            "syllable_spacing", "variation_selector", "thai_phonetic", "json_unicode_escape", "all",
        )
        self.assertEqual(MUTATOR_CHOICES, expected)
        parser = build_parser()
        sub_action = next(a for a in parser._actions if getattr(a, "dest", None) == "command")
        for cmd in ("attack", "chat", "manual"):
            sub_parser = sub_action.choices[cmd]
            mut_action = next(a for a in sub_parser._actions if getattr(a, "dest", None) == "mutator")
            self.assertEqual(tuple(mut_action.choices), expected)
        redteam_parser = sub_action.choices["redteam"]
        rt_subs = next(a for a in redteam_parser._actions if getattr(a, "dest", None) == "subcommand")
        rt_run = rt_subs.choices["run"]
        rt_mut = next(a for a in rt_run._actions if getattr(a, "dest", None) == "mutator")
        self.assertEqual(tuple(rt_mut.choices), expected)

    def test_redteam_run_legacy_defaults_and_preset_override(self):
        parser = build_parser()
        default_args = parser.parse_args(["redteam", "run", "--dry-run"])
        self.assertEqual(default_args.defense, "all")
        self.assertEqual(default_args.role, "registrar_staff")
        self.assertEqual(default_args.profile, "thai_nuanced_adversary")
        self.assertEqual(default_args.strategy, "template")
        self.assertEqual(default_args.technique, "none")
        self.assertEqual(default_args.attempts, 3)
        self.assertFalse(default_args.backtrack)

        override_args = parser.parse_args([
            "redteam", "run", "-P", "sweep", "-t", "all", "-n", "4", "-m", "thai_phonetic",
        ])
        self.assertEqual(override_args.technique, "all")
        self.assertEqual(override_args.strategy, "template")
        self.assertEqual(override_args.attempts, 4)
        self.assertEqual(override_args.mutator, "thai_phonetic")


