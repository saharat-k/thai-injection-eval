import io
import os
import tempfile
import unittest
from unittest.mock import patch
from core.cli.commands.redteam import export_redteam_report, print_preflight_card
from core.evaluator.redteam import RedTeamBenchmarkReport
from core.evaluator.tree import TreeNode, render_ascii_tree

class DummyArgs:
    def __init__(self, **kwargs):
        self.quiet = False
        self.dry_run = True
        self.defense = "all"
        self.strategy = "tree"
        self.beam_width = 2
        self.branch_factor = 3
        self.mutator = "zero_width"
        self.backtrack = True
        self.max_backtracks = 2
        self.attempts = 3
        self.role = "registrar_staff"
        self.profile = "thai_nuanced_adversary"
        self.blue = "gemini-3.5-flash-lite"
        self.red = "openrouter:openrouter/free"
        for k, v in kwargs.items():
            setattr(self, k, v)

class TestRedteamCliDisplay(unittest.TestCase):
    def test_preflight_card_contains_tree_params_and_mutator(self):
        args = DummyArgs()
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_preflight_card(args, total_cases=5, cases_path="data/normalized/test_cases.json", no_color=True)
        out = buf.getvalue()
        self.assertIn("Attack Strategy", out)
        self.assertIn("TREE (Beam Width: 2, Branch Factor: 3)", out)
        self.assertIn("NLP Mutator", out)
        self.assertIn("ZERO_WIDTH", out)

    def test_preflight_card_displays_active_technique(self):
        args_active = DummyArgs(technique="policy_puppetry")
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            print_preflight_card(args_active, total_cases=2, cases_path="data/normalized/test_cases.json", no_color=True)
        out = buf.getvalue()
        self.assertIn("Red Technique", out)
        self.assertIn("POLICY_PUPPETRY [Active]", out)

        args_std = DummyArgs(technique="none")
        buf_std = io.StringIO()
        with patch("sys.stdout", buf_std):
            print_preflight_card(args_std, total_cases=2, cases_path="data/normalized/test_cases.json", no_color=True)
        self.assertIn("NONE [Standard]", buf_std.getvalue())

    def test_tree_topology_indentation(self):
        root = TreeNode(node_id="root", parent_id=None, turn_no=0, prompt="Root Prompt", is_beam_selected=True)
        child = TreeNode(node_id="node_1_1", parent_id="root", turn_no=1, prompt="Child 1", score=10)
        root.children.append(child)
        
        rendered = render_ascii_tree(root, prefix="   ")
        lines = rendered.splitlines()
        self.assertTrue(lines[0].startswith("   root:"), f"Expected indent in '{lines[0]}'")
        self.assertTrue(lines[1].startswith("   └─ node_1_1:"), f"Expected indent in '{lines[1]}'")

    def test_export_redteam_report_markdown_includes_effective_red_models(self):
        report = RedTeamBenchmarkReport(
            timestamp="2026-11-26T00:00:00+00:00",
            defense="all",
            blue_role="registrar_staff",
            red_profile="thai_nuanced_adversary",
            max_attempts=3,
            total_cases=0,
            breached_cases=0,
            defended_cases=0,
            error_cases=0,
            overall_asr=0.0,
            cumulative_asr={},
            average_ttb=None,
            results=[],
            blue_model="gemini-3.5-flash-lite",
            red_model="openrouter:openrouter/free",
            strategy="crescendo",
            effective_red_models=["openrouter:openrouter/free", "gemini-3.5-flash-lite"],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            _, md_path = export_redteam_report(report, export_dir=tmpdir, base_name="rep")
            with open(md_path, "r", encoding="utf-8") as f:
                md_text = f.read()
        self.assertIn("Effective Red Models", md_text)
        self.assertIn("openrouter:openrouter/free, gemini-3.5-flash-lite", md_text)

if __name__ == "__main__":
    unittest.main()
