import io
import unittest
from unittest.mock import patch
from core.cli.commands.redteam import print_preflight_card
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

    def test_tree_topology_indentation(self):
        root = TreeNode(node_id="root", parent_id=None, turn_no=0, prompt="Root Prompt", is_beam_selected=True)
        child = TreeNode(node_id="node_1_1", parent_id="root", turn_no=1, prompt="Child 1", score=10)
        root.children.append(child)
        
        rendered = render_ascii_tree(root, prefix="   ")
        lines = rendered.splitlines()
        self.assertTrue(lines[0].startswith("   root:"), f"Expected indent in '{lines[0]}'")
        self.assertTrue(lines[1].startswith("   └─ node_1_1:"), f"Expected indent in '{lines[1]}'")

if __name__ == "__main__":
    unittest.main()
