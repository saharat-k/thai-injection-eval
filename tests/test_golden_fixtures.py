"""Regression test verifying deterministic parity against golden fixtures."""
import hashlib
import json
import os
import unittest
import agent

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES_DIR = os.path.join(BASE_DIR, "tests", "fixtures")

class TestGoldenFixtures(unittest.TestCase):
    def test_tool_outputs_match_golden_snapshots(self):
        with open(os.path.join(FIXTURES_DIR, "golden_tool_outputs.json"), "r", encoding="utf-8") as f:
            golden = json.load(f)
        for call in golden:
            fn = getattr(agent, call["tool"])
            out = json.loads(fn(**call["args"]))
            self.assertEqual(out, call["expected_output"], f"Mismatch in {call['tool']} output")

    def test_system_prompt_hashes_match_golden(self):
        with open(os.path.join(FIXTURES_DIR, "golden_prompt_hashes.json"), "r", encoding="utf-8") as f:
            golden = json.load(f)
        for key, expected_hash in golden.items():
            tier, role = key.split(":")
            base_sys = agent.core_prompts.HARDENED_SYSTEM_PROMPT if tier in ("prompt", "all") else agent.core_prompts.BASE_SYSTEM_PROMPT
            schema_hint = agent.core_prompts.PUBLIC_SCHEMA_HINT if tier in ("prompt", "tools", "all", "spotlight") else agent.core_prompts.FULL_SCHEMA_HINT
            role_addon = agent.core_prompts.get_blue_role_prompt(role)
            system = f"{base_sys}\n\n{schema_hint}"
            if role_addon:
                system += f"\n\nROLE POLICY:\n{role_addon}"
            h = hashlib.sha256(system.encode("utf-8")).hexdigest()
            self.assertEqual(h, expected_hash, f"Prompt hash mismatch for {key}")

if __name__ == "__main__":
    unittest.main()
