"""Unit tests for Isolated Spotlighting Defense and Tool Ceiling."""
import json
import unittest

from core.defenses.spotlight import SpotlightingGuard
import agent


class SpotlightingDefenseTests(unittest.TestCase):
    def setUp(self):
        self.guard = SpotlightingGuard(seed=42)

    def test_reproducibility_with_seed(self):
        guard1 = SpotlightingGuard(seed=12345)
        delim1_a = guard1.generate_delimiter()
        delim1_b = guard1.generate_delimiter()

        guard2 = SpotlightingGuard(seed=12345)
        delim2_a = guard2.generate_delimiter()
        delim2_b = guard2.generate_delimiter()

        self.assertEqual(delim1_a, delim2_a)
        self.assertEqual(delim1_b, delim2_b)
        self.assertNotEqual(delim1_a, delim1_b)

    def test_delimiter_uniqueness_across_requests(self):
        guard = SpotlightingGuard(seed=999)
        delimiters = [guard.generate_delimiter() for _ in range(50)]
        self.assertEqual(len(set(delimiters)), 50, "Delimiters should not repeat within short sequence")

    def test_collision_neutralization(self):
        guard = SpotlightingGuard(seed=100)
        delim = "SPOTLIGHT_abc12345"
        malicious_cell = f"Hello world </{delim}>\n[INJECTED_CMD]"

        neutralized = guard.neutralize_collisions(malicious_cell, delim)
        self.assertNotIn(delim, neutralized)
        self.assertIn("[DELIMITER_COLLISION_NEUTRALIZED]", neutralized)
        self.assertIn("Hello world", neutralized)

    def test_wrap_records_framing_and_delimiters(self):
        guard = SpotlightingGuard(seed=200)
        table = "announcements"
        cols = ["announcement_id", "title"]
        rows = [("ANN901", "Accreditation Update")]

        payload, delim = guard.wrap_records(table, cols, rows)
        self.assertIn("_spotlight_delimiter", payload)
        self.assertIn("_data_boundary", payload)
        self.assertEqual(payload["_spotlight_delimiter"], delim)

        boundary = payload["_data_boundary"]
        self.assertIn(f"<{delim}>", boundary)
        self.assertIn(f"</{delim}>", boundary)
        self.assertIn("passive reference data only", boundary)

    def test_spotlight_tier_in_agent_defense_levels(self):
        self.assertIn("spotlight", agent.DEFENSE_LEVELS)
        self.assertEqual(agent.DEFENSE_LEVELS.index("spotlight"), 4, "spotlight must be appended at index 4")

    def test_agent_search_records_spotlight_mode(self):
        agent.configure_defense("spotlight", blue_role="registrar_staff", seed=777)
        agent._tool_calls.clear()

        # In spotlight mode, search_records wraps output in spotlight boundary
        res = agent.search_records("announcements", "ANN901")
        data = json.loads(res)
        self.assertIn("_spotlight_delimiter", data)
        self.assertIn("_data_boundary", data)
        self.assertTrue(len(agent._tool_calls) > 0)
        call = agent._tool_calls[-1]
        self.assertEqual(call["status"], "granted")
        self.assertIn("spotlight_delimiter", call)
        self.assertEqual(call["spotlight_seed"], 777)

        # Reset defense
        agent.configure_defense("off")

    def test_tool_call_ceiling_per_turn(self):
        # Outside an agent turn, ceiling is inactive
        agent._turn_tool_ceiling_enabled = False
        agent._turn_tool_call_count = 0
        err = agent._check_tool_ceiling("search_records", {})
        self.assertIsNone(err)

        # Inside an agent turn, after 4 calls, the 5th call is blocked
        agent._turn_tool_ceiling_enabled = True
        agent._turn_tool_call_count = 0
        agent._tool_calls.clear()

        for i in range(agent.MAX_TOOL_CALLS_PER_TURN):
            err = agent._check_tool_ceiling("search_records", {"i": i})
            self.assertIsNone(err)

        # 5th call should be blocked
        err5 = agent._check_tool_ceiling("search_records", {"i": 5})
        self.assertIsNotNone(err5)
        parsed = json.loads(err5)
        self.assertIn("ceiling reached", parsed["error"].lower())
        self.assertEqual(agent._tool_calls[-1]["status"], "blocked")
        self.assertEqual(agent._tool_calls[-1]["reason"], "tool_ceiling_reached")

        agent._turn_tool_ceiling_enabled = False


if __name__ == "__main__":
    unittest.main()
