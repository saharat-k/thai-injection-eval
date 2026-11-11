"""Unit tests for Agentic Multi-Hop Tool Chaining and Excessive Agency defenses."""
import json
import unittest

import agent
from core.adapters.openai_like import OpenAILikeTargetAdapter


class TestMultiHopTools(unittest.TestCase):
    """Verify export_report, send_campus_notification, and excessive agency policy."""

    def setUp(self):
        agent.configure_defense("all", blue_role="registrar_staff")
        agent._tool_calls.clear()

    def tearDown(self):
        agent.configure_defense("off", blue_role="registrar_staff")
        agent._tool_calls.clear()

    def test_export_report_success(self):
        """export_report should return success JSON and log granted telemetry."""
        res_str = agent.export_report(title="Audit 2026", content="# Summary\nClean run", format="markdown")
        data = json.loads(res_str)
        self.assertEqual(data.get("status"), "success")
        self.assertIn("Audit 2026", data.get("message", ""))

        # Check telemetry
        self.assertTrue(any(
            tc.get("tool") == "export_report" and tc.get("status") == "granted"
            for tc in agent._tool_calls
        ))

    def test_send_campus_notification_granted_for_staff(self):
        """Staff role should be permitted to send campus notifications."""
        agent.configure_defense("all", blue_role="registrar_staff")
        res_str = agent.send_campus_notification("REGISTRAR", "System health normal")
        data = json.loads(res_str)
        self.assertEqual(data.get("status"), "delivered")
        self.assertEqual(data.get("recipient"), "REGISTRAR")

        self.assertTrue(any(
            tc.get("tool") == "send_campus_notification" and tc.get("status") == "granted"
            for tc in agent._tool_calls
        ))

    def test_send_campus_notification_blocked_for_student_guest(self):
        """Excessive Agency Defense: student_guest is prohibited from dispatching campus notifications."""
        agent.configure_defense("all", blue_role="student_guest")
        res_str = agent.send_campus_notification("REGISTRAR", "Tampering notice")
        data = json.loads(res_str)
        self.assertIn("error", data)
        self.assertIn("prohibited", data["error"])

        # Telemetry should reflect blocked status
        self.assertTrue(any(
            tc.get("tool") == "send_campus_notification"
            and tc.get("status") == "blocked"
            and tc.get("reason") == "excessive_agency_blocked"
            for tc in agent._tool_calls
        ))

    def test_openai_like_tools_spec_contains_multihop_tools(self):
        """OpenAILikeTargetAdapter._get_tools_spec should declare all multi-hop tools."""
        specs = OpenAILikeTargetAdapter._get_tools_spec()
        tool_names = [s.get("function", {}).get("name") for s in specs]
        self.assertIn("search_records", tool_names)
        self.assertIn("export_report", tool_names)
        self.assertIn("send_campus_notification", tool_names)


if __name__ == "__main__":
    unittest.main()
