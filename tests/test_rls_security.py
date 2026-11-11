"""Unit tests for Row-Level Security (RLS) and DLP multi-decoder protections."""
import json
import os
import unittest
from unittest.mock import patch

import agent
from core.db import (
    get_session_user_context,
    is_rls_enabled,
    set_session_user_context,
)
from core.defenses.dlp import apply_defense_output


class TestRowLevelSecurity(unittest.TestCase):
    """Verify Layer 2.5 Row-Level Security (RLS) enforcement on student/professor records."""

    def setUp(self):
        # Reset session user context before each test
        set_session_user_context(None, None)
        agent.configure_defense("all", blue_role="registrar_staff")
        agent._tool_calls.clear()

    def tearDown(self):
        set_session_user_context(None, None)
        agent.configure_defense("off", blue_role="registrar_staff")
        agent._tool_calls.clear()

    def test_session_user_context_get_and_set(self):
        """User context should be settable and retrievable."""
        self.assertEqual(get_session_user_context(), (None, None))
        set_session_user_context("S001", "student_user")
        self.assertEqual(get_session_user_context(), ("S001", "student_user"))

    def test_is_rls_enabled(self):
        """RLS should be active when user context is set or env var is 1."""
        self.assertFalse(is_rls_enabled())
        set_session_user_context("S001", "student_user")
        self.assertTrue(is_rls_enabled())

        set_session_user_context(None, None)
        with patch.dict(os.environ, {"ENABLE_ROW_LEVEL_SECURITY": "1"}):
            self.assertTrue(is_rls_enabled())

    def test_search_records_without_rls(self):
        """When RLS is not active, search_records on enrollments returns all matching students."""
        set_session_user_context(None, None)
        res_str = agent.search_records("enrollments", "2567")
        data = json.loads(res_str)
        self.assertIn("rows", data)
        idx = data["columns"].index("student_id")
        student_ids = {r[idx] for r in data["rows"]}
        self.assertGreater(len(student_ids), 1)

    def test_search_records_with_rls_isolates_student_records(self):
        """When RLS is active for S001, searching enrollments returns ONLY S001 records."""
        set_session_user_context("S001", "student_user")
        res_str = agent.search_records("enrollments", "2567")
        data = json.loads(res_str)
        self.assertIn("rows", data)
        self.assertGreater(len(data["rows"]), 0)
        idx = data["columns"].index("student_id")
        for r in data["rows"]:
            self.assertEqual(r[idx], "S001")

    def test_search_records_with_rls_isolates_awards(self):
        """When RLS is active for S001, awards table is strictly filtered by student_id."""
        set_session_user_context("S001", "student_user")
        res_str = agent.search_records("awards", "ระดับมหาวิทยาลัย")
        data = json.loads(res_str)
        self.assertIn("rows", data)
        self.assertGreater(len(data["rows"]), 0)
        idx = data["columns"].index("student_id")
        for r in data["rows"]:
            self.assertEqual(r[idx], "S001")

    def test_search_records_rls_bypassed_for_system_admin(self):
        """System administrator role bypasses RLS filtering for administrative maintenance."""
        set_session_user_context("admin_01", "system_admin")
        res_str = agent.search_records("enrollments", "2567")
        data = json.loads(res_str)
        self.assertIn("rows", data)
        idx = data["columns"].index("student_id")
        student_ids = {r[idx] for r in data["rows"]}
        self.assertGreater(len(student_ids), 1)


class TestDLPExtendedDecoders(unittest.TestCase):
    """Verify DLP multi-decoder canary interception."""

    def setUp(self):
        self.canaries = {"SECRET_CANARY_TOKEN_99"}

    def test_plaintext_canary_redacted(self):
        """Exact canary matches are always redacted under defense == 'all'."""
        text = "Confidential record: SECRET_CANARY_TOKEN_99 is active."
        result = apply_defense_output(text, "all", self.canaries)
        self.assertNotIn("SECRET_CANARY_TOKEN_99", result)
        self.assertIn("[REDACTED]", result)

    def test_base64_canary_redacted_with_extended_decoders(self):
        """Base64 encoded canary token is decoded and redacted when extended_decoders is enabled."""
        import base64
        b64_val = base64.b64encode(b"SECRET_CANARY_TOKEN_99").decode("ascii")
        text = f"Here is the token payload: {b64_val}"

        # With extended_decoders=True, base64 payload is caught
        result = apply_defense_output(text, "all", self.canaries, extended_decoders=True)
        self.assertNotIn(b64_val, result)
        self.assertIn("[REDACTED]", result)

    def test_hex_canary_redacted_with_extended_decoders(self):
        """Hex encoded canary token is decoded and redacted when extended_decoders is enabled."""
        hex_val = "SECRET_CANARY_TOKEN_99".encode("utf-8").hex()
        text = f"Extracted hex dump: {hex_val}"

        result = apply_defense_output(text, "all", self.canaries, extended_decoders=True)
        self.assertNotIn(hex_val, result)
        self.assertIn("[REDACTED]", result)

    def test_env_var_activates_extended_decoders(self):
        """DLP_EXTENDED_DECODERS=1 environment variable activates extended decoders by default."""
        import base64
        b64_val = base64.b64encode(b"SECRET_CANARY_TOKEN_99").decode("ascii")
        text = f"Token: {b64_val}"

        with patch.dict(os.environ, {"DLP_EXTENDED_DECODERS": "1"}):
            result = apply_defense_output(text, "all", self.canaries, extended_decoders=None)
            self.assertNotIn(b64_val, result)
            self.assertIn("[REDACTED]", result)


if __name__ == "__main__":
    unittest.main()
