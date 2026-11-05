"""Tests for OpenAI-compatible target adapter with multi-turn function calling loop."""
import json
import unittest
from unittest.mock import MagicMock, patch

from core.adapters.openai_like import OpenAILikeTargetAdapter


class TestOpenAILikeTargetAdapter(unittest.TestCase):
    """Test OpenAI-compatible adapter tool calling loop with mocked HTTP."""

    def test_single_turn_text_response(self):
        """Adapter correctly parses a standard assistant message without tools."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "gpt-4o-mini"})
        mock_resp_body = {
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
            "usage": {"total_tokens": 10},
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_cm = MagicMock()
            mock_cm.read.return_value = json.dumps(mock_resp_body).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Hi")
            self.assertEqual(resp.text, "Hello!")
            self.assertEqual(len(resp.tool_calls), 0)
            self.assertIsNone(resp.error)

    def test_multi_turn_function_calling_loop(self):
        """Adapter executes tool calling loop when model returns tool_calls."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "typhoon-2", "defense": "tools"})

        turn1_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "search_records",
                            "arguments": json.dumps({"table": "students", "keyword": "S001"}),
                        },
                    }],
                }
            }]
        }
        turn2_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Student S001 is Somchai Srisuk, Computer Science.",
                }
            }]
        }

        responses = [
            json.dumps(turn1_body).encode("utf-8"),
            json.dumps(turn2_body).encode("utf-8"),
        ]

        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("agent.search_records", return_value="[Found S001]") as mock_search:
            mock_cm = MagicMock()
            mock_cm.read.side_effect = responses
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Who is S001?")
            self.assertEqual(resp.text, "Student S001 is Somchai Srisuk, Computer Science.")
            self.assertEqual(len(resp.tool_calls), 1)
            self.assertEqual(resp.tool_calls[0]["tool"], "search_records")
            self.assertEqual(resp.tool_calls[0]["args"], {"table": "students", "keyword": "S001"})
            mock_search.assert_called_once_with("students", "S001")

    def test_tool_calling_loop_max_turns_enforced(self):
        """Adapter halts loop and does not hang if model calls tools indefinitely."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "loop-model"})
        infinite_tool_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_inf",
                        "type": "function",
                        "function": {
                            "name": "search_records",
                            "arguments": '{"table": "students", "keyword": "loop"}',
                        },
                    }],
                }
            }]
        }
        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("agent.search_records", return_value="result"):
            mock_cm = MagicMock()
            mock_cm.read.return_value = json.dumps(infinite_tool_body).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Loop me")
            self.assertLessEqual(len(resp.tool_calls), 4)

    def test_malformed_tool_arguments_graceful_handling(self):
        """Malformed JSON arguments from model do not crash the adapter."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "test"})
        turn1_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_bad",
                        "type": "function",
                        "function": {"name": "search_records", "arguments": "NOT_JSON"},
                    }],
                }
            }]
        }
        turn2_body = {
            "choices": [{"message": {"role": "assistant", "content": "Recovered"}}]
        }
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_cm = MagicMock()
            mock_cm.read.side_effect = [
                json.dumps(turn1_body).encode("utf-8"),
                json.dumps(turn2_body).encode("utf-8"),
            ]
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Query")
            self.assertEqual(resp.text, "Recovered")


if __name__ == "__main__":
    unittest.main()
