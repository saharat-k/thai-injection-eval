import unittest
from unittest.mock import patch
import core.cli.commands.chat as chat_cmd

class TestChatEnglishControls(unittest.TestCase):
    @patch("agent._choose")
    def test_review_payload_card_pure_english(self, mock_choose):
        # User selects action 0 (Dispatch)
        mock_choose.return_value = 0
        res = chat_cmd.review_payload_card("ทดสอบ Injection", source="Manual", no_color=True)
        self.assertEqual(res, "ทดสอบ Injection")
        
        # Check call arguments of mock_choose for pure English
        prompt_arg, options_arg, default_arg = mock_choose.call_args[0]
        # Must not contain Thai characters in control prompts/options
        for char in prompt_arg:
            self.assertFalse('\u0e00' <= char <= '\u0e7f', f"Found Thai char in prompt: {prompt_arg}")
        for opt in options_arg:
            for char in opt:
                self.assertFalse('\u0e00' <= char <= '\u0e7f', f"Found Thai char in option: {opt}")

    @patch("agent._ask", return_value="policy_puppetry")
    @patch("agent._choose", side_effect=[3, 0, 0])
    def test_review_payload_card_technique_controls_pure_english(self, mock_choose, _mock_ask):
        with patch("sys.stdout"):
            res = chat_cmd.review_payload_card("ทดสอบ Injection", source="Manual", no_color=True)
        self.assertIn("<interaction-config", res)
        for call in mock_choose.call_args_list:
            prompt_arg, options_arg, _ = call[0]
            self.assertFalse(any('\u0e00' <= c <= '\u0e7f' for c in prompt_arg), f"Found Thai char in prompt: {prompt_arg}")
            for opt in options_arg:
                self.assertFalse(any('\u0e00' <= c <= '\u0e7f' for c in opt), f"Found Thai char in option: {opt}")

if __name__ == "__main__":
    unittest.main()
