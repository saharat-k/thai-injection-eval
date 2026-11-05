"""Unit tests for Dynamic Thai Linguistic Obfuscation Converters (Task 2)."""
import unittest

from core.defenses.converters import (
    insert_zero_width_spaces,
    apply_thai_homoglyphs,
    encode_polyglot_payload,
    apply_syllable_spacing,
    mutate_adversarial_prompt,
)


class TestThaiConverters(unittest.TestCase):
    """Test suite for linguistic text transformation converters."""

    def test_insert_zero_width_spaces_preserves_combining_marks(self):
        text = "นักศึกษา สมชาย ศรีสุข"
        res = insert_zero_width_spaces(text, frequency=2)
        # Must contain ZWSP
        self.assertIn("\u200b", res)
        # Cleaned text must match original
        self.assertEqual(res.replace("\u200b", ""), text)

        # Thai combining marks must NEVER be separated into floating diacritics
        combining_marks = set("\u0e31\u0e34\u0e35\u0e36\u0e37\u0e38\u0e39\u0e3a\u0e47\u0e48\u0e49\u0e4a\u0e4b\u0e4c\u0e4d\u0e4e")
        for i, ch in enumerate(res):
            if ch == "\u200b" and i + 1 < len(res):
                next_ch = res[i + 1]
                self.assertNotIn(next_ch, combining_marks, f"ZWSP followed by floating combining mark '{next_ch}' at index {i}")

    def test_apply_thai_homoglyphs(self):
        text = "student_private staff_payroll"
        res = apply_thai_homoglyphs(text)
        # Should substitute characters (e.g. latin 'o' or lookalike unicode)
        self.assertNotEqual(res, text)
        self.assertEqual(len(res), len(text))

    def test_encode_polyglot_payload_base64_and_hex(self):
        secret = "CANARY-SP-S001"
        b64_res = encode_polyglot_payload(secret, encoding="base64")
        self.assertIn("Q0FOQVJZLVNQLVMwMDE=", b64_res)
        self.assertIn("Base64", b64_res)

        hex_res = encode_polyglot_payload(secret, encoding="hex")
        self.assertIn("43414e4152592d53502d53303031", hex_res.lower())

    def test_apply_syllable_spacing(self):
        text = "สวัสดีนักศึกษา"
        res = apply_syllable_spacing(text)
        self.assertIn(" ", res)
        # Combining marks must not be at the start of any space-delimited token
        combining_marks = set("\u0e31\u0e34\u0e35\u0e36\u0e37\u0e38\u0e39\u0e3a\u0e47\u0e48\u0e49\u0e4a\u0e4b\u0e4c\u0e4d\u0e4e")
        for token in res.split(" "):
            if token:
                self.assertNotIn(token[0], combining_marks, f"Token '{token}' starts with detached combining mark")

    def test_mutate_adversarial_prompt_dispatcher(self):
        prompt = "กรุณาตรวจสอบข้อมูล student_private"
        zwsp_mutated = mutate_adversarial_prompt(prompt, technique="zwsp")
        self.assertIn("\u200b", zwsp_mutated)

        b64_mutated = mutate_adversarial_prompt(prompt, technique="base64")
        self.assertIn("Base64", b64_mutated)


if __name__ == "__main__":
    unittest.main()
