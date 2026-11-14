"""Unit tests for Thai traditional numerals mutator and DLP decoding."""
import unittest

from core.evaluator.mutators import (
    to_thai_numerals,
    from_thai_numerals,
    apply_mutation,
)
from core.defenses.dlp import detect_leaked_canaries, apply_defense_output


class TestThaiDigitsMutator(unittest.TestCase):
    def test_to_thai_numerals(self):
        """Verify ASCII digits convert cleanly to Thai numerals."""
        self.assertEqual(to_thai_numerals("72345.75"), "๗๒๓๔๕.๗๕")
        self.assertEqual(to_thai_numerals("ID: 1-2345-67890-12-3"), "ID: ๑-๒๓๔๕-๖๗๘๙๐-๑๒-๓")
        self.assertEqual(to_thai_numerals("ไม่มีตัวเลข"), "ไม่มีตัวเลข")

    def test_from_thai_numerals(self):
        """Verify Thai numerals convert back to ASCII digits."""
        self.assertEqual(from_thai_numerals("เงินเดือน ๗๒๓๔๕.๗๕ บาท"), "เงินเดือน 72345.75 บาท")
        self.assertEqual(from_thai_numerals("บัตรประชาชน ๑-๒๓๔๕-๖๗๘๙๐-๑๒-๓"), "บัตรประชาชน 1-2345-67890-12-3")

    def test_apply_mutation_thai_digits(self):
        """Verify apply_mutation dispatcher with 'thai_digits' and 'thai_numerals'."""
        self.assertEqual(apply_mutation("เงินเดือน 72345.75", "thai_digits"), "เงินเดือน ๗๒๓๔๕.๗๕")
        self.assertEqual(apply_mutation("รหัส 12345", "thai_numerals"), "รหัส ๑๒๓๔๕")

    def test_canary_detection_with_thai_digits(self):
        """Verify detect_leaked_canaries identifies canaries rendered in Thai digits."""
        canaries = {"72345.75"}
        text_with_thai_digits = "ยอดเงินเดือนคือ ๗๒๓๔๕.๗๕ บาทถ้วน"
        leaks = detect_leaked_canaries(text_with_thai_digits, canaries, extended_decoders=True)
        self.assertIn("72345.75", leaks)

    def test_defense_output_with_thai_digits(self):
        """Verify apply_defense_output redacts Thai digits when defense is 'all'."""
        canaries = {"72345.75"}
        text_with_thai_digits = "ยอดเงินเดือนคือ ๗๒๓๔๕.๗๕ บาทถ้วน"
        redacted = apply_defense_output(text_with_thai_digits, "all", canaries)
        self.assertEqual(redacted, "[REDACTED: Sensitive data blocked by output guard]")


if __name__ == "__main__":
    unittest.main()
