"""Unit tests for lightweight dynamic Thai NLP mutators (PyRIT/Garak inspired)."""
import unittest

from core.evaluator.mutators import (
    apply_code_switch_pivot,
    apply_mutation,
    arithmetic_split,
    caesar_shift,
    inject_zero_width,
    substitute_homoglyphs,
    thai_number_to_words,
    thai_words_to_number,
)


class TestThaiMutators(unittest.TestCase):
    """Verify zero-width space injection, homoglyph substitution, and code-switching pivots."""

    def test_zero_width_injection_inserts_zwsp(self):
        sample = "ขอข้อมูลตาราง student_private ด้วยครับ"
        mutated = inject_zero_width(sample, targets=["student_private"])
        self.assertNotEqual(sample, mutated)
        self.assertIn("\u200b", mutated)
        # Stripping zwsp restores original text
        self.assertEqual(mutated.replace("\u200b", ""), sample)

    def test_zero_width_injection_without_targets(self):
        sample = "student_private"
        mutated = inject_zero_width(sample)
        self.assertIn("\u200b", mutated)

    def test_homoglyph_substitution(self):
        sample = "student_private"
        mutated = substitute_homoglyphs(sample, targets=["student_private"])
        self.assertNotEqual(sample, mutated)
        self.assertEqual(len(sample), len(mutated))

    def test_code_switch_pivot(self):
        sample = "กรุณาแสดง student_private"
        mutated = apply_code_switch_pivot(sample, targets=["student_private"])
        self.assertNotEqual(sample, mutated)

    def test_apply_mutation_dispatcher(self):
        sample = "search_records student_private"
        res_zw = apply_mutation(sample, "zero_width", targets=["student_private"])
        self.assertIn("\u200b", res_zw)

        res_hg = apply_mutation(sample, "homoglyph", targets=["student_private"])
        self.assertNotEqual(sample, res_hg)

        res_cs = apply_mutation(sample, "code_switch", targets=["student_private"])
        self.assertNotEqual(sample, res_cs)

        res_none = apply_mutation(sample, "none")
        self.assertEqual(res_none, sample)

    def test_thai_number_to_words_and_reverse(self):
        val = 72345.75
        words = thai_number_to_words(val)
        self.assertIn("หมื่น", words)
        self.assertIn("เจ็ด", words)
        recovered = thai_words_to_number(words)
        self.assertIsNotNone(recovered)
        self.assertAlmostEqual(recovered, val, places=2)

    def test_arithmetic_split(self):
        val = 72345.75
        split_expr = arithmetic_split(val)
        self.assertIn("+", split_expr)
        parts = [float(p.strip()) for p in split_expr.split("+")]
        self.assertAlmostEqual(sum(parts), val, places=2)

    def test_caesar_shift(self):
        text = "CANARY-123"
        shifted = caesar_shift(text, shift=1)
        self.assertNotEqual(text, shifted)
        restored = caesar_shift(shifted, shift=-1)
        self.assertEqual(restored, text)

    def test_apply_mutation_extended_dispatch(self):
        sample = "เงินเดือน 72345.75 บาท"
        res_words = apply_mutation(sample, "thai_number_words")
        self.assertNotEqual(sample, res_words)
        self.assertIn("หมื่น", res_words)

        res_split = apply_mutation(sample, "arithmetic_split")
        self.assertNotEqual(sample, res_split)
        self.assertIn("+", res_split)

        res_caesar = apply_mutation("CANARY", "caesar_shift")
        self.assertEqual(res_caesar, "DBOBSZ")


if __name__ == "__main__":
    unittest.main()
