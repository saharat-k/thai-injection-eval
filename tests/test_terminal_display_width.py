import unittest
from core.cli.terminal.colors import visible_len, strip_ansi
from core.cli.output.table import format_table

class TestTerminalDisplayWidth(unittest.TestCase):
    def test_ansi_and_zero_width_spaces(self):
        colored_plain = "\033[31mHello\033[0m"
        self.assertEqual(visible_len(colored_plain), 5)

        # Zero-width spaces and joiners should have 0 terminal cell width
        zw_text = "Attack\u200bPayload\ufeff\u200c"
        self.assertEqual(visible_len(zw_text), 13)

    def test_thai_combining_characters(self):
        # 'ก' (1) + 'า' (1) = 2 cells
        # 'ก' (1) + 'ิ' (0 combining) + 'น' (1) = 2 cells
        self.assertEqual(visible_len("กา"), 2)
        self.assertEqual(visible_len("กิน"), 2)

    def test_table_formatting_with_mutated_text(self):
        headers = ["ID", "Payload", "Status"]
        rows = [
            ["TH-1", "Hello\u200bWorld", "DEFENDED"],
            ["TH-2", "Simple", "BREACHED"],
        ]
        table_output = format_table(headers, rows)
        self.assertIn("Hello\u200bWorld", table_output)
        self.assertIn("DEFENDED", table_output)

if __name__ == "__main__":
    unittest.main()
