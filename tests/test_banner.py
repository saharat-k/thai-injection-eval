"""Unit tests for CLI Banner, ASCII art rendering, and color hygiene."""
import io
import unittest
from unittest.mock import patch

from core import __version__
from core.cli.terminal.banner import get_banner, get_banner_lines, print_banner
from core.cli.terminal.colors import strip_ansi
from core.cli.app import build_parser, main


class BannerRenderingTests(unittest.TestCase):
    """Test suite for ASCII art banner generation, styling, and terminal compatibility."""

    def test_banner_content_and_version(self):
        """Banner must contain project title, OWASP standards, and current version."""
        banner = get_banner(color=False)
        self.assertIn("Thai Prompt Injection Security Evaluator", banner)
        self.assertIn(f"v{__version__}", banner)
        self.assertIn("OWASP LLM01 / LLM06", banner)
        self.assertIn("Red Adversary", banner)
        self.assertIn("Blue Defense", banner)

    def test_banner_color_hygiene(self):
        """Color banner must contain ANSI escapes; non-color banner must be 100% clean."""
        color_banner = get_banner(color=True)
        self.assertIn("\033[", color_banner)

        plain_banner = get_banner(color=False)
        self.assertEqual(strip_ansi(plain_banner), plain_banner)
        self.assertNotIn("\033[", plain_banner)

    def test_banner_subtitle_injection(self):
        """Custom subtitle must be cleanly rendered within the banner frame."""
        banner = get_banner(color=False, subtitle="Interactive Wizard Mode")
        self.assertIn("Session: Interactive Wizard Mode", banner)

    def test_print_banner_output_stream(self):
        """print_banner must write properly to any TextIO stream."""
        buf = io.StringIO()
        print_banner(stream=buf, color_enabled=False, subtitle="Diagnostics Stream")
        output = buf.getvalue()
        self.assertIn("Thai Prompt Injection Security Evaluator", output)
        self.assertIn("Diagnostics Stream", output)

    def test_root_parser_help_contains_banner(self):
        """Root parser format_help must include ASCII art banner."""
        parser = build_parser()
        with patch("sys.argv", ["thai-eval", "--help"]):
            help_text = parser.format_help()
            self.assertIn("Thai Prompt Injection Security Evaluator", help_text)
            self.assertIn("OWASP LLM01 / LLM06", help_text)

    def test_quiet_suppresses_banner_in_help(self):
        """Quiet mode (-q, --quiet) must suppress the ASCII banner in help output."""
        parser = build_parser()
        with patch("sys.argv", ["thai-eval", "-q", "--help"]):
            help_text = parser.format_help()
            self.assertNotIn("______  __  _____", help_text)
            self.assertNotIn(f"[v{__version__}]", help_text)

    def test_subparser_help_does_not_duplicate_banner(self):
        """Subcommands (e.g. thai-eval eval --help) must not show root banner."""
        parser = build_parser()
        # Find eval subparser
        subparser_action = [
            action for action in parser._actions
            if action.dest == "command"
        ][0]
        eval_parser = subparser_action.choices["eval"]
        eval_help = eval_parser.format_help()
        self.assertNotIn("______  __  _____", eval_help)
        self.assertNotIn(f"[v{__version__}]", eval_help)

    def test_legacy_cp1252_encoding_safety(self):
        """Banner and safe_print must never crash with UnicodeEncodeError on cp1252 streams."""
        from core.cli.terminal.tty import safe_print, get_rule_line, get_glyph, sanitize_for_stream

        # Create strict cp1252 stream
        stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")

        # 1. Print banner to cp1252 stream
        print_banner(stream=stream, color_enabled=False, subtitle="Encoding Test")

        # 2. Rule line fallback to pure ASCII
        rule = get_rule_line(40, double=True, stream=stream)
        self.assertEqual(rule, "=" * 40)
        stream.write(rule)

        # 3. safe_print with emojis
        safe_print("🚨 ALERT: 🧠 Strategy ➔ 🛡️ Blocked ✔", file=stream)

        # 4. Verify output content
        stream.seek(0)
        raw = stream.read()
        self.assertIn("Thai Prompt Injection Security Evaluator", raw)
        self.assertIn("[ALERT]", raw)
        self.assertIn("[STRATEGY]", raw)
        self.assertIn("[OK]", raw)
