"""Terminal and TTY management utilities."""
from core.cli.terminal.tty import (
    is_tty,
    should_color,
    get_terminal_width,
    supports_utf8,
    get_rule_line,
    get_glyph,
    sanitize_for_stream,
    safe_print,
)
from core.cli.terminal.colors import style, bold, dim, red, green, yellow, cyan, blue, gray, status_badge
from core.cli.terminal.progress import ProgressReporter
from core.cli.terminal.banner import get_banner, get_banner_lines, print_banner

__all__ = [
    "is_tty",
    "should_color",
    "get_terminal_width",
    "supports_utf8",
    "get_rule_line",
    "get_glyph",
    "sanitize_for_stream",
    "safe_print",
    "style",
    "bold",
    "dim",
    "red",
    "green",
    "yellow",
    "cyan",
    "blue",
    "gray",
    "status_badge",
    "ProgressReporter",
    "get_banner",
    "get_banner_lines",
    "print_banner",
]
