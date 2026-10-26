"""Terminal and TTY management utilities."""
from core.cli.terminal.tty import is_tty, should_color, get_terminal_width
from core.cli.terminal.colors import style, bold, dim, red, green, yellow, cyan, blue, gray, status_badge
from core.cli.terminal.progress import ProgressReporter

__all__ = [
    "is_tty",
    "should_color",
    "get_terminal_width",
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
]
