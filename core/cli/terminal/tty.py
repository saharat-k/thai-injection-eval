"""TTY detection and terminal environment utilities."""
import os
import shutil
import sys
from typing import Optional


def is_tty(stream=None) -> bool:
    """Return True if stream is attached to an interactive terminal."""
    target = stream if stream is not None else sys.stdout
    try:
        return hasattr(target, "isatty") and target.isatty()
    except Exception:
        return False


def should_color(stream=None, force_no_color: bool = False) -> bool:
    """Determine whether color output should be enabled.

    Adheres to the NO_COLOR standard (https://no-color.org/) and FORCE_COLOR env var.
    """
    if force_no_color:
        return False
    if "NO_COLOR" in os.environ and os.environ["NO_COLOR"].strip() != "":
        return False
    if "FORCE_COLOR" in os.environ and os.environ["FORCE_COLOR"] not in ("0", "false", "False"):
        return True
    return is_tty(stream)


def get_terminal_width(default: int = 80) -> int:
    """Get the current terminal width in characters."""
    try:
        size = shutil.get_terminal_size(fallback=(default, 24))
        return max(40, size.columns)
    except Exception:
        return default
