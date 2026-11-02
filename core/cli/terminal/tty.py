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


def supports_utf8(stream=None) -> bool:
    """Return True if stream encoding supports UTF-8 characters."""
    target = stream or sys.stdout
    enc = getattr(target, "encoding", None)
    if not isinstance(enc, str):
        return True
    return "utf" in enc.lower()


def get_rule_line(width: int = 60, double: bool = False, stream=None) -> str:
    """Return safe horizontal rule line (Unicode box-drawing or ASCII fallback)."""
    if supports_utf8(stream):
        char = "═" if double else "─"
    else:
        char = "=" if double else "-"
    return char * width


def get_glyph(char: str, fallback: str, stream=None) -> str:
    """Return unicode glyph if stream supports utf-8, else ASCII fallback."""
    return char if supports_utf8(stream) else fallback


EMOJI_FALLBACK_MAP = {
    "🧠": "[STRATEGY]",
    "📤": "[OUTGOING]",
    "📥": "[INCOMING]",
    "⚠️": "[!]",
    "🔧": "[TOOLS]",
    "🛡️": "[SECURITY]",
    "🛡": "[SECURITY]",
    "🚨": "[ALERT]",
    "🎯": "[TARGET]",
    "🔑": "[KEY]",
    "📋": "[SCHEMA]",
    "➔": "->",
    "✔": "[OK]",
    "■": "*",
    "•": "*",
    "─": "-",
    "═": "=",
}


def sanitize_for_stream(text: str, stream=None) -> str:
    """Convert characters that cannot be encoded by stream into safe ASCII representations."""
    target = stream or sys.stdout
    enc = getattr(target, "encoding", None)
    if not isinstance(enc, str):
        return str(text)
    try:
        text.encode(enc)
        return text
    except (UnicodeEncodeError, LookupError):
        res = str(text)
        for em, repl in EMOJI_FALLBACK_MAP.items():
            res = res.replace(em, repl)
        try:
            res.encode(enc)
            return res
        except Exception:
            return res.encode(enc, errors="replace").decode(enc)


def safe_print(*args, **kwargs) -> None:
    """Print to stream safely, replacing non-encodable characters if needed."""
    stream = kwargs.get("file") or sys.stdout
    enc = getattr(stream, "encoding", None)
    if isinstance(enc, str) and not ("utf" in enc.lower()):
        args = tuple(sanitize_for_stream(str(a), stream=stream) for a in args)
    print(*args, **kwargs)
