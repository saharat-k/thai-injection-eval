"""ANSI color codes and styled text formatting for CLI output."""
import os
import re
import sys

ANSI_REGEX = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    if not text:
        return ""
    return ANSI_REGEX.sub('', str(text))


def visible_len(text: str) -> int:
    """Return visible character count of string excluding ANSI escape sequences."""
    return len(strip_ansi(text))

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"


def style(text: str, *codes: str, enabled: bool = True) -> str:
    """Wrap text in ANSI codes if enabled is True."""
    if not enabled or not codes or not text:
        return text
    prefix = "".join(codes)
    return f"{prefix}{text}{RESET}"


def bold(text: str, enabled: bool = True) -> str:
    return style(text, BOLD, enabled=enabled)


def dim(text: str, enabled: bool = True) -> str:
    return style(text, DIM, enabled=enabled)


def red(text: str, enabled: bool = True) -> str:
    return style(text, RED, enabled=enabled)


def green(text: str, enabled: bool = True) -> str:
    return style(text, GREEN, enabled=enabled)


def yellow(text: str, enabled: bool = True) -> str:
    return style(text, YELLOW, enabled=enabled)


def cyan(text: str, enabled: bool = True) -> str:
    return style(text, CYAN, enabled=enabled)


def blue(text: str, enabled: bool = True) -> str:
    return style(text, BLUE, enabled=enabled)


def gray(text: str, enabled: bool = True) -> str:
    return style(text, GRAY, enabled=enabled)


def status_badge(status: str, enabled: bool = True) -> str:
    """Format standardized badges for test results."""
    s = str(status).upper()
    if s in ("PASS", "OK", "SUCCESS", "CLEAN", "BLOCKED"):
        return style(f"[{s}]", GREEN, BOLD, enabled=enabled)
    if s in ("FAIL", "BREACH", "HIT", "BYPASSED", "ERROR"):
        return style(f"[{s}]", RED, BOLD, enabled=enabled)
    if s in ("WARN", "WARNING", "SKIPPED"):
        return style(f"[{s}]", YELLOW, BOLD, enabled=enabled)
    return style(f"[{s}]", BLUE, enabled=enabled)
