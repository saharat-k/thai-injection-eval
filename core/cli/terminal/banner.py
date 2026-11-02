"""ASCII Art Banner and Visual Identity for Thai Injection Eval CLI."""
import sys
from typing import List, Optional, TextIO

from core import __version__
from core.cli.terminal.colors import (
    BOLD,
    CYAN,
    DIM,
    GRAY,
    RED,
    RESET,
    WHITE,
    YELLOW,
    style,
)
from core.cli.terminal.tty import get_terminal_width, should_color, supports_utf8

# Figlet Slant font glyphs for "THAI" and "EVAL"
THAI_SLANT = [
    r"   ______  __  _____    ____",
    r"  /_  __/ / / /   |  /  _/",
    r"   / / / /_/ / /| |  / /  ",
    r"  / / / __  / ___ |_/ /   ",
    r" /_/ /_/ /_/_/  |_/___/   ",
]

EVAL_SLANT = [
    r"     _______ _    _____    __ ",
    r"    / ____/ | |  / /   |  / / ",
    r"   / __/    | | / / /| | / /  ",
    r"  / /___    | |/ / ___ |/ /___",
    r" /_____/    |___/_/  |_/_____/",
]


def get_banner(
    color: bool = True,
    subtitle: Optional[str] = None,
    width: Optional[int] = None,
    stream: Optional[TextIO] = None,
) -> str:
    """Generate the full ProjectDiscovery / Nuclei-style Slant ASCII banner."""
    lines = get_banner_lines(color=color, subtitle=subtitle, width=width, stream=stream)
    return "\n".join(lines)


def get_banner_lines(
    color: bool = True,
    subtitle: Optional[str] = None,
    width: Optional[int] = None,
    stream: Optional[TextIO] = None,
) -> List[str]:
    """Generate list of rendered lines for the banner."""
    use_utf8 = supports_utf8(stream)
    rule_char = "─" if use_utf8 else "-"
    term_width = width or get_terminal_width()
    banner_width = max(58, min(term_width - 2, 66))

    divider = f" {rule_char * banner_width}"
    styled_divider = style(divider, GRAY, enabled=color)

    output: List[str] = [""]

    # 1. ASCII Art with Dual-Tone Slant
    for t_part, e_part in zip(THAI_SLANT, EVAL_SLANT):
        if color:
            line = f"{RED}{BOLD}{t_part}{RESET}{CYAN}{BOLD}{e_part}{RESET}"
        else:
            line = f"{t_part}{e_part}"
        output.append(line)

    # 2. Top Divider
    output.append(styled_divider)

    # 3. Primary Title & Version Tag
    if color:
        tagline = (
            f"  {BOLD}{WHITE}Thai Prompt Injection Security Evaluator{RESET}"
            f"  {YELLOW}[v{__version__}]{RESET}"
        )
    else:
        tagline = f"  Thai Prompt Injection Security Evaluator  [v{__version__}]"
    output.append(tagline)

    # 4. Standards & Adversarial Telemetry
    if color:
        subtag = (
            f"  {DIM}OWASP LLM01 / LLM06  |  {RESET}"
            f"{RED}{BOLD}Red Adversary{RESET}{DIM} vs {RESET}"
            f"{CYAN}{BOLD}Blue Defense{RESET}"
        )
    else:
        subtag = "  OWASP LLM01 / LLM06  |  Red Adversary vs Blue Defense"
    output.append(subtag)

    # 5. Optional Contextual Subtitle
    if subtitle:
        if color:
            sub_line = f"  {DIM}Session: {RESET}{BOLD}{subtitle}{RESET}"
        else:
            sub_line = f"  Session: {subtitle}"
        output.append(sub_line)

    # 6. Bottom Divider
    output.append(styled_divider)
    output.append("")

    return output


def print_banner(
    stream: Optional[TextIO] = None,
    color_enabled: Optional[bool] = None,
    subtitle: Optional[str] = None,
    width: Optional[int] = None,
) -> None:
    """Print banner to the specified output stream (default sys.stdout)."""
    target = stream or sys.stdout
    effective_color = should_color(target) if color_enabled is None else color_enabled
    banner_text = get_banner(
        color=effective_color,
        subtitle=subtitle,
        width=width,
        stream=target,
    )
    try:
        print(banner_text, file=target)
    except UnicodeEncodeError:
        # Fallback to pure ASCII on legacy non-UTF8 terminals
        plain_ascii = banner_text.replace("─", "-").replace("═", "=")
        print(plain_ascii, file=target)
