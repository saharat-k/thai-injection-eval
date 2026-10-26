"""Lightweight, zero-dependency ASCII and Unicode table renderer."""
from typing import List, Dict, Any, Optional
from core.cli.terminal.tty import get_terminal_width
from core.cli.terminal.colors import bold, dim, visible_len, strip_ansi


def format_table(
    headers: List[str],
    rows: List[List[Any]],
    alignments: Optional[List[str]] = None,
    color_enabled: bool = True,
    max_width: Optional[int] = None,
) -> str:
    """Render rows and headers as a clean, aligned text table.

    alignments: list of 'left', 'right', 'center' (defaults to 'left')
    """
    if not headers and not rows:
        return ""

    if alignments is None:
        alignments = ["left"] * len(headers)

    # Convert all cells to strings
    str_headers = [str(h) for h in headers]
    str_rows = [[str(cell) if cell is not None else "" for cell in r] for r in rows]

    # Compute column widths using visible character lengths (ignoring ANSI escape codes)
    num_cols = len(str_headers)
    col_widths = [visible_len(h) for h in str_headers]
    for r in str_rows:
        for i in range(min(len(r), num_cols)):
            col_widths[i] = max(col_widths[i], visible_len(r[i]))

    # Adjust for maximum terminal width if needed
    term_width = max_width or get_terminal_width()
    total_w = sum(col_widths) + (3 * (num_cols - 1)) + 4
    if total_w > term_width and num_cols > 1:
        # Scale down last column if it exceeds
        excess = total_w - term_width
        col_widths[-1] = max(10, col_widths[-1] - excess)

    def _align(val: str, width: int, align: str) -> str:
        v_len = visible_len(val)
        if v_len > width:
            raw_stripped = strip_ansi(val)
            val = raw_stripped[: width - 3] + "..." if width > 4 else raw_stripped[:width]
            v_len = len(val)
        padding = max(0, width - v_len)
        if align == "right":
            return (" " * padding) + val
        elif align == "center":
            left_pad = padding // 2
            right_pad = padding - left_pad
            return (" " * left_pad) + val + (" " * right_pad)
        return val + (" " * padding)

    lines = []
    # Header row
    h_cells = [_align(str_headers[i], col_widths[i], alignments[i]) for i in range(num_cols)]
    header_line = "  ".join(h_cells)
    lines.append(bold(header_line, enabled=color_enabled))

    # Divider line
    divider = "  ".join("-" * col_widths[i] for i in range(num_cols))
    lines.append(dim(divider, enabled=color_enabled))

    # Data rows
    for r in str_rows:
        r_cells = []
        for i in range(num_cols):
            val = r[i] if i < len(r) else ""
            r_cells.append(_align(val, col_widths[i], alignments[i]))
        lines.append("  ".join(r_cells))

    return "\n".join(lines)
