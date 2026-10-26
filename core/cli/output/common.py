"""Unified Output Formatter supporting table, json, jsonl, and csv."""
import sys
from typing import Any, List, Dict, Optional
from core.cli.output.table import format_table
from core.cli.output.json import format_json, format_jsonl
from core.cli.output.csv import format_csv
from core.cli.terminal.tty import should_color

SUPPORTED_FORMATS = ("table", "json", "jsonl", "csv")


def render_output(
    data: Any,
    format_name: str = "table",
    headers: Optional[List[str]] = None,
    table_rows: Optional[List[List[Any]]] = None,
    alignments: Optional[List[str]] = None,
    stream=None,
    no_color: bool = False,
) -> str:
    """Format and print or return string according to format_name."""
    target_stream = stream or sys.stdout
    color_enabled = should_color(target_stream, force_no_color=no_color)
    fmt = (format_name or "table").lower()

    if fmt == "json":
        text = format_json(data)
    elif fmt == "jsonl":
        if isinstance(data, list):
            text = format_jsonl(data)
        else:
            text = format_json(data, indent=None)
    elif fmt == "csv":
        if isinstance(data, list) and all(isinstance(x, dict) for x in data):
            text = format_csv(data)
        elif isinstance(data, dict):
            text = format_csv([data])
        else:
            text = format_csv([{"value": str(x)} for x in (data if isinstance(data, list) else [data])])
    else:  # default to table
        if headers is not None and table_rows is not None:
            text = format_table(headers, table_rows, alignments=alignments, color_enabled=color_enabled)
        elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            h = list(data[0].keys())
            rows = [[row.get(k, "") for k in h] for row in data]
            text = format_table(h, rows, color_enabled=color_enabled)
        elif isinstance(data, dict):
            h = ["Key", "Value"]
            rows = [[k, str(v)] for k, v in data.items()]
            text = format_table(h, rows, color_enabled=color_enabled)
        else:
            text = str(data)

    if stream is not None:
        print(text, file=stream)
    return text
