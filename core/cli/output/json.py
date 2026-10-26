"""JSON and JSONL formatting utilities."""
import json
from typing import Any, List, Dict


def format_json(data: Any, indent: int = 2) -> str:
    """Format data as pretty-printed JSON."""
    return json.dumps(data, ensure_ascii=False, indent=indent, default=str)


def format_jsonl(rows: List[Dict[str, Any]]) -> str:
    """Format list of dicts as JSON Lines (one JSON object per line)."""
    if isinstance(rows, dict):
        return json.dumps(rows, ensure_ascii=False, default=str)
    return "\n".join(json.dumps(r, ensure_ascii=False, default=str) for r in rows)
