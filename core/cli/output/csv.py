"""CSV tabular output formatting utilities."""
import csv
import io
from typing import List, Dict, Any, Optional


def format_csv(rows: List[Dict[str, Any]], fieldnames: Optional[List[str]] = None) -> str:
    """Format list of dicts as standard CSV string."""
    if not rows:
        return ""
    if isinstance(rows, dict):
        rows = [rows]

    if not fieldnames:
        keys = []
        for r in rows:
            if isinstance(r, dict):
                for k in r.keys():
                    if k not in keys:
                        keys.append(k)
        fieldnames = keys

    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for r in rows:
        if isinstance(r, dict):
            writer.writerow(r)
    return out.getvalue().strip()
