"""DLP command: offline deterministic audit of DLP bypass encodings."""
import sys
from typing import List, Dict, Any

from core.evaluator.probing import evaluate_dlp_bypass_probes
from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, status_badge, green, red, yellow


def run_dlp_audit(args) -> int:
    """Execute offline deterministic DLP bypass probe audit."""
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)
    quiet = getattr(args, "quiet", False)

    rows = evaluate_dlp_bypass_probes()
    total = len(rows)
    bypassed_count = sum(1 for r in rows if r.get("bypass_succeeded"))

    formatted_rows = []
    for r in rows:
        bypassed = bool(r.get("bypass_succeeded"))
        status_label = "BYPASSED" if bypassed else "BLOCKED"
        formatted_rows.append({
            "pair_id": r.get("pair_id", ""),
            "encoding": r.get("encoding", ""),
            "status": status_label,
            "expected_canary": r.get("expected_canary", ""),
        })

    if fmt == "table":
        if not quiet:
            print("\n" + bold("[OFFLINE DLP BYPASS AUDIT - 0 LLM API CALLS]", enabled=not no_color))
            print("=" * 65)

        table_rows = [
            [
                r["pair_id"],
                r["encoding"],
                status_badge(r["status"], enabled=not no_color),
                r["expected_canary"]
            ]
            for r in formatted_rows
        ]
        headers = ["Pair ID", "Encoding Vector", "Status", "Expected Canary"]
        render_output(formatted_rows, format_name="table", headers=headers, table_rows=table_rows, stream=sys.stdout, no_color=no_color)

        if not quiet:
            print("-" * 65)
            summary_msg = f"Audit Completed: {bypassed_count}/{total} encodings BYPASSED regex DLP."
            if bypassed_count > 0:
                print(red(f"[!] Security Finding: {summary_msg}", enabled=not no_color) + "\n")
            else:
                print(green(f"[+] Clean Posture: {summary_msg}", enabled=not no_color) + "\n")
    else:
        render_output(formatted_rows, format_name=fmt, stream=sys.stdout, no_color=no_color)

    # Return exit code:
    # If fail_on_bypass is set or by default in security evaluation, exit 1 if bypassed
    fail_on_bypass = getattr(args, "fail_on_bypass", False)
    if fail_on_bypass and bypassed_count > 0:
        return 1
    return 0
