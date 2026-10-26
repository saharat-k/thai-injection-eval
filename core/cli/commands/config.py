"""Config command: view and inspect effective system configuration securely."""
import os
import sys
from typing import Dict, Any
from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, yellow, gray


def _mask_secret(val: str) -> str:
    """Mask secret value preserving only first 4 chars and tail suffix."""
    if not val:
        return "[NOT SET]"
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}...{val[-4:]} (masked)"


def get_effective_config() -> Dict[str, Any]:
    """Retrieve effective configuration with secrets masked."""
    # Try loading .env if available
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        pass

    api_key = os.getenv("GEMINI_API_KEY", "")
    flask_secret = os.getenv("FLASK_SECRET_KEY", "")

    return {
        "GEMINI_API_KEY": _mask_secret(api_key),
        "GEMINI_API_STATUS": "Configured" if api_key else "Missing",
        "FLASK_SECRET_KEY": _mask_secret(flask_secret),
        "DEFAULT_RED_MODEL": os.getenv("RED_MODEL", "gemini-3.8-flash"),
        "DEFAULT_BLUE_MODEL": os.getenv("BLUE_MODEL", "gemini-3.5-flash-lite"),
        "DEFAULT_DEFENSE": os.getenv("DEFAULT_DEFENSE", "off"),
        "DEFAULT_ROLE": os.getenv("DEFAULT_ROLE", "registrar_staff"),
        "DEFAULT_EXPORT_DIR": os.getenv("EXPORT_DIR", "results"),
        "UNIVERSITY_DB_PATH": os.getenv("UNIVERSITY_DB_PATH", os.path.join("data", "university.db")),
        "RESULTS_DB_PATH": os.getenv("RESULTS_DB_PATH", os.path.join("data", "results.db")),
    }


def run_config(args) -> int:
    """Execute config show command."""
    cfg = get_effective_config()
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    if fmt == "table":
        print(bold("Effective Configuration (Secrets Masked):", enabled=not no_color))
        rows = [[k, str(v)] for k, v in cfg.items()]
        headers = ["Configuration Key", "Effective Value"]
        render_output(cfg, format_name="table", headers=headers, table_rows=rows, stream=sys.stdout, no_color=no_color)
        return 0

    render_output(cfg, format_name=fmt, stream=sys.stdout, no_color=no_color)
    return 0
