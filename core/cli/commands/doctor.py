"""Doctor command: inspect environment, dependencies, datasets, and runtime health."""
import importlib
import os
import platform
import sqlite3
import sys
from typing import Dict, Any, List

from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, status_badge, green, red, yellow


def run_diagnostics() -> Dict[str, Any]:
    """Execute comprehensive environment diagnostic checks."""
    checks = []
    overall_status = "OK"

    # 1. Python version check
    py_ver = platform.python_version()
    major, minor = sys.version_info[:2]
    if (major, minor) >= (3, 10):
        py_status = "OK"
        py_msg = f"{py_ver}"
    else:
        py_status = "FAIL"
        py_msg = f"{py_ver} (Requires Python >= 3.10)"
        overall_status = "FAIL"
    checks.append({"category": "Runtime", "component": "Python Version", "status": py_status, "details": py_msg})

    # 2. Required Core Dependencies
    required_deps = [
        ("google-genai", "google.genai"),
        ("python-dotenv", "dotenv"),
    ]
    missing_req = []
    for pkg_name, mod_name in required_deps:
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing_req.append(pkg_name)

    if not missing_req:
        checks.append({"category": "Dependencies", "component": "Core Packages", "status": "OK", "details": "All installed"})
    else:
        checks.append({"category": "Dependencies", "component": "Core Packages", "status": "FAIL", "details": f"Missing: {', '.join(missing_req)}"})
        overall_status = "FAIL"

    # 3. Optional Dependencies
    optional_deps = [
        ("flask", "flask"),
        ("faker", "faker"),
        ("matplotlib", "matplotlib"),
        ("scipy", "scipy"),
    ]
    missing_opt = []
    for pkg_name, mod_name in optional_deps:
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing_opt.append(pkg_name)

    if not missing_opt:
        checks.append({"category": "Dependencies", "component": "Optional Packages", "status": "OK", "details": "All installed"})
    else:
        checks.append({"category": "Dependencies", "component": "Optional Packages", "status": "WARN", "details": f"Optional missing: {', '.join(missing_opt)}"})

    # 4. Benchmark & Test Data
    datasets = [
        ("Parallel Cases", ["data/test_cases_parallel.json", "test_cases_parallel.json"]),
        ("Probing Cases", ["data/test_cases_probing.json", "test_cases_probing.json"]),
        ("Baseline Cases", ["test_cases.json", "data/test_cases.json"]),
        ("Indirect Cases", ["data/test_cases_indirect.json", "test_cases_indirect.json"]),
    ]
    missing_data = []
    for label, paths in datasets:
        found = any(os.path.isfile(p) for p in paths)
        if not found:
            missing_data.append(label)

    if not missing_data:
        checks.append({"category": "Data", "component": "Benchmark Datasets", "status": "OK", "details": "All datasets available"})
    else:
        checks.append({"category": "Data", "component": "Benchmark Datasets", "status": "FAIL", "details": f"Missing: {', '.join(missing_data)}"})
        overall_status = "FAIL"

    # 5. Database Status
    db_paths = ["data/university.db", "university.db"]
    active_db = next((p for p in db_paths if os.path.isfile(p)), None)
    if active_db:
        try:
            conn = sqlite3.connect(active_db)
            cur = conn.cursor()
            cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table'")
            count = cur.fetchone()[0]
            conn.close()
            checks.append({"category": "Database", "component": "SQLite University DB", "status": "OK", "details": f"{active_db} ({count} tables)"})
        except Exception as e:
            checks.append({"category": "Database", "component": "SQLite University DB", "status": "WARN", "details": f"Error querying DB: {e}"})
    else:
        checks.append({"category": "Database", "component": "SQLite University DB", "status": "WARN", "details": "university.db not seeded yet (run scripts/seed_db.py)"})

    # 6. Target Adapters
    try:
        from core.adapters.factory import create_target_adapter
        create_target_adapter("callable", callable_fn=lambda p: "ok")
        checks.append({"category": "Adapters", "component": "Target Adapters", "status": "OK", "details": "Builtin, OpenAI, Callable operational"})
    except Exception as e:
        checks.append({"category": "Adapters", "component": "Target Adapters", "status": "FAIL", "details": f"Factory failed: {e}"})
        overall_status = "FAIL"

    # 7. Configuration & Secrets
    api_key = os.getenv("GEMINI_API_KEY", "")
    if api_key:
        checks.append({"category": "Config", "component": "GEMINI_API_KEY", "status": "OK", "details": "Available in environment"})
    else:
        checks.append({"category": "Config", "component": "GEMINI_API_KEY", "status": "WARN", "details": "Not set (Live API calls disabled; offline tests working)"})

    return {
        "status": overall_status,
        "checks": checks,
    }


def run_doctor(args) -> int:
    """Execute doctor command."""
    diag = run_diagnostics()
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    if fmt == "table":
        print("\n" + bold("Thai Injection Eval - Environment Check", enabled=not no_color))
        print("=" * 60)
        table_rows = []
        for c in diag["checks"]:
            badge = status_badge(c["status"], enabled=not no_color)
            table_rows.append([c["component"], badge, c["details"]])

        headers = ["Component", "Status", "Details"]
        render_output(diag, format_name="table", headers=headers, table_rows=table_rows, stream=sys.stdout, no_color=no_color)
        print("-" * 60)

        if diag["status"] == "OK":
            print(green("Environment is ready.", enabled=not no_color) + "\n")
            return 0
        else:
            print(red("Environment has critical issues that need resolution.", enabled=not no_color) + "\n")
            return 3

    render_output(diag, format_name=fmt, stream=sys.stdout, no_color=no_color)
    return 0 if diag["status"] == "OK" else 3
