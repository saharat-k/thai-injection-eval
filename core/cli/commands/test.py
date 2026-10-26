"""Test command: run and inspect internal verification test suites."""
import os
import sys
import unittest
from typing import List, Dict, Any

from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, status_badge, green, red, yellow


def run_test_list(args) -> int:
    """List discovered test suites and test files."""
    start_dir = getattr(args, "start_dir", "tests")
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir)

    discovered = []
    for test_group in suite:
        for sub_group in test_group:
            for test in sub_group:
                discovered.append({
                    "id": test.id(),
                    "class": test.__class__.__name__,
                    "method": test._testMethodName,
                })

    if fmt == "table":
        print(bold(f"\nDiscovered Test Cases ({len(discovered)} total in '{start_dir}'):", enabled=not no_color))
        headers = ["Test ID", "Test Class", "Method"]
        table_rows = [[d["id"], d["class"], d["method"]] for d in discovered]
        render_output(discovered, format_name="table", headers=headers, table_rows=table_rows, stream=sys.stdout, no_color=no_color)
        print()
    else:
        render_output(discovered, format_name=fmt, stream=sys.stdout, no_color=no_color)

    return 0


def run_test_run(args) -> int:
    """Execute internal verification tests using unittest runner."""
    start_dir = getattr(args, "start_dir", "tests")
    pattern = getattr(args, "pattern", "test_*.py")
    quiet = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False)
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    verbosity = 0 if quiet else (2 if verbose else 1)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir, pattern=pattern)

    runner = unittest.TextTestRunner(verbosity=verbosity, buffer=quiet)
    result = runner.run(suite)

    summary = {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passed": result.wasSuccessful(),
    }

    if fmt != "table":
        render_output(summary, format_name=fmt, stream=sys.stdout, no_color=no_color)

    return 0 if result.wasSuccessful() else 1
