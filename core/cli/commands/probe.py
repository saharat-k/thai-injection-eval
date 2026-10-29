"""Probe command: probing benchmark suite for Item 7 non-trivial attack surfaces."""
import json
import os
import sys
from typing import List, Dict, Any

from core.adapters.factory import create_target_adapter
from core.evaluator.engine import SecurityEvaluator
from core.evaluator.probing import (
    DEFAULT_PROBING_PATH,
    load_probing_document,
    validate_probing_document,
)
from core.evaluator.parallel import file_sha256
from core.evaluator.reporter import export_published_files
from core.evaluator.stats import estimate_requests
from core.cli.output.common import render_output
from core.cli.terminal.colors import bold, status_badge, green, red, yellow
from core.cli.terminal.progress import ProgressReporter


def run_probe_list(args) -> int:
    """List all available probing test cases."""
    cases_path = getattr(args, "probing_cases", DEFAULT_PROBING_PATH)
    if not os.path.exists(cases_path):
        alt = os.path.join("data", os.path.basename(cases_path))
        if os.path.exists(alt):
            cases_path = alt

    try:
        doc = load_probing_document(cases_path)
    except Exception as e:
        print(f"[-] Failed to load probing cases from {cases_path}: {e}", file=sys.stderr)
        return 2

    cases = doc.get("cases", [])
    fmt = getattr(args, "format", "table")
    no_color = getattr(args, "no_color", False)

    summary_list = []
    for c in cases:
        summary_list.append({
            "id": c.get("id", ""),
            "lang": c.get("lang", ""),
            "category": c.get("category", ""),
            "target_defense": c.get("target_defense", ""),
            "technique": c.get("technique", ""),
        })

    if fmt == "table":
        headers = ["Case ID", "Lang", "Category", "Target Tier", "Technique"]
        table_rows = [
            [s["id"], s["lang"], s["category"], s["target_defense"], s["technique"]]
            for s in summary_list
        ]
        print(bold(f"\nProbing Test Cases (v{doc.get('version', '1.0.0')} - {len(cases)} cases):", enabled=not no_color))
        render_output(summary_list, format_name="table", headers=headers, table_rows=table_rows, stream=sys.stdout, no_color=no_color)
        print()
    else:
        render_output(summary_list, format_name=fmt, stream=sys.stdout, no_color=no_color)

    return 0


def run_probe_run(args) -> int:
    """Execute probing benchmark evaluation."""
    cases_path = getattr(args, "probing_cases", DEFAULT_PROBING_PATH)
    if not os.path.exists(cases_path):
        alt = os.path.join("data", os.path.basename(cases_path))
        if os.path.exists(alt):
            cases_path = alt

    raw_def = getattr(args, "defenses", "tools,all")
    defenses = [d.strip() for d in raw_def.split(",") if d.strip()]
    repeats = getattr(args, "repeats", 1)
    target = getattr(args, "target", "builtin")
    role = getattr(args, "role", "registrar_staff")
    dry_run = getattr(args, "dry_run", False)
    quiet = getattr(args, "quiet", False)
    no_color = getattr(args, "no_color", False)
    export_dir = getattr(args, "export_dir", "results")
    export_name = getattr(args, "export_name", "probing_report")
    fmt = getattr(args, "format", "table")

    try:
        doc = load_probing_document(cases_path)
        problems = validate_probing_document(doc)
        if problems:
            print("[-] Probing cases file validation failed:", file=sys.stderr)
            for p in problems:
                print(f"    - {p}", file=sys.stderr)
            return 2
    except Exception as e:
        print(f"[-] Error loading probing cases: {e}", file=sys.stderr)
        return 2

    cases = doc["cases"]
    est = estimate_requests(len(cases), len(defenses), repeats)

    if not quiet and fmt == "table":
        print("\n" + bold("[OWASP LLM SECURITY PROBING BENCHMARK]", enabled=not no_color))
        print("=" * 65)
        print(f"Suite: v{doc['version']} | Cases: {len(cases)} | Tiers: {','.join(defenses)} | Repeats: {repeats}")
        print(f"Estimated LLM requests: >= {est['min_requests']} (typically {est['typical_low']}-{est['typical_high']} with tools)")
        print("=" * 65)

    if dry_run:
        if not quiet:
            print(green("[dry-run] Validation passed. No API calls executed.", enabled=not no_color) + "\n")
        return 0

    reporter = ProgressReporter(quiet=quiet, no_color=no_color)
    callback = reporter.make_eval_callback()

    config = {"defense": defenses[0], "blue_role": role}
    try:
        adapter = create_target_adapter(target, config=config)
    except Exception as e:
        print(f"[-] Failed to initialize target adapter: {e}", file=sys.stderr)
        return 3

    evaluator = SecurityEvaluator(adapter, cases=cases)

    try:
        report = evaluator.run_probing_benchmark(
            defenses=defenses,
            repeats=repeats,
            progress_callback=callback,
            metadata={"cases_version": doc["version"], "cases_sha256": file_sha256(cases_path)},
        )
    except Exception as e:
        print(f"[-] Execution error during probing benchmark: {e}", file=sys.stderr)
        return 3

    os.makedirs(export_dir, exist_ok=True)
    json_path = os.path.join(export_dir, f"{export_name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    if getattr(args, "publish", False):
        pub_dir = os.path.join(export_dir, "published")
        export_published_files(report, output_dir=pub_dir, base_name=export_name)

    # Determine security outcome
    results = report.get("results", [])
    breaches = sum(1 for r in results if r.get("success") == 1)

    if fmt == "table":
        if not quiet:
            print("-" * 65)
            print(f"Reports saved to {json_path}")
            if breaches > 0:
                print(red(f"[FAIL] Security criteria failed: {breaches} breach(es) detected.", enabled=not no_color) + "\n")
            else:
                print(green("[PASS] Security criteria met: 0 breaches detected.", enabled=not no_color) + "\n")
    else:
        render_output(report, format_name=fmt, stream=sys.stdout, no_color=no_color)

    return 1 if breaches > 0 else 0
