"""Local Statistical Analysis CLI for Evaluation Benchmark Results.

Reads published benchmark results (CSV/JSON), computes cell-level rates with
Wilson 95% CIs, performs exact McNemar tests on paired cases (by pair_id),
and calculates Newcombe paired difference confidence intervals for effect sizes.
Runs entirely offline without cloud dependencies.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collections import defaultdict
from typing import Any, Dict, List, Tuple

from core.evaluator.stats import (
    wilson_interval,
    rate_with_ci,
    format_rate,
    exact_mcnemar_test,
    newcombe_paired_ci,
    aggregate_case_repeats,
)


def load_rows_from_csv(csv_path: str) -> List[Dict[str, Any]]:
    """Load evaluation rows from CSV."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    rows = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            # Parse numeric / boolean fields
            parsed = dict(r)
            if "success" in parsed:
                try:
                    parsed["success"] = int(parsed["success"])
                except ValueError:
                    pass
            if "repeat" in parsed:
                try:
                    parsed["repeat"] = int(parsed["repeat"])
                except ValueError:
                    pass
            rows.append(parsed)
    return rows


def analyze_cells(rows: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    """Compute k, n, rate, and Wilson 95% CI per (lang, vector/technique, defense)."""
    groups = defaultdict(list)
    for r in rows:
        success = r.get("success")
        if success not in (0, 1):
            continue  # Exclude transient errors (-1)
        lang = r.get("lang", "UNKNOWN")
        vector = r.get("vector", r.get("category", "UNKNOWN"))
        defense = r.get("defense", "UNKNOWN")
        groups[(lang, vector, defense)].append(success)

    results = {}
    for key, vals in sorted(groups.items()):
        k = sum(vals)
        n = len(vals)
        stat = rate_with_ci(k, n)
        results[key] = stat
    return results


def run_paired_language_analysis(rows: List[Dict[str, Any]], defense_tier: str = "tools") -> Dict[str, Any]:
    """Run exact McNemar and Newcombe paired tests comparing TH vs EN and MIX vs EN for a given defense tier."""
    # Filter rows for the target defense tier and valid success
    tier_rows = [r for r in rows if r.get("defense") == defense_tier and r.get("success") in (0, 1)]

    # Group by (pair_id, lang)
    pair_scores = defaultdict(dict)
    for r in tier_rows:
        pair_id = r.get("pair_id")
        lang = r.get("lang")
        if pair_id and lang:
            pair_scores[pair_id][lang] = r.get("success")

    comparisons = {}
    for comp_name, (l1, l2) in [("TH_vs_EN", ("TH", "EN")), ("MIX_vs_EN", ("MIX", "EN"))]:
        matched_pairs = [
            (pair_scores[pid][l1], pair_scores[pid][l2])
            for pid in sorted(pair_scores.keys())
            if l1 in pair_scores[pid] and l2 in pair_scores[pid]
        ]
        if not matched_pairs:
            continue
        y1 = [p[0] for p in matched_pairs]
        y2 = [p[1] for p in matched_pairs]

        mcnemar = exact_mcnemar_test(y1, y2)
        newcombe = newcombe_paired_ci(y1, y2)
        comparisons[comp_name] = {
            "n_pairs": len(matched_pairs),
            "l1_rate": round(sum(y1) / len(y1) * 100.0, 2),
            "l2_rate": round(sum(y2) / len(y2) * 100.0, 2),
            "rate_diff": newcombe["diff"],
            "diff_ci95": [newcombe["ci95_low"], newcombe["ci95_high"]],
            "mcnemar_exact_p": mcnemar["p_value"],
            "discordant_pairs": {"b": mcnemar["b"], "c": mcnemar["c"]},
        }
    return comparisons


def run_paired_defense_analysis(rows: List[Dict[str, Any]], d1: str, d2: str) -> Dict[str, Any]:
    """Compare two defense tiers on matching test cases using exact McNemar and Newcombe paired CI."""
    scores_d1 = {}
    scores_d2 = {}
    for r in rows:
        case_id = r.get("id")
        defense = r.get("defense")
        success = r.get("success")
        if success not in (0, 1) or not case_id:
            continue
        if defense == d1:
            scores_d1[case_id] = success
        elif defense == d2:
            scores_d2[case_id] = success

    common_cases = sorted(set(scores_d1.keys()) & set(scores_d2.keys()))
    if not common_cases:
        return {"n_matched": 0, "error": f"No overlapping cases between {d1} and {d2}"}

    y1 = [scores_d1[cid] for cid in common_cases]
    y2 = [scores_d2[cid] for cid in common_cases]

    mcnemar = exact_mcnemar_test(y1, y2)
    newcombe = newcombe_paired_ci(y1, y2)
    return {
        "d1": d1,
        "d2": d2,
        "n_matched": len(common_cases),
        "d1_rate": round(sum(y1) / len(y1) * 100.0, 2),
        "d2_rate": round(sum(y2) / len(y2) * 100.0, 2),
        "rate_diff": newcombe["diff"],
        "diff_ci95": [newcombe["ci95_low"], newcombe["ci95_high"]],
        "mcnemar_exact_p": mcnemar["p_value"],
        "discordant_pairs": {"b": mcnemar["b"], "c": mcnemar["c"]},
    }


def main():
    parser = argparse.ArgumentParser(description="Statistical Analysis of Evaluation Benchmark Runs")
    parser.add_argument("--csv", default=os.path.join("results", "published", "probing_live_rows.csv"), help="Path to input results CSV")
    args = parser.parse_args()

    print("=================================================================")
    print("[BENCHMARK LOCAL STATISTICAL ANALYSIS]")
    print(f"Reading: {args.csv}")
    print("=================================================================\n")

    if not os.path.exists(args.csv):
        print(f"[-] CSV file not found: {args.csv}")
        sys.exit(1)

    rows = load_rows_from_csv(args.csv)
    print(f"Loaded {len(rows)} rows.")

    # 1. Cell breakdown (Language x Technique x Defense)
    print("\n--- 1. Cell Rates with Wilson 95% CIs (Language x Technique x Defense) ---")
    cell_stats = analyze_cells(rows)
    for (lang, vector, defense), stat in cell_stats.items():
        print(f"  [{lang}] [{vector:12s}] [defense={defense:9s}] : {format_rate(stat)}")

    # 2. Paired language comparisons
    print("\n--- 2. Paired Language Comparison (TH vs EN, MIX vs EN) ---")
    defenses = sorted({r.get("defense") for r in rows if r.get("defense")})
    for d in defenses:
        print(f"\n[Defense Tier: {d}]")
        comp = run_paired_language_analysis(rows, defense_tier=d)
        for name, data in comp.items():
            print(f"  {name:10s} (n={data['n_pairs']} pairs): "
                  f"L1={data['l1_rate']}% vs L2={data['l2_rate']}% "
                  f"| Diff={data['rate_diff']}% [95% CI {data['diff_ci95'][0]}% to {data['diff_ci95'][1]}%] "
                  f"| Exact McNemar p={data['mcnemar_exact_p']:.4f}")

    # 3. Paired defense comparisons
    if "tools" in defenses and "all" in defenses:
        print("\n--- 3. Paired Defense Tier Comparison (tools vs all) ---")
        d_comp = run_paired_defense_analysis(rows, "tools", "all")
        print(f"  tools vs all (n={d_comp['n_matched']} cases): "
              f"tools={d_comp['d1_rate']}% vs all={d_comp['d2_rate']}% "
              f"| Diff={d_comp['rate_diff']}% [95% CI {d_comp['diff_ci95'][0]}% to {d_comp['diff_ci95'][1]}%] "
              f"| Exact McNemar p={d_comp['mcnemar_exact_p']:.4f}")

    print("\n[NOTE]: This is an exploratory analysis. Reported p-values are uncorrected for multiple comparisons.")


if __name__ == "__main__":
    main()
