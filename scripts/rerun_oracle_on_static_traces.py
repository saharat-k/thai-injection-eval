"""Standalone script to re-evaluate published benchmark static traces using IndependentSecurityOracle.

Allows independent reviewers to verify all 1,080 static benchmark execution traces
offline without calling external model APIs, verifying exact data provenance.
"""

from __future__ import annotations

import os
import sys

# Ensure repository root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scripts.run_multimodel_benchmark import verify_static_traces


def main() -> int:
    jsonl_path = os.path.join("results", "published", "benchmark_v2_static.jsonl")
    ok = verify_static_traces(jsonl_path)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
