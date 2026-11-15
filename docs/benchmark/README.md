# Benchmark Hub & Evaluation Reports

This directory serves as the centralized index for pre-registered benchmark protocols, multi-model evaluation reports, and historical leaderboards for `thai-injection-eval`.

---

## Active Benchmark: Release v2.0.0

![Benchmark v2.0 Scorecard](../images/benchmark_v2_dashboard.png)

The v2.0.0 benchmark introduces an open-science evaluation framework for analyzing prompt injection vulnerabilities across cross-lingual parallel triplets, decoupling backend infrastructure gatekeepers from model behavioral compliance.

### Core Documentation & Data Assets
- **Pre-Registration Specification**: [`PRE_REGISTRATION.md`](PRE_REGISTRATION.md) (Locked primary hypothesis $H_1$, SESOI $10\%$, and FDR protocol under git tag `preregistration-v2.0`).
- **Parallel Benchmark Dataset**: [`data/normalized/test_cases_parallel_v2.json`](../../data/normalized/test_cases_parallel_v2.json) (36 scenarios $\times$ 3 languages = 108 cases, SHA256: `bfcb216cfae6c20935516f8cce148411e415a674488c721fb35f9a7547634ce2`).
- **API Token & Cost Budget Estimate**: [`API_BUDGET_ESTIMATE.md`](API_BUDGET_ESTIMATE.md) (Strict 100% Free Tier execution guidelines).
- **Published Case Traces (JSONL)**: [`results/published/benchmark_v2_static.jsonl`](../../results/published/benchmark_v2_static.jsonl) (1,080 execution traces across 2 model families and 5 defense tiers).
- **Aggregated Statistical Matrix (CSV)**: [`results/published/benchmark_v2_summary.csv`](../../results/published/benchmark_v2_summary.csv) (Summary table with Wilson 95% CIs, paired bootstrap intervals, and Benjamini-Hochberg FDR adjusted p-values).

### Evaluated Model Families
- **Google Family**: `gemini-3.5-flash-lite` (Free Tier)
- **Open-Weights Family**: `meta-llama/llama-3.3-70b-instruct:free` (Free Tier via OpenRouter)
- **Evaluation Oracle**: Deterministic hybrid rule-based oracle with zero-width (Unicode category Cf) stripping and anti-evasion normalization (Stratified Cohen's $\kappa = 0.9333$, Sensitivity = 1.0000).

---

## Historical Benchmark Archive

Previous exploratory evaluation reports and legacy baseline scorecards are retained for longitudinal tracking:

- **v1.2.0 Release**:
  - Scorecard: [`leaderboard_v1.2.0.md`](leaderboard_v1.2.0.md)
  - Raw JSON metrics: [`leaderboard_v1.2.0.json`](leaderboard_v1.2.0.json)
  - Evaluated on: 423 test cases (single-turn exploratory set) on Gemini 3.5 Flash Lite
