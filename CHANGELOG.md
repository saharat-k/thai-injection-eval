# Changelog

All notable changes to the `thai-injection-eval` benchmark and framework are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-11-15

### Added
- **Dataset A v2.0**: 36 isomorphic scenarios across 3 languages (`en`, `th`, `th-en`) yielding 108 standardized test cases with recorded token counts and semantic back-translations (`data/normalized/test_cases_parallel_v2.json`, SHA256: `bfcb216cfae6c20935516f8cce148411e415a674488c721fb35f9a7547634ce2`).
- **Pre-Registration Protocol**: Locked primary hypothesis $H_1$, smallest effect size of interest ($\text{SESOI} = 10\%$), and Benjamini-Hochberg False Discovery Rate family under git tag `preregistration-v2.0` (`docs/benchmark/PRE_REGISTRATION.md`).
- **Decoupled Evaluation Metrics**: Separated model **Attempt Rate** (LLM compliance to adversary) from **Leak Rate** (actual data exfiltration past gatekeeper layers).
- **Ablation Mode**: Added `no_bola_ablation` mode to isolate LLM behavior when backend Broken Object-Level Authorization (BOLA) gatekeepers are disabled.
- **Cross-Family Model Support**: Integrated OpenRouter adapter for open-weights evaluation (`meta-llama/llama-3.3-70b-instruct:free`) alongside Google (`gemini-3.5-flash-lite`).
- **Independent Security Oracle**: Rule-based evaluator with zero-width (Unicode category Cf) stripping and anti-evasion normalization, audited at Cohen's $\kappa = 0.9333$ and 1.0000 sensitivity.
- **Statistical Pipeline**: Added paired triplet bootstrap confidence intervals and Benjamini-Hochberg FDR adjustments in `core/evaluator/stats.py`.
- **Published Benchmark Traces**: Published 1,080 case-level execution traces (`results/published/benchmark_v2_static.jsonl`) and summary matrix (`results/published/benchmark_v2_summary.csv`).
- **Session-Bound Security Context**: Thread-isolated `SecurityContext` enforcing least privilege, action hijacking allowlists, and parameter canary leakage blocks.

### Changed
- Refactored monolithic `agent.py` into modular packages: `core/agent/runtime.py`, `core/tools/legacy.py`, `core/tools/context.py`, and `core/tools/policy.py`.
- Bridged `SecurityContext` with thread-local session context for seamless Row-Level Security (RLS) enforcement in `lookup_student_directory`.
- Updated test suite to 404 passing offline tests.

### Removed
- Removed unchecked development checklists from `README.md` in favor of forward-looking research milestones.

---

## [1.2.0] - 2026-11-14

### Added
- Multi-tier defense architecture: `off`, `prompt`, `tools`, `all`, and `spotlight`.
- Thai linguistic mutation suite with grapheme-aware segmentation, zero-width space insertion, and vowel/tone homoglyphs.
- Output Data Loss Prevention (DLP) layer with regex and NFKC normalization.
- Local Flask inspection web dashboard (`web_ui.py`).

---

## [1.0.0] - 2026-10-23

### Added
- Initial project architecture and SQLite university database mock (`data/university.db`).
- Single-tool evaluation harness using `search_records`.
- Baseline Thai prompt injection datasets and CLI launcher.
