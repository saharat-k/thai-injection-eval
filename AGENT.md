# Agent & Developer Engineering Guide: Thai Injection Eval

Welcome! This document provides concise, high-signal architectural instructions for AI agents and human engineers contributing to **thai-injection-eval**.

---

## 1. Project Mission & Architecture

`thai-injection-eval` is an open-source AI security test bench evaluating Large Language Model (LLM) agents against **OWASP Top 10 for LLMs** (LLM01 Prompt Injection, LLM06 Excessive Agency), specifically focused on Thai, English, and mixed code-switching attack vectors.

### Directory Layout
- `core/cli/`: Unified command-line interface (`thai-eval` / `python -m core.cli.app`).
  - `commands/`: CLI action handlers (`eval.py`, `redteam.py`, `probe.py`, `serve.py`, `test.py`, `doctor.py`).
  - `terminal/`: ANSI styling, slant banners, and Linux-standard telemetry stream renderers.
- `core/evaluator/`: Benchmarking engines (multi-turn Crescendo red-teaming, parallel tests, metrics calculator).
- `core/adapters/`: Model connection abstractions (`builtin.py`, `openai_like.py`, `factory.py`).
- `core/defenses/`: Security layers (Data Loss Prevention / Canary detection, Spotlight delimiting, Linguistic obfuscation converters).
- `data/normalized/`: Canonical benchmark test cases (`test_cases.json`, `test_cases_linguistic.json`, etc.). Single source of truth.
- `web_ui.py` & `templates/`: Flask-based evaluation dashboard and interactive playground.
- `tests/`: 240+ deterministic offline unit and integration tests.

---

## 2. Essential CLI Commands

```bash
# Run unit test suite (offline, zero API cost)
python -m unittest discover tests/

# Check repository hygiene and secrets scanner
python scripts/check_secrets.py --history

# Launch Web UI dashboard
python -m core.cli.app serve --open
# (Alias: python -m core.cli.app view --open)

# Run single-turn evaluation benchmark
python -m core.cli.app eval run --defense tools --limit 5

# Run multi-turn adaptive Red Team evaluation
python -m core.cli.app redteam run --blue gemini-3.5-flash-lite --red openrouter:openrouter/free --limit 3 --attempts 2
```

---

## 3. Mandatory Development Rules

1. **Free-Tier Models Only**: Always use free-tier models:
   - Blue Target: `gemini-3.5-flash-lite` (with fallback to `gemini-3.1-flash-lite`).
   - Red Adversary: `openrouter:openrouter/free` (or `gemini-3.5-flash-lite`).
   - Never default to paid/quota-spike models (`gemini-3.8-flash`, `llama-3.3-70b-instruct`).
2. **Offline-First Verification**: Every change must be validated against `tests/` before completing. Never run live LLM API calls for unit tests; use mocks or synthetic offline fixtures.
3. **Commit Standards (Top-Star Repos)**:
   - Conventional Commits: `type(scope): concise imperative subject <= 72 chars`.
   - Keep commits atomic and focused. Do not write essay-like or bloated commit messages.
   - Never commit `.env`, `*.db`, `results.md`, `.flask_secret`, or internal agent scratchpad artifacts.
4. **Environment Isolation**: Always use the local virtual environment (`.venv\Scripts\python.exe` on Windows).
5. **Data Protection**: All sensitive tables in `data/*.sql` are synthetic with mock canary tokens (`CANARY-*`). Never use real personal data.
