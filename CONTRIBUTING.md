# Contributing to Thai Injection Eval

Thank you for contributing to Thai Injection Eval. This guide covers codebase structure, offline testing requirements, model rules, dataset format, and commit style.

## 1. Codebase architecture

- `core/cli/`: Unified CLI (`thai-eval` or `python -m core.cli.app`) with commands (`eval.py`, `redteam.py`, `probe.py`, `chat.py`, `dlp.py`, `serve.py` / `view` alias, `test.py`, `doctor.py`, `config.py`, `version.py`), ANSI terminal rendering, and table/JSON/CSV exporters.
- `core/agent/`: Multi-turn Red/Blue session runtime, retry logic, and auth circuit breaker (`runtime.py`).
- `core/tools/`: Session-isolated `SecurityContext` (`context.py`), `RoleBasedPolicy` and `AllowAllPolicy` (`policy.py`), and seven instrumented DB/action tools (`legacy.py`).
- `core/evaluator/`: Single-turn evaluator (`engine.py`), adaptive `crescendo` / `tap` red-team runner (`redteam.py`), beam-search tree runner (`tree.py`), `IndependentSecurityOracle` (`oracle.py`), statistical tests (`stats.py`), probing (`probing.py`), indirect judge (`indirect.py`), benchmark lock checks (`lock.py`), and parallel batching (`parallel.py`).
- `core/adapters/`: Target connection adapters (`builtin.py`, `openai_like.py`, `openrouter.py`, `callable.py`, `factory.py`).
- `core/defenses/`: Output DLP (`dlp.py`), context spotlighting (`spotlight.py`), and dynamic Thai NLP mutators (`converters.py`).
- `data/normalized/`: Canonical benchmark datasets (`test_cases_parallel_v2.json`, `test_cases_linguistic.json`, `test_cases.json`, and related suites).
- `web_ui.py` & `templates/`: Local Flask dashboard and interactive playground.
- `tests/`: Offline unit and integration suite (515 tests, 2 expected failures).

## 2. Development setup

Use an isolated virtual environment:

```bash
git clone https://github.com/saharat-k/thai-injection-eval.git
cd thai-injection-eval

python -m venv .venv

# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
pip install -e .
```

## 3. Verification and testing standards

Unit tests run offline without external API calls:

```bash
python -m unittest discover tests/
python scripts/check_secrets.py --history
```

Every pull request must pass the full unit test suite and secret scan before merging.

## 4. Model selection and zero-cost constraints

- Default Blue target: `gemini-3.5-flash-lite` (fallback: `gemini-3.1-flash-lite`).
- Default Red adversary: `openrouter:openrouter/free` (with `gemini-3.5-flash-lite` fallback).
- Heavy or paid models (such as `gemini-3.8-flash` or unapproved paid OpenAI/Anthropic endpoints) must not be configured as defaults or invoked in automated runs. Always honor user-supplied `--blue` and `--red` flags within approved free-tier policies.

## 5. Dataset contribution guidelines

Dataset A (`data/normalized/test_cases_parallel_v2.json`) and its SHA-256 checksums are frozen under `docs/benchmark/PRE_REGISTRATION.md`. New test cases in normalized suites must validate against the canonical Draft-07 schema (`data/schema/test_case.schema.json`), which checks `id`, `category`, `technique`, `language` (`th`, `en`, `mix` or suite-specific values), `is_benign`, `prompt`, `expected_behavior`, and `evaluation`. Legacy entries in `data/normalized/test_cases.json` additionally retain `attack_type` and `source_reference`.

All records, citizen IDs, salaries, and canary tokens (`CANARY-*`) must be synthetic mock values. Never add real personal data or credentials.

## 6. Git and commit conventions

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):

- Format: `<type>(<scope>): <concise imperative subject>` (max 72 chars, lowercase, no trailing period).
- Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.
- Keep commits atomic and concise. Use a single-line message when the change is clear; add at most two or three bullet points on why the change was needed if context matters.
- Never stage or commit `.env`, `*.db`, `results.md`, `.flask_secret`, or scratchpads (`scratch/`, `.superpowers/`). Run `python scripts/check_secrets.py --history` before pushing.
