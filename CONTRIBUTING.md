# Contributing to Thai Injection Eval

Thank you for your interest in contributing to **Thai Injection Eval**! We welcome contributions from researchers, security practitioners, and developers working to advance LLM application security.

This guide outlines our development workflow, engineering standards, and submission guidelines.

---

## 1. Codebase Architecture

The repository is structured into modular layers designed for high auditability and zero external runtime friction:

- **`core/cli/`**: The unified command-line interface (`thai-eval` or `python -m core.cli.app`).
  - `commands/`: Subcommand handlers (`eval.py`, `redteam.py`, `probe.py`, `serve.py`, `test.py`, `doctor.py`).
  - `terminal/`: ANSI rendering, banner display, and Linux-standard status stream formatting.
  - `output/`: Clean table, JSON, and CSV exporters.
- **`core/evaluator/`**: Security evaluation engines:
  - `engine.py`: Single-turn evaluator and baseline assessment.
  - `redteam.py`: Multi-turn adaptive Crescendo red-teaming runner.
  - `probing.py`: Systematic vulnerability probing across defenses.
  - `parallel.py`: Concurrency-controlled batch evaluation.
- **`core/adapters/`**: Target connection abstractions (`builtin.py`, `openai_like.py`, `factory.py`).
- **`core/defenses/`**: Layered defense mechanisms:
  - `dlp.py`: Stateless Data Loss Prevention & multi-format canary redaction.
  - `spotlight.py`: Delimiting and prompt hardening.
  - `converters.py`: Dynamic linguistic obfuscation transformers.
- **`data/normalized/`**: The single source of truth for benchmark datasets (`test_cases.json`, `test_cases_linguistic.json`, etc.).
- **`web_ui.py` & `templates/`**: Zero-dependency Flask dashboard and interactive playground.
- **`tests/`**: Comprehensive offline unit and integration test suite.

---

## 2. Development Setup

We strongly recommend using an isolated Python virtual environment.

```bash
# Clone the repository
git clone https://github.com/saharat-k/thai-injection-eval.git
cd thai-injection-eval

# Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

---

## 3. Verification & Testing Standards

To protect CI stability and prevent unintentional API quota expenditure, we enforce an **offline-first verification policy**:

```bash
# 1. Run all unit and integration tests (zero API cost, takes ~10 seconds)
python -m unittest discover tests/

# 2. Run repository hygiene and secret scanner
python scripts/check_secrets.py --history
```

Every PR must pass the complete unit test suite and secret scan before merging.

---

## 4. Model Selection & Zero-Cost Constraints

To ensure reproducible benchmarks accessible to all researchers without commercial API barriers:
- **Default Blue Target**: `gemini-3.5-flash-lite` (free-tier on Google AI Studio, with automatic retry and `gemini-3.1-flash-lite` fallback).
- **Default Red Adversary**: `openrouter:openrouter/free` (or `gemini-3.5-flash-lite`).
- **Paid Models**: Never hardcode or default to paid/quota-spike models (e.g. `gemini-3.8-flash`, `llama-3.3-70b-instruct`). Always respect user-supplied `--blue` and `--red` flags.

---

## 5. Dataset Contribution Guidelines

When adding or modifying adversarial test cases in `data/normalized/test_cases.json`:
1. **Schema Compliance**: Every record must adhere to the schema:
   - `id`: Unique identifier (e.g., `TH-01`, `EN-05`, `MIX-02`).
   - `language`: `Thai`, `English`, or `Mixed`.
   - `attack_type`: `direct`, `indirect`, `recon`, `semantic`, `roleplay`, `fewshot`, or `obfuscation`.
   - `source_reference`: Origin or publication reference (e.g., `OWASP-LLM01`, `Crescendo`, `academic`).
   - `technique`: Descriptive attack technique name.
   - `prompt`: Injected payload text.
2. **Synthetic Data Only**: All sensitive targets must reference mock records and canary tokens (`CANARY-*`). Never include real personal data, national IDs, or credentials.

---

## 6. Git & Commit Conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat(scope): concise imperative subject <= 72 chars`
- `fix(scope): concise imperative subject <= 72 chars`
- `docs(scope): documentation update`
- `style(scope): formatting, visual styles, UI themes`
- `refactor(scope): code restructuring without changing behavior`
- `test(scope): test suite additions or modifications`
- `chore(scope): repository maintenance, dependency bumps`

**Hygiene Rule**: Never commit `.env`, `*.db`, `results.md`, `.flask_secret`, or temporary scratch artifacts. Verify with `python scripts/check_secrets.py` before opening a Pull Request.
