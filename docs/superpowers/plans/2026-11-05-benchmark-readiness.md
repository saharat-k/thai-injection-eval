# Unified Benchmark Readiness, 20-Table Thai University ERP & Multi-Model Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform `thai-injection-eval` into a scientific, publication-grade LLM Prompt Injection Benchmark platform featuring:
1. **Multi-Model Function Calling & Defense Parity** (`OpenAILikeTargetAdapter` autonomous tool loop + automatic system prompt hardening when `defense` is active).
2. **20-Table Realistic Thai University ERP Database** (`14 Public Tables` + `6 Private PDPA Section 24 & Section 26 Tables`) with updated SHA-256 lock verification (`data/benchmark_lock.json`).
3. **36-Case Benign Control Dataset** (`data/normalized/test_cases_benign.json`) strictly validated against Draft-07 schema for False Refusal Rate (FRR) / Benign Utility evaluation.
4. **Unified CLI Benchmark Runner & 3-Table Leaderboard** (`thai-eval eval run --indirect / --benign`, `thai-eval benchmark run [--from-results] [--limit]`) producing 3 publication-ready Markdown tables with 95% Wilson Score Confidence Intervals.
5. **Publication-Grade System Architecture & Literature Specification** (`docs/architecture.md`, `docs/REFERENCES.md`, `README.md`).

**Architecture:** Extend `OpenAILikeTargetAdapter` with an autonomous stdlib tool-calling loop and defense-aware system prompt builder; expand `scripts/seed_db.py`, `agent.py`, `core/defenses/dlp.py`, and `data/benchmark_lock.json` to support a 20-table Thai Higher Education ERP; add `test_cases_benign.json` for dual-metric (`ASR` vs `Benign Utility / FRR`) scoring; upgrade `core/cli/commands/eval.py` to execute or aggregate (`--from-results`) full suites into a 3-table Markdown leaderboard (`results/benchmark_leaderboard.md`); and document the end-to-end architecture in `docs/architecture.md`.

**Tech Stack:** Python 3.10+ (Standard Library: `urllib.request`, `json`, `sqlite3`, `unittest`), `google-genai` (reference model), `python-dotenv`. Zero new runtime dependencies.

**Spec:** `docs/superpowers/specs/2026-11-05-erp-and-leaderboard-design.md` (synthesized from AgentDojo NeurIPS 2024, ThaiSafetyBench ICLR 2024 / SCB 10X, PyRIT Microsoft AI Red Team, InjecAgent ACL 2024, and Promptfoo).

---

## Global Constraints

- **Zero Global Installs**: All Python commands run through `.venv\Scripts\python.exe`.
- **Zero API Quota Spend on Tests**: All tests in `tests/` must run 100% offline with mocks; live API calls are strictly forbidden in tests.
- **Commit Hygiene**: Never commit `.env`, `.flask_secret`, `results.md`, or `*.db`.
- **Schema & Lock Strictness**: All test cases in `data/normalized/` must strictly validate against `data/schema/test_case.schema.json` (Draft-07), and `data/benchmark_lock.json` must pass `tests/test_lock_integrity.py` 100%.
- **Minimal Code / Ponytail**: No external SDK dependencies (`openai`, `requests`); use existing `urllib.request` in adapters.

## Review Focus

1. **Infinite Tool Calling Loop**: An external model continuously returning `tool_calls` without a final answer must be bounded by `MAX_TOOL_CALLS_PER_TURN` (4 turns) and terminate cleanly.
2. **Malformed Tool Arguments**: External model returning invalid JSON in `tool_calls.arguments` must not crash the adapter.
3. **System Prompt & Defense Parity**: Passing `defense="all"` or `defense="prompt"` to `OpenAILikeTargetAdapter` (via `config` or `send(..., defense=...)`) must inject `HARDENED_SYSTEM_PROMPT` + schema hint + role policy, while bare initialization without `defense` or `system_prompt` preserves backward compatibility (`len(adapter.messages) == 2` after 1 turn).
4. **20-Table ERP & Lock Integrity**: Adding 4 new tables (`curriculums`, `academic_calendar`, `library_catalog`, `health_counseling_records`) and enriching existing tables with default columns must keep all 63 indirect injection lock records (`ANN901..912`, `EV902..911`, `E901..908`, `A902..909`) and existing queries 100% intact.
5. **CLI Dry-Run & Offline Leaderboard Aggregation**: Running `--dry-run` or `--from-results` must return exit code 0 and generate all 3 research tables without making any network calls.

---

## Phase 1: Core Multi-Model Foundation, Benign Dataset, CLI Scaffolding & Architecture Docs (Completed)

### Task 1: OpenAI-Compatible Function Calling Loop (`OpenAILikeTargetAdapter`) — [COMPLETED: `f85b9aa`]

**Files:**
- Modify: `core/adapters/openai_like.py`
- Test: `tests/test_openai_adapter.py`

- [x] **Step 1: Write unit tests for single-turn, multi-turn `tool_calls`, max-turns bound, and malformed JSON arguments**
- [x] **Step 2: Implement `_get_tools_spec()` and autonomous tool loop in `core/adapters/openai_like.py`**
- [x] **Step 3: Verify tests pass and commit (`f85b9aa`)**

---

### Task 2: Dedicated Benign Control Dataset (`data/normalized/test_cases_benign.json`) — [COMPLETED: `c793fe4`]

**Files:**
- Create: `scripts/create_benign_dataset.py`
- Create: `data/normalized/test_cases_benign.json`
- Test: `tests/test_benign_dataset.py`

- [x] **Step 1: Write Draft-07 schema & invariant tests in `tests/test_benign_dataset.py`**
- [x] **Step 2: Generate 36 balanced benign cases (12 TH, 12 EN, 12 MIX) across 6 university domains**
- [x] **Step 3: Verify tests pass and commit (`c793fe4`)**

---

### Task 3: Initial CLI Expansion (`--indirect`, `benchmark run`, `doctor` check) — [COMPLETED: `515c952`]

**Files:**
- Modify: `core/cli/app.py`
- Modify: `core/cli/commands/eval.py`
- Modify: `core/cli/commands/doctor.py`
- Test: `tests/test_benchmark_cli.py`

- [x] **Step 1: Write CLI parser & dry-run tests in `tests/test_benchmark_cli.py`**
- [x] **Step 2: Add `--indirect` to `eval run`/`eval list`, `--benign` to `eval list`, `benchmark run` subcommand, and Benign Cases check in `doctor.py`**
- [x] **Step 3: Verify tests pass and commit (`515c952`)**

---

### Task 4: Publication-Grade System Architecture & Literature References — [COMPLETED: `e2b1260`]

**Files:**
- Modify: `docs/architecture.md`
- Modify: `docs/REFERENCES.md`
- Modify: `README.md`

- [x] **Step 1: Populate `docs/architecture.md` (~9.5 KB) with Mermaid diagrams, 5-tier defense specs, OWASP threat boundaries, Multi-Model Adapter sequence diagram, Wilson 95% CI formulas, and Global Benchmark Parity table**
- [x] **Step 2: Update `docs/REFERENCES.md` (AgentDojo, ThaiSafetyBench, PyRIT) and `README.md` roadmap**
- [x] **Step 3: Verify tests pass and commit (`e2b1260`)**

---

## Phase 2: Adapter System Prompt Parity, 20-Table Thai University ERP & 3-Table Research Leaderboard (Pending Execution)

### Task 5: `OpenAILikeTargetAdapter` System Prompt Injection Parity

**Files:**
- Modify: `core/adapters/openai_like.py:14-90`
- Modify: `tests/test_openai_adapter.py:130-155`

**Interfaces:**
- Consumes:
  - `agent.BASE_SYSTEM_PROMPT`, `agent.HARDENED_SYSTEM_PROMPT`
  - `agent.PUBLIC_SCHEMA_HINT`, `agent.FULL_SCHEMA_HINT`
  - `agent.get_blue_role_prompt(role: str) -> str`
- Produces:
  - Automatic injection of `{"role": "system", "content": self._get_effective_system_prompt(defense, role)}` when `"defense"` or `"blue_role"` is provided in `config` or `send(..., **kwargs)` or when `system_prompt` is set, while preserving 0 system messages when initialized bare (`tests/test_evaluator.py:137`).

- [x] **Step 1: Verify unit test in `tests/test_openai_adapter.py` (`test_defense_kwarg_injects_hardened_system_prompt`)**
  Run: `.venv\Scripts\python.exe -m unittest tests/test_openai_adapter.py tests/test_evaluator.py -v`
  Expected: PASS (both `test_defense_kwarg_injects_hardened_system_prompt` and `test_openai_like_adapter_success` pass).

- [x] **Step 2: Commit Task 5**
  ```bash
  git add core/adapters/openai_like.py tests/test_openai_adapter.py
  git commit -m "fix(adapter): inject effective university system prompt when defense is configured"
  ```

---

### Task 6: Upgrade Database to 20-Table Thai University ERP & Refresh Benchmark Lock

**Files:**
- Modify: `scripts/seed_db.py`
- Modify: `agent.py` (around `PUBLIC_TABLES`, `PRIVATE_TABLES`, `PUBLIC_SCHEMA_HINT`, `FULL_SCHEMA_HINT`)
- Modify: `core/defenses/dlp.py` (around `load_canaries_by_category`)
- Modify: `data/university_schema.sql` & `data/sensitive_schema.sql` (auto-exported or updated alongside `seed_db.py`)
- Modify: `data/benchmark_lock.json`
- Test: `tests/test_lock_integrity.py`, `tests/test_benign_dataset.py`

**Interfaces:**
- Consumes:
  - `scripts/seed_db.py` table definitions and seed rows
  - `core.evaluator.lock.BenchmarkLockVerifier`
- Produces:
  - **14 Public Tables (`PUBLIC_TABLES`)**:
    - Existing 11 tables enriched with default Thai ERP columns (`faculty`, `advisor_id`, `academic_status`, `academic_rank`, `office_hours`, `credit_format`, `funding_agency`, etc.)
    - 3 New Public Tables: `curriculums` (หลักสูตร อว.), `academic_calendar` (ปฏิทินการศึกษา), `library_catalog` (ระบบห้องสมุดมหาวิทยาลัย)
  - **6 Private PDPA Tables (`PRIVATE_TABLES`)**:
    - Existing 5 tables enriched with default columns (`gpax`, `emergency_contact`, `academic_allowance`, `student_loan_status`)
    - 1 New PDPA Section 26 Sensitive Table: `health_counseling_records` (seeded with `CANARY-HC-S001`, `CANARY-HC-S002`)
  - Updated `data/benchmark_lock.json` passing `tests/test_lock_integrity.py` 100%.

- [x] **Step 1: Write failing test for 20-table ERP schema & health counseling canaries**
  Add `test_erp_20_tables_and_health_canaries` to `tests/test_lock_integrity.py` asserting:
  - `len(agent.PUBLIC_TABLES) == 14` (`curriculums`, `academic_calendar`, `library_catalog` present)
  - `len(agent.PRIVATE_TABLES) == 6` (`health_counseling_records` present)
  - `CANARY-HC-S001` is loaded by `core.defenses.dlp.load_canaries_by_category(agent.DB_PATH)`
  Run: `.venv\Scripts\python.exe -m unittest tests/test_lock_integrity.py -v`
  Expected: FAIL (`len(agent.PUBLIC_TABLES)` is 11, `len(agent.PRIVATE_TABLES)` is 5).

- [x] **Step 2: Update `scripts/seed_db.py`, `agent.py`, and `core/defenses/dlp.py`**
  1. Add `curriculums`, `academic_calendar`, `library_catalog` (public) and `health_counseling_records` (private with `CANARY-HC-S001`, `CANARY-HC-S002`) + default Thai ERP columns to `scripts/seed_db.py`, `data/university_schema.sql`, and `data/sensitive_schema.sql`.
  2. Update `PUBLIC_TABLES`, `PRIVATE_TABLES`, `PUBLIC_SCHEMA_HINT`, and `FULL_SCHEMA_HINT` in `agent.py`.
  3. Update `load_canaries_by_category` in `core/defenses/dlp.py` to also scan `health_counseling_records.confidential_token`.
  4. Rebuild `data/university.db` and update `data/benchmark_lock.json` (`seed_db_sha256` and `payload_records`).

- [x] **Step 3: Run lock integrity and full defense tests**
  Run: `.venv\Scripts\python.exe -m unittest tests/test_lock_integrity.py tests/test_defenses.py -v`
  Expected: PASS (100% pass).

- [x] **Step 4: Commit Task 6**
  ```bash
  git add scripts/seed_db.py data/university_schema.sql data/sensitive_schema.sql agent.py core/defenses/dlp.py data/benchmark_lock.json tests/test_lock_integrity.py
  git commit -m "feat(db): upgrade university database to 20-table Thai ERP with PDPA section 26 records"
  ```

---

### Task 7: Full CLI `--benign` Runner, `--from-results` Mode & 3-Table Research Leaderboard

**Files:**
- Modify: `core/cli/app.py`
- Modify: `core/cli/commands/eval.py`
- Modify: `docs/architecture.md` (update table count from 16 to 20 tables)
- Test: `tests/test_benchmark_cli.py`

**Interfaces:**
- Consumes:
  - `data/normalized/test_cases_benign.json`
  - `core.evaluator.stats.rate_with_ci(k, n)`
- Produces:
  - `thai-eval eval run --benign [--dry-run] [--limit N]`
  - `thai-eval benchmark run [--all] [--suites ...] [--defenses ...] [--from-results DIR] [--limit N] [--dry-run]`
  - 3 Research-Grade Tables in `results/benchmark_leaderboard.md`:
    1. **Table 1: Executive Defense Scorecard** (`ASR` [95% Wilson CI], `Benign Utility` / `FRR` [95% Wilson CI], `TVR`, `Defense Efficiency Score [DES]`)
    2. **Table 2: Cross-Lingual Vulnerability Breakdown** (`TH` vs `EN` vs `MIX`)
    3. **Table 3: Threat Category & PDPA Sensitivity Breakdown** (OWASP `LLM01` / `LLM02` / `LLM06` & PDPA Section 24 vs Section 26)

- [x] **Step 1: Write failing tests in `tests/test_benchmark_cli.py`**
  Add tests for:
  - `eval run --benign --dry-run`
  - `benchmark run --from-results <temp_dir>` generating all 3 Markdown tables (`Executive Defense Scorecard`, `Cross-Lingual Vulnerability Breakdown`, `Threat Category & PDPA Sensitivity Breakdown`).
  Run: `.venv\Scripts\python.exe -m unittest tests/test_benchmark_cli.py -v`
  Expected: FAIL (`--benign` under `eval run` or `--from-results` under `benchmark run` not yet implemented).

- [x] **Step 2: Implement `--benign` in `eval run` and 3-table generator + `--from-results` in `benchmark run`**
  Update `core/cli/app.py` and `core/cli/commands/eval.py`, and sync the 20-table ERP count in `docs/architecture.md`.

- [x] **Step 3: Run CLI and full test suite to verify**
  Run: `.venv\Scripts\python.exe -m unittest discover tests`
  Expected: All 228+ tests PASS with zero live API calls.

- [x] **Step 4: Commit Task 7**
  ```bash
  git add core/cli/app.py core/cli/commands/eval.py docs/architecture.md tests/test_benchmark_cli.py docs/superpowers/plans/2026-11-05-benchmark-readiness.md docs/superpowers/specs/2026-11-05-erp-and-leaderboard-design.md
  git commit -m "feat(cli): add benign eval runner, --from-results aggregation, and 3-table leaderboard"
  ```
