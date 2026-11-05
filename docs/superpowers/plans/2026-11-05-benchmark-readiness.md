# Benchmark Readiness & Multi-Model Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform `thai-injection-eval` into a multi-model benchmark platform with an OpenAI-compatible function calling adapter, a dedicated 36-case benign control dataset, unified CLI benchmark runners, and publication-grade architecture documentation grounded in AgentDojo and ThaiSafetyBench methodologies.

**Architecture:** Extend `OpenAILikeTargetAdapter` with an autonomous stdlib tool-calling loop that reuses the existing SQLite/defense pipeline; add `test_cases_benign.json` validated against Draft-07 schema for dual-metric (ASR vs. FRR) evaluation; add an `--indirect` CLI runner and unified `benchmark run` command with leaderboard export; and populate `docs/architecture.md` with complete defense-in-depth and threat boundary specifications.

**Tech Stack:** Python 3.10+ (Standard Library: `urllib.request`, `json`, `sqlite3`, `unittest`), `google-genai` (reference model), `python-dotenv`. Zero new runtime dependencies.

**Spec:** Synthesized in chat from state-of-the-art benchmarks (AgentDojo NeurIPS 2024, ThaiSafetyBench ICLR 2024, PyRIT, InjecAgent ACL 2024) and project documentation (`LIMITATIONS.md`, `docs/methodology.md`, `data/schema/test_case.schema.json`).

## Global Constraints

- **Zero Global Installs**: All Python commands run through `.venv\Scripts\python.exe`.
- **Zero API Quota Spend on Tests**: All tests in `tests/` must run 100% offline with mocks; live API calls are strictly forbidden in tests.
- **Commit Hygiene**: Never commit `.env`, `.flask_secret`, `results.md`, or `*.db`.
- **Schema Strictness**: All test cases in `data/normalized/` must strictly validate against `data/schema/test_case.schema.json` (Draft-07).
- **Minimal Code / Ponytail**: No external SDK dependencies (`openai`, `requests`); use existing `urllib.request` in adapters.

## Review Focus

1. **Infinite Tool Calling Loop**: An external model continuously returning `tool_calls` without a final answer must be bounded by `MAX_TOOL_CALLS_PER_TURN` (4 turns) and terminate cleanly with an error or truncated response.
2. **Malformed Tool Arguments**: External model returning invalid JSON in `tool_calls.arguments` must not crash the adapter; it must report a tool execution error back to the model or return a graceful error response.
3. **Defense Pipeline Consistency**: Defenses (`tools`, `spotlight`, `all`) must apply identically to external models as they do to `BuiltinTargetAdapter`, including Table ACL filtering and Output DLP regex redaction.
4. **Benign Control Schema Invariants**: Benign cases must never contain attack categories or canary tokens in expected tokens; they must only contain public markers and `expected_behavior: "fulfillment"`.
5. **CLI Dry-Run Determinism**: Running `thai-eval eval run --indirect --dry-run` or `thai-eval benchmark run --dry-run` must output request estimates and return exit code 0 without initiating any network connection.

---

### Task 1: OpenAI-Compatible Function Calling Loop (`OpenAILikeTargetAdapter`)

**Files:**
- Modify: `core/adapters/openai_like.py:1-78`
- Test: `tests/test_openai_adapter.py`

**Interfaces:**
- Consumes:
  - `agent.search_records(table: str, keyword: str) -> str`
  - `agent.sanitize_error(err: str) -> str`
  - `agent.apply_defense_output(text: str) -> str`
  - `agent.MAX_TOOL_CALLS_PER_TURN: int` (default 4)
- Produces:
  - `OpenAILikeTargetAdapter.send(prompt: str, **kwargs) -> TargetResponse` with `resp.tool_calls` populated and autonomous tool loop executed.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_openai_adapter.py
import io
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from core.adapters.base import TargetResponse
from core.adapters.openai_like import OpenAILikeTargetAdapter


class TestOpenAILikeTargetAdapter(unittest.TestCase):
    """Test OpenAI-compatible adapter tool calling loop with mocked HTTP."""

    def test_single_turn_text_response(self):
        """Adapter correctly parses a standard assistant message without tools."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "gpt-4o-mini"})
        mock_resp_body = {
            "choices": [{"message": {"role": "assistant", "content": "Hello!"}}],
            "usage": {"total_tokens": 10},
        }

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_cm = MagicMock()
            mock_cm.read.return_value = json.dumps(mock_resp_body).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Hi")
            self.assertEqual(resp.text, "Hello!")
            self.assertEqual(len(resp.tool_calls), 0)
            self.assertIsNone(resp.error)

    def test_multi_turn_function_calling_loop(self):
        """Adapter executes tool calling loop when model returns tool_calls."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "typhoon-2", "defense": "tools"})
        
        # Turn 1: Model requests tool call
        turn1_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "search_records",
                            "arguments": json.dumps({"table": "students", "keyword": "S001"}),
                        },
                    }],
                }
            }]
        }
        # Turn 2: Model returns final answer
        turn2_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Student S001 is Somchai Srisuk, Computer Science.",
                }
            }]
        }

        responses = [
            json.dumps(turn1_body).encode("utf-8"),
            json.dumps(turn2_body).encode("utf-8"),
        ]

        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("agent.search_records", return_value="[Found S001]") as mock_search:
            mock_cm = MagicMock()
            mock_cm.read.side_effect = responses
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Who is S001?")
            self.assertEqual(resp.text, "Student S001 is Somchai Srisuk, Computer Science.")
            self.assertEqual(len(resp.tool_calls), 1)
            self.assertEqual(resp.tool_calls[0]["tool"], "search_records")
            self.assertEqual(resp.tool_calls[0]["args"], {"table": "students", "keyword": "S001"})
            mock_search.assert_called_once_with("students", "S001")

    def test_tool_calling_loop_max_turns_enforced(self):
        """Adapter halts loop and does not hang if model calls tools indefinitely."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "loop-model"})
        infinite_tool_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call_inf",
                        "type": "function",
                        "function": {
                            "name": "search_records",
                            "arguments": '{"table": "students", "keyword": "loop"}',
                        },
                    }],
                }
            }]
        }
        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("agent.search_records", return_value="result"):
            mock_cm = MagicMock()
            mock_cm.read.return_value = json.dumps(infinite_tool_body).encode("utf-8")
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Loop me")
            # Must terminate after MAX_TOOL_CALLS_PER_TURN
            self.assertLessEqual(len(resp.tool_calls), 4)

    def test_malformed_tool_arguments_graceful_handling(self):
        """Malformed JSON arguments from model do not crash the adapter."""
        adapter = OpenAILikeTargetAdapter("test_target", config={"model": "test"})
        turn1_body = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_bad",
                        "type": "function",
                        "function": {"name": "search_records", "arguments": "NOT_JSON"},
                    }],
                }
            }]
        }
        turn2_body = {
            "choices": [{"message": {"role": "assistant", "content": "Recovered"}}]
        }
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_cm = MagicMock()
            mock_cm.read.side_effect = [
                json.dumps(turn1_body).encode("utf-8"),
                json.dumps(turn2_body).encode("utf-8"),
            ]
            mock_urlopen.return_value.__enter__.return_value = mock_cm

            resp = adapter.send("Query")
            self.assertEqual(resp.text, "Recovered")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_openai_adapter.py -v`
Expected: FAIL (missing multi-turn tool handling in `OpenAILikeTargetAdapter`)

- [ ] **Step 3: Implement Tool Calling Loop in `core/adapters/openai_like.py`**

Implement `_get_tools_spec()` declaring `search_records` according to OpenAI standard function calling schema. In `send(prompt, **kwargs)`:
1. Append user prompt to messages.
2. In a loop up to `MAX_TOOL_CALLS_PER_TURN`:
   - Send payload with `tools=self._get_tools_spec()` and `tool_choice="auto"`.
   - If response has `tool_calls`: parse function name and arguments safely. Execute `agent.search_records(table, keyword)` using current defense settings. Record tool call metadata in `tool_calls_turn`. Append `assistant` message with `tool_calls` and corresponding `tool` result messages to `self.messages`.
   - If response has text: break loop and set final response text.
3. If defense is `"all"`, apply `agent.apply_defense_output(reply_text)`.
4. Return `TargetResponse(text=reply_text, tool_calls=tool_calls_turn, metadata=...)`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_openai_adapter.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/adapters/openai_like.py tests/test_openai_adapter.py
git commit -m "feat(adapter): add native openai tool-calling loop and defense enforcement"
```

---

### Task 2: Dedicated Benign Control Dataset (`data/normalized/test_cases_benign.json`)

**Files:**
- Create: `data/normalized/test_cases_benign.json`
- Test: `tests/test_benign_dataset.py`

**Interfaces:**
- Consumes:
  - `data/schema/test_case.schema.json`
  - `scripts.standardize_datasets.validate_against_draft07_schema(case, schema) -> list[str]`
- Produces:
  - `data/normalized/test_cases_benign.json` containing 36 balanced benign cases (12 TH, 12 EN, 12 MIX) across 6 educational domains:
    1. `courses` (Prerequisites, syllabus, credit requirements)
    2. `schedules` / `classrooms` (Exam dates, room locations, office hours)
    3. `professors` / `departments` (Faculty head, department directory)
    4. `announcements` (Academic calendar, public events, registration deadlines)
    5. `awards` (Dean's list honors, graduation awards)
    6. `policy_inquiries` (Public PDPA contact info, university refund policy, legitimate DPO office location without asking for PII)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_benign_dataset.py
import json
import os
import unittest
from scripts.standardize_datasets import SCHEMA_PATH, validate_against_draft07_schema


class TestBenignDataset(unittest.TestCase):
    """Test suite for the dedicated benign control dataset."""

    DATASET_PATH = os.path.join("data", "normalized", "test_cases_benign.json")

    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            cls.schema = json.load(f)

    def test_dataset_exists_and_valid_json(self):
        """Dataset file exists and parses as valid JSON dict with 'cases' list."""
        self.assertTrue(os.path.exists(self.DATASET_PATH), f"Missing {self.DATASET_PATH}")
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("cases", data)
        self.assertEqual(len(data["cases"]), 36)

    def test_all_cases_pass_draft07_schema(self):
        """All 36 benign cases must strictly pass Canonical Draft-07 schema."""
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        for case in data["cases"]:
            errors = validate_against_draft07_schema(case, self.schema)
            self.assertEqual(errors, [], f"Schema errors in case {case.get('id')}: {errors}")

    def test_benign_invariants(self):
        """All cases must have is_benign=True, fulfillment behavior, and balanced languages."""
        with open(self.DATASET_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        by_lang = {"th": 0, "en": 0, "th-en": 0}
        for case in data["cases"]:
            self.assertTrue(case.get("is_benign"))
            self.assertEqual(case.get("category"), "benign_control")
            self.assertEqual(case.get("expected_behavior"), "fulfillment")
            lang = case.get("language")
            self.assertIn(lang, by_lang)
            by_lang[lang] += 1

            # Benign cases must never have canary tokens in expected output
            eval_meta = case.get("evaluation", {})
            tokens = eval_meta.get("expected_tokens", [])
            for t in tokens:
                self.assertNotIn("CANARY-SP", t)
                self.assertNotIn("CANARY-PUB", t)

        self.assertEqual(by_lang["th"], 12)
        self.assertEqual(by_lang["en"], 12)
        self.assertEqual(by_lang["th-en"], 12)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benign_dataset.py -v`
Expected: FAIL (file `data/normalized/test_cases_benign.json` does not exist)

- [ ] **Step 3: Create `data/normalized/test_cases_benign.json`**

Generate 36 structured test cases (12 TH: `BENIGN-TH-01`..`12`, 12 EN: `BENIGN-EN-01`..`12`, 12 MIX: `BENIGN-MIX-01`..`12`) targeting public mock data (`students`, `professors`, `courses`, `departments`, `schedules`, `classrooms`, `awards`, `announcements`). Each record includes:
- `id`: Unique identifier
- `owasp_category`: `"BENIGN:Control-Baseline"`
- `category`: `"benign_control"`
- `technique`: `"benign_thai"` / `"benign_english"` / `"benign_mixed"`
- `language`: `"th"` / `"en"` / `"th-en"`
- `difficulty`: `"easy"` or `"medium"`
- `is_benign`: `true`
- `prompt`: Natural user inquiry
- `expected_behavior`: `"fulfillment"`
- `expected_behavior_description`: Description of helpful fulfillment
- `evaluation`: `{"type": "benign_marker", "expected_markers": [...], "min_matches": 1}`
- `severity`: `"low"`
- `source_reference`: `"Benign Control Dataset v1.0"`

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benign_dataset.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add data/normalized/test_cases_benign.json tests/test_benign_dataset.py
git commit -m "feat(data): add canonical 36-case benign control dataset with draft-07 validation"
```

---

### Task 3: CLI Expansion: Indirect Runner & Unified Benchmark Leaderboard

**Files:**
- Modify: `core/cli/commands/eval.py:1-592`
- Modify: `core/cli/app.py:40-120`
- Modify: `core/cli/commands/doctor.py:65-85`
- Test: `tests/test_benchmark_cli.py`

**Interfaces:**
- Consumes:
  - `core.evaluator.indirect.evaluate_indirect_case(case, adapter, defense)`
  - `core.evaluator.indirect.load_indirect_cases()`
  - `core.evaluator.lock.BenchmarkLockVerifier`
  - `core.evaluator.stats.rate_with_ci(success_count, total_count)`
- Produces:
  - CLI flag `--indirect` in `thai-eval eval run --indirect [--dry-run]`
  - CLI subcommand `thai-eval benchmark run [--suite ...] [--all] [--dry-run] [--target ...] [--model ...]`
  - Leaderboard generation exported to `results/benchmark_leaderboard.md` and `.json`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_benchmark_cli.py
import io
import unittest
from unittest.mock import patch
from core.cli.app import build_parser, SecurityCLIParser
from core.cli.commands.eval import run_eval_run


class TestBenchmarkCLI(unittest.TestCase):
    """Test CLI argument parsing and dry-run execution for indirect and unified benchmark."""

    def setUp(self):
        self.parser = build_parser()

    def test_indirect_eval_flag_parsed(self):
        """CLI parser accepts --indirect flag under eval run."""
        args = self.parser.parse_args(["eval", "run", "--indirect", "--dry-run"])
        self.assertTrue(getattr(args, "indirect", False))
        self.assertTrue(getattr(args, "dry_run", False))

    def test_indirect_dry_run_executes_cleanly(self):
        """eval run --indirect --dry-run returns exit code 0 without network calls."""
        args = self.parser.parse_args(["eval", "run", "--indirect", "--dry-run", "--quiet"])
        ret = run_eval_run(args)
        self.assertEqual(ret, 0)

    def test_benchmark_run_command_parsed(self):
        """CLI parser accepts benchmark run subcommand with --all and --dry-run."""
        args = self.parser.parse_args(["benchmark", "run", "--all", "--dry-run", "--quiet"])
        self.assertEqual(args.command, "benchmark")
        self.assertEqual(args.subcommand, "run")
        self.assertTrue(args.all)
        self.assertTrue(args.dry_run)

    def test_doctor_checks_benign_dataset(self):
        """thai-eval doctor includes test_cases_benign.json in diagnostics."""
        from core.cli.commands.doctor import run_diagnostics
        diag = run_diagnostics()
        components = [c["component"] for c in diag["checks"]]
        self.assertIn("Benchmark Datasets", components)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benchmark_cli.py -v`
Expected: FAIL (`--indirect` or `benchmark` subcommand unrecognized)

- [ ] **Step 3: Implement `--indirect` and `benchmark run` in CLI**

1. In `core/cli/app.py`:
   - Add `--indirect` argument to `eval_run_parser`.
   - Register `benchmark` parser with subcommand `run`:
     - `--all`: run all suites (`parallel`, `indirect`, `probing`, `linguistic`, `benign`)
     - `--suites`: comma-separated list of suites
     - `--defenses`: comma-separated defense tiers (default: `off,prompt,tools,spotlight,all`)
     - `--target`, `--model`, `--base-url`, `--api-key`, `--dry-run`, `--export-dir`
2. In `core/cli/commands/eval.py`:
   - Implement `_run_eval_indirect(args)`: loads `data/normalized/test_cases_indirect.json`, executes lock verification via `BenchmarkLockVerifier`, evaluates cases using `evaluate_indirect_case`, computes Manipulation Rate and Unrequested Disclosure Rate with Wilson 95% CIs.
   - Implement `run_benchmark_command(args)`: handles `benchmark run`, runs each requested suite in dry-run or full mode, aggregates scorecard table, exports unified markdown leaderboard to `results/benchmark_leaderboard.md`.
3. In `core/cli/commands/doctor.py`:
   - Add `"Benign Cases", ["data/normalized/test_cases_benign.json"]` to dataset diagnostics checklist.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python.exe -m unittest tests/test_benchmark_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add core/cli/app.py core/cli/commands/eval.py core/cli/commands/doctor.py tests/test_benchmark_cli.py
git commit -m "feat(cli): add indirect benchmark runner and unified benchmark command"
```

---

### Task 4: Pro-Grade System Architecture Documentation & Literature Update

**Files:**
- Overwrite: `docs/architecture.md` (fill the 0-byte file)
- Modify: `docs/REFERENCES.md`
- Modify: `README.md:120-145`

**Interfaces:**
- Consumes:
  - System components from `agent.py`, `core/adapters/`, `core/defenses/`, `core/evaluator/`
  - References: AgentDojo (Debenedetti et al., NeurIPS 2024), ThaiSafetyBench (Photiwongsawat et al., 2024), InjecAgent (Deng et al., ACL 2024), PyRIT (Microsoft)
- Produces:
  - Complete `docs/architecture.md` with:
    - Section 1: End-to-End Evaluation Pipeline & Component Architecture (Mermaid diagram)
    - Section 2: Defense-in-Depth 5 Tiers Specification (`off`, `prompt`, `tools`, `spotlight`, `all`)
    - Section 3: Threat Boundary & Attack Surface Model (OWASP LLM01, LLM02, LLM06)
    - Section 4: Target Adapter Layer Architecture & Tool Calling Protocol
    - Section 5: Statistical Engine & Wilson Score CI Formulations
    - Section 6: Comparative Mapping to Global Benchmarks (AgentDojo, InjecAgent, BIPIA, ThaiSafetyBench)
  - Updated `docs/REFERENCES.md` with formal academic citations.
  - Updated `README.md` with checked roadmap milestones (`[x] Benign dataset`, `[x] Reproducible benchmark`).

- [ ] **Step 1: Write verification test for documentation presence and integrity**

```python
# In tests/test_cli_architecture.py or new test check
def test_architecture_documentation_complete():
    """Verify docs/architecture.md is populated and exceeds 5KB."""
    arch_path = "docs/architecture.md"
    assert os.path.exists(arch_path)
    assert os.path.getsize(arch_path) > 5000, "docs/architecture.md is too short or empty"
    with open(arch_path, "r", encoding="utf-8") as f:
        content = f.read()
    assert "```mermaid" in content
    assert "Defense-in-Depth" in content
    assert "OWASP-LLM01" in content
```

- [ ] **Step 2: Run verification test to verify it fails**

Run: `.venv\Scripts\python.exe -m unittest tests/test_cli_architecture.py -v`
Expected: FAIL (or verify `docs/architecture.md` is currently 0 bytes)

- [ ] **Step 3: Author `docs/architecture.md` and update `docs/REFERENCES.md` & `README.md`**

1. Write complete `docs/architecture.md` with clean GitHub Markdown, alerts, and verified Mermaid diagrams.
2. Add citations to `docs/REFERENCES.md` for AgentDojo (NeurIPS 2024), ThaiSafetyBench (2024), PyRIT (2024).
3. Update `README.md` roadmap to mark completed items:
   - `- [x] Benign dataset`
   - `- [x] Test suite`
   - `- [x] Reproducible benchmark`

- [ ] **Step 4: Run full offline test suite**

Run: `.venv\Scripts\python.exe -m unittest discover -s tests -v`
Expected: 210+ tests PASS (all offline, zero live API quota spend).

- [ ] **Step 5: Commit**

```bash
git add docs/architecture.md docs/REFERENCES.md README.md
git commit -m "docs: author publication-grade architecture specification and update research references"
```

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-11-05-benchmark-readiness.md`. Please review the plan. Which execution approach would you prefer?

- **Subagent-driven** - A fresh subagent implements each task and a fresh reviewer checks it before the next one starts, then a whole-branch review at the end. Most thorough; costs a fresh context per task and per review.
- **Native** - I implement every task myself in this session, the way this harness runs work, then one fresh reviewer on the most capable model checks the whole branch. Cheapest and fastest; no independent review until the end. Runs well with a mid-tier session model, since the plan carries the design.

**For this plan I recommend Native**, because the tasks build cleanly on existing interfaces (`urllib.request`, JSON Schema validation, and existing test runners), keep code additions minimal (Ponytail mode), and can be verified 100% offline via the local unit test suite. Does the plan capture what you want, and which approach should we use?
