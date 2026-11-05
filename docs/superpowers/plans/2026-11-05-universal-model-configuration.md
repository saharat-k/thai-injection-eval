# Universal Model Selection & CLI Configuration Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple model configuration across `BlueSession`, `BuiltinTargetAdapter`, and the CLI by introducing first-class `--blue`, `--red`, and `--model` flags, matching AgentDojo and UK AISI Inspect AI standards.

**Architecture:** Add `model: Optional[str] = None` to `BlueSession` constructor and pass it through `BuiltinTargetAdapter`. Expose universal `--blue`, `--red`, and `--model` CLI arguments in `core/cli/app.py` and propagate them dynamically to evaluation runners.

**Tech Stack:** Python 3.10+, Argparse, Google GenAI SDK, OpenAILike Client.

**Spec:** [docs/superpowers/specs/2026-11-05-universal-model-configuration-design.md](file:///D:/GitHub/thai-injection-eval/docs/superpowers/specs/2026-11-05-universal-model-configuration-design.md)

## Global Constraints

- **Synthetic Data Only:** Never store or handle real personal data, credentials, or production secrets.
- **Commit & Secret Hygiene:** Never commit `.env`, `*.db`, or `results.md` (keep them git-ignored).
- **Environment Isolation:** Always run commands using `.venv\Scripts\python.exe`.
- **API Cost & Quota:** Maintain default free models (`gemini-3.5-flash-lite`, `openrouter:openrouter/free`).
- **Offline Test Integrity:** All unit tests in `tests/` must remain 100% offline, deterministic, and mock external API dependencies.

## Review Focus

1. **Fallback Model Preservation:** When a custom model is supplied to `BlueSession(model="custom")`, `self.models_to_try` must include the custom model as primary and conditionally append `FALLBACK_MODEL` if fallback is enabled.
2. **Backward Compatibility:** Calling `BlueSession(defense="tools")` without `model` must seamlessly preserve default `BLUE_MODEL` behavior.
3. **CLI Alias Equivalence:** Passing `--model my-model` or `--blue my-model` in `eval run` or `redteam run` must produce identical target adapter configurations.
4. **Target Adapter Reset Parity:** Calling `adapter.reset()` must retain the configured custom model.
5. **No Global State Leaks:** Running a test with `--blue` or `--red` should not permanently mutate process globals in ways that break subsequent offline tests.

---

### Task 1: Wire `model` Parameter into `BlueSession` and `BuiltinTargetAdapter`

**Files:**
- Modify: `agent.py:1475-1510` (`BlueSession.__init__`)
- Modify: `core/adapters/builtin.py:11-35` (`BuiltinTargetAdapter`)
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: `agent.BlueSession(defense: str, role: str = "registrar_staff", allow_fallback: bool = None, model: Optional[str] = None)`
- Produces: `BlueSession` initialized with target `model` instead of default global `BLUE_MODEL`

- [x] **Step 1: Write failing unit tests for custom model initialization**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement `model` parameter in `BlueSession` and `BuiltinTargetAdapter`**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

```bash
git add agent.py core/adapters/builtin.py tests/test_agent.py
git commit -m "feat(adapters): wire explicit model parameter to BlueSession and BuiltinTargetAdapter"
```

---

### Task 2: Add Universal Model CLI Flags (`--blue`, `--red`, `--model`)

**Files:**
- Modify: `core/cli/app.py:90-245`
- Test: `tests/test_cli_model_flags.py`

**Interfaces:**
- Produces: CLI argument parser accepting `--blue`, `--red`, `--model` across `eval run`, `redteam run`, and `benchmark run`

- [x] **Step 1: Write failing unit tests for universal CLI flags**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement universal CLI flags in `core/cli/app.py`**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

---

### Task 3: Propagate Model Flags to Evaluator and Red-Team Run Commands

**Files:**
- Modify: `core/cli/commands/redteam.py:175-230`
- Modify: `core/cli/commands/eval.py:240-270`
- Modify: `core/evaluator/redteam.py:95-125`
- Test: `tests/test_redteam.py`

**Interfaces:**
- Consumes: `args.blue` (or `args.model`), `args.red`
- Produces: Target adapters and red-team runners configured with requested model overrides

- [x] **Step 1: Write failing unit test for redteam runner model propagation**
- [x] **Step 2: Run test to verify it fails**
- [x] **Step 3: Implement model propagation in runners and command handlers**
- [x] **Step 4: Run test to verify it passes**
- [x] **Step 5: Commit**

---

### Task 4: Full Regression Testing & Live Mini Benchmark Verification

**Files:**
- Test: All suites in `tests/`

- [x] **Step 1: Run full offline test suite**
- [x] **Step 2: Run secret & hygiene audit**
- [x] **Step 3: Execute Live API verification using new CLI flags**
- [x] **Step 4: Final commit & status check**

```bash
git status
git log --oneline -n 4
```
