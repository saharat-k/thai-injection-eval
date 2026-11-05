# Design Specification: Universal Model Selection & CLI Configuration Parity

**Date:** 2026-11-05  
**Topic:** Universal CLI Model Flags (`--blue`, `--red`, `--model`) & Target Adapter Decoupling  
**Target:** Align model configuration with industry benchmark standards (AgentDojo, UK AISI Inspect AI, PyRIT)  
**Status:** Approved  

---

## 1. Intent & Context (The "Why")

Currently, model selection across `thai-injection-eval` is fragmented:
1. `agent.BlueSession` hardcodes `make_client(BLUE_MODEL)` using the global environment variable `BLUE_MODEL` rather than accepting an explicit `model` argument in its constructor.
2. In `core/cli/app.py`, `eval run` supports `--model`, but `redteam run` has no `--model`, `--blue`, or `--red` flags. Users are forced to execute shell environment assignments (e.g. `$env:RED_MODEL=...; $env:BLUE_MODEL=...`) before running multi-turn red teaming.
3. Industry benchmark standard frameworks (AgentDojo, UK AISI Inspect AI, Microsoft PyRIT) provide first-class CLI flags (`--model`, `--attack-model`, `--target`) and adapter configuration objects so benchmarks can evaluate and compare multiple models without environment mutation.

---

## 2. Architecture & Design

### 2.1 BlueSession Constructor Decoupling
Modify `agent.BlueSession.__init__`:
```python
def __init__(
    self,
    defense: str,
    role: str = "registrar_staff",
    allow_fallback: bool = None,
    model: Optional[str] = None,
):
    self.defense = defense
    self.role = role if role in BLUE_ROLES else "registrar_staff"
    model_spec = model or BLUE_MODEL
    self.client, self.model = make_client(model_spec)
```

### 2.2 BuiltinTargetAdapter Model Pass-Through
In `core/adapters/builtin.py`:
Extract `self.model = self.config.get("model") or self.config.get("blue_model")` and pass `model=self.model` to `agent.BlueSession(...)`.

### 2.3 Universal CLI Flags
In `core/cli/app.py`:
- `eval run`: Add `--blue` / `--blue-model` (alias of `--model`) and `--red` / `--red-model`.
- `redteam run`: Add `--model` / `--blue` / `--blue-model` and `--red` / `--red-model`.
- `benchmark run`: Add `--blue` / `--blue-model` (alias of `--model`) and `--red` / `--red-model`.

In command runners (`core/cli/commands/redteam.py`, `core/cli/commands/eval.py`):
Honor `--blue` and `--red` by passing them into target adapter configs and `MultiTurnRedTeamRunner`.
