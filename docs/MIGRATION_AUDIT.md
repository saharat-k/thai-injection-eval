# Migration Audit Log

This document records architectural refactoring steps, legacy test adaptations, and preserved/remediated behaviors across the v2.0 overhaul.

## Phase 0 & 1: Preserved Baseline Behaviors

1. **Cross-Thread Fail-Open ACL (Preserved for Phase 1 Refactor Only)**:
   - *Status*: Intentionally captured in Phase 0 deterministic fixtures (`golden_tool_outputs.json`).
   - *Rationale*: Phase 1 requires 100% pure structural refactoring (Zero Semantic Changes). If security semantics were changed during file decomposition, regressions could not be isolated from relocation bugs.
   - *Remediation Gate*: Fixed in Phase 2 via `SecurityContext` deny-by-default and explicit `Policy` objects.

2. **Deterministic Parity Gate**:
   - `tests/test_golden_fixtures.py` verifies all 14 representative tool outputs and 15 system prompt hashes match the pre-refactor state identically.
   - Total pre-refactor unit tests: 376 tests passing (2 expected failures).

## Modified Tests Log

*(Any test modified during module relocation will be logged below with line diff and technical justification)*
- None. Zero tests were modified. The facade architecture in `agent.py` achieved 100% test compatibility across all 378 tests.

## Task 1 Completion Summary
- Modularized monolithic `agent.py` (2,614 lines) into:
  - `core/tools/legacy.py`: 762 lines (tool declarations, connection lifecycle, thread-local proxies).
  - `core/agent/runtime.py`: 1,734 lines (session management, LLM caller, prompt generators, runners).
  - `agent.py`: 134 lines (thin facade delegating dynamically to `core.tools.legacy` and `core.agent.runtime` with transparent attribute proxying).
- Full test discovery: 378 tests passed (expected failures=2, 0 live API calls). Parity verified against golden fixtures.
