# Pro-Level Engineering & Reasoning Standards

This project adheres to Senior Software Engineer & Pro-level reasoning standards.
When executing instructions using thinking models (such as Gemini 3.8 Flash High):

## 1. Architectural & Dependency Analysis (Think Before Acting)
- Before modifying or creating code, trace callers, imports, schemas, and dependent modules.
- Understand how changes affect the end-to-end data flow (e.g., between `agent.py`, `web_ui.py`, database, and test cases).
- Do not apply quick or superficial patches; solve the root cause while preserving existing architectural patterns.

## 2. Regression Prevention & Verification
- Verify changes against existing behavior and edge cases (boundary conditions, null/empty payloads, unexpected inputs).
- Preserve existing functionality, test integrity, and security considerations (especially around prompt injection vectors).
- Avoid modifying working logic outside the explicit scope of the task.

## 3. Code & Documentation Integrity
- Preserve existing comments, docstrings, typing hints, and license headers.
- Maintain consistent code style matching the existing Python codebase (PEP 8, logging practices, exception handling).

## 4. Multi-Step Reasoning for Complex Tasks
- For complex refactoring or security implementations, plan changes in distinct, logical phases.
- Validate each step before proceeding to ensure high confidence and stability.

## 5. Project Constraints & Safety Rules
- **Synthetic Data Only**: Never store or handle real personal data, credentials, or production secrets.
- **Commit & Secret Hygiene**: Never commit `.env`, `*.db`, or `results.md` (keep them git-ignored).
- **Environment Isolation**: Always use the local virtual environment (`.venv`); never execute global `pip install`. Keep dependencies minimal.
- **API Quota & Live Calls**: Running `agent.py` makes live Gemini API calls; only run live evaluations when explicitly requested. Prefer offline verification via `tests/` (`unittest`).
- **Test Case Schema**: When adding prompts to `test_cases.json`, ensure required fields (`id`, `language`, `attack_type`, `source_reference`, `technique`, `prompt`).

