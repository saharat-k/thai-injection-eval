# Security policy and limitations disclosure

## Supported versions

Security updates are maintained for the following versions:

| Version | Supported |
| ------- | --------- |
| 2.0.x | Yes |
| < 2.0.0 | No |

## Reporting a vulnerability

If you discover a vulnerability in the harness itself (such as arbitrary code execution, SQL injection in SQLite drivers, secret leakage from local environments, or harness state bypasses):

1. Do not open a public issue.
2. Report it privately through [GitHub Private Vulnerability Reporting](https://github.com/saharat-k/thai-injection-eval/security/advisories/new) or the repository security contact.
3. Include a minimal reproducible proof of concept and environment details (Python version, OS, and installed dependencies).
4. Maintainers will acknowledge receipt within 48 hours and coordinate remediation before public disclosure.

## Threat Model Boundaries and research scope

`thai-injection-eval` studies prompt injection behavior in Thai-language LLM applications under explicit threat model boundaries.

### 1. Synthetic Sandboxed Environment vs. real-world systems

Records, student profiles, citizen IDs, faculty salaries, and canary tokens in `data/university.db` and the benchmark datasets are 100% synthetic mock data with no real human PII or production credentials. The harness executes against an in-memory or local SQLite mock database and does not connect to live university ERP systems, remote webhooks, or external mail services.

### 2. Explicitly excluded threat vectors

- **Cross-session memory poisoning**: Multi-turn red teaming supports configurable adaptive turns (`--attempts` with `crescendo`, `tap`, and `tree` beam search plus refusal backtracking), but persistent cross-session memory poisoning across independent user sessions is outside scope.
- **Multimodal vectors**: The framework tests textual inputs (Thai, English, and Thai-English code-switching). Injected images, audio, OCR documents, and vision-language payloads are not evaluated.
- **Production tool side effects**: `send_campus_notification` and `export_report` are instrumented stubs gated by `SecurityContext` and `RoleBasedPolicy` (`core/tools/policy.py`). They do not run OS commands or send external network requests.
- **General safety alignment**: The benchmark focuses on OWASP LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure), and LLM06 (Excessive Agency / BOLA), rather than toxicity, hate speech, or other non-injection harms.

### 3. Detector and DLP boundaries

Output Data Loss Prevention (DLP) and evaluation judges use deterministic pattern matching, Unicode normalization (NFKC), and decoded canary checks (Base64, Hex, Thai numerals, and Thai verbal digits). Semantic paraphrasing that conveys approximate values without revealing underlying tokens cannot be blocked solely by lexical filters.

For detailed methodological bounds, read [`LIMITATIONS.md`](LIMITATIONS.md).

## Responsible research and Safe Harbor

This framework exists strictly for defensive security research, academic evaluation, and hardening Thai-language LLM applications. Practitioners must obtain explicit authorization before testing payloads against third-party systems.
