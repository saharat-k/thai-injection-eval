# Security Policy & Limitations Disclosure

## Supported Versions

Security updates and vulnerability remediation are actively maintained for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of this evaluation harness seriously. If you discover a vulnerability in the harness itself (e.g. arbitrary code execution, SQL injection in SQLite drivers, secret leakage from local environments, or harness state bypasses):

1. **Do not open a public issue.**
2. Report the vulnerability privately via **[GitHub Private Vulnerability Reporting](https://github.com/saharat-k/thai-injection-eval/security/advisories/new)** or by contacting the maintainer via repository security channels.
3. Provide a minimal reproducible test case (PoC) and environment details (Python version, OS, relevant dependencies).
4. Maintainers will acknowledge receipt within 48 hours and coordinate remediation before public disclosure.

---

## Threat Model Boundaries & Research Scope

`thai-injection-eval` is designed specifically for studying and benchmarking prompt injection robustness in Thai-language LLM interactions. Users and researchers must understand the formal boundaries of this threat model:

### 1. Synthetic Sandboxed Environment vs. Real-World Systems
- **Synthetic Data**: All records, student profiles, citizen IDs, faculty salaries, and system tokens contained in `data/university.db` and benchmark cases are 100% synthetic mock data. No real human PII or production credentials exist in this repository.
- **Single-Host Sandbox**: The evaluation environment executes against an in-memory or local SQLite mock database. It does not interface with live university enterprise resource planning (ERP) systems, remote webhooks, or cloud services.

### 2. Explicitly Excluded Threat Vectors
The following threat dimensions are explicitly out-of-scope for the current release:
- **Long-Horizon Multi-Turn Attacks**: While the harness supports up to 3 adaptive turns, long-horizon conversational manipulation (e.g. multi-session memory poisoning, extended persona grooming over tens of turns) is outside the primary evaluation scope.
- **Multimodal Prompt Injection**: The framework evaluates textual inputs (Thai, English, and Thai-English code-switching). Multimodal vectors (injected images, adversarial audio, document OCR payloads, or vision-language inputs) are not evaluated.
- **Production Tool Side-Effects**: Tools like `send_campus_notification` and `export_report` are instrumented stubs for monitoring action hijacking and outbound side-channel exfiltration. They do not execute external OS commands or send real network traffic.
- **General Uncensored Jailbreaking**: The benchmark focuses strictly on OWASP LLM01 (Prompt Injection) and LLM06 (Excessive Agency / Tool Authorization Violations), not general safety alignment (such as toxicity, hate speech, or bio-weapon generation).

### 3. Detector & DLP Boundaries
- **Lexical and Regex Constraints**: The output Data Loss Prevention (DLP) layer and automated evaluation judges use deterministic pattern matching, Unicode normalization (NFKC), and decoded canary candidates (Base64, Hex, Thai numerals, and Thai verbal digits).
- **Semantic Paraphrasing**: Complex semantic paraphrasing (e.g. stating approximate ranges or metaphorical descriptions without disclosing underlying tokens or values) cannot be fully eliminated by lexical filters.

For detailed methodological limitations, consult [**`LIMITATIONS.md`**](LIMITATIONS.md).

---

## Responsible Research & Safe Harbor

This framework is created strictly for defensive security research, academic evaluation, and hardening Thai LLM applications against prompt injection. Security practitioners must ensure they have explicit authorization before applying test payloads against third-party production infrastructure.
