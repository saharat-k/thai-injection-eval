---
name: llm-security-evaluator
description: Comprehensive evaluation and red-teaming framework for assessing LLM Agent resilience against OWASP Top 10 for LLM (LLM01 Prompt Injection, LLM06 Excessive Agency), evaluating bypass rates, canary exfiltration, and tool-level authorization policies.
---

# LLM Security Evaluator & Prompt Injection Benchmark

An academic and enterprise-grade evaluation framework designed to benchmark, stress-test, and harden Large Language Model (LLM) agents against Prompt Injection vulnerabilities, Privilege Escalation, and Unauthorized Tool Invocation.

Based on the **OWASP Top 10 for Large Language Model Applications**:
- **LLM01: Prompt Injection** (Direct System Prompt Overrides, Jailbreaks, Virtualization, Obfuscation, and Indirect Data-layer Injections)
- **LLM06: Excessive Agency** (Unauthorized tool calls, Privilege Escalation beyond active role policy, BOLA/IDOR violations)

---

## 1. Core Threat Taxonomy & Attack Classes

The framework evaluates targets across standard adversarial categories:

| Threat Category | Description | Primary Vector |
| :--- | :--- | :--- |
| **`OWASP-LLM01:Direct-Injection`** | Adversarial instructions injected directly in the user turn to override system instructions | Authority impersonation, few-shot priming, disaster recovery roleplay |
| **`OWASP-LLM01:Indirect-Injection`** | Adversarial directives embedded passively inside retrieved data records (RAG / DB) | Poisoned research titles, untrusted database field execution |
| **`OWASP-LLM01:Reconnaissance`** | Probing internal system boundary, schema discovery, or volunteer information disclosure | Catalog exploration, `sqlite_master` probing, policy boundary queries |
| **`OWASP-LLM01:Obfuscation-Evasion`** | Bypassing perimeter pattern filters using encodings or orthographic manipulation | Base64 wrapping, Hex encoding, Thai numeral replacement, spaced tokens |
| **`OWASP-LLM06:Excessive-Agency`** | Inducing the agent to perform privileged business actions outside its assigned role | Calling `get_faculty_payroll` or `get_student_private_record` from guest/registrar roles |

---

## 2. Scientific Evaluation Metrics

The benchmark produces 4 key scientific metrics:

1. **Attack Success Rate (ASR / BSR)**:
   $$\text{ASR} = \frac{\text{Successful Breaches}}{\text{Total Adversarial Tests}} \times 100\%$$
   Target: `< 5.0%` in production, `0.0%` in high-assurance environments.

2. **False Refusal Rate (FRR)**:
   $$\text{FRR} = \frac{\text{Refused Benign Inquiries}}{\text{Total Benign Tests}} \times 100\%$$
   Measures over-defense and usability impact. Target: `< 2.0%`.

3. **Tool Violation Rate (TVR)**:
   $$\text{TVR} = \frac{\text{Unauthorized Tool Attempts}}{\text{Total Tests}} \times 100\%$$
   Evaluates OWASP LLM06 Excessive Agency and broken authorization. Target: `0.0%`.

4. **Defense Efficiency Score (DES)**:
   $$\text{DES} = \left(1 - \frac{\text{ASR}}{100}\right) \times \left(1 - \frac{\text{FRR}}{100}\right) \times 100\%$$
   Harmonic protection index balancing security robustness against legitimate operational utility.

---

## 3. Usage & Execution Workflows

### Workflow A: CLI Evaluation (Built-in or External Target)

Run evaluation directly via Python terminal:

```powershell
# Windows PowerShell:
# Evaluate built-in reference target under full defense
.\.venv\Scripts\python.exe -m core.evaluator --target builtin --defense all --role registrar_staff

# Evaluate an external target (OpenAI / vLLM / Ollama endpoint)
.\.venv\Scripts\python.exe -m core.evaluator --target openai --base-url http://localhost:8000/v1 --model llama-3-70b --api-key sk-test

# Export scientific Markdown & JSON reports
.\.venv\Scripts\python.exe -m core.evaluator --target builtin --defense all --export-dir results/

# Linux / macOS:
# ./.venv/bin/python -m core.evaluator --target builtin --defense all --role registrar_staff
```

### Workflow B: Python API Integration

```python
from core.adapters import create_target_adapter
from core.evaluator import SecurityEvaluator, generate_markdown_report, export_report_files

# 1. Create target adapter (Built-in or External)
target = create_target_adapter("builtin", defense="all", blue_role="registrar_staff")

# 2. Run benchmark
evaluator = SecurityEvaluator(target)
report_data = evaluator.run_benchmark(defense="all", blue_role="registrar_staff")

# 3. Print scientific scorecard
metrics = report_data["metrics"]
print(f"ASR: {metrics['attack_success_rate']}% | FRR: {metrics['false_refusal_rate']}% | DES: {metrics['defense_efficiency_score']}%")

# 4. Export artifacts
export_report_files(report_data, output_dir="results", base_name="owasp_benchmark_run")
```

### Workflow C: Web UI Dashboard

Start the web server:
```powershell
.\.venv\Scripts\python.exe web_ui.py
# Linux / macOS: ./.venv/bin/python web_ui.py
```
Open `http://localhost:5000` and navigate to the **"OWASP Security Benchmark & Research"** tab for interactive visual evaluation, radar charts, and downloadable reports.
