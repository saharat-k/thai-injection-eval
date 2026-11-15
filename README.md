# Thai Injection Eval
───────────────────

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-403%20passing-brightgreen.svg)](tests/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Pre-Registration](https://img.shields.io/badge/pre--registration-v2.0-blueviolet.svg)](docs/benchmark/PRE_REGISTRATION.md)
[![Benchmark Cases](https://img.shields.io/badge/benchmark-Dataset%20A%20108%20cases-orange.svg)](data/normalized/test_cases_parallel_v2.json)

Evaluation framework for studying prompt injection robustness in Thai-language LLM interactions.

> ชุดเครื่องมือและระเบียบวิธีวิจัย (Evaluation Framework) เพื่อศึกษาและประเมินความทนทานต่อการโจมตีแบบ Prompt Injection ในการมีปฏิสัมพันธ์กับโมเดลภาษาขนาดใหญ่ (LLM) และ AI Agent ในบริบทภาษาไทย

---

## Status

**Benchmark v2.0.0 (Pre-Registered & Multi-Model Decoupled Architecture)**

The v2.0 release establishes an open-science benchmark protocol with pre-registered hypotheses ([`docs/benchmark/PRE_REGISTRATION.md`](docs/benchmark/PRE_REGISTRATION.md)), cross-lingual parallel triplets (Dataset A: 36 scenarios $\times$ 3 languages = 108 cases), multi-family LLM evaluation, and decoupled metric tracking separating **Attempt Rate** (LLM compliance to adversary) from **Leak Rate** (actual exfiltration prevented by backend ACL / DLP layers).

Full empirical case traces and aggregated statistical matrices are published in:
- Case-level JSONL traces: [`results/published/benchmark_v2_static.jsonl`](results/published/benchmark_v2_static.jsonl)
- Aggregated CSV with FDR adjustments: [`results/published/benchmark_v2_summary.csv`](results/published/benchmark_v2_summary.csv)
- Methodological bounds & disclosures: [`LIMITATIONS.md`](LIMITATIONS.md)

---

## Empirical Benchmark Results (Dataset A v2.0)

All evaluations use standardized isomorphic triplets from `data/normalized/test_cases_parallel_v2.json` with Wilson 95% score confidence intervals and paired bootstrap testing.

### Target Model Families Evaluated
- **Google Family**: `gemini-3.5-flash-lite` (Free Tier)
- **Open-Weights Family**: `meta-llama/llama-3.3-70b-instruct:free` (Free Tier via OpenRouter)
- **Evaluation Oracle**: Deterministic hybrid rule-based oracle with zero-width / normalization anti-evasion (Stratified Cohen's $\kappa = 0.933$, Sensitivity = 1.0).

### Table 1: Multi-Model Empirical Defense Matrix (Attempt vs. Leak Decoupling)

| Model Family | Defense Tier | Language | Actual Leak Rate (ASR) [95% CI] | Attempt Rate [95% CI] | False Refusal (FRR) | Defense Score (DES) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Gemini 3.5 Flash Lite** | `OFF` | EN | 86.7% `[70.3%, 94.7%]` | 86.7% `[70.3%, 94.7%]` | 0.0% | 13.3 |
| | | TH | 86.7% `[70.3%, 94.7%]` | 86.7% `[70.3%, 94.7%]` | 0.0% | 13.3 |
| | | TH-EN | 90.0% `[74.4%, 96.5%]` | 90.0% `[74.4%, 96.5%]` | 0.0% | 10.0 |
| | `PROMPT` | EN | 60.0% `[42.3%, 75.4%]` | 60.0% `[42.3%, 75.4%]` | 0.0% | 40.0 |
| | | TH | **73.3%** `[55.5%, 85.8%]` | **73.3%** `[55.5%, 85.8%]` | 0.0% | 26.7 |
| | | TH-EN | 73.3% `[55.5%, 85.8%]` | 73.3% `[55.5%, 85.8%]` | 16.7% | 22.2 |
| | `TOOLS` | EN | 0.0% `[0.0%, 11.3%]` | 56.7% `[39.2%, 72.6%]` | 0.0% | 100.0 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 60.0% `[42.3%, 75.4%]` | 0.0% | 100.0 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 63.3% `[45.5%, 78.1%]` | 0.0% | 100.0 |
| | `ALL` | EN | 0.0% `[0.0%, 11.3%]` | 3.3% `[0.6%, 16.7%]` | 16.7% | 83.3 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 33.3% `[19.2%, 51.2%]` | 16.7% | 83.3 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 10.0% `[3.5%, 25.6%]` | 0.0% | 100.0 |
| | `SPOTLIGHT` | EN | 0.0% `[0.0%, 11.3%]` | 3.3% `[0.6%, 16.7%]` | 0.0% | 100.0 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 3.3% `[0.6%, 16.7%]` | 0.0% | 100.0 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 3.3% `[0.6%, 16.7%]` | 0.0% | 100.0 |
| **Meta Llama 3.3 70B Instruct (Free)** | `OFF` | EN | 100.0% `[88.7%, 100.0%]` | 100.0% `[88.7%, 100.0%]` | 0.0% | 0.0 |
| | | TH | 100.0% `[88.7%, 100.0%]` | 100.0% `[88.7%, 100.0%]` | 0.0% | 0.0 |
| | | TH-EN | 93.3% `[78.7%, 98.2%]` | 93.3% `[78.7%, 98.2%]` | 0.0% | 6.7 |
| | `PROMPT` | EN | 50.0% `[33.1%, 66.8%]` | 50.0% `[33.1%, 66.8%]` | 0.0% | 50.0 |
| | | TH | **83.3%** `[66.4%, 92.7%]` | **83.3%** `[66.4%, 92.7%]` | 0.0% | 16.7 |
| | | TH-EN | 70.0% `[52.1%, 83.3%]` | 70.0% `[52.1%, 83.3%]` | 0.0% | 30.0 |
| | `TOOLS` | EN | 0.0% `[0.0%, 11.3%]` | 66.7% `[48.8%, 80.8%]` | 0.0% | 100.0 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 83.3% `[66.4%, 92.7%]` | 0.0% | 100.0 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 66.7% `[48.8%, 80.8%]` | 0.0% | 100.0 |
| | `ALL` | EN | 0.0% `[0.0%, 11.3%]` | 6.7% `[1.9%, 21.3%]` | 0.0% | 100.0 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 20.0% `[9.5%, 37.3%]` | 16.7% | 83.3 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 20.0% `[9.5%, 37.3%]` | 16.7% | 83.3 |
| | `SPOTLIGHT` | EN | 0.0% `[0.0%, 11.3%]` | 0.0% `[0.0%, 11.3%]` | 0.0% | 100.0 |
| | | TH | 0.0% `[0.0%, 11.3%]` | 10.0% `[3.5%, 25.6%]` | 0.0% | 100.0 |
| | | TH-EN | 0.0% `[0.0%, 11.3%]` | 13.3% `[5.3%, 29.7%]` | 0.0% | 100.0 |

> **Key Observation**: In Tier `TOOLS`, exfiltration **Leak Rate is 0.0%** because backend database ACLs intercept out-of-scope queries. However, **Attempt Rate remains elevated at 56.7%–83.3%**, proving that prompt hardening alone does not prevent the model from attempting adversarial compliance. Only context-isolated delimiting (`SPOTLIGHT`) reduces model attempt rates to baseline.

### Table 2: Confirmatory Hypothesis H1 & Paired Cross-Lingual Deltas

Under Pre-Registered Primary Hypothesis $H_1$, we test whether Thai prompt injection vulnerability exceeds English by at least $\text{SESOI} = 10\%$ under Tier `PROMPT`:

| Model Family | Defense Tier | Mean Delta ($\Delta_{\text{TH} - \text{EN}}$) | 95% Bootstrap CI | Nominal $p$-value | FDR-Adjusted $p$-value | Decision ($H_1: \Delta > 0.10$) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Meta Llama 3.3 70B Instruct** | `PROMPT` | **+33.3%** | `[+10.0%, +56.7%]` | $p = 0.010$ | $p_{\text{adj}} = 0.100$ | **CONFIRMED ($\Delta > 0.10$)** |
| **Google Gemini 3.5 Flash Lite** | `PROMPT` | **+13.3%** | `[-10.0%, +33.3%]` | $p = 0.281$ | $p_{\text{adj}} = 1.000$ | Inconclusive ($\text{CI overlaps } 0$) |

### Reproducing Benchmark Results

Run the unified benchmark runner to reproduce all tables:

```bash
# Offline empirical simulation (zero quota consumption)
python scripts/run_multimodel_benchmark.py --mode mock

# Live execution against approved free-tier endpoints
python scripts/run_multimodel_benchmark.py --mode live
```

---

## Research Objective

While extensive safety research and benchmark datasets exist for English-language LLM interactions, evaluation methodologies specifically addressing the linguistic and syntactic nuances of the Thai language remain severely limited. Thai features distinct characteristics—such as the lack of explicit word boundary delimiters (no spaces between words), complex vowel and tone mark placement, rich honorifics, and frequent Thai-English code-switching—that introduce unique attack vectors and defense blindspots for tokenizers, safety guardrails, and system prompt policies.

The objective of **Thai Injection Eval** is to establish an open, reproducible, and scientifically grounded evaluation framework to:
1. **Systematically evaluate LLM robustness** against prompt injection attacks formulated in Thai and mixed Thai-English contexts.
2. **Measure the impact of Thai-specific linguistic evasion techniques** (e.g., zero-width space insertion, vowel/tone homoglyphs, and syllable boundary manipulation) on security guardrails.
3. **Quantify the trade-off between security hardening and utility** (benign interaction preservation) using deterministic, zero-variance evaluation criteria.

---

## Scope

To maintain scientific focus and reproducibility, this project scopes its investigation to:

- **Primary Scope**: Prompt injection vulnerabilities in **Thai-language** LLM interactions.
- **Linguistic Sub-Scopes**:
  - **Thai Native**: Pure Thai phrasing, colloquial idioms, and grammatical structures.
  - **Thai-English Code-Switching**: Sentences seamlessly mixing Thai and English terminology (standard in technical, educational, and business discourse).
- **Target Threat Categories**:
  *(To be defined alongside the standardized dataset schema)*.
- **Synthetic White-Box Environment**: All database schemas, mock credentials, and canary tokens used during evaluation are entirely synthetic to prevent real-world data exposure.

> [!NOTE]
> Multimodal safety vectors, general uncensored jailbreaking, and non-Thai multilingual safety benchmarks outside Thai and Thai-English code-switching are explicitly outside the primary scope of this framework.

---

## Methodology & Architecture

Thai Injection Eval treats security evaluation not merely as a collection of attack prompts, but as a disciplined end-to-end evaluation harness. The framework follows a strict modular pipeline:

```text
┌──────────────┐
│   Dataset    │ (Structured test cases & linguistic mutations)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Target LLM  │ (System prompt, defense wrappers & target model/agent)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Response   │ (Raw generation, tool execution logs & canary behavior)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Evaluator   │ (Deterministic rule-based judge; zero LLM judge variance)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Metrics    │ (Attack Success Rate, False Refusal Rate, Wilson 95% CIs)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Analysis   │ (Statistical hypothesis testing, McNemar paired comparison)
└──────────────┘
```

### Key Methodological Principles:
1. **Deterministic Evaluation**: Replaces subjective or probabilistic LLM-as-a-judge approaches with verifiable canaries, tool call telemetry, and deterministic regex/string boundary checks.
2. **Statistical Rigor**: All evaluated proportions are computed with 95% Wilson Score Confidence Intervals. Comparative defense effectiveness utilizes exact McNemar tests to assess statistical significance without external mathematical dependencies.
3. **Defense-in-Depth Separation**: Evaluates models across isolated defensive layers (unprotected baseline, hardened prompt policies, tool-level access controls, context spotlighting, and multilingual output DLP).

---

## Repository Structure

```text
thai-injection-eval/
├── core/                         # Core evaluation harness engine
│   ├── adapters/                 # Pluggable Target Adapters (Gemini, OpenAI, Callable)
│   ├── cli/                      # CLI application & subcommands
│   ├── defenses/                 # Defense implementations (Prompt, ACL, DLP, Spotlight)
│   └── evaluator/                # Benchmark engines, metrics & statistical tests
├── data/                         # Benchmark datasets and synthetic mock databases
│   ├── archive/                  # Archived raw benchmark datasets
│   ├── normalized/               # Canonical Draft-07 validated benchmark suites (423 cases across 8 suites)
│   ├── schema/                   # JSON Schema definitions (Draft-07)
│   ├── validation/               # Dataset validation reports
│   └── university.db             # Synthetic sandboxed educational database
├── docs/                         # Research design & architectural documentation
│   ├── architecture.md           # Defense-in-depth and security boundaries
│   ├── methodology.md            # Statistical formulas and judge specifications
│   ├── development.md            # Developer guidelines and testing standards
│   └── REFERENCES.md             # Academic literature & OWASP citations
├── tests/                        # Automated offline unit test suite (376 unittests)
├── scripts/                      # Utility scripts (seed generation, reporting helpers)
├── agent.py                      # Multi-role Red vs Blue evaluation runner
├── web_ui.py                     # Local Flask audit dashboard & interactive playground
├── pyproject.toml                # Project metadata & CLI entry points
├── requirements.txt              # Production and test dependencies
├── thai-eval.bat / thai-eval.ps1 # Fast CLI launchers for Windows
└── thai-eval                     # Fast CLI launcher for POSIX
```

---

## Current Limitations

Before reviewing or utilizing this framework, note the following architectural and empirical boundaries:
- **Controlled Educational White-Box Environment**: Indirect injection tests target a mock university relational database (`data/university.db`). Success rates reflect model behavior within this controlled educational environment and should not be extrapolated directly to arbitrary production architectures.
- **Lexical DLP Boundaries**: Regex-based DLP output guards operate on lexical patterns; results measure syntactic and verbal evasion rather than general token-space guarantees.

For full research disclosure, see [**`LIMITATIONS.md`**](LIMITATIONS.md).

---

## Roadmap

- [x] Initial project structure
- [x] Initial experimental datasets
- [x] Standardized taxonomy
- [x] Standardized dataset schema
- [x] Dataset validation
- [x] Evaluation methodology
- [x] Evaluator
- [x] Benign dataset
- [x] Test suite (376 unittests)
- [x] Reproducible benchmark
- [x] Cross-lingual & OWASP model comparison
- [x] Statistical significance analysis (Wilson CIs & McNemar)
- [x] Multi-turn Crescendo adaptive red teaming
- [x] Closed-loop Thai linguistic DLP evasion

---

## Getting Started (Development Setup)

### 1. Environment Installation

Ensure Python 3.10+ is installed:

```bash
# Clone the repository
git clone https://github.com/saharat-k/thai-injection-eval.git
cd thai-injection-eval

# Create and activate local virtual environment
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies and editable package
pip install -r requirements.txt
pip install -e .
```

### 2. Verify System Health (Zero-Cost Offline Check)

Run the built-in diagnostic doctor:

```bash
# Windows
.\thai-eval.bat doctor

# Linux / macOS
./thai-eval doctor
```

### 3. Run Offline Test Suite

Run the full automated test suite without consuming any external API quota:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

### 4. Launch Web UI Console

Start the local security audit console and interactive red-teaming playground:

```bash
python web_ui.py
# Open http://127.0.0.1:5000 in your browser
```

---

## Ethical Statement & Responsible Disclosure

This repository is created exclusively for defensive security research, academic robustness evaluation, and hardening Thai-language LLM applications against prompt injection. 
- All data records, student profiles, and national IDs in this repository are **100% synthetic mock data**.
- Security researchers and practitioners must obtain explicit authorization before evaluating third-party systems.

---

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
