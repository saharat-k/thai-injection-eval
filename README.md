# Thai Injection Eval
───────────────────

Evaluation framework for studying prompt injection robustness in Thai-language LLM interactions.

> ชุดเครื่องมือและระเบียบวิธีวิจัย (Evaluation Framework) เพื่อศึกษาและประเมินความทนทานต่อการโจมตีแบบ Prompt Injection ในการมีปฏิสัมพันธ์กับโมเดลภาษาขนาดใหญ่ (LLM) และ AI Agent ในบริบทภาษาไทย

---

## Status

🚧 **Research / Development**

The evaluation framework is currently under development. Benchmark experiments have not yet been conducted.

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
│   ├── test_cases.json           # Baseline benchmark suite
│   ├── test_cases_parallel.json  # 3-Language parallel test cases (TH, EN, MIX)
│   ├── test_cases_linguistic.json# Thai linguistic mutation test suite
│   ├── test_cases_probing.json   # Architectural probing cases
│   ├── test_cases_indirect.json  # Indirect injection test suite
│   └── university.db             # Synthetic sandboxed educational database
├── docs/                         # Research design & architectural documentation
│   ├── architecture.md           # Defense-in-depth and security boundaries
│   ├── methodology.md            # Statistical formulas and judge specifications
│   ├── development.md            # Developer guidelines and testing standards
│   └── REFERENCES.md             # Academic literature & OWASP citations
├── tests/                        # Automated offline unit test suite (193 unittests)
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
- **No Conducted Benchmark Experiments Yet**: As indicated by the project status, empirical benchmark experiments across public models have not yet been conducted. Any preliminary local artifacts are experimental only.
- **Sandboxed Synthetic Schema**: Indirect injection tests target a mock university relational database (`data/university.db`). Success rates reflect model behavior within this controlled educational white-box environment and should not be extrapolated directly to arbitrary production architectures.
- **Offline-First Defense Evaluation**: Some defense components (e.g., regex DLP) operate on lexical boundaries; evasion results reflect specific pattern matching rather than general token-space guarantees.

For full research disclosure, see [**`LIMITATIONS.md`**](LIMITATIONS.md).

---

## Roadmap

- [x] Initial project structure
- [x] Initial experimental datasets
- [ ] Standardized taxonomy
- [ ] Standardized dataset schema
- [ ] Dataset validation
- [ ] Evaluation methodology
- [ ] Evaluator
- [ ] Benign dataset
- [ ] Test suite
- [ ] Reproducible benchmark
- [ ] Model comparison
- [ ] Analysis

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

---

## Ethical Statement & Responsible Disclosure

This repository is created exclusively for defensive security research, academic robustness evaluation, and hardening Thai-language LLM applications against prompt injection. 
- All data records, student profiles, and national IDs in this repository are **100% synthetic mock data**.
- Security researchers and practitioners must obtain explicit authorization before evaluating third-party systems.

---

## License

This project is licensed under the [Apache 2.0 License](LICENSE).
