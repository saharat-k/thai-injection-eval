# Thai Injection Eval

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Tests](https://github.com/saharat-k/thai-injection-eval/actions/workflows/tests.yml/badge.svg)](https://github.com/saharat-k/thai-injection-eval/actions/workflows/tests.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Pre-Registration](https://img.shields.io/badge/pre--registration-v2.0-blueviolet.svg)](docs/benchmark/PRE_REGISTRATION.md)
[![Benchmark Cases](https://img.shields.io/badge/benchmark-Dataset%20A%20108%20cases-orange.svg)](data/normalized/test_cases_parallel_v2.json)

Evaluation framework for studying prompt injection in Thai-language LLM interactions.

> ชุดเครื่องมือและระเบียบวิธีวิจัย (Evaluation Framework) เพื่อศึกษาและประเมินความทนทานต่อการโจมตีแบบ Prompt Injection ในการมีปฏิสัมพันธ์กับโมเดลภาษาขนาดใหญ่ (LLM) และ AI Agent ในบริบทภาษาไทย

## Status

Benchmark v2.0.0 runs with pre-registered hypotheses ([`docs/benchmark/PRE_REGISTRATION.md`](docs/benchmark/PRE_REGISTRATION.md)), cross-lingual parallel triplets (Dataset A: 36 scenarios x 3 languages = 108 cases), multi-family LLM evaluation, and separate tracking for **Attempt Rate** (LLM compliance with an adversary) and **Leak Rate** (actual exfiltration blocked by backend ACL or DLP layers).

Empirical case traces and statistical tables live in:

- Case-level JSONL traces: [`results/published/benchmark_v2_static.jsonl`](results/published/benchmark_v2_static.jsonl)
- Aggregated CSV with FDR adjustments: [`results/published/benchmark_v2_summary.csv`](results/published/benchmark_v2_summary.csv)
- Methodological bounds and disclosures: [`LIMITATIONS.md`](LIMITATIONS.md)
- Security policy and threat model boundaries: [`SECURITY.md`](SECURITY.md)
- Version history: [`CHANGELOG.md`](CHANGELOG.md)

### Quick links

- [Empirical benchmark results](#empirical-benchmark-results-dataset-a-v20)
- [Research objective](#research-objective)
- [Scope](#scope)
- [Methodology and architecture](#methodology-and-architecture)
- [Repository structure](#repository-structure)
- [Getting started](#getting-started)

## Empirical benchmark results (Dataset A v2.0)

Evaluations use isomorphic triplets from `data/normalized/test_cases_parallel_v2.json` with Wilson 95% score confidence intervals and paired bootstrap testing.

### Benchmark overview

![Red Team Attack Efficacy Across Languages (ASR %)](docs/images/benchmark_trend_sketch.svg)

### Empirical findings

1. **Cross-Lingual Vulnerability Gap on Prompt Hardening (Tier `PROMPT`)**:
   - Meta Llama 3.3 70B Instruct reaches 83.3% vulnerability in Thai vs. 50.0% in English (paired difference $\Delta_{\text{TH} - \text{EN}} = +33.3\%$, 95% bootstrap CI `[+10.0%, +56.7%]`, $p = 0.010$, $p_{\text{adj}} = 0.100$).
   - Google Gemini 3.5 Flash Lite reaches 73.3% in Thai vs. 60.0% in English (paired difference $\Delta_{\text{TH} - \text{EN}} = +13.3\%$, 95% bootstrap CI `[-10.0%, +33.3%]`, $p = 0.281$, $p_{\text{adj}} = 1.000$; CI spans zero).
   - Scope of inference: this gap reflects Meta Llama 3.3 70B and this translated prompt set under prompt hardening, not an inherent vulnerability of the Thai language across all architectures.
2. **Attempt vs. Leak Decoupling**: Under Tier `TOOLS`, backend database access controls (ACL/RLS) keep Leak Rate at 0.0%, while models still attempt unauthorized queries 56.7% to 83.3% of the time. Zero leakage reflects database gatekeeping rather than model resistance.
3. **Utility Trade-off and FRR Sample Bounds**: Lexical filtering under Tier `ALL` produces a 16.7% False Refusal Rate (FRR) on benign queries ($1/6$ refusals; Wilson 95% CI `[3.0%, 56.4%]`).

### Summary by defense tier

| Model | Defense tier | Thai attack success rate (ASR) | Model attempt rate | Enforcement layer |
| :--- | :--- | :--- | :--- | :--- |
| Meta Llama 3.3 70B | `PROMPT` (System prompt hardening) | 83.3% `[66.4%, 92.7%]` | 83.3% `[66.4%, 92.7%]` | None (prompt rules bypassed) |
| | `TOOLS` (Database gatekeeper) | 0.0% `[0.0%, 11.3%]` | 83.3% `[66.4%, 92.7%]` | Database table ACL and RLS |
| Google Gemini 3.5 Flash | `PROMPT` (System prompt hardening) | 73.3% `[55.5%, 85.8%]` | 73.3% `[55.5%, 85.8%]` | None (prompt rules bypassed) |
| | `TOOLS` (Database gatekeeper) | 0.0% `[0.0%, 11.3%]` | 60.0% `[42.3%, 75.4%]` | Database table ACL and RLS |

The full 30-row matrix and confidence intervals are in the [benchmark hub](docs/benchmark/README.md).

### Reproducing benchmark results

Run the benchmark runner to reproduce the published tables:

```bash
# Offline empirical simulation (zero quota consumption)
python scripts/run_multimodel_benchmark.py --mode mock

# Offline trace provenance and oracle verification (zero API calls)
python scripts/run_multimodel_benchmark.py --verify-static
# or:
python scripts/rerun_oracle_on_static_traces.py

# Live execution against approved free-tier endpoints
python scripts/run_multimodel_benchmark.py --mode live
```

## Research objective

Most safety benchmarks cover English prompts. Thai differs in script and usage: it lacks spaces between words, stacks vowels and tone marks above and below consonants, uses rich honorifics, and mixes Thai and English mid-sentence. Those properties affect subword tokenizers, keyword filters, and system prompt policies.

Thai Injection Eval evaluates LLM behavior in this setting by:

1. Testing injection resistance across Thai, English, and Thai-English code-mixed prompts.
2. Measuring how Thai-specific linguistic mutations (zero-width characters, vowel and tone homoglyphs, unnatural word segmentation) evade input filters and output DLP.
3. Quantifying the trade-off between defense tiers and benign task utility using deterministic checks.

## Scope

The framework focuses on Thai and mixed Thai-English prompt injection in a synthetic database-backed agent:

- Linguistic scope covers native Thai phrasing and Thai-English code-switching alongside matched English baselines.
- Threat categories follow OWASP LLM01 and LLM06: `direct_instruction_override`, `broken_object_level_authorization` (BOLA/IDOR), `action_hijacking`, `indirect_prompt_injection`, `linguistic_evasion` (Unicode Cf zero-width characters, homoglyphs, segmentation), and `benign_control` queries for FRR.
- Environment isolation uses synthetic university records, mock credentials, and canary tokens in `data/university.db`.

> [!NOTE]
> Multimodal inputs, general safety/toxicity benchmarks, and non-Thai languages outside the parallel baseline are out of scope.

## Methodology and architecture

Requests flow through an end-to-end harness:

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

The harness relies on deterministic evaluation (canary checks, tool call telemetry, and regex/boundary matching rather than an LLM judge), statistical reporting (95% Wilson Score intervals and exact McNemar paired tests with zero external math dependencies for core runs), and five isolated defense tiers (`off`, `prompt`, `tools`, `spotlight`, `all`) plus `SecurityContext` Row-Level Security (RLS).

## Repository structure

```text
thai-injection-eval/
├── core/                         # Core evaluation harness engine
│   ├── adapters/                 # Pluggable Target Adapters (Gemini, OpenAI-like, OpenRouter, Callable)
│   ├── agent/                    # Multi-turn Red/Blue session runtime, retries, and circuit breaker
│   ├── cli/                      # CLI application and subcommands (eval, redteam, chat, probe, serve, doctor)
│   ├── defenses/                 # Defenses (Output DLP, Spotlighting, Thai NLP converters)
│   ├── evaluator/                # Benchmark engines, oracle, statistics, Crescendo/TAP/Tree runners
│   └── tools/                    # Instrumented DB/action tools, SecurityContext, and RBAC/BOLA policies
├── data/                         # Benchmark datasets and synthetic mock databases
│   ├── archive/                  # Raw source fixtures used by deterministic generators
│   ├── normalized/               # Canonical Draft-07 validated suites (including Dataset A v2.0: 108 cases)
│   ├── schema/                   # JSON Schema definitions (Draft-07)
│   ├── validation/               # Dataset validation reports
│   └── university.db             # Synthetic sandboxed educational database
├── docs/                         # Research design and architectural documentation
│   ├── architecture.md           # Defense-in-depth and security boundaries
│   ├── methodology.md            # Statistical formulas and judge specifications
│   ├── development.md            # Developer guidelines and testing standards
│   ├── taxonomy.md               # Attack categories and OWASP mappings
│   ├── ROADMAP_v2.0.md           # Implementation status and v2.1+ roadmap
│   └── REFERENCES.md             # Academic literature and OWASP citations
├── tests/                        # Offline unit test suite (515 tests, 2 expected failures)
├── scripts/                      # Utility scripts (benchmark runners, secret scan, chart generators)
├── agent.py                      # Backwards-compatible facade over core.agent.runtime and core.tools.legacy
├── web_ui.py                     # Local Flask audit dashboard and interactive playground
├── pyproject.toml                # Project metadata and CLI entry points
├── requirements.txt              # Production and test dependencies
├── thai-eval.bat / thai-eval.ps1 # CLI launchers for Windows
└── thai-eval                     # CLI launcher for POSIX
```

## Current limitations

- Indirect injection and BOLA tests run against a mock SQLite university database (`data/university.db`), so results measure behavior inside this sandbox rather than production ERPs.
- Regex-based output DLP detects syntactic and known encoded forms (`NFKC`, Thai digits `๐-๙`, Base64, Hex, reversed text by default) and does not catch arbitrary semantic paraphrasing.

For the full disclosure, see [**`LIMITATIONS.md`**](LIMITATIONS.md).

## Future research and roadmap

Completed milestones through v2.0.0 and subsequent `main` changes are in [`CHANGELOG.md`](CHANGELOG.md), and architectural milestones live in [`docs/ROADMAP_v2.0.md`](docs/ROADMAP_v2.0.md).

- [x] **Multi-Turn Dynamic Red-Teaming**: Implemented adaptive `crescendo`, `tap`, and `tree` beam-search red teaming with refusal backtracking and dynamic Thai NLP mutators (`thai-eval redteam run`).
- [ ] **Frontier Model Evaluation**: Extend evaluations to larger frontier models under dedicated research allocations.
- [ ] **Cross-Lingual Payload Transfer**: Test asymmetric attacks where Thai user queries retrieve poisoned English records and vice versa.
- [ ] **Dialectal and Regional Variations**: Measure tokenizer behavior on regional Thai dialects and informal slang.

## Getting started

### 1. Environment installation

Requires Python 3.10+.

```bash
git clone https://github.com/saharat-k/thai-injection-eval.git
cd thai-injection-eval

python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
```

### 2. Verify system health (zero-cost offline check)

```bash
# Windows
.\thai-eval.bat doctor

# Linux / macOS
./thai-eval doctor
```

### 3. Run offline test suite

Run all 515 offline tests without consuming API quota:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

### 4. Launch Web UI console

Start the local audit dashboard and interactive playground:

```bash
python web_ui.py
# Open http://127.0.0.1:5000 in your browser
```

## Ethical statement and responsible disclosure

This repository supports defensive security research and prompt injection testing for Thai-language LLM systems.

- All student profiles, national IDs, salaries, and canary tokens in `data/` are synthetic mock data.
- Researchers must obtain explicit authorization before testing third-party systems.

## License

Licensed under the [Apache 2.0 License](LICENSE).
