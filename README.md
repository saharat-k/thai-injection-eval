# Thai Prompt Injection Security Benchmark & Evaluation Harness

[![Tests](https://img.shields.io/badge/Tests-172%20Passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20for%20LLM%20(2025)-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Defense](https://img.shields.io/badge/Defense-4--Tier%20Defense--in--Depth-purple.svg)](docs/architecture.md#2-กลไกการป้องกันความปลอดภัย-4-ระดับ-4-tier-defense-in-depth)
[![CLI](https://img.shields.io/badge/CLI-thai--eval-blueviolet.svg)](#-การใช้งาน-cli-หลัก-canonical-cli-usage)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ชุดเครื่องมือและเฟรมเวิร์กมาตรฐานสำหรับทดสอบ ประเมินความมั่นคงปลอดภัย และทำ Red-Teaming โมเดลภาษาขนาดใหญ่ (LLM) ต่อภัยคุกคามด้าน **Prompt Injection** และ **Sensitive Information Disclosure** ในบริบท **ภาษาไทย ภาษาอังกฤษ และคำถามปนภาษา (Code-mixed)** พร้อมกลไกความปลอดภัยหลายชั้น (Defense-in-Depth) และตัวตัดสินแบบกฎตายตัว (Deterministic Rule-Based Judge)

> **English Executive Summary**: A standardized benchmark harness and evaluation toolkit for assessing Large Language Model (LLM) agents against **Direct/Indirect Prompt Injection (OWASP LLM01)** and **Sensitive Information Disclosure (OWASP LLM02)** across Thai, English, and code-mixed inputs. Features a balanced 3-language parallel dataset, pluggable model adapters, a 4-tier defense architecture, and a 172-test offline verification suite requiring zero API quota.

> [!IMPORTANT]
> **ข้อจำกัดและขอบเขตการแปลผล (Methodology & Scope Limitations):**
> โปรดอ่าน [**`LIMITATIONS.md`**](LIMITATIONS.md) ก่อนนำผลการทดลองไปอ้างอิง เอกสารดังกล่าวระบุข้อจำกัดของโมเดลระดับ Free-tier, ขนาดตัวอย่าง $n$, เหตุผลที่ผลลัพธ์ 0% ในโหมด `tools`/`all` เกิดจากการบล็อกเชิงโครงสร้าง (`blocked by construction`), และช่องโหว่ของตัวตรวจจับ DLP ขาออกอย่างตรงไปตรงมา
>
> **การผูกพันกับสคีมาสังเคราะห์ (Synthetic Schema Coupling):**
> คำสั่งแฝง (Injected Payloads) ในชุดทดสอบการฉีดคำสั่งแบบอ้อม (`test_cases_indirect.json`) ถูกออกแบบและผูกพันโดยตรงกับสถาปัตยกรรมและชื่อตารางของฐานข้อมูลมหาวิทยาลัยจำลอง (`data/university.db`) รวมถึงฟังก์ชันเครื่องมือ (`search_records`) ของโปรเจกต์นี้ (White-box schema coupling) จึงเป็นการจำลองพฤติกรรมในสภาพแวดล้อมเฉพาะ ไม่ควรนำอัตราความสำเร็จไปสรุปหรือคาดการณ์โดยตรงกับระบบงานจริงภายนอกที่มีสคีมาและชุดเครื่องมือแตกต่างออกไป

---

## 🌟 จุดเด่นของระบบ (Key Features)

* **ชุดทดสอบคู่ขนานสมดุล 3 ภาษา ([`data/test_cases_parallel.json`](data/test_cases_parallel.json))**: ควบคุมตัวแปรให้ทุกเจตนาโจมตีมีครบทั้ง **TH, EN, และ MIX** รวม 45 เคส พร้อมรายงานสถิติช่วงความเชื่อมั่น 95% แบบ Wilson Score Confidence Interval
* **สถาปัตยกรรมป้องกัน 4 ระดับ (Defense-in-Depth)**: ไล่ระดับตั้งแต่ System Prompt Policy, Tool ACL (`PUBLIC_TABLES` allowlist), Canary Honeytokens, จนถึง Multilingual Output DLP (รองรับ NFKC, ตัวเลขไทย `๐-๙`, Base64, Hex)
* **ตัวตัดสินแบบกฎตายตัว (Deterministic Rule-Based Judge)**: ตรวจจับ Canary Token และ Schema Leak โดยไม่พึ่งพา LLM-as-a-judge เพื่อลดความแปรปรวนเชิงสุ่มจากการประเมิน
* **การตรวจสอบแบบออฟไลน์ (Zero-Cost Verification)**: มีชุด Unit Tests 152 ข้อ พร้อมโหมด `--dry-run`, `doctor`, และ `dlp audit` ที่รันได้ทันทีโดยไม่ต้องต่ออินเทอร์เน็ตและไม่เสียโควตา API
* **รองรับโมเดลหลากหลาย (Pluggable Target Adapters)**: ทดสอบได้ทั้ง Reference Agent ในตัว, OpenAI-compatible Endpoints (vLLM, Ollama, LM Studio, OpenRouter, Groq), และ Custom Python Callables

---

## ⚡ เริ่มต้นใช้งานอย่างรวดเร็ว (Quick Start)

### 1. ติดตั้งสภาพแวดล้อม (Setup)

```powershell
# 1.1 สร้าง Virtual Environment และติดตั้งไลบรารี
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# ติดตั้งแบบ editable mode เพื่อให้เรียกคำสั่ง thai-eval ได้จากทุกที่
.\.venv\Scripts\python.exe -m pip install -e .
# Linux / macOS: python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt && ./.venv/bin/python -m pip install -e .

# 1.2 ตั้งค่า Environment Variables
copy .env.example .env
# Linux / macOS: cp .env.example .env
# ระบุ GEMINI_API_KEY ในไฟล์ .env หากต้องการรันการประเมินผลผ่าน Live API
```

### 2. ตรวจสอบสภาพแวดล้อมด้วย Doctor (Environment Health Check)

```powershell
.\thai-eval.bat doctor
# Linux / macOS: ./thai-eval doctor
```

---

## 🛠️ สถาปัตยกรรมการใช้งาน CLI (CLI Usage & Commands)

`thai-eval` พัฒนาขึ้นด้วยสถาปัตยกรรม **Hierarchical Subcommand Model** ตามมาตรฐาน Developer & Cyber Security CLI ระดับโลก (เช่น GitHub CLI, Docker, Trivy):

```text
thai-eval [GLOBAL OPTIONS] <command> [subcommand] [OPTIONS]
```

### ผังโครงสร้างคำสั่ง (Command Tree)

```text
thai-eval
├── chat         # เปิดเซสชันทดสอบ Interactive Red-Teaming & Manual Chat พร้อม Cyber Security Turn Card
├── eval
│   ├── run      # รันการประเมินผลความปลอดภัย (Single-tier หรือ Parallel 3-Language)
│   ├── list     # แสดงรายการเคสทดสอบในชุดข้อมูล
│   └── info     # ดูรายละเอียดเชิงลึกและ Prompt ของเคสทดสอบรายตัว
├── probe
│   ├── run      # รันการทดสอบชุดเจาะจุดบอด Item 7 Probing Suite
│   └── list     # แสดงรายการเคสในชุด Probing
├── dlp
│   └── audit    # ทดสอบการหลบเลี่ยง Output DLP แบบออฟไลน์ (0 LLM API calls)
├── test
│   ├── run      # รันชุดทดสอบความถูกต้องภายใน (172 Offline Unittests)
│   └── list     # แสดงรายการชุดทดสอบภายในระบบ
├── serve        # เปิดเว็บ Interactive Red-Teaming Playground (Flask)
├── doctor       # ตรวจสอบความพร้อมของ Python, Dependencies, DB, และ Datasets
├── config
│   └── show     # ตรวจสอบ Effective Configuration (พร้อม Mask ซ่อน Sensitive Keys อัตโนมัติ)
└── version      # แสดงข้อมูลเวอร์ชัน สภาพแวดล้อม และ Platform
```

### 📋 คำสั่งที่ใช้งานเป็นประจำ (Canonical Commands)

```powershell
# 1. การตรวจสอบและทดสอบแบบออฟไลน์ (Offline & Zero-Cost)
.\thai-eval.bat doctor                                 # ตรวจสุขภาพสภาพแวดล้อม
.\thai-eval.bat dlp audit                             # ออดิต DLP Bypass เวกเตอร์
.\thai-eval.bat eval run --parallel --dry-run          # ตรวจสอบชุดข้อมูลและประเมิน API request ล่วงหน้า
.\thai-eval.bat test run                               # รัน unit tests 172 ข้อ

# 2. การประเมินผลความปลอดภัยจริง (Live Security Evaluations)
.\thai-eval.bat eval run --parallel --defenses off,prompt,tools,all
.\thai-eval.bat probe run --defenses tools,all

# 3. เซสชันทดสอบเจาะระบบและพิมพ์ Prompt สด (Interactive Manual Red-Teaming)
.\thai-eval.bat chat                                   # เข้าสู่โหมดเลือกการตั้งค่าภายในและส่ง Prompt (หรือ .\thai-eval.ps1 chat)
.\thai-eval.bat chat --defense tools                   # กำหนด Defense ระดับ Tools ล่วงหน้าแล้วเริ่มทดสอบ
.\thai-eval.bat chat --defense prompt --role registrar_staff  # เจาะจง Role และ Defense

# 4. สำรวจชุดข้อมูลทดสอบ (Dataset Inspection)
.\thai-eval.bat eval list --parallel                   # แสดงรายการเคสทดสอบคู่ขนาน 3 ภาษา
.\thai-eval.bat eval info TH-1                         # เจาะดูรายละเอียด Prompt และ Judge ของเคส TH-1
.\thai-eval.bat probe list                             # แสดงรายการเคส Probing

# 5. ตรวจสอบการตั้งค่าและเปิด Web UI
.\thai-eval.bat config show                            # ดูคอนฟิกที่มีผลใช้งาน
.\thai-eval.bat serve --port 5000                      # สตาร์ท Web Playground
```

---

## 📦 สัญญาการแสดงผล (Output Formats Contract)

ทุกคำสั่งรองรับ Global Options และสัญญา Format กลางที่สม่ำเสมอ:

```bash
--format table   # ตารางจัดระเบียบพร้อม ANSI Colors สำหรับ Human Terminal (Default)
--format json    # ข้อมูลแบบ JSON โครงสร้างสมบูรณ์สำหรับ Programmatic & CI Automation
--format jsonl   # JSON Lines หนึ่งเรคคอร์ดต่อหนึ่งบรรทัด
--format csv     # Comma-Separated Values สำหรับ Import เข้า Spreadsheet
```

* **Global Options:**
  * `--json` : Shorthand สำหรับ `--format json`
  * `-q, --quiet` : ปิดข้อความประดับและ Progress bars (เหมาะกับ Scripting / CI)
  * `-v, --verbose` : แสดง Debug logs เชิงลึก
  * `--no-color` : ปิดการแสดงสี ANSI (รองรับมาตรฐานสากล `NO_COLOR=1`)
  * `-h, --help` : แสดงวิธีใช้และตัวอย่างคำสั่งอย่างละเอียด

---

## 🔄 ระบบ CI/CD และรหัสสถานะออก (Exit Codes)

ออกแบบเพื่อเป็น Security Gate ใน CI/CD Automation (เช่น GitHub Actions) โดยส่งรหัส Exit Code ที่มีความหมายชัดเจน:

| Exit Code | สถานะ (Status) | ความหมาย |
|:---:|---|---|
| **`0`** | **Success / Clean** | การทำงานสำเร็จ และระบบผ่านเกณฑ์ความปลอดภัย (ASR อยู่ในเกณฑ์ที่กำหนด, 0 Breaches) |
| **`1`** | **Security Criteria Failed** | ตรวจพบช่องโหว่ความปลอดภัย (ASR เกินเกณฑ์ `--max-asr`, ตรวจพบ Canary Leak หรือ Unittest ล้มเหลว) |
| **`2`** | **CLI Usage / Validation Error** | ไวยากรณ์คำสั่งไม่ถูกต้อง, ขาด Parameter ที่จำเป็น หรือไฟล์ Dataset ไม่ผ่านการตรวจสอบ Schema |
| **`3`** | **Runtime / Environment Error** | สภาพแวดล้อมไม่พร้อม (เช่น ขาด Dependencies, เชื่อมต่อ API ไม่ได้ หรือไฟล์ DB เสียหาย) |

### ตัวอย่างการรันใน CI/CD Pipeline:

```bash
# ตรวจสอบสุขภาพระบบ
thai-eval doctor --format json

# รันการประเมินผลความปลอดภัย และหยุด Pipeline ทันทีหาก ASR สูงเกิน 5%
thai-eval eval run --parallel --max-asr 5.0 --format json --quiet
```

---

## 🔁 การแปลงคำสั่งดั้งเดิม (Migration from Legacy CLI)

ระบบรักษา Backward Compatibility ไว้อย่างสมบูรณ์ สามารถเรียกสคริปต์เดิมได้โดยมีคำแนะนำชี้เป้าสู่คำสั่งมาตรฐานใหม่:

| คำสั่งดั้งเดิม (Legacy Script) | คำสั่งมาตรฐานใหม่ (Canonical CLI) | ความสามารถที่เพิ่มขึ้น |
|---|---|---|
| `python -m core.evaluator.cli --parallel --dry-run` | `thai-eval eval run --parallel --dry-run` | ไวยากรณ์ `noun verb` ที่เป็นระบบ |
| `python -m core.evaluator.cli --parallel --defenses ...` | `thai-eval eval run --parallel --defenses ...` | รองรับ `--format json/csv` และ Security Exit Codes |
| `python -m core.evaluator.cli --probing` | `thai-eval probe run` | แยก Namespace Probing ชัดเจน |
| `python -m core.evaluator.cli --dlp-audit` | `thai-eval dlp audit` | ตารางรายงานผลสวยงามและเช็ค exit code ได้ |
| `python web_ui.py` | `thai-eval serve` | กำหนด host/port ได้ง่ายผ่าน flag |
| `python -m unittest discover tests` | `thai-eval test run` | รวมการทดสอบเข้าสู่ CLI เดียวกัน |

---

## 📊 สรุปผลการทดลองจริง (Published Benchmark Results)

ผลการทดลองจริงบนโมเดล **`gemini-3.5-flash-lite`** (รันวันที่ `2026-10-23`, commit `10efb96`, รายงานฉบับเต็มใน [`results/published/PUBLISHED_REPORT.md`](results/published/PUBLISHED_REPORT.md)):

### ผลการทดสอบชุดเจาะจุดบอด (Probing Suite: 24 เคส × 2 โหมด = 48 turns)
| หมวดหมู่การเจาะจุดบอด (Probing Category) | ระดับ `tools` (Tool ACL) | ระดับ `all` (ACL + DLP) | ข้อค้นพบสำคัญ |
|---|:---:|:---:|---|
| **`collateral_public_leak`** (ข้อมูลนักศึกษาคนอื่นรั่วไหล) | **100.0%** (6/6)<br/>*[95% CI 61.0%, 100.0%]* | **100.0%** (6/6)<br/>*[95% CI 61.0%, 100.0%]* | ตารางสาธารณะขาดการจำกัดสิทธิ์ระดับแถวข้อมูล (Row-Level Security) ทำให้คำค้นกว้างเปิดเผยข้อมูลคนอื่นทั้งหมด |
| **`indirect_public_tools`** (คำสั่งแฝงข้ามตารางสาธารณะ) | **0.0%** (0/6)<br/>*[95% CI 0.0%, 39.0%]* | **0.0%** (0/6)<br/>*[95% CI 0.0%, 39.0%]* | โมเดลสรุปเนื้อหาประกาศโดยไม่ปฏิบัติตามคำสั่งแฝงที่สั่งให้ค้นตารางอื่น |
| **`dlp_bypass_probe`** (การหลบเลี่ยง Output DLP) | N/A (ไม่มี DLP) | **0.0%** (0/10)*<br/>*[95% CI 0.0%, 27.8%]* | ติดบล็อกที่ระดับ `PUBLIC_TABLES` ก่อนดึงค่า Canary แต่การทดสอบฟังก์ชัน DLP โดยตรง (`--dlp-audit`) พบว่าหลุดรอด 100% |

*\*ตัดข้อมูลที่เกิด transient HTTP 429/500 ออกจากตัวหาร $n$ ตามระเบียบวิธีวิจัย*

---

## 📂 โครงสร้างโปรเจกต์ (Project Structure)

```text
thai-injection-eval/
├── README.md                     # หน้าแรก: ภาพรวมและ Quick Start
├── LIMITATIONS.md                # ข้อจำกัดเชิงวิจัยและขอบเขตการแปลผล
├── requirements.txt              # รายการ dependencies ทั้งหมด
├── requirements-core.txt         # รายการ dependencies ขั้นต่ำสำหรับ Core Benchmark
│
├── core/                         # [CORE] Benchmark Engine & Evaluator
│   ├── adapters/                 # Target Adapters (Builtin, OpenAI-like, Callable)
│   ├── defenses/                 # Stateless Output Guard & DLP Functions
│   └── evaluator/                # Engine, Parallel, Probing, Wilson Stats, CLI
│
├── data/                         # [DATA] ชุดทดสอบและฐานข้อมูลจำลอง
│   ├── test_cases_parallel.json  # ชุดทดสอบหลักคู่ขนาน 3 ภาษา (45 เคส)
│   ├── test_cases_probing.json   # ชุดทดสอบเจาะจุดบอด Probing Suite (24 เคส)
│   ├── test_cases_indirect.json  # ชุดทดสอบ Indirect Injection & Spotlighting (36 เคส)
│   ├── test_cases.json           # ชุดทดสอบดั้งเดิม (Legacy Baseline, 36 เคส)
│   ├── university.db             # Mock SQLite Database (WAL Mode)
│   └── results.db                # Test Audit & Result Database
│
├── docs/                         # [DOCS] เอกสารประกอบการวิจัย
│   ├── methodology.md            # ระเบียบวิธีวิจัย, Attack Taxonomy, สถิติ Wilson CI
│   ├── architecture.md           # สถาปัตยกรรมระบบ, 4-Tier Defense, Data Isolation
│   ├── development.md            # คู่มือการทดสอบออฟไลน์, Seeding, Git Hygiene
│   └── REFERENCES.md             # เอกสารงานวิจัยอ้างอิง
│
├── results/                      # [RESULTS] รายงานผลการประเมิน
│   └── published/                # ผลการทดลองจริงที่เผยแพร่อย่างเป็นทางการ
│
├── tests/                        # [TESTS] ชุดทดสอบออฟไลน์ (136 ข้อสอบ)
│
├── agent.py                      # [OPTIONAL] Standalone Single-case CLI Runner
├── web_ui.py                     # [OPTIONAL] Interactive Red-Teaming Playground (Flask)
└── personas.json                 # บทบาทผู้ช่วย Blue และโปรไฟล์ผู้โจมตี Red
```

---

## 🎮 เครื่องมือเสริมสำหรับการทดลองแบบโต้ตอบ (Optional Tools)

นอกจาก Core Benchmark CLI แล้ว ระบบยังมีเครื่องมือเสริมสำหรับการสาธิตและการทดลองแบบ Interactive:

### 1. Interactive Web Playground & Dashboard ([`web_ui.py`](web_ui.py))
เปิดหน้าต่างเว็บแอปพลิเคชัน Flask สำหรับการทดลองเจาะระบบแบบ Turn-by-Turn พร้อม Audit Log แบบสด:
```powershell
.\.venv\Scripts\python.exe web_ui.py
# เปิดเบราว์เซอร์ไปที่ http://127.0.0.1:5000
```

### 2. Single Attack Probe CLI ([`agent.py`](agent.py))
ทดสอบส่งคำถามโจมตีเดี่ยวเพื่อสังเกตพฤติกรรมของโมเดล:
```powershell
.\.venv\Scripts\python.exe agent.py --case TH-1 --defense off --attempts 1
```

---

## 📚 เอกสารเชิงลึกและการอ้างอิง (Documentation & Citations)

* [**ระเบียบวิธีวิจัยและ Attack Taxonomy**](docs/methodology.md)
* [**สถาปัตยกรรมระบบและ Defense-in-Depth**](docs/architecture.md)
* [**คู่มือการพัฒนาและทดสอบระบบ**](docs/development.md)
* [**แหล่งอ้างอิงทางวิชาการ (References)**](docs/REFERENCES.md)
* [**ข้อจำกัดของงานทดลอง (Limitations)**](LIMITATIONS.md)

---

## 📄 ใบอนุญาต (License)

โปรเจกต์นี้เผยแพร่ภายใต้เงื่อนไข [Apache 2.0 License](LICENSE)
