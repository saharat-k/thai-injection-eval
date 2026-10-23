# Thai Prompt Injection Security Benchmark & Evaluation Harness

[![Tests](https://img.shields.io/badge/Tests-114%20Passing-brightgreen.svg)](tests/)
[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010%20for%20LLM%20(2025)-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Defense](https://img.shields.io/badge/Defense-4--Tier%20Defense--in--Depth-purple.svg)](docs/architecture.md#2-กลไกการป้องกันความปลอดภัย-4-ระดับ-4-tier-defense-in-depth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ชุดเครื่องมือและเฟรมเวิร์กมาตรฐานสำหรับทดสอบ ประเมินความมั่นคงปลอดภัย และทำ Red-Teaming โมเดลภาษาขนาดใหญ่ (LLM) ต่อภัยคุกคามด้าน **Prompt Injection** และ **Sensitive Information Disclosure** ในบริบท **ภาษาไทย ภาษาอังกฤษ และคำถามปนภาษา (Code-mixed)** พร้อมกลไกความปลอดภัยหลายชั้น (Defense-in-Depth) และตัวตัดสินแบบกฎตายตัว (Deterministic Rule-Based Judge)

> **English Executive Summary**: A standardized benchmark harness and evaluation toolkit for assessing Large Language Model (LLM) agents against **Direct/Indirect Prompt Injection (OWASP LLM01)** and **Sensitive Information Disclosure (OWASP LLM02)** across Thai, English, and code-mixed inputs. Features a balanced 3-language parallel dataset, pluggable model adapters, a 4-tier defense architecture, and a 114-test offline verification suite requiring zero API quota.

> [!IMPORTANT]
> **ข้อจำกัดและขอบเขตการแปลผล (Methodology & Scope Limitations):**
> โปรดอ่าน [**`LIMITATIONS.md`**](LIMITATIONS.md) ก่อนนำผลการทดลองไปอ้างอิง เอกสารดังกล่าวระบุข้อจำกัดของโมเดลระดับ Free-tier, ขนาดตัวอย่าง $n$, เหตุผลที่ผลลัพธ์ 0% ในโหมด `tools`/`all` เกิดจากการบล็อกเชิงโครงสร้าง (`blocked by construction`), และช่องโหว่ของตัวตรวจจับ DLP ขาออกอย่างตรงไปตรงมา

---

## 🌟 จุดเด่นของระบบ (Key Features)

* **ชุดทดสอบคู่ขนานสมดุล 3 ภาษา ([`data/test_cases_parallel.json`](data/test_cases_parallel.json))**: ควบคุมตัวแปรให้ทุกเจตนาโจมตีมีครบทั้ง **TH, EN, และ MIX** รวม 45 เคส พร้อมรายงานสถิติช่วงความเชื่อมั่น 95% แบบ Wilson Score Confidence Interval
* **สถาปัตยกรรมป้องกัน 4 ระดับ (Defense-in-Depth)**: ไล่ระดับตั้งแต่ System Prompt Policy, Tool ACL (`PUBLIC_TABLES` allowlist), Canary Honeytokens, จนถึง Multilingual Output DLP (รองรับ NFKC, ตัวเลขไทย `๐-๙`, Base64, Hex)
* **ตัวตัดสินแบบกฎตายตัว (Deterministic Rule-Based Judge)**: ตรวจจับ Canary Token และ Schema Leak โดยไม่พึ่งพา LLM-as-a-judge เพื่อขจัดความแปรปรวนเชิงสุ่ม
* **การตรวจสอบแบบออฟไลน์ 100% (Zero-Cost Verification)**: มีชุด Unit Tests 114 ข้อ พร้อมโหมด `--dry-run` และ `--dlp-audit` ที่รันได้ทันทีโดยไม่ต้องต่ออินเทอร์เน็ตและไม่เสียโควตา API
* **รองรับโมเดลหลากหลาย (Pluggable Target Adapters)**: ทดสอบได้ทั้ง Reference Agent ในตัว, OpenAI-compatible Endpoints (vLLM, Ollama, LM Studio, OpenRouter, Groq), และ Custom Python Callables

---

## ⚡ เริ่มต้นใช้งานอย่างรวดเร็ว (Quick Start)

### 1. ติดตั้งสภาพแวดล้อม (Setup)

```powershell
# 1.1 สร้าง Virtual Environment และติดตั้งไลบรารี
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# Linux / macOS: python3 -m venv .venv && ./.venv/bin/python -m pip install -r requirements.txt

# 1.2 ตั้งค่า Environment Variables
copy .env.example .env
# Linux / macOS: cp .env.example .env
# ระบุ GEMINI_API_KEY ในไฟล์ .env หากต้องการรันการประเมินผลผ่าน Live API
```

### 2. ตรวจสอบระบบแบบออฟไลน์ (Zero-Cost Offline Verification)

ยืนยันความถูกต้องของระบบด้วยชุดทดสอบ 114 รายการ (ไม่เสียค่า API และไม่ต่ออินเทอร์เน็ต):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
# Linux / macOS: ./.venv/bin/python -m unittest discover -s tests -v
```
*ผลลัพธ์ที่คาดหวัง:* `Ran 114 tests in ~9s - OK`

### 3. ประเมินจำนวน Request ล่วงหน้า (Dry-Run Benchmarking)

ตรวจสอบความถูกต้องของข้อมูลและคำนวณจำนวน API Request ที่จะเกิดขึ้นโดยไม่มีการยิง API จริง:

```powershell
.\.venv\Scripts\python.exe -m core.evaluator.cli --parallel --dry-run
# Linux / macOS: ./.venv/bin/python -m core.evaluator.cli --parallel --dry-run
```

### 4. รันการประเมินผลความปลอดภัย (Run Benchmark)

```powershell
# 4.1 รันการประเมินผลชุดทดสอบคู่ขนาน 3 ภาษา (Parallel Benchmark)
.\.venv\Scripts\python.exe -m core.evaluator.cli --parallel --defenses off,prompt,tools,all

# 4.2 รันการทดสอบเจาะจุดบอด Probing Suite (Tools & All tiers)
.\.venv\Scripts\python.exe -m core.evaluator.cli --probing

# 4.3 ตรวจสอบช่องโหว่ Output DLP แบบออฟไลน์ 100% (ROT13, URL-percent, Tilde, HTML Entities)
.\.venv\Scripts\python.exe -m core.evaluator.cli --dlp-audit
```

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
├── tests/                        # [TESTS] ชุดทดสอบออฟไลน์ 100% (114 ข้อสอบ)
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
