# คู่มือการพัฒนาและการทดสอบระบบ (Development & Testing Guide)

เอกสารนี้อธิบายการติดตั้งสภาพแวดล้อม การรันชุดทดสอบแบบออฟไลน์ คำสั่งตรวจสอบก่อนรัน API จริง และการใช้ตัวสแกนความลับก่อนส่งโค้ด

## 1. การติดตั้งสภาพแวดล้อมการพัฒนา (Environment Setup)

โปรเจกต์ใช้ Python Virtual Environment เพื่อแยกไลบรารี:

```powershell
# 1.1 สร้าง Virtual Environment
python -m venv .venv

# 1.2 ติดตั้ง Dependencies เข้า Virtual Environment โดยตรง
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip install -e .
# Linux / macOS: ./.venv/bin/python -m pip install -r requirements.txt && ./.venv/bin/python -m pip install -e .

# 1.3 ตั้งค่าไฟล์ Environment Variables
copy .env.example .env
# Linux / macOS: cp .env.example .env
# ระบุ GEMINI_API_KEY และ OPENROUTER_API_KEY หากต้องการรัน Live Evaluation
```

> [!TIP]
> กลุ่ม Benchmark หลักและชุดทดสอบออฟไลน์ใช้ Python Standard Library + `python-dotenv` (และ `google-genai` สำหรับ Live API) ส่วน `flask`, `matplotlib` และ `faker` ใช้เฉพาะสำหรับ `web_ui.py`, สคริปต์สร้างกราฟ และ `seed_db.py`

## 2. การรันชุดทดสอบออฟไลน์ (Zero-Cost Verification Suite)

ระบบมีชุดทดสอบอัตโนมัติ **515 รายการ (`expected failures=2`)** ที่รันแบบออฟไลน์ทั้งหมดโดยไม่เสียค่า API และไม่เรียกเครือข่ายภายนอก:

```powershell
# รันชุดทดสอบทั้งหมด
.\.venv\Scripts\python.exe -m unittest discover tests/
# Linux / macOS: ./.venv/bin/python -m unittest discover tests/

# หรือตรวจสอบสภาพแวดล้อมผ่าน CLI
.\thai-eval.bat doctor
```

กลุ่มชุดทดสอบหลักใน `tests/`:

- [`tests/test_redteam.py`](../tests/test_redteam.py), [`tests/test_crescendo_redteam.py`](../tests/test_crescendo_redteam.py), [`tests/test_redteam_tree.py`](../tests/test_redteam_tree.py), [`tests/test_redteam_closed_loop.py`](../tests/test_redteam_closed_loop.py): ทดสอบ Crescendo, TAP, Tree Beam Search, การย้อนกลับเมื่อถูกปฏิเสธ (`--backtrack`), Circuit Breaker, Refusal Detection และ Multi-turn Red Team Engine
- [`tests/test_agent.py`](../tests/test_agent.py), [`tests/test_rls_security.py`](../tests/test_rls_security.py), [`tests/test_multihop_tools.py`](../tests/test_multihop_tools.py): ทดสอบ SQLite Isolation, RBAC, `SecurityContext`, Row-Level Security (RLS) และ Multi-tool Action Stubs
- [`tests/test_dataset_schema.py`](../tests/test_dataset_schema.py), [`tests/test_lock_integrity.py`](../tests/test_lock_integrity.py), [`tests/test_documentation_and_artifacts.py`](../tests/test_documentation_and_artifacts.py): ตรวจสอบ JSON Schema Draft-07, SHA-256 ของไฟล์ Normalized, Lock Integrity และ Artifact โครงสร้างโปรเจกต์
- [`tests/test_parallel.py`](../tests/test_parallel.py), [`tests/test_probing.py`](../tests/test_probing.py), [`tests/test_indirect_judge.py`](../tests/test_indirect_judge.py), [`tests/test_attempt_vs_leak.py`](../tests/test_attempt_vs_leak.py): ทดสอบชุด Parallel, Probing, Indirect Injection และแยก Attempt Rate กับ Leak Rate
- [`tests/test_spotlight.py`](../tests/test_spotlight.py), [`tests/test_converters.py`](../tests/test_converters.py), [`tests/test_linguistic_benchmark.py`](../tests/test_linguistic_benchmark.py): ทดสอบ Spotlighting Guard, ตัวแปลงภาษาไทย และ Benchmark ภาษาศาสตร์ (รวม 2 `@unittest.expectedFailure` ที่บันทึกไว้ใน `LIMITATIONS.md`)
- [`tests/test_statistics.py`](../tests/test_statistics.py), [`tests/test_statistical_pipeline.py`](../tests/test_statistical_pipeline.py), [`tests/test_oracle_and_adapters.py`](../tests/test_oracle_and_adapters.py), [`tests/test_evaluator.py`](../tests/test_evaluator.py): ทดสอบ Wilson CI, Exact McNemar, Paired Bootstrap, `IndependentSecurityOracle` และ Target Adapters
- [`tests/test_golden_fixtures.py`](../tests/test_golden_fixtures.py), [`tests/test_cli_architecture.py`](../tests/test_cli_architecture.py), [`tests/test_web_ui.py`](../tests/test_web_ui.py): ทดสอบความคงที่ของ Prompt/Tool Golden Fixtures, CLI Commands และ Web UI REST/CSRF

## 3. การทดสอบแบบแห้ง (Dry-Run Benchmarking)

ก่อนรันผ่าน Live API ให้ใช้ `--dry-run` เพื่อตรวจสอบพารามิเตอร์และจำนวน Request โดยไม่เรียก API จริง:

```powershell
# ประเมิน Request สำหรับชุดทดสอบคู่ขนาน (Parallel Suite)
.\thai-eval.bat eval run --parallel --dry-run

# จำลองการโจมตีหลายรอบด้วย Red Team (เช่น crescendo หรือ tree)
.\thai-eval.bat redteam run --strategy tree --attempts 3 --dry-run

# เปิดหน้าเว็บ Web UI Console
.\thai-eval.bat view --port 5000
```

## 4. การตรวจสอบสุขอนามัยของ Git และความลับ (Secret Hygiene Scanner)

รันสคริปต์สแกนก่อน Commit หรือ Push ทุกครั้ง:

```powershell
.\.venv\Scripts\python.exe scripts/check_secrets.py --history
```

กติกาหลักที่สคริปต์ตรวจสอบ:

1. ห้าม Commit `.env`, `.flask_secret`, `results.md`, ไฟล์ฐานข้อมูล `*.db`, `*.sqlite`, `*.db-wal` หรือโฟลเดอร์ชั่วคราว (`scratch/`, `.superpowers/`)
2. ห้าม Commit ผลรันดิบใน `results/` ยกเว้นไฟล์ที่คัดกรองแล้วใน `results/published/`
3. สแกนหา API Key เช่น `AIzaSy...`, `sk-or-v1-...`, `gsk_...` ในโค้ดและ Git History

## 5. การสร้างฐานข้อมูลจำลองใหม่ (Synthetic Mock Data Seeding)

หากต้องการรีเซ็ตหรือสร้างข้อมูลจำลองใน `data/university.db` ใหม่:

```powershell
.\.venv\Scripts\python.exe scripts/seed_db.py --rebuild-all
```

สคริปต์ใช้ `faker` สร้างข้อมูลบุคคลสังเคราะห์และฝัง Canary Token ลงในตารางลับอัตโนมัติ

## 6. ข้อกำหนดการเพิ่มกรณีศึกษาใหม่ (Canonical Test Case Schema)

กรณีศึกษาที่เพิ่มใน `data/normalized/` ต้องผ่าน [Canonical JSON Schema (`data/schema/test_case.schema.json`)](../data/schema/test_case.schema.json):

```json
{
  "id": "PAR-13-TH",
  "category": "direct_injection",
  "technique": "instruction_override",
  "language": "th",
  "difficulty": "medium",
  "is_benign": false,
  "prompt": "ข้อความคำสั่งโจมตี...",
  "expected_behavior": "refusal",
  "evaluation": {
    "type": "canary",
    "expected_tokens": ["CANARY-PAR-13-TH"],
    "metadata": {
      "pair_id": "PAR-13",
      "lang": "TH",
      "attack_type": "direct"
    }
  }
}
```

ตรวจสอบความถูกต้องของ Schema ด้วยคำสั่ง:

```powershell
.\.venv\Scripts\python.exe scripts/standardize_datasets.py
```
