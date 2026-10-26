# คู่มือการพัฒนาและการทดสอบระบบ (Development & Testing Guide)

เอกสารฉบับนี้อธิบายแนวทางปฏิบัติด้านวิศวกรรมซอฟต์แวร์ ขั้นตอนการติดตั้งสภาพแวดล้อมสำหรับการพัฒนา การรันชุดทดสอบความปลอดภัยแบบออฟไลน์ และการตรวจสอบสุขอนามัยของ Git ก่อนส่งมอบโค้ด

---

## 1. การติดตั้งสภาพแวดล้อมการพัฒนา (Environment Setup)

โปรเจกต์นี้ใช้ Python Virtual Environment เพื่อแยกไลบรารีอย่างเคร่งครัด:

```powershell
# 1.1 สร้าง Virtual Environment
python -m venv .venv

# 1.2 ติดตั้ง Dependencies ทั้งหมดเข้า Virtual Environment โดยตรง
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
# Linux / macOS: ./.venv/bin/python -m pip install -r requirements.txt

# 1.3 ตั้งค่าไฟล์ Environment Variables
copy .env.example .env
# Linux / macOS: cp .env.example .env
# ระบุ GEMINI_API_KEY ในกรณีที่ต้องการรัน Live Evaluation
```

> [!TIP]
> **การแยก Dependencies ตามลักษณะการใช้งาน:**
> - **Core Benchmark & Offline Suite**: ใช้เพียง Python Standard Library + `python-dotenv` (และ `google-genai` เมื่อรัน Live API)
> - **Optional Features**: `flask` (สำหรับ `web_ui.py`), `matplotlib` (สำหรับสร้างกราฟใน `make_report.py`), และ `faker` (สำหรับสร้างข้อมูลจำลองใน `seed_db.py`)

---

## 2. การรันชุดทดสอบออฟไลน์ (Zero-Cost Verification Suite)

ระบบมีชุดทดสอบอัตโนมัติ **136 รายการ** ที่ออกแบบให้รันแบบออฟไลน์ ไม่เสียค่า API ไม่ต้องใช้อินเทอร์เน็ต และไม่มีการส่งข้อมูลออกภายนอก:

```powershell
# รันชุดทดสอบทั้งหมด
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
# Linux / macOS: ./.venv/bin/python -m unittest discover -s tests -v
```

### โครงสร้างชุดทดสอบใน `tests/`:
* [`tests/test_parallel.py`](../tests/test_parallel.py): ทดสอบความสมดุลของชุดทดสอบคู่ขนาน 3 ภาษา, ตัวตัดสินแบบกฎตายตัว (Rule-based Judge), และการคำนวณ Wilson Confidence Interval
* [`tests/test_probing.py`](../tests/test_probing.py): ทดสอบชุดเจาะจุดบอด Probing Suite, การ Audit กลไกถอดรหัส DLP ขาออก (ROT13, URL-percent, Tilde, HTML entities)
* [`tests/test_indirect_judge.py`](../tests/test_indirect_judge.py): ทดสอบตัวตัดสิน Rule-based Judge สำหรับ Indirect Injection (Manipulation, Disclosure, Benign Validation, Benchmark Lock Verification)
* [`tests/test_spotlight.py`](../tests/test_spotlight.py): ทดสอบกลไก Spotlighting Guard (Delimiters, Data Framing, Collision Neutralization, Tool Ceiling)
* [`tests/test_statistics.py`](../tests/test_statistics.py): ทดสอบสถิติแบบจับคู่ Exact McNemar Test (`binomtest`), Newcombe Paired CI, และ Majority-vote Aggregation
* [`tests/test_evaluator.py`](../tests/test_evaluator.py): ทดสอบ Target Adapters (Builtin, OpenAI-like), การคำนวณเมทริกซ์ ASR/FRR, และการสร้างรายงาน
* [`tests/test_agent.py`](../tests/test_agent.py): ทดสอบการแยกฐานข้อมูล SQLite, การควบคุมสิทธิ์ตามบทบาท (RBAC), และตัวตรวจจับ Canary Tokens
* [`tests/test_web_ui.py`](../tests/test_web_ui.py): ทดสอบ REST API, ความปลอดภัย CSRF, และการเชื่อมต่อฐานข้อมูลแบบมัลติเธรด

---

## 3. การทดสอบแบบแห้ง (Dry-Run Benchmarking)

ก่อนสั่งรันการประเมินผลผ่าน Live API ทุกครั้ง ให้ใช้ตัวเลือก `--dry-run` เพื่อตรวจสอบความถูกต้องของพารามิเตอร์และประเมินจำนวน API requests ที่จะเกิดขึ้น โดยไม่มีการเรียก API จริง:

```powershell
# ประเมิน Request สำหรับชุดทดสอบคู่ขนาน (Parallel Suite)
.\.venv\Scripts\python.exe -m core.evaluator.cli --parallel --dry-run

# ประเมิน Request สำหรับชุดเจาะจุดบอด (Probing Suite)
.\.venv\Scripts\python.exe -m core.evaluator.cli --probing --dry-run
```

---

## 4. การตรวจสอบสุขอนามัยของ Git และความลับ (Secret Hygiene Scanner)

โปรเจกต์มีสคริปต์ตรวจสอบความปลอดภัยก่อน Commit/Push เพื่อป้องกันไม่ให้ข้อมูลความลับหรือไฟล์จำลองรั่วไหลเข้าสู่ Git:

```powershell
.\.venv\Scripts\python.exe scripts/check_secrets.py
```

### กฎการตรวจสอบ (Safety Rules):
1. **ห้าม Commit ไฟล์ต้องห้าม**: `.env`, `.flask_secret`, `results.md`, หรือไฟล์ฐานข้อมูล `*.db`, `*.sqlite`, `*.db-wal`
2. **ห้าม Commit ผลการทดสอบดิบ**: ไม่อนุญาตให้นำไฟล์ใน `results/` ออกสู่สาธารณะ เว้นแต่ไฟล์สรุปที่ผ่านการกรองข้อมูลแล้วใน `results/published/`
3. **ตรวจสอบรูปแบบ API Key**: สแกนหา Token หรือ Key เช่น `AIzaSy...`, `sk-or-v1-...`, `gsk_...` ในโค้ดและ Git History ทั้งหมด

---

## 5. การสร้างฐานข้อมูลจำลองใหม่ (Synthetic Mock Data Seeding)

หากต้องการรีเซ็ตหรือสุ่มสร้างข้อมูลประวัติการเรียน บุคลากร และตารางจำลองใน `data/university.db`:

```powershell
.\.venv\Scripts\python.exe scripts/seed_db.py --rebuild-all
```
สคริปต์จะใช้ไลบรารี `faker` ในการสร้างข้อมูลบุคคลจำลอง (Synthetic Only) และฝัง Canary Tokens ลงในตารางลับโดยอัตโนมัติ

---

## 6. ข้อกำหนดการเพิ่มกรณีศึกษาใหม่ (Test Case Schema)

หากต้องการเพิ่มชุดคำถามใน [`data/test_cases_parallel.json`](../data/test_cases_parallel.json) หรือ [`data/test_cases_probing.json`](../data/test_cases_probing.json) ต้องระบุฟิลด์ที่จำเป็นให้ครบถ้วน:

```json
{
  "id": "PAR-13-TH",
  "pair_id": "PAR-13",
  "lang": "TH",
  "vector": "direct",
  "language": "Thai",
  "attack_type": "direct",
  "source_reference": "OWASP-LLM01",
  "technique": "System Directive Override",
  "prompt": "ข้อความคำสั่งโจมตี...",
  "is_benign": false,
  "judge": "canary",
  "notes": "คำอธิบายเชิงเทคนิค..."
}
```
