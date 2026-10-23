# Published Evaluation Artifacts (`results/published/`)

โฟลเดอร์นี้ใช้เก็บเฉพาะผลลัพธ์การประเมินที่ผ่านการคัดกรองข้อมูลดิบแล้ว (Sanitized & Reproducible Summary Artifacts) เพื่อให้สามารถนำเข้า Git และตรวจสอบย้อนหลังได้โดยไม่เปิดเผยข้อความคำตอบดิบของโมเดล

## กฎของไฟล์ใน `results/published/`
1. **ห้ามเก็บ Raw Prompt หรือ Raw Response เต็ม**: เก็บเฉพาะรหัสเคส (`id`, `pair_id`, `lang`, `vector`, `is_benign`), ระดับการป้องกัน (`defense`), รอบที่รัน (`repeat`), ผลตัดสิน `0`/`1` (`success`), รายการ Canary/Table ที่ตรงเงื่อนไข (`matched`), จำนวนการเรียกใช้เครื่องมือ (`tool_calls_total`, `tool_calls_blocked`), และชื่อโมเดลที่ถูกเรียกจริง (`model_used`)
2. **Metadata เพื่อการทำซ้ำครบถ้วน**: ทุกไฟล์สรุป (`*_summary.json`) และตารางรายแถว (`*_rows.csv`) ต้องระบุ `red_model`, `blue_model`, `model_used`, `provider`, `timestamp`, `attempts`, `random_seed`, `defense`, `git_commit`, `cases_version`, และ `cases_sha256`
3. **สถานะปัจจุบัน**:
   - **ชุดทดสอบคู่ขนาน (`test_cases_parallel.json`, 45 เคส × 4 โหมด)**: `TBD (ยังไม่ได้รันจริง)`
   - **ชุดทดสอบเจาะจุดบอด (`test_cases_probing.json`, 24 เคส × 2 โหมด `tools,all`)**: รันจริงแล้วเมื่อ `2026-10-23T10:56:21Z` บนโมเดล `gemini-3.5-flash-lite` (Provider: `gemini`, Commit: `10efb96`) ผลสรุปอยู่ใน [`probing_live_summary.json`](probing_live_summary.json), [`probing_live_rows.csv`](probing_live_rows.csv), [`probing_live_report.md`](probing_live_report.md), [`probing_by_category.png`](probing_by_category.png) และ [`PUBLISHED_REPORT.md`](PUBLISHED_REPORT.md)
   - เมื่อต้องการรันหรืออัปเดตรายงานใหม่:
   ```powershell
   .\.venv\Scripts\python.exe -m core.evaluator.cli --parallel --publish
   .\.venv\Scripts\python.exe -m core.evaluator.cli --probing --publish
   .\.venv\Scripts\python.exe scripts/make_report.py
   ```
   สคริปต์ [`scripts/make_report.py`](../../scripts/make_report.py) จะอ่านเฉพาะไฟล์ใน `results/published/` เพื่อสร้างตารางสรุปและกราฟพร้อมช่วงความเชื่อมั่น 95% (Wilson CI) โดยอัตโนมัติ
