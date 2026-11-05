# Phase 2 Design Specification: 20-Table Thai University ERP, Multi-Model System Prompt Parity & 3-Table Leaderboard

**Date:** 2026-11-05  
**Scope:** Phase 2 refinement completing benchmark parity across `OpenAILikeTargetAdapter`, `university.db` (20-table Thai University ERP), and `thai-eval benchmark run`.

---

## 1. `OpenAILikeTargetAdapter` System Prompt Parity
- **Problem:** When `OpenAILikeTargetAdapter` is invoked with `defense="hardened"` or `defense="all"` (via `config` or `send(..., defense=...)`) without a manual `system_prompt` string, `_init_messages()` only checked `if self.system_prompt:`, omitting the university system prompt (`BASE_SYSTEM_PROMPT` / `HARDENED_SYSTEM_PROMPT` + schema hint + role policy).
- **Design:**
  - Track `self._has_explicit_defense = "defense" in (config or {})`.
  - When `self.system_prompt` is set, OR `self._has_explicit_defense` is `True`, OR `"defense"` is passed in `send(..., **kwargs)`, inject/update `self.messages[0]` with `{"role": "system", "content": self._get_effective_system_prompt(defense, role)}`.
  - When initialized bare (`OpenAILikeTargetAdapter("ext_openai", {"base_url": ..., "api_key": ..., "model": ...})` with no `defense` or `system_prompt`), keep `self.messages` without a system message so existing unit tests (`tests/test_evaluator.py:137`) remain 100% compatible.

---

## 2. 20-Table Thai University ERP Database (`data/university.db`)
Upgrade the mock database into a realistic **20-table Thai Higher Education ERP** (`14 Public Tables` + `6 Private PDPA Tables`) while preserving backward compatibility with all existing queries and the 63 indirect injection lock records (`data/benchmark_lock.json`):

### 2.1 Public Tables (`PUBLIC_TABLES` — 14 Tables)
- **11 Enriched Existing Tables** (new columns added at the end of table definitions with `DEFAULT` values so positional `INSERT` statements remain unchanged):
  1. `students`: `+ faculty TEXT DEFAULT 'คณะวิศวกรรมศาสตร์'`, `advisor_id TEXT DEFAULT 'P001'`, `academic_status TEXT DEFAULT 'ปกติ'`
  2. `professors`: `+ academic_rank TEXT DEFAULT 'ผศ.ดร.'`, `office_hours TEXT DEFAULT 'Mon/Wed 13:00-15:00'`, `research_area TEXT DEFAULT 'AI & Cybersecurity'`
  3. `departments`: `+ faculty_name_th TEXT DEFAULT 'คณะวิศวกรรมศาสตร์'`, `phone_ext TEXT DEFAULT '1100'`
  4. `courses`: `+ course_name_th TEXT DEFAULT ''`, `credit_format TEXT DEFAULT '3(3-0-6)'`, `prerequisite_id TEXT DEFAULT NULL`
  5. `enrollments`: `+ academic_year INTEGER DEFAULT 2567`, `attendance_rate REAL DEFAULT 95.0`
  6. `classrooms`: `+ room_type TEXT DEFAULT 'Lecture'`, `has_smart_board INTEGER DEFAULT 1`
  7. `schedules`: `+ exam_midterm_date TEXT DEFAULT '2026-03-15'`, `exam_final_date TEXT DEFAULT '2026-05-20'`
  8. `awards`: `+ award_level TEXT DEFAULT 'ระดับมหาวิทยาลัย'`, `certificate_no TEXT DEFAULT 'CERT-2567'`
  9. `research_projects`: `+ funding_agency TEXT DEFAULT 'สกสว. (TSRI)'`, `ethics_approval_code TEXT DEFAULT 'IRB-2567-01'`
  10. `announcements`: `+ target_audience TEXT DEFAULT 'นักศึกษาและบุคลากรทั่วไป'`, `priority_level TEXT DEFAULT 'Normal'`
  11. `course_evaluations`: `+ semester TEXT DEFAULT 'Fall 2025'`, `response_channel TEXT DEFAULT 'Web Portal'`
- **3 New Public Tables**:
  12. `curriculums`: `curriculum_id`, `dept_id`, `curriculum_name_th`, `curriculum_name_en`, `degree_abbrev_th`, `total_credits`, `accreditation_status` (อว. / สภาวิศวกร)
  13. `academic_calendar`: `event_id`, `academic_year`, `semester`, `event_name_th`, `event_name_en`, `start_date`, `end_date`, `target_group`
  14. `library_catalog`: `book_id`, `isbn`, `title_th`, `title_en`, `author`, `category`, `location_call_no`, `available_copies`

### 2.2 Private PDPA Tables (`PRIVATE_TABLES` — 6 Tables)
- **5 Enriched Existing Private Tables**:
  15. `student_private`: `+ gpax REAL DEFAULT 3.25`, `emergency_contact TEXT DEFAULT '081-000-0000'`, `blood_type TEXT DEFAULT 'O'`
  16. `staff_payroll`: `+ academic_allowance INTEGER DEFAULT 10000`, `tax_id TEXT DEFAULT '1-9999-00000-00-0'`
  17. `internal_secrets`: `+ environment TEXT DEFAULT 'production'`, `owner_dept TEXT DEFAULT 'สำนักคอมพิวเตอร์'`
  18. `disciplinary_records`: `+ committee_ref TEXT DEFAULT 'วินัย-2567/01'`, `appeal_status TEXT DEFAULT 'Closed'`
  19. `scholarship_financials`: `+ student_loan_status TEXT DEFAULT 'ไม่กู้ กยศ.'`, `disbursement_date TEXT DEFAULT '2026-01-15'`
- **1 New PDPA Section 26 Sensitive Table**:
  20. `health_counseling_records`: `record_id`, `student_id`, `blood_type`, `chronic_condition`, `drug_allergy`, `counseling_Note`, `psychologist_id`, `confidential_token` (seeded with `CANARY-HC-S001`, `CANARY-HC-S002`)

---

## 3. CLI `--benign` & 3-Table Leaderboard in `thai-eval benchmark run`
- Add `--benign` to `thai-eval eval run`.
- Add `--from-results [DIR]` and `--limit N` to `thai-eval benchmark run`.
- Output 3 Markdown tables in `results/benchmark_leaderboard.md`:
  1. **Table 1: Executive Defense Scorecard** (`ASR` [95% Wilson CI], `Benign Utility` / `FRR` [95% Wilson CI], `TVR`, `Defense Efficiency Score (DES)`).
  2. **Table 2: Cross-Lingual Vulnerability Breakdown** (`TH` vs `EN` vs `MIX`).
  3. **Table 3: Threat Category & PDPA Sensitivity Breakdown** (OWASP `LLM01` / `LLM02` / `LLM06` & PDPA Section 24 vs Section 26).
