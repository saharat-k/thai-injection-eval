"""Benchmark Lock and Integrity Verification Module.

Enforces strict tamper-proofing of test cases, system prompts, defense implementations,
database seed scripts, and benchmark payload records. Aborts execution before any API
calls if any locked component differs from the frozen benchmark specification.
"""

import hashlib
import inspect
import json
import os
import sqlite3
from typing import Any, Dict, Optional, Tuple

from core.defenses.spotlight import SpotlightingGuard


def compute_seed_db_hash(seed_path: str = "scripts/seed_db.py") -> str:
    """Compute deterministic SHA-256 hash of seed_db.py with line-ending normalization.
    
    Normalizes all CRLF and CR line endings to LF before hashing to ensure
    cross-platform stability (Windows vs Linux vs Git checkout).
    """
    if not os.path.exists(seed_path):
        raise FileNotFoundError(f"[BENCHMARK LOCK ERROR] Seed script not found at: {seed_path}")

    with open(seed_path, "r", encoding="utf-8") as f:
        content = f.read()

    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def dump_benchmark_payload_records(
    db_path: str = "data/university.db",
    cases_path: str = "data/test_cases_indirect.json",
) -> Dict[str, Any]:
    """Extract a canonical dictionary of all 63 benchmark records across the 4 relevant tables.
    
    Identifies records based on the source_record_id and pivot_record_id entries
    defined in test_cases_indirect.json:
      - 24 announcements (ANN901..ANN912 across TH, EN, MIX)
      - 12 course_evaluations (EV902..EV911 across TH, EN, MIX)
      - 12 enrollments (E901..E908 across TH, EN, MIX)
      - 15 awards (A902..A909 across TH, EN, MIX)
    """
    if not os.path.exists(db_path):
        raise FileNotFoundError(f"[BENCHMARK LOCK ERROR] Database not found at: {db_path}")
    if not os.path.exists(cases_path):
        raise FileNotFoundError(f"[BENCHMARK LOCK ERROR] Cases file not found at: {cases_path}")

    with open(cases_path, "r", encoding="utf-8") as f:
        cases_data = json.load(f)

    ann_ids = []
    eval_ids = []
    enroll_ids = []
    award_ids = []

    for c in cases_data.get("cases", []):
        st = c.get("source_table")
        sid = c.get("source_record_id")
        pt = c.get("pivot_table")
        pid = c.get("pivot_record_id")

        if st == "announcements" and sid and sid not in ann_ids:
            ann_ids.append(sid)
        elif st == "course_evaluations" and sid and sid not in eval_ids:
            eval_ids.append(sid)

        if pt == "enrollments" and pid and pid not in enroll_ids:
            enroll_ids.append(pid)
        elif pt == "awards" and pid and pid not in award_ids:
            award_ids.append(pid)

    ann_ids.sort()
    eval_ids.sort()
    enroll_ids.sort()
    award_ids.sort()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    def fetch_records(table: str, pk_col: str, ids: list) -> list:
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        query = f"SELECT * FROM {table} WHERE {pk_col} IN ({placeholders}) ORDER BY {pk_col} ASC"
        cur.execute(query, ids)
        rows = [dict(r) for r in cur.fetchall()]
        return [{k: row[k] for k in sorted(row.keys())} for row in rows]

    ann_records = fetch_records("announcements", "announcement_id", ann_ids)
    eval_records = fetch_records("course_evaluations", "eval_id", eval_ids)
    enroll_records = fetch_records("enrollments", "enrollment_id", enroll_ids)
    award_records = fetch_records("awards", "award_id", award_ids)
    conn.close()

    total_records = len(ann_records) + len(award_records) + len(eval_records) + len(enroll_records)

    return {
        "record_counts": {
            "announcements": len(ann_records),
            "awards": len(award_records),
            "course_evaluations": len(eval_records),
            "enrollments": len(enroll_records),
            "total": total_records,
        },
        "records": {
            "announcements": ann_records,
            "awards": award_records,
            "course_evaluations": eval_records,
            "enrollments": enroll_records,
        },
    }


def compute_payload_records_hash(
    db_path: str = "data/university.db",
    cases_path: str = "data/test_cases_indirect.json",
) -> Tuple[str, Dict[str, Any]]:
    """Compute deterministic SHA-256 hash of canonical JSON dump of benchmark database records."""
    dump = dump_benchmark_payload_records(db_path, cases_path)
    canonical_json = json.dumps(dump, sort_keys=True, ensure_ascii=False)
    payload_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return payload_hash, dump


def compute_spotlight_neutralizer_hash() -> str:
    """Compute deterministic SHA-256 hash of SpotlightingGuard.neutralize_collisions source."""
    src = inspect.getsource(SpotlightingGuard.neutralize_collisions).strip()
    return hashlib.sha256(src.encode("utf-8")).hexdigest()


def compute_spotlight_framing_hash() -> str:
    """Compute deterministic SHA-256 hash of Spotlighting framing structure."""
    guard = SpotlightingGuard(seed=42)
    sample_payload, _ = guard.wrap_records(
        table="sample_table",
        cols=["c1"],
        rows=[("r1",)],
        delimiter="SPOTLIGHT_TEST",
    )
    framing = sample_payload.get("_data_boundary", "")
    return hashlib.sha256(framing.encode("utf-8")).hexdigest()


def verify_benchmark_lock(
    lock_path: str = "data/benchmark_lock.json",
    db_path: Optional[str] = None,
    seed_path: Optional[str] = None,
    cases_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify that all live files, seeds, payloads, and prompt configurations match the benchmark lock.

    Aborts immediately with RuntimeError before any API call if any hash does not match.
    """
    if not os.path.exists(lock_path):
        raise RuntimeError(f"[BENCHMARK LOCK ERROR] Lock file not found at: {lock_path}")

    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)

    # 1. Verify test cases file hash
    cases_file = cases_path or lock.get("cases_file", "data/test_cases_indirect.json")
    if not os.path.exists(cases_file):
        raise RuntimeError(f"[BENCHMARK LOCK ERROR] Cases file not found at: {cases_file}")

    with open(cases_file, "rb") as f:
        actual_cases_hash = hashlib.sha256(f.read()).hexdigest()
    expected_cases_hash = lock.get("cases_sha256")
    if actual_cases_hash != expected_cases_hash:
        raise RuntimeError(
            f"[BENCHMARK LOCK ERROR] Test cases hash mismatch!\n"
            f"Expected: {expected_cases_hash}\n"
            f"Actual:   {actual_cases_hash}\n"
            f"Modifying test cases after freeze is strictly prohibited."
        )

    # 2. Verify spotlight framing & neutralizer hashes
    spotlight_meta = lock.get("spotlight_defense_lock") or {}
    expected_neut_hash = spotlight_meta.get("neutralizer_sha256")
    if expected_neut_hash:
        actual_neut_hash = compute_spotlight_neutralizer_hash()
        if actual_neut_hash != expected_neut_hash:
            raise RuntimeError(
                f"[BENCHMARK LOCK ERROR] Spotlight neutralizer hash mismatch!\n"
                f"Expected: {expected_neut_hash}\n"
                f"Actual:   {actual_neut_hash}"
            )

    expected_frame_hash = spotlight_meta.get("framing_sha256")
    if expected_frame_hash:
        actual_frame_hash = compute_spotlight_framing_hash()
        if actual_frame_hash != expected_frame_hash:
            raise RuntimeError(
                f"[BENCHMARK LOCK ERROR] Spotlight framing hash mismatch!\n"
                f"Expected: {expected_frame_hash}\n"
                f"Actual:   {actual_frame_hash}"
            )

    # 3. Verify seed_db.py and payload records hashes (Payload Lock)
    payload_lock = lock.get("payload_lock") or {}
    expected_seed_hash = payload_lock.get("seed_db_sha256")
    if expected_seed_hash:
        active_seed_path = seed_path or payload_lock.get("seed_db_file", "scripts/seed_db.py")
        actual_seed_hash = compute_seed_db_hash(active_seed_path)
        if actual_seed_hash != expected_seed_hash:
            raise RuntimeError(
                f"[BENCHMARK LOCK ERROR] seed_db.py hash mismatch!\n"
                f"Expected: {expected_seed_hash}\n"
                f"Actual:   {actual_seed_hash}\n"
                f"Modifying database seed scripts after freeze is strictly prohibited."
            )

    expected_records_hash = payload_lock.get("payload_records_sha256")
    if expected_records_hash:
        active_db_path = db_path or payload_lock.get("database_file", "data/university.db")
        actual_records_hash, _ = compute_payload_records_hash(active_db_path, cases_file)
        if actual_records_hash != expected_records_hash:
            raise RuntimeError(
                f"[BENCHMARK LOCK ERROR] Benchmark payload records hash mismatch!\n"
                f"Expected: {expected_records_hash}\n"
                f"Actual:   {actual_records_hash}\n"
                f"Modifying benchmark database records after freeze is strictly prohibited."
            )

    # 4. Verify system prompts for each defense tier (if present)
    prompt_locks = lock.get("system_prompt_locks") or {}
    if prompt_locks:
        import agent
        for tier, expected_info in prompt_locks.items():
            base_sys = agent.HARDENED_SYSTEM_PROMPT if tier in ("prompt", "all") else agent.BASE_SYSTEM_PROMPT
            schema_hint = agent.PUBLIC_SCHEMA_HINT if tier in ("prompt", "tools", "all") else agent.FULL_SCHEMA_HINT
            role_addon = agent.get_blue_role_prompt("registrar_staff")
            sys_prompt = f"{base_sys}\n\n{schema_hint}\n\nROLE POLICY:\n{role_addon}"
            actual_hash = hashlib.sha256(sys_prompt.encode("utf-8")).hexdigest()
            expected_hash = expected_info.get("sha256") if isinstance(expected_info, dict) else expected_info
            if actual_hash != expected_hash:
                raise RuntimeError(
                    f"[BENCHMARK LOCK ERROR] System prompt hash mismatch for tier '{tier}'!\n"
                    f"Expected: {expected_hash}\n"
                    f"Actual:   {actual_hash}"
                )

    return lock
