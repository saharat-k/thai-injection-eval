"""Unit tests for benchmark lock and integrity verification (Task 1).

Verifies tamper-resistance of seed_db.py, SQLite benchmark records, test cases,
spotlight components, and guarantees runner aborts before any API calls.
Uses temporary copies exclusively; never mutates live repository databases.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from core.evaluator.lock import (
    compute_seed_db_hash,
    compute_payload_records_hash,
    dump_benchmark_payload_records,
    verify_benchmark_lock,
)
from core.evaluator.indirect import ResumableIndirectRunner


class TestBenchmarkLockIntegrity(unittest.TestCase):
    """Test suite ensuring strict tamper-detection across benchmark artifacts."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.lock_path = "data/benchmark_lock.json"
        self.db_path = "data/university.db"
        self.seed_path = "scripts/seed_db.py"
        self.cases_path = "data/test_cases_indirect.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_current_repo_state_passes(self):
        """Live repository state must strictly pass verification with zero warnings."""
        lock = verify_benchmark_lock(
            lock_path=self.lock_path,
            db_path=self.db_path,
            seed_path=self.seed_path,
            cases_path=self.cases_path,
        )
        self.assertIsInstance(lock, dict)
        self.assertEqual(lock.get("status"), "LOCKED")
        self.assertIn("payload_lock", lock)
        self.assertEqual(lock["payload_lock"]["record_counts"]["total"], 63)

    def test_changing_payload_record_fails_verification(self):
        """Mutating any benchmark record in university.db must trigger an immediate RuntimeError."""
        temp_db = os.path.join(self.temp_dir, "university_tampered.db")
        shutil.copy2(self.db_path, temp_db)

        # Tamper with one benchmark enrollment record
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        cur.execute(
            "UPDATE enrollments SET grade = 'F TAMPERED' WHERE enrollment_id = 'E901_TH'"
        )
        conn.commit()
        conn.close()

        with self.assertRaises(RuntimeError) as ctx:
            verify_benchmark_lock(
                lock_path=self.lock_path,
                db_path=temp_db,
                seed_path=self.seed_path,
                cases_path=self.cases_path,
            )
        self.assertIn("Benchmark payload records hash mismatch", str(ctx.exception))

    def test_changing_seed_db_fails_verification(self):
        """Mutating seed_db.py must trigger an immediate RuntimeError."""
        temp_seed = os.path.join(self.temp_dir, "seed_db_tampered.py")
        with open(self.seed_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Append tampering comment
        with open(temp_seed, "w", encoding="utf-8") as f:
            f.write(content + "\n# Tampering injection payload\n")

        with self.assertRaises(RuntimeError) as ctx:
            verify_benchmark_lock(
                lock_path=self.lock_path,
                db_path=self.db_path,
                seed_path=temp_seed,
                cases_path=self.cases_path,
            )
        self.assertIn("seed_db.py hash mismatch", str(ctx.exception))

    def test_seed_db_crlf_vs_lf_line_endings_match(self):
        """Seed script hash must be completely invariant to Windows CRLF vs Linux LF line endings."""
        sample_code = "BASELINE_AWARDS = [\n    ('A001', 'S001', 'Dean', 2024)\n]\n"
        crlf_file = os.path.join(self.temp_dir, "seed_crlf.py")
        lf_file = os.path.join(self.temp_dir, "seed_lf.py")

        with open(crlf_file, "wb") as f:
            f.write(sample_code.replace("\n", "\r\n").encode("utf-8"))

        with open(lf_file, "wb") as f:
            f.write(sample_code.encode("utf-8"))

        crlf_hash = compute_seed_db_hash(crlf_file)
        lf_hash = compute_seed_db_hash(lf_file)

        self.assertEqual(crlf_hash, lf_hash)

    def test_changing_test_cases_fails_verification(self):
        """Mutating test_cases_indirect.json must fail with test cases hash mismatch."""
        temp_cases = os.path.join(self.temp_dir, "test_cases_tampered.json")
        with open(self.cases_path, "r", encoding="utf-8") as f:
            cases_data = json.load(f)

        # Alter one prompt slightly
        cases_data["cases"][0]["prompt"] += " TAMPERED"
        with open(temp_cases, "w", encoding="utf-8") as f:
            json.dump(cases_data, f, indent=2, ensure_ascii=False)

        with self.assertRaises(RuntimeError) as ctx:
            verify_benchmark_lock(
                lock_path=self.lock_path,
                db_path=self.db_path,
                seed_path=self.seed_path,
                cases_path=temp_cases,
            )
        self.assertIn("Test cases hash mismatch", str(ctx.exception))

    @patch("agent.make_client")
    def test_runner_refuses_to_start_on_mismatch_without_api_calls(self, mock_make_client):
        """Runner must abort in __init__ on tampered lock without creating agent client or making API calls."""
        temp_lock = os.path.join(self.temp_dir, "tampered_lock.json")
        with open(self.lock_path, "r", encoding="utf-8") as f:
            lock_data = json.load(f)

        # Invalidate cases sha
        lock_data["cases_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
        with open(temp_lock, "w", encoding="utf-8") as f:
            json.dump(lock_data, f, indent=2)

        with self.assertRaises(RuntimeError) as ctx:
            ResumableIndirectRunner(lock_path=temp_lock)

        self.assertIn("Test cases hash mismatch", str(ctx.exception))
        # Ensure make_client was never called and no API calls were made
        mock_make_client.assert_not_called()

    @patch("agent.BlueSession")
    def test_runner_run_batch_and_checkpoint_offline(self, mock_session_cls):
        """Runner must process scheduled units, track requests, and persist checkpoints correctly."""
        mock_session = MagicMock()
        mock_session.model = "gemini-3.5-flash-lite"
        mock_session.last_model_version = "gemini-3.5-flash-lite-v1"
        mock_session.last_timestamp = "2026-10-26T14:00:00Z"
        mock_session.send.return_value = "Summary of announcement with facts 15 and 28."
        mock_session_cls.return_value = mock_session

        temp_checkpoint = os.path.join(self.temp_dir, "test_cp.json")
        runner = ResumableIndirectRunner(
            lock_path=self.lock_path,
            checkpoint_path=temp_checkpoint,
            daily_quota_limit=400,
        )

        # Run 2 units
        results = runner.run_batch(max_units=2, delay_seconds=0.0, verbose=False)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(runner.checkpoint["completed_orders"]), 2)
        self.assertTrue(os.path.exists(temp_checkpoint))

        # Check request tracking
        self.assertGreaterEqual(runner.get_today_requests(), 2)

        # Resume run for next 1 unit
        runner2 = ResumableIndirectRunner(
            lock_path=self.lock_path,
            checkpoint_path=temp_checkpoint,
            daily_quota_limit=400,
        )
        self.assertEqual(len(runner2.checkpoint["completed_orders"]), 2)
        remaining = runner2.get_remaining_units()
        self.assertEqual(len(remaining), 538)

        results2 = runner2.run_batch(max_units=1, delay_seconds=0.0, verbose=False)
        self.assertEqual(len(results2), 1)
        self.assertEqual(len(runner2.checkpoint["completed_orders"]), 3)

    @patch("agent.BlueSession")
    def test_runner_auto_halts_when_quota_reached(self, mock_session_cls):
        """Runner must halt immediately when the daily quota limit is reached."""
        mock_session = MagicMock()
        mock_session.model = "gemini-3.5-flash-lite"
        mock_session.last_model_version = "v1"
        mock_session.last_timestamp = "2026-10-26T14:00:00Z"
        mock_session.send.return_value = "Response text"
        mock_session_cls.return_value = mock_session

        temp_checkpoint = os.path.join(self.temp_dir, "quota_cp.json")
        # Set quota limit to 2
        runner = ResumableIndirectRunner(
            lock_path=self.lock_path,
            checkpoint_path=temp_checkpoint,
            daily_quota_limit=2,
        )

        # Running 5 units should halt after quota is reached (at 2 requests)
        results = runner.run_batch(max_units=5, delay_seconds=0.0, verbose=False)
        self.assertLessEqual(len(results), 2)
        self.assertTrue(runner.is_daily_quota_reached())

    @patch("agent.BlueSession")
    def test_runner_aborts_without_fallback_on_primary_model_error(self, mock_session_cls):
        """Runner must abort immediately on primary model error and refuse silent fallback."""
        mock_session = MagicMock()
        mock_session.model = "gemini-3.5-flash-lite"
        mock_session.send.side_effect = RuntimeError("503 Service Unavailable")
        mock_session_cls.return_value = mock_session

        temp_checkpoint = os.path.join(self.temp_dir, "err_cp.json")
        runner = ResumableIndirectRunner(
            lock_path=self.lock_path,
            checkpoint_path=temp_checkpoint,
            daily_quota_limit=400,
        )

        with self.assertRaises(RuntimeError) as ctx:
            runner.run_batch(max_units=1, delay_seconds=0.0, verbose=False)

        self.assertIn("Fallback model switching is strictly disabled", str(ctx.exception))
        # Ensure completed orders did not add the failed unit
        self.assertEqual(len(runner.checkpoint["completed_orders"]), 0)
