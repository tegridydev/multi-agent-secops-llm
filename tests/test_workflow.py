import json
import os
import sqlite3
import stat
import subprocess
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier

from test_ingest import ROOT, encoded, event

from secops_harness.store import StoreError, open_queue, review


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.db = self.dir / "triage ? review.sqlite3"

    def cli(self, *args, module=True):
        prefix = ["-m", "secops_harness"] if module else ["multiagent.py"]
        return subprocess.run(
            [sys.executable, *prefix, *map(str, args)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def demo(self):
        result = self.cli("demo", "--format", "json", "--db", self.db)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_original_entry_point_runs_offline_demo(self):
        result = self.cli(module=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("3 cases from 9 unique events", result.stdout)
        self.assertIn("successful login was expected", result.stdout)

    def test_batch_to_queue_and_review_idempotence(self):
        first = self.demo()
        self.assertEqual(first["queue"], {"new_cases": 3, "existing_cases": 0})
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.db.stat().st_mode) & 0o077, 0)
        case_id = first["cases"][0]["case_id"]
        pending = self.cli("cases", "--db", self.db, "--state", "pending", "--limit", 2)
        self.assertEqual(pending.returncode, 0, pending.stderr)
        self.assertEqual(len(json.loads(pending.stdout)), 2)
        reviewed = self.cli(
            "review",
            case_id,
            "--db",
            self.db,
            "--decision",
            "acknowledged",
            "--by",
            "mark",
            "--note",
            "Compared with the source alert.",
        )
        self.assertEqual(reviewed.returncode, 0, reviewed.stderr)
        repeated = self.demo()
        self.assertEqual(repeated["queue"], {"new_cases": 0, "existing_cases": 3})
        detail = self.cli("show", case_id, "--db", self.db)
        self.assertEqual(detail.returncode, 0, detail.stderr)
        payload = json.loads(detail.stdout)
        self.assertEqual(payload["review"]["state"], "acknowledged")
        self.assertEqual(payload["review"]["note"], "Compared with the source alert.")
        self.assertEqual(payload["case"], first["cases"][0])
        self.assertEqual(payload["policy"], first["policy"])
        override = self.cli(
            "review",
            case_id,
            "--db",
            self.db,
            "--decision",
            "dismissed",
            "--by",
            "another",
            "--note",
            "Duplicate.",
        )
        self.assertEqual(override.returncode, 1)
        self.assertIn("already has a recorded review", override.stderr)

    def test_concurrent_reviews_do_not_overwrite_each_other(self):
        case_id = self.demo()["cases"][0]["case_id"]
        gate = Barrier(2)

        def decide(name):
            with open_queue(self.db, write=True) as conn:
                gate.wait(timeout=5)
                try:
                    review(conn, case_id, "dismissed", name, "Reviewed the export.")
                except StoreError:
                    return None
                return name

        with ThreadPoolExecutor(max_workers=2) as pool:
            winners = [name for name in pool.map(decide, ("one", "two")) if name]
        self.assertEqual(len(winners), 1)
        detail = json.loads(self.cli("show", case_id, "--db", self.db).stdout)
        self.assertEqual(detail["review"]["reviewer"], winners[0])

    def test_malformed_batch_does_not_create_queue_or_output_partial_result(self):
        path = self.dir / "batch.jsonl"
        path.write_bytes(encoded(event(kind="malware_alert")) + b'{not json, "private": "secret"}\n')
        result = self.cli("triage", path, "--db", self.db, "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("line 2", result.stderr)
        self.assertNotIn("secret", result.stderr)
        self.assertFalse(self.db.exists())

    def test_refuses_to_use_the_same_file_for_input_and_queue(self):
        self.db.write_bytes(encoded(event(kind="malware_alert")))
        result = self.cli("triage", self.db, "--db", self.db)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be different files", result.stderr)
        self.assertEqual(self.db.read_bytes(), encoded(event(kind="malware_alert")))

    def test_unrelated_database_is_unchanged(self):
        with sqlite3.connect(self.db) as raw:
            raw.execute("CREATE TABLE existing_data (note TEXT)")
            raw.execute("INSERT INTO existing_data VALUES ('keep')")
        result = self.cli("demo", "--db", self.db)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not an empty or supported SecOps queue", result.stderr)
        with sqlite3.connect(self.db) as raw:
            self.assertEqual(raw.execute("SELECT note FROM existing_data").fetchone()[0], "keep")

    def test_missing_queue_is_not_created_by_list(self):
        result = self.cli("cases", "--db", self.db)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.db.exists())

    def test_threshold_exit_keeps_report_and_records_case(self):
        result = self.cli("demo", "--fail-on", "high", "--format", "json", "--db", self.db)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(json.loads(result.stdout)["queue"]["new_cases"], 3)

    def test_ollama_configuration_errors_are_actionable(self):
        result = self.cli("demo", "--reviewer-model", "demo")
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --ollama-model", result.stderr)
        result = self.cli("demo", "--ollama-model", "model:cloud")
        self.assertEqual(result.returncode, 2)
        self.assertIn("local Ollama tag", result.stderr)

    def test_wazuh_example_finds_two_cases_with_custom_threshold(self):
        result = self.cli(
            "triage",
            "examples/wazuh-alerts.jsonl",
            "--input-format",
            "wazuh",
            "--auth-failures",
            "2",
            "--format",
            "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["coverage"]["ignored_rows"], 1)
        self.assertEqual(
            [item["findings"][0]["rule"] for item in report["cases"]],
            ["auth_success_after_failures", "reported_security_alert"],
        )
        self.assertNotIn("Synthetic integrity alert text", result.stdout)
