import json
import os
import subprocess
import sys
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread

from test_ingest import ROOT, event


class WireWorkflowTests(unittest.TestCase):
    def test_live_cli_polls_one_endpoint_and_exports_a_provenanced_report(self):
        calls = []
        data = json.dumps([event(kind="malware_alert", asset="test-endpoint")]).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        with TemporaryDirectory() as temp, HTTPServer(("127.0.0.1", 0), Handler) as http:
            root = Path(temp)
            url = f"http://localhost:{http.server_port}/alerts"
            thread = Thread(target=http.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        "masop.py",
                        "--home",
                        str(root / "state"),
                        "live",
                        "--feed",
                        url,
                        "--cycles",
                        "1",
                        "--token-env",
                        "MASOP_TEST_FEED_KEY",
                        "--format",
                        "json",
                        "--rules-only",
                        "--report-dir",
                        str(root / "reports"),
                    ],
                    cwd=ROOT,
                    env={**os.environ, "MASOP_TEST_FEED_KEY": "fake-fixture-token"},
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
            finally:
                http.shutdown()
                thread.join(timeout=2)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(calls, [("/alerts", "Bearer fake-fixture-token")])
            item = json.loads(result.stdout)
            self.assertEqual(item["queue"]["new_cases"], 1)
            self.assertEqual(
                item["cases"][0]["evidence"][0]["origin"], f"127.0.0.1:{http.server_port}/alerts"
            )
            self.assertNotIn("fake-fixture-token", result.stdout)
            (report,) = (root / "reports").glob("*.json")
            self.assertEqual(json.loads(report.read_text()), item)

    def test_no_changes_is_a_successful_poll_not_an_error(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            data = root / "data"
            data.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    "masop.py",
                    "--home",
                    str(root / "state"),
                    "live",
                    "--directory",
                    str(data),
                    "--cycles",
                    "1",
                    "--rules-only",
                    "--format",
                    "json",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
