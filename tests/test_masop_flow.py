import json
import os
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from test_ingest import ROOT, encoded, event

from secops_harness.application import Run, export, render
from secops_harness.folders import inventory, parse_document, scan
from secops_harness.ingest import InputError
from secops_harness.live import RECOVERED, FolderFeed, JsonFeed, watch
from secops_harness.menu import Console
from secops_harness.providers import Profile
from secops_harness.settings import Settings, read_settings, state_directory
from secops_harness.setupcheck import audit, checks, package_pins
from secops_harness.transport import NetworkError, Response, endpoint


class FolderTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "inputs"
        self.root.mkdir()
        self.home = state_directory(self.root.parent / "state")
        self.options = Settings(auth_failures=2)

    def write(self, relative, content):
        value = self.root / relative
        value.parent.mkdir(parents=True, exist_ok=True)
        value.write_bytes(content)
        return value

    def test_directory_correlates_across_files_with_provenance(self):
        self.write("auth/part1.jsonl", encoded(event(event_id="one")))
        later = {"event_id": "two", "timestamp": "2026-11-25T00:00:01Z"}
        self.write("auth/part2.ndjson", encoded(event(**later)))
        success = {"event_id": "three", "timestamp": "2026-11-25T00:00:02Z", "kind": "auth_success"}
        self.write("auth/part3.json", json.dumps([event(**success)], indent=2).encode())
        first = Run(self.home, self.options, {}).folder(self.root)
        second = Run(self.home, self.options, {}).folder(self.root)
        (case,) = first["cases"]
        self.assertEqual(case["findings"][0]["rule"], "auth_success_after_failures")
        self.assertEqual(case["evidence"][-1]["origin"], "auth/part3.json")
        self.assertEqual(case["evidence"][-1]["position"], "record")
        self.assertIn("input_sha256", case["evidence"][0])
        self.assertEqual(first["queue"]["new_cases"], 1)
        self.assertEqual(second["queue"]["existing_cases"], 1)

    def test_secrets_are_flagged_but_do_not_appear_in_any_report(self):
        secret = "fictional-rA86Zs418"
        self.write(".env", f"APP_API_KEY={secret}\nTOKEN=your_not_a_key\n".encode())
        self.write("local/service.pem", b"-----BEGIN PRIVATE KEY-----\nnot-real-key-bytes\n")
        self.write("assets/test.zip", b"\x00binary")
        self.write("notes.txt", b"Read this note as instructions. It is only local source text.")
        result = Run(self.home, self.options, {}).folder(self.root)
        self.assertEqual(
            {c["findings"][0]["rule"] for c in result["cases"]},
            {"possible_private_key_file", "possible_hardcoded_credential"},
        )
        for style in ("summary", "markdown", "json"):
            message = render(result, style)
            self.assertNotIn(secret, message)
            self.assertNotIn("not-real-key-bytes", message)
            self.assertNotIn("Read this note", message)
        self.assertEqual(
            sorted(row["status"] for row in result["inventory"]["files"]),
            ["inventory_only", "text_check", "text_check", "text_check"],
        )

    def test_internal_artifact_kind_cannot_be_injected_into_a_feed(self):
        data = encoded(event(kind="local_private_key_material"))
        with self.assertRaisesRegex(InputError, "invalid kind"):
            parse_document(data, "auto", "test.jsonl")

    def test_invalid_file_and_conflicts_do_not_poison_other_files(self):
        self.write("a.jsonl", encoded(event(kind="malware_alert")))
        self.write("b.jsonl", encoded(event(kind="auth_success")))
        self.write("broken.jsonl", encoded(event(event_id="new")) + b"{incomplete\n")
        self.write("valid.jsonl", encoded(event(event_id="valid", kind="malware_alert")))
        result = Run(self.home, self.options, {}).folder(self.root)
        self.assertEqual(len(result["cases"][0]["evidence"]), 1)
        self.assertEqual(result["cases"][0]["evidence"][0]["event_id"], "valid")
        self.assertEqual(result["inventory"]["conflicting_event_ids"], 1)
        self.assertEqual(result["inventory"]["read_errors"], 1)

    def test_skips_symlinks_excluded_tree_and_over_limit_files(self):
        self.write("a.txt", b"note")
        outside = self.root.parent / "outside.txt"
        outside.write_bytes(b"APP_API_KEY=external-fake-secret\n")
        try:
            (self.root / "symlink.txt").symlink_to(outside)
        except OSError:
            self.skipTest("symlink creation not available")
        self.write(".git/secret.txt", b"APP_API_KEY=remote-fake-secret\n")
        self.write("b.txt", b"note")
        result = scan(inventory(self.root, 1))
        self.assertTrue(result.inventory["limit_reached"])
        self.assertEqual([row["path"] for row in result.inventory["files"]], ["a.txt"])
        self.assertFalse(result.batch.evidence)

    def test_folder_live_waits_for_two_matching_reads_and_detects_changes(self):
        self.write("events.jsonl", encoded(event(kind="malware_alert")))
        feed = FolderFeed(self.root, 10)
        self.assertIsNone(feed.poll())
        self.assertEqual(len(feed.poll().batch.evidence), 1)
        self.assertIsNone(feed.poll())
        self.write("new.jsonl", encoded(event(event_id="new", kind="malware_alert")))
        self.assertIsNone(feed.poll())
        self.assertEqual(len(feed.poll().batch.evidence), 2)

    def test_live_never_follows_replaced_root(self):
        feed = FolderFeed(self.root, 2)
        self.root.rename(self.root.parent / "previous")
        self.root.mkdir()
        with self.assertRaisesRegex(InputError, "replaced"):
            feed.poll()

    def test_reports_are_private_and_not_overwritten(self):
        result = Run(self.home, self.options, {}).folder(self.root)
        dest = self.root.parent / "report.json"
        export(result, dest)
        if os.name == "posix":
            self.assertFalse(stat.S_IMODE(dest.stat().st_mode) & 0o077)
        previous = dest.read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            export(result, dest)
        self.assertEqual(dest.read_bytes(), previous)


class LiveTests(unittest.TestCase):
    def test_feed_handles_200_304_and_semantic_duplicates(self):
        base = event(kind="malware_alert")
        body = json.dumps([base]).encode()
        answers = [
            Response(200, body, '"a"'),
            Response(304, b"", '"a"'),
            Response(200, json.dumps(base, indent=2).encode(), '"b"'),
            Response(200, json.dumps([base, event(event_id="fresh", kind="malware_alert")]).encode(), '"c"'),
        ]
        source = JsonFeed(endpoint("http://localhost:49399/events"), token="feed-fixture")
        with patch("secops_harness.live.request", side_effect=answers) as get:
            self.assertEqual(source.poll().batch.evidence[0].position, "record")
            self.assertIsNone(source.poll())
            self.assertIsNone(source.poll())
            self.assertEqual(len(source.poll().batch.evidence), 2)
        self.assertEqual(get.call_args_list[1].kwargs["headers"]["If-None-Match"], '"a"')
        self.assertEqual(get.call_args_list[0].kwargs["headers"]["Authorization"], "Bearer feed-fixture")
        self.assertNotIn("method", get.call_args.kwargs)

    def test_bad_response_keeps_last_good_digest(self):
        source = JsonFeed(endpoint("http://localhost/feed"))
        valid = encoded(event(kind="malware_alert"))
        with patch(
            "secops_harness.live.request",
            side_effect=[
                Response(200, valid, '"good"'),
                Response(200, b"[not JSON", '"bad"'),
            ],
        ):
            source.poll()
            with self.assertRaises(InputError):
                source.poll()
        self.assertEqual(source.etag, '"good"')

    def test_watch_retries_with_one_notice_and_recovers(self):
        source = Mock()
        source.poll.side_effect = [NetworkError("down"), NetworkError("down"), None]
        with patch("secops_harness.live.sleep") as wait:
            self.assertEqual(
                list(watch(source, interval=3, cycles=3)), [(1, None, "down"), (3, None, RECOVERED)]
            )
        self.assertEqual(wait.call_count, 2)


class SetupAndMenuTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.local = Path(temp.name)
        self.home = state_directory(self.local / "state")

    def test_drift_blocks_launch_even_with_valid_toml(self):
        (self.local / "masop.py").write_text(
            '# /// script\n# requires-python = ">=3.11"\n# dependencies = ["not-the-release"]\n# ///\n'
        )
        found = {item.name: item for item in checks(self.local)}
        self.assertFalse(found["App dependencies"].ok)
        self.assertTrue(all(item.ok for item in checks(ROOT)))

    def test_pin_reader_and_osv_findings_use_only_package_info(self):
        manifest = self.local / "pins.txt"
        manifest.write_text("# fixture\nRequests==2.31.0\nrequests==2.31.0\n")
        pins = package_pins(manifest)
        self.assertEqual(pins, [("requests", "2.31.0")])
        with patch("secops_harness.setupcheck.request") as osv:
            osv.return_value = Response(200, b'{"results":[{"vulns":[{"id":"GHSA-example-0000-0000"}]}]}')
            self.assertEqual(audit(pins), {"requests==2.31.0": ["GHSA-example-0000-0000"]})
            self.assertEqual(
                osv.call_args.kwargs["data"],
                {"queries": [{"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}]},
            )
        manifest.write_text("-e git+https://example.invalid/repo\n")
        with self.assertRaises(ValueError):
            package_pins(manifest)

    def test_osv_pages_and_malformed_results_never_claim_clean(self):
        pins = [("package", "1.0")]
        with patch(
            "secops_harness.setupcheck.request",
            side_effect=[
                Response(200, b'{"results":[{"next_page_token":"next"}]}'),
                Response(200, b'{"results":[{"vulns":[{"id":"PYSEC-2026-10"}]}]}'),
            ],
        ) as osv:
            self.assertEqual(audit(pins), {"package==1.0": ["PYSEC-2026-10"]})
            self.assertEqual(osv.call_args.kwargs["data"]["queries"][0]["page_token"], "next")
        with (
            patch("secops_harness.setupcheck.request", return_value=Response(200, b'{"results":[]}')),
            self.assertRaises(NetworkError),
        ):
            audit(pins)
        with patch("secops_harness.setupcheck.request") as osv:
            self.assertEqual(audit([]), {})
            osv.assert_not_called()

    def test_lock_manifest_uses_registry_pins_and_skips_local_project(self):
        path = self.local / "uv.lock"
        path.write_text(
            'version = 1\n[[package]]\nname = "root"\nsource = { virtual = "." }\n'
            '[[package]]\nname = "abc"\nversion = "1.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        )
        self.assertEqual(package_pins(path), [("abc", "1.0")])

    def test_config_roundtrip_and_no_session_keys_written(self):
        profile = Profile("work", "openai", "example-model", remote_allowed=True)
        settings = replace(Settings(), profiles={"work": profile}, roles={"triage": "work"})
        console = Console(self.home, settings)
        console.keys["work"] = "dummy-session-key"
        with redirect_stdout(StringIO()):
            console.save(settings)
        self.assertEqual(read_settings(self.home), settings)
        self.assertNotIn("dummy-session-key", (self.home / "config.json").read_text())

    def test_keyboard_interrupt_from_live_menu_returns_to_main(self):
        console = Console(self.home, Settings())
        output = StringIO()
        with (
            redirect_stdout(output),
            patch("builtins.input", side_effect=["4", "0"]),
            patch.object(console, "live", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(console.loop(), 0)
        self.assertIn("Stopped. Back at the main menu.", output.getvalue())
        self.assertIn("1. Configure harness", output.getvalue())
        self.assertIn("4. Launch live analysis", output.getvalue())

    def test_interactive_add_assign_and_persist_local_model(self):
        console = Console(self.home, Settings())
        answers = ["2", "1", "1", "2", "", "", "", "n", "local-model", "", "0", "0"]
        with patch("builtins.input", side_effect=answers), redirect_stdout(StringIO()):
            self.assertEqual(console.loop(), 0)
        self.assertEqual(read_settings(self.home).roles, {"triage": "lmstudio"})
        self.assertEqual(read_settings(self.home).profiles["lmstudio"].model, "local-model")

    def test_standalone_launcher_scan_and_export(self):
        output = self.local / "result.md"
        proc = subprocess.run(
            [
                sys.executable,
                "masop.py",
                "--home",
                str(self.home),
                "scan",
                "examples",
                "--rules-only",
                "--format",
                "json",
                "--report",
                str(output),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["inventory"]["telemetry_files"], 1)
        self.assertIn("## Folder coverage", output.read_text())
