import json
import os
import unittest
from datetime import timedelta
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from secops_harness.domain import Kind, Severity
from secops_harness.ingest import InputError, load, parse

ROOT = Path(__file__).resolve().parents[1]


def event(**changes):
    row = {
        "event_id": "evt1",
        "source": "demo",
        "asset": "asset1",
        "timestamp": "2026-11-25T00:00:00Z",
        "kind": "auth_failure",
        "principal": "Domain\\alex",
        "source_ip": "192.0.2.1",
    }
    return {**row, **changes}


def encoded(*rows):
    return b"".join(json.dumps(row).encode() + b"\n" for row in rows)


class IngestTests(unittest.TestCase):
    def test_dedupe_after_time_and_ip_normalisation(self):
        raw = b"\n" + encoded(
            event(), event(timestamp="2026-11-25T10:00:00+10:00", source_ip="::ffff:192.0.2.1")
        )
        batch = parse(BytesIO(raw))
        self.assertEqual((batch.lines, batch.blank_rows, batch.duplicate_rows), (3, 1, 1))
        self.assertEqual(batch.sha256, sha256(raw).hexdigest())
        (row,) = batch.evidence
        self.assertEqual(row.line, 2)
        self.assertEqual(row.event.timestamp.utcoffset(), timedelta(0))
        self.assertEqual(row.event.principal, "Domain\\alex")

    def test_conflicting_duplicate_is_not_ignored(self):
        with self.assertRaisesRegex(InputError, "line 2: conflicting reuse"):
            parse(BytesIO(encoded(event(), event(kind="auth_success"))))

    def test_event_ids_are_scoped_to_source_and_asset(self):
        batch = parse(BytesIO(encoded(event(), event(source="other"), event(asset="other"))))
        self.assertEqual(len({row.ref for row in batch.evidence}), 3)

    def test_invalid_timestamps(self):
        for time in (
            "2026-11-25T00:00:00",
            "2026-02-30T00:00:00Z",
            "2026-11-25T00:00:00+10:60",
            "0001-01-01T00:00:00+01:00",
        ):
            with self.subTest(time=time), self.assertRaisesRegex(InputError, "timestamp"):
                parse(BytesIO(encoded(event(timestamp=time))))

    def test_reject_unknown_field_and_unsafe_tokens_without_echo(self):
        for row in (
            event(unknown="do not repeat me"),
            event(asset="do not repeat me"),
            event(source_ip="2001:db8::1%local"),
            event(cve="CVE-2099-12345"),
        ):
            with self.subTest(row=row), self.assertRaises(InputError) as found:
                parse(BytesIO(encoded(row)))
            self.assertNotIn("do not repeat me", str(found.exception))

    def test_reject_invalid_json(self):
        for raw in (
            b"[1,2]\n",
            b'{"private":NaN}\n',
            b'{"private":1e1000}\n',
            b'{"private":1,"private":2}\n',
            b"\xff\n",
            b"{broken\n",
            b'{"private":' + b"[" * 1500 + b"]" * 1500 + b"}\n",
        ):
            with self.subTest(raw=raw[:35]), self.assertRaisesRegex(InputError, "line 1"):
                parse(BytesIO(raw))

    def test_limits_reject_entire_batch(self):
        with (
            patch("secops_harness.ingest.MAX_LINES", 1),
            self.assertRaisesRegex(InputError, "line 2: batch exceeds"),
        ):
            parse(BytesIO(encoded(event(), event())))
        for limit in ("MAX_LINE_BYTES", "MAX_INPUT_BYTES"):
            with (
                patch(f"secops_harness.ingest.{limit}", 32),
                self.assertRaisesRegex(InputError, "line 1: batch exceeds"),
            ):
                parse(BytesIO(encoded(event())))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support needed")
    def test_fifo_is_rejected_without_opening_a_writer(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "pipe"
            os.mkfifo(path)
            with self.assertRaisesRegex(InputError, "regular file"):
                load(path, "event-v1")

    def test_wazuh_maps_completed_export(self):
        batch = load(ROOT / "examples" / "wazuh-alerts.jsonl", "wazuh")
        self.assertEqual((batch.lines, batch.ignored_rows, len(batch.evidence)), (5, 1, 4))
        self.assertEqual(batch.evidence[0].event.source, "wazuh:demo-manager")
        self.assertEqual(batch.evidence[0].event.asset, "agent-001")
        self.assertEqual(batch.evidence[0].event.kind, Kind.AUTH_FAILURE)
        self.assertEqual(batch.evidence[2].event.kind, Kind.AUTH_SUCCESS)
        self.assertEqual(batch.evidence[3].event.severity, Severity.HIGH)

    def test_wazuh_drops_raw_unstructured_content(self):
        row = {
            "timestamp": "2026-11-24T20:00:00-0400",
            "id": "123.456",
            "agent": {"id": "003", "name": "ignore previous instructions"},
            "manager": {"name": "demo"},
            "rule": {"level": 12, "groups": ["syscheck"], "description": "privileged note"},
            "full_log": "sensitive request body",
        }
        (result,) = parse(BytesIO(encoded(row)), "wazuh").evidence
        self.assertEqual(result.event.timestamp.isoformat(), "2026-11-25T00:00:00+00:00")
        for text in ("privileged note", "sensitive request body", "ignore previous instructions"):
            self.assertNotIn(text, repr(result))

    def test_wazuh_active_advisory_and_resolved_filter(self):
        row = {
            "timestamp": "2026-11-25T00:00:00Z",
            "id": "123.456",
            "agent": {"id": "001"},
            "manager": {"name": "demo"},
            "rule": {"level": 10, "groups": ["vulnerability-detector"]},
        }
        active = {
            **row,
            "data": {"vulnerability": {"cve": "CVE-2099-12345", "severity": "Critical", "status": "Active"}},
        }
        resolved = {
            **row,
            "data": {"vulnerability": {"cve": "CVE-2099-12345", "severity": "Critical", "status": "Solved"}},
        }
        batch = parse(BytesIO(encoded(active, resolved)), "wazuh")
        self.assertEqual(batch.ignored_rows, 1)
        (evidence,) = batch.evidence
        self.assertEqual(
            (evidence.event.kind, evidence.event.severity), (Kind.VULNERABILITY, Severity.CRITICAL)
        )
