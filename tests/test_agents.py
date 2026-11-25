import json
import os
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from threading import Thread
from unittest.mock import patch

from test_ingest import encoded, event

from secops_harness.agents import MAX_REPLY_BYTES, Adviser, InvalidReply, Ollama, Unavailable, validate_model
from secops_harness.detect import Policy, correlate
from secops_harness.ingest import parse
from secops_harness.report import analyse


class ScriptedBackend:
    def __init__(self, *responses):
        self.responses = iter(responses)
        self.calls = []

    def ask(self, model, system, payload, schema):
        self.calls.append((model, system, payload, schema))
        reply = next(self.responses)
        if isinstance(reply, Exception):
            raise reply
        return reply


def batch():
    return parse(
        BytesIO(
            encoded(
                event(asset="internal-tenant-name", kind="malware_alert"),
                event(
                    asset="internal-tenant-name",
                    event_id="advisory-id",
                    source_ip="192.0.2.3",
                    kind="vulnerability_alert",
                    cve="CVE-2099-12345",
                    severity="high",
                ),
                event(asset="private-endpoint-two", kind="malware_alert"),
            )
        )
    )


def adviser(fake, max_cases=1):
    return Adviser(fake, "analyst:local", "reviewer:local", max_cases=max_cases)


@contextmanager
def server(body, status=200, advertised=None):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append((self.path, request))
            payload = body(request) if callable(body) else body
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            if status == 302:
                self.send_header("Location", "http://127.0.0.1:1/do-not-follow")
            self.send_header("Content-Length", str(len(payload) if advertised is None else advertised))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as http:
        thread = Thread(target=http.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield http.server_port, calls
        finally:
            http.shutdown()
            thread.join(timeout=2)


def completion(content, reason="stop", **message):
    return json.dumps(
        {
            "done": True,
            "done_reason": reason,
            "message": {"role": "assistant", "content": json.dumps(content), **message},
        }
    ).encode()


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.case = correlate(batch().evidence, Policy())[0]

    def test_two_roles_only_receive_the_projection(self):
        stream = ScriptedBackend(
            {"option": "f2:verify_installed_version"},
            {"decision": "accept"},
        )
        result = analyse(batch(), Policy(), adviser(stream))
        self.assertEqual(
            [case["model"]["status"] for case in result["cases"]], ["accepted", "budget_skipped"]
        )
        self.assertEqual(result["cases"][0]["model"]["check"], "verify_installed_version")
        self.assertEqual([call[0] for call in stream.calls], ["analyst:local", "reviewer:local"])
        self.assertEqual(stream.calls[1][2]["finding"]["finding"], "f2")
        self.assertNotIn("findings", stream.calls[1][2])
        for forbidden in (
            "Domain",
            "evt1",
            "advisory-id",
            "internal-tenant-name",
            "192.0.2.3",
            "CVE-2099-12345",
        ):
            self.assertNotIn(forbidden, repr(stream.calls))
        baseline = analyse(batch(), Policy())
        for got, expected in zip(result["cases"], baseline["cases"], strict=True):
            self.assertEqual(
                {k: v for k, v in got.items() if k != "model"},
                {k: v for k, v in expected.items() if k != "model"},
            )

    def test_invented_or_mismatched_citations_are_rejected(self):
        for output in (
            {"option": "f99:verify_endpoint_detection"},
            {"option": "f1:check_patch_plan"},
            {"option": "f1:verify_endpoint_detection", "decision": "ignore evidence"},
            {"option": None},
        ):
            with self.subTest(output=output):
                fake = ScriptedBackend(output)
                self.assertEqual(adviser(fake).advise(self.case)["status"], "invalid_proposal")
                self.assertEqual(len(fake.calls), 1)

    def test_review_cannot_swap_evidence(self):
        fake = ScriptedBackend(
            {"option": "f1:verify_endpoint_detection"},
            {"decision": "accept", "finding": "f2"},
        )
        self.assertEqual(adviser(fake).advise(self.case)["status"], "invalid_review")

    def test_old_contradictory_review_is_not_accepted(self):
        fake = ScriptedBackend(
            {"option": "f2:verify_installed_version"},
            {"verdict": "accept", "finding": "f2", "context": "software_inventory"},
        )
        output = adviser(fake).advise(self.case)
        self.assertEqual(output["status"], "invalid_review")
        self.assertIn("contract", output["detail"])
        self.assertEqual(
            set(fake.calls[1][3]["properties"]["decision"]["enum"]),
            {"accept", "need_asset_context", "need_software_inventory"},
        )

    def test_review_context_withholds_proposal(self):
        fake = ScriptedBackend(
            {"option": "f1:verify_endpoint_detection"},
            {"decision": "need_alert_confirmation"},
        )
        output = adviser(fake).advise(self.case)
        self.assertEqual(output["status"], "needs_context")
        self.assertNotIn("check", output)

    def test_unavailable_backend_circuit_breaker_preserves_rules(self):
        fake = ScriptedBackend(Unavailable("not running"))
        cases = analyse(batch(), Policy(), adviser(fake, max_cases=5))["cases"]
        self.assertEqual(
            [case["model"]["status"] for case in cases], ["model_unavailable", "backend_skipped"]
        )
        self.assertEqual([case["severity"] for case in cases], ["high", "high"])
        self.assertEqual(len(fake.calls), 1)

    def test_cloud_designations_rejected(self):
        for name in ("model:70b-cloud", "model-cloud", "cloud/model", "https://remote"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate_model(name)
        self.assertEqual(validate_model("qwen2.5:3b"), "qwen2.5:3b")

    def test_ollama_wire_contract_ignores_proxy_environment(self):
        with (
            server(completion({"finding": "f1"})) as (port, calls),
            patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}),
        ):
            self.assertEqual(Ollama(port).ask("demo", "system", {"safe": True}, {}), {"finding": "f1"})
        request_path, request = calls[0]
        self.assertEqual(request_path, "/api/chat")
        self.assertIs(request["stream"], False)
        self.assertNotIn("tools", request)
        self.assertEqual(json.loads(request["messages"][1]["content"]), {"safe": True})

    def test_reject_incomplete_tool_calls_and_oversize(self):
        for body in (
            completion({"finding": "f1"}, reason="length"),
            completion({}, tool_calls=[{"function": {"name": "unavailable"}}]),
            b" " * (MAX_REPLY_BYTES + 1),
            b'{"done":true,"done":false}',
        ):
            with self.subTest(body=body[:20]), server(body) as (port, _), self.assertRaises(InvalidReply):
                Ollama(port).ask("demo", "system", {}, {})

    def test_does_not_follow_redirects(self):
        with server(b"", status=302) as (port, calls), self.assertRaises(Unavailable):
            Ollama(port).ask("demo", "system", {}, {})
        self.assertEqual(len(calls), 1)

    def test_reject_advertised_but_missing_bytes_even_for_valid_json(self):
        body = completion({"finding": "f1"})
        with (
            server(body, advertised=len(body) + 1) as (port, _),
            self.assertRaisesRegex(InvalidReply, "incomplete"),
        ):
            Ollama(port).ask("demo", "system", {}, {})

    def test_both_roles_end_to_end_through_local_http(self):
        def answer(request):
            if request["model"] == "analyst:local":
                return completion({"option": "f1:verify_endpoint_detection"})
            return completion({"decision": "accept"})

        with server(answer) as (port, calls):
            result = analyse(batch(), Policy(), Adviser(Ollama(port), "analyst:local", "reviewer:local"))
        self.assertEqual(result["cases"][0]["model"]["status"], "accepted")
        self.assertEqual(len(calls), 2)
        self.assertNotIn("internal-tenant-name", repr(calls))
