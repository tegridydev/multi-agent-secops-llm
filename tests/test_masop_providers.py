import json
import os
import socket
import unittest
from io import BytesIO
from unittest.mock import patch

from test_agents import completion, server
from test_ingest import encoded, event

from secops_harness.agents import InvalidReply, Unavailable
from secops_harness.detect import Policy, correlate
from secops_harness.ingest import parse
from secops_harness.providers import Budget, Client, Profile, RoutedAdviser, _answer, _body, discover
from secops_harness.transport import NetworkError, Response, _safe_ips, endpoint


def fixture(dialect, obj):
    text = json.dumps(obj)
    if dialect == "ollama":
        return json.loads(completion(obj))
    if dialect == "chat":
        return {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": text}}]}
    if dialect == "responses":
        return {
            "status": "completed",
            "output": [
                {"type": "reasoning"},
                {
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": text}],
                },
            ],
        }
    if dialect == "messages":
        return {"role": "assistant", "stop_reason": "end_turn", "content": [{"type": "text", "text": text}]}
    return {"candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": text}]}}]}


class ProviderTests(unittest.TestCase):
    def test_current_preset_urls_and_model_formats(self):
        expected = {
            "openai": ("api.openai.com", "/v1/responses"),
            "anthropic": ("api.anthropic.com", "/v1/messages"),
            "gemini": ("generativelanguage.googleapis.com", "/v1beta/models/test:generateContent"),
            "groq": ("api.groq.com", "/openai/v1/chat/completions"),
            "together": ("api.together.ai", "/v1/chat/completions"),
            "openrouter": ("openrouter.ai", "/api/v1/chat/completions"),
            "xai": ("api.x.ai", "/v1/responses"),
        }
        for provider, (host, path) in expected.items():
            with self.subTest(provider=provider):
                profile = Profile("demo", provider, "test", remote_allowed=True)
                self.assertEqual((profile.target().host, profile.target().path), (host, path))
        self.assertEqual(
            Profile("azure", "azure", "test", "https://example.openai.azure.com", remote_allowed=True)
            .target()
            .path,
            "/openai/v1/chat/completions",
        )
        self.assertEqual(
            Profile("custom", "custom-chat", "test", "http://localhost:49000/v1").target().path,
            "/v1/chat/completions",
        )

    def test_hosted_profile_cannot_change_hosts_or_use_approval_by_default(self):
        for builder in (
            lambda: Profile("demo", "openai", "test"),
            lambda: Profile(
                "demo", "openai", "test", "https://example.com/v1/responses", remote_allowed=True
            ),
            lambda: Profile(
                "azure", "azure", "test", "https://fake-openai.azure.com.example.org", remote_allowed=True
            ),
            lambda: Profile("demo", "ollama", "demo:cloud"),
            lambda: Profile("demo", "ollama", "test", key_env="actual-key-value"),
            lambda: Profile("demo", "gemini", "bad/model:test", remote_allowed=True),
        ):
            with self.subTest(builder=builder), self.assertRaises(ValueError):
                builder()

    def test_credential_header_follows_provider_and_never_selects_another_session_key(self):
        tests = [
            (Profile("anthropic", "anthropic", "test", remote_allowed=True), "Authorization", "Bearer dummy"),
            (Profile("gemini", "gemini", "test", remote_allowed=True), "x-goog-api-key", "dummy"),
            (
                Profile("azure", "azure", "test", "https://example.openai.azure.com", remote_allowed=True),
                "api-key",
                "dummy",
            ),
            (Profile("openai", "openai", "test", remote_allowed=True), "Authorization", "Bearer dummy"),
        ]
        with patch.dict(os.environ, {}, clear=True):
            for profile, header, value in tests:
                with self.subTest(profile=profile.name):
                    self.assertEqual(profile.headers({profile.name: "dummy"})[header], value)
                    with self.assertRaises(Unavailable):
                        profile.headers({"other": "dummy", profile.key_name: "dummy"})

    def test_wire_formats_only_allow_a_complete_tool_free_answer(self):
        for dialect in ("ollama", "chat", "responses", "messages", "gemini"):
            with self.subTest(dialect=dialect):
                self.assertEqual(_answer(dialect, fixture(dialect, {"ok": "yes"})), {"ok": "yes"})
                with self.assertRaises(InvalidReply):
                    _answer(dialect, {"status": "incomplete"})
        altered = fixture("chat", {"ok": "yes"})
        altered["choices"][0]["message"]["tool_calls"] = [{"type": "function"}]
        with self.assertRaises(InvalidReply):
            _answer("chat", altered)
        response = fixture("responses", {"ok": "yes"})
        response["output"].append({"type": "function_call"})
        with self.assertRaises(InvalidReply):
            _answer("responses", response)

    def test_request_contract_no_tools_or_telemetry_fields(self):
        for profile in (
            Profile("native", "ollama", "foo"),
            Profile("compatible", "lmstudio", "foo"),
            Profile("native", "openai", "foo", remote_allowed=True),
            Profile("native", "anthropic", "foo", remote_allowed=True),
            Profile("native", "gemini", "foo", remote_allowed=True),
        ):
            with self.subTest(profile=profile.provider):
                result = _body(profile, "system", {"evidence_count": 3}, {"type": "object"})
                self.assertNotIn("tools", result)
                self.assertIn("evidence_count", str(result))
                if profile.provider == "openai":
                    self.assertFalse(result["store"])
                    self.assertTrue(result["text"]["format"]["strict"])

    def test_model_discovery_checks_only_the_selected_local_server(self):
        with patch("secops_harness.providers.request") as call:
            call.return_value = Response(
                200, b'{"models":[{"name":"valid:3b"},{"name":"test-cloud"},{"name":"\\n"}]}'
            )
            self.assertEqual(discover("ollama", "http://localhost:32100"), ["valid:3b"])
            self.assertEqual(call.call_args.args[0].path, "/api/tags")
            self.assertEqual(discover("ollama", "https://example.com"), [])
            self.assertEqual(call.call_count, 1)

    def test_prefixed_base_urls_keep_their_prefix_for_completion_and_discovery(self):
        prefix = "http://localhost:31234/gateway"
        self.assertEqual(
            Profile("local", "custom-chat", "demo", prefix + "/v1/").target().path,
            "/gateway/v1/chat/completions",
        )
        self.assertEqual(
            Profile("local", "custom-responses", "demo", prefix + "/v1").target().path,
            "/gateway/v1/responses",
        )
        with patch("secops_harness.providers.request") as call:
            call.return_value = Response(200, b'{"data":[{"id":"demo"}]}')
            self.assertEqual(discover("lmstudio", prefix + "/v1/"), ["demo"])
            self.assertEqual(call.call_args.args[0].path, "/gateway/v1/models")
            call.return_value = Response(200, b'{"models":[{"name":"demo:1b"}]}')
            self.assertEqual(discover("ollama", prefix + "/api"), ["demo:1b"])
            self.assertEqual(call.call_args.args[0].path, "/gateway/api/tags")

    def test_routes_delegate_only_safe_facts_to_separate_loopback_profiles(self):
        row = event(
            kind="malware_alert", asset="PRIVATE-ASSET", principal="PRIVATE-USER", source_ip="192.0.2.45"
        )
        (case,) = correlate(parse(BytesIO(encoded(row))).evidence, Policy())
        analyst_answer = json.dumps(fixture("chat", {"option": "f1:verify_endpoint_detection"})).encode()
        review_answer = json.dumps(fixture("chat", {"decision": "accept"})).encode()
        with server(analyst_answer) as (first, a_calls), server(review_answer) as (second, b_calls):
            profiles = {
                "detector": Profile("detector", "custom-chat", "same-id", f"http://127.0.0.1:{first}/v1"),
                "review": Profile("review", "custom-chat", "same-id", f"http://127.0.0.1:{second}/v1"),
            }
            budget = Budget(2)
            routes = RoutedAdviser(profiles, {"endpoint": "detector", "reviewer": "review"}, {}, budget, 4, 2)
            result = routes.advise(case)
            self.assertEqual(result["status"], "accepted")
            self.assertEqual(result["analyst_profile"], "detector")
            self.assertEqual(result["reviewer_profile"], "review")
            self.assertEqual(result["role"], "endpoint")
            self.assertEqual(routes.advise(case)["status"], "session_budget_skipped")
        self.assertEqual((len(a_calls), len(b_calls)), (1, 1))
        self.assertEqual(budget.used, 2)
        for value in ("PRIVATE-ASSET", "PRIVATE-USER", "192.0.2.45", "evt1"):
            self.assertNotIn(value, repr([a_calls, b_calls]))

    def test_bad_reply_has_no_raw_error_body(self):
        profile = Profile("remote", "openai", "test", remote_allowed=True)
        with (
            patch(
                "secops_harness.providers.request", side_effect=NetworkError("endpoint returned HTTP 429")
            ) as call,
            self.assertRaisesRegex(Unavailable, "429"),
        ):
            Client(profile, {"remote": "fake-token"}, Budget(1)).ask("test", "test", {}, {})
        self.assertEqual(call.call_count, 1)


class TransportTests(unittest.TestCase):
    def test_no_cleartext_to_network_or_secret_url_components(self):
        for url in (
            "http://192.168.1.3/api",
            "https://user:pass@example.com/a",
            "https://example.com/a?key=1",
            "https://example.com/a#fragment",
            "https://example.com/%0a",
            "https://example.com/a/../b",
            "https://example.com:0/path",
            "file:///etc/hosts",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                endpoint(url)
        self.assertTrue(endpoint("http://localhost:9050/feed").loopback)

    def test_dns_answers_are_pinned_and_mixed_public_private_answer_is_refused(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        blocked = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443))
        target = endpoint("https://example.com/api")
        with (
            patch("secops_harness.transport.socket.getaddrinfo", return_value=[public, blocked]),
            self.assertRaises(NetworkError),
        ):
            _safe_ips(target, allow_lan=True)
        with patch("secops_harness.transport.socket.getaddrinfo", return_value=[public]):
            self.assertEqual(_safe_ips(target, allow_lan=False), ["8.8.8.8"])
        private = endpoint("https://192.168.1.3/api")
        with self.assertRaises(NetworkError):
            _safe_ips(private, allow_lan=False)
        self.assertEqual(_safe_ips(private, allow_lan=True), ["192.168.1.3"])
