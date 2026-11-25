import ssl
import unittest
from unittest.mock import MagicMock, patch

from secops_harness.setupcheck import OSV, audit, osv_proxy
from secops_harness.transport import NetworkError, Response, connect_proxy, endpoint, request


class AuditRoutingTests(unittest.TestCase):
    def test_configured_proxy_bypass_and_direct_opt_out(self):
        with (
            patch(
                "secops_harness.setupcheck.getproxies", return_value={"https": "http://proxy.office:8080"}
            ) as probes,
            patch("secops_harness.setupcheck.proxy_bypass", return_value=False) as bypass,
        ):
            self.assertIsNone(osv_proxy(direct=True))
            probes.assert_not_called()
            self.assertEqual(osv_proxy().authority, "proxy.office:8080")
            bypass.assert_called_once_with("api.osv.dev")
            bypass.return_value = True
            self.assertIsNone(osv_proxy())
            self.assertEqual(probes.call_count, 1)

    def test_only_original_https_host_is_tunnelled_with_tls_verification(self):
        value = MagicMock()
        response = value.getresponse.return_value.__enter__.return_value
        response.status, response.length = 200, 0
        response.getheader.return_value = None
        response.read.return_value = b'{"results":[{}]}'
        proxy = connect_proxy("http://localhost:49234")
        with patch("secops_harness.transport.http.client.HTTPSConnection", return_value=value) as dial:
            result = audit([("demo", "1.0")], proxy=proxy)
        self.assertEqual(result, {"demo==1.0": []})
        self.assertEqual(dial.call_args.args, ("127.0.0.1", 49234))
        tls = dial.call_args.kwargs["context"]
        self.assertTrue(tls.check_hostname)
        self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)
        value.set_tunnel.assert_called_once_with("api.osv.dev", 443)
        self.assertEqual(value.request.call_args.args, ("POST", "/v1/querybatch"))
        self.assertEqual(value.request.call_args.kwargs["headers"]["Host"], "api.osv.dev")
        self.assertNotIn("Authorization", value.request.call_args.kwargs["headers"])

    def test_proxy_requires_plain_connect_address_and_https_destination(self):
        for invalid in (
            "http://user:pass@proxy:88",
            "http://proxy/path",
            "https://proxy:88",
            "http://proxy?q=a",
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "HTTP CONNECT"):
                connect_proxy(invalid)
        with self.assertRaises(ValueError):
            request(endpoint("http://localhost/alerts"), proxy=connect_proxy("http://localhost:8700"))

    def test_uncertain_osv_payload_is_never_reported_clean(self):
        for raw in (
            b'{"results":[{"error":"service error"}]}',
            b'{"results":[{"next_page_token":0}]}',
            b'{"results":[{"next_page_token":null}]}',
            b'{"results":[{"vulns":null}]}',
        ):
            with (
                self.subTest(raw=raw),
                patch("secops_harness.setupcheck.request", return_value=Response(200, raw)),
                self.assertRaises(NetworkError),
            ):
                audit([("demo", "1.0")])
        with (
            patch(
                "secops_harness.setupcheck.request",
                return_value=Response(200, b'{"results":[{"next_page_token":"repeats"}]}'),
            ) as call,
            self.assertRaises(NetworkError),
        ):
            audit([("demo", "1.0")])
        self.assertEqual(call.call_count, 2)
        self.assertEqual(call.call_args.args[0], OSV)
