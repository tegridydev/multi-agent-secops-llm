import random
import unittest
from datetime import UTC, datetime, timedelta
from io import BytesIO

from test_ingest import encoded, event

from secops_harness.detect import Policy, correlate
from secops_harness.domain import Rule, Severity
from secops_harness.ingest import parse
from secops_harness.report import analyse, markdown

START = datetime(2026, 11, 25, tzinfo=UTC)


def auth(i, seconds, kind="auth_failure", **fields):
    return event(
        event_id=f"evt{i}", timestamp=(START + timedelta(seconds=seconds)).isoformat(), kind=kind, **fields
    )


def cases(*rows, policy=None):
    return correlate(parse(BytesIO(encoded(*rows))).evidence, policy or Policy())


class DetectionTests(unittest.TestCase):
    def test_burst_includes_exact_boundary_and_citations(self):
        (result,) = cases(*(auth(i, time) for i, time in enumerate([0, 30, 60, 120, 300])))
        self.assertEqual(result.severity, Severity.MEDIUM)
        (finding,) = result.findings
        self.assertEqual(finding.rule, Rule.AUTH_BURST)
        self.assertEqual(len(finding.evidence), 5)

    def test_success_requires_same_scope_user_and_ip(self):
        rows = [auth(i, 15 * i) for i in range(5)]
        ordinary = (
            auth(6, 70, "auth_success", principal="other"),
            auth(7, 71, "auth_success", source_ip="192.0.2.99"),
            auth(8, 72, "auth_success", source="other"),
            auth(9, 73, "auth_success", asset="other"),
        )
        (one,) = cases(*rows, *ordinary)
        self.assertEqual(one.severity, Severity.MEDIUM)
        (two,) = cases(*rows, *ordinary, auth(10, 74, "auth_success"))
        self.assertEqual(two.severity, Severity.HIGH)
        (finding,) = two.findings
        self.assertEqual(finding.rule, Rule.AUTH_SUCCESS_AFTER)
        self.assertEqual(finding.evidence[-1].event.event_id, "evt10")

    def test_same_timestamp_is_not_treated_as_after(self):
        rows = [auth(i, 15 * i) for i in range(5)]
        (one,) = cases(*rows, auth(8, 60, "auth_success"))
        self.assertEqual(one.findings[0].rule, Rule.AUTH_BURST)

    def test_outside_window_and_missing_context(self):
        rows = [auth(i, i * 120) for i in range(5)]
        self.assertEqual(cases(*rows), [])
        without_ip = [{key: value for key, value in row.items() if key != "source_ip"} for row in rows]
        report = analyse(parse(BytesIO(encoded(*without_ip))), Policy())
        self.assertEqual(report["coverage"]["unmatched_auth_context"], 5)
        self.assertIn("does not establish that the asset is clean", markdown(report))

    def test_reordered_input_has_same_case_id(self):
        rows = [auth(i, 15 * i) for i in range(5)]
        (first,) = cases(*rows)
        (second,) = cases(*reversed(rows))
        self.assertEqual(first.case_id, second.case_id)

    def test_changed_policy_gets_different_case_id(self):
        rows = [auth(i, 15 * i) for i in range(5)]
        (first,) = cases(*rows)
        (second,) = cases(*rows, policy=Policy(4, 300))
        self.assertNotEqual(first.case_id, second.case_id)

    def test_groups_alerts_without_calling_them_compromise(self):
        rows = [
            event(event_id="cve1", kind="vulnerability_alert", cve="CVE-2099-12345", severity="critical"),
            event(event_id="cve2", kind="vulnerability_alert", cve="CVE-2099-12345", severity="high"),
            event(event_id="cve3", kind="vulnerability_alert", cve="CVE-2099-55555", severity="medium"),
            event(event_id="detect1", kind="malware_alert", severity="info"),
            event(event_id="rule1", kind="security_alert", severity="high"),
        ]
        (one,) = cases(*rows)
        self.assertEqual(one.severity, Severity.CRITICAL)
        self.assertEqual(
            [(finding.rule, len(finding.evidence)) for finding in one.findings],
            [(Rule.VULNERABILITY, 2), (Rule.MALWARE, 1), (Rule.SECURITY, 1)],
        )
        report = analyse(parse(BytesIO(encoded(*rows))), Policy())
        self.assertIn("not confirmation of compromise", markdown(report))
        evidence = {item["ref"] for item in report["cases"][0]["evidence"]}
        self.assertTrue(all(set(f["evidence_refs"]) <= evidence for f in report["cases"][0]["findings"]))

    def test_sliding_window_matches_small_reference_implementation(self):
        rng = random.Random(123)
        policy = Policy(3, 30)
        for _ in range(200):
            samples = [(rng.randrange(140), rng.choice(("auth_failure", "auth_success"))) for _ in range(35)]
            rows = [auth(i, stamp, kind) for i, (stamp, kind) in enumerate(samples)]
            failures = [stamp for stamp, kind in samples if kind == "auth_failure"]
            best_after = max(
                (
                    sum(0 < stamp - fail <= 30 for fail in failures)
                    for stamp, kind in samples
                    if kind == "auth_success"
                ),
                default=0,
            )
            best_burst = max(
                (sum(0 <= stamp - fail <= 30 for fail in failures) for stamp in failures), default=0
            )
            actual = cases(*rows, policy=policy)
            if best_after >= 3:
                self.assertEqual(actual[0].findings[0].rule, Rule.AUTH_SUCCESS_AFTER)
                self.assertEqual(len(actual[0].findings[0].evidence), best_after + 1)
            elif best_burst >= 3:
                self.assertEqual(actual[0].findings[0].rule, Rule.AUTH_BURST)
                self.assertEqual(len(actual[0].findings[0].evidence), best_burst)
            else:
                self.assertEqual(actual, [])
