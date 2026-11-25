"""Rules establish the queue and its severity. Models never enter this module."""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from .domain import SEVERITY_RANK, Case, Evidence, Finding, Kind, Rule, Severity, identity

POLICY_VERSION = "rules-v1"


@dataclass(frozen=True, slots=True)
class Policy:
    auth_failures: int = 5
    window_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self.auth_failures) is not int or not 2 <= self.auth_failures <= 50:
            raise ValueError("auth threshold must be between 2 and 50")
        if type(self.window_seconds) is not int or not 30 <= self.window_seconds <= 3600:
            raise ValueError("auth window must be between 30 and 3600 seconds")

    def fields(self) -> dict[str, str | int]:
        return {
            "version": POLICY_VERSION,
            "auth_failures": self.auth_failures,
            "window_seconds": self.window_seconds,
        }


def _auth_evidence(rows: list[Evidence], policy: Policy) -> Finding | None:
    """One strongest episode per user/IP on an asset, using two moving indices."""
    window = timedelta(seconds=policy.window_seconds)
    failures = [row for row in rows if row.event.kind is Kind.AUTH_FAILURE]
    left = right = 0
    best_after: tuple[int, int, Evidence] | None = None
    for success in (row for row in rows if row.event.kind is Kind.AUTH_SUCCESS):
        time = success.event.timestamp
        while right < len(failures) and failures[right].event.timestamp < time:
            right += 1
        while left < right and time - failures[left].event.timestamp > window:
            left += 1
        if right - left >= policy.auth_failures and (
            best_after is None or right - left > best_after[1] - best_after[0]
        ):
            best_after = (left, right, success)
    if best_after is not None:
        start, end, success = best_after
        return Finding(Rule.AUTH_SUCCESS_AFTER, Severity.HIGH, (*failures[start:end], success))

    left = best_start = best_end = 0
    for right, failure in enumerate(failures):
        while failure.event.timestamp - failures[left].event.timestamp > window:
            left += 1
        if right + 1 - left > best_end - best_start:
            best_start, best_end = left, right + 1
    if best_end - best_start >= policy.auth_failures:
        return Finding(Rule.AUTH_BURST, Severity.MEDIUM, tuple(failures[best_start:best_end]))
    return None


def correlate(evidence: tuple[Evidence, ...], policy: Policy) -> list[Case]:
    per_asset: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for row in evidence:
        per_asset[row.event.source, row.event.asset].append(row)

    cases: list[Case] = []
    for (source, asset), rows in per_asset.items():
        auth: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
        alerts: dict[tuple[Rule, str], list[Evidence]] = defaultdict(list)
        for row in sorted(rows, key=lambda row: (row.event.timestamp, row.ref)):
            event = row.event
            if event.kind in (Kind.AUTH_FAILURE, Kind.AUTH_SUCCESS):
                if event.principal is not None and event.source_ip is not None:
                    auth[event.principal, event.source_ip].append(row)
            elif event.kind is Kind.MALWARE:
                alerts[Rule.MALWARE, ""].append(row)
            elif event.kind is Kind.ARTIFACT_KEY:
                alerts[Rule.ARTIFACT_KEY, ""].append(row)
            elif event.kind is Kind.ARTIFACT_CREDENTIAL:
                alerts[Rule.ARTIFACT_CREDENTIAL, ""].append(row)
            elif SEVERITY_RANK[event.severity] >= SEVERITY_RANK[Severity.HIGH]:
                rule = Rule.VULNERABILITY if event.kind is Kind.VULNERABILITY else Rule.SECURITY
                alerts[rule, event.cve or ""].append(row)
        findings = [item for group in auth.values() if (item := _auth_evidence(group, policy)) is not None]
        for (rule, _), group in alerts.items():
            severity = max((row.event.severity for row in group), key=SEVERITY_RANK.__getitem__)
            if rule is Rule.MALWARE and SEVERITY_RANK[severity] < SEVERITY_RANK[Severity.HIGH]:
                severity = Severity.HIGH
            findings.append(Finding(rule, severity, tuple(group)))
        if not findings:
            continue
        findings.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.rule, item.evidence[0].ref))
        case_id = identity(
            "c_",
            [
                policy.fields(),
                source,
                asset,
                [[finding.rule, [row.ref for row in finding.evidence]] for finding in findings],
            ],
        )
        cases.append(Case(case_id, source, asset, findings[0].severity, tuple(findings)))
    return sorted(cases, key=lambda case: (-SEVERITY_RANK[case.severity], case.source, case.asset))
