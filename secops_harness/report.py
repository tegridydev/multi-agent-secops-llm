"""One report contract, with full JSON evidence and a human-readable rendering."""

import json
from typing import Any

from . import __version__
from .agents import CHECKS, CONTEXT_CHECKS, FINDING_CHECKS, Advice
from .detect import Policy, correlate
from .domain import Case, Kind, Rule
from .ingest import Batch

TITLES = {
    Rule.AUTH_BURST: "Repeated authentication failures",
    Rule.AUTH_SUCCESS_AFTER: "Successful login after repeated failures",
    Rule.MALWARE: "Upstream malware alert",
    Rule.VULNERABILITY: "Reported high or critical vulnerability",
    Rule.SECURITY: "Upstream high or critical security alert",
    Rule.ARTIFACT_KEY: "Possible private key material",
    Rule.ARTIFACT_CREDENTIAL: "Possible hardcoded credential",
}


def _case(case: Case, batch: Batch, adviser: Advice | None) -> dict[str, Any]:
    evidence = {row.ref: row for finding in case.findings for row in finding.evidence}
    return {
        "case_id": case.case_id,
        "asset": case.asset,
        "source": case.source,
        "severity": case.severity,
        "input_sha256": batch.sha256,
        "input_format": batch.format,
        "findings": [
            {
                "id": f"f{number}",
                "rule": item.rule,
                "title": TITLES[item.rule],
                "severity": item.severity,
                "evidence_refs": [row.ref for row in item.evidence],
                "checks": [{"code": check, "text": CHECKS[check]} for check in FINDING_CHECKS[item.rule]],
            }
            for number, item in enumerate(case.findings, 1)
        ],
        "evidence": [
            row.public_dict()
            for row in sorted(evidence.values(), key=lambda row: (row.event.timestamp, row.ref))
        ],
        "model": adviser.advise(case) if adviser else {"status": "disabled"},
    }


def analyse(batch: Batch, policy: Policy, adviser: Advice | None = None) -> dict[str, Any]:
    cases = correlate(batch.evidence, policy)
    return {
        "schema_version": 1,
        "harness_version": __version__,
        "policy": policy.fields(),
        "input": {"format": batch.format, "sha256": batch.sha256},
        "coverage": {
            "lines": batch.lines,
            "events": len(batch.evidence),
            "ignored_rows": batch.ignored_rows,
            "blank_rows": batch.blank_rows,
            "duplicate_rows": batch.duplicate_rows,
            "unmatched_auth_context": sum(
                row.event.kind in (Kind.AUTH_FAILURE, Kind.AUTH_SUCCESS)
                and (row.event.principal is None or row.event.source_ip is None)
                for row in batch.evidence
            ),
        },
        "cases": [_case(case, batch, adviser) for case in cases],
    }


def _code(text: str) -> str:
    # Ticks, HTML and Unicode control characters cannot enter these fields through the adapters.
    return f"`{text}`"


def _location(event: dict[str, Any]) -> str:
    if "origin" not in event:
        return f"line {event['line']}"
    safe = json.dumps(event["origin"], ensure_ascii=True)[1:-1].replace(chr(96), "\\u0060")
    return f"{_code(safe)} {event['position']} {event['line']}"


def markdown(report: dict[str, Any]) -> str:
    coverage = report["coverage"]
    policy = report["policy"]
    lines = [
        "# SecOps triage brief",
        "",
        f"Input {_code(report['input']['format'])} · SHA256 {_code(report['input']['sha256'])}",
        f"Policy {_code(policy['version'])} · {policy['auth_failures']} failures within {policy['window_seconds']} s",
        "",
        f"{len(report['cases'])} cases from {coverage['events']} unique events "
        f"({coverage['lines']} lines · duplicates {coverage['duplicate_rows']} · "
        f"out of scope {coverage['ignored_rows']} · blank {coverage['blank_rows']}).",
        f"Authentication events missing a usable user or source IP: {coverage['unmatched_auth_context']}.",
        "",
        "Severity is review priority. Findings are signals, not confirmation of compromise.",
    ]
    if "queue" in report:
        queue = report["queue"]
        lines += ["", f"Review queue: {queue['new_cases']} new, {queue['existing_cases']} already recorded."]
    if not report["cases"]:
        lines += [
            "",
            "No selected rules matched this batch. This does not establish that the asset is clean.",
        ]
    for case in report["cases"]:
        lines += ["", f"## {case['severity'].upper()} · {_code(case['asset'])}", ""]
        lines += [f"Source {_code(case['source'])} · case {_code(case['case_id'])}", ""]
        events = {event["ref"]: event for event in case["evidence"]}
        for finding in case["findings"]:
            refs = finding["evidence_refs"]
            sample = ", ".join(_location(events[ref]) for ref in refs[:4])
            omitted = f", +{len(refs) - 4} more in JSON" if len(refs) > 4 else ""
            cve = events[refs[0]].get("cve")
            label = finding["title"] + (f" ({_code(cve)})" if cve else "")
            lines.append(f"- **{finding['id']} · {label}** · {finding['severity']} · {sample}{omitted}")
            lines.append(f"  - {finding['checks'][0]['text']}")
        model = case["model"]
        if model["status"] == "accepted":
            lines += ["", f"Model suggested first check ({model['finding']}) — {CHECKS[model['check']]}"]
        elif model["status"] == "needs_context":
            lines += [
                "",
                f"Model reviewer requested context ({model['finding']}) — {CONTEXT_CHECKS[model['context']]}",
            ]
        elif model["status"] != "disabled":
            lines += ["", f"Model did not add a check ({_code(model['status'])})."]
    return "\n".join(lines) + "\n"
