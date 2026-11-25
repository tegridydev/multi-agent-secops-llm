"""Typed evidence, canonical JSON and the deterministic identifiers it supports."""

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Any


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


class Kind(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    MALWARE = "malware_alert"
    VULNERABILITY = "vulnerability_alert"
    SECURITY = "security_alert"
    ARTIFACT_KEY = "local_private_key_material"
    ARTIFACT_CREDENTIAL = "local_plaintext_credential"


class Rule(StrEnum):
    AUTH_BURST = "auth_failure_burst"
    AUTH_SUCCESS_AFTER = "auth_success_after_failures"
    MALWARE = "reported_malware_alert"
    VULNERABILITY = "reported_vulnerability"
    SECURITY = "reported_security_alert"
    ARTIFACT_KEY = "possible_private_key_file"
    ARTIFACT_CREDENTIAL = "possible_hardcoded_credential"


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    source: str
    asset: str
    timestamp: datetime
    kind: Kind
    severity: Severity
    principal: str | None = None
    source_ip: str | None = None
    cve: str | None = None

    def fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "event_id": self.event_id,
            "source": self.source,
            "asset": self.asset,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "kind": self.kind,
            "severity": self.severity,
        }
        for key in ("principal", "source_ip", "cve"):
            if (value := getattr(self, key)) is not None:
                fields[key] = value
        return fields


@dataclass(frozen=True, slots=True)
class Evidence:
    ref: str
    line: int
    event: Event
    origin: str | None = None
    input_sha256: str | None = None
    position: str = "line"

    def public_dict(self) -> dict[str, Any]:
        row = {"ref": self.ref, "line": self.line, **self.event.fields()}
        if self.origin is not None:
            row.update(origin=self.origin, input_sha256=self.input_sha256, position=self.position)
        return row


@dataclass(frozen=True, slots=True)
class Finding:
    rule: Rule
    severity: Severity
    evidence: tuple[Evidence, ...]


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    source: str
    asset: str
    severity: Severity
    findings: tuple[Finding, ...]


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def identity(prefix: str, value: Any) -> str:
    return prefix + sha256(canonical_json(value).encode("ascii")).hexdigest()


def strict_json(value: str | bytes) -> Any:
    """Reject duplicate keys and non-finite numbers at every nesting level."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        obj: dict[str, Any] = {}
        for key, item in pairs:
            if key in obj:
                raise ValueError("duplicate JSON field")
            obj[key] = item
        return obj

    def invalid_constant(_: str) -> Any:
        raise ValueError("non-finite JSON number")

    def finite_float(text: str) -> float:
        number = float(text)
        if number in (float("inf"), float("-inf")):
            raise ValueError("non-finite JSON number")
        return number

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(
        value, object_pairs_hook=unique_object, parse_constant=invalid_constant, parse_float=finite_float
    )
