"""Bounded JSONL ingestion. Only explicitly selected fields become evidence."""

import ipaddress
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO

from .domain import Event, Evidence, Kind, Severity, identity, strict_json

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_LINES = 10_000

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,79}", re.ASCII)
_PRINCIPAL = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._@\\$-]{0,79}", re.ASCII)
_EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}", re.ASCII)
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}", re.ASCII)
_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)
_WAZUH_TIMESTAMP = re.compile(r"([+-][0-9]{2})([0-9]{2})$")
_REQUIRED = {"event_id", "source", "asset", "timestamp", "kind"}
_OPTIONAL = {"severity", "principal", "source_ip", "cve"}


class InputError(ValueError):
    """An operator-actionable error that does not echo input content."""


@dataclass(frozen=True, slots=True)
class Batch:
    format: str
    sha256: str
    evidence: tuple[Evidence, ...]
    lines: int
    ignored_rows: int
    blank_rows: int
    duplicate_rows: int


def _token(data: dict[str, Any], field: str, pattern: re.Pattern[str]) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise InputError(f"invalid {field}")
    return value


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise InputError("timestamp must include a date, time and explicit offset")
    try:
        return datetime.fromisoformat(value).astimezone(UTC)
    except (ValueError, OverflowError):
        raise InputError("invalid timestamp") from None


def _ip(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise InputError("invalid source_ip")
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return str(address)
    except ValueError:
        raise InputError("invalid source_ip") from None


def _event(data: dict[str, Any]) -> Event:
    if not _REQUIRED.issubset(data) or data.keys() - (_REQUIRED | _OPTIONAL):
        raise InputError("unexpected or missing event-v1 fields")
    try:
        kind = Kind(data["kind"])
    except (TypeError, ValueError):
        raise InputError("invalid kind") from None
    if kind in (Kind.ARTIFACT_KEY, Kind.ARTIFACT_CREDENTIAL):
        raise InputError("invalid kind")
    try:
        severity = Severity(data.get("severity", Severity.INFO))
    except (TypeError, ValueError):
        raise InputError("invalid severity") from None
    if kind is Kind.VULNERABILITY and "cve" not in data:
        raise InputError("vulnerability alerts require a CVE identifier")
    if kind is not Kind.VULNERABILITY and "cve" in data:
        raise InputError("cve is only allowed on vulnerability alerts")
    return Event(
        event_id=_token(data, "event_id", _EVENT_ID),
        source=_token(data, "source", _TOKEN),
        asset=_token(data, "asset", _TOKEN),
        timestamp=_timestamp(data["timestamp"]),
        kind=kind,
        severity=severity,
        principal=_token(data, "principal", _PRINCIPAL) if "principal" in data else None,
        source_ip=_ip(data["source_ip"]) if "source_ip" in data else None,
        cve=_token(data, "cve", _CVE) if "cve" in data else None,
    )


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _wazuh(data: dict[str, Any]) -> Event | None:
    rule = _mapping(data.get("rule"))
    groups = rule.get("groups")
    level = rule.get("level")
    if type(level) is not int or not 0 <= level <= 16:
        raise InputError("Wazuh rule.level must be an integer from 0 to 16")
    if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups):
        raise InputError("Wazuh rule.groups must be a list of strings")
    severity = (
        Severity.CRITICAL
        if level >= 15
        else Severity.HIGH
        if level >= 12
        else Severity.MEDIUM
        if level >= 7
        else Severity.LOW
        if level >= 3
        else Severity.INFO
    )
    details = _mapping(data.get("data"))
    vuln = _mapping(details.get("vulnerability"))
    is_failure = "authentication_failed" in groups
    is_success = "authentication_success" in groups
    if "vulnerability-detector" in groups:
        kind = Kind.VULNERABILITY
        mapped = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        if not isinstance(vuln.get("severity"), str) or vuln["severity"].lower() not in mapped:
            return None
        # A fixed/resolved state is not an active vulnerability finding.
        status = vuln.get("status")
        if status is not None and (not isinstance(status, str) or status.lower() != "active"):
            return None
        severity = mapped[vuln["severity"].lower()]
    elif is_failure != is_success:
        kind = Kind.AUTH_FAILURE if is_failure else Kind.AUTH_SUCCESS
    elif is_failure and is_success:
        return None
    elif severity in (Severity.HIGH, Severity.CRITICAL):
        kind = Kind.SECURITY
    else:
        return None
    agent_id = _mapping(data.get("agent")).get("id")
    manager = _mapping(data.get("manager")).get("name")
    if not isinstance(agent_id, str) or not re.fullmatch(r"[0-9]{1,12}", agent_id):
        raise InputError("invalid Wazuh agent.id")
    if not isinstance(manager, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,72}", manager):
        raise InputError("invalid Wazuh manager.name")
    time = data.get("timestamp")
    event = {
        "event_id": data.get("id"),
        "source": "wazuh:" + manager,
        "asset": "agent-" + agent_id,
        "timestamp": _WAZUH_TIMESTAMP.sub(r"\1:\2", time) if isinstance(time, str) else time,
        "kind": kind,
        "severity": severity,
    }
    if kind is Kind.VULNERABILITY:
        event["cve"] = vuln.get("cve")
    elif kind in (Kind.AUTH_FAILURE, Kind.AUTH_SUCCESS):
        # Some decoders have no usable user or IP. Do not invent a join key.
        principal = details.get("dstuser") or details.get("srcuser")
        if isinstance(principal, str) and _PRINCIPAL.fullmatch(principal):
            event["principal"] = principal
        with suppress(InputError):
            event["source_ip"] = _ip(details.get("srcip"))
    return _event(event)


def parse(stream: BinaryIO, input_format: str = "event-v1") -> Batch:
    if input_format not in ("event-v1", "wazuh"):
        raise InputError("unknown input format")
    digest = sha256()
    entries: dict[tuple[str, str, str], Evidence] = {}
    size = lines = blank = ignored = duplicates = 0
    while line := stream.readline(MAX_LINE_BYTES + 1):
        lines += 1
        size += len(line)
        if lines > MAX_LINES or size > MAX_INPUT_BYTES or len(line) > MAX_LINE_BYTES:
            raise InputError(f"line {lines}: batch exceeds its line, record or file size limit")
        digest.update(line)
        if not line.strip():
            blank += 1
            continue
        try:
            try:
                data = strict_json(line)
            except (ValueError, RecursionError):
                raise InputError("invalid or ambiguous UTF-8 JSON") from None
            if not isinstance(data, dict):
                raise InputError("expected one JSON object per line")
            event = _event(data) if input_format == "event-v1" else _wazuh(data)
            if event is None:
                ignored += 1
                continue
            key = (event.source, event.asset, event.event_id)
            if (prior := entries.get(key)) is not None:
                if prior.event != event:
                    raise InputError("conflicting reuse of an event_id within the same source and asset")
                duplicates += 1
                continue
            entries[key] = Evidence(identity("e_", event.fields()), lines, event)
        except InputError as error:
            raise InputError(f"line {lines}: {error}") from None
    return Batch(input_format, digest.hexdigest(), tuple(entries.values()), lines, ignored, blank, duplicates)


def load(path: Path, input_format: str) -> Batch:
    # A mistyped FIFO or device must not turn a scheduled batch into a blocking read.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise InputError("input must be a regular file")
        if before.st_size > MAX_INPUT_BYTES:
            raise InputError("input exceeds its file size limit")
        batch = parse(stream, input_format)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise InputError("input changed during read; provide a completed export")
        return batch
