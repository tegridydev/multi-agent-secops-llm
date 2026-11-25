"""Bounded, read-only directory analysis. Raw file contents stay local."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from .domain import Event, Evidence, Kind, Severity, canonical_json, identity, strict_json
from .ingest import MAX_INPUT_BYTES, MAX_LINE_BYTES, MAX_LINES, Batch, InputError, parse

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    ".masop",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
}
FEED_EXTENSIONS = {".json", ".jsonl", ".ndjson"}
TEXT_EXTENSIONS = {
    ".env",
    ".txt",
    ".log",
    ".md",
    ".yml",
    ".yaml",
    ".ini",
    ".toml",
    ".conf",
    ".cfg",
    ".xml",
    ".json",
    ".jsonl",
    ".ndjson",
    ".csv",
    ".properties",
    ".py",
    ".js",
    ".ts",
    ".sh",
    ".ps1",
    ".pem",
    ".key",
    ".crt",
}
MAX_TEXT = 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MAX_DEPTH = 24
_SIGNAL_LIMIT = 20
_PEM = re.compile(r"^\s*-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s*$")
_ASSIGNMENT = re.compile(
    r"""^\s*(?:export\s+)?["']?(?:[A-Za-z0-9]+[_-])*(?:api[_-]?key|password|client[_-]?secret|access[_-]?token)["']?\s*[:=]\s*["']?([^\s"'#,;]{8,200})(?=["'\s,;#]|$)""",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"(?i)^(?:example|dummy|replace|placeholder|change[_-]?me|your[_-]|not[_-]a[_-]|redacted|process\.env|os\.environ|os\.getenv|vault[:/]|secret[:/])"
)


@dataclass(frozen=True, slots=True)
class Entry:
    relative: Path
    stamp: tuple[int, int, int, int, int]
    size: int
    modified: float


@dataclass(frozen=True, slots=True)
class Inventory:
    root: Path
    entries: tuple[Entry, ...]
    limited: bool
    ignored: int
    errors: int


@dataclass(frozen=True, slots=True)
class DirectoryResult:
    batch: Batch
    inventory: dict[str, Any]


def _stamp(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _junction(path: Path) -> bool:
    check = getattr(os.path, "isjunction", None)
    if check:
        return check(path)
    if os.name == "nt":
        # Python 3.11 on Windows has reparse attributes but no os.path.isjunction.
        return bool(getattr(path.lstat(), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    return False


def inventory(folder: Path, max_files: int, exclude: tuple[Path, ...] = ()) -> Inventory:
    root = folder.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise InputError("choose a directory, not a file")
    omitted = {path.expanduser().resolve() for path in exclude}
    if root in omitted:
        raise InputError("choose a data folder rather than MASOP's own state or report folder")
    files = []
    ignored = errors = visits = 0
    limited = False
    stack = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            if directory.is_symlink() or _junction(directory) or directory.resolve(strict=True) != directory:
                ignored += 1
                continue
            with os.scandir(directory) as entries:
                candidates = []
                for item in entries:
                    visits += 1
                    if visits > max(2000, max_files * 8):
                        limited = True
                        break
                    candidates.append(item)
                for item in sorted(candidates, key=lambda child: child.name):
                    absolute = Path(item.path)
                    try:
                        if absolute in omitted or item.is_symlink() or _junction(absolute):
                            ignored += 1
                            continue
                        info = item.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            if item.name in SKIP_DIRS or depth >= MAX_DEPTH:
                                ignored += 1
                            else:
                                stack.append((absolute, depth + 1))
                        elif stat.S_ISREG(info.st_mode):
                            if len(files) == max_files:
                                limited = True
                                break
                            files.append(
                                Entry(absolute.relative_to(root), _stamp(info), info.st_size, info.st_mtime)
                            )
                        else:
                            ignored += 1
                    except OSError:
                        errors += 1
        except (OSError, RuntimeError):
            errors += 1
        if limited:
            break
    return Inventory(
        root, tuple(sorted(files, key=lambda value: value.relative.as_posix())), limited, ignored, errors
    )


def _open_file(root: Path, relative: Path) -> int:
    flags = (
        os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    )
    if os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"):
        # Pin each directory component, so replacing it with a symlink mid-scan cannot escape the root.
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        handle = os.open(root, directory_flags)
        try:
            for part in relative.parts[:-1]:
                child = os.open(part, directory_flags, dir_fd=handle)
                os.close(handle)
                handle = child
            return os.open(relative.name, flags, dir_fd=handle)
        finally:
            os.close(handle)
    path = root / relative
    if path.resolve(strict=True) != path or path.is_symlink():
        raise InputError("file moved or became a link")
    return os.open(path, flags)


def _read(entry: Entry, root: Path, maximum: int) -> bytes:
    fd = _open_file(root, entry.relative)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or _stamp(info) != entry.stamp:
            raise InputError("file changed before reading; try again on a completed export")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(64 * 1024, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > maximum or _stamp(os.fstat(fd)) != entry.stamp:
            raise InputError("file exceeded its limit or changed while being read")
        return bytes(data)
    finally:
        os.close(fd)


def _format(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    if {"event_id", "source", "asset", "timestamp", "kind"} <= value.keys():
        return "event-v1"
    if {"id", "timestamp", "rule", "agent", "manager"} <= value.keys():
        return "wazuh"
    return None


def _encoded_rows(rows: list[Any]) -> bytes:
    if len(rows) > MAX_LINES:
        raise InputError("JSON document exceeds the record limit")
    output = BytesIO()
    for row in rows:
        encoded = canonical_json(row).encode("ascii") + b"\n"
        if len(encoded) > MAX_LINE_BYTES or output.tell() + len(encoded) > MAX_INPUT_BYTES:
            raise InputError("JSON document exceeds the expanded record or batch byte limit")
        output.write(encoded)
    return output.getvalue()


def parse_document(
    data: bytes, kind: str, origin: str, *, optional: bool = False, prefer_json: bool = False
) -> Batch | None:
    if len(data) > MAX_INPUT_BYTES:
        raise InputError("telemetry document exceeds its byte limit")
    raw = data.strip()
    if not raw:
        if optional:
            return None
        raise InputError("telemetry response contains no JSON records")
    digest = hashlib.sha256(data).hexdigest()
    position = "line"
    if raw.startswith(b"[") or prefer_json:
        try:
            document = strict_json(raw)
        except (ValueError, RecursionError):
            if raw.startswith(b"["):
                raise InputError("invalid or ambiguous JSON array") from None
            document = None
        if isinstance(document, (list, dict)):
            rows = document if isinstance(document, list) else [document]
            resolved = kind if kind != "auto" else (_format(rows[0]) if rows else "event-v1")
            if resolved is None:
                if optional:
                    return None
                raise InputError("expected event-v1 or Wazuh JSON objects")
            data = _encoded_rows(rows)
            if isinstance(document, list) or b"\n" in raw:
                position = "record"
            kind = resolved
    if kind == "auto":
        with BytesIO(data) as probe:
            while line := probe.readline(MAX_LINE_BYTES + 1):
                if line.strip():
                    break
        try:
            row = strict_json(line)
        except (ValueError, RecursionError):
            if optional and prefer_json:
                return None
            raise InputError("first telemetry record was not valid JSON") from None
        resolved = _format(row)
        if resolved is None:
            if optional:
                return None
            raise InputError("expected event-v1 or Wazuh JSON objects")
        kind = resolved
    batch = parse(BytesIO(data), kind)
    return replace(
        batch,
        sha256=digest,
        evidence=tuple(
            replace(row, origin=origin, input_sha256=digest, position=position) for row in batch.evidence
        ),
    )


def _possible_value(value: str) -> bool:
    return (
        value[0] not in "$<>{[(*"
        and not _PLACEHOLDER.match(value)
        and len(set(value)) >= 5
        and not value.isdecimal()
        and not value.startswith(("http://", "https://"))
    )


def _text_findings(
    data: bytes, root_key: str, name: str, modified: float
) -> tuple[list[Evidence], bool, bool]:
    if b"\x00" in data:
        return [], False, False
    try:
        text = data.decode("utf-8-sig")
        when = datetime.fromtimestamp(modified, UTC)
    except (UnicodeError, ValueError, OverflowError, OSError):
        return [], False, False
    digest = hashlib.sha256(data).hexdigest()
    rows = []
    truncated = False
    asset = identity("file-", (root_key, name))[:37]
    for line, value in enumerate(text.splitlines(), 1):
        found: Kind | None = None
        if len(value) <= 1024:
            if _PEM.fullmatch(value):
                found = Kind.ARTIFACT_KEY
            elif (assignment := _ASSIGNMENT.match(value)) and _possible_value(assignment[1]):
                found = Kind.ARTIFACT_CREDENTIAL
        if found is None:
            continue
        if len(rows) >= _SIGNAL_LIMIT:
            truncated = True
            break
        event_id = identity("a_", (asset, digest, line, found))
        event = Event(
            event_id,
            "local-artifact",
            asset,
            when,
            found,
            Severity.HIGH if found is Kind.ARTIFACT_KEY else Severity.MEDIUM,
        )
        rows.append(Evidence(identity("e_", event_id), line, event, name, digest))
    return rows, True, truncated


def scan(snapshot: Inventory) -> DirectoryResult:
    size = lines = ignored = blank = duplicates = conflicts = telemetry_files = text_files = 0
    details = []
    warnings = snapshot.errors
    limited = snapshot.limited
    event_rows: dict[tuple[str, str, str], Evidence] = {}
    conflict_keys: set[tuple[str, str, str]] = set()
    manifest = []
    root_key = str(snapshot.root)
    for entry in snapshot.entries:
        name = entry.relative.as_posix()
        suffix = entry.relative.suffix.lower()
        item: dict[str, Any] = {"path": name, "bytes": entry.size, "status": "inventory_only"}
        details.append(item)
        eligible = suffix in TEXT_EXTENSIONS or entry.relative.name.startswith(".env") or not suffix
        if not eligible:
            continue
        ceiling = MAX_INPUT_BYTES if suffix in FEED_EXTENSIONS else MAX_TEXT
        if entry.size > ceiling or size + entry.size > MAX_TOTAL:
            item["status"] = "size_limit"
            limited = True
            continue
        try:
            data = _read(entry, snapshot.root, ceiling)
            size += len(data)
            manifest.append((name, hashlib.sha256(data).hexdigest()))
            batch = (
                parse_document(data, "auto", name, optional=True, prefer_json=suffix == ".json")
                if suffix in FEED_EXTENSIONS
                else None
            )
            if batch is not None:
                if lines + batch.lines > MAX_LINES:
                    item["status"] = "record_limit"
                    limited = True
                    continue
                item["status"] = batch.format
                telemetry_files += 1
                lines += batch.lines
                ignored += batch.ignored_rows
                blank += batch.blank_rows
                duplicates += batch.duplicate_rows
                rows = batch.evidence
            else:
                if len(data) > MAX_TEXT:
                    item["status"] = "size_limit"
                    limited = True
                    continue
                rows, text, truncated = _text_findings(data, root_key, name, entry.modified)
                if text:
                    text_files += 1
                    item["status"] = "text_check"
                if truncated:
                    item["notice"] = "per-file signal limit reached"
                    limited = True
            for observed in rows:
                event = observed.event
                key = (event.source, event.asset, event.event_id)
                if key in conflict_keys:
                    conflicts += 1
                    continue
                if (prior := event_rows.get(key)) is not None:
                    if prior.event != event:
                        del event_rows[key]
                        conflict_keys.add(key)
                        conflicts += 1
                    else:
                        duplicates += 1
                    continue
                event_rows[key] = observed
        except (InputError, OSError, RuntimeError) as error:
            warnings += 1
            item["status"] = "skipped"
            item["notice"] = (
                str(error) if isinstance(error, InputError) else "could not read a stable regular file"
            )

    metadata = {
        "files": details,
        "ignored_entries": snapshot.ignored,
        "read_errors": warnings,
        "telemetry_files": telemetry_files,
        "text_files": text_files,
        "limit_reached": limited,
        "conflicting_event_ids": conflicts,
        "bytes_read": size,
    }
    digest = identity("", manifest)
    return DirectoryResult(
        Batch("directory", digest, tuple(event_rows.values()), lines, ignored, blank, duplicates), metadata
    )
