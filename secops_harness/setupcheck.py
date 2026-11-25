"""Offline startup checks and a read-only, explicit OSV audit for pinned packages."""

import re
import shutil
import sqlite3
import ssl
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.request import getproxies, proxy_bypass

from .transport import Endpoint, NetworkError, connect_proxy, endpoint, request

OSV = endpoint("https://api.osv.dev/v1/querybatch")
PIN = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9_.-]{0,126})==([a-zA-Z0-9][a-zA-Z0-9.+!_-]{0,79})", re.ASCII)
ADVISORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,95}", re.ASCII)
MAX_PACKAGES = 200


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def _declared(root: Path) -> None:
    script, project = root / "masop.py", root / "pyproject.toml"
    if script.is_file():
        # Check only the released metadata. uv reads it before this code can run.
        text = _bounded_text(script)
        match = re.search(r"(?m)^# /// script\n((?:#(?: .*)?\n)+?)# ///$", text)
        if not match:
            raise ValueError("the launcher is missing its dependency declaration")
        metadata = tomllib.loads(
            "\n".join(line[2:] if line.startswith("# ") else "" for line in match[1].splitlines())
        )
        if metadata.get("dependencies") != [] or "tool" in metadata:
            raise ValueError("the launcher declares unreviewed dependency or tool overrides")
        # A script lock is not needed and may affect uv before startup.
        if script.with_name("masop.py.lock").exists():
            raise ValueError("this release has no script lock; use the clean release files")
    if project.is_file():
        metadata = tomllib.loads(_bounded_text(project)).get("project", {})
        if metadata.get("dependencies") != [] or "dependencies" in metadata.get("dynamic", []):
            raise ValueError("project runtime dependencies are not the released empty set")


def checks(root: Path) -> list[Check]:
    result = [Check("Python", sys.version_info >= (3, 11), sys.version.split()[0])]
    try:
        _declared(root)
        result.append(
            Check("App dependencies", True, "zero third-party runtime packages; no package installs")
        )
    except (OSError, ValueError, TypeError, AttributeError):
        result.append(
            Check(
                "App dependencies", False, "unexpected project metadata; restore the official release files"
            )
        )
    try:
        with sqlite3.connect(":memory:") as connection:
            ready = connection.execute("SELECT 1").fetchone() == (1,) and sqlite3.sqlite_version_info >= (
                3,
                24,
                0,
            )
        connection.close()
        result.append(Check("SQLite", ready, sqlite3.sqlite_version))
    except sqlite3.Error:
        result.append(Check("SQLite", False, "the interpreter's SQLite module could not run a query"))
    try:
        tls = ssl.create_default_context()
        result.append(
            Check("TLS", tls.check_hostname and tls.verify_mode == ssl.CERT_REQUIRED, ssl.OPENSSL_VERSION)
        )
    except (ValueError, OSError):
        result.append(Check("TLS", False, "could not initialise certificate verification"))
    result.append(
        Check(
            "uv",
            True,
            "available" if shutil.which("uv") else "not on PATH; direct Python launch is supported",
        )
    )
    return result


def _bounded_text(path: Path) -> str:
    if not path.is_file():
        raise ValueError("use a regular text file")
    with path.open("rb") as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("file is larger than 1 MiB")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("file is not UTF-8 text") from None


def package_pins(path: Path) -> list[tuple[str, str]]:
    text = _bounded_text(path)
    pins = []
    if path.name == "uv.lock":
        data = tomllib.loads(text)
        packages = data.get("package")
        if type(data.get("version")) is not int or data["version"] != 1 or not isinstance(packages, list):
            raise ValueError("invalid uv.lock package entries")
        for item in packages:
            if not isinstance(item, dict) or not isinstance(item.get("source"), dict):
                raise ValueError("invalid lock package source")
            source = item["source"]
            if source in ({"editable": "."}, {"virtual": "."}):
                continue
            if source not in (
                {"registry": "https://pypi.org/simple"},
                {"registry": "https://pypi.org/simple/"},
            ):
                raise ValueError(
                    "only PyPI registry packages can be audited; the lock contains another source"
                )
            pins.append(f"{item.get('name', '')}=={item.get('version', '')}")
    else:
        for line in text.splitlines():
            value = line.partition("#")[0].strip()
            if value:
                pins.append(value)
    result = set()
    for pin in pins:
        match = PIN.fullmatch(pin)
        if not match:
            raise ValueError("use exact PyPI pins of the form package==version; no options, URLs or ranges")
        result.add((re.sub(r"[-_.]+", "-", match[1]).lower(), match[2]))
        if len(result) > MAX_PACKAGES:
            raise ValueError(f"too many packages; audit up to {MAX_PACKAGES} exact pins at a time")
    return sorted(result)


def osv_proxy(*, direct: bool = False) -> Endpoint | None:
    if direct or proxy_bypass(OSV.host):
        return None
    url = getproxies().get("https")
    return connect_proxy(url) if url else None


def audit(pins: list[tuple[str, str]], *, proxy: Endpoint | None = None) -> dict[str, list[str]]:
    if not pins:
        return {}
    pending = [
        (i, {"package": {"ecosystem": "PyPI", "name": name}, "version": version})
        for i, (name, version) in enumerate(pins)
    ]
    findings: dict[str, set[str]] = {f"{name}=={version}": set() for name, version in pins}
    pages: set[tuple[int, str]] = set()
    for _ in range(4):
        envelope = request(
            OSV,
            method="POST",
            data={"queries": [query for _, query in pending]},
            max_bytes=512 * 1024,
            proxy=proxy,
        ).json()
        results = envelope.get("results") if isinstance(envelope, dict) else None
        if not isinstance(results, list) or len(results) != len(pending):
            raise NetworkError("OSV returned an incomplete audit; no clean result was reported")
        remaining = []
        for (i, query), row in zip(pending, results, strict=True):
            if (
                not isinstance(row, dict)
                or row.keys() - {"vulns", "next_page_token"}
                or not isinstance(row.get("vulns", []), list)
            ):
                raise NetworkError("OSV returned invalid audit results")
            name, version = pins[i]
            for vuln in row.get("vulns", []):
                advisory = vuln.get("id") if isinstance(vuln, dict) else None
                if not isinstance(advisory, str) or not ADVISORY.fullmatch(advisory):
                    raise NetworkError("OSV returned an invalid advisory identifier")
                findings[f"{name}=={version}"].add(advisory)
            if "next_page_token" in row:
                token = row["next_page_token"]
                if not isinstance(token, str) or not 1 <= len(token) <= 4096 or (i, token) in pages:
                    raise NetworkError("OSV returned an invalid pagination token")
                pages.add((i, token))
                remaining.append((i, {**query, "page_token": token}))
        if not remaining:
            return {pin: sorted(vulns) for pin, vulns in findings.items()}
        pending = remaining
    raise NetworkError("OSV audit exceeded its page limit; no clean result was reported")
