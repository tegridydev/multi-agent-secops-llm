"""Bounded HTTP. Model and feed callers use direct connections without redirects."""

import http.client
import ipaddress
import re
import socket
import ssl
from dataclasses import dataclass, replace
from typing import Any
from urllib.parse import urlsplit

from .domain import canonical_json, strict_json

_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", re.ASCII)
_PATH = re.compile(r"/[A-Za-z0-9._~/:-]*", re.ASCII)
PRIVATE_LAN = tuple(
    ipaddress.ip_network(net) for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)
ETAG = re.compile(r'(?:W/)?"[\x21\x23-\x7e]{0,124}"', re.ASCII)


class NetworkError(RuntimeError):
    """Safe network failure text that never includes credentials or a response body."""


class InvalidBody(NetworkError):
    """The response cannot safely be read as a bounded document."""


@dataclass(frozen=True, slots=True)
class Endpoint:
    scheme: str
    host: str
    port: int
    path: str

    @property
    def loopback(self) -> bool:
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    def at(self, path: str) -> "Endpoint":
        if not _PATH.fullmatch(path) or any(part in (".", "..") for part in path.split("/")):
            raise ValueError("use a plain, absolute API path")
        return replace(self, path=path)

    @property
    def authority(self) -> str:
        hostname = f"[{self.host}]" if ":" in self.host else self.host
        return f"{hostname}:{self.port}"


def _endpoint(url: str, allow_cleartext: bool = False) -> Endpoint:
    if not isinstance(url, str) or not re.fullmatch(r"[!-~]{1,900}", url) or any(x in url for x in "?#\\%"):
        raise ValueError("use a plain HTTP(S) URL without credentials, query parameters or fragments")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("invalid endpoint URL or port") from None
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host or parts.username is not None:
        raise ValueError("use a complete HTTP(S) endpoint without URL credentials")
    if host == "localhost":
        host = "127.0.0.1"
    try:
        address = ipaddress.ip_address(host)
        host = str(address)
    except ValueError:
        if len(host) > 253 or not all(_LABEL.fullmatch(part) for part in host.split(".")):
            raise ValueError("invalid endpoint hostname") from None
    result = Endpoint(
        parts.scheme, host, port if port is not None else (443 if parts.scheme == "https" else 80), "/"
    )
    if not 1 <= result.port <= 65535:
        raise ValueError("invalid endpoint port")
    if parts.scheme == "http" and not (result.loopback or allow_cleartext):
        raise ValueError("HTTP is only supported on this computer; use HTTPS elsewhere")
    return result.at(parts.path or "/")


def endpoint(url: str) -> Endpoint:
    return _endpoint(url)


def connect_proxy(url: str) -> Endpoint:
    """Only an HTTP CONNECT hop, with TLS still terminated at the audited HTTPS service."""
    try:
        target = _endpoint(url, allow_cleartext=True)
        if target.scheme != "http" or target.path != "/":
            raise ValueError()
    except ValueError:
        raise ValueError(
            "OSV needs an HTTP CONNECT proxy such as http://proxy:8080, without credentials or a path"
        ) from None
    return target


def _address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    ip = ipaddress.ip_address(value)
    return (ip.ipv4_mapped or ip) if isinstance(ip, ipaddress.IPv6Address) else ip


def _safe_ips(target: Endpoint, allow_lan: bool) -> list[str]:
    if target.loopback:
        # Do not resolve a local hostname via DNS.
        return [target.host]
    try:
        try:
            addresses = [_address(target.host)]
        except ValueError:
            answers = socket.getaddrinfo(
                target.host, target.port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
            )
            addresses = list(dict.fromkeys(_address(answer[4][0]) for answer in answers))
    except (OSError, ValueError):
        raise NetworkError("could not resolve the configured endpoint") from None
    # Check all answers, then connect to the approved number, not the hostname.
    for address in addresses:
        lan = allow_lan and any(address in subnet for subnet in PRIVATE_LAN)
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or not (address.is_global or lan)
        ):
            raise NetworkError("endpoint resolved to a disallowed address")
    if not addresses:
        raise NetworkError("no address found for the configured endpoint")
    return [str(address) for address in addresses]


class _Connection(http.client.HTTPConnection):
    def __init__(self, target: Endpoint, address: str, timeout: float):
        super().__init__(target.host, target.port, timeout=timeout)
        self.target = target
        self.address = address

    def connect(self) -> None:
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try:
            if self.target.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.target.host)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    etag: str | None = None

    def json(self) -> Any:
        try:
            return strict_json(self.body)
        except (ValueError, RecursionError):
            raise InvalidBody("response was not valid UTF-8 JSON") from None


def request(
    target: Endpoint,
    *,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20,
    max_bytes: int = 128 * 1024,
    allow_lan: bool = False,
    statuses: tuple[int, ...] = (200,),
    proxy: Endpoint | None = None,
) -> Response:
    if method not in ("GET", "POST") or (data is not None) != (method == "POST"):
        raise ValueError("unexpected request method or body")
    if proxy and (target.scheme != "https" or proxy.scheme != "http" or proxy.path != "/"):
        raise ValueError("proxy routing requires an HTTP CONNECT proxy and a verified HTTPS target")
    addresses = _safe_ips(proxy or target, allow_lan=bool(proxy) or allow_lan)
    # TCP fallback is safe before sending a request. Never replay a submitted POST.
    connection = None
    for address in addresses[:4]:
        candidate: http.client.HTTPConnection
        if proxy:
            candidate = http.client.HTTPSConnection(
                address, proxy.port, timeout=timeout, context=ssl.create_default_context()
            )
            # http.client tunnels first, then verifies the target hostname in TLS.
            candidate.set_tunnel(target.host, target.port)
        else:
            candidate = _Connection(target, address, timeout)
        try:
            candidate.connect()
            connection = candidate
            break
        except (OSError, http.client.HTTPException):
            candidate.close()
    if connection is None:
        hint = (
            "could not establish the OSV proxy tunnel; check HTTPS_PROXY and certificate trust"
            if proxy
            else "could not connect; check the configured server and its TLS certificate"
        )
        raise NetworkError(hint)
    try:
        outgoing = {"Accept": "application/json, application/x-ndjson", **(headers or {})}
        if proxy:
            outgoing["Host"] = target.authority if target.port != 443 or ":" in target.host else target.host
        if data is not None:
            outgoing["Content-Type"] = "application/json"
        body = canonical_json(data).encode("ascii") if data is not None else None
        connection.request(method, target.path, body=body, headers=outgoing)
        with connection.getresponse() as reply:
            if reply.status not in statuses:
                raise NetworkError(
                    f"endpoint returned HTTP {reply.status}; no redirect or retry was followed"
                )
            if reply.length is not None and reply.length > max_bytes:
                raise InvalidBody("endpoint response exceeds its byte limit")
            raw = reply.read(max_bytes + 1)
            if len(raw) > max_bytes or reply.length not in (None, 0):
                raise InvalidBody("endpoint response is too large or incomplete")
            etag = reply.getheader("ETag")
            return Response(reply.status, raw, etag if etag and ETAG.fullmatch(etag) else None)
    except (OSError, http.client.HTTPException):
        raise NetworkError("endpoint request failed or timed out") from None
    finally:
        connection.close()


def credential(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[!-~]{1,4096}", value):
        raise ValueError("credential must be a nonempty token with no spaces or control characters")
    return value
