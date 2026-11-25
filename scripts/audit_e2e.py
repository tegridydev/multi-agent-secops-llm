"""Opt-in check using a real loopback Ollama daemon, real HTTP feed and public OSV."""

import argparse
import http.client
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-masop-feed-token"


def ollama_state(url: str, model: str) -> str:
    target = urlsplit(url)
    host = "127.0.0.1" if target.hostname == "localhost" else target.hostname
    if (
        target.scheme != "http"
        or not host
        or not ip_address(host).is_loopback
        or target.path not in ("", "/")
        or target.query
        or target.fragment
        or target.username is not None
    ):
        raise ValueError("use an Ollama server base URL on this computer")
    conn = http.client.HTTPConnection(host, target.port or 11434, timeout=10)
    try:
        inventories = []
        for path in ("/api/version", "/api/tags"):
            conn.request("GET", path)
            with conn.getresponse() as response:
                if response.status != 200:
                    raise RuntimeError(f"{path} returned HTTP {response.status}")
                inventories.append(json.loads(response.read(1024 * 1024)))
        if not any(item.get("name") == model for item in inventories[1]["models"]):
            raise RuntimeError("the exact model is not in Ollama's installed model list")
        return inventories[0]["version"]
    finally:
        conn.close()


def run_cli(*args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, str(ROOT / "masop.py"), *args],
        cwd=ROOT,
        env={**os.environ, "MASOP_E2E_FEED_TOKEN": TOKEN},
        timeout=150,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != expected:
        raise RuntimeError(
            f"{args[0]} exited {result.returncode}, expected {expected}\n{result.stderr}\n{result.stdout}"
        )
    return result


def cases() -> tuple[dict, dict]:
    event = {
        "event_id": "e2e-endpoint-1",
        "source": "simulated-edr",
        "asset": "lab-workstation",
        "timestamp": "2026-11-25T00:00:00Z",
        "kind": "malware_alert",
        "severity": "high",
    }
    vulnerability = {
        **event,
        "event_id": "e2e-inventory-1",
        "source": "simulated-inventory",
        "asset": "lab-build",
        "kind": "vulnerability_alert",
        "cve": "CVE-2099-12345",
    }
    return event, vulnerability


def status(row: dict) -> str:
    label = row["model"]["status"]
    if label not in ("accepted", "needs_context"):
        raise RuntimeError(f"local advice failed the contract for this case: {row['model']}")
    return label


def main() -> int:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    cli.add_argument("--model", default="qwen2.5:0.5b")
    cli.add_argument("--skip-osv", action="store_true", help="run only the local paths")
    cli.add_argument(
        "--osv-clean-pin", default="requests==2.34.2", help="exact pin expected to have no known advisories"
    )
    args = cli.parse_args()

    try:
        version = ollama_state(args.ollama_url, args.model)
        first, second = cases()
        events: list[int] = []
        received: list[str | None] = []
        bodies = (json.dumps([first]).encode(), json.dumps([first, second]).encode())

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/alerts" or self.headers.get("Authorization") != f"Bearer {TOKEN}":
                    self.send_error(401)
                    return
                received.append(self.headers.get("If-None-Match"))
                turn = len(received)
                active = 0 if turn <= 2 else 1
                tag = ('"one"', '"two"')[active]
                changed = self.headers.get("If-None-Match") != tag
                code = 503 if turn == 4 else (200 if changed else 304)
                body = bodies[active] if code == 200 else b""
                events.append(code)
                self.send_response(code)
                self.send_header("ETag", tag)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, *_):
                pass

        with (
            TemporaryDirectory(prefix="masop-e2e-") as scratch,
            ThreadingHTTPServer(("127.0.0.1", 0), Handler) as http,
        ):
            tmp = Path(scratch)
            home = tmp / "state"
            home.mkdir(mode=0o700)
            (home / "config.json").write_text(
                json.dumps(
                    {
                        "profiles": {
                            name: {
                                "name": name,
                                "provider": "ollama",
                                "model": args.model,
                                "url": args.ollama_url,
                            }
                            for name in ("local-analyst", "local-reviewer")
                        },
                        "roles": {"triage": "local-analyst", "reviewer": "local-reviewer"},
                        "session_calls": 4,
                    }
                ),
                encoding="utf-8",
            )
            files = tmp / "input"
            files.mkdir()
            (files / "endpoint.jsonl").write_text(json.dumps(first) + "\n", encoding="utf-8")
            # A separate queue lets the live run exercise first insert and replay.
            offline_export = tmp / "static.md"
            static = run_cli(
                "--home", str(home), "scan", str(files), "--format", "json", "--report", str(offline_export)
            )
            static_report = json.loads(static.stdout)
            (static_case,) = static_report["cases"]
            assert static_case["evidence"][0]["origin"] == "endpoint.jsonl"
            assert offline_export.is_file()
            static_status = status(static_case)
            (home / "cases.sqlite3").unlink()

            worker = Thread(target=http.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            worker.start()
            feed = f"http://127.0.0.1:{http.server_port}/alerts"
            common = (
                "--home",
                str(home),
                "live",
                "--feed",
                feed,
                "--token-env",
                "MASOP_E2E_FEED_TOKEN",
                "--format",
                "json",
            )
            try:
                result = run_cli(
                    *common, "--cycles", "5", "--poll", "2", "--report-dir", str(tmp / "reports")
                )
                assert TOKEN not in result.stdout + result.stderr
                assert "HTTP 503" in result.stderr and "live source recovered" in result.stderr
                first_report, second_report = map(json.loads, result.stdout.splitlines())
                auth_status = status(first_report["cases"][0])
                new_status = status(next(c for c in second_report["cases"] if c["asset"] == "lab-build"))
                assert first_report["model_requests"] == {"used": 2, "max": 4}
                assert second_report["model_requests"] == {"used": 4, "max": 4}
                assert second_report["queue"] == {"new_cases": 1, "existing_cases": 1}
                assert len(list((tmp / "reports").glob("*.json"))) == 2
                assert events == [200, 304, 200, 503, 304]
                replay = run_cli(*common, "--cycles", "1", "--rules-only")
                assert json.loads(replay.stdout)["queue"] == {"new_cases": 0, "existing_cases": 2}
            finally:
                http.shutdown()
                worker.join(timeout=5)

            print(
                f"Local inference OK | Ollama {version} | {args.model} | static {static_status} | live {auth_status}, {new_status}"
            )
            print(f"Live HTTP OK | {events[:5]} | 2 exports | recovery and queue deduplication verified")
            if not args.skip_osv:
                known = tmp / "vulnerable-sample.txt"
                known.write_text("requests==2.31.0\n", encoding="utf-8")
                vulnerable = run_cli("audit", str(known), expected=3)
                assert "Known advisories found" in vulnerable.stdout
                clean = tmp / "clean-sample.txt"
                clean.write_text(args.osv_clean_pin + "\n", encoding="utf-8")
                clear = run_cli("audit", str(clean))
                assert "no known advisories" in clear.stdout
                print("OSV vulnerable pin (exit 3)")
                print(vulnerable.stdout, end="")
                print("OSV pin without published matches (exit 0)")
                print(clear.stdout, end="")
    except (OSError, ValueError, RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(f"End-to-end check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
