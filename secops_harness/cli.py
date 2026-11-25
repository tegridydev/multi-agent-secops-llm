"""The offline demo, batch triage and auditable local operator workflow."""

import argparse
import json
import sqlite3
import sys
from collections.abc import Callable
from importlib.resources import files
from pathlib import Path
from typing import Any

from . import __version__
from .agents import Adviser, Ollama, validate_model
from .detect import Policy
from .domain import SEVERITY_RANK, Severity
from .ingest import InputError, load, parse
from .report import analyse, markdown
from .store import STATES, StoreError, list_cases, open_queue, record, review, show


def _bounded_int(minimum: int, maximum: int) -> Callable[[str], int]:
    def convert(value: str) -> int:
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError("expected an integer") from None
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"expected an integer from {minimum} to {maximum}")
        return number

    return convert


def _triage_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", type=Path, help="Persist unique cases in this SQLite review queue")
    parser.add_argument(
        "--format", choices=("markdown", "json"), default="markdown", help="Report format on stdout"
    )
    parser.add_argument(
        "--auth-failures", type=_bounded_int(2, 50), default=5, help="Failure threshold (default: 5)"
    )
    parser.add_argument(
        "--window-seconds", type=_bounded_int(30, 3600), default=300, help="Auth window (default: 300)"
    )
    parser.add_argument(
        "--ollama-model", help="Opt in to suggestions using this installed local Ollama model"
    )
    parser.add_argument("--reviewer-model", help="Optional installed model for the reviewer role")
    parser.add_argument(
        "--ollama-port", type=_bounded_int(1, 65535), default=11434, help="Loopback port (default: 11434)"
    )
    parser.add_argument(
        "--ollama-timeout",
        type=_bounded_int(1, 120),
        default=30,
        help="Socket timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--model-cases", type=_bounded_int(1, 5), default=1, help="Maximum cases to annotate (default: 1)"
    )
    parser.add_argument(
        "--fail-on",
        choices=("medium", "high", "critical"),
        help="Emit full report, then exit 3 on cases of this priority or higher",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secops-harness", description="Local, evidence-first defensive alert triage"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Triage bundled synthetic events, offline by default")
    _triage_options(demo)
    triage = commands.add_parser("triage", help="Triage one completed local JSONL export")
    triage.add_argument("input", type=Path, help="Regular JSONL file")
    triage.add_argument("--input-format", choices=("event-v1", "wazuh"), default="event-v1")
    _triage_options(triage)
    queue = commands.add_parser("cases", help="List case snapshots, highest priority first")
    queue.add_argument("--db", type=Path, required=True)
    queue.add_argument("--state", choices=STATES)
    queue.add_argument("--limit", type=_bounded_int(1, 200), default=50)
    detail = commands.add_parser("show", help="Read a case, its evidence and any human decision")
    detail.add_argument("case_id")
    detail.add_argument("--db", type=Path, required=True)
    decision = commands.add_parser(
        "review", help="Record a human acknowledgement or dismissal without taking action"
    )
    decision.add_argument("case_id")
    decision.add_argument("--db", type=Path, required=True)
    decision.add_argument("--decision", choices=STATES[1:], required=True)
    decision.add_argument("--by", dest="reviewer", required=True)
    decision.add_argument("--note", required=True)
    return parser


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=True, indent=2, allow_nan=False), flush=True)


def _triage(args: argparse.Namespace) -> int:
    policy = Policy(args.auth_failures, args.window_seconds)
    if args.reviewer_model is not None and args.ollama_model is None:
        raise InputError("--reviewer-model requires --ollama-model")
    adviser = None
    if args.ollama_model is not None:
        try:
            adviser = Adviser(
                Ollama(args.ollama_port, args.ollama_timeout),
                validate_model(args.ollama_model),
                validate_model(args.reviewer_model if args.reviewer_model is not None else args.ollama_model),
                args.model_cases,
            )
        except ValueError as error:
            raise InputError(str(error)) from None
    if args.command == "demo":
        with files("secops_harness").joinpath("fixtures", "demo.jsonl").open("rb") as data:
            batch = parse(data)
    else:
        if args.db is not None:
            try:
                if args.input.samefile(args.db):
                    raise InputError("input file and review queue must be different files")
            except FileNotFoundError:
                pass
        batch = load(args.input, args.input_format)
    result = analyse(batch, policy, adviser)
    if args.db is not None:
        with open_queue(args.db, create=True) as conn:
            result["queue"] = record(conn, result)
    if args.format == "json":
        _print_json(result)
    else:
        print(markdown(result), end="", flush=True)
    if args.fail_on and any(
        SEVERITY_RANK[Severity(item["severity"])] >= SEVERITY_RANK[Severity(args.fail_on)]
        for item in result["cases"]
    ):
        return 3
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command in ("demo", "triage"):
            return _triage(args)
        with open_queue(args.db, write=args.command == "review") as conn:
            if args.command == "cases":
                result = list_cases(conn, args.state, args.limit)
            elif args.command == "show":
                result = show(conn, args.case_id)
            else:
                result = review(conn, args.case_id, args.decision, args.reviewer, args.note)
        _print_json(result)
        return 0
    except InputError as error:
        print(f"secops-harness: {error}", file=sys.stderr)
        return 2
    except StoreError as error:
        print(f"secops-harness: {error}", file=sys.stderr)
        return 1
    except sqlite3.Error:
        print(
            "secops-harness: could not access the SQLite queue; check the file, free space and concurrent writers",
            file=sys.stderr,
        )
        return 1
    except OSError as error:
        print(f"secops-harness: {error.strerror or 'could not read or write a file'}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
