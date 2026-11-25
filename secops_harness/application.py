"""Shared flow for the interactive menu and automation commands."""

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .folders import DirectoryResult, inventory, scan
from .live import RECOVERED, Source, watch
from .providers import Budget, RoutedAdviser
from .report import analyse, markdown
from .settings import Settings, write_private
from .store import open_queue, record

MAX_SEEN = 20_000


@dataclass(frozen=True, slots=True)
class LiveStats:
    batches: int
    last_problem: str | None


@dataclass(slots=True)
class Run:
    data_home: Path
    settings: Settings
    keys: Mapping[str, str]
    rules_only: bool = False
    budget: Budget = field(init=False)
    seen: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.budget = Budget(0 if self.rules_only else self.settings.session_calls)

    def folder(self, path: Path, exclude: tuple[Path, ...] = ()) -> dict[str, Any]:
        source = scan(inventory(path, self.settings.max_files, (self.data_home, *exclude)))
        return self.analyse(source)

    def analyse(self, data: DirectoryResult, *, persist: bool | None = None) -> dict[str, Any]:
        use_models = (
            not self.rules_only
            and self.settings.model_cases > 0
            and self.budget.limit > 0
            and self.settings.roles
        )
        adviser = (
            RoutedAdviser(
                self.settings.profiles,
                self.settings.roles,
                self.keys,
                self.budget,
                self.settings.model_cases,
                self.settings.request_timeout,
                self.seen,
            )
            if use_models
            else None
        )
        result = analyse(data.batch, self.settings.policy, adviser)
        if adviser is not None:
            if len(self.seen) >= MAX_SEEN:
                # Keep the session bounded. The SQLite review queue still deduplicates cases.
                self.seen.clear()
            self.seen.update(
                case["case_id"]
                for case in result["cases"]
                if case["model"]["status"] in ("accepted", "needs_context")
            )
            result["model_requests"] = {"used": self.budget.used, "max": self.budget.limit}
        if data.inventory:
            result["inventory"] = data.inventory
        retain = self.settings.persist_cases if persist is None else persist
        if retain:
            with open_queue(self.data_home / "cases.sqlite3", create=True) as connection:
                result["queue"] = record(connection, result)
        return result

    def live(
        self,
        source: Source,
        print_report: Callable[[dict[str, Any]], None],
        notice: Callable[[str], None],
        *,
        interval: int,
        cycles: int | None = None,
        output: Path | None = None,
    ) -> LiveStats:
        batches = 0
        last_problem = None
        for _, data, problem in watch(source, interval=interval, cycles=cycles):
            if problem is not None:
                notice(problem)
                last_problem = None if problem == RECOVERED else problem
                continue
            if data is None:
                continue
            result = self.analyse(data)
            batches += 1
            print_report(result)
            if output:
                key = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
                export(result, output / f"masop-{key}-{batches:04d}.json")
        return LiveStats(batches, last_problem)


def export(report: dict[str, Any], path: Path) -> None:
    suffix = path.suffix.lower()
    if suffix not in (".json", ".md"):
        raise ValueError("export to a filename ending in .json or .md")
    write_private(path, render(report, "json" if suffix == ".json" else "markdown"), replace=False)


def _safe_label(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)[1:-1]


def render(report: dict[str, Any], style: str = "summary") -> str:
    if style == "json":
        return json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    inventory = report.get("inventory")
    if style == "markdown":
        text = markdown(report)
        if inventory:
            text += (
                f"\n## Folder coverage\n\n{len(inventory['files'])} inventoried · "
                f"{inventory['telemetry_files']} telemetry · {inventory['text_files']} text checked · "
                f"{inventory['read_errors']} read or parse errors · "
                f"{inventory['conflicting_event_ids']} conflicting event identities.\n"
            )
            if inventory["limit_reached"]:
                text += (
                    "\nSome files or observations were outside this run's bounds. See the JSON inventory.\n"
                )
        return text
    cases = report["cases"]
    text = [f"{len(cases)} case(s) from {report['coverage']['events']} observations"]
    if inventory:
        text.append(
            f"Files: {len(inventory['files'])} inventoried | {inventory['telemetry_files']} telemetry | "
            f"{inventory['text_files']} checked as text"
        )
        if inventory["limit_reached"] or inventory["read_errors"] or inventory["conflicting_event_ids"]:
            text.append(
                f"Partial coverage | {inventory['read_errors']} unreadable or invalid | "
                f"{inventory['conflicting_event_ids']} identity conflicts | limits reached: "
                f"{'yes' if inventory['limit_reached'] else 'no'}"
            )
            for item in [
                item
                for item in inventory["files"]
                if item["status"] in ("skipped", "size_limit", "record_limit")
            ][:5]:
                text.append(f"  Skipped {_safe_label(item['path'])} ({item.get('notice', item['status'])})")
    for case in cases[:10]:
        by_reference = {row["ref"]: row for row in case["evidence"]}
        for finding in case["findings"][:4]:
            row = by_reference[finding["evidence_refs"][0]]
            where = row.get("origin") or case["asset"]
            text.append(
                f"  {finding['severity'].upper():8} {finding['title']} | {_safe_label(where)} "
                f"{row.get('position', 'line')} {row['line']}"
            )
            text.append("           " + finding["checks"][0]["text"])
        if len(case["findings"]) > 4:
            text.append("           More findings for this case in the full report.")
        model = case["model"]
        if model["status"] in ("accepted", "needs_context"):
            from .agents import CHECKS, CONTEXT_CHECKS

            detail = (
                CHECKS[model["check"]] if model["status"] == "accepted" else CONTEXT_CHECKS[model["context"]]
            )
            text.append(f"           Agent {model['finding']}: {detail}")
        elif model["status"] not in ("disabled", "already_observed"):
            text.append(f"           Agent: {model['status'].replace('_', ' ')}")
            if detail := model.get("detail"):
                text.append(f"           {_safe_label(detail)}")
    if len(cases) > 10:
        text.append(f"  {len(cases) - 10} more cases in the full report.")
    if not cases:
        text.append("No selected rules matched. Check coverage before drawing conclusions.")
    if queue := report.get("queue"):
        text.append(f"Review queue: {queue['new_cases']} new, {queue['existing_cases']} already recorded.")
    if usage := report.get("model_requests"):
        text.append(f"Model calls this run: {usage['used']}/{usage['max']}.")
    return "\n".join(text) + "\n"
