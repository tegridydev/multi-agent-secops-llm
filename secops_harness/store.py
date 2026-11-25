"""A local review queue. Case snapshots and reviewer decisions are first-write wins."""

import json
import os
import re
import sqlite3
import stat
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .domain import SEVERITY_RANK, Severity, canonical_json

APP_ID = 0x534F4348  # SOCH
SCHEMA_VERSION = 1
STATES = ("pending", "acknowledged", "dismissed")
_CASE_ID = re.compile(r"c_[0-9a-f]{64}", re.ASCII)
_REVIEWER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}", re.ASCII)


class StoreError(RuntimeError):
    """A missing, incompatible or already reviewed queue item."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@contextmanager
def _transaction(conn: sqlite3.Connection) -> Iterator[None]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def _version(conn: sqlite3.Connection) -> tuple[int, int]:
    return (
        conn.execute("PRAGMA application_id").fetchone()[0],
        conn.execute("PRAGMA user_version").fetchone()[0],
    )


def _initialise(conn: sqlite3.Connection) -> None:
    with _transaction(conn):
        if (version := _version(conn)) == (APP_ID, SCHEMA_VERSION):
            return
        if version != (0, 0) or conn.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone():
            raise StoreError("database is not an empty or supported SecOps queue")
        conn.execute("""
            CREATE TABLE cases (
                case_id TEXT PRIMARY KEY NOT NULL,
                asset TEXT NOT NULL,
                source TEXT NOT NULL,
                severity TEXT NOT NULL,
                rank INTEGER NOT NULL,
                state TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending', 'acknowledged', 'dismissed')),
                first_seen TEXT NOT NULL,
                snapshot TEXT NOT NULL,
                reviewer TEXT,
                reviewed_at TEXT,
                note TEXT
            )
        """)
        conn.execute("CREATE INDEX cases_queue ON cases (state, rank DESC, first_seen, case_id)")
        conn.execute("CREATE INDEX cases_order ON cases (rank DESC, first_seen, case_id)")
        conn.execute(f"PRAGMA application_id = {APP_ID}")
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


@contextmanager
def open_queue(path: Path, *, create: bool = False, write: bool = False) -> Iterator[sqlite3.Connection]:
    path = path.absolute()
    if create:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            os.close(fd)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise StoreError("queue must be a regular file, not a symlink or device")
    mode = "rw" if create or write else "ro"
    conn = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=5, isolation_level=None)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA trusted_schema = OFF")
        if create:
            _initialise(conn)
        elif _version(conn) != (APP_ID, SCHEMA_VERSION):
            raise StoreError("database is not a supported SecOps queue")
        yield conn
    finally:
        conn.close()


def record(conn: sqlite3.Connection, report: dict[str, Any]) -> dict[str, int]:
    new = 0
    stamped = _utc_now()
    with _transaction(conn):
        for item in report["cases"]:
            snapshot = {
                "schema_version": report["schema_version"],
                "harness_version": report["harness_version"],
                "policy": report["policy"],
                "case": item,
            }
            result = conn.execute(
                """
                INSERT INTO cases (case_id, asset, source, severity, rank, first_seen, snapshot)
                VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(case_id) DO NOTHING
            """,
                (
                    item["case_id"],
                    item["asset"],
                    item["source"],
                    item["severity"],
                    SEVERITY_RANK[Severity(item["severity"])],
                    stamped,
                    canonical_json(snapshot),
                ),
            )
            new += result.rowcount
    return {"new_cases": new, "existing_cases": len(report["cases"]) - new}


def list_cases(conn: sqlite3.Connection, state: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    if state is not None and state not in STATES:
        raise StoreError("invalid case state")
    if type(limit) is not int or not 1 <= limit <= 200:
        raise StoreError("list limit must be between 1 and 200")
    query = "SELECT case_id, asset, source, severity, state, first_seen, reviewed_at FROM cases"
    params: tuple[Any, ...] = (limit,)
    if state is not None:
        query += " WHERE state = ?"
        params = (state, limit)
    query += " ORDER BY rank DESC, first_seen, case_id LIMIT ?"
    return [dict(row) for row in conn.execute(query, params)]


def validate_case_id(case_id: str) -> None:
    if not _CASE_ID.fullmatch(case_id):
        raise StoreError("use the full case ID shown by the cases command")


def show(conn: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    validate_case_id(case_id)
    row = conn.execute(
        """
        SELECT state, first_seen, reviewer, reviewed_at, note, snapshot FROM cases WHERE case_id = ?
    """,
        (case_id,),
    ).fetchone()
    if row is None:
        raise StoreError("case ID not found")
    value = dict(row)
    return {**json.loads(value.pop("snapshot")), "review": value}


def review(conn: sqlite3.Connection, case_id: str, state: str, reviewer: str, note: str) -> dict[str, str]:
    validate_case_id(case_id)
    if state not in ("acknowledged", "dismissed"):
        raise StoreError("invalid review decision")
    if not _REVIEWER.fullmatch(reviewer):
        raise StoreError("reviewer must be a simple name or handle")
    if (
        not note.strip()
        or len(note) > 500
        or any(unicodedata.category(char).startswith("C") for char in note)
    ):
        raise StoreError("review note must contain 1 to 500 visible characters with no control characters")
    stamped = _utc_now()
    with _transaction(conn):
        outcome = conn.execute(
            """
            UPDATE cases SET state = ?, reviewer = ?, reviewed_at = ?, note = ?
            WHERE case_id = ? AND state = 'pending'
        """,
            (state, reviewer, stamped, note.strip(), case_id),
        )
        if outcome.rowcount != 1:
            if conn.execute("SELECT 1 FROM cases WHERE case_id = ?", (case_id,)).fetchone() is None:
                raise StoreError("case ID not found")
            raise StoreError("case already has a recorded review")
    return {"case_id": case_id, "state": state, "reviewer": reviewer, "reviewed_at": stamped}
