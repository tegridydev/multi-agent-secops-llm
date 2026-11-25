"""Read-only polling of stable folder snapshots or one configured telemetry URL."""

import hashlib
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path
from time import sleep
from typing import Protocol

from .folders import DirectoryResult, inventory, parse_document, scan
from .ingest import MAX_INPUT_BYTES, InputError
from .transport import Endpoint, NetworkError, credential, request


@dataclass(slots=True)
class FolderFeed:
    directory: Path
    max_files: int
    exclude: tuple[Path, ...] = ()
    _previous: dict[Path, tuple[int, ...]] = field(default_factory=dict)
    _reported: dict[Path, tuple[int, ...]] = field(default_factory=dict)
    _root_id: tuple[int, int] = field(init=False)

    def __post_init__(self) -> None:
        self.directory = self.directory.expanduser().resolve(strict=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise InputError("select an existing data directory")
        self._root_id = (info.st_dev, info.st_ino)

    def poll(self) -> DirectoryResult | None:
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self._root_id:
            raise InputError("watched directory was replaced; restart live analysis to select a new source")
        snapshot = inventory(self.directory, self.max_files, self.exclude)
        if snapshot.root != self.directory:
            raise InputError("watched directory resolved outside the selected source")
        ready = tuple(
            entry for entry in snapshot.entries if self._previous.get(entry.relative) == entry.stamp
        )
        self._previous = {entry.relative: entry.stamp for entry in snapshot.entries}
        stable = {entry.relative: entry.stamp for entry in ready}
        if not stable or stable == self._reported:
            return None
        self._reported = stable
        return scan(replace(snapshot, entries=ready))


@dataclass(slots=True)
class JsonFeed:
    target: Endpoint
    format: str = "auto"
    token: str | None = field(default=None, repr=False)
    allow_lan: bool = False
    timeout: int = 25
    etag: str | None = None
    digest: str | None = None
    event_refs: tuple[str, ...] | None = None

    def poll(self) -> DirectoryResult | None:
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + credential(self.token)
        if self.etag is not None:
            headers["If-None-Match"] = self.etag
        reply = request(
            self.target,
            headers=headers,
            allow_lan=self.allow_lan,
            timeout=self.timeout,
            max_bytes=MAX_INPUT_BYTES,
            statuses=(200, 204, 304),
        )
        if reply.status in (204, 304):
            return None
        digest = hashlib.sha256(reply.body).hexdigest()
        if self.digest == digest:
            self.etag = reply.etag
            return None
        origin = f"{self.target.authority}{self.target.path}"
        batch = parse_document(reply.body, self.format, origin, prefer_json=True)
        if batch is None:
            raise InputError("telemetry endpoint did not return supported records")
        self.etag, self.digest = reply.etag, digest
        refs = tuple(sorted(row.ref for row in batch.evidence))
        if self.event_refs == refs:
            return None
        self.event_refs = refs
        return DirectoryResult(batch, {})


class Source(Protocol):
    def poll(self) -> DirectoryResult | None: ...


RECOVERED = "live source recovered"


def watch(source: Source, *, interval: int, cycles: int | None = None):
    """Yield complete observations or short safe errors. Ctrl-C is handled by the caller."""
    count = 0
    last_problem = None
    while cycles is None or count < cycles:
        count += 1
        try:
            result = source.poll()
        except (NetworkError, InputError, OSError) as error:
            problem = (
                str(error) if not isinstance(error, OSError) else "live source is not currently readable"
            )
            if last_problem != problem:
                yield count, None, problem
            last_problem = problem
        else:
            if last_problem:
                yield count, None, RECOVERED
            last_problem = None
            if result is not None:
                yield count, result, None
        if cycles is None or count < cycles:
            sleep(interval)
