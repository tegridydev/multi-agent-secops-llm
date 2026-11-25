"""Versioned local configuration, with no stored API credentials."""

import json
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .detect import Policy
from .domain import strict_json
from .providers import ROLES, Profile

LIMITS = {
    "auth_failures": (2, 50),
    "window_seconds": (30, 3600),
    "poll_seconds": (2, 300),
    "max_files": (1, 1000),
    "model_cases": (0, 5),
    "session_calls": (0, 200),
    "request_timeout": (2, 120),
}
MAX_SETTINGS = 128 * 1024


@dataclass(frozen=True, slots=True)
class Settings:
    schema: int = 1
    auth_failures: int = 5
    window_seconds: int = 300
    poll_seconds: int = 5
    max_files: int = 200
    model_cases: int = 1
    session_calls: int = 20
    request_timeout: int = 25
    persist_cases: bool = True
    profiles: dict[str, Profile] = field(default_factory=dict)
    roles: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.schema) is not int or self.schema != 1:
            raise ValueError("unsupported configuration version")
        for name, (minimum, maximum) in LIMITS.items():
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} should be from {minimum} to {maximum}")
        if type(self.persist_cases) is not bool:
            raise ValueError("persist_cases should be true or false")
        if not isinstance(self.profiles, dict) or len(self.profiles) > 32:
            raise ValueError("configure up to 32 agent profiles")
        if any(
            not isinstance(profile, Profile) or key != profile.name for key, profile in self.profiles.items()
        ):
            raise ValueError("profile registry names must match their entries")
        if not isinstance(self.roles, dict) or any(
            role not in ROLES or not isinstance(name, str) or name not in self.profiles
            for role, name in self.roles.items()
        ):
            raise ValueError("roles must point to existing agent profiles")

    @property
    def policy(self) -> Policy:
        return Policy(self.auth_failures, self.window_seconds)


def _safely_owned(info: os.stat_result) -> bool:
    if os.name != "posix":
        return True
    return info.st_uid == os.getuid() and not info.st_mode & 0o022


def state_directory(path: Path) -> Path:
    path = path.expanduser().absolute()
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not _safely_owned(info):
        raise ValueError("the MASOP state directory must be owned by you and not writable by other users")
    return path


def read_settings(directory: Path) -> Settings:
    path = directory / "config.json"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return Settings()
    if not stat.S_ISREG(info.st_mode) or not _safely_owned(info):
        raise ValueError("MASOP config.json must be a regular file editable only by you")
    with path.open("rb") as stream:
        raw = stream.read(MAX_SETTINGS + 1)
    if len(raw) > MAX_SETTINGS:
        raise ValueError("MASOP config is larger than its size limit")
    try:
        data = strict_json(raw)
        if not isinstance(data, dict) or not isinstance(data.get("profiles", {}), dict):
            raise ValueError("configuration must be an object with named profiles")
        data["profiles"] = {key: Profile(**item) for key, item in data.get("profiles", {}).items()}
        return Settings(**data)
    except (ValueError, TypeError, RecursionError):
        raise ValueError(
            "invalid MASOP config.json; fix it or use --home to start with a clean profile"
        ) from None


def write_private(path: Path, content: str, *, replace: bool) -> None:
    """Use a private temp file and publish it atomically, refusing export collisions."""
    path = path.expanduser().absolute()
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError:
                raise ValueError("an export already exists at that path; choose another filename") from None
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


def save_settings(directory: Path, settings: Settings) -> None:
    data: dict[str, Any] = asdict(settings)
    raw = json.dumps(data, sort_keys=True, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    write_private(directory / "config.json", raw, replace=True)
