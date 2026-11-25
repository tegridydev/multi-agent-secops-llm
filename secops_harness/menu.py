"""A small terminal wizard over the same operations as the automation CLI."""

import argparse
import getpass
import json
import os
import sqlite3
import sys
import warnings
from dataclasses import replace
from importlib.resources import files
from pathlib import Path

from . import __version__
from .agents import InvalidReply, Unavailable
from .application import Run, export, render
from .folders import DirectoryResult
from .ingest import InputError, parse
from .live import FolderFeed, JsonFeed, Source
from .providers import ENV, LOCAL_PRESETS, PRESETS, ROLES, Budget, Client, Profile, discover
from .settings import LIMITS, Settings, read_settings, save_settings, state_directory
from .setupcheck import audit, checks, osv_proxy, package_pins
from .store import StoreError, list_cases, open_queue, review, show
from .transport import NetworkError, credential, endpoint

ROOT = Path(__file__).resolve().parents[1]
STYLES = ("summary", "json", "markdown")
FEED_FORMATS = ("auto", "event-v1", "wazuh")
HELP = "Rules work offline without a model. Press Enter at a default, or 0 to go back."
OPERATION_ERRORS = (ValueError, OSError, sqlite3.Error, StoreError, NetworkError, Unavailable, InvalidReply)


def _demo() -> DirectoryResult:
    with files("secops_harness").joinpath("fixtures", "demo.jsonl").open("rb") as stream:
        return DirectoryResult(parse(stream), {})


def _health(verbose: bool) -> bool:
    report = checks(ROOT)
    if all(item.ok for item in report):
        try:
            from .report import analyse

            result = analyse(_demo().batch, Settings().policy)
            ready = len(result["cases"]) == 3 and result["coverage"]["events"] == 9
        except (OSError, ValueError):
            ready = False
        if verbose:
            print(f"[{'OK' if ready else 'FAIL'}] Offline self-test | bundled synthetic evidence")
    else:
        ready = False
    for item in report:
        if verbose or not item.ok:
            print(
                f"[{'OK' if item.ok else 'FAIL'}] {item.name} | {item.detail}",
                file=sys.stdout if item.ok else sys.stderr,
            )
    return ready


def _say_error(error: BaseException) -> None:
    if isinstance(error, OSError):
        detail = error.strerror or "could not open a file or directory"
    elif isinstance(error, sqlite3.Error):
        detail = "could not access the local queue; check permissions and concurrent use"
    else:
        detail = str(error)
    print(f"MASOP: {detail}", file=sys.stderr)


def _integer(value: str, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError:
        raise ValueError("enter a whole number") from None
    if not minimum <= number <= maximum:
        raise ValueError(f"enter a value from {minimum} to {maximum}")
    return number


def _yes(prompt: str, default: bool = False) -> bool:
    choice = input(f"{prompt} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    if not choice:
        return default
    if choice not in ("y", "yes", "n", "no"):
        raise ValueError("enter y or n")
    return choice in ("y", "yes")


def _choice(title: str, names: list[str], *, zero: str = "Back") -> int:
    print(f"\n{title}")
    for number, name in enumerate(names, 1):
        print(f"  {number}. {name}")
    print(f"  0. {zero}")
    raw = input("Choose [0] ").strip()
    return _integer(raw or "0", 0, len(names)) - 1


def _safe_key(name: str) -> str:
    if not ENV.fullmatch(name):
        raise ValueError("use an environment variable name, such as MASOP_MODEL_KEY")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            secret = getpass.getpass(f"Key for {name} (hidden, this session only) ")
    except getpass.GetPassWarning:
        raise ValueError(f"masked input unavailable; set {name} before launching MASOP") from None
    return credential(secret)


def _show_audit(path: Path, *, direct: bool = False) -> int:
    pins = package_pins(path)
    if not pins:
        print("No pinned third-party packages to query. No network request or installation was made.")
        return 0
    proxy = osv_proxy(direct=direct)
    route = "configured HTTPS proxy" if proxy else "direct HTTPS"
    print(f"Checking {len(pins)} exact PyPI pin(s) against OSV over {route}.", flush=True)
    try:
        findings = audit(pins, proxy=proxy)
    except NetworkError as error:
        raise NetworkError(f"OSV audit incomplete. No clean result was issued. {error}") from None
    affected = {pin: ids for pin, ids in findings.items() if ids}
    if affected:
        print(
            f"Known advisories found for {len(affected)}/{len(findings)} pinned packages. Nothing was installed."
        )
        for pin, ids in affected.items():
            print(f"  {pin} | {', '.join(ids)}")
        return 3
    print(f"OSV returned no known advisories for {len(findings)} exact pins. Nothing was installed.")
    return 0


def _feed(url: str, format: str, key_name: str, allow_lan: bool, timeout: int) -> JsonFeed:
    target = endpoint(url)
    if key_name and not ENV.fullmatch(key_name):
        raise ValueError("use the token environment variable name, not the token")
    token = os.environ.get(key_name) if key_name else None
    if key_name and not token:
        raise ValueError(f"set {key_name} before connecting to the telemetry feed")
    return JsonFeed(target, format, credential(token) if token else None, allow_lan, timeout)


def _ready_folder(value: Path, data_home: Path, export_dir: Path | None = None) -> Path:
    try:
        root = value.expanduser().resolve(strict=True)
    except RuntimeError:
        raise ValueError("could not resolve the selected directory") from None
    if not root.is_dir():
        raise ValueError("choose an existing directory")
    if root == data_home.resolve() or (export_dir is not None and root == export_dir.resolve()):
        raise ValueError("choose a data directory separate from MASOP's state and live export directories")
    return root


class Console:
    def __init__(self, home: Path, settings: Settings):
        self.home = home
        self.settings = settings
        self.keys: dict[str, str] = {}

    def save(self, value: Settings) -> None:
        save_settings(self.home, value)
        self.settings = value
        print("Saved.")

    def loop(self) -> int:
        print(f"\nMASOP {__version__} | local defensive analysis")
        print(HELP)
        while True:
            print(
                "\n  1. Configure harness\n  2. Configure agents\n  3. Run static analysis\n"
                "  4. Launch live analysis\n  D. Try the offline demo\n  0. Exit"
            )
            try:
                choice = input("MASOP [D] > ").strip().lower() or "d"
                if choice == "0":
                    return 0
                if choice == "1":
                    self.harness()
                elif choice == "2":
                    self.agents()
                elif choice == "3":
                    self.static()
                elif choice == "4":
                    self.live()
                elif choice == "d":
                    result = Run(self.home, self.settings, {}, True).analyse(_demo(), persist=False)
                    print(render(result), end="")
                else:
                    print("Choose 1 to 4, D or 0.")
            except EOFError:
                return 0
            except KeyboardInterrupt:
                print("\nStopped. Back at the main menu.")
            except OPERATION_ERRORS as error:
                _say_error(error)

    def harness(self) -> None:
        while True:
            choice = _choice(
                "Configure harness",
                [
                    "Run system checks and the offline self-test",
                    "Change run defaults",
                    "Audit pinned packages against OSV",
                    "Open the local review queue",
                ],
            )
            if choice < 0:
                return
            if choice == 0:
                _health(True)
            elif choice == 1:
                print(
                    "Press Enter to keep each current value. Set model cases or total calls to 0 for rules only."
                )
                labels = (
                    "Sign-in failures to flag",
                    "Sign-in window in seconds",
                    "Live poll interval in seconds",
                    "Files per folder snapshot",
                    "Model cases per batch",
                    "Model requests per run",
                    "Model/feed socket timeout in seconds",
                )
                changes = {}
                for (key, bounds), label in zip(LIMITS.items(), labels, strict=True):
                    value = input(f"{label} [{getattr(self.settings, key)}] ").strip()
                    if value:
                        changes[key] = _integer(value, *bounds)
                changes["persist_cases"] = _yes("Keep a local review queue?", self.settings.persist_cases)
                self.save(replace(self.settings, **changes))
            elif choice == 2:
                value = input("Path to uv.lock or a file of exact PyPI package pins (Enter cancels) ").strip()
                if value and _yes("Send package names and versions to OSV for a read-only check?"):
                    _show_audit(Path(value).expanduser())
            elif choice == 3:
                self.queue()

    def queue(self) -> None:
        db = self.home / "cases.sqlite3"
        if not db.is_file():
            print("No queue yet. Run a static or live analysis first.")
            return
        with open_queue(db) as connection:
            pending = list_cases(connection, state="pending", limit=25)
        if not pending:
            print("No pending cases.")
            return
        choice = _choice(
            "Review pending cases", [f"{item['severity'].upper()} | {item['asset']}" for item in pending]
        )
        if choice < 0:
            return
        case_id = pending[choice]["case_id"]
        with open_queue(db) as connection:
            details = show(connection, case_id)
        print(json.dumps(details, ensure_ascii=True, indent=2))
        action = _choice("Record a local review", ["Acknowledge", "Dismiss"])
        if action < 0:
            return
        who = input("Reviewer name or handle ").strip()
        note = input("Review note ").strip()
        with open_queue(db, write=True) as connection:
            review(connection, case_id, ("acknowledged", "dismissed")[action], who, note)
        print("Review recorded. Nothing was executed.")

    def agents(self) -> None:
        while True:
            print("\nRoles")
            for role, label in ROLES.items():
                profile = self.settings.roles.get(role)
                value = (
                    f"{profile} / {self.settings.profiles[profile].model}"
                    if profile
                    else "rules only or falls back"
                )
                print(f"  {label:23} {value}")
            choice = _choice(
                "Configure agents",
                [
                    "Add or update a model profile",
                    "Assign or clear a role",
                    "Test a profile with synthetic input",
                    "Add a key for this session",
                    "Remove a model profile",
                ],
            )
            if choice < 0:
                return
            if choice == 0:
                self.add_profile()
            elif choice == 1:
                self.assign()
            else:
                profile = self.pick_profile()
                if profile is None:
                    continue
                if choice == 2:
                    self.test(profile)
                elif choice == 3:
                    if not profile.key_name:
                        print(
                            "This profile has no credential variable. Update it first if authentication is required."
                        )
                    else:
                        self.keys[profile.name] = _safe_key(profile.key_name)
                        print("Key kept for this session only.")
                elif choice == 4 and _yes(f"Remove profile {profile.name} and its assignments?"):
                    profiles = {
                        name: item for name, item in self.settings.profiles.items() if name != profile.name
                    }
                    roles = {name: item for name, item in self.settings.roles.items() if item != profile.name}
                    self.save(replace(self.settings, profiles=profiles, roles=roles))
                    self.keys.pop(profile.name, None)

    def pick_profile(self) -> Profile | None:
        profiles = list(self.settings.profiles.values())
        if not profiles:
            print("Add a model profile first.")
            return None
        choice = _choice(
            "Choose profile", [f"{item.name} | {item.preset.label} | {item.model}" for item in profiles]
        )
        return profiles[choice] if choice >= 0 else None

    def add_profile(self) -> None:
        custom = ("custom-chat", "custom-responses")
        hosted = tuple(key for key in PRESETS if key not in (*LOCAL_PRESETS, *custom))
        group = _choice(
            "Where is the model running?",
            ["Local model server", "Hosted AI provider", "Custom compatible endpoint"],
        )
        if group < 0:
            return
        options = (LOCAL_PRESETS, hosted, custom)[group]
        chosen = _choice("Model provider", [PRESETS[key].label for key in options])
        if chosen < 0:
            return
        provider = options[chosen]
        preset = PRESETS[provider]
        url = ""
        if preset.adjustable:
            display = f" [{preset.url}]" if preset.url else ""
            url = input(f"Server URL or full API endpoint{display} ").strip()
        target = endpoint(url or preset.url)
        remote = not target.loopback
        if remote and not _yes(
            f"Allow calls to {target.authority}? It gets finding types and counts, and may charge for calls"
        ):
            return
        lan = preset.adjustable and remote and _yes("Is this a trusted private LAN HTTPS endpoint?")
        key = input(f"Key environment variable [{preset.key_env or 'none'}] ").strip()
        if key and not ENV.fullmatch(key):
            raise ValueError("enter the environment variable name, not the key itself")
        name = input(f"Profile name [{provider}] ").strip() or provider
        if name in self.settings.profiles and not _yes(f"Update existing profile {name}?"):
            return
        candidate = None
        if (
            provider in LOCAL_PRESETS
            and target.loopback
            and _yes("List models from this local server?", True)
        ):
            try:
                temp = Profile(name, provider, "probe-model", url, key, remote, bool(lan))
                found = discover(provider, url, temp.headers(self.keys))
            except (ValueError, NetworkError, Unavailable) as error:
                print(f"Model list unavailable. Enter an installed model ID manually. {error}")
            else:
                if found:
                    models = found[:25]
                    selected = _choice("Models served locally", models, zero="Enter ID manually")
                    if selected >= 0:
                        candidate = models[selected]
                else:
                    print("No models listed. Start the server and load or pull a model, then enter its ID.")
        model = candidate or input("Model ID as shown by your provider/server (Enter cancels) ").strip()
        if not model:
            return
        profile = Profile(name, provider, model, url, key, remote, bool(lan))
        profiles = {**self.settings.profiles, name: profile}
        roles = dict(self.settings.roles)
        if "triage" not in roles and _yes("Use it for general triage and default review?", True):
            roles["triage"] = name
        self.save(replace(self.settings, profiles=profiles, roles=roles))
        # A pasted key is scoped to the saved profile, not a replacement endpoint.
        self.keys.pop(name, None)
        if profile.key_name and not os.environ.get(profile.key_name):
            print(f"To use this profile, set {profile.key_name} or choose Add a key for this session.")

    def assign(self) -> None:
        slots = list(ROLES)
        choice = _choice("Role to configure", list(ROLES.values()))
        if choice < 0:
            return
        names = list(self.settings.profiles)
        target = _choice("Assign profile", [*names, "Clear this assignment"])
        if target < 0:
            return
        roles = dict(self.settings.roles)
        if target == len(names):
            roles.pop(slots[choice], None)
        else:
            roles[slots[choice]] = names[target]
        self.save(replace(self.settings, roles=roles))

    def test(self, profile: Profile) -> None:
        if not _yes(
            f"Send one synthetic contract test to {profile.target().authority}?", profile.target().loopback
        ):
            return
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["status"],
            "properties": {"status": {"type": "string", "enum": ["ok"]}},
        }
        result = Client(profile, self.keys, Budget(1), self.settings.request_timeout).ask(
            profile.model,
            "This is a synthetic connectivity check. Return status ok.",
            {"test": "connectivity"},
            schema,
        )
        if result != {"status": "ok"}:
            raise InvalidReply("server responded but the model failed the JSON contract")
        print("Profile passed the synthetic test. No telemetry was sent.")

    def static(self) -> None:
        selected = input("Directory to analyse (Enter cancels) ").strip()
        if not selected:
            return
        path = _ready_folder(Path(selected), self.home)
        print("Reading eligible files locally. This does not run files or scan a network.")
        result = Run(self.home, self.settings, self.keys).folder(path)
        print(render(result), end="")
        dest = input("Export the full report to a .json or .md path (Enter skips) ").strip()
        if dest:
            export(result, Path(dest))
            print("Report exported.")

    def live(self) -> None:
        mode = _choice(
            "Choose a live data source", ["Watch a local directory", "Poll one HTTP(S) JSON telemetry feed"]
        )
        if mode < 0:
            return
        selected = input("Directory " if mode == 0 else "Telemetry URL ").strip()
        if not selected:
            return
        locator = input("Report export directory (Enter for no file exports) ").strip()
        output = state_directory(Path(locator)) if locator else None
        source: Source
        if mode == 0:
            source = FolderFeed(
                _ready_folder(Path(selected), self.home, output),
                self.settings.max_files,
                (self.home, output) if output else (self.home,),
            )
        else:
            target = endpoint(selected)
            if not target.loopback and not _yes(
                f"Poll this single read-only HTTPS feed at {target.authority}?"
            ):
                return
            use_lan = not target.loopback and _yes("Is this a trusted private LAN HTTPS feed?")
            env = input("Bearer token environment variable (Enter for no authentication) ").strip()
            source = _feed(selected, "auto", env, use_lan, self.settings.request_timeout)
        print(
            f"Live analysis runs every {self.settings.poll_seconds} seconds. Ctrl-C returns to the menu.",
            flush=True,
        )
        run = Run(self.home, self.settings, self.keys)
        run.live(
            source,
            lambda value: print(render(value), end="", flush=True),
            lambda notice: print(notice, file=sys.stderr, flush=True),
            interval=self.settings.poll_seconds,
            output=output,
        )


def _parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="masop", description="MASOP local defensive triage and live analysis")
    cli.add_argument("--version", action="version", version=f"MASOP {__version__}")
    cli.add_argument("--home", type=Path, help="operator-owned config and queue directory")
    group = cli.add_subparsers(dest="command")
    group.add_parser("check", help="run offline setup and smoke checks")
    demo = group.add_parser("demo", help="run the offline sample without persisting anything")
    demo.add_argument("--format", choices=STYLES, default="summary")
    package = group.add_parser(
        "audit", help="query OSV with exact PyPI package pins; never installs anything"
    )
    package.add_argument("manifest", type=Path)
    package.add_argument(
        "--direct", action="store_true", help="use direct HTTPS instead of a configured OSV proxy"
    )
    single = group.add_parser("scan", help="analyse a local directory once")
    single.add_argument("directory", type=Path)
    single.add_argument("--report", type=Path, help="write a new .json or .md report")
    live = group.add_parser("live", help="watch a directory or poll a trusted JSON feed")
    source = live.add_mutually_exclusive_group(required=True)
    source.add_argument("--directory", type=Path)
    source.add_argument("--feed")
    live.add_argument("--input-format", choices=FEED_FORMATS, default="auto")
    live.add_argument("--token-env", default="", help="environment variable name for the feed's bearer token")
    live.add_argument(
        "--allow-lan", action="store_true", help="allow explicitly configured private HTTPS feed"
    )
    live.add_argument("--poll", type=lambda value: _integer(value, *LIMITS["poll_seconds"]))
    live.add_argument(
        "--cycles", type=lambda value: _integer(value, 1, 10000), help="exit after this many polls"
    )
    live.add_argument("--report-dir", type=Path, help="write one new JSON report per changed batch")
    for item in (single, live):
        item.add_argument(
            "--rules-only", action="store_true", help="disable all model inference for this run"
        )
        item.add_argument(
            "--format", choices=STYLES, default="summary", help="JSON is one line per batch in live mode"
        )
    return cli


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if not args.command and not sys.stdin.isatty():
            parser.print_help()
            print("\nRun in a terminal for the interactive menu.")
            return 0
        if not _health(args.command == "check"):
            print("Startup checks failed. No analysis or model calls ran.", file=sys.stderr)
            return 2
        if args.command == "check":
            return 0
        if args.command == "audit":
            return _show_audit(args.manifest.expanduser(), direct=args.direct)
        if args.command == "demo":
            from .report import analyse

            print(render(analyse(_demo().batch, Settings().policy), args.format), end="")
            return 0
        home = state_directory(args.home or Path(os.environ.get("MASOP_HOME") or Path.home() / ".masop"))
        settings = read_settings(home)
        if args.command is None:
            return Console(home, settings).loop()
        task = Run(home, settings, {}, args.rules_only)
        if args.command == "scan":
            result = task.folder(_ready_folder(args.directory, home), (args.report,) if args.report else ())
            print(render(result, args.format), end="")
            if args.report:
                export(result, args.report)
            return 0
        output = state_directory(args.report_dir) if args.report_dir else None
        live_source: Source
        if args.directory:
            if args.token_env or args.allow_lan or args.input_format != "auto":
                raise ValueError("feed credentials and format options are only for --feed")
            live_source = FolderFeed(
                _ready_folder(args.directory, home, output),
                settings.max_files,
                (home, output) if output else (home,),
            )
        else:
            live_source = _feed(
                args.feed, args.input_format, args.token_env, args.allow_lan, settings.request_timeout
            )
        stats = task.live(
            live_source,
            lambda report: print(
                json.dumps(report, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
                if args.format == "json"
                else render(report, args.format).rstrip(),
                flush=True,
            ),
            lambda notice: print(notice, file=sys.stderr, flush=True),
            interval=args.poll or settings.poll_seconds,
            cycles=args.cycles,
            output=output,
        )
        return 1 if stats.last_problem else 0
    except KeyboardInterrupt:
        return 130
    except OPERATION_ERRORS as error:
        _say_error(error)
        return 2 if isinstance(error, (ValueError, InputError)) and not isinstance(error, InvalidReply) else 1
