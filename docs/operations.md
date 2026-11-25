# Operations

## Start with a sample

```sh
uv run masop.py
```

Press Enter to try the offline demo. Choose **1 → Run system checks** to repeat the setup and demo checks. MASOP runs on Python 3.11 or later with the standard library and SQLite. uv's inline script metadata keeps project package installation out of this launch path. If Python is missing, uv can fetch it before MASOP runs. The app cannot certify that interpreter, the operating system, uv itself or any model server. [uv script behaviour](https://docs.astral.sh/uv/guides/scripts/)

On launch, startup checks verify the release's empty runtime dependency declarations, SQLite support and TLS verification. The separate offline smoke test runs the packaged synthetic evidence. **Audit pinned packages against OSV** is optional and online. It accepts a PyPI backed `uv.lock` or a plain text file with one `name==version` per line. It sends only package names and versions. The audit returns exit 3 for known advisories and fails if results are incomplete or the service is unreachable. It never installs anything. OSV uses an available system HTTPS proxy, honours `NO_PROXY`, and still verifies the certificate for `api.osv.dev`. The supported proxy address is an unauthenticated HTTP CONNECT address such as `http://proxy:8080`. If your network supports direct HTTPS, `uv run masop.py audit ./pins.txt --direct` ignores the configured proxy. Model and telemetry routes are not affected. [OSV query contract](https://google.github.io/osv.dev/post-v1-querybatch/)

## Where state and findings go

By default MASOP uses `~/.masop`. Pass `--home /some/private/directory` before a command, or set `MASOP_HOME`, to use a separate workspace. The folder must be under your control. Sessions save profile settings and assignments but not keys. Scan and live findings are kept in `cases.sqlite3` unless you turn off the local queue.

Use **Configure harness → Open the local review queue** to acknowledge or dismiss a finding with a note. Reviews are local records. They don't run a response on any host. Identical evidence won't create another case or reset a decision. New evidence or a change to detection policy can produce a new case.

Exports are optional. For static scans use `--report /path/to/new.md` or `.json`. For live scans use `--report-dir /private/reports` to write one new JSON file per changed batch. Keep exports and the queue private because they can contain local identifiers and paths. The launcher won't overwrite a report file. Manage retention and backups at the host level.

## Pilot live analysis

```sh
uv run masop.py live --directory ./incoming --rules-only
uv run masop.py live --feed https://collector.example.org/alerts \
  --token-env MASOP_FEED_TOKEN --input-format event-v1 --poll 10 --rules-only
```

The directory mode waits for a file to be stable across two checks. Changed stable snapshots are analysed together. Keep the state and export folders separate from the watched data. Files still being written wait for a quiet poll interval. Press Ctrl+C to stop. In the menu this returns to the main menu.

An endpoint must be a trusted, user configured GET route that returns supported telemetry. MASOP doesn't try other URLs, follow links or redirects, or discover devices. It can use conditional GET with ETag and suppress repeats. If the feed stalls or becomes invalid it reports the issue without discarding prior cases, then checks again at the configured interval.

For scripts, add `--format json` to emit one JSON document per changed live batch. `--cycles N` is useful for testing a bounded run. A healthy poll with nothing new is a success, not an error. Live cases reflect the evidence available in that snapshot, not an unbounded incident timeline. [Input types and limits](inputs.md)

## Existing users

The original `python3 multiagent.py` demo and `python3 -m secops_harness triage` still work. Use the old batch CLI for a single JSONL file or for existing automation. An existing review database with the same schema can still be used through the batch CLI. Raw text arguments from the original May 2024 script are no longer a supported interface. [Original README](https://github.com/tegridydev/multi-agent-secops-llm/blob/caa9ed263d85a0033193b078f1639fd4b951f1ca/README.md)
