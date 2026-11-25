# Changelog

## 0.3.1

- Fixed OSV on networks that require a proxy. Added a direct mode and fail-closed handling of malformed or repeated pagination data.
- Replaced independent reviewer fields with one allowed decision. Analyst choices also bind the finding and check in one option. Real local Qwen inference now completes the previously rejected review.
- Fixed base paths such as `/gateway/v1` in local and compatible model setup, and surfaced safe model errors in the terminal.
- Added a repeatable live audit with a real Ollama daemon, a changing HTTP feed and public OSV.

## 0.3.0

- Added the MASOP launcher, four interactive menus and automation commands.
- Added offline startup checks and a read only advisory audit for pinned PyPI dependencies.
- Added local model discovery, named profiles, specialist role routing and hosted API contracts without SDK dependencies.
- Added bounded directory analysis, redacted credential checks and file level evidence provenance.
- Added live polling for stable folder snapshots and JSON feeds, model request budgets and private report export.
- Kept the original offline demo and JSONL batch CLI working.

## 0.2.0

The rebuild of the unversioned May 2024 prototype.

- Added a model free CLI, normalised JSONL and Wazuh import, strict input validation, and bounded batches.
- Added deterministic authentication correlation and an evidence trail for source reported endpoint and vulnerability alerts.
- Added JSON and Markdown reports, a replay safe SQLite review queue, and auditable human decisions.
- Replaced free form model handoffs with optional loopback Ollama analyst and reviewer roles. Both can only choose from allowed checks and references. A model failure does not suppress a rules finding.
- Added a reproducible demo, regression tests, packaging and a Python version matrix for CI.
- Removed the Together provider, inline key configuration and automatic scanning of local text files. See the [upgrade notes](docs/operations.md#upgrade-from-the-2024-script).
