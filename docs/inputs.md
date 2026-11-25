# Input contract

## Normalised event JSONL

Write one UTF-8 JSON object per line. Choose a stable source and asset namespace before exporting and use the same normalisation every time. [Event schema](event-v1.schema.json)

```json
{"event_id":"login-182","source":"identity","asset":"vpn-gateway","timestamp":"2026-11-25T11:00:00+11:00","kind":"auth_failure","principal":"alex","source_ip":"192.0.2.10"}
```

| Field | Meaning |
| --- | --- |
| `event_id`, `source`, `asset` | Required identifiers. An event ID is unique within its source and asset. A replayed observation should keep the same event ID. |
| `timestamp` | Required ISO timestamp with an explicit offset, down to microseconds. The harness normalises it to UTC. |
| `kind` | Required. One of `auth_failure`, `auth_success`, `malware_alert`, `vulnerability_alert` or `security_alert`. |
| `severity` | Optional. `info` (default), `low`, `medium`, `high` or `critical`, as reported by your source. |
| `principal`, `source_ip` | Optional. Both are needed to correlate authentication events. IP addresses are normalised, including IPv4 mapped IPv6. IDs and user names remain case sensitive. |
| `cve` | Required for `vulnerability_alert`, forbidden on other kinds. Indicates a source reported advisory. The harness doesn't reach out to a CVE service or test an asset. |

Severity and attribution are asserted by the producer. The harness verifies structure and internal consistency, not the producer's identity. Use a trusted collector. Deliberately omit messages, commands, payloads, credentials and arbitrary nested data.

Blank lines and identical normalised duplicates are counted. A malformed line, unexpected field or conflicting reuse of the same event identity rejects the entire batch. Limits are 8 MiB, 10,000 lines and 64 KiB per line, including whitespace and delimiters.

## Wazuh manager alert JSONL

Choose `--input-format wazuh` for an ordinary manager alert JSONL export. Wazuh writes alert JSON to `/var/ossec/logs/alerts/alerts.json` by default. Copy or export a completed slice from your collector under its own access rules. The harness does not read the manager automatically. [Wazuh alert management](https://documentation.wazuh.com/current/user-manual/manager/alert-management.html)

- Recognises `rule.groups` values `authentication_failed` and `authentication_success` when exactly one is present. It uses `data.dstuser` or `data.srcuser` and `data.srcip` when usable. An aggregate rule's `firedtimes` is not counted as separate attempts.
- Recognises `vulnerability-detector` alerts with `data.vulnerability.cve` and a known severity. A supplied status must be `Active` (case insensitive). Solved and unsupported records do not count as open findings.
- Treats other alerts with rule level 12 or above as generic high priority signals (15 or above is critical). It doesn't infer malware from a description. The other nonmatching rows are counted as out of scope.
- Uses `wazuh:<manager.name>` as the source, `agent-<agent.id>` as the asset and top level `id` as the observation ID. It discards names, descriptions, `full_log` and any unselected fields.
- Uses the manager alert timestamp, not a decoder's claimed event time embedded in text. If success events are filtered before export, the harness cannot identify a success after a failure burst.

This is not a Wazuh indexer API adapter or an import of the vulnerability inventory index. [Sample manager export](../examples/wazuh-alerts.jsonl) · [Wazuh vulnerability status](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)

## Static folder and live feed coverage

A directory scan inventories regular files recursively. It skips symlinks, common generated directories such as `.git`, `.venv` and `node_modules`, and MASOP's own state directory. The report counts skipped entries, file and byte limits, unreadable inputs and conflicting event identities. JSON exports also include the file inventory. A limit or parse error means partial coverage.

Files ending in `.jsonl`, `.ndjson` and `.json` are recognised as telemetry when their records match the expected shape. A JSON document can contain one event or an array of events. Within a scan, typed events can correlate across files, and duplicate identities are deduplicated. Conflicting versions of an event identity are excluded and counted. Evidence in JSONL points to its file and line. Evidence in an array or multiline object points to a record number and the original document hash.

Small UTF-8 text and config files, including `.env`, are checked for common private key headers and likely hardcoded credential assignments. Findings contain the file, line and check, never the matched value. These are narrow indicators and can miss real secrets or flag a placeholder. Source files are never run. Unknown file types and binaries get an inventory entry, not deep analysis.

Live endpoint polling accepts a supported JSON object, JSON array or newline delimited export. The endpoint is a read only snapshot, not a webhook, SSE or WebSocket. For data that arrives continuously, publish an export with enough overlap to cover the configured correlation window. Live directories wait for two consecutive observations of the same file stamp, then analyse the stable files together. Use a completed export or an atomic drop for busy logs.

A single telemetry response or file is bounded to 8 MiB and 10,000 records. A folder scan reads up to 16 MiB in total, at most 10,000 input telemetry lines across files and up to 20 text check signals per file. The configurable file cap defaults to 200. Text checks skip files larger than 1 MiB. These budgets are reported rather than silently treated as full coverage.
