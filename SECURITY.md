# Security model

MASOP is a defensive triage tool for local operators. It does not replace a SIEM, run offensive workflows or declare an incident confirmed.

- The default startup and demo are offline. MASOP installs no Python runtime packages, model weights or servers. Its metadata check is not a security guarantee for uv, Python, the operating system or a modified checkout. The optional OSV audit is a known advisory lookup for exact package versions, not a malware scan or a permission to install.
- Rules, evidence and review decisions are controlled by Python and SQLite. Models have no shell, file, network, SIEM or remediation tools. Both replies are checked against the actual cited finding and an allowlist of checks.
- Hosted model routes require explicit operator configuration. Sent prompts contain a bounded projection of finding classes, counts and spans. They do not contain raw records, paths, secret values or account identifiers. API keys are not saved in the config. Provider processing, billing and data policies still apply.
- Only operator configured HTTP endpoints are used. Nonloopback routes require verified HTTPS. DNS answers are checked before a connection and the selected address is pinned for that request. Model and telemetry requests never follow redirects or use ambient proxies. The optional dependency audit may use the configured HTTP CONNECT proxy for the fixed OSV HTTPS host, with hostname and certificate verification retained. Local and LAN daemons must still be trusted.
- Folder and feed analysis is read only. It never executes input, opens archives or forwards instructions found in a file. Source records may be wrong or manipulated. A valid citation means the reference exists, not that the incident or model advice is correct.
- Local reports and queue snapshots can contain identifiers, paths and operator notes. Keep them private and use the host's account permissions, backups and retention policy. Report security bugs privately via GitHub advisory reporting if enabled.

Design references include [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), [OWASP Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) and [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/top-10-for-agentic-applications-2026/).
