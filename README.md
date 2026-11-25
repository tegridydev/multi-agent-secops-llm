# MASOP · Multi Agent SecOps LLM

Turn a folder or live feed into a queue of security findings you can trace back to the evidence. Start offline, then add your own models if you want help picking what to check first.

I put the original local LLM prototype on GitHub on **17 May 2024**. MASOP keeps the specialist roles and overseer and gives them a proper operator workflow.

## Start here

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) if you don't have it. Extract the whole release or clone the repo, open a terminal in that folder and run:

```sh
uv run masop.py
```

Press **Enter** for the offline demo. It needs no model, API key or Python packages. uv can provision a compatible Python interpreter if needed. If you already have Python 3.11 or later, `python3 masop.py` also works.

| Menu | What it does |
| --- | --- |
| **1. Configure harness** | Check the setup, change thresholds and live intervals, audit pinned dependencies, or review queued cases. |
| **2. Configure agents** | Discover models on a selected local server, save named local or hosted profiles, test them and assign analyst or reviewer roles. |
| **3. Run static analysis** | Pick a directory. Find correlated events and common credential handling issues. Optionally export Markdown or JSON. |
| **4. Launch live analysis** | Watch a directory for new or changed files, or poll one JSON telemetry endpoint. Press Ctrl+C to return to the menu. |

## Use your own models

Start Ollama, LM Studio, llama.cpp or vLLM in its own app or terminal first. In MASOP, choose **Configure agents → Add or update a model profile → Local model server**. Accept the usual server URL or enter yours, let MASOP list the installed models, and assign the one you want. For hosted models pick a preset, enter the model ID, and supply its key from an environment variable or paste it into the masked session prompt. [Provider setup](docs/providers.md)

Assign profiles to general triage, identity, endpoint, vulnerability or reviewer roles. The rules always decide what lands in the queue. Models can only suggest a verification step from a fixed list. They see finding types, counts and time spans, without raw logs, filenames, IPs, user names or secret values. Hosted calls require explicit configuration and have a request cap. If a model fails, the offline results still work.

## Run without the menu

```sh
uv run masop.py check
uv run masop.py scan ./examples --rules-only --report ./triage.json
uv run masop.py live --directory ./incoming --poll 5
uv run masop.py live --feed http://127.0.0.1:8080/alerts --rules-only
uv run masop.py audit ./uv.lock
```

Directory scans handle event JSONL, Wazuh alert exports and JSON records or arrays. Common text and config files get narrow local checks for possible private keys and hardcoded credentials. Other files are inventoried. It does not execute files, unpack archives, probe networks or act on an alert. [Input contract and coverage](docs/inputs.md)

The startup checks run offline and refuse unexpected runtime dependencies in the release metadata. MASOP installs no Python packages. The optional OSV audit queries known advisories for exact PyPI pins and never installs them. A clean result does not certify a package, operating system or Python interpreter. [Setup and operation](docs/operations.md) · [Security model](SECURITY.md)

Run the tests with `python3 -m unittest discover -s tests -v`. The original `python3 multiagent.py` offline demo and batch CLI still work.

[v0.3.1 live audit and how to repeat it](docs/audit-v0.3.1.md) · [Changelog](CHANGELOG.md) · MIT licensed.
