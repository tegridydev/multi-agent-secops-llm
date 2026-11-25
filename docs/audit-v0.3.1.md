# MASOP v0.3.1 end to end audit

Run on **25 November 2026** using Linux x86_64, Python 3.12 and Ollama 0.40.18 on CPU. The local model was `qwen2.5:0.5b` Q4_K_M, registry manifest `a8b0c5157701`. The runtime archive and model blob were checked against published SHA256 digests. Ollama ran with cloud features disabled and no proxy configuration. [Ollama release assets](https://github.com/ollama/ollama/releases/tag/v0.40.18) · [Model card](https://ollama.com/library/qwen2.5:0.5b)

| Path | Observed result |
| --- | --- |
| Local model | Real Ollama calls produced a valid proposal and review for a directory scan and two live cases. Two checks were accepted and one requested more software context. |
| Terminal setup | A fresh terminal session discovered the installed model, assigned it, and passed the synthetic profile test using the same local daemon. |
| Live feed | An authenticated loopback server returned 200, 304, 200, 503 and 304. MASOP emitted two reports, stayed up on the 503 and recovered without duplicating cases. Data was synthetic defensive telemetry. |
| OSV with advisories | Live lookup for `requests==2.31.0` returned six advisory IDs and exit 3. No package was installed. |
| OSV without matches | Live lookup for `requests==2.34.2` returned no known advisories and exit 0 on the audit date. The result can change. |
| OSV with connectivity failure | The direct DNS path on this proxy-only network failed with exit 1. It did not print a clean result. |

## What changed

The old reviewer schema allowed separate valid values for verdict and context. The real model returned `accept` together with `software_inventory` for the same proposal. MASOP correctly rejected the combination, but users saw no useful advice. The new schema lets the reviewer choose either acceptance or a single context request. MASOP binds the review to the original finding. The analyst also picks an allowed finding and check pair as one option.

The public OSV request worked via the environment's HTTPS proxy while v0.3.0 always attempted direct DNS. v0.3.1 can tunnel its optional OSV request through the configured HTTP CONNECT proxy and still checks the OSV certificate. It never uses that proxy for models or telemetry. Invalid or incomplete audit responses are errors, never zero findings. [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)

The setup audit also caught model base URLs under a prefix. A URL such as `http://127.0.0.1:8000/gateway/v1` now keeps `/gateway` when MASOP constructs the completion and local model discovery routes.

## Repeat the test

If Ollama isn't running, start the Ollama app or run `OLLAMA_NO_CLOUD=1 ollama serve` in another terminal. Then run from the repo root:

```sh
ollama pull qwen2.5:0.5b
python3 scripts/audit_e2e.py
```

You can use `--ollama-url` for another loopback port or `--model` to test another installed local model. Use `--osv-clean-pin package==version` to change the comparison pin if OSV is updated, or `--skip-osv` to run only the local paths. The script uses temporary config and report folders and supplies its own local feed. It doesn't need your telemetry, keys or production services.

This smoke test checks the workflow and boundaries, not SOC detection accuracy. Hosted models were not part of the real inference run.
