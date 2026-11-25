# Relaunch copy

## GitHub release title

MASOP v0.3.1 · Real local models, live feeds and OSV verified

## GitHub description

Local defensive triage with folder scans, live telemetry, evidence linked findings and optional model review.

## Ready to post after publishing

Back in May 2024 I put a scrappy SecOps experiment on GitHub. Four LLM roles looked at security data and an overseer stitched their notes together. It ran on Ollama and it did what I wanted at the time.

I revisited it after people started finding the repo again. You can now run it with one command, point it at a folder or a live feed, and get findings you can trace back to the input. Bring your own models if you want an extra opinion on what to check first. The demo works offline with no keys or model setup.

```sh
uv run masop.py
```

[Repo and quick start](https://github.com/tegridydev/multi-agent-secops-llm) · [Original May 2024 MVP](https://github.com/tegridydev/multi-agent-secops-llm/commit/457eb272d04b85ab165548eb17cd994827e4c718)
