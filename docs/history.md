# What was online in May 2024

**A dated, early open source example of local LLM roles for defensive security analysis.** There were already LLM security products and general multi agent frameworks. The part that holds up here is taking four separate security jobs and using an overseer to assemble a brief, with local Ollama as the default in the MVP.

The 2024 script used separate prompts for threat intelligence, log analysis, vulnerability assessment and incident response. A fifth role combined their output. All five defaulted to the same `phi3` model. They were sequential roles in a file based prototype, not five independent runtimes or an autonomous SOC. [MVP code at that date](https://github.com/tegridydev/multi-agent-secops-llm/blob/457eb272d04b85ab165548eb17cd994827e4c718/multiagent.py)

## Public evidence

Git history and the archived public GitHub event stream agree on the release date. These times are UTC on **17 May 2024**. The local time in Melbourne was ten hours ahead.

| Time | Evidence |
| --- | --- |
| 01:43:43 | Initial licence and README commit. [7945e62](https://github.com/tegridydev/multi-agent-secops-llm/commit/7945e62d099d33d813fbcf048bdf1a12975a3749) |
| 01:43:44 | Repository and main branch creation in GH Archive. |
| 01:44:57 | First implementation committed, public push at 01:45:04. [d665216](https://github.com/tegridydev/multi-agent-secops-llm/commit/d6652166ca6b80db44835aef7669fc31e2d0c171) |
| 01:51:19 | Ollama integration in the code, public push at 01:51:30. [4cd92d1](https://github.com/tegridydev/multi-agent-secops-llm/commit/4cd92d1a39f2ecba50087170ecf8618a09e26e41) |
| 02:21:12 | Commit titled working MVP with the overseer and local default, public push at 02:21:18. [457eb27](https://github.com/tegridydev/multi-agent-secops-llm/commit/457eb272d04b85ab165548eb17cd994827e4c718) |

You can independently check the creation and push records in the ClickHouse public copy of GH Archive. Use the [ClickHouse SQL Playground](https://play.clickhouse.com/) or its documented public HTTP query endpoint. [GH Archive](https://www.gharchive.org/) · [About the public dataset](https://ghe.clickhouse.tech/)

```sql
SELECT event_type, created_at, ref, ref_type
FROM github_events
WHERE repo_name = 'tegridydev/multi-agent-secops-llm'
  AND created_at >= '2024-05-17 00:00:00'
  AND created_at < '2024-05-18 00:00:00'
ORDER BY created_at, event_type, ref_type;
```

## How early was it?

| Public date | Project or publication | What it establishes |
| --- | --- | --- |
| 28 Mar 2023 | [Microsoft Security Copilot](https://www.microsoft.com/en-us/security/blog/2023/03/28/introducing-microsoft-security-copilot-empowering-defenders-at-the-speed-of-ai/) | LLM support for defenders already existed as an announced category. |
| 2 Aug 2023 | [Torq Socrates](https://torq.io/news/socrates/) | Earlier commercial generative AI agent for SOC triage and investigation. |
| 8 Aug 2023 | [Dropzone AI](https://venturebeat.com/ai/dropzone-ai-launches-autonomous-ai-agent-to-investigate-security-alerts-raises-3-5m-in-seed-funding) | Earlier commercial LLM agent for autonomous alert investigation. |
| 16 Aug 2023 | [AutoGen preprint](https://arxiv.org/abs/2308.08155) | General multi agent LLM orchestration, rather than a dedicated local SecOps prototype. |
| 2 Mar 2024 | [AutoDefense preprint](https://arxiv.org/abs/2403.04783) | Earlier multi agent LLM security work aimed at protecting model outputs, rather than analysing SOC evidence. |
| 17 May 2024 | [Multi Agent SecOps LLM MVP](https://github.com/tegridydev/multi-agent-secops-llm/commit/457eb272d04b85ab165548eb17cd994827e4c718) | Public MIT licensed local workflow with four specialist roles and an overseer. |
| 11 Dec 2024 | [Torq multi agent framework](https://torq.io/news/torq-expands-agentic-ai/) | Torq announced its broader multi agent SecOps architecture about seven months later. This is a date comparison, not a claim about influence. |
| 24 Mar 2025 | [Microsoft Security Copilot agents](https://www.microsoft.com/en-us/security/blog/2025/03/24/microsoft-unveils-microsoft-security-copilot-agents-and-new-protections-for-ai/) | Microsoft announced specialised security agents after its earlier Copilot launch. |
| 30 Sep 2025 | [CORTEX preprint](https://arxiv.org/abs/2510.00311) | A later research example of specialised LLM agents for evidence based alert triage. |

I compared indexed GitHub repositories, public repository creation events using SecOps and multi agent name variants, arXiv and company announcements. The search didn't turn up a verified earlier open source Ollama workflow with this particular role split and brief. That isn't evidence that no earlier project exists. Repo names miss code inside broader projects, and public archives can't establish private or unindexed work.

The strongest claim is the one the commits can back up. **I published a local, open source multi agent SecOps prototype in May 2024.** Avoid claims that it was the first AI SOC, the first security agent, or the first multi agent LLM system.
