# Connect your models

Open **Configure agents → Add or update a model profile**. Pick a provider, set the model ID and give the profile a short name. Run the synthetic test before assigning it to a role. That test sends no real telemetry, but a hosted provider can charge for it.

## Local servers

Start the server and load a model in that app first. MASOP can list the models served at the chosen loopback address. It never downloads models, installs a server or starts a background service.

| Preset | Default request endpoint |
| --- | --- |
| Ollama | `http://127.0.0.1:11434/api/chat` · [API](https://docs.ollama.com/api/chat) |
| LM Studio | `http://127.0.0.1:1234/v1/chat/completions` · [API](https://lmstudio.ai/docs/developer/openai-compat) |
| llama.cpp | `http://127.0.0.1:8080/v1/chat/completions` · [Server docs](https://github.com/ggml-org/llama.cpp/tree/master/tools/server) |
| vLLM | `http://127.0.0.1:8000/v1/chat/completions` · [API](https://docs.vllm.ai/en/stable/serving/openai_compatible_server/) |

For Ollama, use a local tag and disable cloud features in the daemon if you require on device inference. The harness rejects native Ollama cloud tag designations but cannot attest to daemon settings or model aliases. [Ollama local mode](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features)

## Hosted presets

| Provider | API contract | Default credential variable |
| --- | --- | --- |
| OpenAI | [Responses](https://platform.openai.com/docs/api-reference/responses/create) | `OPENAI_API_KEY` |
| Anthropic | [Messages](https://platform.claude.com/docs/en/api/messages/create) | `ANTHROPIC_API_KEY` |
| Google Gemini | [generateContent](https://ai.google.dev/api/generate-content) | `GEMINI_API_KEY` |
| Azure OpenAI | [Chat Completions v1](https://learn.microsoft.com/en-us/azure/foundry/openai/latest) | `AZURE_OPENAI_API_KEY` |
| OpenRouter | [Chat Completions](https://openrouter.ai/docs/api-reference/chat-completion) | `OPENROUTER_API_KEY` |
| Groq | [Chat Completions](https://console.groq.com/docs/openai) | `GROQ_API_KEY` |
| Together AI | [Chat Completions](https://docs.together.ai/docs/inference/openai-compatibility) | `TOGETHER_API_KEY` |
| DeepSeek | [Chat Completions](https://api-docs.deepseek.com/api/create-chat-completion/) | `DEEPSEEK_API_KEY` |
| Mistral | [OpenAI compatible Chat Completions](https://docs.mistral.ai/inference/conversations/chat-completion) | `MISTRAL_API_KEY` |
| xAI | [Responses](https://docs.x.ai/developers/rest-api-reference/inference/responses) | `XAI_API_KEY` |

Use the model ID listed for your account. For Azure enter the resource URL and your deployment name. The direct adapters use API keys or bearer tokens. Native AWS IAM signing, Google Vertex authentication and browser sign in are not included.

For another server, use **Custom Chat Completions** or **Custom Responses**. Enter a compatible API URL, model ID and, if needed, the name of a bearer token variable. A base URL ending in `/v1` is expanded to the standard path. For a different API prefix, give the full route. API gateways with one of these contracts can serve other backends. Compatibility depends on the specific server and model returning complete text or JSON. Some models may refuse these small constrained calls or exceed the output budget.

Plain HTTP is only for a loopback server on your own computer. Use HTTPS for every other address. For a private LAN server, explicitly allow that route and use a certificate your system trusts. There is no insecure TLS bypass, ambient proxy use or redirect following. Do not put credentials in URLs.

## Keys, roles and budgets

Save only the name of a key variable in the profile. Use **Add a key for this session** for masked input that disappears on exit. A pasted key belongs to the selected profile and is cleared when that profile changes. For automation, set the environment variable before launching MASOP. Telemetry feeds have separate bearer token variables.

The highest priority finding selects a specialist when one is assigned. Otherwise MASOP uses general triage. The reviewer can use another provider, or the analyst's model if you haven't assigned one. A profile can serve more than one role. Case priority and evidence are never model decisions.

By default MASOP annotates at most one case each batch and makes at most 20 model calls per static or live run. A complete proposal and review needs two calls. Tune both numbers in **Configure harness** or set either to zero. Leave hosted profiles unassigned, or run with `--rules-only`, when you do not want inference.
