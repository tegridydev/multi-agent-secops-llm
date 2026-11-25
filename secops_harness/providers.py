"""Model profiles and supported, stateless text inference contracts."""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from time import monotonic
from typing import Any

from .agents import Adviser, InvalidReply, Unavailable, validate_model, validate_model_id
from .domain import Case, Rule, canonical_json, strict_json
from .transport import Endpoint, InvalidBody, NetworkError, credential, endpoint, request

NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}", re.ASCII)
ENV = re.compile(r"[A-Z][A-Z0-9_]{0,63}", re.ASCII)
GEMINI_ID = re.compile(r"(?:models/)?([a-zA-Z0-9][a-zA-Z0-9._-]{0,100})", re.ASCII)
ROLES = {
    "triage": "General triage",
    "identity": "Identity and sign-ins",
    "endpoint": "Endpoint detections",
    "vulnerability": "Vulnerability reports",
    "reviewer": "Overseer and review",
}


@dataclass(frozen=True, slots=True)
class Preset:
    label: str
    dialect: str
    url: str = ""
    key_env: str = ""
    adjustable: bool = False
    auth: str = "bearer"
    token_field: str = "max_tokens"


PRESETS = {
    "ollama": Preset("Ollama", "ollama", "http://127.0.0.1:11434/api/chat", adjustable=True),
    "lmstudio": Preset("LM Studio", "chat", "http://127.0.0.1:1234/v1/chat/completions", adjustable=True),
    "llamacpp": Preset("llama.cpp", "chat", "http://127.0.0.1:8080/v1/chat/completions", adjustable=True),
    "vllm": Preset("vLLM", "chat", "http://127.0.0.1:8000/v1/chat/completions", adjustable=True),
    "openai": Preset("OpenAI", "responses", "https://api.openai.com/v1/responses", "OPENAI_API_KEY"),
    "anthropic": Preset(
        "Anthropic", "messages", "https://api.anthropic.com/v1/messages", "ANTHROPIC_API_KEY"
    ),
    "gemini": Preset(
        "Google Gemini",
        "gemini",
        "https://generativelanguage.googleapis.com/v1beta",
        "GEMINI_API_KEY",
        auth="google",
    ),
    "azure": Preset(
        "Azure OpenAI v1",
        "chat",
        key_env="AZURE_OPENAI_API_KEY",
        adjustable=True,
        auth="api-key",
        token_field="max_completion_tokens",
    ),
    "openrouter": Preset(
        "OpenRouter", "chat", "https://openrouter.ai/api/v1/chat/completions", "OPENROUTER_API_KEY"
    ),
    "groq": Preset(
        "Groq",
        "chat",
        "https://api.groq.com/openai/v1/chat/completions",
        "GROQ_API_KEY",
        token_field="max_completion_tokens",
    ),
    "together": Preset(
        "Together AI", "chat", "https://api.together.ai/v1/chat/completions", "TOGETHER_API_KEY"
    ),
    "deepseek": Preset("DeepSeek", "chat", "https://api.deepseek.com/chat/completions", "DEEPSEEK_API_KEY"),
    "mistral": Preset(
        "Mistral", "chat", "https://api.mistral.ai/openai/v1/chat/completions", "MISTRAL_API_KEY"
    ),
    "xai": Preset("xAI", "responses", "https://api.x.ai/v1/responses", "XAI_API_KEY"),
    "custom-chat": Preset("Custom Chat Completions", "chat", adjustable=True),
    "custom-responses": Preset("Custom Responses", "responses", adjustable=True),
}
LOCAL_PRESETS = ("ollama", "lmstudio", "llamacpp", "vllm")


def _completion_route(target: Endpoint, dialect: str) -> Endpoint:
    base = target.path.rstrip("/")
    if dialect == "ollama":
        if base in ("", "/v1"):
            base = "/api"
        return target.at(base + "/chat") if base.endswith("/api") else target
    if base in ("", "/api"):
        base = "/v1"
    if base.endswith("/v1"):
        return target.at(base + ("/chat/completions" if dialect == "chat" else "/responses"))
    return target


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    provider: str
    model: str
    url: str = ""
    key_env: str = ""
    remote_allowed: bool = False
    allow_lan: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not NAME.fullmatch(self.name):
            raise ValueError("profile names use 1 to 32 letters, digits, dashes or underscores")
        if not isinstance(self.provider, str) or self.provider not in PRESETS:
            raise ValueError("unknown provider")
        if not isinstance(self.url, str) or not isinstance(self.key_env, str):
            raise ValueError("endpoint and credential names must be text")
        if type(self.remote_allowed) is not bool or type(self.allow_lan) is not bool:
            raise ValueError("invalid network settings")
        validate_model_id(self.model)
        if self.provider == "ollama":
            validate_model(self.model)
        if self.provider == "gemini" and not GEMINI_ID.fullmatch(self.model):
            raise ValueError("use a Gemini model ID, optionally prefixed with models/")
        if self.key_name and not ENV.fullmatch(self.key_name):
            raise ValueError("enter the environment variable name, not the key itself")
        target = self.target()
        if not target.loopback and not self.remote_allowed:
            raise ValueError("this endpoint is off this computer; explicit approval is needed")
        if self.allow_lan and (not self.preset.adjustable or target.loopback):
            raise ValueError("private LAN routing is only for a custom remote HTTPS endpoint")

    @property
    def preset(self) -> Preset:
        return PRESETS[self.provider]

    @property
    def key_name(self) -> str:
        return self.key_env or self.preset.key_env

    def target(self) -> Endpoint:
        preset = self.preset
        if self.url and not preset.adjustable:
            raise ValueError(
                "this provider preset has a fixed endpoint; use a custom profile for another host"
            )
        target = endpoint(self.url or preset.url)
        if self.provider == "azure":
            if (
                target.scheme != "https"
                or not target.host.endswith(
                    (".openai.azure.com", ".services.ai.azure.com", ".cognitiveservices.azure.com")
                )
                or target.port != 443
                or target.path.rstrip("/") not in ("/", "", "/openai/v1", "/openai/v1/chat/completions")
            ):
                raise ValueError(
                    "use your Azure resource HTTPS URL or its /openai/v1/chat/completions endpoint"
                )
            return target.at("/openai/v1/chat/completions")
        if preset.dialect == "gemini":
            model = GEMINI_ID.fullmatch(self.model)
            if not model:
                raise ValueError("invalid Gemini model ID")
            return target.at(f"{target.path.rstrip('/')}/models/{model[1]}:generateContent")
        return _completion_route(target, preset.dialect) if preset.adjustable else target

    def headers(self, session_keys: Mapping[str, str]) -> dict[str, str]:
        output = {}
        if self.provider == "anthropic":
            output["anthropic-version"] = "2026-10-21"
        if name := self.key_name:
            value = session_keys.get(self.name) or os.environ.get(name)
            if not value:
                raise Unavailable(f"set {name} or add a session key in Configure agents")
            secret = credential(value)
            if self.preset.auth == "google":
                output["x-goog-api-key"] = secret
            elif self.preset.auth == "api-key":
                output["api-key"] = secret
            else:
                output["Authorization"] = f"Bearer {secret}"
        return output


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvalidReply("expected a model reply object")
    return value


def _items(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise InvalidReply("expected a list in the model reply")
    return value


def _one(value: Any) -> dict[str, Any]:
    rows = _items(value)
    if len(rows) != 1:
        raise InvalidReply("expected a single model answer")
    return _object(rows[0])


def _text_parts(parts: Any, part_type: str) -> str:
    output = []
    for raw in _items(parts):
        part = _object(raw)
        if part.get("type") not in (part_type, "thinking", "redacted_thinking"):
            raise InvalidReply("unexpected model reply block")
        if part.get("type") == part_type:
            if not isinstance(part.get("text"), str):
                raise InvalidReply("expected a text reply")
            output.append(part["text"])
    return "".join(output)


def _answer(dialect: str, raw: Any) -> dict[str, Any]:
    env = _object(raw)
    text = None
    if dialect in ("chat", "ollama"):
        if dialect == "chat":
            choice = _one(env.get("choices"))
            if choice.get("finish_reason") != "stop":
                raise InvalidReply("chat did not end with a complete text answer")
            message = _object(choice.get("message"))
        else:
            if env.get("done") is not True or env.get("done_reason") not in (None, "stop"):
                raise InvalidReply("Ollama did not finish with a complete answer")
            message = _object(env.get("message"))
        if message.get("role") != "assistant" or any(
            message.get(k) for k in ("tool_calls", "function_call", "refusal")
        ):
            raise InvalidReply("expected assistant text without tools")
        text = message.get("content")
    elif dialect == "responses":
        if env.get("status") != "completed":
            raise InvalidReply("Responses reply was not completed")
        messages = []
        for raw_item in _items(env.get("output")):
            item = _object(raw_item)
            if item.get("type") == "reasoning":
                continue
            if (
                item.get("type") != "message"
                or item.get("role") != "assistant"
                or item.get("status") != "completed"
            ):
                raise InvalidReply("unexpected Responses output item")
            messages.append(item)
        text = _text_parts(_one(messages).get("content"), "output_text")
    elif dialect == "messages":
        if env.get("role") != "assistant" or env.get("stop_reason") != "end_turn":
            raise InvalidReply("Messages reply was not a complete assistant turn")
        text = _text_parts(env.get("content"), "text")
    elif dialect == "gemini":
        candidate = _one(env.get("candidates"))
        if candidate.get("finishReason") != "STOP":
            raise InvalidReply("Gemini did not finish with a complete answer")
        pieces = []
        for raw_part in _items(_object(candidate.get("content")).get("parts")):
            part = _object(raw_part)
            if not isinstance(part.get("text"), str) or set(part) - {"text", "thought", "thoughtSignature"}:
                raise InvalidReply("expected Gemini text without tools")
            if part.get("thought") is not True:
                pieces.append(part["text"])
        text = "".join(pieces)
    if not isinstance(text, str) or not text:
        raise InvalidReply("model returned no text")
    try:
        return _object(strict_json(text))
    except (ValueError, RecursionError):
        raise InvalidReply("model text was not a valid JSON object") from None


def _body(profile: Profile, system: str, payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    dialect = profile.preset.dialect
    text = canonical_json(payload)
    instruction = system + "\nReturn exactly a JSON object fitting this schema: " + canonical_json(schema)
    messages = [{"role": "system", "content": instruction}, {"role": "user", "content": text}]
    if dialect == "chat":
        body = {
            "model": profile.model,
            "messages": messages,
            "stream": False,
            profile.preset.token_field: 768,
        }
        if profile.provider == "deepseek":
            body["reasoning_effort"] = "none"
        return body
    if dialect == "responses":
        body = {
            "model": profile.model,
            "input": messages,
            "store": False,
            "stream": False,
            "max_output_tokens": 768,
        }
        if profile.provider == "openai":
            body["text"] = {
                "format": {"type": "json_schema", "name": "masop_advice", "strict": True, "schema": schema}
            }
        return body
    if dialect == "messages":
        return {
            "model": profile.model,
            "system": instruction,
            "messages": messages[1:],
            "max_tokens": 768,
            "stream": False,
        }
    if dialect == "gemini":
        return {
            "systemInstruction": {"parts": [{"text": instruction}]},
            "contents": [{"role": "user", "parts": [{"text": text}]}],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseJsonSchema": schema,
                "maxOutputTokens": 768,
            },
        }
    return {
        "model": profile.model,
        "messages": messages,
        "format": schema,
        "stream": False,
        "options": {"temperature": 0, "num_predict": 320, "num_ctx": 4096},
    }


class SessionCap(Unavailable):
    """Session model call cap reached; rules can continue."""


@dataclass(slots=True)
class Budget:
    limit: int
    used: int = 0
    cooldowns: dict[str, float] = field(default_factory=dict)

    def claim(self, profile: Profile) -> None:
        if self.used >= self.limit:
            raise SessionCap("session model request cap reached")
        if self.cooldowns.get(profile.name, 0) > monotonic():
            raise Unavailable("profile is in cooldown after a connection error")
        self.used += 1


@dataclass(frozen=True, slots=True)
class Client:
    profile: Profile
    keys: Mapping[str, str]
    budget: Budget
    timeout: int = 25

    def ask(self, model: str, system: str, payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
        if model != self.profile.model:
            raise Unavailable("agent route no longer matches its configured model")
        try:
            headers = self.profile.headers(self.keys)
            self.budget.claim(self.profile)
            raw = request(
                self.profile.target(),
                method="POST",
                data=_body(self.profile, system, payload, schema),
                headers=headers,
                timeout=self.timeout,
                allow_lan=self.profile.allow_lan,
            ).json()
        except InvalidBody:
            raise InvalidReply("provider returned invalid or oversized JSON") from None
        except NetworkError as error:
            self.budget.cooldowns[self.profile.name] = monotonic() + 30
            raise Unavailable(str(error)) from None
        except ValueError as error:
            raise Unavailable(str(error)) from None
        return _answer(self.profile.preset.dialect, raw)


def discover(provider: str, url: str, headers: dict[str, str] | None = None) -> list[str]:
    """List already served models on one selected localhost endpoint."""
    if provider not in LOCAL_PRESETS:
        return []
    preset = PRESETS[provider]
    target = endpoint(url or preset.url)
    if not target.loopback:
        return []
    target = _completion_route(target, preset.dialect)
    base = target.path.rstrip("/")
    if preset.dialect == "ollama":
        if not base.endswith("/api/chat"):
            return []
        path, key, field_name = base.removesuffix("/chat") + "/tags", "models", "name"
    else:
        if not base.endswith("/chat/completions"):
            return []
        path, key, field_name = base.removesuffix("/chat/completions") + "/models", "data", "id"
    envelope = request(target.at(path), headers=headers, timeout=3, max_bytes=512 * 1024).json()
    entries = envelope.get(key) if isinstance(envelope, dict) else None
    if not isinstance(entries, list):
        raise NetworkError("model server did not return a list")
    valid = set()
    for item in entries[:200]:
        model = item.get(field_name) if isinstance(item, dict) else None
        try:
            valid.add((validate_model if provider == "ollama" else validate_model_id)(model))
        except ValueError:
            continue
    return sorted(valid)


_RULE_SLOT = {
    Rule.AUTH_BURST: "identity",
    Rule.AUTH_SUCCESS_AFTER: "identity",
    Rule.MALWARE: "endpoint",
    Rule.VULNERABILITY: "vulnerability",
}


@dataclass(slots=True)
class RoutedAdviser:
    profiles: Mapping[str, Profile]
    roles: Mapping[str, str]
    keys: Mapping[str, str]
    budget: Budget
    max_cases: int
    timeout: int
    skip: set[str] = field(default_factory=set)
    attempted: int = 0

    def advise(self, case: Case) -> dict[str, Any]:
        if case.case_id in self.skip:
            return {"status": "already_observed"}
        if self.budget.limit - self.budget.used < 2:
            return {"status": "session_budget_skipped"}
        if self.attempted >= self.max_cases:
            return {"status": "budget_skipped"}
        slot = _RULE_SLOT.get(case.findings[0].rule, "triage")
        first = self.roles.get(slot) or self.roles.get("triage")
        if not first:
            return {"status": "disabled"}
        reviewer = self.roles.get("reviewer") or first
        analyst_profile, reviewer_profile = self.profiles[first], self.profiles[reviewer]
        self.attempted += 1
        agent = Adviser(
            Client(analyst_profile, self.keys, self.budget, self.timeout),
            analyst_profile.model,
            reviewer_profile.model,
            reviewer_backend=Client(reviewer_profile, self.keys, self.budget, self.timeout),
        )
        result = agent.advise(case)
        return {
            **result,
            "analyst_profile": first,
            "reviewer_profile": reviewer,
            "role": slot if slot in self.roles else "triage",
        }
