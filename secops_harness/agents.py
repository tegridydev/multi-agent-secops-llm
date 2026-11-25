"""Optional, tool-free analyst and reviewer over a narrow typed projection."""

import http.client
import re
from dataclasses import dataclass
from typing import Any, Protocol

from .domain import Case, Finding, Rule, canonical_json, strict_json

MAX_MODEL_FINDINGS = 8
MAX_REPLY_BYTES = 64 * 1024
AGENT_CONTRACT = "agents-v2"
MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", re.ASCII)
CHECKS = {
    "verify_identity_context": "Verify the account and authentication context in the source logs.",
    "check_auth_baseline": "Compare with the normal failure baseline for this account and source.",
    "verify_success_with_owner": "Confirm whether the successful login was expected with the account owner.",
    "check_adjacent_auth_events": "Review adjacent authentication events and determine which session succeeded.",
    "verify_endpoint_detection": "Confirm the detection and disposition in the endpoint console.",
    "check_endpoint_timeline": "Inspect the endpoint timeline around the reported detection.",
    "verify_installed_version": "Check the installed version and vendor advisory before treating the asset as affected.",
    "check_patch_plan": "Check patch ownership, exceptions and the approved maintenance window.",
    "verify_source_alert": "Check the original alert, its rule and any source-side disposition.",
    "check_asset_timeline": "Review nearby logs for independent corroboration.",
    "verify_key_material": "Verify locally whether the reported material is a real private key.",
    "review_key_handling": "Check approved key storage and follow your rotation process if exposed.",
    "verify_credential_assignment": "Check locally for a hardcoded credential rather than a placeholder.",
    "review_secret_storage": "If this contains a real credential, review its handling with the owner.",
}
FINDING_CHECKS: dict[Rule, tuple[str, str]] = {
    Rule.AUTH_BURST: ("verify_identity_context", "check_auth_baseline"),
    Rule.AUTH_SUCCESS_AFTER: ("verify_success_with_owner", "check_adjacent_auth_events"),
    Rule.MALWARE: ("verify_endpoint_detection", "check_endpoint_timeline"),
    Rule.VULNERABILITY: ("verify_installed_version", "check_patch_plan"),
    Rule.SECURITY: ("verify_source_alert", "check_asset_timeline"),
    Rule.ARTIFACT_KEY: ("verify_key_material", "review_key_handling"),
    Rule.ARTIFACT_CREDENTIAL: ("verify_credential_assignment", "review_secret_storage"),
}
CONTEXT_CHECKS = {
    "alert_confirmation": "Get the original source alert and disposition.",
    "identity_context": "Confirm the account owner and expected login activity.",
    "asset_context": "Confirm ownership and normal behaviour for this asset.",
    "software_inventory": "Confirm installed versions and the patch inventory.",
}
FINDING_CONTEXT: dict[Rule, tuple[str, ...]] = {
    Rule.AUTH_BURST: ("identity_context", "asset_context"),
    Rule.AUTH_SUCCESS_AFTER: ("identity_context", "asset_context"),
    Rule.MALWARE: ("alert_confirmation", "asset_context"),
    Rule.VULNERABILITY: ("software_inventory", "asset_context"),
    Rule.SECURITY: ("alert_confirmation", "asset_context"),
    Rule.ARTIFACT_KEY: ("alert_confirmation", "asset_context"),
    Rule.ARTIFACT_CREDENTIAL: ("alert_confirmation", "asset_context"),
}


class InvalidReply(ValueError):
    """The daemon replied but the artifact must not be used."""


class Unavailable(RuntimeError):
    """The local model or service was unavailable."""


class Backend(Protocol):
    def ask(
        self, model: str, system: str, payload: dict[str, Any], schema: dict[str, Any]
    ) -> dict[str, Any]: ...


class Advice(Protocol):
    def advise(self, case: Case) -> dict[str, Any]: ...


def validate_model_id(model: str) -> str:
    if not isinstance(model, str) or not MODEL_ID.fullmatch(model) or "://" in model:
        raise ValueError("use a model identifier from your server or provider")
    return model


def validate_model(model: str) -> str:
    if (
        not isinstance(model, str)
        or not MODEL_ID.fullmatch(model)
        or "://" in model
        or "cloud" in re.split(r"[-_:/\.]", model.lower())
    ):
        raise ValueError("model must be a local Ollama tag, without a cloud designation")
    return model


@dataclass(frozen=True, slots=True)
class Ollama:
    port: int = 11434
    timeout: float = 30

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid Ollama port")
        if not 1 <= self.timeout <= 120:
            raise ValueError("invalid Ollama socket timeout")

    def ask(self, model: str, system: str, payload: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
        request = canonical_json(
            {
                "model": validate_model(model),
                "stream": False,
                "format": schema,
                "options": {"temperature": 0, "num_predict": 256, "num_ctx": 4096},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": canonical_json(payload)},
                ],
            }
        ).encode("ascii")
        # A fixed numeric address and direct HTTPConnection mean no DNS, proxies or redirect handling.
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            connection.request(
                "POST", "/api/chat", body=request, headers={"Content-Type": "application/json"}
            )
            with connection.getresponse() as response:
                if response.status != 200:
                    raise Unavailable("local Ollama did not return a successful response")
                if response.length is not None and response.length > MAX_REPLY_BYTES:
                    raise InvalidReply("model reply exceeds byte limit")
                raw = response.read(MAX_REPLY_BYTES + 1)
                if response.length not in (None, 0):
                    raise InvalidReply("incomplete model reply")
        except (OSError, http.client.HTTPException) as error:
            raise Unavailable("local Ollama connection failed") from error
        finally:
            connection.close()
        if len(raw) > MAX_REPLY_BYTES:
            raise InvalidReply("model reply exceeds byte limit")
        try:
            envelope = strict_json(raw)
            if not isinstance(envelope, dict) or envelope.get("done") is not True:
                raise InvalidReply("expected a completed Ollama reply")
            if envelope.get("done_reason") not in (None, "stop"):
                raise InvalidReply("model did not finish normally")
            message = envelope.get("message")
            if (
                not isinstance(message, dict)
                or message.get("role") != "assistant"
                or message.get("tool_calls")
                or not isinstance(message.get("content"), str)
            ):
                raise InvalidReply("expected assistant content without tool calls")
            reply = strict_json(message["content"])
            if not isinstance(reply, dict):
                raise InvalidReply("model content is not an object")
            return reply
        except (ValueError, RecursionError) as error:
            raise InvalidReply("invalid model reply") from error


def _schema(**values: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(values),
        "properties": {key: {"type": "string", "enum": options} for key, options in values.items()},
    }


def _selection(output: dict[str, Any], key: str, choices: dict[str, Any]) -> str:
    if not isinstance(output, dict) or set(output) != {key} or not isinstance(output[key], str):
        raise InvalidReply("model fields do not match the contract")
    if output[key] not in choices:
        raise InvalidReply(f"model did not select an allowed {key}")
    return output[key]


def _projection(finding_id: str, finding: Finding) -> dict[str, Any]:
    stamps = [row.event.timestamp for row in finding.evidence]
    return {
        "finding": finding_id,
        "rule": finding.rule,
        "severity": finding.severity,
        "evidence_count": len(stamps),
        "span_seconds": int((max(stamps) - min(stamps)).total_seconds()),
        "checks": list(FINDING_CHECKS[finding.rule]),
        "available_context_requests": list(FINDING_CONTEXT[finding.rule]),
    }


@dataclass(slots=True)
class Adviser:
    backend: Backend
    analyst_model: str
    reviewer_model: str
    max_cases: int = 1
    reviewer_backend: Backend | None = None
    _attempted: int = 0
    _unavailable: bool = False

    def __post_init__(self) -> None:
        validate_model_id(self.analyst_model)
        validate_model_id(self.reviewer_model)
        if not 1 <= self.max_cases <= 5:
            raise ValueError("model case budget must be between 1 and 5")

    def advise(self, case: Case) -> dict[str, Any]:
        if self._unavailable:
            return {"status": "backend_skipped"}
        if self._attempted >= self.max_cases:
            return {"status": "budget_skipped"}
        self._attempted += 1

        findings = {f"f{number}": item for number, item in enumerate(case.findings[:MAX_MODEL_FINDINGS], 1)}
        # Encode allowed combinations as one choice. Independent JSON enums cannot enforce the relation.
        choices = {
            f"{finding_id}:{check}": (finding_id, check)
            for finding_id, item in findings.items()
            for check in FINDING_CHECKS[item.rule]
        }
        payload = {
            "findings": [_projection(key, value) for key, value in findings.items()],
            "omitted_findings": len(case.findings) - len(findings),
        }
        metadata = {
            "analyst_model": self.analyst_model,
            "reviewer_model": self.reviewer_model,
            "contract": AGENT_CONTRACT,
            "omitted_findings": payload["omitted_findings"],
        }

        def unavailable(stage: str, error: Unavailable) -> dict[str, Any]:
            self._unavailable = True
            return {**metadata, "status": "model_unavailable", "stage": stage, "detail": str(error)}

        try:
            proposal = self.backend.ask(
                self.analyst_model,
                "You are a defensive SOC analyst. Select one allowed option for the first verification step. "
                "Each option names a finding and its permitted check. Respond with just the JSON object.",
                payload,
                _schema(option=list(choices)),
            )
            finding_id, check = choices[_selection(proposal, "option", choices)]
        except InvalidReply as error:
            return {**metadata, "status": "invalid_proposal", "detail": str(error)}
        except Unavailable as error:
            return unavailable("analyst", error)

        decisions: dict[str, str | None] = {"accept": None}
        decisions.update(
            {f"need_{context}": context for context in FINDING_CONTEXT[findings[finding_id].rule]}
        )
        try:
            review = (self.reviewer_backend or self.backend).ask(
                self.reviewer_model,
                "You are a defensive SOC reviewer. Review only the given finding and proposed check. "
                "Select accept if it is a sensible first check. Otherwise select one need_ decision for missing "
                "context. Respond with just the JSON object.",
                {"finding": _projection(finding_id, findings[finding_id]), "proposed_check": check},
                _schema(decision=list(decisions)),
            )
            context = decisions[_selection(review, "decision", decisions)]
            if context is None:
                return {**metadata, "status": "accepted", "finding": finding_id, "check": check}
            return {**metadata, "status": "needs_context", "finding": finding_id, "context": context}
        except InvalidReply as error:
            return {**metadata, "status": "invalid_review", "detail": str(error)}
        except Unavailable as error:
            return unavailable("reviewer", error)
