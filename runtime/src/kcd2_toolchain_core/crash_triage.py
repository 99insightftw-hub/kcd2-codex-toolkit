"""Bounded, redacted, evidence-grounded crash and hang triage."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .hashing import canonical_json_bytes


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_TYPES = frozenset(
    {
        "BUGSPLAT",
        "AFTERMATH",
        "MINIDUMP",
        "KCD_LOG",
        "WINDOWS_EVENT",
        "RUNTIME_SESSION",
        "MODULE_MAP",
        "DEPLOYMENT",
    }
)
_SOURCE_STATES = frozenset(
    {"AVAILABLE_PARSED", "AVAILABLE_UNSUPPORTED", "NOT_FOUND", "ERROR"}
)
_MAX_TEXT = 4096
_MAX_SOURCES = 64
_MAX_MODULES = 4096
_MAX_ERRORS = 4096
_MAX_EVENTS = 100_000
_MAX_LAST_EVENTS = 256
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class CrashTriageError(ValueError):
    """The supplied evidence cannot produce a deterministic bounded report."""


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise CrashTriageError(
            f"{name} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CrashTriageError(f"{name} must be a mapping")
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CrashTriageError(f"{name} must be a sequence")
    if len(value) > maximum:
        raise CrashTriageError(f"{name} exceeds the hard limit of {maximum}")
    return value


def _integer(value: object, name: str, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise CrashTriageError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _hash(value: object, name: str) -> str:
    text = _text(value, name, maximum=64).casefold()
    if _SHA256.fullmatch(text) is None:
        raise CrashTriageError(f"{name} must be a lowercase SHA-256 digest")
    return text


def _redactor(
    personal_identifiers: Mapping[str, Sequence[str]] | None,
) -> tuple[Any, list[str]]:
    replacements: list[tuple[str, str]] = []
    categories: list[str] = []
    if personal_identifiers is not None:
        source = _mapping(personal_identifiers, "personal_identifiers")
        if len(source) > 32:
            raise CrashTriageError("personal_identifiers exceeds the hard limit of 32 categories")
        for category in sorted(source):
            clean_category = _text(category, "redaction category", maximum=64)
            values = _sequence(source[category], f"redaction values for {category}", 256)
            clean_values = sorted(
                {_text(item, f"redaction value for {category}") for item in values},
                key=lambda item: (-len(item), item.casefold()),
            )
            if clean_values:
                categories.append(clean_category)
                replacements.extend(
                    (value, f"[REDACTED:{clean_category}]") for value in clean_values
                )

    def redact(value: str) -> str:
        result = re.sub(
            r"(?i)(?<=\\Users\\)[^\\/:*?\"<>|\s]+",
            "[REDACTED:windows_user]",
            value,
        )
        result = re.sub(
            r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
            "[REDACTED:email]",
            result,
        )
        for original, replacement in replacements:
            result = re.sub(re.escape(original), replacement, result, flags=re.IGNORECASE)
        return result

    return redact, categories


def _sources(values: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    output: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(values, "sources", _MAX_SOURCES)):
        item = _mapping(raw, f"sources[{index}]")
        source_type = _text(item.get("source_type"), "source_type", maximum=32).upper()
        state = _text(item.get("state"), "source state", maximum=32).upper()
        if source_type not in _SOURCE_TYPES or state not in _SOURCE_STATES:
            raise CrashTriageError("source_type or source state is unsupported")
        if source_type in seen:
            raise CrashTriageError(f"duplicate source_type: {source_type}")
        seen.add(source_type)
        digest_value = item.get("sha256")
        digest = None if digest_value is None else _hash(digest_value, "source sha256")
        if state.startswith("AVAILABLE_") and digest is None:
            raise CrashTriageError("available sources require a content hash")
        if state == "NOT_FOUND" and digest is not None:
            raise CrashTriageError("not-found sources must not carry a content hash")
        output.append({"source_type": source_type, "state": state, "sha256": digest})
        if state != "AVAILABLE_PARSED":
            gaps.append(f"{source_type}_{state}")
    output.sort(key=lambda item: item["source_type"])
    return output, sorted(gaps)


def _exact_exception(
    crash_artifact: Mapping[str, Any] | None,
    module_map: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    if crash_artifact is None:
        return None
    crash = _mapping(crash_artifact, "crash_artifact")
    name = _text(crash.get("module_name"), "crash module name", maximum=512)
    digest = _hash(crash.get("module_sha256"), "crash module sha256")
    address = _integer(crash.get("exception_address"), "exception_address")
    matches: list[tuple[str, str, int]] = []
    for index, raw in enumerate(_sequence(module_map, "module_map", _MAX_MODULES)):
        module = _mapping(raw, f"module_map[{index}]")
        module_name = _text(module.get("name"), "module name", maximum=512)
        module_hash = _hash(module.get("sha256"), "module sha256")
        base = _integer(module.get("base_address"), "module base_address")
        size = _integer(module.get("image_size"), "module image_size", minimum=1, maximum=2**32)
        if (
            module_name.casefold() == name.casefold()
            and module_hash == digest
            and base <= address < base + size
        ):
            matches.append((module_name, module_hash, address - base))
    if len(matches) != 1:
        return None
    module_name, module_hash, rva = matches[0]
    return {
        "level": "EXACT_EXCEPTION_MODULE_AND_RVA",
        "module": {"name": module_name, "sha256": module_hash},
        "rva": rva,
        "provider": None,
        "member": None,
        "confidence": "HIGH",
        "evidence_class": "runtime",
    }


def _named_association(
    named_errors: Sequence[Mapping[str, Any]],
    provider_resolutions: Sequence[Mapping[str, Any]],
    redact: Any,
) -> dict[str, Any] | None:
    errors = _sequence(named_errors, "named_errors", _MAX_ERRORS)
    resolutions = _sequence(provider_resolutions, "provider_resolutions", _MAX_ERRORS)
    parsed_resolutions: dict[str, tuple[str, str]] = {}
    for index, raw in enumerate(resolutions):
        item = _mapping(raw, f"provider_resolutions[{index}]")
        member = _text(item.get("member"), "resolved member")
        provider = _text(item.get("provider"), "resolved provider")
        coverage = _text(item.get("coverage"), "provider coverage", maximum=64)
        parsed_resolutions[member.replace("\\", "/").casefold()] = (provider, coverage)
    for index, raw in enumerate(errors):
        item = _mapping(raw, f"named_errors[{index}]")
        member = _text(item.get("member"), "named error member")
        provider_value = item.get("provider")
        exact_provider = item.get("exact_provider_named", False)
        if not isinstance(exact_provider, bool):
            raise CrashTriageError("exact_provider_named must be boolean")
        if exact_provider:
            provider = _text(provider_value, "named error provider")
            return {
                "level": "EXACT_ERROR_NAMES_PROVIDER_OR_MEMBER",
                "module": None,
                "rva": None,
                "provider": redact(provider),
                "member": redact(member),
                "confidence": "HIGH",
                "evidence_class": "runtime",
            }
        resolution = parsed_resolutions.get(member.replace("\\", "/").casefold())
        if resolution is not None and resolution[1] == "complete_for_requested_scope":
            return {
                "level": "MEMBER_RESOLVED_TO_ACTIVE_PROVIDER",
                "module": None,
                "rva": None,
                "provider": redact(resolution[0]),
                "member": redact(member),
                "confidence": "HIGH",
                "evidence_class": "runtime",
            }
        return {
            "level": "EXACT_ERROR_NAMES_PROVIDER_OR_MEMBER",
            "module": None,
            "rva": None,
            "provider": None,
            "member": redact(member),
            "confidence": "MEDIUM",
            "evidence_class": "runtime",
        }
    return None


def _last_events(
    timeline_events: Sequence[Mapping[str, Any]], max_last_events: int, redact: Any
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for index, raw in enumerate(_sequence(timeline_events, "timeline_events", _MAX_EVENTS)):
        item = _mapping(raw, f"timeline_events[{index}]")
        events.append(
            {
                "event_id": redact(_text(item.get("event_id"), "event_id", maximum=256)),
                "session_time_ns": _integer(item.get("session_time_ns"), "session_time_ns"),
                "summary": redact(_text(item.get("summary"), "event summary")),
                "association": "TEMPORAL_ASSOCIATION_ONLY",
            }
        )
    events.sort(key=lambda item: (item["session_time_ns"], item["event_id"]))
    return events[-max_last_events:]


@dataclass(frozen=True, slots=True)
class CrashTriageReport:
    payload: Mapping[str, Any]
    max_response_bytes: int

    def to_json(self) -> str:
        encoded = canonical_json_bytes(self.payload)
        if len(encoded) > self.max_response_bytes:
            raise CrashTriageError("crash triage report exceeds max_response_bytes")
        return encoded.decode("utf-8")

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())


def triage_crash(
    *,
    report_id: str,
    cross_tool_identity_id: str,
    sources: Sequence[Mapping[str, Any]],
    incident_kind: str = "CRASH",
    crash_artifact: Mapping[str, Any] | None = None,
    module_map: Sequence[Mapping[str, Any]] = (),
    named_errors: Sequence[Mapping[str, Any]] = (),
    provider_resolutions: Sequence[Mapping[str, Any]] = (),
    timeline_events: Sequence[Mapping[str, Any]] = (),
    deployment: Mapping[str, Any] | None = None,
    personal_identifiers: Mapping[str, Sequence[str]] | None = None,
    max_last_events: int = 20,
    max_response_bytes: int = 65_536,
) -> CrashTriageReport:
    """Correlate supplied evidence without treating deployment order as causal evidence."""

    report_id = _text(report_id, "report_id", maximum=256)
    incident_kind = _text(incident_kind, "incident_kind", maximum=8).upper()
    if incident_kind not in {"CRASH", "HANG"}:
        raise CrashTriageError("incident_kind must be CRASH or HANG")
    cross_tool_identity_id = _text(
        cross_tool_identity_id, "cross_tool_identity_id", maximum=256
    )
    max_last_events = _integer(
        max_last_events, "max_last_events", minimum=1, maximum=_MAX_LAST_EVENTS
    )
    max_response_bytes = _integer(
        max_response_bytes, "max_response_bytes", minimum=512, maximum=_MAX_RESPONSE_BYTES
    )
    sanitized_sources, gaps = _sources(sources)
    redact, categories = _redactor(personal_identifiers)

    # Deployment is coverage context only. Its order is deliberately never consulted for association.
    if deployment is not None:
        deployment_map = _mapping(deployment, "deployment")
        ordered = _sequence(deployment_map.get("ordered_providers", ()), "ordered_providers", 4096)
        for provider in ordered:
            _text(provider, "ordered provider")

    events = _last_events(timeline_events, max_last_events, redact)
    association = _exact_exception(crash_artifact, module_map)
    if association is None:
        association = _named_association(named_errors, provider_resolutions, redact)
    if association is None and events:
        association = {
            "level": "TEMPORAL_ASSOCIATION_ONLY",
            "module": None,
            "rva": None,
            "provider": None,
            "member": None,
            "confidence": "LOW",
            "evidence_class": "runtime",
        }
    if association is None:
        inconclusive = bool(gaps) or not sanitized_sources
        association = {
            "level": "INCONCLUSIVE_COVERAGE" if inconclusive else "NO_SUPPORTED_ASSOCIATION",
            "module": None,
            "rva": None,
            "provider": None,
            "member": None,
            "confidence": "LOW",
            "evidence_class": "runtime",
        }

    claim_validity = (
        "capture_inconclusive"
        if association["level"] == "INCONCLUSIVE_COVERAGE"
        else "supported_for_reported_association"
    )
    payload: dict[str, Any] = {
        "schema_version": "kcd2.crash-triage-report.v1",
        "report_id": redact(report_id),
        "incident_kind": incident_kind,
        "cross_tool_identity_id": redact(cross_tool_identity_id),
        "sources": sanitized_sources,
        "association": association,
        "last_events": events,
        "redaction": {
            "applied": True,
            "categories": categories,
            "sanitization": "SANITIZED",
        },
        "coverage": {
            "status": "complete" if not gaps else "partial",
            "claim_validity": claim_validity,
            "gaps": gaps,
        },
        "notes": [
            "Deployment/load order is coverage context, not causal association evidence.",
            "Temporal events identify sequence only and do not establish provider ownership.",
        ],
    }
    while len(canonical_json_bytes(payload)) > max_response_bytes and payload["last_events"]:
        payload["last_events"].pop(0)
    if len(canonical_json_bytes(payload)) > max_response_bytes:
        raise CrashTriageError("irreducible crash triage report exceeds max_response_bytes")
    return CrashTriageReport(payload, max_response_bytes)
