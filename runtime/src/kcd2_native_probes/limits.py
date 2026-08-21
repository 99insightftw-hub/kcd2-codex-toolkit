"""Shared aggregate limits and deterministic redaction for probe evidence."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any


INTEGER_MAX = 2**63 - 1
DEFAULT_LIMITS = MappingProxyType(
    {
        "max_events": 10_000,
        "max_captures": 1_000,
        "max_event_families": 32,
        "max_total_bytes": 64 * 1024 * 1024,
        "max_fields": 32,
        "max_string_chars": 4096,
        "max_memory_region_bytes": 4096,
    }
)
HARD_CEILINGS = MappingProxyType(
    {
        "max_events": 100_000,
        "max_captures": 10_000,
        "max_event_families": 128,
        "max_total_bytes": 512 * 1024 * 1024,
        "max_fields": 128,
        "max_string_chars": 65_536,
        "max_memory_region_bytes": 4096,
    }
)
RAW_POINTER_RE = re.compile(r"0[xX][A-Fa-f0-9]{9,16}")
POINTER_FIELD_RE = re.compile(
    r"(?:^|_)(?:absolute|address|module_base|pointer|ptr)(?:$|_)", re.IGNORECASE
)


@dataclass(frozen=True, slots=True)
class ProbeLimits:
    """Reviewed probe defaults constrained by immutable hard ceilings."""

    max_events: int = DEFAULT_LIMITS["max_events"]
    max_captures: int = DEFAULT_LIMITS["max_captures"]
    max_event_families: int = DEFAULT_LIMITS["max_event_families"]
    max_total_bytes: int = DEFAULT_LIMITS["max_total_bytes"]
    max_fields: int = DEFAULT_LIMITS["max_fields"]
    max_string_chars: int = DEFAULT_LIMITS["max_string_chars"]
    max_memory_region_bytes: int = DEFAULT_LIMITS["max_memory_region_bytes"]

    def __post_init__(self) -> None:
        for name, ceiling in HARD_CEILINGS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{name} must be an integer")
            minimum = 1024 if name == "max_total_bytes" else 1
            if not minimum <= value <= ceiling:
                raise ValueError(f"{name} must be between {minimum} and {ceiling}")

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> ProbeLimits:
        """Construct limits without silently accepting missing or unknown names."""
        expected = set(HARD_CEILINGS)
        supplied = set(values)
        if supplied != expected:
            missing = sorted(expected - supplied)
            unknown = sorted(supplied - expected)
            raise ValueError(f"limit names differ; missing={missing}, unknown={unknown}")
        return cls(**{name: values[name] for name in HARD_CEILINGS})

    def to_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in HARD_CEILINGS}


@dataclass(frozen=True, slots=True)
class LimitDiagnostic:
    code: str
    limit_name: str
    observed: int
    limit: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "limit_name": self.limit_name,
            "observed": self.observed,
            "limit": self.limit,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class ProbeLimitState:
    usage: Mapping[str, int]
    diagnostics: tuple[LimitDiagnostic, ...]
    absence_claim_allowed: bool
    verdict: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "usage": dict(self.usage),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "absence_claim_allowed": self.absence_claim_allowed,
            "verdict": self.verdict,
        }


class ProbeLimitTracker:
    """Track one capture envelope and fail closed at saturation or overflow."""

    def __init__(self, limits: ProbeLimits | None = None) -> None:
        self.limits = limits or ProbeLimits()
        self._usage = {name: 0 for name in HARD_CEILINGS}
        self._families: set[str] = set()
        self._diagnostics: dict[str, LimitDiagnostic] = {}

    def consume_event(
        self,
        event_family: str,
        *,
        encoded_bytes: int,
        fields: int = 0,
        maximum_string_chars: int = 0,
        memory_region_bytes: int = 0,
    ) -> bool:
        if not isinstance(event_family, str) or not event_family:
            raise ValueError("event_family must be a nonempty string")
        _require_count(encoded_bytes, "max_total_bytes")
        _require_count(fields, "max_fields")
        _require_count(maximum_string_chars, "max_string_chars")
        _require_count(memory_region_bytes, "max_memory_region_bytes")
        self._require_increment_capacity("max_events", 1)
        self._require_increment_capacity("max_total_bytes", encoded_bytes)
        self._families.add(event_family)
        accepted = self._set_usage("max_event_families", len(self._families))
        accepted = self._increment("max_events", 1) and accepted
        accepted = self._increment("max_total_bytes", encoded_bytes) and accepted
        accepted = self._set_usage("max_fields", fields) and accepted
        accepted = self._set_usage("max_string_chars", maximum_string_chars) and accepted
        accepted = self._set_usage("max_memory_region_bytes", memory_region_bytes) and accepted
        return accepted

    def consume_capture(
        self,
        *,
        encoded_bytes: int,
        fields: int = 0,
        maximum_string_chars: int = 0,
        memory_region_bytes: int = 0,
    ) -> bool:
        _require_count(encoded_bytes, "max_total_bytes")
        _require_count(fields, "max_fields")
        _require_count(maximum_string_chars, "max_string_chars")
        _require_count(memory_region_bytes, "max_memory_region_bytes")
        self._require_increment_capacity("max_captures", 1)
        self._require_increment_capacity("max_total_bytes", encoded_bytes)
        accepted = self._increment("max_captures", 1)
        accepted = self._increment("max_total_bytes", encoded_bytes) and accepted
        accepted = self._set_usage("max_fields", fields) and accepted
        accepted = self._set_usage("max_string_chars", maximum_string_chars) and accepted
        accepted = self._set_usage("max_memory_region_bytes", memory_region_bytes) and accepted
        return accepted

    def state(self) -> ProbeLimitState:
        diagnostics = tuple(self._diagnostics[name] for name in sorted(self._diagnostics))
        complete = not diagnostics
        return ProbeLimitState(
            usage=MappingProxyType(dict(self._usage)),
            diagnostics=diagnostics,
            absence_claim_allowed=complete,
            verdict="not_evaluated" if complete else "capture_inconclusive",
        )

    def observe(self, limit_name: str, observed: int) -> bool:
        """Record an independently measured aggregate against one named limit."""
        if limit_name not in HARD_CEILINGS:
            raise ValueError(f"unknown limit: {limit_name}")
        return self._set_usage(limit_name, observed)

    def _increment(self, name: str, increment: int) -> bool:
        _require_count(increment, name)
        self._require_increment_capacity(name, increment)
        return self._set_usage(name, self._usage[name] + increment)

    def _require_increment_capacity(self, name: str, increment: int) -> None:
        if increment > INTEGER_MAX - self._usage[name]:
            raise ValueError(f"{name} counter overflow")

    def _set_usage(self, name: str, observed: int) -> bool:
        _require_count(observed, name)
        self._usage[name] = max(self._usage[name], observed)
        limit = getattr(self.limits, name)
        if observed >= limit:
            code = "LIMIT_SATURATED" if observed == limit else "LIMIT_EXCEEDED"
            self._diagnostics[name] = LimitDiagnostic(
                code=code,
                limit_name=name,
                observed=observed,
                limit=limit,
                message=f"{name} reached or exceeded its configured limit",
            )
        return observed <= limit


def evaluate_probe_bundle_limits(bundle: Mapping[str, Any]) -> ProbeLimitState:
    """Measure every declared aggregate limit in a probe bundle."""
    raw_limits = bundle.get("limits")
    if not isinstance(raw_limits, Mapping):
        raise ValueError("bundle limits must be an object")
    limits = ProbeLimits.from_mapping(raw_limits)
    tracker = ProbeLimitTracker(limits)
    captures_value = bundle.get("captures")
    captures = captures_value if isinstance(captures_value, list) else []
    event_families = {
        capture.get("event")
        for capture in captures
        if isinstance(capture, Mapping) and isinstance(capture.get("event"), str)
    }
    encoded = json.dumps(
        bundle,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    maximum_fields, maximum_string_chars, maximum_memory = _measure_json(bundle)
    tracker.observe("max_events", len(captures))
    tracker.observe("max_captures", len(captures))
    tracker.observe("max_event_families", len(event_families))
    tracker.observe("max_total_bytes", len(encoded))
    tracker.observe("max_fields", maximum_fields)
    tracker.observe("max_string_chars", maximum_string_chars)
    tracker.observe("max_memory_region_bytes", maximum_memory)
    return tracker.state()


@dataclass(frozen=True, slots=True)
class RedactionDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class RedactionResult:
    value: Any
    diagnostics: tuple[RedactionDiagnostic, ...]

    @property
    def redacted(self) -> bool:
        return bool(self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "redacted": self.redacted,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


def redact_probe_output(
    value: Any,
    *,
    sensitive_fields: Set[str] | frozenset[str] = frozenset(),
    pointer_fields: Set[str] | frozenset[str] = frozenset(),
) -> RedactionResult:
    """Return a deterministic JSON value with sensitive data and raw pointers removed."""
    sensitive = set(sensitive_fields)
    pointers = set(pointer_fields)
    diagnostics: list[RedactionDiagnostic] = []
    pointer_tokens: dict[str, str] = {}

    def token(raw: str) -> str:
        if raw not in pointer_tokens:
            pointer_tokens[raw] = f"pointer:redacted:{len(pointer_tokens) + 1:04d}"
        return pointer_tokens[raw]

    def visit(item: Any, path: str, field_name: str | None = None) -> Any:
        if field_name in sensitive:
            diagnostics.append(
                RedactionDiagnostic(
                    "SENSITIVE_FIELD_REDACTED", path, "sensitive field value was removed"
                )
            )
            return "[REDACTED]"
        is_pointer_field = field_name is not None and (
            field_name in pointers or POINTER_FIELD_RE.search(field_name) is not None
        )
        if is_pointer_field and item is not None:
            raw = _canonical_scalar(item)
            diagnostics.append(
                RedactionDiagnostic("POINTER_REDACTED", path, "raw pointer value was removed")
            )
            return token(raw)
        if isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise ValueError(f"{path} contains a non-string object key")
            return {
                key: visit(item[key], f"{path}.{key}", key)
                for key in sorted(item)
            }
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            return [visit(child, f"{path}[{index}]") for index, child in enumerate(item)]
        if isinstance(item, str):
            found = False

            def replace(match: re.Match[str]) -> str:
                nonlocal found
                found = True
                return token(match.group(0).lower())

            sanitized = RAW_POINTER_RE.sub(replace, item)
            if found:
                diagnostics.append(
                    RedactionDiagnostic("POINTER_REDACTED", path, "raw pointer text was removed")
                )
            return sanitized
        if item is None or isinstance(item, (bool, int, float)):
            return item
        raise ValueError(f"{path} contains a non-JSON value")

    redacted = visit(value, "$")
    unique = {(item.code, item.path): item for item in diagnostics}
    ordered = tuple(unique[key] for key in sorted(unique))
    return RedactionResult(redacted, ordered)


def _require_count(value: int, name: str) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= INTEGER_MAX
    ):
        raise ValueError(f"{name} increment must be between 0 and {INTEGER_MAX}")


def _canonical_scalar(value: Any) -> str:
    if isinstance(value, str) and RAW_POINTER_RE.fullmatch(value) is not None:
        return value.lower()
    if value is None or isinstance(value, (str, bool, int, float)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    raise ValueError("pointer fields must contain JSON scalar values")


def _measure_json(value: Any) -> tuple[int, int, int]:
    maximum_fields = 0
    maximum_string_chars = 0
    maximum_memory = 0
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            fields = item.get("fields")
            if isinstance(fields, Mapping):
                maximum_fields = max(maximum_fields, len(fields))
            memory_bytes = item.get("bytes") if "bytes_hex" in item else None
            if isinstance(memory_bytes, int) and not isinstance(memory_bytes, bool):
                maximum_memory = max(maximum_memory, memory_bytes)
            for key, child in item.items():
                if key != "bytes_hex":
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            maximum_string_chars = max(maximum_string_chars, len(item))
    return maximum_fields, maximum_string_chars, maximum_memory
