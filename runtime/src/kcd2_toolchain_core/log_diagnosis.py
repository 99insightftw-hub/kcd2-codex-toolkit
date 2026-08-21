"""Evidence-grounded, redacted diagnosis of the latest complete boot log."""

from __future__ import annotations

import codecs
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable, Mapping, Sequence
from typing import Any, Literal, Pattern

from .hashing import canonical_json_bytes, sha256_json
from .results import ContinuationHandle, ResponseLimitError, decode_continuation_handle


EventKind = Literal[
    "load_window",
    "pak_open",
    "member_open",
    "custom_instrumentation",
    "warning",
    "error",
    "other",
]
AttributionLevel = Literal[
    "DIRECT_PAK_AND_MEMBER",
    "DIRECT_MEMBER_PROVIDER_RESOLVED",
    "TEMPORAL_ASSOCIATION_ONLY",
    "NO_DEFENSIBLE_ATTRIBUTION",
]

_EVENT_KINDS = frozenset(
    {
        "load_window",
        "pak_open",
        "member_open",
        "custom_instrumentation",
        "warning",
        "error",
        "other",
    }
)
_MAX_PATTERN = 4096
_MAX_TEXT = 4096
_MAX_LOG_BYTES = 32 * 1024 * 1024
_MAX_LOG_LINES = 500_000
_MAX_PAGE_SIZE = 10_000
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_UNATTRIBUTED_PACKAGE = re.compile(r"(?i)(?<![\w.-])[\w.-]+\.pak(?![\w.-])")


class LogDiagnosisError(ValueError):
    """Inputs cannot support deterministic bounded diagnosis."""


def _bounded_text(value: object, name: str, *, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise LogDiagnosisError(
            f"{name} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _compile(value: str, name: str) -> Pattern[str]:
    _bounded_text(value, name, maximum=_MAX_PATTERN)
    try:
        return re.compile(value)
    except re.error as exc:
        raise LogDiagnosisError(f"{name} is not a valid regex: {exc}") from exc


def _identity(value: str) -> str:
    normalized = value.replace("\\", "/")
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    return normalized.casefold()


@dataclass(frozen=True, slots=True)
class LogEventPattern:
    """A reviewed typed event syntax; incident values stay in caller profiles."""

    kind: EventKind
    pattern: str
    _compiled: Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.kind not in _EVENT_KINDS:
            raise LogDiagnosisError(f"unsupported event kind: {self.kind}")
        compiled = _compile(self.pattern, "event pattern")
        object.__setattr__(self, "_compiled", compiled)


@dataclass(frozen=True, slots=True)
class LogDiagnosisProfile:
    """Reviewed boundaries and typed syntax for one log format."""

    boot_start_pattern: str
    boot_complete_pattern: str
    events: tuple[LogEventPattern, ...]
    encoding: str = "utf-8"
    _start: Pattern[str] = field(init=False, repr=False, compare=False)
    _complete: Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.events, tuple) or not self.events:
            raise LogDiagnosisError("events must be a non-empty tuple")
        if any(not isinstance(event, LogEventPattern) for event in self.events):
            raise LogDiagnosisError("events must contain only LogEventPattern values")
        try:
            codecs.lookup(_bounded_text(self.encoding, "encoding", maximum=128))
        except LookupError as exc:
            raise LogDiagnosisError(f"encoding is not recognized: {self.encoding}") from exc
        object.__setattr__(self, "_start", _compile(self.boot_start_pattern, "boot start pattern"))
        object.__setattr__(
            self,
            "_complete",
            _compile(self.boot_complete_pattern, "boot complete pattern"),
        )


@dataclass(frozen=True, slots=True)
class AttributionEvidence:
    """Direct log evidence or provider resolution for one exact observed member."""

    level: Literal["DIRECT_PAK_AND_MEMBER", "DIRECT_MEMBER_PROVIDER_RESOLVED"]
    line_number: int
    package: str
    member: str
    coverage_basis: str | None = None

    def __post_init__(self) -> None:
        if self.level not in {
            "DIRECT_PAK_AND_MEMBER",
            "DIRECT_MEMBER_PROVIDER_RESOLVED",
        }:
            raise LogDiagnosisError("unsupported attribution evidence level")
        if (
            not isinstance(self.line_number, int)
            or isinstance(self.line_number, bool)
            or self.line_number < 1
        ):
            raise LogDiagnosisError("line_number must be a positive integer")
        _bounded_text(self.package, "package")
        _bounded_text(self.member, "member")
        if self.level == "DIRECT_MEMBER_PROVIDER_RESOLVED":
            if self.coverage_basis != "COMPLETE_FOR_REQUESTED_SCOPE":
                raise LogDiagnosisError(
                    "provider resolution requires COMPLETE_FOR_REQUESTED_SCOPE coverage"
                )
        elif self.coverage_basis is not None:
            raise LogDiagnosisError("direct evidence must not carry provider coverage")

    @classmethod
    def direct(cls, *, line_number: int, package: str, member: str) -> "AttributionEvidence":
        return cls("DIRECT_PAK_AND_MEMBER", line_number, package, member)

    @classmethod
    def provider_resolved(
        cls,
        *,
        line_number: int,
        member: str,
        package: str,
        coverage_basis: str,
    ) -> "AttributionEvidence":
        return cls(
            "DIRECT_MEMBER_PROVIDER_RESOLVED",
            line_number,
            package,
            member,
            coverage_basis,
        )


@dataclass(frozen=True, slots=True)
class LogDiagnosis:
    payload: Mapping[str, Any]
    max_response_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        encoded = canonical_json_bytes(self.payload)
        if len(encoded) > self.max_response_bytes:
            raise ResponseLimitError("complete log diagnosis exceeds max_response_bytes")
        return encoded.decode("utf-8")


@dataclass(frozen=True, slots=True)
class _Boot:
    start_line: int
    end_line: int
    lines: tuple[tuple[int, str], ...]


def _latest_complete_boot(lines: Sequence[str], profile: LogDiagnosisProfile) -> _Boot | None:
    complete: list[_Boot] = []
    start: int | None = None
    captured: list[tuple[int, str]] = []
    for number, line in enumerate(lines, start=1):
        if profile._start.search(line) is not None:
            start = number
            captured = []
            continue
        if start is None:
            continue
        if profile._complete.search(line) is not None:
            complete.append(_Boot(start, number, tuple(captured)))
            start = None
            captured = []
            continue
        captured.append((number, line))
    return complete[-1] if complete else None


def _redactor(
    personal_identifiers: Mapping[str, Sequence[str]] | None,
) -> tuple[Callable[[str], str], list[str]]:
    replacements: list[tuple[str, str]] = []
    categories: list[str] = []
    if personal_identifiers is not None:
        if not isinstance(personal_identifiers, Mapping):
            raise LogDiagnosisError("personal_identifiers must be a mapping")
        for category in sorted(personal_identifiers):
            _bounded_text(category, "redaction category", maximum=128)
            values = personal_identifiers[category]
            if isinstance(values, str) or not isinstance(values, Sequence):
                raise LogDiagnosisError("redaction values must be a sequence of strings")
            clean = sorted(
                {_bounded_text(value, f"{category} redaction value") for value in values},
                key=lambda item: (-len(item), item.casefold()),
            )
            if clean:
                categories.append(category)
                replacements.extend((value, f"[REDACTED:{category}]") for value in clean)

    def redact(value: str) -> str:
        result = value
        for original, replacement in replacements:
            result = re.sub(re.escape(original), replacement, result, flags=re.IGNORECASE)
        return result

    return redact, categories


def _match_evidence(
    *,
    line_number: int,
    captures: Mapping[str, str],
    evidence: Sequence[AttributionEvidence],
) -> tuple[AttributionLevel, str | None]:
    member = captures.get("member")
    raw_package = captures.get("package")
    if not member:
        return "NO_DEFENSIBLE_ATTRIBUTION", None
    for item in evidence:
        if item.line_number != line_number or _identity(item.member) != _identity(member):
            continue
        if item.level == "DIRECT_PAK_AND_MEMBER":
            if raw_package and _identity(item.package) == _identity(raw_package):
                return item.level, item.package
            continue
        return item.level, item.package
    if raw_package:
        return "TEMPORAL_ASSOCIATION_ONLY", None
    return "NO_DEFENSIBLE_ATTRIBUTION", None


def _findings(
    boot: _Boot,
    profile: LogDiagnosisProfile,
    evidence: Sequence[AttributionEvidence],
    redact: Callable[[str], str],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in boot.lines:
        for event in profile.events:
            matched = event._compiled.search(line)
            if matched is None:
                continue
            captures = {
                key: value
                for key, value in matched.groupdict().items()
                if value is not None
            }
            level, package = _match_evidence(
                line_number=line_number,
                captures=captures,
                evidence=evidence,
            )
            message = captures.get("message", matched.group(0))
            message = redact(message)
            if package is None:
                message = _UNATTRIBUTED_PACKAGE.sub("[UNATTRIBUTED_PACKAGE]", message)
            findings.append(
                {
                    "kind": event.kind,
                    "line_numbers": [line_number],
                    "message": message,
                    "attribution_level": level,
                    "package": package,
                }
            )
            break
    return findings


def _severity(findings: Sequence[Mapping[str, Any]]) -> str:
    kinds = {item["kind"] for item in findings}
    if "error" in kinds:
        return "error"
    if "warning" in kinds:
        return "warning"
    return "informational"


def diagnose_latest_boot(
    *,
    diagnosis_id: str,
    log_path: Path,
    profile: LogDiagnosisProfile,
    attribution_evidence: Sequence[AttributionEvidence] = (),
    personal_identifiers: Mapping[str, Sequence[str]] | None = None,
    max_log_bytes: int = _MAX_LOG_BYTES,
    max_log_lines: int = _MAX_LOG_LINES,
    max_response_bytes: int = 65_536,
    page_size: int = 100,
    continuation_token: str | None = None,
) -> LogDiagnosis:
    """Diagnose one bounded page from the latest complete boot only."""

    diagnosis_id = _bounded_text(diagnosis_id, "diagnosis_id")
    if not isinstance(log_path, Path):
        raise LogDiagnosisError("log_path must be a pathlib.Path")
    if not isinstance(profile, LogDiagnosisProfile):
        raise LogDiagnosisError("profile must be a LogDiagnosisProfile")
    evidence = tuple(attribution_evidence)
    if any(not isinstance(item, AttributionEvidence) for item in evidence):
        raise LogDiagnosisError("attribution_evidence contains an invalid item")
    integer_bounds = {
        "max_log_bytes": (max_log_bytes, 1, _MAX_LOG_BYTES),
        "max_log_lines": (max_log_lines, 1, _MAX_LOG_LINES),
        "max_response_bytes": (max_response_bytes, 512, _MAX_RESPONSE_BYTES),
        "page_size": (page_size, 1, _MAX_PAGE_SIZE),
    }
    for name, (value, minimum, maximum) in integer_bounds.items():
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise LogDiagnosisError(f"{name} must be between {minimum} and {maximum}")
    redact, redaction_categories = _redactor(personal_identifiers)

    lines: list[str] = []
    coverage = "capture_inconclusive"
    boot: _Boot | None = None
    if log_path.is_file():
        try:
            if log_path.stat().st_size <= max_log_bytes:
                with log_path.open("rb") as stream:
                    raw = stream.read(max_log_bytes + 1)
                if len(raw) <= max_log_bytes:
                    decoded = raw.decode(profile.encoding, errors="strict")
                    lines = decoded.splitlines()
                    if len(lines) <= max_log_lines:
                        boot = _latest_complete_boot(lines, profile)
        except (OSError, UnicodeDecodeError):
            boot = None

    if boot is None:
        all_findings: list[dict[str, Any]] = []
        scope = {"latest_boot": True, "start_line": 0, "end_line": 0, "complete_boot": False}
        severity = "unknown"
        evidence_grade = "unknown"
    else:
        all_findings = _findings(boot, profile, evidence, redact)
        scope = {
            "latest_boot": True,
            "start_line": boot.start_line,
            "end_line": boot.end_line,
            "complete_boot": True,
        }
        severity = _severity(all_findings)
        coverage = "complete_for_requested_scope"
        evidence_grade = "E4" if evidence else "E1"

    scope_key = f"log-diagnosis-v2:{diagnosis_id}"
    if continuation_token is None:
        offset = 0
        page_number = 1
    else:
        try:
            handle = decode_continuation_handle(
                continuation_token,
                scope=scope_key,
                items=all_findings,
            )
        except ValueError as exc:
            raise LogDiagnosisError(str(exc)) from exc
        offset = handle.offset
        page_number = handle.page

    implicated = sorted(
        {item["package"] for item in all_findings if item["package"] is not None},
        key=str.casefold,
    )
    maximum_count = min(page_size, len(all_findings) - offset)
    for count in range(maximum_count, -1, -1):
        more = offset + count < len(all_findings)
        token = None
        if more and count:
            token = ContinuationHandle(
                scope=scope_key,
                items_sha256=sha256_json(all_findings),
                offset=offset + count,
                page=page_number + 1,
            ).to_token()
        payload = {
            "schema_version": "kcd2.log-diagnosis.v2",
            "diagnosis_id": diagnosis_id,
            "scope": scope,
            "severity": severity,
            "findings": all_findings[offset : offset + count],
            "implicated_packages": implicated,
            "redactions": redaction_categories,
            "pagination": {
                "details_available": more,
                "continuation_token": token,
            },
            "coverage": coverage,
            "evidence_grade": evidence_grade,
        }
        if len(canonical_json_bytes(payload)) <= max_response_bytes:
            if more and count == 0:
                break
            return LogDiagnosis(payload, max_response_bytes)
    raise ResponseLimitError(
        "irreducible log diagnosis or one finding cannot fit max_response_bytes"
    )
