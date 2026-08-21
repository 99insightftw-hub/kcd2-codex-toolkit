"""Bounded, paginated, deterministic result envelopes for every public tool."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, replace
from typing import Any, Iterable, Literal, Mapping, Sequence

from .diagnostics import Diagnostic, DiagnosticAggregate, aggregate_diagnostics
from .errors import ToolError
from .hashing import canonical_json_bytes, sha256_json


ResultStatus = Literal["ok", "partial", "error", "capture_inconclusive"]
EvidenceGrade = Literal["E0", "E1", "E2", "E3", "E4", "E5", "E6", "mixed", "unknown"]
EVIDENCE_GRADES = frozenset({"E0", "E1", "E2", "E3", "E4", "E5", "E6", "mixed", "unknown"})


class ResponseLimitError(ValueError):
    """The irreducible envelope or one page item cannot fit the response ceiling."""


@dataclass(frozen=True, slots=True)
class ResponseLimits:
    max_response_bytes: int = 65_536
    max_examples: int = 3
    page_size: int = 100
    max_pages: int = 100
    schema_version: str = "kcd2.response-limits.v1"

    HARD_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
    HARD_MAX_EXAMPLES = 100
    HARD_MAX_PAGE_SIZE = 10_000
    HARD_MAX_PAGES = 10_000

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.response-limits.v1":
            raise ValueError("unsupported response limits schema_version")
        bounds = {
            "max_response_bytes": (self.max_response_bytes, 512, self.HARD_MAX_RESPONSE_BYTES),
            "max_examples": (self.max_examples, 0, self.HARD_MAX_EXAMPLES),
            "page_size": (self.page_size, 1, self.HARD_MAX_PAGE_SIZE),
            "max_pages": (self.max_pages, 1, self.HARD_MAX_PAGES),
        }
        for name, (value, minimum, maximum) in bounds.items():
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "max_response_bytes": self.max_response_bytes,
            "max_examples": self.max_examples,
            "page_size": self.page_size,
            "max_pages": self.max_pages,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ResponseLimits":
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ContinuationHandle:
    scope: str
    items_sha256: str
    offset: int
    page: int
    schema_version: str = "kcd2.continuation-handle.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.continuation-handle.v1":
            raise ValueError("unsupported continuation handle schema_version")
        if not self.scope or len(self.scope) > 256:
            raise ValueError("continuation scope must contain at most 256 characters")
        if len(self.items_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.items_sha256
        ):
            raise ValueError("continuation items_sha256 must be lowercase SHA-256")
        if self.offset < 0 or self.page < 1:
            raise ValueError("continuation offset and page are outside their bounds")

    def to_token(self) -> str:
        payload = {
            "schema_version": self.schema_version,
            "scope": self.scope,
            "items_sha256": self.items_sha256,
            "offset": self.offset,
            "page": self.page,
        }
        return base64.urlsafe_b64encode(canonical_json_bytes(payload)).rstrip(b"=").decode("ascii")

    @classmethod
    def from_token(cls, token: str) -> "ContinuationHandle":
        if not isinstance(token, str) or not token or len(token) > 2_048:
            raise ValueError("continuation token is missing or exceeds its bound")
        try:
            padding = "=" * (-len(token) % 4)
            decoded = base64.b64decode(token + padding, altchars=b"-_", validate=True)
            payload = json.loads(decoded)
        except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("continuation token is malformed") from exc
        if not isinstance(payload, dict):
            raise ValueError("continuation token payload must be an object")
        expected = {"schema_version", "scope", "items_sha256", "offset", "page"}
        if set(payload) != expected:
            raise ValueError("continuation token fields do not match v1")
        return cls(**payload)


def _items_digest(items: Sequence[Any]) -> str:
    try:
        return sha256_json(list(items))
    except (TypeError, ValueError) as exc:
        raise ValueError("page items must be finite JSON values") from exc


def decode_continuation_handle(
    token: str,
    *,
    scope: str,
    items: Sequence[Any],
) -> ContinuationHandle:
    """Decode a handle and bind it to both its route and immutable item sequence."""
    handle = ContinuationHandle.from_token(token)
    if handle.scope != scope:
        raise ValueError("continuation token belongs to a different scope")
    if handle.items_sha256 != _items_digest(items):
        raise ValueError("continuation token belongs to different page content")
    if handle.offset > len(items):
        raise ValueError("continuation offset exceeds the item count")
    return handle


@dataclass(frozen=True, slots=True)
class Pagination:
    page: int = 1
    page_size: int = 0
    returned_items: int = 0
    total_items: int = 0
    continuation_token: str | None = None
    truncated: bool = False
    schema_version: str = "kcd2.pagination.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.pagination.v1":
            raise ValueError("unsupported pagination schema_version")
        if self.page < 1 or min(self.page_size, self.returned_items, self.total_items) < 0:
            raise ValueError("pagination counts are outside their bounds")
        if self.returned_items > self.page_size or self.returned_items > self.total_items:
            raise ValueError("pagination returned_items exceeds its declared bounds")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "page": self.page,
            "page_size": self.page_size,
            "returned_items": self.returned_items,
            "total_items": self.total_items,
            "continuation_token": self.continuation_token,
            "truncated": self.truncated,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "Pagination":
        return cls(**dict(value))


@dataclass(frozen=True, slots=True)
class ResultEnvelope:
    status: ResultStatus
    evidence_grade: EvidenceGrade = "unknown"
    data: Mapping[str, Any] | None = None
    error: ToolError | None = None
    diagnostics: Sequence[Diagnostic | DiagnosticAggregate] = ()
    diagnostics_truncated: bool = False
    pagination: Pagination = Pagination()
    limits: ResponseLimits = ResponseLimits()
    schema_version: str = "kcd2.result-envelope.v1"

    def __post_init__(self) -> None:
        if self.status not in ("ok", "partial", "error", "capture_inconclusive"):
            raise ValueError("unsupported result status")
        if self.evidence_grade not in EVIDENCE_GRADES:
            raise ValueError("unsupported top-level evidence grade")
        if self.schema_version != "kcd2.result-envelope.v1":
            raise ValueError("unsupported result envelope schema_version")
        if (self.status == "error") != (self.error is not None):
            raise ValueError("error status and typed error must be present together")
        values = tuple(self.diagnostics)
        if values and all(isinstance(item, Diagnostic) for item in values):
            raw = tuple(item for item in values if isinstance(item, Diagnostic))
            aggregates = aggregate_diagnostics(
                raw,
                max_examples=self.limits.max_examples,
                max_messages=self.limits.max_examples,
            )
            detail_truncated = (
                len({item.example for item in raw if item.example is not None})
                > self.limits.max_examples
                or len({item.message for item in raw}) > self.limits.max_examples
            )
            object.__setattr__(self, "diagnostics", aggregates)
            object.__setattr__(
                self,
                "diagnostics_truncated",
                self.diagnostics_truncated or detail_truncated,
            )
            values = aggregates
        elif any(isinstance(item, Diagnostic) for item in values):
            raise TypeError("diagnostics cannot mix observations and aggregates")
        if any(not isinstance(item, DiagnosticAggregate) for item in values):
            raise TypeError("diagnostics must contain Diagnostic or DiagnosticAggregate values")
        keys = [(item.code, item.cause) for item in values]
        if len(keys) != len(set(keys)):
            raise ValueError("diagnostic aggregates must be unique by code and cause")
        if sum(len(item.examples) for item in values) > self.limits.max_examples:
            raise ValueError("diagnostic examples exceed the response-wide maximum")

    @property
    def authoritative_evidence_grade(self) -> EvidenceGrade:
        """Return the sole grade used for wrapper-level decisions."""
        return self.evidence_grade

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "evidence_grade": self.evidence_grade,
            "data": dict(self.data) if self.data is not None else None,
            "error": self.error.to_dict() if self.error is not None else None,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
            "pagination": self.pagination.to_dict(),
            "limits": self.limits.to_dict(),
        }

    def to_json(self) -> str:
        """Return canonical JSON only when the complete envelope fits its ceiling."""
        encoded = canonical_json_bytes(self.to_dict())
        if len(encoded) > self.limits.max_response_bytes:
            raise ResponseLimitError("complete response exceeds max_response_bytes")
        return encoded.decode("utf-8")

    @classmethod
    def from_json(cls, value: str) -> "ResultEnvelope":
        decoded = json.loads(value)
        if not isinstance(decoded, dict):
            raise ValueError("result envelope must be a JSON object")
        expected = {
            "schema_version",
            "status",
            "evidence_grade",
            "data",
            "error",
            "diagnostics",
            "diagnostics_truncated",
            "pagination",
            "limits",
        }
        if set(decoded) != expected:
            raise ValueError("result envelope fields do not match v1")
        diagnostics: list[DiagnosticAggregate] = []
        for item in decoded["diagnostics"]:
            if item.get("schema_version") != "kcd2.diagnostic-aggregate.v1":
                raise ValueError("result envelope diagnostics must be aggregates")
            diagnostics.append(
                DiagnosticAggregate(
                    code=item["code"],
                    cause=item["cause"],
                    severity=item["severity"],
                    count=item["count"],
                    messages=tuple(item["messages"]),
                    examples=tuple(item["examples"]),
                    schema_version=item["schema_version"],
                )
            )
        return cls(
            schema_version=decoded["schema_version"],
            status=decoded["status"],
            evidence_grade=decoded["evidence_grade"],
            data=decoded["data"],
            error=ToolError.from_dict(decoded["error"]) if decoded["error"] else None,
            diagnostics=tuple(diagnostics),
            diagnostics_truncated=decoded["diagnostics_truncated"],
            pagination=Pagination.from_dict(decoded["pagination"]),
            limits=ResponseLimits.from_dict(decoded["limits"]),
        )


def _trim_diagnostics(
    diagnostics: tuple[DiagnosticAggregate, ...],
) -> tuple[DiagnosticAggregate, ...]:
    """Remove one optional detail deterministically, then one aggregate as a last resort."""
    values = list(diagnostics)
    for index in range(len(values) - 1, -1, -1):
        item = values[index]
        if item.examples:
            values[index] = replace(item, examples=item.examples[:-1])
            return tuple(values)
        if len(item.messages) > 1:
            values[index] = replace(item, messages=item.messages[:-1])
            return tuple(values)
    if values:
        values.pop()
    return tuple(values)


def build_bounded_envelope(
    *,
    status: ResultStatus,
    evidence_grade: EvidenceGrade,
    data: Mapping[str, Any] | None = None,
    items: Sequence[Any] | None = None,
    diagnostics: Iterable[Diagnostic] = (),
    error: ToolError | None = None,
    limits: ResponseLimits | None = None,
    continuation_token: str | None = None,
    continuation_scope: str = "default",
) -> ResultEnvelope:
    """Build one page and enforce the byte ceiling over the complete envelope."""
    if limits is None:
        limits = ResponseLimits()
    payload = dict(data) if data is not None else {}
    if items is not None and "items" in payload:
        raise ValueError("data.items is reserved when paginated items are supplied")
    all_items: Sequence[Any] = items if items is not None else ()
    digest = _items_digest(all_items)
    if continuation_token is None:
        offset = 0
        page = 1
    else:
        handle = decode_continuation_handle(
            continuation_token,
            scope=continuation_scope,
            items=all_items,
        )
        offset = handle.offset
        page = handle.page
    if page > limits.max_pages:
        raise ValueError("continuation page exceeds max_pages")

    raw_diagnostics = tuple(diagnostics)
    aggregates = aggregate_diagnostics(
        raw_diagnostics,
        max_examples=limits.max_examples,
        max_messages=limits.max_examples,
    )
    distinct_examples = {
        item.example for item in raw_diagnostics if item.example is not None
    }
    distinct_messages = {item.message for item in raw_diagnostics}
    diagnostics_truncated = (
        len(distinct_examples) > limits.max_examples
        or len(distinct_messages) > limits.max_examples
    )

    remaining = len(all_items) - offset
    maximum_count = min(limits.page_size, remaining)
    current_diagnostics = aggregates
    while True:
        minimum_count = 1 if remaining else 0
        for count in range(maximum_count, minimum_count - 1, -1):
            page_items = list(all_items[offset : offset + count])
            page_data = dict(payload)
            if items is not None:
                page_data["items"] = page_items
            more_items = offset + count < len(all_items)
            can_continue = more_items and page < limits.max_pages
            token = (
                ContinuationHandle(
                    scope=continuation_scope,
                    items_sha256=digest,
                    offset=offset + count,
                    page=page + 1,
                ).to_token()
                if can_continue
                else None
            )
            envelope = ResultEnvelope(
                status=status,
                evidence_grade=evidence_grade,
                data=page_data if data is not None or items is not None else None,
                error=error,
                diagnostics=current_diagnostics,
                diagnostics_truncated=diagnostics_truncated,
                pagination=Pagination(
                    page=page,
                    page_size=limits.page_size,
                    returned_items=count,
                    total_items=len(all_items),
                    continuation_token=token,
                    truncated=more_items or diagnostics_truncated,
                ),
                limits=limits,
            )
            if len(canonical_json_bytes(envelope.to_dict())) <= limits.max_response_bytes:
                return envelope

        trimmed = _trim_diagnostics(current_diagnostics)
        if trimmed != current_diagnostics:
            current_diagnostics = trimmed
            diagnostics_truncated = True
            continue
        if remaining:
            raise ResponseLimitError(
                "one page item cannot fit inside max_response_bytes with the envelope"
            )
        raise ResponseLimitError("irreducible response exceeds max_response_bytes")
