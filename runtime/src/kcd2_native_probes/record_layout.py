"""Family-specific record-layout lint and bounded offline discovery helpers."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping


MAX_READABLE_SPAN_BYTES = 4096
MAX_KNOWN_VALUES = 128
MAX_KNOWN_VALUE_BYTES = 512
MAX_DISCOVERY_MATCHES = 256
MAX_LAYOUT_DIAGNOSTICS = 256
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_IDENTITY_TYPES = frozenset(
    {
        "fragment_guid",
        "table_row_identity",
        "record_pointer_ephemeral",
        "database_index",
        "dispatch_id",
    }
)
_CORROBORATION_KINDS = frozenset({"native_consumer", "repeated_positive_control"})


@dataclass(frozen=True, slots=True)
class LayoutDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class RecordLayoutLintReport:
    valid: bool
    diagnostics: tuple[LayoutDiagnostic, ...]
    diagnostics_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.record-layout-lint.v1",
            "status": "PASS" if self.valid else "FAIL",
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
        }


class _Collector:
    def __init__(self, maximum: int) -> None:
        if not 1 <= maximum <= 10_000:
            raise ValueError("max_diagnostics must be between 1 and 10000")
        self.maximum = maximum
        self.items: list[LayoutDiagnostic] = []
        self.truncated = False

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.items) < self.maximum:
            self.items.append(LayoutDiagnostic(code, path, message))
        else:
            self.truncated = True


def record_layout_lint(
    document: Mapping[str, Any], *, max_diagnostics: int = MAX_LAYOUT_DIAGNOSTICS
) -> RecordLayoutLintReport:
    """Lint one standalone layout document or complete probe-contract v2 manifest."""
    collector = _Collector(max_diagnostics)
    if not isinstance(document, Mapping):
        collector.add("DOCUMENT_TYPE_INVALID", "$", "layout input must be an object")
        return _report(collector)

    module_sha256 = _module_sha256(document, collector)
    layouts = document.get("record_layout_evidence")
    matchers = document.get("identity_matchers")
    if not isinstance(layouts, list):
        collector.add(
            "LAYOUT_COLLECTION_INVALID",
            "$.record_layout_evidence",
            "record_layout_evidence must be an array",
        )
        layouts = []
    if not isinstance(matchers, list):
        collector.add(
            "MATCHER_COLLECTION_INVALID",
            "$.identity_matchers",
            "identity_matchers must be an array",
        )
        matchers = []

    fields: dict[tuple[str, str], tuple[Mapping[str, Any], str]] = {}
    identity_locations: dict[tuple[str, int, int], tuple[str, str]] = {}
    for layout_index, layout in enumerate(layouts[:256]):
        layout_path = f"$.record_layout_evidence[{layout_index}]"
        if not isinstance(layout, Mapping):
            collector.add("LAYOUT_TYPE_INVALID", layout_path, "layout entry must be an object")
            continue
        family = layout.get("family")
        if not isinstance(family, str) or not family or len(family) > 256:
            collector.add(
                "RECORD_FAMILY_INVALID",
                f"{layout_path}.family",
                "layout must declare one bounded record family",
            )
            continue
        layout_hash = layout.get("module_sha256")
        if module_sha256 is not None and (
            not isinstance(layout_hash, str) or layout_hash.casefold() != module_sha256.casefold()
        ):
            collector.add(
                "LAYOUT_MODULE_MISMATCH",
                f"{layout_path}.module_sha256",
                "layout module SHA-256 differs from the document module identity",
            )
        layout_fields = layout.get("fields")
        if not isinstance(layout_fields, list):
            collector.add(
                "FIELD_COLLECTION_INVALID",
                f"{layout_path}.fields",
                "layout fields must be an array",
            )
            continue
        for field_index, field in enumerate(layout_fields[:256]):
            field_path = f"{layout_path}.fields[{field_index}]"
            if not isinstance(field, Mapping):
                collector.add("FIELD_TYPE_INVALID", field_path, "field must be an object")
                continue
            field_id = field.get("field_id")
            if not isinstance(field_id, str) or not field_id or len(field_id) > 256:
                collector.add(
                    "FIELD_ID_INVALID",
                    f"{field_path}.field_id",
                    "field_id must be bounded and non-empty",
                )
                continue
            key = (family, field_id)
            if key in fields:
                collector.add(
                    "FIELD_KEY_DUPLICATE",
                    f"{field_path}.field_id",
                    "field_id is duplicated within its record family",
                )
            else:
                fields[key] = (field, field_path)
            _lint_field(field, family, field_path, collector)
            offset = _hex_offset(field.get("offset"))
            width = field.get("width")
            semantic = field.get("semantic_type")
            if (
                offset is not None
                and isinstance(width, int)
                and not isinstance(width, bool)
                and semantic in _IDENTITY_TYPES
            ):
                physical_key = (family, offset, width)
                prior = identity_locations.get(physical_key)
                if prior is not None and prior[0] != semantic:
                    collector.add(
                        "FIELD_IDENTITY_CONFLATION",
                        f"{field_path}.semantic_type",
                        f"same family offset/width was already typed as {prior[0]!r}",
                    )
                else:
                    identity_locations[physical_key] = (semantic, field_path)
        if len(layout_fields) > 256:
            collector.add(
                "FIELD_COLLECTION_LIMIT",
                f"{layout_path}.fields",
                "layout exceeds 256 fields",
            )
    if len(layouts) > 256:
        collector.add(
            "LAYOUT_COLLECTION_LIMIT",
            "$.record_layout_evidence",
            "record_layout_evidence exceeds 256 layouts",
        )

    for matcher_index, matcher in enumerate(matchers[:128]):
        path = f"$.identity_matchers[{matcher_index}]"
        _lint_matcher(matcher, path, fields, collector)
    if len(matchers) > 128:
        collector.add(
            "MATCHER_COLLECTION_LIMIT",
            "$.identity_matchers",
            "identity_matchers exceeds 128 entries",
        )
    return _report(collector)


def discover_readable_span(
    *,
    record_family: str,
    span: bytes,
    known_values: Mapping[str, bytes],
    evidence: Mapping[str, Any],
    maximum_span_bytes: int,
) -> list[dict[str, Any]]:
    """Find exact known byte strings in one caller-supplied bounded readable span.

    This helper reads no process memory. It only examines bytes already supplied by the caller,
    and every result is explicitly provisional until separately corroborated.
    """
    if not isinstance(record_family, str) or not 1 <= len(record_family) <= 256:
        raise ValueError("record_family must contain 1 to 256 characters")
    if (
        not isinstance(maximum_span_bytes, int)
        or isinstance(maximum_span_bytes, bool)
        or not 1 <= maximum_span_bytes <= MAX_READABLE_SPAN_BYTES
    ):
        raise ValueError(f"maximum_span_bytes must be between 1 and {MAX_READABLE_SPAN_BYTES}")
    if not isinstance(span, bytes):
        raise TypeError("span must be bytes")
    if len(span) > maximum_span_bytes:
        raise ValueError("supplied readable span exceeds maximum_span_bytes")
    if not isinstance(known_values, Mapping):
        raise TypeError("known_values must be a mapping of identifiers to bytes")
    if not 1 <= len(known_values) <= MAX_KNOWN_VALUES:
        raise ValueError(f"known_values must contain 1 to {MAX_KNOWN_VALUES} entries")
    _validate_discovery_citation(evidence, record_family)

    results: list[dict[str, Any]] = []
    for known_value_id in sorted(known_values):
        value = known_values[known_value_id]
        if not isinstance(known_value_id, str) or not 1 <= len(known_value_id) <= 128:
            raise ValueError("known value identifiers must contain 1 to 128 characters")
        if not isinstance(value, bytes) or not 1 <= len(value) <= MAX_KNOWN_VALUE_BYTES:
            raise ValueError(
                f"known values must contain 1 to {MAX_KNOWN_VALUE_BYTES} bytes"
            )
        cursor = 0
        while True:
            offset = span.find(value, cursor)
            if offset < 0:
                break
            safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", known_value_id)
            results.append(
                {
                    "field_id": f"discovery-{safe_id}-{offset:x}",
                    "offset": f"0x{offset:X}",
                    "width": len(value),
                    "semantic_type": "unknown_discovery_candidate",
                    "evidence": [deepcopy(dict(evidence))],
                    "confidence": "low",
                    "promotion_state": "provisional_discovery",
                    "discovery": {
                        "mode": "bounded_readable_span",
                        "known_value_id": known_value_id,
                        "readable_span_bytes": len(span),
                    },
                    "corroboration": [],
                }
            )
            if len(results) > MAX_DISCOVERY_MATCHES:
                raise ValueError(f"discovery exceeds {MAX_DISCOVERY_MATCHES} matches")
            cursor = offset + 1
    return results


def _module_sha256(
    document: Mapping[str, Any], collector: _Collector
) -> str | None:
    value = document.get("module_sha256")
    expected_module = document.get("expected_module")
    if value is None and isinstance(expected_module, Mapping):
        value = expected_module.get("sha256")
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        collector.add(
            "MODULE_IDENTITY_INVALID",
            "$.module_sha256",
            "document must declare a 64-digit module SHA-256",
        )
        return None
    return value


def _lint_field(
    field: Mapping[str, Any], family: str, path: str, collector: _Collector
) -> None:
    offset = field.get("offset")
    if _hex_offset(offset) is None:
        collector.add("FIELD_OFFSET_INVALID", f"{path}.offset", "offset must be hexadecimal")
    width = field.get("width")
    if not isinstance(width, int) or isinstance(width, bool) or not 1 <= width <= 4096:
        collector.add("FIELD_WIDTH_INVALID", f"{path}.width", "width must be 1 to 4096")
    _lint_citations(field.get("evidence"), family, f"{path}.evidence", collector)

    semantic = field.get("semantic_type")
    promotion = field.get("promotion_state")
    discovery = field.get("discovery")
    if promotion == "provisional_discovery" and not isinstance(discovery, Mapping):
        collector.add(
            "PROVISIONAL_DISCOVERY_METADATA_REQUIRED",
            f"{path}.discovery",
            "provisional discovery requires bounded readable-span metadata",
        )
    if semantic == "unknown_discovery_candidate" and not isinstance(discovery, Mapping):
        collector.add(
            "DISCOVERY_METADATA_REQUIRED",
            f"{path}.discovery",
            "unknown discovery candidate requires bounded readable-span metadata",
        )
    if semantic == "unknown_discovery_candidate" and promotion == "confirmed":
        collector.add(
            "DISCOVERY_SEMANTIC_UNRESOLVED",
            f"{path}.semantic_type",
            "an unknown discovery candidate cannot be a confirmed field",
        )
    if discovery is not None:
        if not isinstance(discovery, Mapping) or discovery.get("mode") != "bounded_readable_span":
            collector.add(
                "DISCOVERY_MODE_INVALID",
                f"{path}.discovery",
                "discovered fields must declare bounded_readable_span mode",
            )
        if promotion == "provisional_discovery" and semantic != "unknown_discovery_candidate":
            collector.add(
                "DISCOVERY_PROVISIONAL_TYPE_INVALID",
                f"{path}.semantic_type",
                "a provisional discovered field must remain an unknown discovery candidate",
            )
        if promotion == "confirmed" and not _valid_corroboration(
            field.get("corroboration"), family, path, collector
        ):
            collector.add(
                "DISCOVERY_PROMOTION_UNCORROBORATED",
                f"{path}.promotion_state",
                "discovered offset requires a native consumer or repeated positive control",
            )


def _lint_matcher(
    matcher: object,
    path: str,
    fields: Mapping[tuple[str, str], tuple[Mapping[str, Any], str]],
    collector: _Collector,
) -> None:
    if not isinstance(matcher, Mapping):
        collector.add("MATCHER_TYPE_INVALID", path, "identity matcher must be an object")
        return
    family = matcher.get("record_family")
    if not isinstance(family, str) or not family:
        collector.add(
            "MATCHER_FAMILY_INVALID",
            f"{path}.record_family",
            "identity matcher must declare one record family",
        )
        return
    _lint_citations(matcher.get("evidence"), family, f"{path}.evidence", collector)
    mode = matcher.get("mode")
    identity_kind = matcher.get("identity_kind")
    field_id = matcher.get("field_id")
    field_entry = fields.get((family, field_id)) if isinstance(field_id, str) else None
    if field_entry is None:
        collector.add(
            "MATCHER_FIELD_NOT_PROVEN_FOR_FAMILY",
            f"{path}.field_id",
            "matcher field has no evidence under the declared record family",
        )
        return
    field, _ = field_entry

    if mode == "bounded_readable_span":
        if identity_kind != "known_value_span_discovery":
            collector.add(
                "DISCOVERY_IDENTITY_KIND_INVALID",
                f"{path}.identity_kind",
                "bounded span mode requires known_value_span_discovery",
            )
        if matcher.get("state") != "provisional_discovery":
            collector.add(
                "DISCOVERY_MATCHER_NOT_PROVISIONAL",
                f"{path}.state",
                "bounded readable-span matching cannot act as a confirmed filter",
            )
        bound = matcher.get("bounded_span_bytes")
        if not isinstance(bound, int) or isinstance(bound, bool) or not 1 <= bound <= 4096:
            collector.add(
                "DISCOVERY_SPAN_BOUND_INVALID",
                f"{path}.bounded_span_bytes",
                "bounded readable span must be between 1 and 4096 bytes",
            )
        known_values = matcher.get("known_values")
        if not isinstance(known_values, list) or not 1 <= len(known_values) <= 128:
            collector.add(
                "DISCOVERY_KNOWN_VALUES_INVALID",
                f"{path}.known_values",
                "bounded discovery requires 1 to 128 exact known values",
            )
        if not isinstance(field.get("discovery"), Mapping):
            collector.add(
                "DISCOVERY_FIELD_REQUIRED",
                f"{path}.field_id",
                "bounded span matcher must reference a discovered field",
            )
        elif isinstance(bound, int):
            readable_span_bytes = field["discovery"].get("readable_span_bytes")
            if not isinstance(readable_span_bytes, int) or readable_span_bytes > bound:
                collector.add(
                    "DISCOVERY_SPAN_BOUND_MISMATCH",
                    f"{path}.bounded_span_bytes",
                    "matcher bound is smaller than the recorded readable span",
                )
        return

    semantic = field.get("semantic_type")
    if identity_kind not in _IDENTITY_TYPES or semantic != identity_kind:
        collector.add(
            "IDENTITY_TYPE_MISMATCH",
            f"{path}.identity_kind",
            "identity kind must exactly match the family-specific field semantic type",
        )

    if mode == "exact_field":
        if matcher.get("state") == "confirmed_filter" and field.get(
            "promotion_state"
        ) != "confirmed":
            collector.add(
                "MATCHER_FIELD_PROVISIONAL",
                f"{path}.field_id",
                "confirmed filter requires a confirmed family-specific field",
            )
        if matcher.get("state") not in {"confirmed_filter", "unfiltered_observation"}:
            collector.add(
                "MATCHER_STATE_INVALID",
                f"{path}.state",
                "exact-field matcher state is invalid",
            )
        known_values = matcher.get("known_values")
        if matcher.get("state") == "confirmed_filter" and (
            not isinstance(known_values, list) or not 1 <= len(known_values) <= 128
        ):
            collector.add(
                "MATCHER_KNOWN_VALUES_REQUIRED",
                f"{path}.known_values",
                "confirmed exact-field matcher requires 1 to 128 known values",
            )
    elif mode in {"runtime_token", "unfiltered_population"}:
        if matcher.get("state") != "unfiltered_observation":
            collector.add(
                "MATCHER_STATE_INVALID",
                f"{path}.state",
                "runtime-token and population matchers must be unfiltered observations",
            )
    else:
        collector.add(
            "MATCHER_MODE_INVALID",
            f"{path}.mode",
            "identity matcher mode is unsupported",
        )


def _lint_citations(
    citations: object, family: str, path: str, collector: _Collector
) -> None:
    if not isinstance(citations, list) or not citations:
        collector.add(
            "FIELD_EVIDENCE_REQUIRED",
            path,
            "every offset or matcher requires cited static/runtime evidence",
        )
        return
    for index, citation in enumerate(citations[:256]):
        citation_path = f"{path}[{index}]"
        if not isinstance(citation, Mapping):
            collector.add(
                "EVIDENCE_CITATION_INVALID", citation_path, "citation must be an object"
            )
            continue
        if citation.get("evidence_class") not in {"static", "runtime"}:
            collector.add(
                "EVIDENCE_CLASS_INVALID",
                f"{citation_path}.evidence_class",
                "evidence_class must be static or runtime",
            )
        if citation.get("record_family") != family:
            collector.add(
                "EVIDENCE_FAMILY_MISMATCH",
                f"{citation_path}.record_family",
                "citation does not prove the field under this record family",
            )
        for name in ("artifact", "locator", "claim"):
            value = citation.get(name)
            if not isinstance(value, str) or not value:
                collector.add(
                    "EVIDENCE_CITATION_INVALID",
                    f"{citation_path}.{name}",
                    f"citation {name} must be non-empty",
                )


def _valid_corroboration(
    corroboration: object,
    family: str,
    field_path: str,
    collector: _Collector,
) -> bool:
    valid = False
    if not isinstance(corroboration, list):
        return False
    for index, item in enumerate(corroboration[:16]):
        path = f"{field_path}.corroboration[{index}]"
        if not isinstance(item, Mapping) or item.get("kind") not in _CORROBORATION_KINDS:
            collector.add(
                "CORROBORATION_KIND_INVALID",
                f"{path}.kind",
                "corroboration must be a native consumer or repeated positive control",
            )
            continue
        before = len(collector.items)
        _lint_citations(item.get("evidence"), family, f"{path}.evidence", collector)
        valid = valid or len(collector.items) == before
    return valid


def _validate_discovery_citation(evidence: Mapping[str, Any], family: str) -> None:
    if not isinstance(evidence, Mapping):
        raise TypeError("evidence must be a citation object")
    if evidence.get("evidence_class") not in {"static", "runtime"}:
        raise ValueError("evidence_class must be static or runtime")
    if evidence.get("record_family") != family:
        raise ValueError("evidence record_family must match record_family")
    for name in ("artifact", "locator", "claim"):
        value = evidence.get(name)
        if not isinstance(value, str) or not 1 <= len(value) <= 1024:
            raise ValueError(f"evidence {name} must contain 1 to 1024 characters")


def _hex_offset(value: object) -> int | None:
    if not isinstance(value, str) or re.fullmatch(r"0x[A-Fa-f0-9]+", value) is None:
        return None
    return int(value, 16)


def _report(collector: _Collector) -> RecordLayoutLintReport:
    diagnostics = tuple(collector.items)
    return RecordLayoutLintReport(
        valid=not diagnostics and not collector.truncated,
        diagnostics=diagnostics,
        diagnostics_truncated=collector.truncated,
    )
