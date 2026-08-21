"""Bounded, case-aware reference integrity over explicit package observations."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_toolchain_core.paths import canonical_relative_path

from .coverage import CoverageValidity


_FAMILIES = frozenset(
    {
        "table",
        "localization",
        "asset",
        "lua",
        "quest",
        "xsd",
        "smart_object",
        "animation",
    }
)
_PATH_FAMILIES = frozenset({"asset", "lua", "quest", "xsd", "animation"})
_MAX_TEXT = 1024
_MAX_DEFINITIONS = 20_000
_MAX_REFERENCES = 20_000
_MAX_MATCHES = 256
_MAX_EDGES = 100_000
_MAX_INDEX = 2**31 - 1


class ReferenceIntegrityError(ValueError):
    """Reference observations cannot produce a safe bounded report."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise ReferenceIntegrityError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _index(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_INDEX:
        raise ReferenceIntegrityError(
            f"{name} must be an integer from 0 through {_MAX_INDEX}"
        )
    return value


def _family(value: object) -> str:
    checked = _text(value, "family")
    if checked not in _FAMILIES:
        raise ReferenceIntegrityError(f"family must be one of {sorted(_FAMILIES)}")
    return checked


def _key(value: object, family: str, name: str) -> str:
    checked = _text(value, name)
    if family in _PATH_FAMILIES:
        try:
            return canonical_relative_path(checked)
        except (TypeError, ValueError) as exc:
            raise ReferenceIntegrityError(f"{name} must be a canonical relative path") from exc
    return checked


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ReferenceIntegrityError("reference report must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _bounded_items(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ReferenceIntegrityError(f"{name} must be an array")
    if len(value) > maximum:
        raise ReferenceIntegrityError(f"{name} exceeds the {maximum}-item hard bound")
    return value


@dataclass(frozen=True, slots=True)
class ReferenceDefinition:
    """One observed definition in the global provider inventory."""

    definition_id: str
    family: str
    key: str
    provider_id: str
    provider_kind: str
    source_path: str
    active: bool
    dependency: bool
    load_order_index: int

    def __post_init__(self) -> None:
        _text(self.definition_id, "definition_id")
        checked_family = _family(self.family)
        _key(self.key, checked_family, "definition.key")
        _text(self.provider_id, "definition.provider_id")
        _text(self.provider_kind, "definition.provider_kind")
        _text(self.source_path, "definition.source_path")
        if not isinstance(self.active, bool) or not isinstance(self.dependency, bool):
            raise ReferenceIntegrityError("active and dependency must be booleans")
        _index(self.load_order_index, "definition.load_order_index")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ReferenceDefinition":
        expected = {
            "definition_id",
            "family",
            "key",
            "provider_id",
            "provider_kind",
            "source_path",
            "active",
            "dependency",
            "load_order_index",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ReferenceIntegrityError("definition fields do not match the input contract")
        return cls(**value)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "definition_id": self.definition_id,
            "family": self.family,
            "key": _key(self.key, self.family, "definition.key"),
            "provider_id": self.provider_id,
            "provider_kind": self.provider_kind,
            "source_path": self.source_path,
            "active": self.active,
            "dependency": self.dependency,
            "load_order_index": self.load_order_index,
        }


@dataclass(frozen=True, slots=True)
class ReferenceUse:
    """One reference emitted by a table record or package member."""

    reference_id: str
    family: str
    target: str
    provider_id: str
    source_path: str
    load_order_index: int

    def __post_init__(self) -> None:
        _text(self.reference_id, "reference_id")
        checked_family = _family(self.family)
        _key(self.target, checked_family, "reference.target")
        _text(self.provider_id, "reference.provider_id")
        _text(self.source_path, "reference.source_path")
        _index(self.load_order_index, "reference.load_order_index")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ReferenceUse":
        expected = {
            "reference_id",
            "family",
            "target",
            "provider_id",
            "source_path",
            "load_order_index",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ReferenceIntegrityError("reference fields do not match the input contract")
        return cls(**value)  # type: ignore[arg-type]

    def to_dict(self) -> dict[str, object]:
        return {
            "reference_id": self.reference_id,
            "family": self.family,
            "target": _key(self.target, self.family, "reference.target"),
            "provider_id": self.provider_id,
            "source_path": self.source_path,
            "load_order_index": self.load_order_index,
        }


@dataclass(frozen=True, slots=True)
class ReferenceIntegrityReport:
    """Immutable schema-ready reference graph and bounded diagnostic report."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _definition_order(item: ReferenceDefinition) -> tuple[object, ...]:
    return (
        item.family,
        _key(item.key, item.family, "definition.key").casefold(),
        _key(item.key, item.family, "definition.key"),
        item.load_order_index,
        item.provider_id.casefold(),
        item.definition_id.casefold(),
    )


def _reference_order(item: ReferenceUse) -> tuple[object, ...]:
    return (item.reference_id.casefold(), item.reference_id)


def _matched_payload(items: Sequence[ReferenceDefinition]) -> list[dict[str, object]]:
    if len(items) > _MAX_MATCHES:
        raise ReferenceIntegrityError(
            f"one reference exceeds the {_MAX_MATCHES}-definition match hard bound"
        )
    return [
        {
            "definition_id": item.definition_id,
            "defined_key": _key(item.key, item.family, "definition.key"),
            "provider_id": item.provider_id,
            "active": item.active,
            "dependency": item.dependency,
            "load_order_index": item.load_order_index,
        }
        for item in sorted(items, key=_definition_order)
    ]


def _resolve_one(
    reference: ReferenceUse,
    exact: Sequence[ReferenceDefinition],
    folded: Sequence[ReferenceDefinition],
    *,
    absence_allowed: bool,
) -> dict[str, object]:
    target = _key(reference.target, reference.family, "reference.target")
    active = [item for item in exact if item.active]
    reasons: list[str]
    matches: Sequence[ReferenceDefinition]
    if len(active) > 1:
        classification = "ambiguous_duplicate_definition"
        matches = active
        reasons = ["AMBIGUOUS_ACTIVE_DEFINITIONS"]
    elif len(active) == 1:
        matches = active
        if active[0].load_order_index > reference.load_order_index:
            classification = "defined_by_later_mod"
            reasons = ["DEFINITION_LOADS_AFTER_REFERENCE_PROVIDER"]
        else:
            classification = "resolved_active"
            reasons = []
    else:
        dependency = [item for item in exact if item.dependency]
        inactive = [item for item in exact if not item.dependency]
        if len(dependency) > 1:
            classification = "ambiguous_duplicate_definition"
            matches = dependency
            reasons = ["AMBIGUOUS_DEPENDENCY_DEFINITIONS"]
        elif dependency:
            classification = "available_only_in_dependency"
            matches = dependency
            reasons = ["DEPENDENCY_DEFINITION_NOT_ACTIVE"]
        elif len(inactive) > 1:
            classification = "ambiguous_duplicate_definition"
            matches = inactive
            reasons = ["AMBIGUOUS_INACTIVE_DEFINITIONS"]
        elif inactive:
            classification = "missing_from_active_set"
            matches = inactive
            reasons = ["GLOBAL_DEFINITION_NOT_ACTIVE"]
        else:
            if folded:
                classification = "defined_wrong_case"
                matches = folded
                reasons = ["CASE_MISMATCH"]
                if len(folded) > 1:
                    reasons.append("AMBIGUOUS_CASE_INSENSITIVE_MATCH")
            elif absence_allowed:
                classification = "missing_globally"
                matches = ()
                reasons = ["NO_GLOBAL_DEFINITION"]
            else:
                classification = "capture_inconclusive"
                matches = ()
                reasons = ["GLOBAL_ABSENCE_BLOCKED_BY_COVERAGE"]
    return {
        "reference_id": reference.reference_id,
        "family": reference.family,
        "target": target,
        "classification": classification,
        "reason_codes": sorted(reasons),
        "matched_definitions": _matched_payload(matches),
    }


def check_reference_integrity(
    *,
    report_id: str,
    definitions: Sequence[ReferenceDefinition],
    references: Sequence[ReferenceUse],
    coverage: CoverageValidity,
) -> ReferenceIntegrityReport:
    """Resolve explicit references without widening claims beyond supplied coverage."""

    checked_id = _text(report_id, "report_id")
    definition_items = _bounded_items(definitions, "definitions", _MAX_DEFINITIONS)
    reference_items = _bounded_items(references, "references", _MAX_REFERENCES)
    if any(not isinstance(item, ReferenceDefinition) for item in definition_items):
        raise ReferenceIntegrityError("definitions must contain ReferenceDefinition values")
    if any(not isinstance(item, ReferenceUse) for item in reference_items):
        raise ReferenceIntegrityError("references must contain ReferenceUse values")
    if not isinstance(coverage, CoverageValidity):
        raise ReferenceIntegrityError("coverage must be CoverageValidity")

    typed_definitions = tuple(definition_items)  # type: ignore[assignment]
    typed_references = tuple(reference_items)  # type: ignore[assignment]
    definition_ids = [item.definition_id.casefold() for item in typed_definitions]
    reference_ids = [item.reference_id.casefold() for item in typed_references]
    if len(definition_ids) != len(set(definition_ids)):
        raise ReferenceIntegrityError("definition_id values must be case-insensitively unique")
    if len(reference_ids) != len(set(reference_ids)):
        raise ReferenceIntegrityError("reference_id values must be case-insensitively unique")

    ordered_definitions = tuple(sorted(typed_definitions, key=_definition_order))
    ordered_references = tuple(sorted(typed_references, key=_reference_order))
    coverage_payload = coverage.to_dict()
    permissions = coverage_payload.get("claim_permissions")
    if not isinstance(permissions, Mapping):
        raise ReferenceIntegrityError("coverage claim_permissions are missing")
    absence_allowed = permissions.get("absence_claim_allowed") is True

    exact_index: dict[tuple[str, str], list[ReferenceDefinition]] = {}
    folded_index: dict[tuple[str, str], list[ReferenceDefinition]] = {}
    for definition in ordered_definitions:
        defined_key = _key(definition.key, definition.family, "definition.key")
        exact_index.setdefault((definition.family, defined_key), []).append(definition)
        folded_index.setdefault((definition.family, defined_key.casefold()), []).append(
            definition
        )
    resolutions = [
        _resolve_one(
            reference,
            exact_index.get(
                (
                    reference.family,
                    _key(reference.target, reference.family, "reference.target"),
                ),
                (),
            ),
            folded_index.get(
                (
                    reference.family,
                    _key(
                        reference.target, reference.family, "reference.target"
                    ).casefold(),
                ),
                (),
            ),
            absence_allowed=absence_allowed,
        )
        for reference in ordered_references
    ]
    classifications = {item["classification"] for item in resolutions}
    complete_coverage = coverage_payload.get("overall_status") in {
        "COMPLETE",
        "COMPLETE_FOR_REQUESTED_SCOPE",
    }
    if not complete_coverage or "capture_inconclusive" in classifications:
        status = "capture_inconclusive"
    elif classifications.issubset({"resolved_active"}):
        status = "resolved"
    else:
        status = "issues_found"

    definition_payloads = [item.to_dict() for item in ordered_definitions]
    reference_payloads = [item.to_dict() for item in ordered_references]
    edges = [
        {
            "reference_id": resolution["reference_id"],
            "definition_id": match["definition_id"],
            "classification": resolution["classification"],
        }
        for resolution in resolutions
        for match in resolution["matched_definitions"]
    ]
    if len(edges) > _MAX_EDGES:
        raise ReferenceIntegrityError(
            f"reference graph exceeds the {_MAX_EDGES}-edge hard bound"
        )
    payload = {
        "schema_version": "kcd2.reference-integrity-report.v1",
        "report_id": checked_id,
        "input_sha256": hashlib.sha256(
            _canonical_bytes(
                {
                    "definitions": definition_payloads,
                    "references": reference_payloads,
                    "coverage": coverage_payload,
                }
            )
        ).hexdigest(),
        "status": status,
        "coverage": {
            "coverage_id": coverage_payload["coverage_id"],
            "overall_status": coverage_payload["overall_status"],
            "absence_claim_allowed": absence_allowed,
            "reason_codes": list(coverage_payload["reason_codes"]),
        },
        "bounds": {
            "max_definitions": _MAX_DEFINITIONS,
            "max_references": _MAX_REFERENCES,
            "max_matches_per_reference": _MAX_MATCHES,
            "max_edges": _MAX_EDGES,
            "definitions_considered": len(ordered_definitions),
            "references_considered": len(ordered_references),
        },
        "graph": {
            "definitions": definition_payloads,
            "references": reference_payloads,
            "edges": edges,
        },
        "resolutions": resolutions,
    }
    return ReferenceIntegrityReport(payload=_json_copy(payload))
