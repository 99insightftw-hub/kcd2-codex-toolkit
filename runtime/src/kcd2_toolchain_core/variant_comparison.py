"""Bounded cross-layer variant comparison and release/rollback selection gates."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path
from .variant_selection import VariantSelectionReceipt, validate_variant_selection


COMPARISON_SCHEMA_VERSION = "kcd2.variant-comparison.v1"
BOUNDARY_SCHEMA_VERSION = "kcd2.variant-boundary-gate.v1"
PROVIDER_STATE_SCHEMA_VERSION = "kcd2.variant-provider-state.v1"
MAX_DIFFERENCES = 4096
MAX_PROVIDER_BINDINGS = 4096
MAX_RUNTIME_DIFFERENCES = 2048
MAX_SELECTED_MEMBER_DETAILS = 64
MAX_RUNTIME_ITEM_BYTES = 64 * 1024
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_COMPARISON_ID = re.compile(r"^variant-comparison:sha256:[0-9a-f]{64}$")
_GATE_ID = re.compile(r"^variant-boundary-gate:sha256:[0-9a-f]{64}$")


class VariantComparisonError(ValueError):
    """Variant comparison evidence is malformed or exceeds a fixed bound."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise VariantComparisonError(f"{field} must be a mapping with string keys")
    return value


def _sequence(value: Any, field: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise VariantComparisonError(f"{field} must be an array")
    if len(value) > maximum:
        raise VariantComparisonError(f"{field} exceeds the hard bound of {maximum}")
    return value


def _text(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise VariantComparisonError(
            f"{field} must be non-empty text of at most {maximum} characters"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise VariantComparisonError(f"{field} must be a SHA-256 hex digest")
    return value.lower()


def _exact_fields(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    if set(value) != expected:
        raise VariantComparisonError(
            f"{field} fields do not match contract; "
            f"missing={sorted(expected - set(value))}, "
            f"unknown={sorted(set(value) - expected)}"
        )


def _detached_json(value: Any, field: str, maximum_bytes: int | None = None) -> Any:
    try:
        encoded = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise VariantComparisonError(f"{field} must be finite JSON") from exc
    if maximum_bytes is not None and len(encoded) > maximum_bytes:
        raise VariantComparisonError(f"{field} exceeds the hard byte bound")
    return copy.deepcopy(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class VariantComparisonReport:
    """Deeply immutable comparison of selected semantics, providers, and runtime."""

    _value: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True, slots=True)
class VariantBoundaryReport:
    """Deeply immutable release or rollback selection-boundary decision."""

    _value: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def _selected_summary(group: Mapping[str, Any]) -> tuple[dict[str, Any], bool]:
    members = {item["member_id"]: item for item in group["members"]}
    selected = [members[member_id] for member_id in group["selected_member_ids"]]
    selected.sort(key=lambda item: item["member_id"])
    retained = selected[:MAX_SELECTED_MEMBER_DETAILS]
    details = [
        {
            "member_id": item["member_id"],
            "artifact_sha256": item["artifact_sha256"],
            "mount_context": copy.deepcopy(item["mount_context"]),
            "selector": item["selector"],
            "provided_resource_count": len(item["provided_resources"]),
            "provided_resources_sha256": sha256_json(item["provided_resources"]),
        }
        for item in retained
    ]
    return (
        {
            "rule": group["rule"],
            "selected_member_count": len(selected),
            "selected_members": details,
            "selected_members_sha256": sha256_json(
                [
                    {
                        "member_id": item["member_id"],
                        "artifact_sha256": item["artifact_sha256"],
                        "mount_context": item["mount_context"],
                        "selector": item["selector"],
                        "provided_resources": item["provided_resources"],
                    }
                    for item in selected
                ]
            ),
            "details_truncated": len(selected) > len(retained),
        },
        len(selected) > len(retained),
    )


def _semantic_differences(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    left = {group["group_id"]: group for group in before["groups"]}
    right = {group["group_id"]: group for group in after["groups"]}
    result: list[dict[str, Any]] = []
    details_truncated = False
    for group_id in sorted(set(left) | set(right)):
        old_summary = None
        new_summary = None
        if group_id in left:
            old_summary, old_truncated = _selected_summary(left[group_id])
            details_truncated = details_truncated or old_truncated
        if group_id in right:
            new_summary, new_truncated = _selected_summary(right[group_id])
            details_truncated = details_truncated or new_truncated
        if old_summary != new_summary:
            result.append(
                {
                    "layer": "semantic",
                    "key": group_id,
                    "before": old_summary,
                    "after": new_summary,
                }
            )
    return result, details_truncated


def _provider_state(value: Any, field: str) -> tuple[dict[str, dict[str, Any]], bool]:
    state = _mapping(value, field)
    _exact_fields(state, {"schema_version", "complete", "bindings"}, field)
    if state["schema_version"] != PROVIDER_STATE_SCHEMA_VERSION:
        raise VariantComparisonError(
            f"{field}.schema_version must be {PROVIDER_STATE_SCHEMA_VERSION}"
        )
    complete = state["complete"]
    if not isinstance(complete, bool):
        raise VariantComparisonError(f"{field}.complete must be boolean")
    bindings: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(
        _sequence(state["bindings"], f"{field}.bindings", MAX_PROVIDER_BINDINGS)
    ):
        item_field = f"{field}.bindings[{index}]"
        item = _mapping(raw, item_field)
        _exact_fields(
            item,
            {"path", "provider_id", "artifact_sha256", "resolution_semantics"},
            item_field,
        )
        path = canonical_relative_path(item["path"])
        key = canonical_path_key(path)
        if key in bindings:
            raise VariantComparisonError(f"{field}.bindings contains duplicate paths")
        bindings[key] = {
            "path": path,
            "provider_id": _text(item["provider_id"], f"{item_field}.provider_id"),
            "artifact_sha256": _digest(
                item["artifact_sha256"], f"{item_field}.artifact_sha256"
            ),
            "resolution_semantics": _text(
                item["resolution_semantics"],
                f"{item_field}.resolution_semantics",
                128,
            ),
        }
    return bindings, complete


def _provider_differences(
    before: Any, after: Any
) -> tuple[list[dict[str, Any]], bool]:
    left, left_complete = _provider_state(before, "before_providers")
    right, right_complete = _provider_state(after, "after_providers")
    if not left_complete or not right_complete:
        return [], False
    result = []
    for key in sorted(set(left) | set(right)):
        if left.get(key) != right.get(key):
            path = (right.get(key) or left[key])["path"]
            result.append(
                {
                    "layer": "provider",
                    "key": path,
                    "before": copy.deepcopy(left.get(key)),
                    "after": copy.deepcopy(right.get(key)),
                }
            )
    return result, True


def _runtime_differences(value: Any) -> tuple[list[dict[str, Any]], bool, bool]:
    report = _mapping(value, "runtime_comparison")
    expected = {
        "schema_version",
        "before_session_id",
        "after_session_id",
        "status",
        "reasons",
        "changed",
        "unchanged",
        "counts",
        "total_assertions",
        "truncated",
    }
    _exact_fields(report, expected, "runtime_comparison")
    if report["schema_version"] != "kcd2.runtime-observation-comparison.v1":
        raise VariantComparisonError("runtime_comparison schema_version is unsupported")
    _text(report["before_session_id"], "runtime_comparison.before_session_id")
    _text(report["after_session_id"], "runtime_comparison.after_session_id")
    if report["status"] not in {"complete", "capture_inconclusive"}:
        raise VariantComparisonError("runtime_comparison.status is unsupported")
    reasons = _sequence(report["reasons"], "runtime_comparison.reasons", 256)
    if any(not isinstance(item, str) or not item or len(item) > 128 for item in reasons):
        raise VariantComparisonError("runtime_comparison.reasons contains invalid text")
    changed = _sequence(
        report["changed"], "runtime_comparison.changed", MAX_RUNTIME_DIFFERENCES
    )
    unchanged = _sequence(
        report["unchanged"], "runtime_comparison.unchanged", MAX_RUNTIME_DIFFERENCES
    )
    counts = _mapping(report["counts"], "runtime_comparison.counts")
    _exact_fields(counts, {"changed", "unchanged"}, "runtime_comparison.counts")
    if (
        any(isinstance(counts[key], bool) or not isinstance(counts[key], int) for key in counts)
        or counts["changed"] != len(changed)
        or counts["unchanged"] != len(unchanged)
    ):
        raise VariantComparisonError("runtime_comparison counts do not match retained entries")
    total = report["total_assertions"]
    if isinstance(total, bool) or not isinstance(total, int) or not 0 <= total <= 4096:
        raise VariantComparisonError("runtime_comparison.total_assertions is invalid")
    truncated = report["truncated"]
    if not isinstance(truncated, bool):
        raise VariantComparisonError("runtime_comparison.truncated must be boolean")
    if report["status"] == "capture_inconclusive":
        if changed or unchanged:
            raise VariantComparisonError(
                "an inconclusive runtime comparison cannot claim changed or unchanged assertions"
            )
        return [], False, truncated
    if reasons:
        raise VariantComparisonError("a complete runtime comparison cannot contain reasons")
    result = []
    required_item_fields = {
        "domain",
        "name",
        "expected",
        "before_actual",
        "after_actual",
        "before_status",
        "after_status",
    }
    for index, raw in enumerate(changed):
        field = f"runtime_comparison.changed[{index}]"
        item = _mapping(raw, field)
        _exact_fields(item, required_item_fields, field)
        domain = _text(item["domain"], f"{field}.domain", 128)
        name = _text(item["name"], f"{field}.name", 256)
        detached = _detached_json(item, field, MAX_RUNTIME_ITEM_BYTES)
        result.append(
            {
                "layer": "runtime",
                "key": f"{domain}/{name}",
                "before": {
                    "actual": detached["before_actual"],
                    "status": detached["before_status"],
                },
                "after": {
                    "actual": detached["after_actual"],
                    "status": detached["after_status"],
                },
            }
        )
    return result, True, truncated


def compare_variants(
    before_selection: Mapping[str, Any] | VariantSelectionReceipt,
    after_selection: Mapping[str, Any] | VariantSelectionReceipt,
    *,
    before_providers: Mapping[str, Any],
    after_providers: Mapping[str, Any],
    runtime_comparison: Mapping[str, Any],
    max_differences: int = 128,
) -> VariantComparisonReport:
    """Compare selected semantics, effective providers, and runtime evidence.

    Both selections are validated before any difference is emitted, so an invalid exactly-one
    group cannot enter either a comparison or a downstream release gate. Caller-supplied provider
    and runtime evidence must be complete to support claims in those layers.
    """

    if (
        isinstance(max_differences, bool)
        or not isinstance(max_differences, int)
        or not 1 <= max_differences <= MAX_DIFFERENCES
    ):
        raise VariantComparisonError(
            f"max_differences must be from 1 through {MAX_DIFFERENCES}"
        )
    before = validate_variant_selection(before_selection).to_dict()
    after = validate_variant_selection(after_selection).to_dict()
    semantic, semantic_details_truncated = _semantic_differences(before, after)
    provider, providers_complete = _provider_differences(
        before_providers, after_providers
    )
    runtime, runtime_complete, runtime_truncated = _runtime_differences(
        runtime_comparison
    )
    differences = sorted(
        [*semantic, *provider, *runtime],
        key=lambda item: (item["layer"], item["key"].casefold(), item["key"]),
    )
    retained = differences[:max_differences]
    reason_codes = []
    if semantic_details_truncated:
        reason_codes.append("SEMANTIC_DETAIL_TRUNCATED")
    if not providers_complete:
        reason_codes.append("PROVIDER_SCOPE_INCOMPLETE")
    if not runtime_complete:
        reason_codes.append("RUNTIME_COMPARISON_INCONCLUSIVE")
    if runtime_truncated:
        reason_codes.append("RUNTIME_COMPARISON_TRUNCATED")
    counts = {
        "semantic": len(semantic),
        "provider": len(provider),
        "runtime": len(runtime),
        "total": len(differences),
        "returned": len(retained),
    }
    material = {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "before_selection_id": before["selection_id"],
        "after_selection_id": after["selection_id"],
        "status": "capture_inconclusive" if reason_codes else "complete",
        "reason_codes": reason_codes,
        "difference_counts": counts,
        "differences": retained,
        "truncated": len(retained) < len(differences),
    }
    return VariantComparisonReport(
        _freeze(
            {
                **material,
                "comparison_id": f"variant-comparison:sha256:{sha256_json(material)}",
            }
        )
    )


def _comparison_document(
    value: Mapping[str, Any] | VariantComparisonReport,
) -> dict[str, Any]:
    document = value.to_dict() if isinstance(value, VariantComparisonReport) else dict(value)
    expected = {
        "schema_version",
        "comparison_id",
        "before_selection_id",
        "after_selection_id",
        "status",
        "reason_codes",
        "difference_counts",
        "differences",
        "truncated",
    }
    _exact_fields(document, expected, "comparison_report")
    if document["schema_version"] != COMPARISON_SCHEMA_VERSION:
        raise VariantComparisonError("comparison_report schema_version is unsupported")
    asserted = document.pop("comparison_id")
    computed = f"variant-comparison:sha256:{sha256_json(document)}"
    if not isinstance(asserted, str) or _COMPARISON_ID.fullmatch(asserted) is None:
        raise VariantComparisonError("comparison_report comparison_id is invalid")
    if asserted != computed:
        raise VariantComparisonError("comparison_report comparison_id does not match content")
    return {**document, "comparison_id": asserted}


def _boundary_report(material: dict[str, Any]) -> VariantBoundaryReport:
    return VariantBoundaryReport(
        _freeze(
            {
                **material,
                "gate_id": f"variant-boundary-gate:sha256:{sha256_json(material)}",
            }
        )
    )


def evaluate_variant_release_gate(
    selection: Mapping[str, Any] | VariantSelectionReceipt,
    *,
    topology_report: Mapping[str, Any],
    comparison_report: Mapping[str, Any] | VariantComparisonReport,
) -> VariantBoundaryReport:
    """Require one valid selected set and complete, untruncated release evidence."""

    selected = validate_variant_selection(selection).to_dict()
    topology = _mapping(topology_report, "topology_report")
    comparison = _comparison_document(comparison_report)
    reasons: list[str] = []
    inconclusive = False
    topology_selection_id = topology.get("selection_id")
    if topology_selection_id != selected["selection_id"]:
        reasons.append("TOPOLOGY_SELECTION_MISMATCH")
    topology_status = topology.get("status")
    if topology_status == "capture_inconclusive":
        reasons.append("TOPOLOGY_CAPTURE_INCONCLUSIVE")
        inconclusive = True
    elif topology_status != "PASS" or topology.get("release_allowed") is not True:
        reasons.append("TOPOLOGY_RELEASE_BLOCKED")
    if comparison["after_selection_id"] != selected["selection_id"]:
        reasons.append("COMPARISON_SELECTION_MISMATCH")
    if comparison["status"] != "complete":
        reasons.append("COMPARISON_INCONCLUSIVE")
        inconclusive = True
    if comparison["truncated"] is True:
        reasons.append("DIFFERENCES_TRUNCATED")
        inconclusive = True
    allowed = not reasons
    status = "PASS" if allowed else ("capture_inconclusive" if inconclusive else "FAIL")
    material = {
        "schema_version": BOUNDARY_SCHEMA_VERSION,
        "boundary": "release",
        "status": status,
        "allowed": allowed,
        "selection_id": selected["selection_id"],
        "release_selection_id": selected["selection_id"],
        "restore_selection_id": comparison["before_selection_id"],
        "selection_restored": False,
        "comparison_id": comparison["comparison_id"],
        "topology_report_id": topology.get("report_id"),
        "reason_codes": sorted(set(reasons)),
    }
    return _boundary_report(material)


def _release_gate_document(
    value: Mapping[str, Any] | VariantBoundaryReport,
) -> dict[str, Any]:
    document = value.to_dict() if isinstance(value, VariantBoundaryReport) else dict(value)
    expected = {
        "schema_version",
        "gate_id",
        "boundary",
        "status",
        "allowed",
        "selection_id",
        "release_selection_id",
        "restore_selection_id",
        "selection_restored",
        "comparison_id",
        "topology_report_id",
        "reason_codes",
    }
    _exact_fields(document, expected, "release_gate")
    if document["schema_version"] != BOUNDARY_SCHEMA_VERSION:
        raise VariantComparisonError("release_gate schema_version is unsupported")
    asserted = document.pop("gate_id")
    computed = f"variant-boundary-gate:sha256:{sha256_json(document)}"
    if not isinstance(asserted, str) or _GATE_ID.fullmatch(asserted) is None:
        raise VariantComparisonError("release_gate gate_id is invalid")
    if asserted != computed:
        raise VariantComparisonError("release_gate gate_id does not match content")
    return {**document, "gate_id": asserted}


def evaluate_variant_rollback_gate(
    release_gate: Mapping[str, Any] | VariantBoundaryReport,
    *,
    current_selection: Mapping[str, Any] | VariantSelectionReceipt,
    restored_selection: Mapping[str, Any] | VariantSelectionReceipt,
) -> VariantBoundaryReport:
    """Verify rollback moved from the released selection to the exact prior selection."""

    gate = _release_gate_document(release_gate)
    current = validate_variant_selection(current_selection).to_dict()
    restored = validate_variant_selection(restored_selection).to_dict()
    reasons = []
    if gate["boundary"] != "release" or gate["allowed"] is not True:
        reasons.append("RELEASE_GATE_NOT_AUTHORIZED")
    if current["selection_id"] != gate["release_selection_id"]:
        reasons.append("CURRENT_SELECTION_MISMATCH")
    if restored["selection_id"] != gate["restore_selection_id"]:
        reasons.append("RESTORED_SELECTION_MISMATCH")
    selection_restored = not reasons
    material = {
        "schema_version": BOUNDARY_SCHEMA_VERSION,
        "boundary": "rollback",
        "status": "PASS" if selection_restored else "FAIL",
        "allowed": selection_restored,
        "selection_id": restored["selection_id"],
        "release_selection_id": gate["release_selection_id"],
        "restore_selection_id": gate["restore_selection_id"],
        "selection_restored": selection_restored,
        "comparison_id": gate["comparison_id"],
        "topology_report_id": gate["topology_report_id"],
        "reason_codes": sorted(reasons),
    }
    return _boundary_report(material)


__all__ = [
    "BOUNDARY_SCHEMA_VERSION",
    "COMPARISON_SCHEMA_VERSION",
    "PROVIDER_STATE_SCHEMA_VERSION",
    "VariantBoundaryReport",
    "VariantComparisonError",
    "VariantComparisonReport",
    "compare_variants",
    "evaluate_variant_release_gate",
    "evaluate_variant_rollback_gate",
]
