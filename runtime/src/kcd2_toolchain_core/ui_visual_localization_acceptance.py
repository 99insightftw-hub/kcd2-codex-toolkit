"""Bounded COMPAT-005 UI, visual, and localization stack acceptance."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_research_graph.ui_runtime import UIRuntimeAdapterError, adapt_ui_gfx_runtime

from .asset_runtime import AssetRuntimeAdapterError, adapt_visual_lighting_runtime
from .compatibility_stacks import CompatibilityStackError, evaluate_compatibility_stack
from .hashing import sha256_json
from .localization_release import (
    LocalizationReleaseAcceptanceError,
    evaluate_localization_release_acceptance,
)
from .paths import canonical_path_key


SCHEMA_VERSION = "kcd2.ui-visual-localization-stack-acceptance.v1"
_MAX_BINDINGS = 64
_MAX_TEXT = 1024
_ROOT_FIELDS = {
    "schema_version",
    "acceptance_id",
    "stack_manifest",
    "provider_bindings",
    "expected_aspect",
    "ui_runtime",
    "visual_runtime",
    "localization_release",
}
_BINDING_FIELDS = {
    "provider_id",
    "project_id",
    "selection_id",
    "selected_member_id",
}


class UIVisualLocalizationAcceptanceError(ValueError):
    """A COMPAT-005 fixture is malformed or exceeds a hard bound."""


@dataclass(frozen=True, slots=True)
class UIVisualLocalizationAcceptanceReceipt:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _mapping(value: object, fields: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise UIVisualLocalizationAcceptanceError(
            f"{name} fields do not match the contract"
        )
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise UIVisualLocalizationAcceptanceError(f"{name} must be an array")
    if not value or len(value) > maximum:
        raise UIVisualLocalizationAcceptanceError(f"{name} violates its hard bound")
    return value


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise UIVisualLocalizationAcceptanceError(
            f"{name} must be bounded non-empty text"
        )
    return value


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise UIVisualLocalizationAcceptanceError(
            "input must contain JSON values only"
        ) from exc


def _bindings(value: object) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(value, "provider_bindings", _MAX_BINDINGS)):
        row = _mapping(raw, _BINDING_FIELDS, f"provider_bindings[{index}]")
        normalized = {field: _text(row[field], field) for field in _BINDING_FIELDS}
        key = normalized["provider_id"].casefold()
        if key in seen:
            raise UIVisualLocalizationAcceptanceError(
                "provider bindings must have unique provider_id values"
            )
        seen.add(key)
        rows.append(normalized)
    return sorted(rows, key=lambda row: row["provider_id"].casefold())


def _gate(
    rows: list[dict[str, Any]],
    gate_id: str,
    status: str,
    layer: str,
    evidence_refs: Sequence[str],
) -> None:
    rows.append(
        {
            "gate_id": gate_id,
            "status": status,
            "evidence_layer": layer,
            "evidence_refs": sorted(set(evidence_refs), key=str.casefold),
        }
    )


def evaluate_ui_visual_localization_acceptance(
    value: Mapping[str, Any],
) -> UIVisualLocalizationAcceptanceReceipt:
    """Evaluate one self-contained, synthetic or reviewed non-live stack fixture."""

    root = _mapping(_detached(value), _ROOT_FIELDS, "acceptance input")
    if root["schema_version"] != SCHEMA_VERSION:
        raise UIVisualLocalizationAcceptanceError(
            f"schema_version must be {SCHEMA_VERSION}"
        )
    acceptance_id = _text(root["acceptance_id"], "acceptance_id")
    bindings = _bindings(root["provider_bindings"])
    aspect = _mapping(
        root["expected_aspect"], {"aspect_ratio", "mode"}, "expected_aspect"
    )
    expected_ratio = _text(aspect["aspect_ratio"], "expected_aspect.aspect_ratio")
    expected_mode = _text(aspect["mode"], "expected_aspect.mode")
    try:
        stack = evaluate_compatibility_stack(root["stack_manifest"]).to_dict()
        ui = adapt_ui_gfx_runtime(root["ui_runtime"])
        visual = adapt_visual_lighting_runtime(root["visual_runtime"])
        localization = evaluate_localization_release_acceptance(
            root["localization_release"]
        ).to_dict()
    except (
        AssetRuntimeAdapterError,
        CompatibilityStackError,
        LocalizationReleaseAcceptanceError,
        UIRuntimeAdapterError,
        TypeError,
    ) as exc:
        raise UIVisualLocalizationAcceptanceError(str(exc)) from exc

    gates: list[dict[str, Any]] = []
    reasons: set[str] = set()
    binding_by_provider = {row["provider_id"]: row for row in bindings}
    selections = {row["project_id"]: row for row in stack["selected_variants"]}
    members = {row["project_id"] for row in stack["members"]}
    binding_errors: list[str] = []
    for binding in bindings:
        selection = selections.get(binding["project_id"])
        if (
            binding["project_id"] not in members
            or selection is None
            or selection["selection_id"] != binding["selection_id"]
            or binding["selected_member_id"] not in selection["selected_member_ids"]
        ):
            binding_errors.append(binding["provider_id"])
    stack_bound = (
        stack["family"] == "UI_VISUAL_LOCALIZATION"
        and stack["result"] == "PASS"
        and not binding_errors
    )
    if not stack_bound:
        reasons.add("SELECTED_VARIANT_UNBOUND")
    _gate(
        gates,
        "selected_variant_binding",
        "PASS" if stack_bound else "FAIL",
        "static",
        binding_errors or [stack["stack_id"]],
    )

    intended = {
        canonical_path_key(row["resource"]): row["provider_project_id"]
        for row in stack["intended_winners"]
    }
    winner_errors: list[str] = []

    def winner_matches(path: str, provider_id: str) -> bool:
        binding = binding_by_provider.get(provider_id)
        return binding is not None and intended.get(canonical_path_key(path)) == binding[
            "project_id"
        ]

    for resource in ui["provider_resolution"]["resources"]:
        if resource["exact_active_winner"] and not winner_matches(
            resource["canonical_path"], resource["winner_provider_id"]
        ):
            winner_errors.append(resource["resource_id"])
    for resource in visual["resources"]:
        if resource["resolution_status"] == "exact_active_winner" and not winner_matches(
            resource["canonical_path"], resource["winner_provider_id"]
        ):
            winner_errors.append(resource["resource_id"])
    for package in localization["package_isolation"]:
        if not winner_matches(package["package_path"], package["provider_id"]):
            winner_errors.append(package["mount_id"])
    if winner_errors:
        reasons.add("RESOURCE_WINNER_UNBOUND")
    _gate(
        gates,
        "resource_winners",
        "PASS" if not winner_errors else "FAIL",
        "static",
        winner_errors or [stack["stack_id"]],
    )

    localization_inconclusive = localization["status"] == "capture_inconclusive"
    mount_collision = any(
        not row["isolated"] or not row["audit_mount_matched"]
        for row in localization["package_isolation"]
    )
    language_ok = (
        localization["status"] == "accepted"
        and localization["localization_audit"]["no_conflict_claim_allowed"] is True
        and not mount_collision
    )
    language_status = "PASS" if language_ok else (
        "INCONCLUSIVE" if localization_inconclusive else "FAIL"
    )
    if language_status == "FAIL":
        reasons.add("LANGUAGE_MOUNT_COLLISION" if mount_collision else "LOCALIZATION_REJECTED")
    elif language_status == "INCONCLUSIVE":
        reasons.add("LANGUAGE_COVERAGE_INCONCLUSIVE")
    _gate(
        gates,
        "language_mounts",
        language_status,
        "static",
        [row["mount_id"] for row in localization["package_isolation"]],
    )

    runtime_complete = ui["status"] == "complete" and visual["status"] == "complete"
    focus_ok = ui["focus"]["status"] == "restored"
    input_ok = ui["input_ownership"]["status"] == "released"
    lifecycle_ok = focus_ok and input_ok and ui["cleanup"]["active_instances"] == 0
    if not focus_ok:
        reasons.add("FOCUS_NOT_RESTORED")
    if not input_ok:
        reasons.add("INPUT_OWNERSHIP_NOT_RELEASED")
    _gate(
        gates,
        "focus_input_lifecycle",
        "PASS" if lifecycle_ok else "INCONCLUSIVE",
        "runtime",
        [ui["session_id"]],
    )

    instance_aspects = {
        (row["aspect_ratio"], row["aspect_mode"])
        for row in ui["instances"]
        if row["aspect_ratio"] is not None
    }
    aspect_ok = (expected_ratio, expected_mode) in instance_aspects
    if not aspect_ok:
        reasons.add("ASPECT_BEHAVIOR_UNPROVEN")
    _gate(
        gates,
        "aspect_behavior",
        "PASS" if aspect_ok else "INCONCLUSIVE",
        "runtime",
        [f"{expected_ratio}:{expected_mode}"],
    )

    listeners_ok = (
        ui["listeners"]["active_count"] == 0
        and ui["cleanup"]["active_listeners"] == 0
        and ui["cleanup"]["session_state"] == "complete"
    )
    if not listeners_ok:
        reasons.add("LISTENER_CLEANUP_INCOMPLETE")
    _gate(
        gates,
        "listener_cleanup",
        "PASS" if listeners_ok else "INCONCLUSIVE",
        "runtime",
        [ui["session_id"]],
    )

    declared_fallbacks = sum(
        row["fallback_resource_id"] is not None
        for row in ui["provider_resolution"]["resources"]
    ) + sum(row["fallback_resource_id"] is not None for row in visual["resources"])
    explicit_fallbacks = len(ui["fallbacks"]) + len(visual["fallbacks"])
    fallback_ok = declared_fallbacks == explicit_fallbacks
    if not fallback_ok:
        reasons.add("RESOURCE_FALLBACK_UNPROVEN")
    _gate(
        gates,
        "resource_fallbacks",
        "PASS" if fallback_ok else "INCONCLUSIVE",
        "runtime",
        [ui["session_id"], visual["session_id"]],
    )

    snapshot = stack["identity"]["active_snapshot_id"]
    sessions = set(stack["identity"]["runtime_session_ids"])
    identity_ok = (
        ui["active_snapshot_id"] == snapshot
        and visual["active_snapshot_id"] == snapshot
        and localization["localization_audit"]["snapshot_id"] == snapshot
        and ui["session_id"] in sessions
        and visual["session_id"] in sessions
    )
    if not identity_ok:
        reasons.add("RUNTIME_IDENTITY_UNBOUND")
    _gate(
        gates,
        "runtime_identity",
        "PASS" if identity_ok else "FAIL",
        "runtime",
        [snapshot, ui["session_id"], visual["session_id"]],
    )

    if not runtime_complete:
        reasons.add("RUNTIME_CAPTURE_INCONCLUSIVE")
    gates.sort(key=lambda row: row["gate_id"])
    if any(row["status"] == "FAIL" for row in gates):
        status = "FAIL"
    elif any(row["status"] == "INCONCLUSIVE" for row in gates):
        status = "INCONCLUSIVE"
    else:
        status = "PASS"
    payload = {
        "schema_version": SCHEMA_VERSION,
        "acceptance_id": acceptance_id,
        "stack_id": stack["stack_id"],
        "active_snapshot_id": snapshot,
        "status": status,
        "evidence_layers": {"static": True, "runtime": True, "causal": False},
        "gates": gates,
        "ui": {
            "session_id": ui["session_id"],
            "focus_status": ui["focus"]["status"],
            "input_status": ui["input_ownership"]["status"],
            "aspect_status": ui["aspect"]["status"],
            "active_listener_count": ui["listeners"]["active_count"],
        },
        "visual": {
            "session_id": visual["session_id"],
            "status": visual["status"],
            "peak_active_emitters": visual["emitters"]["peak_active"],
        },
        "localization": {
            "release_id": localization["release_id"],
            "status": localization["status"],
            "isolated_mount_count": localization["counts"]["isolated_packages"],
            "no_false_language_collisions": language_ok,
        },
        "fallbacks": {
            "declared_count": declared_fallbacks,
            "explicit_count": explicit_fallbacks,
        },
        "component_receipts": {
            "ui_sha256": sha256_json(ui),
            "visual_sha256": sha256_json(visual),
            "localization_sha256": sha256_json(localization),
        },
        "reason_codes": sorted(reasons),
    }
    return UIVisualLocalizationAcceptanceReceipt(payload)


__all__ = [
    "UIVisualLocalizationAcceptanceError",
    "UIVisualLocalizationAcceptanceReceipt",
    "evaluate_ui_visual_localization_acceptance",
]
