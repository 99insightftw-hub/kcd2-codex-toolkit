"""Bounded COMPAT-006 animation, audio, and haptic stack acceptance."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_research_graph.combat_route_lint import (
    CombatRouteLintError,
    lint_combat_routes,
)

from .audio_haptic_routes import AudioHapticRouteError, resolve_audio_haptic_routes_mapping
from .audio_haptic_runtime import AudioHapticRuntimeError, adapt_audio_haptic_runtime
from .compatibility_stacks import CompatibilityStackError, evaluate_compatibility_stack
from .hashing import sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.animation-haptic-stack-acceptance.v1"
_MAX_TEXT = 2048
_MAX_BINDINGS = 1024
_MAX_ANIMATION_ROUTES = 4096
_ROOT_FIELDS = {
    "schema_version",
    "acceptance_id",
    "stack_manifest",
    "provider_bindings",
    "controller_binding",
    "animation_routes",
    "combat_route_model",
    "audio_haptic_routes",
    "audio_haptic_runtime",
}
_BINDING_FIELDS = {
    "provider_id",
    "project_id",
    "selection_id",
    "selected_member_id",
    "roles",
}
_CONTROLLER_FIELDS = {"controller_id", "runtime_type"}
_ANIMATION_FIELDS = {
    "route_id",
    "adb_path",
    "fragment_id",
    "animevent",
    "provider_id",
    "source_role",
    "target_role",
}
_KNOWN_ROLES = {"master", "slave"}


class AnimationHapticAcceptanceError(ValueError):
    """The supplied acceptance fixture is malformed or exceeds a hard bound."""


@dataclass(frozen=True, slots=True)
class AnimationHapticAcceptanceReceipt:
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
        raise AnimationHapticAcceptanceError(f"{name} fields do not match the contract")
    return value


def _sequence(value: object, name: str, maximum: int, *, nonempty: bool = True) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AnimationHapticAcceptanceError(f"{name} must be an array")
    if (nonempty and not value) or len(value) > maximum:
        raise AnimationHapticAcceptanceError(f"{name} violates its hard bound")
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise AnimationHapticAcceptanceError(f"{name} must be bounded non-empty text")
    return value


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise AnimationHapticAcceptanceError("input must contain JSON values only") from exc


def _normalize_bindings(value: object) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(value, "provider_bindings", _MAX_BINDINGS)):
        row = _mapping(raw, _BINDING_FIELDS, f"provider_bindings[{index}]")
        provider_id = _text(row["provider_id"], "provider_id")
        if provider_id.casefold() in seen:
            raise AnimationHapticAcceptanceError("provider_id values must be unique")
        seen.add(provider_id.casefold())
        roles = sorted(
            {_text(role, "provider role") for role in _sequence(row["roles"], "roles", 2)},
            key=str.casefold,
        )
        if len(roles) != len(row["roles"]) or not set(roles) <= _KNOWN_ROLES:
            raise AnimationHapticAcceptanceError("provider roles must be unique master/slave roles")
        rows.append(
            {
                "provider_id": provider_id,
                "project_id": _text(row["project_id"], "project_id"),
                "selection_id": _text(row["selection_id"], "selection_id"),
                "selected_member_id": _text(row["selected_member_id"], "selected_member_id"),
                "roles": roles,
            }
        )
    return sorted(rows, key=lambda row: row["provider_id"].casefold())


def _normalize_animation_routes(value: object) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(
        _sequence(value, "animation_routes", _MAX_ANIMATION_ROUTES)
    ):
        row = _mapping(raw, _ANIMATION_FIELDS, f"animation_routes[{index}]")
        route_id = _text(row["route_id"], "animation route_id")
        if route_id.casefold() in seen:
            raise AnimationHapticAcceptanceError("animation route_id values must be unique")
        seen.add(route_id.casefold())
        try:
            adb_path = canonical_relative_path(_text(row["adb_path"], "adb_path"))
        except (TypeError, ValueError) as exc:
            raise AnimationHapticAcceptanceError("adb_path must be canonical and relative") from exc
        rows.append(
            {
                "route_id": route_id,
                "adb_path": adb_path,
                "fragment_id": _text(row["fragment_id"], "fragment_id"),
                "animevent": _text(row["animevent"], "animevent"),
                "provider_id": _text(row["provider_id"], "provider_id"),
                "source_role": _text(row["source_role"], "source_role"),
                "target_role": _text(row["target_role"], "target_role"),
            }
        )
    return sorted(rows, key=lambda row: row["route_id"].casefold())


def _combat_routes(model: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for family in model.get("route_families", []):
        for route in family.get("routes", []):
            result[str(route["route_id"])] = route
    return result


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


def evaluate_animation_haptic_acceptance(
    value: Mapping[str, Any],
) -> AnimationHapticAcceptanceReceipt:
    """Evaluate one reviewed, fixture-backed stack without live access or control output."""

    root = _mapping(_detached(value), _ROOT_FIELDS, "acceptance input")
    if root["schema_version"] != SCHEMA_VERSION:
        raise AnimationHapticAcceptanceError(f"schema_version must be {SCHEMA_VERSION}")
    acceptance_id = _text(root["acceptance_id"], "acceptance_id")
    bindings = _normalize_bindings(root["provider_bindings"])
    animations = _normalize_animation_routes(root["animation_routes"])
    controller = _mapping(root["controller_binding"], _CONTROLLER_FIELDS, "controller_binding")
    controller_id = _text(controller["controller_id"], "controller_id")
    runtime_type = _text(controller["runtime_type"], "runtime_type")

    try:
        stack = evaluate_compatibility_stack(root["stack_manifest"]).to_dict()
        combat = lint_combat_routes(root["combat_route_model"]).to_dict()
        audio = resolve_audio_haptic_routes_mapping(root["audio_haptic_routes"]).to_dict()
        runtime = adapt_audio_haptic_runtime(root["audio_haptic_runtime"])
    except (
        CompatibilityStackError,
        CombatRouteLintError,
        AudioHapticRouteError,
        AudioHapticRuntimeError,
        TypeError,
    ) as exc:
        raise AnimationHapticAcceptanceError(str(exc)) from exc

    gates: list[dict[str, Any]] = []
    reasons: set[str] = set()
    binding_by_id = {row["provider_id"]: row for row in bindings}
    selection_by_project = {
        row["project_id"]: row for row in stack["selected_variants"]
    }
    members = {row["project_id"] for row in stack["members"]}

    binding_errors: list[str] = []
    for binding in bindings:
        selection = selection_by_project.get(binding["project_id"])
        if (
            binding["project_id"] not in members
            or selection is None
            or selection["selection_id"] != binding["selection_id"]
            or binding["selected_member_id"] not in selection["selected_member_ids"]
        ):
            binding_errors.append(binding["provider_id"])
    stack_bound = (
        stack["family"] == "ANIMATION_AUDIO_HAPTIC"
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
        [stack["stack_id"], *binding_errors],
    )

    winners = {
        canonical_path_key(row["resource"]): row["provider_project_id"]
        for row in stack["intended_winners"]
    }
    provider_errors: list[str] = []
    for route in animations:
        binding = binding_by_id.get(route["provider_id"])
        winner = winners.get(canonical_path_key(route["adb_path"]))
        if binding is None or winner != binding["project_id"]:
            provider_errors.append(route["route_id"])
    for route in root["audio_haptic_routes"].get("routes", []):
        binding = binding_by_id.get(str(route.get("provider_id")))
        try:
            route_path = canonical_path_key(canonical_relative_path(route.get("source_path")))
        except (TypeError, ValueError):
            route_path = ""
        if binding is None or winners.get(route_path) != binding["project_id"]:
            provider_errors.append(str(route.get("route_id", "unknown")))
    if provider_errors:
        reasons.add("PROVIDER_WINNER_UNBOUND")
    _gate(
        gates,
        "provider_winner_binding",
        "PASS" if not provider_errors else "FAIL",
        "static",
        provider_errors or [stack["stack_id"]],
    )

    combat_routes = _combat_routes(root["combat_route_model"])
    animation_by_id = {row["route_id"]: row for row in animations}
    coverage_errors = sorted(
        set(combat_routes).symmetric_difference(animation_by_id), key=str.casefold
    )
    if coverage_errors:
        reasons.add("ANIMATION_ROUTE_COVERAGE_MISMATCH")
    _gate(
        gates,
        "animation_route_coverage",
        "PASS" if not coverage_errors else "FAIL",
        "static",
        coverage_errors or [combat["model_id"]],
    )

    role_errors: list[str] = []
    for route_id in sorted(set(combat_routes).intersection(animation_by_id), key=str.casefold):
        route = animation_by_id[route_id]
        combat_route = combat_routes[route_id]
        binding = binding_by_id.get(route["provider_id"])
        if (
            binding is None
            or route["source_role"] != combat_route.get("source_role")
            or route["target_role"] != combat_route.get("target_role")
            or route["source_role"] not in binding["roles"]
            or route["target_role"] not in binding["roles"]
        ):
            role_errors.append(route_id)
    if role_errors:
        reasons.add("ROLE_INCOMPATIBLE")
    _gate(
        gates,
        "role_compatibility",
        "PASS" if not role_errors else "FAIL",
        "static",
        role_errors or [combat["model_id"]],
    )

    resolution = audio.get("resolution")
    event_errors = [
        row["route_id"]
        for row in animations
        if resolution is None or row["animevent"] != resolution.get("animevent")
    ]
    if event_errors:
        reasons.add("ANIMEVENT_ROUTE_MISMATCH")
    _gate(
        gates,
        "animevent_event_routes",
        "PASS" if not event_errors else "FAIL",
        "static",
        event_errors or [str(resolution["route_id"])],
    )

    identity_match = (
        audio["snapshot_id"] == stack["identity"]["active_snapshot_id"]
        and runtime["active_snapshot_id"] == stack["identity"]["active_snapshot_id"]
        and runtime["session_id"] in stack["identity"]["runtime_session_ids"]
    )
    configuration_ok = resolution is not None and identity_match
    if not configuration_ok:
        reasons.add("CONFIGURATION_ROUTE_UNRESOLVED")
    _gate(
        gates,
        "configuration_and_identity",
        "PASS" if configuration_ok else "FAIL",
        "static",
        [audio["graph_id"], stack["identity"]["active_snapshot_id"]],
    )

    scope_ok = combat["summary"]["scope_leak_count"] == 0
    finite_ok = combat["summary"]["non_terminating_route_count"] == 0
    if not scope_ok:
        reasons.add("CROSS_SCOPE_LEAK")
    if not finite_ok:
        reasons.add("NON_FINITE_EXIT")
    _gate(gates, "scope_isolation", "PASS" if scope_ok else "FAIL", "static", [combat["model_id"]])
    _gate(gates, "finite_exit", "PASS" if finite_ok else "FAIL", "static", [combat["model_id"]])

    runtime_complete = runtime["status"] == "complete"
    controller_ok = (
        resolution is not None
        and resolution["controller_id"] == controller_id
        and runtime_type in runtime["controller_types"]
    )
    controller_status = "PASS" if controller_ok and runtime_complete else (
        "INCONCLUSIVE" if not runtime_complete else "FAIL"
    )
    if controller_status != "PASS":
        reasons.add(
            "CONTROLLER_BEHAVIOR_UNPROVEN"
            if not runtime_complete
            else "CONTROLLER_MISMATCH"
        )
    _gate(gates, "controller_behavior", controller_status, "runtime", [runtime["session_id"]])

    fallback_expected = resolution is not None and len(resolution["fallback_chain"]) > 1
    fallback_observed = any(
        row["fallback_route_id"] == (resolution or {}).get("route_id")
        for row in runtime["requests"]
    )
    fallback_ok = not fallback_expected or fallback_observed
    fallback_status = "PASS" if fallback_ok and runtime_complete else (
        "INCONCLUSIVE" if not runtime_complete else "FAIL"
    )
    if fallback_status != "PASS":
        reasons.add("FALLBACK_BEHAVIOR_UNPROVEN" if not runtime_complete else "FALLBACK_MISMATCH")
    _gate(gates, "fallback_behavior", fallback_status, "runtime", [runtime["session_id"]])

    haptics_ok = runtime["haptics_preservation"]["dualsense_behavior"] == "preserved"
    haptics_status = "PASS" if haptics_ok and runtime_complete else "INCONCLUSIVE"
    if haptics_status != "PASS":
        reasons.add("HAPTICS_PRESERVATION_UNPROVEN")
    _gate(
        gates,
        "haptics_preservation",
        haptics_status,
        "runtime",
        [runtime["haptics_preservation"]["reference"]],
    )

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
        "active_snapshot_id": stack["identity"]["active_snapshot_id"],
        "runtime_session_id": runtime["session_id"],
        "status": status,
        "evidence_layers": {"static": True, "runtime": True, "causal": False},
        "gates": gates,
        "summary": {
            "provider_binding_count": len(bindings),
            "animation_route_count": len(animations),
            "scope_leak_count": combat["summary"]["scope_leak_count"],
            "non_terminating_route_count": combat["summary"]["non_terminating_route_count"],
        },
        "animation_routes": animations,
        "audio_haptic": {
            "route_id": None if resolution is None else resolution["route_id"],
            "configuration_id": None if resolution is None else resolution["configuration_id"],
            "controller_id": None if resolution is None else resolution["controller_id"],
            "controller_type": runtime_type,
            "fallback_observed": fallback_observed,
            "haptics_behavior": runtime["haptics_preservation"]["dualsense_behavior"],
            "safety_gate": runtime["safety_gate"],
        },
        "component_receipts": {
            "combat_route_lint_sha256": sha256_json(combat),
            "audio_route_graph_sha256": sha256_json(audio),
            "audio_runtime_sha256": sha256_json(runtime),
        },
        "reason_codes": sorted(reasons),
    }
    return AnimationHapticAcceptanceReceipt(payload)


__all__ = [
    "AnimationHapticAcceptanceError",
    "AnimationHapticAcceptanceReceipt",
    "evaluate_animation_haptic_acceptance",
]
