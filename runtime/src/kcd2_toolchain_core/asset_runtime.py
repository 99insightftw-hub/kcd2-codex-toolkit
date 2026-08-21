"""Bounded observation-only visual and lighting runtime adapter."""

from __future__ import annotations

import copy
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

from .paths import canonical_relative_path


SCHEMA_VERSION = "kcd2.asset-runtime-receipt.v1"
MAX_EVENTS = 4096
MAX_RESOURCES = 4096
MAX_ENTITIES = 4096
MAX_ACTIVE_EMITTERS = 65536
MAX_PAYLOAD_BYTES = 4096
MAX_TEXT = 1024
_ROOT_FIELDS = {
    "session_id", "experiment_id", "active_snapshot_id", "adapter", "limits",
    "resources", "events",
}
_ADAPTER_FIELDS = {"adapter_id", "observation_mode", "control_output", "runtime_route"}
_ROUTE_FIELDS = {"route_id", "status", "reason"}
_LIMIT_FIELDS = {
    "maximum_events", "maximum_payload_bytes", "maximum_entities",
    "maximum_active_emitters",
}
_RESOURCE_FIELDS = {
    "resource_id", "kind", "canonical_path", "required", "fallback_resource_id",
    "resolution_status", "winner_provider_id",
}
_EVENT_FIELDS = {
    "schema_version", "session_id", "experiment_id", "domain", "event_type",
    "monotonic_ns", "source_health", "identity", "payload", "cleanup_state",
}
_EVENT_PAYLOAD_FIELDS = {
    "ENTITY_CREATED": {"archetype_resource_id"},
    "LIGHT_CREATED": {"light_resource_id", "intensity", "scale"},
    "MATERIAL_SELECTED": {"resource_id"},
    "EFFECT_SELECTED": {"resource_id"},
    "EMITTER_COUNT": {"active_emitters"},
    "PHASE_TRANSITION": {"from_resource_id", "to_resource_id"},
    "LOD_TRANSITION": {"from_resource_id", "to_resource_id"},
    "RESOURCE_RESOLVED": {"resource_id", "provider_id"},
    "FALLBACK_SELECTED": {"from_resource_id", "to_resource_id", "reason"},
}
_KINDS = {
    "model", "material", "texture", "dds_stream", "particle", "effect",
    "archetype", "light", "emitter", "phase", "lod",
}
_REASON_ORDER = (
    "UNSUPPORTED_RUNTIME_ROUTE", "EVENT_STREAM_EMPTY", "SOURCE_HEALTH_INCOMPLETE",
    "RESOURCE_RESOLUTION_INCOMPLETE", "FALLBACK_UNOBSERVED",
)


class AssetRuntimeAdapterError(ValueError):
    """The visual/lighting event stream violates the bounded adapter contract."""


def _mapping(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AssetRuntimeAdapterError(f"{name} fields do not match the contract")
    return dict(value)


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > MAX_TEXT:
        raise AssetRuntimeAdapterError(f"{name} must be non-empty bounded NUL-free text")
    return value


def _optional_text(value: Any, name: str) -> str | None:
    return None if value is None else _text(value, name)


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise AssetRuntimeAdapterError(f"{name} must be boolean")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AssetRuntimeAdapterError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _number(value: Any, name: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise AssetRuntimeAdapterError(f"{name} must be a finite non-negative number")
    if not 0 <= value <= 1_000_000:
        raise AssetRuntimeAdapterError(f"{name} exceeds its supported bound")
    return value


def _limits(value: Any) -> dict[str, int]:
    limits = _mapping(value, _LIMIT_FIELDS, "limits")
    return {
        "maximum_events": _integer(limits["maximum_events"], "maximum_events", 1, MAX_EVENTS),
        "maximum_payload_bytes": _integer(limits["maximum_payload_bytes"], "maximum_payload_bytes", 64, MAX_PAYLOAD_BYTES),
        "maximum_entities": _integer(limits["maximum_entities"], "maximum_entities", 1, MAX_ENTITIES),
        "maximum_active_emitters": _integer(limits["maximum_active_emitters"], "maximum_active_emitters", 0, MAX_ACTIVE_EMITTERS),
    }


def _route(value: Any) -> dict[str, Any]:
    route = _mapping(value, _ROUTE_FIELDS, "adapter.runtime_route")
    status = _text(route["status"], "adapter.runtime_route.status")
    if status not in {"supported", "unsupported"}:
        raise AssetRuntimeAdapterError("adapter.runtime_route.status is unsupported")
    reason = _optional_text(route["reason"], "adapter.runtime_route.reason")
    if (status == "unsupported") != (reason is not None):
        raise AssetRuntimeAdapterError("unsupported runtime route requires a reason and supported route forbids one")
    return {"route_id": _text(route["route_id"], "adapter.runtime_route.route_id"), "status": status, "reason": reason}


def _resources(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or len(value) > MAX_RESOURCES:
        raise AssetRuntimeAdapterError("resources must be a bounded sequence")
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, item in enumerate(value):
        row = _mapping(item, _RESOURCE_FIELDS, f"resources[{index}]")
        resource_id = _text(row["resource_id"], f"resources[{index}].resource_id")
        if resource_id.casefold() in ids:
            raise AssetRuntimeAdapterError("resource_id values must be case-insensitively unique")
        ids.add(resource_id.casefold())
        kind = _text(row["kind"], f"resources[{index}].kind")
        if kind not in _KINDS:
            raise AssetRuntimeAdapterError(f"resources[{index}].kind is unsupported")
        try:
            path = canonical_relative_path(row["canonical_path"])
        except (TypeError, ValueError) as exc:
            raise AssetRuntimeAdapterError(f"resources[{index}].canonical_path must be safe") from exc
        resolution_status = _text(row["resolution_status"], f"resources[{index}].resolution_status")
        if resolution_status not in {"exact_active_winner", "missing_with_fallback", "missing"}:
            raise AssetRuntimeAdapterError(f"resources[{index}].resolution_status is unsupported")
        fallback = _optional_text(row["fallback_resource_id"], f"resources[{index}].fallback_resource_id")
        winner = _optional_text(row["winner_provider_id"], f"resources[{index}].winner_provider_id")
        if resolution_status == "exact_active_winner" and winner is None:
            raise AssetRuntimeAdapterError("exact_active_winner requires winner_provider_id")
        if resolution_status != "exact_active_winner" and winner is not None:
            raise AssetRuntimeAdapterError("missing resource cannot name a winner_provider_id")
        if resolution_status == "missing_with_fallback" and fallback is None:
            raise AssetRuntimeAdapterError("missing_with_fallback requires fallback_resource_id")
        result.append({
            "resource_id": resource_id, "kind": kind, "canonical_path": path,
            "required": _boolean(row["required"], f"resources[{index}].required"),
            "fallback_resource_id": fallback, "resolution_status": resolution_status,
            "winner_provider_id": winner,
        })
    by_id = {row["resource_id"]: row for row in result}
    for row in result:
        fallback = row["fallback_resource_id"]
        if fallback is not None and (fallback not in by_id or by_id[fallback]["kind"] != row["kind"] or by_id[fallback]["resolution_status"] != "exact_active_winner"):
            raise AssetRuntimeAdapterError("fallback resource is missing, wrong-kind, or lacks an exact winner")
    return sorted(result, key=lambda row: row["resource_id"].casefold())


def _event(value: Any, index: int, session_id: str, experiment_id: str, limits: Mapping[str, int]) -> dict[str, Any]:
    event = _mapping(value, _EVENT_FIELDS, f"events[{index}]")
    if event["schema_version"] != "kcd2.runtime-domain-event.v1" or event["domain"] != "VISUAL_LIGHTING":
        raise AssetRuntimeAdapterError(f"events[{index}] has an unsupported schema or domain")
    if event["session_id"] != session_id or event["experiment_id"] != experiment_id:
        raise AssetRuntimeAdapterError(f"events[{index}] session or experiment identity differs")
    event_type = event["event_type"]
    if event_type not in _EVENT_PAYLOAD_FIELDS:
        raise AssetRuntimeAdapterError(f"events[{index}].event_type is unsupported")
    identity_fields = {"entity_id", "light_id"} if event_type == "LIGHT_CREATED" else {"entity_id"}
    identity = _mapping(event["identity"], identity_fields, f"events[{index}].identity")
    checked_identity = {key: _text(identity[key], f"events[{index}].identity.{key}") for key in sorted(identity)}
    payload = _mapping(event["payload"], _EVENT_PAYLOAD_FIELDS[event_type], f"events[{index}].payload")
    try:
        size = len(json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")).encode())
    except (TypeError, ValueError) as exc:
        raise AssetRuntimeAdapterError(f"events[{index}].payload must be finite JSON") from exc
    if size > limits["maximum_payload_bytes"]:
        raise AssetRuntimeAdapterError(f"events[{index}].payload exceeds maximum_payload_bytes")
    checked_payload = copy.deepcopy(payload)
    if event_type == "LIGHT_CREATED":
        checked_payload["intensity"] = _number(payload["intensity"], "intensity")
        checked_payload["scale"] = _number(payload["scale"], "scale")
    elif event_type == "EMITTER_COUNT":
        checked_payload["active_emitters"] = _integer(
            payload["active_emitters"], "active_emitters against maximum_active_emitters", 0,
            limits["maximum_active_emitters"],
        )
    else:
        for key, item in payload.items():
            checked_payload[key] = _optional_text(item, f"events[{index}].payload.{key}") if key == "from_resource_id" else _text(item, f"events[{index}].payload.{key}")
    health = event["source_health"]
    if health not in {"HEALTHY", "PARTIAL", "DROPPED_EVENTS", "TRUNCATED", "UNAVAILABLE"}:
        raise AssetRuntimeAdapterError(f"events[{index}].source_health is unsupported")
    if event["cleanup_state"] is not None:
        _text(event["cleanup_state"], f"events[{index}].cleanup_state")
    return {"event_type": event_type, "monotonic_ns": _integer(event["monotonic_ns"], "monotonic_ns", 0, 2**63 - 1), "source_health": health, "identity": checked_identity, "payload": checked_payload}


def adapt_visual_lighting_runtime(value: Mapping[str, Any]) -> dict[str, Any]:
    """Correlate a passive VISUAL_LIGHTING stream without controlling the engine."""

    root = _mapping(value, _ROOT_FIELDS, "visual lighting runtime input")
    session_id = _text(root["session_id"], "session_id")
    experiment_id = _text(root["experiment_id"], "experiment_id")
    snapshot_id = _text(root["active_snapshot_id"], "active_snapshot_id")
    adapter = _mapping(root["adapter"], _ADAPTER_FIELDS, "adapter")
    adapter_id = _text(adapter["adapter_id"], "adapter.adapter_id")
    if adapter["observation_mode"] != "existing_event_stream_only" or _boolean(adapter["control_output"], "adapter.control_output"):
        raise AssetRuntimeAdapterError("adapter must be passive existing_event_stream_only with no control output")
    route = _route(adapter["runtime_route"])
    limits = _limits(root["limits"])
    resources = _resources(root["resources"])
    resource_by_id = {row["resource_id"]: row for row in resources}
    raw_events = root["events"]
    if isinstance(raw_events, (str, bytes)) or not isinstance(raw_events, Sequence):
        raise AssetRuntimeAdapterError("events must be a sequence")
    if len(raw_events) > limits["maximum_events"]:
        raise AssetRuntimeAdapterError("events violates maximum_events")
    if route["status"] == "supported" and not raw_events:
        events: list[dict[str, Any]] = []
    elif route["status"] == "unsupported" and raw_events:
        raise AssetRuntimeAdapterError("unsupported runtime route cannot carry runtime events")
    else:
        events = [_event(row, index, session_id, experiment_id, limits) for index, row in enumerate(raw_events)]
    if [row["monotonic_ns"] for row in events] != sorted(row["monotonic_ns"] for row in events):
        raise AssetRuntimeAdapterError("event monotonic timestamps must be nondecreasing")

    entities: dict[str, dict[str, Any]] = {}
    lights: dict[str, dict[str, Any]] = {}
    phase_transitions: list[dict[str, Any]] = []
    lod_transitions: list[dict[str, Any]] = []
    fallbacks: list[dict[str, Any]] = []
    resolutions: list[dict[str, Any]] = []
    emitter_samples: list[int] = []
    source_incomplete = False
    referenced: set[str] = set()

    def require_resource(resource_id: str, kind: str) -> dict[str, Any]:
        resource = resource_by_id.get(resource_id)
        if resource is None or resource["kind"] != kind:
            raise AssetRuntimeAdapterError(f"event references unknown or wrong-kind {kind} resource")
        return resource

    for event in events:
        source_incomplete |= event["source_health"] != "HEALTHY"
        event_type = event["event_type"]
        entity_id = event["identity"]["entity_id"]
        payload = event["payload"]
        if event_type == "ENTITY_CREATED":
            if entity_id in entities:
                raise AssetRuntimeAdapterError("ENTITY_CREATED identity is duplicated")
            if len(entities) == limits["maximum_entities"]:
                raise AssetRuntimeAdapterError("maximum_entities would be exceeded")
            require_resource(payload["archetype_resource_id"], "archetype")
            referenced.add(payload["archetype_resource_id"])
            entities[entity_id] = {"entity_id": entity_id, "archetype_resource_id": payload["archetype_resource_id"], "selected_material_id": None, "selected_effect_id": None, "active_emitters": None}
            continue
        if entity_id not in entities:
            raise AssetRuntimeAdapterError(f"{event_type} requires a previously created entity")
        entity = entities[entity_id]
        if event_type == "LIGHT_CREATED":
            require_resource(payload["light_resource_id"], "light")
            referenced.add(payload["light_resource_id"])
            light_id = event["identity"]["light_id"]
            if light_id in lights:
                raise AssetRuntimeAdapterError("LIGHT_CREATED identity is duplicated")
            lights[light_id] = {"light_id": light_id, "entity_id": entity_id, "light_resource_id": payload["light_resource_id"], "intensity": payload["intensity"], "scale": payload["scale"]}
        elif event_type in {"MATERIAL_SELECTED", "EFFECT_SELECTED"}:
            kind = "material" if event_type == "MATERIAL_SELECTED" else "effect"
            require_resource(payload["resource_id"], kind)
            referenced.add(payload["resource_id"])
            entity["selected_material_id" if kind == "material" else "selected_effect_id"] = payload["resource_id"]
        elif event_type == "EMITTER_COUNT":
            emitter_samples.append(payload["active_emitters"])
            entity["active_emitters"] = payload["active_emitters"]
        elif event_type in {"PHASE_TRANSITION", "LOD_TRANSITION"}:
            kind = "phase" if event_type == "PHASE_TRANSITION" else "lod"
            before = payload["from_resource_id"]
            if before is not None:
                require_resource(before, kind)
                referenced.add(before)
            require_resource(payload["to_resource_id"], kind)
            referenced.add(payload["to_resource_id"])
            row = {"entity_id": entity_id, "from_resource_id": before, "to_resource_id": payload["to_resource_id"], "monotonic_ns": event["monotonic_ns"]}
            (phase_transitions if kind == "phase" else lod_transitions).append(row)
        elif event_type == "RESOURCE_RESOLVED":
            resource = resource_by_id.get(payload["resource_id"])
            if resource is None or resource["resolution_status"] != "exact_active_winner" or resource["winner_provider_id"] != payload["provider_id"]:
                raise AssetRuntimeAdapterError("RESOURCE_RESOLVED does not match the declared exact winner")
            resolutions.append({"entity_id": entity_id, "resource_id": payload["resource_id"], "canonical_path": resource["canonical_path"], "provider_id": payload["provider_id"]})
        elif event_type == "FALLBACK_SELECTED":
            source = resource_by_id.get(payload["from_resource_id"])
            target = resource_by_id.get(payload["to_resource_id"])
            if source is None or target is None or source["fallback_resource_id"] != target["resource_id"] or target["resolution_status"] != "exact_active_winner":
                raise AssetRuntimeAdapterError("FALLBACK_SELECTED does not match the declared fallback")
            fallbacks.append({"entity_id": entity_id, "from_resource_id": source["resource_id"], "to_resource_id": target["resource_id"], "reason": payload["reason"]})

    resolved_ids = {row["resource_id"] for row in resolutions}
    resolution_incomplete = bool(referenced - resolved_ids)
    missing = []
    fallback_sources = {row["from_resource_id"] for row in fallbacks}
    fallback_unobserved = False
    for resource in resources:
        if resource["required"] and resource["resolution_status"] != "exact_active_winner":
            observed = resource["resource_id"] in fallback_sources
            fallback_unobserved |= resource["resolution_status"] == "missing_with_fallback" and not observed
            missing.append({"resource_id": resource["resource_id"], "kind": resource["kind"], "canonical_path": resource["canonical_path"], "fallback_resource_id": resource["fallback_resource_id"], "fallback_observed": observed})

    reason_flags = {
        "UNSUPPORTED_RUNTIME_ROUTE": route["status"] == "unsupported",
        "EVENT_STREAM_EMPTY": route["status"] == "supported" and not events,
        "SOURCE_HEALTH_INCOMPLETE": source_incomplete,
        "RESOURCE_RESOLUTION_INCOMPLETE": resolution_incomplete,
        "FALLBACK_UNOBSERVED": fallback_unobserved,
    }
    reasons = [reason for reason in _REASON_ORDER if reason_flags[reason]]
    covered = not reasons
    claims: list[str] = []
    event_types = {event["event_type"] for event in events}
    if "ENTITY_CREATED" in event_types:
        claims.append("entity_creation_observed")
    if event_types & {"MATERIAL_SELECTED", "EFFECT_SELECTED"}:
        claims.append("visual_selection_observed")
    if "LIGHT_CREATED" in event_types:
        claims.append("light_parameters_observed")
    if event_types & {"PHASE_TRANSITION", "LOD_TRANSITION"}:
        claims.append("phase_lod_transitions_observed")
    if resolutions:
        claims.append("resource_resolution_observed")
    if fallbacks:
        claims.append("resource_fallback_observed")
    if covered and emitter_samples:
        claims.append("active_emitter_bound_measured")
    if covered:
        claims.append("no_other_missing_resources_in_covered_scope")
    return {
        "schema_version": SCHEMA_VERSION, "session_id": session_id,
        "experiment_id": experiment_id, "active_snapshot_id": snapshot_id,
        "adapter_id": adapter_id, "status": "complete" if covered else "capture_inconclusive",
        "evidence_layer": "runtime", "runtime_route": route, "event_count": len(events),
        "resources": resources,
        "missing_resources": missing,
        "entities": sorted(entities.values(), key=lambda row: row["entity_id"].casefold()),
        "lights": sorted(lights.values(), key=lambda row: row["light_id"].casefold()),
        "resolutions": sorted(resolutions, key=lambda row: (row["resource_id"].casefold(), row["entity_id"].casefold())),
        "fallbacks": sorted(fallbacks, key=lambda row: row["from_resource_id"].casefold()),
        "phase_transitions": phase_transitions, "lod_transitions": lod_transitions,
        "emitters": {"status": "measured" if covered and emitter_samples else "unresolved", "peak_active": max(emitter_samples) if covered and emitter_samples else None, "final_active": emitter_samples[-1] if covered and emitter_samples else None},
        "safety_gate": {"passive": True, "no_control_output": True},
        "limits": limits, "reason_codes": reasons, "permitted_claims": claims,
    }


__all__ = ["AssetRuntimeAdapterError", "adapt_visual_lighting_runtime"]
