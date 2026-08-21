"""Deterministic static audio/animevent/haptic route resolution.

The provider models declared relationships only.  It deliberately preserves the
action input path as context and never turns static route discovery into runtime
proof.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .hashing import sha256_json
from .paths import canonical_relative_path


_MAX_TEXT = 2048
_MAX_ROUTES = 4096
_MAX_COMPONENTS = 1024
_ROOT_FIELDS = {
    "snapshot_id",
    "input_path",
    "context",
    "configurations",
    "controllers",
    "providers",
    "routes",
}
_CONTEXT_FIELDS = {"animevent", "language", "mount", "controller_id"}
_CONFIG_FIELDS = {"configuration_id", "state", "source_ref"}
_CONTROLLER_FIELDS = {"controller_id", "available", "source_ref"}
_PROVIDER_FIELDS = {"provider_id", "state", "priority", "source_ref"}
_ROUTE_FIELDS = {
    "route_id",
    "source_path",
    "animevent",
    "audio_trigger",
    "haptic_route",
    "language",
    "mount",
    "configuration_id",
    "controller_id",
    "provider_id",
    "fallback_route_id",
    "source_ref",
}


class AudioHapticRouteError(ValueError):
    """Static route inputs violate the exact, bounded provider contract."""


def _text(value: object, field: str, *, wildcard: bool = False) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
        or (value == "*" and not wildcard)
    ):
        qualifier = " or '*'" if wildcard else ""
        raise AudioHapticRouteError(
            f"{field} must be a non-empty NUL-free string{qualifier} of at most "
            f"{_MAX_TEXT} characters"
        )
    return value


def _mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AudioHapticRouteError(f"{name} fields do not match the contract")
    return value


def _array(value: object, name: str, maximum: int, *, nonempty: bool = True) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AudioHapticRouteError(f"{name} must be an array")
    if len(value) > maximum or (nonempty and not value):
        raise AudioHapticRouteError(f"{name} violates its {maximum}-item hard bound")
    return value


def _unique(rows: Sequence[Mapping[str, object]], key: str, name: str) -> None:
    values = [str(row[key]).casefold() for row in rows]
    if len(values) != len(set(values)):
        raise AudioHapticRouteError(f"{name} values must be case-insensitively unique")


@dataclass(frozen=True, slots=True)
class AudioHapticRouteGraph:
    """Immutable schema-ready static route graph and contextual resolution."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(json.loads(self.to_json()))

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _route_key(route: Mapping[str, object]) -> tuple[str, str, str, str]:
    return (
        str(route["animevent"]).casefold(),
        str(route["language"]).casefold(),
        str(route["mount"]).casefold(),
        str(route["controller_id"]).casefold(),
    )


def _matches(route: Mapping[str, object], context: Mapping[str, object]) -> bool:
    return (
        str(route["animevent"]).casefold() == str(context["animevent"]).casefold()
        and str(route["controller_id"]).casefold()
        == str(context["controller_id"]).casefold()
        and all(
            str(route[field]) == "*"
            or str(route[field]).casefold() == str(context[field]).casefold()
            for field in ("language", "mount")
        )
    )


def _check_fallbacks(routes: Mapping[str, Mapping[str, object]]) -> None:
    for start in routes:
        seen: set[str] = set()
        current: str | None = start
        while current is not None:
            key = current.casefold()
            if key in seen:
                raise AudioHapticRouteError(f"fallback cycle detected from {start}")
            seen.add(key)
            target = routes[current]["fallback_route_id"]
            current = None if target is None else str(target)


def resolve_audio_haptic_routes_mapping(value: Mapping[str, object]) -> AudioHapticRouteGraph:
    """Validate declarations, construct a route graph, and resolve one static context."""

    root = _mapping(value, _ROOT_FIELDS, "audio route input")
    snapshot_id = _text(root["snapshot_id"], "snapshot_id")
    try:
        input_path = canonical_relative_path(_text(root["input_path"], "input_path"))
    except (TypeError, ValueError) as exc:
        raise AudioHapticRouteError("input_path must be a canonical relative path") from exc
    context = _mapping(root["context"], _CONTEXT_FIELDS, "context")
    checked_context = {
        field: _text(context[field], f"context.{field}") for field in sorted(_CONTEXT_FIELDS)
    }

    configurations = [
        _mapping(item, _CONFIG_FIELDS, "configuration")
        for item in _array(root["configurations"], "configurations", _MAX_COMPONENTS)
    ]
    controllers = [
        _mapping(item, _CONTROLLER_FIELDS, "controller")
        for item in _array(root["controllers"], "controllers", _MAX_COMPONENTS)
    ]
    providers = [
        _mapping(item, _PROVIDER_FIELDS, "provider")
        for item in _array(root["providers"], "providers", _MAX_COMPONENTS)
    ]
    raw_routes = [
        _mapping(item, _ROUTE_FIELDS, "route")
        for item in _array(root["routes"], "routes", _MAX_ROUTES)
    ]

    checked_configurations: list[dict[str, object]] = []
    for row in configurations:
        state = row["state"]
        if state not in {"enabled", "disabled", "unknown"}:
            raise AudioHapticRouteError("configuration.state is not supported")
        checked_configurations.append(
            {
                "configuration_id": _text(row["configuration_id"], "configuration_id"),
                "state": state,
                "source_ref": _text(row["source_ref"], "configuration.source_ref"),
            }
        )
    checked_controllers: list[dict[str, object]] = []
    for row in controllers:
        if not isinstance(row["available"], bool):
            raise AudioHapticRouteError("controller.available must be a boolean")
        checked_controllers.append(
            {
                "controller_id": _text(row["controller_id"], "controller_id"),
                "available": row["available"],
                "source_ref": _text(row["source_ref"], "controller.source_ref"),
            }
        )
    checked_providers: list[dict[str, object]] = []
    for row in providers:
        if row["state"] not in {"loaded", "present", "inactive", "unknown"}:
            raise AudioHapticRouteError("provider.state is not supported")
        priority = row["priority"]
        if (
            isinstance(priority, bool)
            or not isinstance(priority, int)
            or not 0 <= priority <= 65535
        ):
            raise AudioHapticRouteError("provider.priority must be an integer from 0 through 65535")
        checked_providers.append(
            {
                "provider_id": _text(row["provider_id"], "provider_id"),
                "state": row["state"],
                "priority": priority,
                "source_ref": _text(row["source_ref"], "provider.source_ref"),
            }
        )
    _unique(checked_configurations, "configuration_id", "configuration_id")
    _unique(checked_controllers, "controller_id", "controller_id")
    _unique(checked_providers, "provider_id", "provider_id")
    configuration_by_id = {str(row["configuration_id"]): row for row in checked_configurations}
    controller_by_id = {str(row["controller_id"]): row for row in checked_controllers}
    provider_by_id = {str(row["provider_id"]): row for row in checked_providers}

    checked_routes: list[dict[str, object]] = []
    for row in raw_routes:
        try:
            source_path = canonical_relative_path(_text(row["source_path"], "route.source_path"))
        except (TypeError, ValueError) as exc:
            raise AudioHapticRouteError(
                "route.source_path must be a canonical relative path"
            ) from exc
        fallback = row["fallback_route_id"]
        checked_routes.append(
            {
                "route_id": _text(row["route_id"], "route_id"),
                "source_path": source_path,
                "animevent": _text(row["animevent"], "route.animevent"),
                "audio_trigger": _text(row["audio_trigger"], "route.audio_trigger"),
                "haptic_route": _text(row["haptic_route"], "route.haptic_route"),
                "language": _text(row["language"], "route.language", wildcard=True),
                "mount": _text(row["mount"], "route.mount", wildcard=True),
                "configuration_id": _text(row["configuration_id"], "route.configuration_id"),
                "controller_id": _text(row["controller_id"], "route.controller_id"),
                "provider_id": _text(row["provider_id"], "route.provider_id"),
                "fallback_route_id": None
                if fallback is None
                else _text(fallback, "route.fallback_route_id"),
                "source_ref": _text(row["source_ref"], "route.source_ref"),
            }
        )
    _unique(checked_routes, "route_id", "route_id")
    route_by_id = {str(row["route_id"]): row for row in checked_routes}
    for route in checked_routes:
        if route["configuration_id"] not in configuration_by_id:
            raise AudioHapticRouteError(
                f"route {route['route_id']} references an unknown configuration"
            )
        if route["controller_id"] not in controller_by_id:
            raise AudioHapticRouteError(
                f"route {route['route_id']} references an unknown controller"
            )
        if route["provider_id"] not in provider_by_id:
            raise AudioHapticRouteError(f"route {route['route_id']} references an unknown provider")
        fallback = route["fallback_route_id"]
        if fallback is not None and fallback not in route_by_id:
            raise AudioHapticRouteError(f"route {route['route_id']} references an unknown fallback")
    _check_fallbacks(route_by_id)

    duplicate_groups: dict[tuple[str, str, str, str], list[str]] = {}
    for route in checked_routes:
        duplicate_groups.setdefault(_route_key(route), []).append(str(route["route_id"]))
    diagnostics = [
        {
            "code": "DUPLICATE_ROUTE",
            "route_ids": sorted(ids, key=str.casefold),
            "selector": {
                "animevent": key[0],
                "language": key[1],
                "mount": key[2],
                "controller_id": key[3],
            },
        }
        for key, ids in sorted(duplicate_groups.items())
        if len(ids) > 1
    ]

    nodes: list[dict[str, object]] = []
    edges: list[dict[str, str]] = []
    for row in checked_configurations:
        nodes.append({"node_id": row["configuration_id"], "kind": "configuration", **row})
    for row in checked_controllers:
        nodes.append({"node_id": row["controller_id"], "kind": "controller", **row})
    for row in checked_providers:
        nodes.append({"node_id": row["provider_id"], "kind": "provider", **row})
    for route in checked_routes:
        route_id = str(route["route_id"])
        event_id = f"animevent:{route['animevent']}"
        audio_id = f"audio-trigger:{route['audio_trigger']}"
        haptic_id = f"haptic-route:{route['haptic_route']}"
        nodes.extend(
            [
                {"node_id": route_id, "kind": "route", **route},
                {"node_id": event_id, "kind": "animevent", "name": route["animevent"]},
                {"node_id": audio_id, "kind": "audio_trigger", "name": route["audio_trigger"]},
                {"node_id": haptic_id, "kind": "haptic_route", "name": route["haptic_route"]},
            ]
        )
        edges.extend(
            [
                {"from": event_id, "relationship": "animevent_triggers_audio", "to": audio_id},
                {"from": event_id, "relationship": "animevent_routes_haptic", "to": haptic_id},
                {
                    "from": route_id,
                    "relationship": "requires_configuration",
                    "to": str(route["configuration_id"]),
                },
                {
                    "from": route_id,
                    "relationship": "targets_controller",
                    "to": str(route["controller_id"]),
                },
                {"from": route_id, "relationship": "provided_by", "to": str(route["provider_id"])},
            ]
        )
        if route["fallback_route_id"] is not None:
            edges.append(
                {
                    "from": route_id,
                    "relationship": "falls_back_to",
                    "to": str(route["fallback_route_id"]),
                }
            )
    # Shared event/trigger/haptic identities are intentionally folded into one graph node.
    node_by_id = {str(node["node_id"]): node for node in nodes}
    nodes = sorted(node_by_id.values(), key=lambda item: (str(item["kind"]), str(item["node_id"])))
    edges.sort(key=lambda item: (item["from"], item["relationship"], item["to"]))

    resolution: dict[str, object] | None = None
    status = "duplicate_routes" if diagnostics else "unresolved"
    if not diagnostics:
        matching = [route for route in checked_routes if _matches(route, checked_context)]
        matching.sort(
            key=lambda route: (
                -sum(route[field] != "*" for field in ("language", "mount")),
                -int(provider_by_id[str(route["provider_id"])]["priority"]),
                str(route["route_id"]).casefold(),
            )
        )
        for primary in matching:
            chain: list[str] = []
            current: dict[str, object] | None = primary
            while current is not None:
                chain.append(str(current["route_id"]))
                usable = (
                    configuration_by_id[str(current["configuration_id"])]["state"] == "enabled"
                    and controller_by_id[str(current["controller_id"])]["available"] is True
                    and provider_by_id[str(current["provider_id"])]["state"] == "loaded"
                    and _matches(current, checked_context)
                )
                if usable:
                    resolution = {
                        "route_id": current["route_id"],
                        "provider_id": current["provider_id"],
                        "configuration_id": current["configuration_id"],
                        "controller_id": current["controller_id"],
                        "animevent": current["animevent"],
                        "audio_trigger": current["audio_trigger"],
                        "haptic_route": current["haptic_route"],
                        "language": checked_context["language"],
                        "mount": checked_context["mount"],
                        "input_path": input_path,
                        "fallback_chain": chain,
                        "evidence_layer": "static",
                        "runtime_state": "unknown",
                    }
                    status = "static_route_resolved"
                    break
                fallback = current["fallback_route_id"]
                current = None if fallback is None else route_by_id[str(fallback)]
            if resolution is not None:
                break

    payload: dict[str, Any] = {
        "schema_version": "kcd2.audio-haptic-route-graph.v1",
        "snapshot_id": snapshot_id,
        "input_path": input_path,
        "context": checked_context,
        "status": status,
        "evidence_layer": "static",
        "runtime_state": "unknown",
        "runtime_proof": False,
        "nodes": nodes,
        "edges": edges,
        "diagnostics": diagnostics,
        "resolution": resolution,
    }
    payload["graph_id"] = f"audio-route-graph:sha256:{sha256_json(payload)}"
    return AudioHapticRouteGraph(payload)


__all__ = [
    "AudioHapticRouteError",
    "AudioHapticRouteGraph",
    "resolve_audio_haptic_routes_mapping",
]
