"""Bounded COMPAT-003 AI, quest, and world stack acceptance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_index_adapter.ai_quest_runtime import AIQuestRuntimeError, adapt_ai_quest_runtime
from kcd2_index_adapter.quest_topology import (
    ExactTopologySource,
    ProviderWinnerEvidence,
    TopologyAcquisitionError,
    acquire_quest_xgen_topology,
)
from kcd2_index_adapter.world_behavior import (
    ExactWorldBehaviorSource,
    WorldBehaviorResolutionError,
    resolve_world_behavior_graph,
)

from .compatibility_stacks import CompatibilityStackError, evaluate_compatibility_stack
from .hashing import sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.ai-world-stack-acceptance.v1"
_MAX_TEXT = 8192
_MAX_SOURCES = 256
_MAX_PATHS = 256
_MAX_PATH_LENGTH = 32
_REQUIRED_CAPABILITIES = {
    "quest_path",
    "dialog",
    "roles_factions",
    "smart_object",
    "scheduler",
    "spawn",
    "reputation",
}
_ROOT_FIELDS = {
    "schema_version",
    "acceptance_id",
    "stack_manifest",
    "provider_bindings",
    "shared_paths",
    "persistence_bindings",
    "quest_query_id",
    "quest_graph_id",
    "quest_sources",
    "provider_winners",
    "world_graph_id",
    "world_sources",
    "runtime_binding",
    "runtime_capture",
}


class AIWorldAcceptanceError(ValueError):
    """An AI/world acceptance fixture is malformed or exceeds a hard bound."""


@dataclass(frozen=True, slots=True)
class AIWorldAcceptanceReceipt:
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
        raise AIWorldAcceptanceError(f"{name} fields do not match the contract")
    return value


def _sequence(
    value: object,
    name: str,
    maximum: int,
    *,
    minimum: int = 1,
) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AIWorldAcceptanceError(f"{name} must be an array")
    if not minimum <= len(value) <= maximum:
        raise AIWorldAcceptanceError(f"{name} violates its hard bound")
    return value


def _text(value: object, name: str, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise AIWorldAcceptanceError(f"{name} must be bounded non-empty text")
    return value


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise AIWorldAcceptanceError("input must contain JSON values only") from exc


def _content_bytes(value: object, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping):
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise AIWorldAcceptanceError(f"{name} is not canonical JSON") from exc
    raise AIWorldAcceptanceError(f"{name} must be UTF-8 text or an object")


def _quest_sources(value: object) -> tuple[ExactTopologySource, ...]:
    fields = {
        "provider_id",
        "provider_kind",
        "source_kind",
        "source_path",
        "canonical_path",
        "content",
        "expected_sha256",
        "captured_at",
        "topology_complete",
    }
    result: list[ExactTopologySource] = []
    for index, raw in enumerate(_sequence(value, "quest_sources", _MAX_SOURCES)):
        row = _mapping(raw, fields, f"quest_sources[{index}]")
        content = _content_bytes(row["content"], "quest source content")
        result.append(
            ExactTopologySource(
                provider_id=row["provider_id"],
                provider_kind=row["provider_kind"],
                source_kind=row["source_kind"],
                source_path=row["source_path"],
                canonical_path=row["canonical_path"],
                content=content,
                expected_sha256=row["expected_sha256"],
                captured_at=row["captured_at"],
                topology_complete=row["topology_complete"],
            )
        )
    return tuple(sorted(result, key=lambda row: (row.canonical_path.casefold(), row.provider_id)))


def _provider_winners(value: object) -> tuple[ProviderWinnerEvidence, ...]:
    fields = {
        "canonical_path",
        "coverage_id",
        "coverage_status",
        "snapshot_id",
        "snapshot_sha256",
        "fresh",
        "conclusion",
        "winner_provider_id",
        "exact_locator",
    }
    result: list[ProviderWinnerEvidence] = []
    for index, raw in enumerate(_sequence(value, "provider_winners", _MAX_SOURCES)):
        row = _mapping(raw, fields, f"provider_winners[{index}]")
        result.append(ProviderWinnerEvidence(**row))
    return tuple(sorted(result, key=lambda row: row.canonical_path.casefold()))


def _world_sources(value: object) -> tuple[ExactWorldBehaviorSource, ...]:
    fields = {
        "source_id",
        "provider_id",
        "source_path",
        "canonical_path",
        "content",
        "expected_sha256",
        "captured_at",
        "coverage_complete",
    }
    result: list[ExactWorldBehaviorSource] = []
    for index, raw in enumerate(_sequence(value, "world_sources", _MAX_SOURCES)):
        row = _mapping(raw, fields, f"world_sources[{index}]")
        content = _content_bytes(row["content"], "world source content")
        result.append(
            ExactWorldBehaviorSource(
                source_id=row["source_id"],
                provider_id=row["provider_id"],
                source_path=row["source_path"],
                canonical_path=row["canonical_path"],
                content=content,
                expected_sha256=row["expected_sha256"],
                captured_at=row["captured_at"],
                coverage_complete=row["coverage_complete"],
            )
        )
    return tuple(sorted(result, key=lambda row: (row.canonical_path.casefold(), row.provider_id)))


def _bindings(value: object) -> list[dict[str, str]]:
    fields = {"provider_id", "project_id", "selection_id", "selected_member_id"}
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(value, "provider_bindings", _MAX_SOURCES)):
        row = _mapping(raw, fields, f"provider_bindings[{index}]")
        normalized = {field: _text(row[field], field, 256) for field in fields}
        provider_key = normalized["provider_id"].casefold()
        if provider_key in seen:
            raise AIWorldAcceptanceError("provider bindings must be unique")
        seen.add(provider_key)
        result.append(normalized)
    return sorted(result, key=lambda row: row["provider_id"].casefold())


def _shared_paths(value: object) -> list[dict[str, Any]]:
    fields = {"path_id", "graph", "capability", "identity_keys", "edge_kinds"}
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    capabilities: set[str] = set()
    for index, raw in enumerate(_sequence(value, "shared_paths", _MAX_PATHS)):
        row = _mapping(raw, fields, f"shared_paths[{index}]")
        path_id = _text(row["path_id"], "path_id", 256)
        if path_id.casefold() in seen:
            raise AIWorldAcceptanceError("shared path identifiers must be unique")
        seen.add(path_id.casefold())
        graph = _text(row["graph"], "graph", 16)
        capability = _text(row["capability"], "capability", 64)
        identities = [
            _text(item, "identity_key", 1024)
            for item in _sequence(
                row["identity_keys"],
                "identity_keys",
                _MAX_PATH_LENGTH,
                minimum=2,
            )
        ]
        edge_kinds = [
            _text(item, "edge_kind", 256)
            for item in _sequence(row["edge_kinds"], "edge_kinds", _MAX_PATH_LENGTH)
        ]
        if graph not in {"quest", "world"} or len(edge_kinds) != len(identities) - 1:
            raise AIWorldAcceptanceError("shared path topology is invalid")
        capabilities.add(capability)
        result.append(
            {
                "path_id": path_id,
                "graph": graph,
                "capability": capability,
                "identity_keys": identities,
                "edge_kinds": edge_kinds,
            }
        )
    if capabilities != _REQUIRED_CAPABILITIES:
        raise AIWorldAcceptanceError("shared paths do not cover every required capability")
    return sorted(result, key=lambda row: row["path_id"].casefold())


def _audit_complete(audit: Mapping[str, Any]) -> bool:
    coverage = audit.get("coverage", [])
    return bool(coverage) and audit.get("verdict") == "valid" and all(
        row.get("status") == "complete" and row.get("absence_claim_allowed") is True
        for row in coverage
    )


def _path_resolves(audit: Mapping[str, Any], path: Mapping[str, Any]) -> bool:
    nodes = {row["identity_key"]: row["node_id"] for row in audit["nodes"]}
    identities = path["identity_keys"]
    if any(identity not in nodes for identity in identities):
        return False
    edges = {
        (row["from_node_id"], row["to_node_id"], row["normalized_kind"])
        for row in audit["edges"]
        if row["support_state"] == "supported"
    }
    return all(
        (nodes[left], nodes[right], kind) in edges
        for left, right, kind in zip(
            identities[:-1],
            identities[1:],
            path["edge_kinds"],
            strict=True,
        )
    )


def _gate(
    gates: list[dict[str, Any]],
    gate_id: str,
    status: str,
    layer: str,
    evidence_refs: Sequence[str],
) -> None:
    gates.append(
        {
            "gate_id": gate_id,
            "status": status,
            "evidence_layer": layer,
            "evidence_refs": sorted(set(evidence_refs), key=str.casefold),
        }
    )


def evaluate_ai_world_acceptance(value: Mapping[str, Any]) -> AIWorldAcceptanceReceipt:
    """Evaluate a self-contained non-live AI/world compatibility fixture."""

    root = _mapping(_detached(value), _ROOT_FIELDS, "acceptance input")
    if root["schema_version"] != SCHEMA_VERSION:
        raise AIWorldAcceptanceError(f"schema_version must be {SCHEMA_VERSION}")
    acceptance_id = _text(root["acceptance_id"], "acceptance_id", 256)
    bindings = _bindings(root["provider_bindings"])
    paths = _shared_paths(root["shared_paths"])
    quest_sources = _quest_sources(root["quest_sources"])
    winners = _provider_winners(root["provider_winners"])
    world_sources = _world_sources(root["world_sources"])
    try:
        stack = evaluate_compatibility_stack(root["stack_manifest"]).to_dict()
        topology = acquire_quest_xgen_topology(
            query_id=_text(root["quest_query_id"], "quest_query_id"),
            graph_id=_text(root["quest_graph_id"], "quest_graph_id"),
            sources=quest_sources,
            provider_winners=winners,
        ).to_dict()
        world = resolve_world_behavior_graph(
            graph_id=_text(root["world_graph_id"], "world_graph_id"),
            sources=world_sources,
        ).to_dict()
        runtime = adapt_ai_quest_runtime(root["runtime_capture"])
    except (
        AIQuestRuntimeError,
        CompatibilityStackError,
        TopologyAcquisitionError,
        WorldBehaviorResolutionError,
        TypeError,
    ) as exc:
        raise AIWorldAcceptanceError(str(exc)) from exc

    gates: list[dict[str, Any]] = []
    reasons: set[str] = set()
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
    stack_exact = stack["family"] == "AI_WORLD" and not binding_errors
    stack_status = "PASS" if stack_exact and stack["result"] == "PASS" else (
        "INCONCLUSIVE" if stack_exact and stack["result"] == "INCONCLUSIVE" else "FAIL"
    )
    if stack_status != "PASS":
        reasons.add(
            "STACK_COVERAGE_INCONCLUSIVE"
            if stack_status == "INCONCLUSIVE"
            else "SELECTED_VARIANT_UNBOUND"
        )
    _gate(
        gates,
        "selected_variant_binding",
        stack_status,
        "static",
        binding_errors or [stack["stack_id"]],
    )

    binding_by_provider = {row["provider_id"]: row for row in bindings}
    intended = {
        canonical_path_key(row["resource"]): row["provider_project_id"]
        for row in stack["intended_winners"]
    }
    winner_errors: list[str] = []
    for join in topology["provider_join"]:
        binding = binding_by_provider.get(join["effective_winner_provider_id"])
        if (
            join["effective_conclusion"] != "winner"
            or binding is None
            or intended.get(canonical_path_key(join["canonical_path"]))
            != binding["project_id"]
        ):
            winner_errors.append(join["canonical_path"])
    for source in world_sources:
        binding = binding_by_provider.get(source.provider_id)
        if (
            binding is None
            or intended.get(canonical_path_key(source.canonical_path)) != binding["project_id"]
        ):
            winner_errors.append(source.canonical_path)
    winner_status = "PASS" if not winner_errors else "FAIL"
    if winner_errors:
        reasons.add("PROVIDER_WINNER_UNBOUND")
    _gate(
        gates,
        "provider_winner_binding",
        winner_status,
        "static",
        winner_errors or [stack["stack_id"]],
    )

    topology_complete = _audit_complete(topology["graph_audit"])
    world_complete = _audit_complete(world["graph_audit"])
    static_complete = topology_complete and world_complete
    graph_status = "PASS" if static_complete else "INCONCLUSIVE"
    if not static_complete:
        reasons.add("PARTIAL_COVERAGE")
    _gate(
        gates,
        "graph_topology",
        graph_status,
        "static",
        [root["quest_graph_id"], root["world_graph_id"]],
    )

    unresolved_paths: list[str] = []
    for path in paths:
        audit = topology["graph_audit"] if path["graph"] == "quest" else world["graph_audit"]
        resolved = _path_resolves(audit, path)
        status = "PASS" if resolved else ("FAIL" if static_complete else "INCONCLUSIVE")
        if not resolved:
            unresolved_paths.append(path["path_id"])
        _gate(gates, path["capability"], status, "static", [path["path_id"]])
    if unresolved_paths:
        reasons.add(
            "SHARED_GRAPH_PATH_UNRESOLVED"
            if static_complete
            else "SHARED_GRAPH_PATH_COVERAGE_INCONCLUSIVE"
        )

    scheduler_path = next(row for row in paths if row["capability"] == "scheduler")
    world_nodes = {row["identity_key"]: row for row in world["graph_audit"]["nodes"]}
    scheduler = world_nodes.get(scheduler_path["identity_keys"][0])
    schedule = world_nodes.get(scheduler_path["identity_keys"][1])
    scheduler_owned = (
        scheduler is not None
        and schedule is not None
        and schedule["ownership"]["state"] == "declared"
        and schedule["ownership"]["owner_node_id"] == scheduler["node_id"]
    )
    ownership_status = "PASS" if scheduler_owned else (
        "FAIL" if world_complete else "INCONCLUSIVE"
    )
    if not scheduler_owned:
        reasons.add("SCHEDULER_OWNERSHIP_UNRESOLVED")
    _gate(
        gates,
        "scheduler_ownership",
        ownership_status,
        "static",
        [scheduler_path["path_id"]],
    )

    runtime_binding = _mapping(
        root["runtime_binding"],
        {"capture_session_id", "stack_runtime_session_id"},
        "runtime_binding",
    )
    snapshot_digest = stack["identity"]["active_snapshot_id"].rsplit(":", 1)[-1]
    runtime_identity_ok = (
        runtime_binding["capture_session_id"] == runtime["session"]["session_id"]
        and runtime_binding["stack_runtime_session_id"]
        in stack["identity"]["runtime_session_ids"]
        and runtime["deployment_identity"]["active_snapshot_sha256"] == snapshot_digest
        and all(
            join["snapshot_id"] == stack["identity"]["active_snapshot_id"]
            and join["snapshot_sha256"] == snapshot_digest
            for join in topology["provider_join"]
        )
    )
    runtime_capture_complete = runtime["status"] == "complete"
    runtime_complete = runtime_capture_complete and runtime_identity_ok
    runtime_status = "PASS" if runtime_complete else (
        "FAIL" if runtime_capture_complete else "INCONCLUSIVE"
    )
    if not runtime_identity_ok:
        reasons.add("RUNTIME_IDENTITY_UNBOUND")
    if not runtime_capture_complete:
        reasons.add("RUNTIME_CAPTURE_INCONCLUSIVE")
    _gate(
        gates,
        "runtime_capture",
        runtime_status,
        "runtime",
        [runtime["session"]["session_id"]],
    )

    persistence_rows = _sequence(
        root["persistence_bindings"], "persistence_bindings", _MAX_PATHS
    )
    static_checks = {
        row["state_identity_key"]: row for row in world["persistence_checks"]
    }
    runtime_checks = {
        row["state_identity_key"]: row for row in runtime["persistence"]["checks"]
    }
    persistence_refs: list[str] = []
    static_persistence_ok = True
    runtime_persistence_ok = True
    for index, raw in enumerate(persistence_rows):
        row = _mapping(
            raw,
            {"static_state_identity_key", "runtime_state_identity_key"},
            f"persistence_bindings[{index}]",
        )
        static_key = _text(row["static_state_identity_key"], "static_state_identity_key")
        runtime_key = _text(row["runtime_state_identity_key"], "runtime_state_identity_key")
        persistence_refs.extend([static_key, runtime_key])
        static_persistence_ok = static_persistence_ok and (
            static_checks.get(static_key, {}).get("status") == "resolved"
        )
        runtime_persistence_ok = runtime_persistence_ok and (
            runtime_checks.get(runtime_key, {}).get("status") == "verified"
            and static_key == runtime_key
        )
    persistence_verified = (
        static_persistence_ok
        and runtime_persistence_ok
        and runtime["persistence"]["status"] == "verified"
        and runtime_identity_ok
    )
    persistence_status = "PASS" if persistence_verified else "INCONCLUSIVE"
    if not persistence_verified:
        reasons.add("SAVE_CONTINUITY_UNPROVEN")
    _gate(gates, "persistence", persistence_status, "runtime", persistence_refs)

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
        "runtime_session_id": runtime["session"]["session_id"],
        "status": status,
        "absence_claim_allowed": static_complete and runtime["absence_claim_allowed"],
        "evidence_layers": {"static": True, "runtime": True, "causal": False},
        "gates": gates,
        "resolved_paths": [
            {
                "path_id": path["path_id"],
                "capability": path["capability"],
                "graph": path["graph"],
                "resolved": path["path_id"] not in unresolved_paths,
            }
            for path in paths
        ],
        "persistence": {
            "static_status": "resolved" if static_persistence_ok else "unresolved",
            "runtime_status": runtime["persistence"]["status"],
            "identity_correlated": runtime_identity_ok,
            "state_identity_keys": sorted(set(persistence_refs), key=str.casefold),
        },
        "summary": {
            "shared_path_count": len(paths),
            "resolved_path_count": len(paths) - len(unresolved_paths),
            "provider_binding_count": len(bindings),
            "quest_node_count": len(topology["graph_audit"]["nodes"]),
            "world_node_count": len(world["graph_audit"]["nodes"]),
        },
        "component_receipts": {
            "quest_topology_sha256": sha256_json(topology),
            "world_behavior_sha256": sha256_json(world),
            "runtime_receipt_sha256": sha256_json(runtime),
        },
        "reason_codes": sorted(reasons),
    }
    return AIWorldAcceptanceReceipt(payload)


__all__ = [
    "AIWorldAcceptanceError",
    "AIWorldAcceptanceReceipt",
    "evaluate_ai_world_acceptance",
]
