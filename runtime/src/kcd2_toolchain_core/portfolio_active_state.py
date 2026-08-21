"""Exact, coverage-aware links from portfolio identity to active/runtime state."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .hashing import sha256_json
from .portfolio_registry import PortfolioRegistry, canonicalize_portfolio_registry


_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_PROJECT_ID = re.compile(r"^project:sha256:[0-9a-f]{64}$")
_COMPLETE_COVERAGE = frozenset({"COMPLETE", "COMPLETE_FOR_REQUESTED_SCOPE"})
_COVERAGE = frozenset(
    {
        "COMPLETE",
        "COMPLETE_FOR_REQUESTED_SCOPE",
        "PARTIAL_LIMIT_REACHED",
        "PARTIAL_STALE",
        "INCONCLUSIVE",
        "UNAVAILABLE",
    }
)
_MAX_PROJECTS = 256
_MAX_SESSIONS = 4096


class PortfolioActiveStateError(ValueError):
    """Supplied evidence cannot be joined under exact portfolio identity."""


def _text(value: object, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise PortfolioActiveStateError(f"{field} must be bounded non-empty text")
    return value


def _digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PortfolioActiveStateError(f"{field} must be a SHA-256 digest")
    return value.lower()


def _timestamp(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PortfolioActiveStateError("evaluated_at must be an offset-aware datetime")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise PortfolioActiveStateError(f"{field} must be a mapping with string keys")
    return value


@dataclass(frozen=True, slots=True)
class ActiveSnapshotBinding:
    snapshot_id: str
    snapshot_sha256: str
    current: bool
    coverage_status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "snapshot_id", _text(self.snapshot_id, "snapshot_id"))
        object.__setattr__(
            self, "snapshot_sha256", _digest(self.snapshot_sha256, "snapshot_sha256")
        )
        if not isinstance(self.current, bool):
            raise TypeError("current must be a boolean")
        if self.coverage_status not in _COVERAGE:
            raise PortfolioActiveStateError("coverage_status is not supported")


@dataclass(frozen=True, slots=True)
class ModOrderBinding:
    path: str
    sha256: str
    snapshot_sha256: str

    def __post_init__(self) -> None:
        if self.path != "mods/mod_order.txt":
            raise PortfolioActiveStateError("mod-order path must be exactly mods/mod_order.txt")
        object.__setattr__(self, "sha256", _digest(self.sha256, "mod_order.sha256"))
        object.__setattr__(
            self,
            "snapshot_sha256",
            _digest(self.snapshot_sha256, "mod_order.snapshot_sha256"),
        )


@dataclass(frozen=True, slots=True)
class LatestBootBinding:
    boot_id: str
    receipt_id: str
    receipt_sha256: str
    snapshot_sha256: str
    mod_order_sha256: str
    complete: bool
    latest_complete_boot: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "boot_id", _text(self.boot_id, "boot_id"))
        object.__setattr__(self, "receipt_id", _text(self.receipt_id, "receipt_id"))
        for field in ("receipt_sha256", "snapshot_sha256", "mod_order_sha256"):
            object.__setattr__(self, field, _digest(getattr(self, field), field))
        if not isinstance(self.complete, bool) or not isinstance(
            self.latest_complete_boot, bool
        ):
            raise TypeError("boot scope flags must be booleans")


@dataclass(frozen=True, slots=True)
class ProjectInstalledStateBinding:
    project_id: str
    reconciliation: Mapping[str, Any]

    def __post_init__(self) -> None:
        project_id = _text(self.project_id, "project_id")
        if _PROJECT_ID.fullmatch(project_id) is None:
            raise PortfolioActiveStateError("project_id must be content-addressed")
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(
            self, "reconciliation", copy.deepcopy(dict(_mapping(self.reconciliation, "reconciliation")))
        )


@dataclass(frozen=True, slots=True)
class RuntimeProjectBinding:
    project_id: str
    session: Mapping[str, Any]

    def __post_init__(self) -> None:
        project_id = _text(self.project_id, "project_id")
        if _PROJECT_ID.fullmatch(project_id) is None:
            raise PortfolioActiveStateError("project_id must be content-addressed")
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(
            self, "session", copy.deepcopy(dict(_mapping(self.session, "runtime session")))
        )


@dataclass(frozen=True, slots=True)
class PortfolioActiveState:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _drift(
    *,
    project_id: str,
    drift_kind: str,
    expected: str | None,
    observed: str | None,
) -> dict[str, Any]:
    material = {
        "project_id": project_id,
        "drift_kind": drift_kind,
        "expected": expected,
        "observed": observed,
        "evidence_layer": "reconciled_read_only",
    }
    return {"event_id": f"portfolio-drift:sha256:{sha256_json(material)}", **material}


def _installed_payload(binding: ProjectInstalledStateBinding) -> dict[str, Any]:
    value = dict(binding.reconciliation)
    for field in ("reconciliation_id", "configuration", "semantic_index", "latest_load"):
        if field not in value:
            raise PortfolioActiveStateError(f"reconciliation lacks {field}")
    configuration = _mapping(value["configuration"], "configuration")
    semantic = _mapping(value["semantic_index"], "semantic_index")
    latest = _mapping(value["latest_load"], "latest_load")
    required_configuration = {"state", "mod_order_path", "entry_count"}
    required_semantic = {"indexed", "snapshot_id", "snapshot_current"}
    if not required_configuration <= set(configuration):
        raise PortfolioActiveStateError("configuration fields are incomplete")
    if not required_semantic <= set(semantic):
        raise PortfolioActiveStateError("semantic_index fields are incomplete")
    if not {"boot_receipt_id", "state"} <= set(latest):
        raise PortfolioActiveStateError("latest_load fields are incomplete")
    if not isinstance(semantic["indexed"], bool) or not isinstance(
        semantic["snapshot_current"], bool
    ):
        raise PortfolioActiveStateError("semantic index flags must be booleans")
    return value


def link_portfolio_active_state(
    *,
    registry: PortfolioRegistry | Mapping[str, Any],
    inventory: Mapping[str, Any],
    snapshot: ActiveSnapshotBinding,
    mod_order: ModOrderBinding,
    latest_boot: LatestBootBinding,
    installed_states: Sequence[ProjectInstalledStateBinding],
    runtime_sessions: Sequence[RuntimeProjectBinding],
    evaluated_at: datetime,
) -> PortfolioActiveState:
    """Join a bounded project scope without upgrading stale or partial evidence."""

    canonical = canonicalize_portfolio_registry(registry)
    evaluated = _timestamp(evaluated_at)
    if not isinstance(snapshot, ActiveSnapshotBinding):
        raise TypeError("snapshot must be ActiveSnapshotBinding")
    if not isinstance(mod_order, ModOrderBinding):
        raise TypeError("mod_order must be ModOrderBinding")
    if not isinstance(latest_boot, LatestBootBinding):
        raise TypeError("latest_boot must be LatestBootBinding")
    inventory_value = _mapping(inventory, "inventory")
    if inventory_value.get("schema_version") != "kcd2.project-provider-inventory.v1":
        raise PortfolioActiveStateError("inventory schema_version is not supported")
    if inventory_value.get("registry_id") != canonical.registry_id:
        raise PortfolioActiveStateError("inventory registry_id differs from registry")
    inventory_id = _text(inventory_value.get("inventory_id"), "inventory_id")
    requested = inventory_value.get("requested_project_ids")
    projects = inventory_value.get("projects")
    if not isinstance(requested, list) or not 1 <= len(requested) <= _MAX_PROJECTS:
        raise PortfolioActiveStateError("inventory requested project scope is invalid")
    if len(requested) != len(set(requested)):
        raise PortfolioActiveStateError("inventory requested project IDs must be unique")
    if not isinstance(projects, list):
        raise PortfolioActiveStateError("inventory projects must be an array")
    inventory_projects = {
        _text(item.get("project_id"), "inventory project_id"): item
        for item in (_mapping(value, "inventory project") for value in projects)
    }
    requested_set = set(requested)
    if requested_set != set(inventory_projects):
        raise PortfolioActiveStateError("inventory projects differ from requested scope")
    registry_projects = {
        item["project_id"]: item for item in canonical.to_dict()["projects"]
    }
    if not requested_set <= set(registry_projects):
        raise PortfolioActiveStateError("inventory contains a project outside the registry")
    if not isinstance(installed_states, Sequence) or isinstance(installed_states, (str, bytes)):
        raise TypeError("installed_states must be a sequence")
    if not isinstance(runtime_sessions, Sequence) or isinstance(runtime_sessions, (str, bytes)):
        raise TypeError("runtime_sessions must be a sequence")
    if len(runtime_sessions) > _MAX_SESSIONS:
        raise PortfolioActiveStateError("runtime_sessions exceeds its hard bound")
    if any(not isinstance(item, ProjectInstalledStateBinding) for item in installed_states):
        raise TypeError("installed_states contains an invalid binding")
    if any(not isinstance(item, RuntimeProjectBinding) for item in runtime_sessions):
        raise TypeError("runtime_sessions contains an invalid binding")
    installed_by_project = {item.project_id: item for item in installed_states}
    if len(installed_by_project) != len(installed_states):
        raise PortfolioActiveStateError("installed state project IDs must be unique")
    if set(installed_by_project) != requested_set:
        raise PortfolioActiveStateError("installed state scope differs from inventory scope")
    if any(item.project_id not in requested_set for item in runtime_sessions):
        raise PortfolioActiveStateError("runtime session is outside requested project scope")

    coverage = _mapping(inventory_value.get("coverage"), "inventory coverage")
    inventory_coverage = coverage.get("overall_status")
    if inventory_coverage not in _COVERAGE:
        raise PortfolioActiveStateError("inventory coverage status is unsupported")
    absence_allowed = coverage.get("absence_claim_allowed")
    if not isinstance(absence_allowed, bool):
        raise PortfolioActiveStateError("inventory absence claim permission must be boolean")
    coverage_reasons = coverage.get("reason_codes")
    if not isinstance(coverage_reasons, list) or any(
        not isinstance(item, str) for item in coverage_reasons
    ):
        raise PortfolioActiveStateError("inventory coverage reason_codes must be an array")
    complete_coverage = (
        inventory_coverage in _COMPLETE_COVERAGE
        and snapshot.coverage_status in _COMPLETE_COVERAGE
    )
    global_reasons: set[str] = set(coverage_reasons)
    if not complete_coverage:
        global_reasons.add("SNAPSHOT_COVERAGE_PARTIAL")
    if not snapshot.current:
        global_reasons.add("ACTIVE_SNAPSHOT_STALE")
    if mod_order.snapshot_sha256 != snapshot.snapshot_sha256:
        global_reasons.add("MOD_ORDER_SNAPSHOT_DRIFT")
    if latest_boot.snapshot_sha256 != snapshot.snapshot_sha256:
        global_reasons.add("LATEST_BOOT_SNAPSHOT_DRIFT")
    if latest_boot.mod_order_sha256 != mod_order.sha256:
        global_reasons.add("LATEST_BOOT_MOD_ORDER_DRIFT")
    if not latest_boot.complete or not latest_boot.latest_complete_boot:
        global_reasons.add("LATEST_COMPLETE_BOOT_MISSING")

    sessions_by_project: dict[str, list[RuntimeProjectBinding]] = {
        project_id: [] for project_id in requested_set
    }
    for item in runtime_sessions:
        sessions_by_project[item.project_id].append(item)

    output_projects: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    for project_id in sorted(requested_set):
        reconciliation = _installed_payload(installed_by_project[project_id])
        configuration = reconciliation["configuration"]
        semantic = reconciliation["semantic_index"]
        latest_load = reconciliation["latest_load"]
        reasons = set(global_reasons)
        if configuration["mod_order_path"] != mod_order.path:
            reasons.add("MOD_ORDER_PATH_DRIFT")
        semantic_status = "current"
        if not semantic["indexed"]:
            semantic_status = "missing"
            reasons.add("SEMANTIC_INDEX_MISSING")
        elif not semantic["snapshot_current"] or semantic["snapshot_id"] != snapshot.snapshot_id:
            semantic_status = "stale"
            reasons.add("SEMANTIC_INDEX_STALE")
        elif not snapshot.current:
            semantic_status = "stale"
        elif not complete_coverage:
            semantic_status = "partial"
        current_truth = semantic_status == "current" and not global_reasons
        if "SEMANTIC_INDEX_STALE" in reasons:
            events.append(
                _drift(
                    project_id=project_id,
                    drift_kind="semantic_index_stale",
                    expected=snapshot.snapshot_id,
                    observed=semantic["snapshot_id"],
                )
            )
        if latest_load["boot_receipt_id"] != latest_boot.receipt_id:
            reasons.add("LATEST_LOAD_BOOT_DRIFT")
            events.append(
                _drift(
                    project_id=project_id,
                    drift_kind="latest_load_boot_drift",
                    expected=latest_boot.receipt_id,
                    observed=latest_load["boot_receipt_id"],
                )
            )

        declared_provider_ids = {
            item["provider_id"] for item in registry_projects[project_id]["providers"]
        }
        provider_output: list[dict[str, Any]] = []
        inventory_project = _mapping(inventory_projects[project_id], "inventory project")
        provider_values = inventory_project.get("providers")
        if not isinstance(provider_values, list):
            raise PortfolioActiveStateError("inventory providers must be an array")
        for raw_provider in provider_values:
            provider = _mapping(raw_provider, "inventory provider")
            provider_id = _text(provider.get("provider_id"), "provider_id")
            if provider_id not in declared_provider_ids:
                reasons.add("UNDECLARED_PROVIDER_OBSERVED")
            states = provider.get("states")
            if not isinstance(states, list) or any(not isinstance(item, str) for item in states):
                raise PortfolioActiveStateError("provider states must be an array")
            digest = provider.get("sha256")
            provider_output.append(
                {
                    "provider_id": provider_id,
                    "states": sorted(set(states)),
                    "sha256": None if digest is None else _digest(digest, "provider sha256"),
                }
            )
        observed_declared = {item["provider_id"] for item in provider_output} & declared_provider_ids
        if observed_declared != declared_provider_ids:
            reasons.add("PROVIDER_EVIDENCE_MISSING")
        provider_output.sort(key=lambda item: item["provider_id"])

        session_output: list[dict[str, Any]] = []
        seen_sessions: set[str] = set()
        for binding in sessions_by_project[project_id]:
            from kcd2_native_probes.runtime_session_inspection import (
                bind_runtime_session_record,
            )

            session = bind_runtime_session_record(binding.session)
            session_id = session["session_id"]
            if session_id in seen_sessions:
                raise PortfolioActiveStateError("runtime session IDs must be unique per project")
            seen_sessions.add(session_id)
            runtime_status = "exact"
            identity = session["cross_tool_identity"]
            if session["latest_boot_id"] != latest_boot.boot_id:
                runtime_status = "stale"
                reasons.add("RUNTIME_LATEST_BOOT_DRIFT")
                events.append(
                    _drift(
                        project_id=project_id,
                        drift_kind="runtime_latest_boot_drift",
                        expected=latest_boot.boot_id,
                        observed=session["latest_boot_id"],
                    )
                )
            if identity["active_snapshot_id"] != snapshot.snapshot_id:
                runtime_status = "stale"
                reasons.add("RUNTIME_ACTIVE_SNAPSHOT_DRIFT")
                events.append(
                    _drift(
                        project_id=project_id,
                        drift_kind="runtime_active_snapshot_drift",
                        expected=snapshot.snapshot_id,
                        observed=identity["active_snapshot_id"],
                    )
                )
            if identity["mod_order_sha256"] != mod_order.sha256:
                runtime_status = "stale"
                reasons.add("RUNTIME_MOD_ORDER_DRIFT")
                events.append(
                    _drift(
                        project_id=project_id,
                        drift_kind="runtime_mod_order_drift",
                        expected=mod_order.sha256,
                        observed=identity["mod_order_sha256"],
                    )
                )
            session_output.append(
                {
                    "session_id": session_id,
                    "status": runtime_status,
                    "latest_boot_id": session["latest_boot_id"],
                    "session_binding_sha256": session["session_binding_sha256"],
                    "candidate_sha256": session["candidate_sha256"],
                    "deployment_sha256": session["deployment_sha256"],
                    "source_sha256": session["source_sha256"],
                }
            )
        if not session_output:
            reasons.add("RUNTIME_SESSION_MISSING")
        session_output.sort(key=lambda item: item["session_id"])

        if not reasons and current_truth:
            project_status = "current"
        elif semantic_status == "stale" or any("DRIFT" in reason for reason in reasons):
            project_status = "stale"
        elif semantic_status == "missing" or "RUNTIME_SESSION_MISSING" in reasons:
            project_status = "missing"
        else:
            project_status = "partial"
        output_projects.append(
            {
                "project_id": project_id,
                "status": project_status,
                "reason_codes": sorted(reasons),
                "configuration": {
                    "state": configuration["state"],
                    "mod_order_path": configuration["mod_order_path"],
                    "entry_count": configuration["entry_count"],
                },
                "semantic_index": {
                    "indexed": semantic["indexed"],
                    "snapshot_id": semantic["snapshot_id"],
                    "snapshot_current": semantic["snapshot_current"],
                    "status": semantic_status,
                    "current_truth": current_truth,
                },
                "latest_load_state": latest_load["state"],
                "providers": provider_output,
                "runtime_sessions": session_output,
            }
        )

    events.sort(key=lambda item: item["event_id"])
    coverage_status = "complete" if complete_coverage else "partial"
    status = (
        "exact_current"
        if all(item["status"] == "current" for item in output_projects)
        else "capture_inconclusive"
    )
    payload: dict[str, Any] = {
        "schema_version": "kcd2.portfolio-active-state.v1",
        "registry_id": canonical.registry_id,
        "inventory_id": inventory_id,
        "evaluated_at": _iso(evaluated),
        "status": status,
        "snapshot": {
            "snapshot_id": snapshot.snapshot_id,
            "sha256": snapshot.snapshot_sha256,
            "current": snapshot.current,
            "coverage_status": snapshot.coverage_status,
        },
        "mod_order": {
            "path": mod_order.path,
            "sha256": mod_order.sha256,
            "snapshot_sha256": mod_order.snapshot_sha256,
        },
        "latest_boot": {
            "boot_id": latest_boot.boot_id,
            "receipt_id": latest_boot.receipt_id,
            "receipt_sha256": latest_boot.receipt_sha256,
            "snapshot_sha256": latest_boot.snapshot_sha256,
            "mod_order_sha256": latest_boot.mod_order_sha256,
            "complete": latest_boot.complete,
            "latest_complete_boot": latest_boot.latest_complete_boot,
        },
        "coverage": {
            "status": coverage_status,
            "inventory_status": inventory_coverage,
            "snapshot_status": snapshot.coverage_status,
            "absence_claim_allowed": absence_allowed and complete_coverage,
            "reason_codes": sorted(global_reasons),
        },
        "projects": output_projects,
        "drift_events": events,
    }
    payload["link_id"] = f"portfolio-active-state:sha256:{sha256_json(payload)}"
    return PortfolioActiveState(payload)


__all__ = [
    "ActiveSnapshotBinding",
    "LatestBootBinding",
    "ModOrderBinding",
    "PortfolioActiveState",
    "PortfolioActiveStateError",
    "ProjectInstalledStateBinding",
    "RuntimeProjectBinding",
    "link_portfolio_active_state",
]
