"""Bounded, non-live COMPAT-002 core scripting stack acceptance."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_native_probes.overhead import audit_probe_overhead
from kcd2_research_graph.lua_runtime import (
    LuaRuntimeAdapterError,
    adapt_lua_entity_runtime,
)

from .compatibility_stacks import CompatibilityStackError, evaluate_compatibility_stack
from .hashing import sha256_json


SCHEMA_VERSION = "kcd2.core-scripting-stack-acceptance.v1"
_INPUT_VERSION = "kcd2.core-scripting-stack-suite.v1"
_ROOT_FIELDS = {
    "schema_version",
    "acceptance_id",
    "stack_manifest",
    "namespace_claims",
    "runtime_captures",
    "custom_log",
    "overhead_observation",
    "mutation_count",
}
_CLAIM_KINDS = {"ACTION", "GLOBAL", "LISTENER", "TIMER"}
_LOG_LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"}
_MAX_CLAIMS = 4096
_MAX_CAPTURES = 256
_MAX_LOG_LINES = 100_000
_MAX_LINE_BYTES = 64 * 1024


class CoreScriptingAcceptanceError(ValueError):
    """A core scripting acceptance fixture is malformed or exceeds a hard bound."""


@dataclass(frozen=True, slots=True)
class CoreScriptingAcceptanceReceipt:
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
        raise CoreScriptingAcceptanceError(f"{name} fields do not match the contract")
    return value


def _sequence(value: object, name: str, maximum: int, *, minimum: int = 1) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CoreScriptingAcceptanceError(f"{name} must be an array")
    if not minimum <= len(value) <= maximum:
        raise CoreScriptingAcceptanceError(f"{name} violates its hard bound")
    return value


def _text(value: object, name: str, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise CoreScriptingAcceptanceError(f"{name} must be bounded non-empty text")
    return value


def _detached(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise CoreScriptingAcceptanceError("input must contain JSON values only") from exc


def _claims(value: object, project_ids: set[str]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    claim_ids: set[str] = set()
    for index, raw in enumerate(_sequence(value, "namespace_claims", _MAX_CLAIMS)):
        row = _mapping(
            raw,
            {"claim_id", "kind", "namespace", "project_id"},
            f"namespace_claims[{index}]",
        )
        claim_id = _text(row["claim_id"], "claim_id", 256)
        kind = _text(row["kind"], "kind", 32).upper()
        namespace = _text(row["namespace"], "namespace")
        project_id = _text(row["project_id"], "project_id", 256)
        if claim_id in claim_ids:
            raise CoreScriptingAcceptanceError("namespace claim identifiers must be unique")
        if kind not in _CLAIM_KINDS:
            raise CoreScriptingAcceptanceError(f"unsupported namespace claim kind: {kind}")
        if project_id not in project_ids:
            raise CoreScriptingAcceptanceError("namespace claim project is not a stack member")
        claim_ids.add(claim_id)
        rows.append(
            {
                "claim_id": claim_id,
                "kind": kind,
                "namespace": namespace,
                "project_id": project_id,
            }
        )
    if {row["kind"] for row in rows} != _CLAIM_KINDS:
        raise CoreScriptingAcceptanceError("namespace claims must cover every scripting kind")
    return sorted(rows, key=lambda row: (row["kind"], row["namespace"].casefold(), row["claim_id"]))


def _collisions(claims: Sequence[Mapping[str, str]]) -> list[dict[str, Any]]:
    groups: defaultdict[tuple[str, str], list[Mapping[str, str]]] = defaultdict(list)
    for row in claims:
        groups[(row["kind"], row["namespace"].casefold())].append(row)
    collisions: list[dict[str, Any]] = []
    for (kind, _), rows in sorted(groups.items()):
        projects = sorted({row["project_id"] for row in rows})
        if len(projects) > 1:
            collisions.append(
                {
                    "kind": kind,
                    "namespace": min(row["namespace"] for row in rows),
                    "project_ids": projects,
                    "claim_ids": sorted(row["claim_id"] for row in rows),
                }
            )
    return collisions


def _runtime(value: object, project_ids: set[str]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    receipts: list[dict[str, Any]] = []
    seen_projects: set[str] = set()
    for index, raw in enumerate(_sequence(value, "runtime_captures", _MAX_CAPTURES)):
        row = _mapping(raw, {"project_id", "capture"}, f"runtime_captures[{index}]")
        project_id = _text(row["project_id"], "project_id", 256)
        if project_id not in project_ids or project_id in seen_projects:
            raise CoreScriptingAcceptanceError(
                "runtime capture projects must be unique exact stack members"
            )
        try:
            receipt = adapt_lua_entity_runtime(row["capture"])
        except (LuaRuntimeAdapterError, TypeError, ValueError) as exc:
            raise CoreScriptingAcceptanceError(str(exc)) from exc
        seen_projects.add(project_id)
        receipts.append(
            {
                "project_id": project_id,
                "session_id": receipt["session_id"],
                "status": receipt["status"],
                "reason_codes": receipt["reason_codes"],
                "instrumentation_channels": receipt["instrumentation_channels"],
                "initialization_count": sum(
                    instance["initialization_count"] for instance in receipt["instances"]
                ),
                "active_listener_count": receipt["cleanup"]["active_listener_count"],
                "active_timer_count": receipt["cleanup"]["active_timer_count"],
            }
        )
    summary = {
        "capture_count": len(receipts),
        "initialization_count": sum(row["initialization_count"] for row in receipts),
        "active_listener_count": sum(row["active_listener_count"] for row in receipts),
        "active_timer_count": sum(row["active_timer_count"] for row in receipts),
    }
    return sorted(receipts, key=lambda row: row["project_id"]), summary


def _custom_log(value: object) -> dict[str, Any]:
    root = _mapping(value, {"format", "lines", "maximum_error_rate"}, "custom_log")
    if root["format"] != "jsonl":
        raise CoreScriptingAcceptanceError("custom_log.format must be jsonl")
    maximum_error_rate = root["maximum_error_rate"]
    if (
        not isinstance(maximum_error_rate, (int, float))
        or isinstance(maximum_error_rate, bool)
        or not 0 <= maximum_error_rate <= 1
    ):
        raise CoreScriptingAcceptanceError("maximum_error_rate must be between zero and one")
    imported: list[dict[str, Any]] = []
    for index, line in enumerate(_sequence(root["lines"], "custom_log.lines", _MAX_LOG_LINES)):
        text = _text(line, f"custom_log.lines[{index}]", _MAX_LINE_BYTES)
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CoreScriptingAcceptanceError("custom log line is not valid JSON") from exc
        row = _mapping(
            parsed,
            {"sequence", "level", "channel", "message"},
            f"custom_log.lines[{index}] record",
        )
        if row["sequence"] != index:
            raise CoreScriptingAcceptanceError("custom log sequences must be contiguous")
        level = _text(row["level"], "level", 16).upper()
        if level not in _LOG_LEVELS:
            raise CoreScriptingAcceptanceError("custom log level is unsupported")
        imported.append(
            {
                "sequence": index,
                "level": level,
                "channel": _text(row["channel"], "channel", 128),
                "message": _text(row["message"], "message", 4096),
            }
        )
    errors = sum(row["level"] in {"ERROR", "FATAL"} for row in imported)
    error_rate = errors / len(imported)
    levels = Counter(row["level"] for row in imported)
    return {
        "format": "jsonl",
        "imported_event_count": len(imported),
        "error_count": errors,
        "error_rate": error_rate,
        "maximum_error_rate": float(maximum_error_rate),
        "level_counts": dict(sorted(levels.items())),
        "records_sha256": sha256_json(imported),
    }


def _gate(
    gates: list[dict[str, Any]], gate_id: str, status: str, layer: str, evidence: Sequence[str]
) -> None:
    gates.append(
        {
            "gate_id": gate_id,
            "status": status,
            "evidence_layer": layer,
            "evidence_refs": sorted(set(evidence)),
        }
    )


def evaluate_core_scripting_acceptance(
    value: Mapping[str, Any],
) -> CoreScriptingAcceptanceReceipt:
    """Evaluate one exact-identity scripting stack without accessing live state."""

    root = _mapping(_detached(value), _ROOT_FIELDS, "acceptance input")
    if root["schema_version"] != _INPUT_VERSION:
        raise CoreScriptingAcceptanceError(f"schema_version must be {_INPUT_VERSION}")
    acceptance_id = _text(root["acceptance_id"], "acceptance_id", 256)
    mutation_count = root["mutation_count"]
    if (
        not isinstance(mutation_count, int)
        or isinstance(mutation_count, bool)
        or not 0 <= mutation_count <= 1_000_000
    ):
        raise CoreScriptingAcceptanceError("mutation_count violates its hard bound")
    try:
        stack = evaluate_compatibility_stack(root["stack_manifest"]).to_dict()
        overhead = audit_probe_overhead(root["overhead_observation"])
    except (CompatibilityStackError, TypeError, ValueError) as exc:
        raise CoreScriptingAcceptanceError(str(exc)) from exc
    if stack["family"] != "CORE_SCRIPTING":
        raise CoreScriptingAcceptanceError("stack family must be CORE_SCRIPTING")
    project_ids = {row["project_id"] for row in stack["members"]}
    claims = _claims(root["namespace_claims"], project_ids)
    collisions = _collisions(claims)
    runtime, runtime_summary = _runtime(root["runtime_captures"], project_ids)
    custom_log = _custom_log(root["custom_log"])

    gates: list[dict[str, Any]] = []
    reasons: set[str] = set()
    stack_status = stack["result"]
    _gate(gates, "exact_stack_identity", stack_status, "static", [stack["stack_id"]])

    collision_status = "FAIL" if collisions else "PASS"
    if collisions:
        reasons.add("NAMESPACE_COLLISION")
    _gate(
        gates,
        "namespace_collisions",
        collision_status,
        "static",
        [row["claim_id"] for row in claims],
    )

    runtime_inconclusive = any(row["status"] == "capture_inconclusive" for row in runtime)
    positive_failure_reasons = {
        "DUPLICATE_INITIALIZATION",
        "DUPLICATE_LISTENER_REGISTRATION",
        "DUPLICATE_TIMER_START",
        "LISTENER_LEAK",
        "LISTENER_LIFECYCLE_INVALID",
        "TIMER_LEAK",
        "TIMER_LIFECYCLE_INVALID",
        "CLEANUP_INCOMPLETE",
    }
    runtime_failed = any(
        row["status"] == "issues_found"
        or positive_failure_reasons.intersection(row["reason_codes"])
        for row in runtime
    )
    runtime_status = (
        "FAIL" if runtime_failed else "INCONCLUSIVE" if runtime_inconclusive else "PASS"
    )
    for row in runtime:
        reasons.update(row["reason_codes"])
    if runtime_inconclusive:
        reasons.add("RUNTIME_CAPTURE_INCONCLUSIVE")
    _gate(
        gates,
        "runtime_lifecycle",
        runtime_status,
        "runtime_observed",
        [row["session_id"] for row in runtime],
    )

    log_ok = custom_log["error_rate"] <= custom_log["maximum_error_rate"]
    log_status = "PASS" if log_ok else "INCONCLUSIVE"
    if not log_ok:
        reasons.add("CUSTOM_LOG_ERROR_RATE_EXCEEDED")
    _gate(gates, "custom_log_error_rate", log_status, "runtime_observed", [acceptance_id])

    overhead_status = "PASS" if overhead["capture_validity"] == "complete" else "INCONCLUSIVE"
    if overhead_status != "PASS":
        reasons.add("OVERHEAD_CAPTURE_INCONCLUSIVE")
    _gate(
        gates,
        "overhead",
        overhead_status,
        "runtime_observed",
        [overhead["session_id"]],
    )

    mutation_status = "PASS" if mutation_count == 0 else "FAIL"
    if mutation_count:
        reasons.add("MUTATION_DETECTED")
    _gate(gates, "non_mutation", mutation_status, "static", [acceptance_id])
    gates.sort(key=lambda row: row["gate_id"])
    if any(row["status"] == "FAIL" for row in gates):
        status = "FAIL"
    elif any(row["status"] == "INCONCLUSIVE" for row in gates):
        status = "INCONCLUSIVE"
    else:
        status = "PASS"

    permitted_claims = ["namespace_collisions_shown", "custom_log_imported"]
    if mutation_count == 0:
        permitted_claims.append("mutation_count_zero")
    if runtime_status == "PASS":
        permitted_claims.extend(
            ["no_duplicate_initialization", "no_listener_leaks", "no_timer_leaks"]
        )
    normalized_input = {
        "acceptance_id": acceptance_id,
        "stack_id": stack["stack_id"],
        "namespace_claims": claims,
        "runtime_captures": runtime,
        "custom_log": custom_log,
        "overhead": overhead,
        "mutation_count": mutation_count,
    }
    material = {
        "schema_version": SCHEMA_VERSION,
        "acceptance_id": acceptance_id,
        "input_sha256": sha256_json(normalized_input),
        "stack_id": stack["stack_id"],
        "status": status,
        "reason_codes": sorted(reasons),
        "gates": gates,
        "namespace_claims": claims,
        "collisions": collisions,
        "runtime_captures": runtime,
        "runtime_summary": runtime_summary,
        "custom_log": custom_log,
        "overhead": {
            "session_id": overhead["session_id"],
            "capture_validity": overhead["capture_validity"],
            "severe_overhead": overhead["severe_overhead"],
            "recommendation": overhead["recommendation"],
            "invalidation_reasons": overhead["invalidation_reasons"],
        },
        "mutation_count": mutation_count,
        "permitted_claims": sorted(permitted_claims),
    }
    material["receipt_id"] = f"core-scripting-acceptance:sha256:{sha256_json(material)}"
    return CoreScriptingAcceptanceReceipt(material)


__all__ = [
    "CoreScriptingAcceptanceError",
    "CoreScriptingAcceptanceReceipt",
    "evaluate_core_scripting_acceptance",
]
