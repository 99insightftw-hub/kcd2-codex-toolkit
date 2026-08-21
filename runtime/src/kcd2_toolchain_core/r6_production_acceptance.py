"""Bounded TEST-006 acceptance for the R6 read-only public surfaces."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Any

from .live_readonly_acceptance import (
    REQUIRED_LIVE_READONLY_CASE_IDS,
    _canonical_bytes,
    _hash_records,
    _mapping,
    _revision_map,
    _sha256,
    _text,
    _text_list,
    _timestamp,
)


LEGACY_R5_CASE_IDS = REQUIRED_LIVE_READONLY_CASE_IDS
REQUIRED_R6_CASE_IDS = (
    "orchestrator_catalog_schema_parity",
    "orchestrator_doctor_profile_drift",
    "orchestrator_start_status_readonly",
    "synchronized_timeline_merge",
    "exact_session_clock_quality",
    "native_registry_module_identity",
    "x64dbg_provider_state_readonly",
    "ghidra_exporter_bounded_fixture",
    "crash_triage_bounded",
    "probe_overhead_readonly",
    "cross_surface_identity_chain",
)
_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"})
_EXECUTION_CLASSES = frozenset({"non_live_fixture", "live_read_only"})
_MAX_RESPONSE_BYTES = 1024 * 1024


class R6ProductionAcceptanceError(ValueError):
    """The TEST-006 authorization or bounded observation is invalid."""


def authorization_binding_sha256(authorization: Mapping[str, object]) -> str:
    payload = dict(_mapping(authorization, "authorization"))
    payload.pop("binding_sha256", None)
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _authorization(value: Mapping[str, object]) -> dict[str, Any]:
    source = dict(_mapping(value, "authorization"))
    required = {
        "schema_version", "authorization_id", "task_id", "execution_class",
        "environment_profile_id", "environment_profile_sha256", "authorized_at",
        "expires_at", "case_ids", "source_revisions", "tool_revisions",
        "binding_sha256",
    }
    if set(source) != required:
        raise R6ProductionAcceptanceError("authorization fields are incomplete or unknown")
    if source["schema_version"] != "kcd2.r6-production-acceptance-authorization.v1":
        raise R6ProductionAcceptanceError("authorization schema_version is invalid")
    if source["task_id"] != "TEST-006":
        raise R6ProductionAcceptanceError("authorization must be bound only to TEST-006")
    if source["execution_class"] not in _EXECUTION_CLASSES:
        raise R6ProductionAcceptanceError("authorization execution_class is invalid")
    case_ids = _text_list(source["case_ids"], "authorization.case_ids", nonempty=True)
    if tuple(case_ids) != REQUIRED_R6_CASE_IDS:
        raise R6ProductionAcceptanceError("authorization must name the exact R6 case matrix")
    binding = _sha256(source["binding_sha256"], "authorization.binding_sha256")
    if binding != authorization_binding_sha256(source):
        raise R6ProductionAcceptanceError("authorization binding does not match its content")
    return {
        "schema_version": source["schema_version"],
        "authorization_id": _text(source["authorization_id"], "authorization_id"),
        "task_id": "TEST-006",
        "execution_class": source["execution_class"],
        "environment_profile_id": _text(source["environment_profile_id"], "environment_profile_id"),
        "environment_profile_sha256": _sha256(
            source["environment_profile_sha256"], "environment_profile_sha256"
        ),
        "authorized_at": _text(source["authorized_at"], "authorized_at"),
        "expires_at": _text(source["expires_at"], "expires_at"),
        "case_ids": case_ids,
        "source_revisions": _revision_map(source["source_revisions"], "source_revisions"),
        "tool_revisions": _revision_map(source["tool_revisions"], "tool_revisions"),
        "binding_sha256": binding,
    }


def _observation(value: Mapping[str, object]) -> dict[str, Any]:
    source = _mapping(value, "observation")
    required = {
        "case_id", "status", "reads", "writes", "input_hashes", "output_hashes",
        "protected_state_before", "protected_state_after", "response_bytes",
        "response_ceiling_bytes", "notes",
    }
    if set(source) != required:
        raise R6ProductionAcceptanceError("observation fields are incomplete or unknown")
    case_id = _text(source["case_id"], "case_id")
    if case_id not in REQUIRED_R6_CASE_IDS:
        raise R6ProductionAcceptanceError(f"unknown TEST-006 case: {case_id}")
    status = source["status"]
    if status not in _STATUSES:
        raise R6ProductionAcceptanceError(f"invalid observation status for {case_id}")
    response_bytes = source["response_bytes"]
    ceiling = source["response_ceiling_bytes"]
    if not isinstance(response_bytes, int) or not 0 <= response_bytes <= _MAX_RESPONSE_BYTES:
        raise R6ProductionAcceptanceError(f"{case_id}.response_bytes is invalid")
    if not isinstance(ceiling, int) or not 1 <= ceiling <= _MAX_RESPONSE_BYTES:
        raise R6ProductionAcceptanceError(f"{case_id}.response_ceiling_bytes is invalid")
    writes = _text_list(source["writes"], f"{case_id}.writes", nonempty=False)
    before = _revision_map(source["protected_state_before"], f"{case_id}.protected_state_before")
    after = _revision_map(source["protected_state_after"], f"{case_id}.protected_state_after")
    drifted = sorted(
        subject
        for subject in set(before) | set(after)
        if before.get(subject) != after.get(subject)
    )
    mutation_count = len(writes) + len(drifted)
    ceiling_satisfied = response_bytes <= ceiling
    if mutation_count or not ceiling_satisfied:
        status = "FAIL"
    return {
        "case_id": case_id,
        "status": status,
        "reads": _text_list(source["reads"], f"{case_id}.reads", nonempty=True),
        "writes": writes,
        "input_hashes": _hash_records(source["input_hashes"], f"{case_id}.input_hashes"),
        "output_hashes": _hash_records(source["output_hashes"], f"{case_id}.output_hashes"),
        "protected_state_before": before,
        "protected_state_after": after,
        "drifted_protected_subjects": drifted,
        "mutation_count": mutation_count,
        "response_bytes": response_bytes,
        "response_ceiling_bytes": ceiling,
        "response_ceiling_satisfied": ceiling_satisfied,
        "notes": _text(source["notes"], f"{case_id}.notes"),
    }


def evaluate_r6_production_acceptance(
    *, authorization: Mapping[str, object], observations: Sequence[Mapping[str, object]],
    receipt_id: str, started_at: str, closed_at: str,
) -> dict[str, Any]:
    """Evaluate pre-captured evidence without performing or authorizing I/O."""
    try:
        checked = _authorization(authorization)
        started = _timestamp(started_at, "started_at")
        closed = _timestamp(closed_at, "closed_at")
        authorized = _timestamp(checked["authorized_at"], "authorized_at")
        expires = _timestamp(checked["expires_at"], "expires_at")
    except R6ProductionAcceptanceError:
        raise
    except ValueError as exc:
        raise R6ProductionAcceptanceError(str(exc)) from exc
    if not authorized <= started <= closed <= expires:
        raise R6ProductionAcceptanceError("receipt interval is outside the authorization interval")
    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise R6ProductionAcceptanceError("observations must be an array")
    by_id: dict[str, dict[str, Any]] = {}
    try:
        for value in observations:
            item = _observation(value)
            if item["case_id"] in by_id:
                raise R6ProductionAcceptanceError(f"duplicate observation for {item['case_id']}")
            by_id[item["case_id"]] = item
    except R6ProductionAcceptanceError:
        raise
    except ValueError as exc:
        raise R6ProductionAcceptanceError(str(exc)) from exc
    if set(by_id) != set(REQUIRED_R6_CASE_IDS):
        raise R6ProductionAcceptanceError("observations must cover the exact R6 case matrix")
    cases = [by_id[case_id] for case_id in REQUIRED_R6_CASE_IDS]
    for case in cases:
        case["environment_profile_id"] = checked["environment_profile_id"]
        case["environment_profile_sha256"] = checked["environment_profile_sha256"]
        case["source_revisions"] = checked["source_revisions"]
        case["tool_revisions"] = checked["tool_revisions"]
    statuses = {case["status"] for case in cases}
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "BLOCKED" in statuses:
        overall = "BLOCKED"
    elif "INCONCLUSIVE" in statuses:
        overall = "PARTIAL"
    else:
        overall = "PASS"
    execution_class = checked["execution_class"]
    return {
        "schema_version": "kcd2.r6-production-acceptance-receipt.v1",
        "receipt_id": _text(receipt_id, "receipt_id"),
        "task_id": "TEST-006",
        "execution_class": execution_class,
        "preserved_baseline_case_ids": list(LEGACY_R5_CASE_IDS),
        "environment_profile_id": checked["environment_profile_id"],
        "environment_profile_sha256": checked["environment_profile_sha256"],
        "authorization": checked,
        "started_at": started_at,
        "closed_at": closed_at,
        "source_revisions": checked["source_revisions"],
        "tool_revisions": checked["tool_revisions"],
        "cases": cases,
        "mutation_count": sum(case["mutation_count"] for case in cases),
        "unresolved_case_ids": [case["case_id"] for case in cases if case["status"] != "PASS"],
        "evidence_states": {
            "non_live": overall if execution_class == "non_live_fixture" else "NOT_RECORDED",
            "live_read_only": overall if execution_class == "live_read_only" else "NOT_RUN",
        },
        "overall_status": overall,
    }


__all__ = [
    "LEGACY_R5_CASE_IDS", "REQUIRED_R6_CASE_IDS", "R6ProductionAcceptanceError",
    "authorization_binding_sha256", "evaluate_r6_production_acceptance",
]
