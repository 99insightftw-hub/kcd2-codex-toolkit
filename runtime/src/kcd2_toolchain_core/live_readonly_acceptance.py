"""Fail-closed evaluation for explicitly authorized live read-only acceptance."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any


REQUIRED_LIVE_READONLY_CASE_IDS = (
    "active_snapshot_freshness",
    "selected_mod_exact_scope",
    "targeted_refresh_dry_run_scope",
    "packaging_profile_consistency",
    "workshop_provider_state",
    "latest_boot_log_diagnosis",
    "exact_session_inspection",
    "public_catalog_visibility",
    "research_graph_discovery",
    "requested_output_limits",
    "cross_tool_identity_consistency",
)
_EXECUTION_CLASSES = frozenset({"non_live_fixture", "live_read_only"})
_CASE_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"})
_SHA256_LENGTH = 64
_MAX_TEXT = 2048
_MAX_IO_RECORDS = 4096
_MAX_REVISION_RECORDS = 64


class LiveReadOnlyAcceptanceError(ValueError):
    """An authorization or observation cannot support a bounded receipt."""


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LiveReadOnlyAcceptanceError("document is not canonical JSON") from exc


def authorization_binding_sha256(authorization: Mapping[str, object]) -> str:
    """Bind every authorization field except its self-referential digest."""
    payload = dict(_mapping(authorization, "authorization"))
    payload.pop("binding_sha256", None)
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise LiveReadOnlyAcceptanceError(f"{field} must be an object")
    return value


def _text(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise LiveReadOnlyAcceptanceError(f"{field} must be bounded non-empty text")
    return value


def _sha256(value: object, field: str) -> str:
    text = _text(value, field).lower()
    if len(text) != _SHA256_LENGTH or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise LiveReadOnlyAcceptanceError(f"{field} must be a SHA-256 digest")
    return text


def _timestamp(value: object, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LiveReadOnlyAcceptanceError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise LiveReadOnlyAcceptanceError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _revision_map(value: object, field: str) -> dict[str, str]:
    source = _mapping(value, field)
    if not source or len(source) > _MAX_REVISION_RECORDS:
        raise LiveReadOnlyAcceptanceError(
            f"{field} must contain 1 through {_MAX_REVISION_RECORDS} records"
        )
    return {
        _text(key, f"{field} key"): _sha256(digest, f"{field}.{key}")
        for key, digest in sorted(source.items())
    }


def _text_list(value: object, field: str, *, nonempty: bool) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise LiveReadOnlyAcceptanceError(f"{field} must be an array")
    if len(value) > _MAX_IO_RECORDS or (nonempty and not value):
        raise LiveReadOnlyAcceptanceError(f"{field} violates its item bound")
    return [_text(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _hash_records(value: object, field: str) -> list[dict[str, str]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise LiveReadOnlyAcceptanceError(f"{field} must be an array")
    if not value or len(value) > _MAX_IO_RECORDS:
        raise LiveReadOnlyAcceptanceError(f"{field} violates its item bound")
    records: list[dict[str, str]] = []
    for index, item in enumerate(value):
        record = _mapping(item, f"{field}[{index}]")
        if set(record) != {"subject", "sha256"}:
            raise LiveReadOnlyAcceptanceError(
                f"{field}[{index}] must contain only subject and sha256"
            )
        records.append(
            {
                "subject": _text(record["subject"], f"{field}[{index}].subject"),
                "sha256": _sha256(record["sha256"], f"{field}[{index}].sha256"),
            }
        )
    return records


def _validate_authorization(value: Mapping[str, object]) -> dict[str, Any]:
    authorization = dict(_mapping(value, "authorization"))
    required = {
        "schema_version",
        "authorization_id",
        "execution_class",
        "environment_profile_id",
        "environment_profile_sha256",
        "authorized_at",
        "expires_at",
        "case_ids",
        "source_revisions",
        "tool_revisions",
        "binding_sha256",
    }
    if set(authorization) != required:
        raise LiveReadOnlyAcceptanceError("authorization fields are incomplete or unknown")
    if authorization["schema_version"] != "kcd2.live-readonly-authorization.v1":
        raise LiveReadOnlyAcceptanceError("authorization schema_version is invalid")
    execution_class = authorization["execution_class"]
    if execution_class not in _EXECUTION_CLASSES:
        raise LiveReadOnlyAcceptanceError("authorization execution_class is invalid")
    case_ids = _text_list(authorization["case_ids"], "authorization.case_ids", nonempty=True)
    if tuple(case_ids) != REQUIRED_LIVE_READONLY_CASE_IDS:
        raise LiveReadOnlyAcceptanceError("authorization must name the exact required case matrix")
    expected_binding = authorization_binding_sha256(authorization)
    supplied_binding = _sha256(
        authorization["binding_sha256"], "authorization.binding_sha256"
    )
    if supplied_binding != expected_binding:
        raise LiveReadOnlyAcceptanceError("authorization binding does not match its content")
    return {
        "schema_version": authorization["schema_version"],
        "authorization_id": _text(
            authorization["authorization_id"], "authorization.authorization_id"
        ),
        "execution_class": execution_class,
        "environment_profile_id": _text(
            authorization["environment_profile_id"],
            "authorization.environment_profile_id",
        ),
        "environment_profile_sha256": _sha256(
            authorization["environment_profile_sha256"],
            "authorization.environment_profile_sha256",
        ),
        "authorized_at": _text(authorization["authorized_at"], "authorization.authorized_at"),
        "expires_at": _text(authorization["expires_at"], "authorization.expires_at"),
        "case_ids": case_ids,
        "source_revisions": _revision_map(
            authorization["source_revisions"], "authorization.source_revisions"
        ),
        "tool_revisions": _revision_map(
            authorization["tool_revisions"], "authorization.tool_revisions"
        ),
        "binding_sha256": supplied_binding,
    }


def _evaluate_observation(value: Mapping[str, object]) -> dict[str, Any]:
    observation = _mapping(value, "observation")
    required = {
        "case_id",
        "status",
        "reads",
        "writes",
        "input_hashes",
        "output_hashes",
        "protected_state_before",
        "protected_state_after",
        "notes",
    }
    if set(observation) != required:
        raise LiveReadOnlyAcceptanceError("observation fields are incomplete or unknown")
    case_id = _text(observation["case_id"], "observation.case_id")
    status = observation["status"]
    if status not in _CASE_STATUSES:
        raise LiveReadOnlyAcceptanceError(f"observation status is invalid for {case_id}")
    reads = _text_list(observation["reads"], f"{case_id}.reads", nonempty=True)
    writes = _text_list(observation["writes"], f"{case_id}.writes", nonempty=False)
    before = _revision_map(
        observation["protected_state_before"], f"{case_id}.protected_state_before"
    )
    after = _revision_map(
        observation["protected_state_after"], f"{case_id}.protected_state_after"
    )
    drifted = sorted(
        subject for subject in set(before) | set(after) if before.get(subject) != after.get(subject)
    )
    mutation_count = len(writes) + len(drifted)
    if mutation_count:
        status = "FAIL"
    return {
        "case_id": case_id,
        "status": status,
        "input_hashes": _hash_records(observation["input_hashes"], f"{case_id}.input_hashes"),
        "output_hashes": _hash_records(
            observation["output_hashes"], f"{case_id}.output_hashes"
        ),
        "reads": reads,
        "writes": writes,
        "protected_state_before": before,
        "protected_state_after": after,
        "drifted_protected_subjects": drifted,
        "mutation_count": mutation_count,
        "notes": _text(observation["notes"], f"{case_id}.notes"),
    }


def evaluate_live_readonly_acceptance(
    *,
    authorization: Mapping[str, object],
    observations: Sequence[Mapping[str, object]],
    receipt_id: str,
    started_at: str,
    closed_at: str,
) -> dict[str, Any]:
    """Return a deterministic receipt without performing or authorizing any I/O."""
    checked_authorization = _validate_authorization(authorization)
    started = _timestamp(started_at, "started_at")
    closed = _timestamp(closed_at, "closed_at")
    authorized = _timestamp(checked_authorization["authorized_at"], "authorized_at")
    expires = _timestamp(checked_authorization["expires_at"], "expires_at")
    if not authorized <= started <= closed <= expires:
        raise LiveReadOnlyAcceptanceError(
            "receipt interval is outside the authorization interval"
        )
    if isinstance(observations, (str, bytes)) or not isinstance(observations, Sequence):
        raise LiveReadOnlyAcceptanceError("observations must be an array")
    evaluated_by_id: dict[str, dict[str, Any]] = {}
    for observation in observations:
        evaluated = _evaluate_observation(observation)
        case_id = evaluated["case_id"]
        if case_id in evaluated_by_id:
            raise LiveReadOnlyAcceptanceError(f"duplicate observation for {case_id}")
        evaluated_by_id[case_id] = evaluated
    if set(evaluated_by_id) != set(REQUIRED_LIVE_READONLY_CASE_IDS):
        raise LiveReadOnlyAcceptanceError("observations must cover the exact required case matrix")
    cases = [evaluated_by_id[case_id] for case_id in REQUIRED_LIVE_READONLY_CASE_IDS]
    for case in cases:
        case["environment_profile_id"] = checked_authorization["environment_profile_id"]
        case["environment_profile_sha256"] = checked_authorization[
            "environment_profile_sha256"
        ]
        case["source_revisions"] = checked_authorization["source_revisions"]
        case["tool_revisions"] = checked_authorization["tool_revisions"]
    unresolved = [case["case_id"] for case in cases if case["status"] != "PASS"]
    statuses = {case["status"] for case in cases}
    if "FAIL" in statuses:
        overall = "FAIL"
    elif "BLOCKED" in statuses:
        overall = "BLOCKED"
    elif "INCONCLUSIVE" in statuses:
        overall = "PARTIAL"
    else:
        overall = "PASS"
    execution_class = checked_authorization["execution_class"]
    evidence_states = {
        "non_live": overall if execution_class == "non_live_fixture" else "NOT_RECORDED",
        "live_read_only": overall if execution_class == "live_read_only" else "NOT_RUN",
    }
    return {
        "schema_version": "kcd2.live-readonly-acceptance-receipt.v1",
        "receipt_id": _text(receipt_id, "receipt_id"),
        "execution_class": execution_class,
        "environment_profile_id": checked_authorization["environment_profile_id"],
        "environment_profile_sha256": checked_authorization["environment_profile_sha256"],
        "authorization": checked_authorization,
        "started_at": started_at,
        "closed_at": closed_at,
        "source_revisions": checked_authorization["source_revisions"],
        "tool_revisions": checked_authorization["tool_revisions"],
        "cases": cases,
        "mutation_count": sum(case["mutation_count"] for case in cases),
        "unresolved_case_ids": unresolved,
        "evidence_states": evidence_states,
        "overall_status": overall,
    }


__all__ = [
    "REQUIRED_LIVE_READONLY_CASE_IDS",
    "LiveReadOnlyAcceptanceError",
    "authorization_binding_sha256",
    "evaluate_live_readonly_acceptance",
]
