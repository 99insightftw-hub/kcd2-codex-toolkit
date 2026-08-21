"""Bounded gameplay observation recording and before/after comparison."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from kcd2_toolchain_core.cross_tool_identity import (
    IdentityMismatchError,
    bind_cross_tool_identity,
)
from kcd2_toolchain_core.hashing import canonical_json_bytes, sha256_json


SCHEMA_VERSION = "kcd2.runtime-observation-session.v1"
COMPARISON_SCHEMA_VERSION = "kcd2.runtime-observation-comparison.v1"
MAX_STEPS = 512
MAX_ASSERTIONS = 2_048
DOMAINS = frozenset(
    {
        "inventory",
        "processing",
        "prompts",
        "animations",
        "items",
        "localization",
        "ui",
        "icons",
        "stats",
        "project_assertions",
    }
)
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_SESSION_FIELDS = {
    "schema_version",
    "session_id",
    "cross_tool_identity",
    "latest_boot_id",
    "candidate_sha256",
    "deployment_sha256",
    "source_sha256",
    "started_at",
    "closed_at",
    "matrix_id",
    "test_case",
    "steps",
    "assertions",
    "completeness",
    "result",
    "session_binding_sha256",
}
_STEP_FIELDS = {"sequence", "domain", "instruction", "expected", "actual", "status"}
_ASSERTION_FIELDS = {"domain", "name", "expected", "actual", "status"}
_STATUSES = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"}
_COMPLETENESS = {"COMPLETE", "INCOMPLETE", "TRUNCATED", "IDENTITY_DRIFT", "UNKNOWN"}


def _text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be non-empty text of at most {maximum} characters")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


def _finite_json(value: Any, field: str) -> Any:
    try:
        canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be finite JSON") from exc
    return copy.deepcopy(value)


def _timestamp(value: Any, field: str) -> tuple[str, datetime]:
    text = _text(value, field, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO 8601 timestamp with timezone") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return text, parsed


def _exact_fields(value: Mapping[str, Any], allowed: set[str], field: str) -> None:
    actual = set(value)
    if actual != allowed:
        raise ValueError(
            f"{field} fields do not match contract; "
            f"missing={sorted(allowed - actual)}, unknown={sorted(actual - allowed)}"
        )


def _normalize_status(value: Any, field: str) -> str:
    if value not in _STATUSES:
        raise ValueError(f"{field} must be one of {sorted(_STATUSES)}")
    return value


def _normalize_domain(value: Any, field: str) -> str:
    if value not in DOMAINS:
        raise ValueError(f"{field} is not a supported gameplay domain")
    return value


def _normalize_steps(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not values or len(values) > MAX_STEPS:
        raise ValueError(f"steps must contain from 1 through {MAX_STEPS} entries")
    result: list[dict[str, Any]] = []
    sequences: set[int] = set()
    for index, raw in enumerate(values):
        if not isinstance(raw, Mapping):
            raise TypeError(f"steps[{index}] must be a mapping")
        item = dict(raw)
        _exact_fields(item, _STEP_FIELDS, f"steps[{index}]")
        sequence = item["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError(f"steps[{index}].sequence must be a positive integer")
        if sequence in sequences:
            raise ValueError("step sequences must be unique")
        sequences.add(sequence)
        result.append(
            {
                "sequence": sequence,
                "domain": _normalize_domain(item["domain"], f"steps[{index}].domain"),
                "instruction": _text(item["instruction"], f"steps[{index}].instruction", 2048),
                "expected": _finite_json(item["expected"], f"steps[{index}].expected"),
                "actual": _finite_json(item["actual"], f"steps[{index}].actual"),
                "status": _normalize_status(item["status"], f"steps[{index}].status"),
            }
        )
    return sorted(result, key=lambda item: item["sequence"])


def _normalize_assertions(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list) or not values or len(values) > MAX_ASSERTIONS:
        raise ValueError(f"assertions must contain from 1 through {MAX_ASSERTIONS} entries")
    result: list[dict[str, Any]] = []
    keys: set[tuple[str, str]] = set()
    for index, raw in enumerate(values):
        if not isinstance(raw, Mapping):
            raise TypeError(f"assertions[{index}] must be a mapping")
        item = dict(raw)
        _exact_fields(item, _ASSERTION_FIELDS, f"assertions[{index}]")
        domain = _normalize_domain(item["domain"], f"assertions[{index}].domain")
        name = _text(item["name"], f"assertions[{index}].name", 256)
        key = (domain, name)
        if key in keys:
            raise ValueError("assertion domain/name keys must be unique")
        keys.add(key)
        result.append(
            {
                "domain": domain,
                "name": name,
                "expected": _finite_json(item["expected"], f"assertions[{index}].expected"),
                "actual": _finite_json(item["actual"], f"assertions[{index}].actual"),
                "status": _normalize_status(item["status"], f"assertions[{index}].status"),
            }
        )
    return sorted(result, key=lambda item: (item["domain"], item["name"]))


def _derived_result(completeness: str, statuses: list[str]) -> str:
    if completeness != "COMPLETE" or any(
        status in {"INCONCLUSIVE", "NOT_RUN"} for status in statuses
    ):
        return "INCONCLUSIVE"
    if "FAIL" in statuses:
        return "FAIL"
    return "PASS"


def record_gameplay_observation_session(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate, normalize, and bind one complete or explicitly incomplete playtest."""

    if not isinstance(value, Mapping):
        raise TypeError("gameplay observation session must be a mapping")
    supplied = copy.deepcopy(dict(value))
    optional = {"result", "session_binding_sha256"}
    actual = set(supplied)
    required = _SESSION_FIELDS - optional
    if not required <= actual or actual - _SESSION_FIELDS:
        raise ValueError(
            "session fields do not match contract; "
            f"missing={sorted(required - actual)}, unknown={sorted(actual - _SESSION_FIELDS)}"
        )
    if supplied["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    identity = bind_cross_tool_identity(supplied["cross_tool_identity"]).to_dict()
    candidate_sha256 = _digest(supplied["candidate_sha256"], "candidate_sha256")
    source_sha256 = _digest(supplied["source_sha256"], "source_sha256")
    candidate_id = identity["candidate_id"]
    if isinstance(candidate_id, str) and candidate_id.startswith("cand:sha256:"):
        if candidate_id.removeprefix("cand:sha256:").lower() != candidate_sha256:
            raise IdentityMismatchError("candidate_sha256 differs from cross-tool candidate_id")
    if identity["source"]["tree_sha256"].lower() != source_sha256:
        raise IdentityMismatchError("source_sha256 differs from cross-tool source tree")
    completeness = supplied["completeness"]
    if completeness not in _COMPLETENESS:
        raise ValueError(f"completeness must be one of {sorted(_COMPLETENESS)}")
    steps = _normalize_steps(supplied["steps"])
    assertions = _normalize_assertions(supplied["assertions"])
    started_at, started = _timestamp(supplied["started_at"], "started_at")
    closed_at, closed = _timestamp(supplied["closed_at"], "closed_at")
    if closed < started:
        raise ValueError("closed_at cannot precede started_at")
    result = _derived_result(
        completeness,
        [item["status"] for item in [*steps, *assertions]],
    )
    if supplied.get("result") is not None and supplied["result"] != result:
        raise ValueError("supplied result differs from the completeness/assertion-derived result")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "session_id": _text(supplied["session_id"], "session_id"),
        "cross_tool_identity": identity,
        "latest_boot_id": _text(supplied["latest_boot_id"], "latest_boot_id"),
        "candidate_sha256": candidate_sha256,
        "deployment_sha256": _digest(supplied["deployment_sha256"], "deployment_sha256"),
        "source_sha256": source_sha256,
        "started_at": started_at,
        "closed_at": closed_at,
        "matrix_id": _text(supplied["matrix_id"], "matrix_id"),
        "test_case": _text(supplied["test_case"], "test_case"),
        "steps": steps,
        "assertions": assertions,
        "completeness": completeness,
        "result": result,
    }
    binding = sha256_json(normalized)
    asserted = supplied.get("session_binding_sha256")
    if asserted is not None and _digest(asserted, "session_binding_sha256") != binding:
        raise IdentityMismatchError("session_binding_sha256 does not match session content")
    normalized["session_binding_sha256"] = binding
    return normalized


def compare_gameplay_observation_sessions(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    max_assertions: int = MAX_ASSERTIONS,
) -> dict[str, Any]:
    """Compare like-for-like assertions without turning incomplete coverage into a claim."""

    if (
        isinstance(max_assertions, bool)
        or not isinstance(max_assertions, int)
        or not 1 <= max_assertions <= MAX_ASSERTIONS
    ):
        raise ValueError(f"max_assertions must be from 1 through {MAX_ASSERTIONS}")
    left = record_gameplay_observation_session(before)
    right = record_gameplay_observation_session(after)
    reasons: list[str] = []
    if left["completeness"] != "COMPLETE" or right["completeness"] != "COMPLETE":
        reasons.append("INCOMPLETE_SESSION")
    if left["matrix_id"] != right["matrix_id"] or left["test_case"] != right["test_case"]:
        reasons.append("PLAYTEST_SCOPE_DRIFT")
    if left["cross_tool_identity"]["game"] != right["cross_tool_identity"]["game"]:
        reasons.append("GAME_BUILD_DRIFT")
    left_by_key = {(item["domain"], item["name"]): item for item in left["assertions"]}
    right_by_key = {(item["domain"], item["name"]): item for item in right["assertions"]}
    if set(left_by_key) != set(right_by_key):
        reasons.append("ASSERTION_SET_DRIFT")
    common_keys = sorted(set(left_by_key) & set(right_by_key))
    if any(left_by_key[key]["expected"] != right_by_key[key]["expected"] for key in common_keys):
        reasons.append("EXPECTED_VALUE_DRIFT")
    if reasons:
        return {
            "schema_version": COMPARISON_SCHEMA_VERSION,
            "before_session_id": left["session_id"],
            "after_session_id": right["session_id"],
            "status": "capture_inconclusive",
            "reasons": reasons,
            "changed": [],
            "unchanged": [],
            "counts": {"changed": 0, "unchanged": 0},
            "total_assertions": len(common_keys),
            "truncated": False,
        }
    changed: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    for key in common_keys:
        old = left_by_key[key]
        new = right_by_key[key]
        item = {
            "domain": key[0],
            "name": key[1],
            "expected": copy.deepcopy(new["expected"]),
            "before_actual": copy.deepcopy(old["actual"]),
            "after_actual": copy.deepcopy(new["actual"]),
            "before_status": old["status"],
            "after_status": new["status"],
        }
        target = (
            changed
            if (old["actual"], old["status"]) != (new["actual"], new["status"])
            else unchanged
        )
        target.append(item)
    combined = sorted(
        [("changed", item) for item in changed] + [("unchanged", item) for item in unchanged],
        key=lambda entry: (entry[1]["domain"], entry[1]["name"]),
    )
    retained = combined[:max_assertions]
    bounded_changed = [item for kind, item in retained if kind == "changed"]
    bounded_unchanged = [item for kind, item in retained if kind == "unchanged"]
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "before_session_id": left["session_id"],
        "after_session_id": right["session_id"],
        "status": "complete",
        "reasons": [],
        "changed": bounded_changed,
        "unchanged": bounded_unchanged,
        "counts": {"changed": len(bounded_changed), "unchanged": len(bounded_unchanged)},
        "total_assertions": len(combined),
        "truncated": len(combined) > max_assertions,
    }


__all__ = [
    "compare_gameplay_observation_sessions",
    "record_gameplay_observation_session",
]
