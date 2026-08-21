"""Bounded AI/quest runtime marker adaptation and persistence assertions."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 8192
_MAX_EVENTS = 100_000
_MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
_MAX_DURATION_NS = 24 * 60 * 60 * 1_000_000_000
_MARKER_KINDS = (
    "graph_entry",
    "condition_result",
    "branch_selected",
    "entity_resolved",
    "role_resolved",
    "spawned",
    "action_requested",
    "action_result",
    "state_mutated",
    "save_started",
    "save_completed",
    "load_started",
    "load_completed",
    "persistence_checked",
    "despawned",
    "graph_exit",
)
_EVENT_KINDS = frozenset((*_MARKER_KINDS, "session_cleanup"))
_SOURCE_HEALTH = frozenset(
    {"healthy", "partial", "dropped_events", "truncated", "unavailable"}
)


class AIQuestRuntimeError(ValueError):
    """A capture violates the reviewed AI/quest runtime adapter contract."""


def _text(value: object, name: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > maximum:
        raise AIQuestRuntimeError(f"{name} must be non-empty bounded text without NUL")
    return value


def _timestamp(value: object, name: str) -> str:
    checked = _text(value, name, 128)
    try:
        parsed = datetime.fromisoformat(checked.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AIQuestRuntimeError(f"{name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AIQuestRuntimeError(f"{name} must include a timezone")
    return checked


def _integer(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise AIQuestRuntimeError(f"{name} must be an integer from 0 through {maximum}")
    return value


def _mapping(value: object, name: str, fields: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AIQuestRuntimeError(f"{name} fields do not match the contract")
    return value


def _array(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AIQuestRuntimeError(f"{name} must be an array")
    if len(value) > maximum:
        raise AIQuestRuntimeError(f"{name} exceeds the {maximum}-item hard bound")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AIQuestRuntimeError("capture values must be finite JSON") from exc


def _identity_list(value: object, name: str) -> list[str]:
    values = _array(value, name, 4096)
    result = [_text(item, f"{name} item", 2048) for item in values]
    if len(result) != len(set(result)):
        raise AIQuestRuntimeError(f"{name} must contain unique identities")
    return result


def _stable_id(session_id: str, event_id: str) -> str:
    digest = hashlib.sha256(f"{session_id}\0{event_id}".encode()).hexdigest()[:24]
    return f"runtime:{digest}"


def adapt_ai_quest_runtime(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a passive capture and emit deterministic stage/persistence assertions."""

    top = _mapping(
        value,
        "capture",
        {
            "schema_version",
            "session",
            "deployment_identity",
            "capture",
            "limits",
            "expected",
            "events",
        },
    )
    if top["schema_version"] != "kcd2.ai-quest-runtime-capture.v1":
        raise AIQuestRuntimeError("capture schema_version is unsupported")
    session = _mapping(
        top["session"], "session", {"session_id", "experiment_id", "graph_id"}
    )
    session_id = _text(session["session_id"], "session_id", 1024)
    experiment_id = _text(session["experiment_id"], "experiment_id", 1024)
    graph_id = _text(session["graph_id"], "graph_id", 1024)

    deployment = _mapping(
        top["deployment_identity"],
        "deployment_identity",
        {
            "binding_state",
            "deployment_id",
            "candidate_id",
            "active_snapshot_sha256",
            "deployment_identity_sha256",
            "close_deployment_identity_sha256",
        },
    )
    if deployment["binding_state"] != "EXACT":
        raise AIQuestRuntimeError("deployment binding_state must be EXACT")
    for field in ("deployment_id", "candidate_id"):
        _text(deployment[field], f"deployment_identity.{field}", 1024)
    for field in (
        "active_snapshot_sha256",
        "deployment_identity_sha256",
        "close_deployment_identity_sha256",
    ):
        if not isinstance(deployment[field], str) or _SHA256.fullmatch(deployment[field]) is None:
            raise AIQuestRuntimeError(f"deployment_identity.{field} must be a lowercase SHA-256")
    if deployment["deployment_identity_sha256"] != deployment["close_deployment_identity_sha256"]:
        raise AIQuestRuntimeError("deployment identity changed between capture start and close")

    capture = _mapping(
        top["capture"],
        "capture health",
        {"source_health", "capture_complete", "filter_valid", "correlation_valid"},
    )
    if capture["source_health"] not in _SOURCE_HEALTH:
        raise AIQuestRuntimeError("capture.source_health is unsupported")
    for field in ("capture_complete", "filter_valid", "correlation_valid"):
        if not isinstance(capture[field], bool):
            raise AIQuestRuntimeError(f"capture.{field} must be a boolean")

    limits = _mapping(
        top["limits"],
        "limits",
        {"maximum_events", "maximum_payload_bytes", "maximum_session_duration_ns"},
    )
    maximum_events = _integer(limits["maximum_events"], "maximum_events", _MAX_EVENTS)
    maximum_payload_bytes = _integer(
        limits["maximum_payload_bytes"], "maximum_payload_bytes", _MAX_PAYLOAD_BYTES
    )
    maximum_duration = _integer(
        limits["maximum_session_duration_ns"],
        "maximum_session_duration_ns",
        _MAX_DURATION_NS,
    )
    if min(maximum_events, maximum_payload_bytes, maximum_duration) < 1:
        raise AIQuestRuntimeError("capture limits must be positive")

    expected = _mapping(
        top["expected"],
        "expected",
        {"entity_identity_keys", "role_identity_keys", "persistence_state_identity_keys"},
    )
    expected_entities = _identity_list(expected["entity_identity_keys"], "entity_identity_keys")
    expected_roles = _identity_list(expected["role_identity_keys"], "role_identity_keys")
    expected_states = _identity_list(
        expected["persistence_state_identity_keys"], "persistence_state_identity_keys"
    )

    raw_events = _array(top["events"], "events (maximum_events)", maximum_events)
    if not raw_events:
        raise AIQuestRuntimeError("events must contain at least one marker")
    events: list[dict[str, Any]] = []
    payload_bytes = 0
    prior_sequence = -1
    prior_ns = -1
    event_ids: set[str] = set()
    for index, raw in enumerate(raw_events):
        event = _mapping(
            raw,
            f"events[{index}]",
            {
                "event_id",
                "session_id",
                "sequence",
                "monotonic_ns",
                "observed_at",
                "marker_kind",
                "node_ids",
                "edge_ids",
                "payload",
            },
        )
        event_id = _text(event["event_id"], f"events[{index}].event_id", 1024)
        if event_id in event_ids:
            raise AIQuestRuntimeError("event_id values must be unique")
        event_ids.add(event_id)
        if event["session_id"] != session_id:
            raise AIQuestRuntimeError(f"events[{index}].session_id does not match session")
        sequence = _integer(event["sequence"], f"events[{index}].sequence", 2**63 - 1)
        monotonic_ns = _integer(
            event["monotonic_ns"], f"events[{index}].monotonic_ns", 2**63 - 1
        )
        if sequence <= prior_sequence:
            raise AIQuestRuntimeError("event sequence must be strictly increasing")
        if monotonic_ns < prior_ns:
            raise AIQuestRuntimeError("event monotonic_ns must be nondecreasing")
        prior_sequence, prior_ns = sequence, monotonic_ns
        kind = event["marker_kind"]
        if kind not in _EVENT_KINDS:
            raise AIQuestRuntimeError(f"events[{index}].marker_kind is unsupported")
        node_ids = _identity_list(event["node_ids"], f"events[{index}].node_ids")
        edge_ids = _identity_list(event["edge_ids"], f"events[{index}].edge_ids")
        if not isinstance(event["payload"], Mapping):
            raise AIQuestRuntimeError(f"events[{index}].payload must be an object")
        payload = copy.deepcopy(dict(event["payload"]))
        payload_bytes += len(_canonical_bytes(payload))
        events.append(
            {
                "event_id": event_id,
                "session_id": session_id,
                "sequence": sequence,
                "monotonic_ns": monotonic_ns,
                "observed_at": _timestamp(event["observed_at"], f"events[{index}].observed_at"),
                "marker_kind": kind,
                "node_ids": node_ids,
                "edge_ids": edge_ids,
                "payload": payload,
            }
        )
    if payload_bytes > maximum_payload_bytes:
        raise AIQuestRuntimeError("event payloads exceed maximum_payload_bytes")
    duration_ns = events[-1]["monotonic_ns"] - events[0]["monotonic_ns"]
    if duration_ns > maximum_duration:
        raise AIQuestRuntimeError("capture exceeds maximum_session_duration_ns")

    reasons: set[str] = set()
    if capture["source_health"] != "healthy":
        reasons.add("CAPTURE_SOURCE_UNHEALTHY")
    if not capture["capture_complete"]:
        reasons.add("CAPTURE_INCOMPLETE")
    if not capture["filter_valid"]:
        reasons.add("CAPTURE_FILTER_INVALID")
    if not capture["correlation_valid"]:
        reasons.add("CAPTURE_CORRELATION_INVALID")

    by_kind: dict[str, list[dict[str, Any]]] = {
        kind: [event for event in events if event["marker_kind"] == kind]
        for kind in _EVENT_KINDS
    }
    assertions: list[dict[str, Any]] = []
    for stage in _MARKER_KINDS:
        observed = by_kind[stage]
        reason = None if observed else f"{stage.upper()}_UNOBSERVED"
        if stage == "action_result" and not observed:
            reason = "ACTION_RESULT_UNOBSERVED"
        if reason:
            reasons.add(reason)
        assertions.append(
            {
                "stage": stage,
                "status": "observed" if observed else "unresolved",
                "first_sequence": observed[0]["sequence"] if observed else None,
                "marker_ids": [_stable_id(session_id, item["event_id"]) for item in observed],
                "reason_code": reason,
            }
        )

    observed_stage_sequences = [
        item["first_sequence"] for item in assertions if item["first_sequence"] is not None
    ]
    if observed_stage_sequences != sorted(observed_stage_sequences):
        reasons.add("STAGE_SEQUENCE_INVALID")

    requested_action_ids = {
        event["payload"].get("action_id") for event in by_kind["action_requested"]
    }
    if any(
        event["payload"].get("action_id") not in requested_action_ids
        for event in by_kind["action_result"]
    ):
        reasons.add("ACTION_RESULT_UNCORRELATED")

    resolution_requirements = (
        ("entity_resolved", "entity_identity_key", expected_entities),
        ("role_resolved", "role_identity_key", expected_roles),
    )
    for kind, field, identities in resolution_requirements:
        observed = {event["payload"].get(field) for event in by_kind[kind]}
        if any(identity not in observed for identity in identities):
            reasons.add(f"EXPECTED_{kind.upper()}_MISSING")

    persistence_checks: list[dict[str, Any]] = []
    for state_identity in expected_states:
        state_reasons: set[str] = set()
        mutation = next(
            (
                event
                for event in by_kind["state_mutated"]
                if event["payload"].get("state_identity_key") == state_identity
            ),
            None,
        )
        save_start = by_kind["save_started"][0] if by_kind["save_started"] else None
        save_end = by_kind["save_completed"][0] if by_kind["save_completed"] else None
        load_start = by_kind["load_started"][0] if by_kind["load_started"] else None
        load_end = by_kind["load_completed"][0] if by_kind["load_completed"] else None
        check = next(
            (
                event
                for event in by_kind["persistence_checked"]
                if event["payload"].get("state_identity_key") == state_identity
                and event["payload"].get("result") == "verified"
            ),
            None,
        )
        required = (
            (mutation, "STATE_MUTATION_UNOBSERVED"),
            (save_start, "SAVE_START_UNOBSERVED"),
            (save_end, "SAVE_COMPLETION_UNOBSERVED"),
            (load_start, "LOAD_START_UNOBSERVED"),
            (load_end, "LOAD_COMPLETION_UNOBSERVED"),
            (check, "PERSISTENCE_CHECK_UNVERIFIED"),
        )
        state_reasons.update(reason for event, reason in required if event is None)
        if mutation is not None and check is not None:
            mutation_digest = mutation["payload"].get("value_digest")
            checked_digest = check["payload"].get("value_digest")
            if (
                not isinstance(mutation_digest, str)
                or _SHA256.fullmatch(mutation_digest) is None
                or checked_digest != mutation_digest
            ):
                state_reasons.add("PERSISTED_VALUE_MISMATCH")
        save_ids = {
            event["payload"].get("save_correlation_id")
            for event in (save_start, save_end, load_start, load_end)
            if event is not None
        }
        if len(save_ids) > 1 or (save_ids and None in save_ids):
            state_reasons.add("SAVE_LOAD_CORRELATION_INVALID")
        ordered = [event["sequence"] for event, _reason in required if event is not None]
        if len(ordered) == len(required) and ordered != sorted(ordered):
            state_reasons.add("PERSISTENCE_SEQUENCE_INVALID")
        reasons.update(state_reasons)
        persistence_checks.append(
            {
                "state_identity_key": state_identity,
                "status": "verified" if not state_reasons else "unresolved",
                "reason_codes": sorted(state_reasons),
            }
        )
    persistence_status = (
        "verified"
        if persistence_checks and all(item["status"] == "verified" for item in persistence_checks)
        else "unresolved"
    )
    persistence_reasons = sorted(
        {reason for item in persistence_checks for reason in item["reason_codes"]}
    )
    if not expected_states:
        persistence_reasons = ["NO_PERSISTENCE_STATE_DECLARED"]
        reasons.update(persistence_reasons)

    cleanup_events = by_kind["session_cleanup"]
    cleanup_event = cleanup_events[-1] if cleanup_events else None
    cleanup_counts = {"active_hooks": None, "active_listeners": None, "buffered_events": None}
    cleanup_complete = False
    debugger_state = None
    if cleanup_event is not None:
        cleanup_counts = {
            field: cleanup_event["payload"].get(field)
            for field in ("active_hooks", "active_listeners", "buffered_events")
        }
        debugger_state = cleanup_event["payload"].get("debugger_state")
        cleanup_complete = (
            all(value == 0 for value in cleanup_counts.values())
            and debugger_state in {"unavailable", "running", "detached"}
            and cleanup_event is events[-1]
        )
    if not cleanup_complete:
        reasons.add("SESSION_CLEANUP_INCOMPLETE")

    status = "complete" if not reasons else "capture_inconclusive"
    markers = [
        {
            "marker_id": _stable_id(session_id, event["event_id"]),
            "evidence_layer": "runtime",
            "marker_kind": event["marker_kind"],
            "session_id": session_id,
            "sequence": event["sequence"],
            "node_ids": event["node_ids"],
            "edge_ids": event["edge_ids"],
            "source_health": capture["source_health"],
            "observed_at": event["observed_at"],
            "exact_locator": f"runtime-session://{session_id}/events/{event['event_id']}",
            "payload": event["payload"],
        }
        for event in events
        if event["marker_kind"] != "session_cleanup"
    ]
    permitted_claims: list[str] = []
    if status == "complete":
        permitted_claims.extend(["npc_action_path_observed", "capture_complete_in_declared_scope"])
    if persistence_status == "verified" and status == "complete":
        permitted_claims.append("state_persistence_verified")
    if cleanup_complete:
        permitted_claims.append("session_cleanup_complete")
    return {
        "schema_version": "kcd2.ai-quest-runtime-receipt.v1",
        "status": status,
        "session": {
            "session_id": session_id,
            "experiment_id": experiment_id,
            "graph_id": graph_id,
        },
        "deployment_identity": copy.deepcopy(dict(deployment)),
        "capture_health": copy.deepcopy(dict(capture)),
        "capture_limits": copy.deepcopy(dict(limits)),
        "capture_usage": {
            "event_count": len(events),
            "payload_bytes": payload_bytes,
            "session_duration_ns": duration_ns,
        },
        "absence_claim_allowed": status == "complete",
        "event_counts": dict(sorted(Counter(event["marker_kind"] for event in events).items())),
        "runtime_markers": markers,
        "session_assertions": assertions,
        "persistence": {
            "status": persistence_status,
            "checks": persistence_checks,
            "reason_codes": persistence_reasons,
        },
        "cleanup": {
            "status": "complete" if cleanup_complete else "incomplete",
            **cleanup_counts,
            "debugger_state": debugger_state,
        },
        "permitted_claims": sorted(permitted_claims),
        "reason_codes": sorted(reasons),
    }


__all__ = ["AIQuestRuntimeError", "adapt_ai_quest_runtime"]
