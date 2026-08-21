"""Bounded observation-only audio and haptic runtime event adapter."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA_VERSION = "kcd2.audio-haptic-runtime-receipt.v1"
MAX_EVENTS = 4096
MAX_PAYLOAD_BYTES = 4096
MAX_TEXT = 512
_ROOT_FIELDS = {
    "session_id",
    "experiment_id",
    "active_snapshot_id",
    "adapter",
    "limits",
    "events",
}
_ADAPTER_FIELDS = {
    "adapter_id",
    "observation_mode",
    "action_map_unchanged",
    "input_synthesis",
    "input_consumption",
    "control_output",
    "dualsense_proof",
}
_PROOF_FIELDS = {
    "status",
    "evidence_layer",
    "capture_complete",
    "correlation_valid",
    "reference",
}
_LIMIT_FIELDS = {
    "maximum_events",
    "maximum_payload_bytes",
    "maximum_duration_ms",
    "maximum_overlap_pairs",
}
_EVENT_FIELDS = {
    "schema_version",
    "session_id",
    "experiment_id",
    "domain",
    "event_type",
    "monotonic_ns",
    "source_health",
    "identity",
    "payload",
    "cleanup_state",
}
_EVENT_PAYLOAD_FIELDS = {
    "EVENT_FIRED": {"request_id", "resource_kind"},
    "ROUTE_SELECTED": {"request_id", "route_id"},
    "REQUEST_ADMITTED": {"request_id"},
    "REQUEST_REJECTED": {"request_id", "reason"},
    "HAPTIC_STARTED": {"request_id", "controller_type", "duration_ms", "intensity"},
    "HAPTIC_ENDED": {"request_id"},
    "FALLBACK_SELECTED": {"request_id", "from_route_id", "to_route_id"},
    "SESSION_CLEANUP": set(),
}
_REASON_ORDER = (
    "SOURCE_HEALTH_INCOMPLETE",
    "REQUEST_LIFECYCLE_INCOMPLETE",
    "CAPTURE_CLEANUP_INCOMPLETE",
    "OVERLAP_PAIR_LIMIT_REACHED",
    "DUALSENSE_PRESERVATION_UNPROVEN",
)


class AudioHapticRuntimeError(ValueError):
    """The passive runtime input violates a safety or bounded-data contract."""


def _mapping(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AudioHapticRuntimeError(f"{name} must be a mapping")
    result = dict(value)
    if set(result) != fields:
        raise AudioHapticRuntimeError(f"{name} fields do not match the contract")
    return result


def _text(value: Any, name: str, maximum: int = MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\x00" in value
        or len(value) > maximum
    ):
        raise AudioHapticRuntimeError(f"{name} must be non-empty bounded NUL-free text")
    return value


def _boolean(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise AudioHapticRuntimeError(f"{name} must be boolean")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AudioHapticRuntimeError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _proof(value: Any) -> tuple[dict[str, Any], bool]:
    proof = _mapping(value, _PROOF_FIELDS, "adapter.dualsense_proof")
    if proof["status"] not in {"proven", "unproven"}:
        raise AudioHapticRuntimeError("adapter.dualsense_proof.status is unsupported")
    if proof["evidence_layer"] not in {"static", "runtime", "user_confirmed", "causal"}:
        raise AudioHapticRuntimeError("adapter.dualsense_proof.evidence_layer is unsupported")
    complete = _boolean(proof["capture_complete"], "dualsense_proof.capture_complete")
    correlated = _boolean(proof["correlation_valid"], "dualsense_proof.correlation_valid")
    _text(proof["reference"], "dualsense_proof.reference")
    sufficient = (
        proof["status"] == "proven"
        and proof["evidence_layer"] in {"runtime", "causal"}
        and complete
        and correlated
    )
    return proof, sufficient


def _adapter(value: Any) -> tuple[dict[str, Any], dict[str, Any], bool]:
    adapter = _mapping(value, _ADAPTER_FIELDS, "adapter")
    adapter_id = _text(adapter["adapter_id"], "adapter.adapter_id")
    failures: list[str] = []
    if adapter["observation_mode"] != "existing_event_stream_only":
        failures.append("PASSIVE_OBSERVATION_REQUIRED")
    if not _boolean(adapter["action_map_unchanged"], "adapter.action_map_unchanged"):
        failures.append("ACTION_MAP_MUTATION_FORBIDDEN")
    if _boolean(adapter["input_synthesis"], "adapter.input_synthesis"):
        failures.append("INPUT_SYNTHESIS_FORBIDDEN")
    if _boolean(adapter["input_consumption"], "adapter.input_consumption"):
        failures.append("INPUT_CONSUMPTION_FORBIDDEN")
    if _boolean(adapter["control_output"], "adapter.control_output"):
        failures.append("CONTROL_OUTPUT_FORBIDDEN")
    if failures:
        raise AudioHapticRuntimeError(",".join(failures))
    proof, sufficient = _proof(adapter["dualsense_proof"])
    safety = {
        "passive": True,
        "action_map_unchanged": True,
        "input_not_synthesized": True,
        "input_not_consumed": True,
        "no_control_output": True,
    }
    return {"adapter_id": adapter_id, **safety}, proof, sufficient


def _limits(value: Any) -> dict[str, int]:
    limits = _mapping(value, _LIMIT_FIELDS, "limits")
    return {
        "maximum_events": _integer(limits["maximum_events"], "maximum_events", 1, MAX_EVENTS),
        "maximum_payload_bytes": _integer(
            limits["maximum_payload_bytes"], "maximum_payload_bytes", 64, MAX_PAYLOAD_BYTES
        ),
        "maximum_duration_ms": _integer(
            limits["maximum_duration_ms"], "maximum_duration_ms", 1, 600_000
        ),
        "maximum_overlap_pairs": _integer(
            limits["maximum_overlap_pairs"], "maximum_overlap_pairs", 1, 65_536
        ),
    }


def _event(
    value: Any,
    index: int,
    session_id: str,
    experiment_id: str,
    limits: Mapping[str, int],
) -> dict[str, Any]:
    event = _mapping(value, _EVENT_FIELDS, f"events[{index}]")
    if event["schema_version"] != "kcd2.runtime-domain-event.v1":
        raise AudioHapticRuntimeError(f"events[{index}].schema_version is unsupported")
    if event["session_id"] != session_id or event["experiment_id"] != experiment_id:
        raise AudioHapticRuntimeError(f"events[{index}] session or experiment identity differs")
    if event["domain"] != "AUDIO_HAPTIC":
        raise AudioHapticRuntimeError(f"events[{index}].domain must be AUDIO_HAPTIC")
    event_type = event["event_type"]
    if event_type not in _EVENT_PAYLOAD_FIELDS:
        raise AudioHapticRuntimeError(f"events[{index}].event_type is unsupported")
    monotonic_ns = _integer(event["monotonic_ns"], f"events[{index}].monotonic_ns", 0, 2**63 - 1)
    if event["source_health"] not in {
        "HEALTHY",
        "PARTIAL",
        "DROPPED_EVENTS",
        "TRUNCATED",
        "UNAVAILABLE",
    }:
        raise AudioHapticRuntimeError(f"events[{index}].source_health is unsupported")
    identity = event["identity"]
    if not isinstance(identity, Mapping) or set(identity) != {"resource_id"}:
        raise AudioHapticRuntimeError(f"events[{index}].identity must contain only resource_id")
    resource_id = _text(identity["resource_id"], f"events[{index}].identity.resource_id")
    payload = _mapping(
        event["payload"], _EVENT_PAYLOAD_FIELDS[event_type], f"events[{index}].payload"
    )
    try:
        payload_size = len(
            json.dumps(payload, allow_nan=False, sort_keys=True, separators=(",", ":")).encode()
        )
    except (TypeError, ValueError) as exc:
        raise AudioHapticRuntimeError(f"events[{index}].payload must be finite JSON") from exc
    if payload_size > limits["maximum_payload_bytes"]:
        raise AudioHapticRuntimeError(f"events[{index}].payload exceeds maximum_payload_bytes")
    for field in payload:
        if field in {"duration_ms", "intensity"}:
            continue
        _text(payload[field], f"events[{index}].payload.{field}")
    if event_type == "HAPTIC_STARTED":
        _integer(payload["duration_ms"], "duration_ms", 0, limits["maximum_duration_ms"])
        intensity = payload["intensity"]
        if (
            isinstance(intensity, bool)
            or not isinstance(intensity, (int, float))
            or not 0 <= intensity <= 1
        ):
            raise AudioHapticRuntimeError("intensity must be a finite number from 0 through 1")
    cleanup_state = event["cleanup_state"]
    if cleanup_state is not None:
        _text(cleanup_state, f"events[{index}].cleanup_state")
    if event_type == "SESSION_CLEANUP" and cleanup_state is None:
        raise AudioHapticRuntimeError("SESSION_CLEANUP requires cleanup_state")
    return {
        "event_type": event_type,
        "monotonic_ns": monotonic_ns,
        "source_health": event["source_health"],
        "resource_id": resource_id,
        "payload": copy.deepcopy(payload),
        "cleanup_state": cleanup_state,
    }


def _new_request(request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "fired_resource_id": None,
        "resource_kind": None,
        "selected_route_id": None,
        "admission": "unresolved",
        "rejection_reason": None,
        "controller_type": None,
        "duration_ms": None,
        "intensity": None,
        "fallback_route_id": None,
        "started_ns": None,
        "ended_ns": None,
        "cleanup_state": "unresolved",
    }


def adapt_audio_haptic_runtime(value: Mapping[str, Any]) -> dict[str, Any]:
    """Correlate a pre-existing event stream without an input or haptic control surface."""

    root = _mapping(value, _ROOT_FIELDS, "audio haptic runtime input")
    session_id = _text(root["session_id"], "session_id")
    experiment_id = _text(root["experiment_id"], "experiment_id")
    active_snapshot_id = _text(root["active_snapshot_id"], "active_snapshot_id")
    adapter, proof, proof_sufficient = _adapter(root["adapter"])
    limits = _limits(root["limits"])
    raw_events = root["events"]
    if isinstance(raw_events, (str, bytes)) or not isinstance(raw_events, Sequence):
        raise AudioHapticRuntimeError("events must be a sequence")
    if not raw_events or len(raw_events) > limits["maximum_events"]:
        raise AudioHapticRuntimeError("events violates maximum_events")
    events = [
        _event(item, index, session_id, experiment_id, limits)
        for index, item in enumerate(raw_events)
    ]
    times = [event["monotonic_ns"] for event in events]
    if times != sorted(times):
        raise AudioHapticRuntimeError("event monotonic timestamps must be nondecreasing")

    requests: dict[str, dict[str, Any]] = {}
    counts: dict[str, int] = {}
    cleanup_state = "missing"
    source_incomplete = False
    for event in events:
        event_type = event["event_type"]
        counts[event_type] = counts.get(event_type, 0) + 1
        source_incomplete |= event["source_health"] != "HEALTHY"
        if event_type == "SESSION_CLEANUP":
            cleanup_state = str(event["cleanup_state"])
            continue
        request_id = str(event["payload"]["request_id"])
        request = requests.setdefault(request_id, _new_request(request_id))
        payload = event["payload"]
        if event_type == "EVENT_FIRED":
            request["fired_resource_id"] = event["resource_id"]
            request["resource_kind"] = payload["resource_kind"]
        elif event_type == "ROUTE_SELECTED":
            request["selected_route_id"] = payload["route_id"]
        elif event_type == "REQUEST_ADMITTED":
            request["admission"] = "admitted"
        elif event_type == "REQUEST_REJECTED":
            request["admission"] = "rejected"
            request["rejection_reason"] = payload["reason"]
        elif event_type == "HAPTIC_STARTED":
            request["controller_type"] = payload["controller_type"]
            request["duration_ms"] = payload["duration_ms"]
            request["intensity"] = payload["intensity"]
            request["started_ns"] = event["monotonic_ns"]
        elif event_type == "HAPTIC_ENDED":
            request["ended_ns"] = event["monotonic_ns"]
            request["cleanup_state"] = event["cleanup_state"] or "complete"
        elif event_type == "FALLBACK_SELECTED":
            if request["selected_route_id"] not in {None, payload["from_route_id"]}:
                raise AudioHapticRuntimeError("fallback source does not match selected route")
            request["fallback_route_id"] = payload["to_route_id"]

    request_rows = sorted(requests.values(), key=lambda item: item["request_id"].casefold())
    lifecycle_incomplete = False
    intervals: list[tuple[int, int, str]] = []
    for request in request_rows:
        admitted = request["admission"] == "admitted"
        rejected = request["admission"] == "rejected"
        if admitted:
            complete = all(
                request[field] is not None
                for field in (
                    "fired_resource_id",
                    "selected_route_id",
                    "controller_type",
                    "duration_ms",
                    "intensity",
                    "started_ns",
                    "ended_ns",
                )
            ) and request["cleanup_state"] == "complete"
            lifecycle_incomplete |= not complete
            if request["started_ns"] is not None and request["ended_ns"] is not None:
                if request["ended_ns"] < request["started_ns"]:
                    raise AudioHapticRuntimeError("haptic end precedes start")
                intervals.append(
                    (request["started_ns"], request["ended_ns"], request["request_id"])
                )
        elif rejected:
            lifecycle_incomplete |= request["rejection_reason"] is None
        else:
            lifecycle_incomplete = True

    capture_cleanup_incomplete = cleanup_state != "complete" or any(
        row["admission"] == "admitted" and row["cleanup_state"] != "complete"
        for row in request_rows
    )
    overlap_resolved = (
        not lifecycle_incomplete and not capture_cleanup_incomplete and not source_incomplete
    )
    pairs: list[dict[str, Any]] = []
    maximum_concurrent = 0
    if overlap_resolved:
        boundaries: list[tuple[int, int]] = []
        for start, end, _request_id in intervals:
            boundaries.extend(((start, 1), (end, -1)))
        active = 0
        for _timestamp, delta in sorted(boundaries, key=lambda item: (item[0], item[1])):
            active += delta
            maximum_concurrent = max(maximum_concurrent, active)
        for left_index, left in enumerate(intervals):
            for right in intervals[left_index + 1 :]:
                overlap_start = max(left[0], right[0])
                overlap_end = min(left[1], right[1])
                if overlap_start < overlap_end:
                    if len(pairs) == limits["maximum_overlap_pairs"]:
                        overlap_resolved = False
                        break
                    pairs.append(
                        {
                            "request_ids": sorted((left[2], right[2]), key=str.casefold),
                            "overlap_duration_ns": overlap_end - overlap_start,
                        }
                    )
            if not overlap_resolved:
                break

    reason_flags = {
        "SOURCE_HEALTH_INCOMPLETE": source_incomplete,
        "REQUEST_LIFECYCLE_INCOMPLETE": lifecycle_incomplete,
        "CAPTURE_CLEANUP_INCOMPLETE": capture_cleanup_incomplete,
        "OVERLAP_PAIR_LIMIT_REACHED": not overlap_resolved
        and not (source_incomplete or lifecycle_incomplete or capture_cleanup_incomplete),
        "DUALSENSE_PRESERVATION_UNPROVEN": not proof_sufficient,
    }
    reasons = [code for code in _REASON_ORDER if reason_flags[code]]
    status = "complete" if not reasons else "capture_inconclusive"
    permitted_claims = [
        "event_fired_observed",
        "route_selection_observed",
        "request_admission_observed",
        "controller_parameters_observed",
        "fallback_observed",
        "cleanup_observed",
    ]
    if overlap_resolved:
        permitted_claims.append("overlap_measured" if pairs else "no_overlap_in_covered_capture")
    if proof_sufficient:
        permitted_claims.append("dualsense_behavior_preserved_in_covered_capture")
    controller_types = sorted(
        {str(row["controller_type"]) for row in request_rows if row["controller_type"] is not None},
        key=str.casefold,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "experiment_id": experiment_id,
        "active_snapshot_id": active_snapshot_id,
        "adapter_id": adapter["adapter_id"],
        "status": status,
        "evidence_layer": "runtime",
        "event_count": len(events),
        "event_counts": dict(sorted(counts.items())),
        "controller_types": controller_types,
        "requests": request_rows,
        "overlap": {
            "status": "measured" if overlap_resolved else "unresolved",
            "maximum_concurrent_requests": maximum_concurrent if overlap_resolved else None,
            "pairs": pairs if overlap_resolved else [],
        },
        "cleanup": {
            "state": cleanup_state,
            "active_requests": sum(
                row["admission"] == "admitted" and row["cleanup_state"] != "complete"
                for row in request_rows
            ),
        },
        "haptics_preservation": {
            "dualsense_behavior": "preserved" if proof_sufficient else "unresolved",
            "evidence_layer": proof["evidence_layer"],
            "reference": proof["reference"],
            "capture_complete": proof["capture_complete"],
            "correlation_valid": proof["correlation_valid"],
        },
        "safety_gate": {key: adapter[key] for key in adapter if key != "adapter_id"},
        "limits": limits,
        "reason_codes": reasons,
        "permitted_claims": permitted_claims,
    }


__all__ = ["AudioHapticRuntimeError", "adapt_audio_haptic_runtime"]
