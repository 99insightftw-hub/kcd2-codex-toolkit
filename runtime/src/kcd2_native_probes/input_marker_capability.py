"""Fail-closed preflight for passive input transitions and metadata-only test markers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


SCHEMA_VERSION = "kcd2.input-marker-capability.v1"
MAX_CANDIDATE_ROUTES = 16
_ROUTE_FIELDS = {
    "route_id",
    "route_kind",
    "observation_mode",
    "action_map_unchanged",
    "input_synthesis",
    "input_consumption",
    "marker_mode",
    "current_button_binding",
    "transition_proof",
    "haptics_proof",
}
_PROOF_FIELDS = {
    "status",
    "evidence_layer",
    "capture_complete",
    "correlation_valid",
    "reference",
}
_ROUTE_KINDS = {"documented_callback", "native_hook", "provider_event_tap"}
_BLOCKER_ORDER = (
    "OBSERVATION_NOT_PASS_THROUGH",
    "ACTION_MAP_MUTATION_FORBIDDEN",
    "INPUT_SYNTHESIS_FORBIDDEN",
    "INPUT_CONSUMPTION_FORBIDDEN",
    "MARKER_NOT_METADATA_ONLY",
    "CURRENT_BUTTON_BINDING_FORBIDDEN",
    "TRANSITION_OBSERVATION_UNPROVEN",
    "HAPTICS_PRESERVATION_UNPROVEN",
)


def _text(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be non-empty text of at most {maximum} characters")
    return value


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be boolean")
    return value


def _exact_fields(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ValueError(
            f"{field} fields do not match contract; "
            f"missing={sorted(expected - actual)}, unknown={sorted(actual - expected)}"
        )


def _proof_is_sufficient(value: Any, field: str) -> bool:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    proof = dict(value)
    _exact_fields(proof, _PROOF_FIELDS, field)
    if proof["status"] not in {"proven", "unproven"}:
        raise ValueError(f"{field}.status must be proven or unproven")
    if proof["evidence_layer"] not in {"static", "runtime", "user_confirmed", "causal"}:
        raise ValueError(f"{field}.evidence_layer is unsupported")
    complete = _boolean(proof["capture_complete"], f"{field}.capture_complete")
    correlated = _boolean(proof["correlation_valid"], f"{field}.correlation_valid")
    _text(proof["reference"], f"{field}.reference", 512)
    return (
        proof["status"] == "proven"
        and proof["evidence_layer"] in {"runtime", "causal"}
        and complete
        and correlated
    )


def _evaluate_route(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("each candidate route must be a mapping")
    route = dict(value)
    _exact_fields(route, _ROUTE_FIELDS, "candidate route")
    route_id = _text(route["route_id"], "route_id")
    if route["route_kind"] not in _ROUTE_KINDS:
        raise ValueError(f"route_kind must be one of {sorted(_ROUTE_KINDS)}")
    booleans = {
        field: _boolean(route[field], field)
        for field in (
            "action_map_unchanged",
            "input_synthesis",
            "input_consumption",
            "current_button_binding",
        )
    }
    transition_proven = _proof_is_sufficient(route["transition_proof"], "transition_proof")
    haptics_proven = _proof_is_sufficient(route["haptics_proof"], "haptics_proof")
    failed = {
        "OBSERVATION_NOT_PASS_THROUGH": route["observation_mode"] != "pass_through",
        "ACTION_MAP_MUTATION_FORBIDDEN": not booleans["action_map_unchanged"],
        "INPUT_SYNTHESIS_FORBIDDEN": booleans["input_synthesis"],
        "INPUT_CONSUMPTION_FORBIDDEN": booleans["input_consumption"],
        "MARKER_NOT_METADATA_ONLY": route["marker_mode"] != "observer_metadata_only",
        "CURRENT_BUTTON_BINDING_FORBIDDEN": booleans["current_button_binding"],
        "TRANSITION_OBSERVATION_UNPROVEN": not transition_proven,
        "HAPTICS_PRESERVATION_UNPROVEN": not haptics_proven,
    }
    blockers = [code for code in _BLOCKER_ORDER if failed[code]]
    return {"route_id": route_id, "eligible": not blockers, "blockers": blockers}


def evaluate_input_marker_capability(
    candidate_routes: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return a deterministic receipt; never infer a route from path presence or silence."""

    if isinstance(candidate_routes, (str, bytes)) or not isinstance(candidate_routes, Sequence):
        raise ValueError("candidate_routes must be a sequence")
    if len(candidate_routes) > MAX_CANDIDATE_ROUTES:
        raise ValueError(f"candidate_routes exceeds the {MAX_CANDIDATE_ROUTES}-route hard bound")
    evaluations = sorted(
        (_evaluate_route(route) for route in candidate_routes), key=lambda item: item["route_id"]
    )
    route_ids = [item["route_id"].casefold() for item in evaluations]
    if len(route_ids) != len(set(route_ids)):
        raise ValueError("candidate route IDs must be case-insensitively unique")
    eligible = [item for item in evaluations if item["eligible"]]
    selected = eligible[0] if eligible else None
    if selected is not None:
        blockers: list[str] = []
    elif not evaluations:
        blockers = ["NO_CANDIDATE_ROUTE"]
    else:
        present = {code for item in evaluations for code in item["blockers"]}
        blockers = [code for code in _BLOCKER_ORDER if code in present]
    available = selected is not None
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "available" if available else "unavailable",
        "selected_route_id": selected["route_id"] if selected else None,
        "evaluated_routes": len(evaluations),
        "safety_gate": {
            "pass_through": available,
            "action_map_unchanged": available,
            "input_not_synthesized": available,
            "input_not_consumed": available,
            "metadata_only_markers": available,
            "haptics_preserved": available,
            "no_current_button_binding": available,
        },
        "blockers": blockers,
        "routes": evaluations,
    }


__all__ = ["MAX_CANDIDATE_ROUTES", "evaluate_input_marker_capability"]
