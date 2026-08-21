"""Deterministic result-validity decisions for bounded native-probe captures."""

from __future__ import annotations

from typing import Any, Mapping

from .correlation import validate_native_stage_correlation

RESULT_INPUT_VERSION = "kcd2.probe-result-input.v1"
RESULT_VALIDITY_VERSION = "kcd2.probe-result-validity.v1"
REQUIRED_CHECKS = (
    "boot_ok",
    "install_ok",
    "game_fingerprint_match",
    "deployment_binding_exact",
    "module_base_emitted",
    "unfiltered_queries_observed",
    "record_layout_valid",
    "identity_filter_valid",
    "positive_control_or_population",
    "log_complete",
    "no_dropped_events",
    "user_state_confirmed",
    "correlation_contract_valid",
)
MAX_EVENT_FAMILIES = 128
MAX_EVIDENCE_REFS = 512


def validate_probe_result(result_input: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical verdict and audit for one bounded probe result.

    ``filtered_event_count`` is the only observation used to select positive,
    negative, or not-evaluated handling. A zero count is promoted only through
    :func:`negative_capture_audit`; no caller-supplied verdict is trusted.
    """
    normalized = _normalize_input(result_input)
    filtered_event_count = normalized.pop("filtered_event_count")
    if filtered_event_count is None:
        return _build_audit(
            normalized,
            verdict="not_evaluated",
            reasons=[],
            permitted_runtime_claims=["none"],
        )
    if filtered_event_count > 0:
        if not normalized["checks"]["correlation_contract_valid"]:
            return _build_audit(
                normalized,
                verdict="capture_inconclusive",
                reasons=_correlation_reasons(normalized),
                permitted_runtime_claims=["query_observed"],
            )
        return _build_audit(
            normalized,
            verdict="positive_observation",
            reasons=[],
            permitted_runtime_claims=["query_observed"],
        )
    return _audit_zero_count(normalized)


def negative_capture_audit(result_input: Mapping[str, Any]) -> dict[str, Any]:
    """Audit a zero-event result without ever overstating invalid evidence."""
    normalized = _normalize_input(result_input)
    filtered_event_count = normalized.pop("filtered_event_count")
    if filtered_event_count != 0:
        raise ValueError("negative_capture_audit requires filtered_event_count equal to zero")
    return _audit_zero_count(normalized)


def _audit_zero_count(normalized: dict[str, Any]) -> dict[str, Any]:
    checks = normalized["checks"]
    saturation = normalized["event_family_saturation"]
    reasons = [f"check_failed:{name}" for name in REQUIRED_CHECKS if not checks[name]]
    if not checks["correlation_contract_valid"]:
        reasons.extend(_correlation_reasons(normalized))
    if not saturation:
        reasons.append("event_family_saturation_missing")
    reasons.extend(
        f"event_family_saturated:{name}"
        for name, state in saturation.items()
        if state["reached"]
    )
    if reasons:
        claims = ["query_observed"] if checks["unfiltered_queries_observed"] else ["none"]
        return _build_audit(
            normalized,
            verdict="capture_inconclusive",
            reasons=reasons,
            permitted_runtime_claims=claims,
        )
    return _build_audit(
        normalized,
        verdict="confirmed_negative_in_covered_scope",
        reasons=[],
        permitted_runtime_claims=["none"],
    )


def _normalize_input(result_input: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(result_input, Mapping):
        raise TypeError("probe result input must be an object")
    if result_input.get("schema_version") != RESULT_INPUT_VERSION:
        raise ValueError(f"schema_version must be {RESULT_INPUT_VERSION}")
    probe_id = _bounded_string(result_input.get("probe_id"), "probe_id", 256)
    session_id = _bounded_string(result_input.get("session_id"), "session_id", 256)

    count = result_input.get("filtered_event_count")
    if count is not None and (
        not isinstance(count, int) or isinstance(count, bool) or count < 0 or count > 100_000
    ):
        raise ValueError("filtered_event_count must be null or an integer from 0 to 100000")

    supplied_checks = result_input.get("checks")
    if not isinstance(supplied_checks, Mapping):
        supplied_checks = {}
    unexpected_checks = sorted(set(supplied_checks) - set(REQUIRED_CHECKS))
    if unexpected_checks:
        raise ValueError(f"checks contains unknown gate {unexpected_checks[0]!r}")
    checks = {name: supplied_checks.get(name) is True for name in REQUIRED_CHECKS}
    correlation_contract = result_input.get("correlation_contract")
    correlation_codes: list[str]
    if isinstance(correlation_contract, Mapping):
        correlation_report = validate_native_stage_correlation(correlation_contract)
        correlation_codes = list(correlation_report.diagnostic_codes)
        checks["correlation_contract_valid"] = (
            checks["correlation_contract_valid"] and correlation_report.valid
        )
    else:
        correlation_codes = ["CORRELATION_PROOF_MISSING"]
        checks["correlation_contract_valid"] = False

    supplied_saturation = result_input.get("event_family_saturation")
    if not isinstance(supplied_saturation, Mapping):
        supplied_saturation = {}
    if len(supplied_saturation) > MAX_EVENT_FAMILIES:
        raise ValueError(f"event_family_saturation exceeds {MAX_EVENT_FAMILIES} families")
    saturation: dict[str, dict[str, Any]] = {}
    for family in sorted(supplied_saturation):
        name = _bounded_string(family, "event family name", 128)
        state = supplied_saturation[family]
        if not isinstance(state, Mapping):
            raise ValueError(f"event family {name!r} state must be an object")
        observed = _bounded_integer(state.get("observed"), f"{name}.observed", 0, 100_000)
        limit = _bounded_integer(state.get("limit"), f"{name}.limit", 1, 100_000)
        declared_reached = state.get("reached")
        if declared_reached is not None and not isinstance(declared_reached, bool):
            raise ValueError(f"{name}.reached must be boolean when supplied")
        saturation[name] = {
            "observed": observed,
            "limit": limit,
            "reached": declared_reached is True or observed >= limit,
        }

    normalized: dict[str, Any] = {
        "probe_id": probe_id,
        "session_id": session_id,
        "filtered_event_count": count,
        "checks": checks,
        "event_family_saturation": saturation,
        "correlation_diagnostic_codes": correlation_codes,
    }
    evidence_refs = result_input.get("audit_evidence_refs")
    if evidence_refs is not None:
        if not isinstance(evidence_refs, list) or not 1 <= len(evidence_refs) <= MAX_EVIDENCE_REFS:
            raise ValueError("audit_evidence_refs must contain 1 to 512 strings")
        normalized["audit_evidence_refs"] = sorted(
            {
                _bounded_string(reference, "audit evidence reference", 512)
                for reference in evidence_refs
            }
        )
    return normalized


def _correlation_reasons(normalized: Mapping[str, Any]) -> list[str]:
    codes = normalized.get("correlation_diagnostic_codes")
    if not isinstance(codes, list) or not codes:
        return ["check_failed:correlation_contract_valid"]
    return ["correlation_invalid:" + str(code) for code in codes]


def _build_audit(
    normalized: Mapping[str, Any],
    *,
    verdict: str,
    reasons: list[str],
    permitted_runtime_claims: list[str],
) -> dict[str, Any]:
    audit = {
        "schema_version": RESULT_VALIDITY_VERSION,
        "probe_id": normalized["probe_id"],
        "session_id": normalized["session_id"],
        "checks": normalized["checks"],
        "event_family_saturation": normalized["event_family_saturation"],
        "verdict": verdict,
        "reasons": reasons,
        "permitted_runtime_claims": permitted_runtime_claims,
    }
    if "audit_evidence_refs" in normalized:
        audit["audit_evidence_refs"] = normalized["audit_evidence_refs"]
    return audit


def _bounded_string(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} must contain 1 to {maximum} characters")
    return value


def _bounded_integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value
