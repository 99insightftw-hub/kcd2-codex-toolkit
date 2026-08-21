"""Bounded, read-only probe/logging overhead audit calculations."""

from __future__ import annotations

import math
from decimal import Decimal, ROUND_CEILING, ROUND_FLOOR, localcontext
from typing import Any


OBSERVATION_SCHEMA_VERSION = "kcd2.probe-overhead-observation.v1"
REPORT_SCHEMA_VERSION = "kcd2.probe-overhead-report.v1"
MAX_SOURCES = 128
MAX_COUNTER = 2**63 - 1
MAX_DURATION_NS = 24 * 60 * 60 * 1_000_000_000
RATE_DECIMALS = Decimal("0.000001")
LEVELS = ("OFF", "MINIMAL", "NORMAL", "VERBOSE", "TRACE")
RESPONSIVENESS = ("responsive", "unresponsive", "not_observed")


def audit_probe_overhead(observation: dict[str, Any]) -> dict[str, Any]:
    """Create a deterministic report from passive, pre-aggregated observations.

    The function performs no process, game, debugger, or filesystem access. Timing and rate
    results are conservative intervals derived from the declared monotonic clock resolution.
    """
    if not isinstance(observation, dict):
        raise ValueError("observation must be an object")
    if observation.get("schema_version") != OBSERVATION_SCHEMA_VERSION:
        raise ValueError(f"expected {OBSERVATION_SCHEMA_VERSION}")
    _exact_keys(
        observation,
        {
            "schema_version",
            "session_id",
            "measurement_window",
            "responsiveness",
            "sources",
        },
        "observation",
    )
    session_id = _text(observation.get("session_id"), "session_id", 256)
    window = _object(observation.get("measurement_window"), "measurement_window")
    _exact_keys(
        window,
        {"duration_ns", "clock_resolution_ns", "clock", "method"},
        "measurement_window",
    )
    duration_ns = _integer(window.get("duration_ns"), "duration_ns", 1, MAX_DURATION_NS)
    resolution_ns = _integer(
        window.get("clock_resolution_ns"),
        "clock_resolution_ns",
        1,
        duration_ns - 1,
    )
    clock = _text(window.get("clock"), "clock", 128)
    if window.get("method") != "precomputed_monotonic_aggregate":
        raise ValueError("measurement_window.method is not a safe supported timing method")
    responsiveness = observation.get("responsiveness")
    if responsiveness not in RESPONSIVENESS:
        raise ValueError("responsiveness is invalid")
    raw_sources = observation.get("sources")
    if not isinstance(raw_sources, list) or not 1 <= len(raw_sources) <= MAX_SOURCES:
        raise ValueError(f"sources must contain 1 to {MAX_SOURCES} entries")

    sources: list[dict[str, Any]] = []
    names: set[str] = set()
    invalidation_reasons: set[str] = set()
    severe_overhead = responsiveness == "unresponsive"
    if responsiveness != "responsive":
        invalidation_reasons.add("responsiveness_not_confirmed")
    if responsiveness == "unresponsive":
        invalidation_reasons.add("severe_responsiveness_failure")

    for index, raw_source in enumerate(raw_sources):
        source = _audit_source(raw_source, duration_ns, resolution_ns, index)
        if source["source"] in names:
            raise ValueError(f"duplicate source: {source['source']}")
        names.add(source["source"])
        sources.append(source)
        if source["severe_timing_overhead"]:
            severe_overhead = True
            invalidation_reasons.add("severe_timing_overhead")
        if (
            source["dropped"]
            or source["malformed"]
            or source["truncated"]
            or source["saturated"]
            or source["rate_limit_exceeded"]
        ):
            invalidation_reasons.add("source_loss_or_saturation")

    if severe_overhead:
        recommendation = "CAPTURE_INVALID_OVERHEAD"
    else:
        recommendation = _overall_recommendation(sources)
    capture_validity = "capture_inconclusive" if invalidation_reasons else "complete"
    notes = [
        "Rates and timing ratios are conservative bounds, not exact performance claims.",
        "This report does not apply logging changes; build/deploy approval is separate.",
    ]
    if any(source["callback_time_fraction"] is None for source in sources):
        notes.append("Callback timing was not supplied for at least one source.")

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "session_id": session_id,
        "measurement_window": {
            "duration_ns": duration_ns,
            "clock_resolution_ns": resolution_ns,
            "clock": clock,
            "method": "precomputed_monotonic_aggregate",
        },
        "sources": sources,
        "responsiveness": responsiveness,
        "severe_overhead": severe_overhead,
        "capture_validity": capture_validity,
        "invalidation_reasons": sorted(invalidation_reasons),
        "recommendation": recommendation,
        "live_logging_change_requires_separate_approval": True,
        "notes": notes,
    }


def _audit_source(
    raw_source: Any,
    duration_ns: int,
    resolution_ns: int,
    index: int,
) -> dict[str, Any]:
    source = _object(raw_source, f"sources[{index}]")
    required_source_keys = {
        "source",
        "observed_events",
        "observed_bytes",
        "hook_callback_count",
        "dropped",
        "malformed",
        "truncated",
        "saturated",
        "log_write_count",
        "log_flush_count",
        "logging_level",
        "policy",
    }
    _exact_keys(
        source,
        required_source_keys,
        f"sources[{index}]",
        optional={"callback_total_ns"},
    )
    name = _text(source.get("source"), f"sources[{index}].source", 128)
    counts = {
        key: _integer(source.get(key), f"{name}.{key}", 0, MAX_COUNTER)
        for key in (
            "observed_events",
            "observed_bytes",
            "hook_callback_count",
            "dropped",
            "malformed",
            "truncated",
            "log_write_count",
            "log_flush_count",
        )
    }
    saturated = source.get("saturated")
    if not isinstance(saturated, bool):
        raise ValueError(f"{name}.saturated must be a boolean")
    logging_level = source.get("logging_level")
    if logging_level not in LEVELS:
        raise ValueError(f"{name}.logging_level is invalid")
    policy = _object(source.get("policy"), f"{name}.policy")
    _exact_keys(
        policy,
        {
            "max_events_per_second",
            "max_bytes_per_second",
            "severe_callback_time_fraction",
            "steady_state_logging_level",
        },
        f"{name}.policy",
    )
    max_event_rate = _number(policy.get("max_events_per_second"), "max_events_per_second")
    max_byte_rate = _number(policy.get("max_bytes_per_second"), "max_bytes_per_second")
    severe_fraction = _number(
        policy.get("severe_callback_time_fraction"),
        "severe_callback_time_fraction",
        maximum=1,
        exclusive_minimum=True,
    )
    steady_state = policy.get("steady_state_logging_level")
    if steady_state not in LEVELS:
        raise ValueError(f"{name}.steady_state_logging_level is invalid")

    event_rate = _rate_interval(counts["observed_events"], duration_ns, resolution_ns)
    byte_rate = _rate_interval(counts["observed_bytes"], duration_ns, resolution_ns)
    rate_limit_exceeded = (
        event_rate["upper_bound"] > max_event_rate
        or byte_rate["upper_bound"] > max_byte_rate
    )
    callback_total = source.get("callback_total_ns")
    callback_fraction = None
    severe_timing = False
    if callback_total is not None:
        callback_total_ns = _integer(
            callback_total,
            f"{name}.callback_total_ns",
            0,
            MAX_COUNTER,
        )
        if callback_total_ns and not counts["hook_callback_count"]:
            raise ValueError(f"{name}.callback_total_ns requires hook callbacks")
        callback_fraction = _fraction_interval(
            callback_total_ns,
            counts["hook_callback_count"],
            duration_ns,
            resolution_ns,
        )
        severe_timing = callback_fraction["upper_bound"] >= severe_fraction

    recommended = min((logging_level, steady_state), key=LEVELS.index)
    return {
        "source": name,
        **counts,
        "saturated": saturated,
        "logging_level": logging_level,
        "recommended_logging_level": recommended,
        "event_rate_per_second": event_rate,
        "byte_rate_per_second": byte_rate,
        "callback_time_fraction": callback_fraction,
        "rate_limit_exceeded": rate_limit_exceeded,
        "severe_timing_overhead": severe_timing,
        "policy": {
            "max_events_per_second": max_event_rate,
            "max_bytes_per_second": max_byte_rate,
            "severe_callback_time_fraction": severe_fraction,
        },
    }


def _rate_interval(count: int, duration_ns: int, resolution_ns: int) -> dict[str, Any]:
    with localcontext() as context:
        context.prec = 80
        numerator = Decimal(count) * Decimal(1_000_000_000)
        lower = numerator / Decimal(duration_ns + resolution_ns)
        upper = numerator / Decimal(duration_ns - resolution_ns)
    return _interval(lower, upper, "monotonic_interval")


def _fraction_interval(
    total_ns: int,
    callback_count: int,
    duration_ns: int,
    resolution_ns: int,
) -> dict[str, Any]:
    aggregate_error = callback_count * resolution_ns
    lower_numerator = max(0, total_ns - aggregate_error)
    upper_numerator = total_ns + aggregate_error
    with localcontext() as context:
        context.prec = 80
        lower = Decimal(lower_numerator) / Decimal(duration_ns + resolution_ns)
        upper = Decimal(upper_numerator) / Decimal(duration_ns - resolution_ns)
    return _interval(lower, upper, "aggregate_clock_resolution")


def _interval(lower: Decimal, upper: Decimal, basis: str) -> dict[str, Any]:
    with localcontext() as context:
        context.prec = 80
        return {
            "lower_bound": float(lower.quantize(RATE_DECIMALS, rounding=ROUND_FLOOR)),
            "upper_bound": float(upper.quantize(RATE_DECIMALS, rounding=ROUND_CEILING)),
            "basis": basis,
            "decimal_places": 6,
        }


def _overall_recommendation(sources: list[dict[str, Any]]) -> str:
    target = min((source["recommended_logging_level"] for source in sources), key=LEVELS.index)
    reduction_needed = any(
        LEVELS.index(source["logging_level"])
        > LEVELS.index(source["recommended_logging_level"])
        for source in sources
    )
    if not reduction_needed:
        return "KEEP_CURRENT"
    return {
        "OFF": "DISABLE_AFTER_VALIDATION",
        "MINIMAL": "REDUCE_TO_MINIMAL",
        "NORMAL": "REDUCE_TO_NORMAL",
        "VERBOSE": "KEEP_CURRENT",
        "TRACE": "KEEP_CURRENT",
    }[target]


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _text(value: Any, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{name} must be a string of 1 to {maximum} characters")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _number(
    value: Any,
    name: str,
    *,
    maximum: float | None = None,
    exclusive_minimum: bool = False,
) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise ValueError(f"{name} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"{name} must be finite")
    minimum_ok = number > 0 if exclusive_minimum else number >= 0
    if not minimum_ok or maximum is not None and number > maximum:
        raise ValueError(f"{name} is outside its supported bound")
    return number


def _exact_keys(
    value: dict[str, Any],
    required: set[str],
    name: str,
    *,
    optional: set[str] | None = None,
) -> None:
    optional = optional or set()
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing:
        raise ValueError(f"{name} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValueError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")
