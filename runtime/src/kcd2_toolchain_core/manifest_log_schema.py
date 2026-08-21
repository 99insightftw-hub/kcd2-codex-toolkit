"""Bounded, redacted diagnosis driven entirely by a manifest log schema."""

from __future__ import annotations

import json
import math
import re
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from .jsonl import BoundedJsonlLimits, read_bounded_jsonl

SCHEMA_VERSION = "kcd2.manifest-log-schema.v1"
SUMMARY_SCHEMA_VERSION = "kcd2.manifest-log-summary.v1"
_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}")
_FIELD_TYPES = {"string", "integer", "number", "boolean", "null", "object", "array"}
_ASSERTION_KINDS = {"install", "fire", "count", "truncation", "cleanup", "sequence"}


class ManifestLogSchemaError(ValueError):
    """Raised when a manifest log-schema declaration is unsafe or inconsistent."""


def validate_manifest_log_schema(manifest: Mapping[str, Any]) -> None:
    """Validate hard bounds and all declaration cross-references."""
    if not isinstance(manifest, Mapping):
        raise ManifestLogSchemaError("manifest must be an object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ManifestLogSchemaError(f"schema_version must be {SCHEMA_VERSION}")
    _name(manifest.get("schema_id"), "schema_id")
    event_name_field = _name(manifest.get("event_name_field"), "event_name_field")
    sequence = _mapping(manifest.get("sequence"), "sequence")
    _exact_keys(sequence, {"field", "start", "step", "required"}, "sequence")
    sequence_field = _name(sequence.get("field"), "sequence.field")
    _bounded_int(sequence.get("start"), "sequence.start", 0, 2**63 - 1)
    _bounded_int(sequence.get("step"), "sequence.step", 1, 1_000_000)
    if not isinstance(sequence.get("required"), bool):
        raise ManifestLogSchemaError("sequence.required must be a boolean")
    if sequence_field == event_name_field:
        raise ManifestLogSchemaError("sequence.field and event_name_field must differ")

    events = _mapping(manifest.get("events"), "events")
    if not 1 <= len(events) <= 128:
        raise ManifestLogSchemaError("events must contain between 1 and 128 declarations")
    for event_name, raw_schema in events.items():
        _name(event_name, "event name")
        schema = _mapping(raw_schema, f"events.{event_name}")
        _exact_keys(
            schema,
            {"fields", "required_fields", "redacted_fields", "maximum_events", "maximum_bytes"},
            f"events.{event_name}",
        )
        fields = _mapping(schema.get("fields"), f"events.{event_name}.fields")
        if len(fields) > 128:
            raise ManifestLogSchemaError(f"events.{event_name}.fields exceeds 128")
        for field_name, field_type in fields.items():
            _name(field_name, f"events.{event_name} field")
            if field_type not in _FIELD_TYPES:
                raise ManifestLogSchemaError(f"events.{event_name}.{field_name} has invalid type")
        required = _name_list(schema.get("required_fields"), f"events.{event_name}.required_fields")
        redacted = _name_list(schema.get("redacted_fields"), f"events.{event_name}.redacted_fields")
        if not set(required) <= set(fields):
            raise ManifestLogSchemaError(f"events.{event_name}.required_fields are not declared")
        if not set(redacted) <= set(fields):
            raise ManifestLogSchemaError(f"events.{event_name}.redacted_fields are not declared")
        _bounded_int(
            schema.get("maximum_events"),
            f"events.{event_name}.maximum_events",
            1,
            100_000,
        )
        _bounded_int(
            schema.get("maximum_bytes"),
            f"events.{event_name}.maximum_bytes",
            1,
            32 * 1024 * 1024,
        )

    relations = _bounded_list(manifest.get("relations"), "relations", 128)
    for index, raw_relation in enumerate(relations):
        relation = _mapping(raw_relation, f"relations[{index}]")
        _exact_keys(
            relation,
            {"parent_event", "parent_field", "child_event", "child_field"},
            f"relations[{index}]",
        )
        for event_key, field_key in (
            ("parent_event", "parent_field"),
            ("child_event", "child_field"),
        ):
            event = _name(relation.get(event_key), f"relations[{index}].{event_key}")
            field = _name(relation.get(field_key), f"relations[{index}].{field_key}")
            if event not in events:
                raise ManifestLogSchemaError(f"relations[{index}].{event_key} is not declared")
            if field not in events[event]["fields"]:
                raise ManifestLogSchemaError(f"relations[{index}].{field_key} is not declared")

    markers = _bounded_list(manifest.get("completion_markers"), "completion_markers", 32)
    if not markers:
        raise ManifestLogSchemaError("completion_markers must not be empty")
    for index, raw_marker in enumerate(markers):
        marker = _mapping(raw_marker, f"completion_markers[{index}]")
        _exact_keys(marker, {"event", "minimum", "maximum"}, f"completion_markers[{index}]")
        event = _name(marker.get("event"), f"completion_markers[{index}].event")
        if event not in events:
            raise ManifestLogSchemaError(f"completion_markers[{index}].event is not declared")
        minimum = _bounded_int(marker.get("minimum"), "completion minimum", 1, 100_000)
        maximum = _bounded_int(marker.get("maximum"), "completion maximum", 1, 100_000)
        if minimum > maximum:
            raise ManifestLogSchemaError("completion marker minimum exceeds maximum")

    redaction = _mapping(manifest.get("redaction"), "redaction")
    _exact_keys(redaction, {"field_names", "replacement"}, "redaction")
    _name_list(redaction.get("field_names"), "redaction.field_names")
    replacement = redaction.get("replacement")
    if not isinstance(replacement, str) or not 1 <= len(replacement) <= 64:
        raise ManifestLogSchemaError("redaction.replacement must contain 1 to 64 characters")

    limits = _mapping(manifest.get("limits"), "limits")
    expected_limits = {
        "maximum_records": (1, 100_000),
        "maximum_line_bytes": (256, 8 * 1024 * 1024),
        "maximum_total_bytes": (256, 512 * 1024 * 1024),
        "maximum_unknown_events": (0, 256),
        "maximum_unknown_fields": (0, 128),
        "maximum_string_chars": (1, 65_536),
        "maximum_diagnostics": (0, 256),
    }
    _exact_keys(limits, set(expected_limits), "limits")
    for key, (minimum, maximum) in expected_limits.items():
        _bounded_int(limits.get(key), f"limits.{key}", minimum, maximum)

    assertions = _bounded_list(manifest.get("assertions"), "assertions", 128)
    assertion_ids: set[str] = set()
    for index, raw_assertion in enumerate(assertions):
        assertion = _mapping(raw_assertion, f"assertions[{index}]")
        allowed = {
            "assertion_id",
            "kind",
            "event",
            "field",
            "equals",
            "minimum",
            "maximum",
            "then_event",
        }
        if not {"assertion_id", "kind", "event"} <= set(assertion) or not set(assertion) <= allowed:
            raise ManifestLogSchemaError(f"assertions[{index}] has invalid keys")
        assertion_id = _name(assertion.get("assertion_id"), f"assertions[{index}].assertion_id")
        if assertion_id in assertion_ids:
            raise ManifestLogSchemaError("assertion_id values must be unique")
        assertion_ids.add(assertion_id)
        kind = assertion.get("kind")
        if kind not in _ASSERTION_KINDS:
            raise ManifestLogSchemaError(f"assertions[{index}].kind is invalid")
        event = _name(assertion.get("event"), f"assertions[{index}].event")
        if event not in events:
            raise ManifestLogSchemaError(f"assertions[{index}].event is not declared")
        if kind == "sequence":
            if set(assertion) != {"assertion_id", "kind", "event", "then_event"}:
                raise ManifestLogSchemaError(
                    f"assertions[{index}] sequence assertion has invalid keys"
                )
            then_event = _name(
                assertion.get("then_event"), f"assertions[{index}].then_event"
            )
            if then_event not in events:
                raise ManifestLogSchemaError(
                    f"assertions[{index}].then_event is not declared"
                )
            if sequence["required"] is not True:
                raise ManifestLogSchemaError(
                    "sequence assertions require the manifest sequence field"
                )
        elif "then_event" in assertion:
            raise ManifestLogSchemaError(
                f"assertions[{index}].then_event is allowed only for sequence assertions"
            )
        if kind in {"install", "truncation", "cleanup"}:
            field = _name(assertion.get("field"), f"assertions[{index}].field")
            if field not in events[event]["fields"] or "equals" not in assertion:
                raise ManifestLogSchemaError(
                    f"assertions[{index}] must declare a valid field and equals"
                )
            if not _is_scalar(assertion["equals"]):
                raise ManifestLogSchemaError(f"assertions[{index}].equals must be scalar")
        if kind in {"fire", "count"}:
            minimum = _bounded_int(assertion.get("minimum", 1), "assertion minimum", 0, 100_000)
            maximum = _bounded_int(
                assertion.get("maximum", 100_000), "assertion maximum", 0, 100_000
            )
            if minimum > maximum:
                raise ManifestLogSchemaError("assertion minimum exceeds maximum")


def diagnose_manifest_log_records(
    manifest: Mapping[str, Any], records: Iterable[Mapping[str, Any]]
) -> dict[str, Any]:
    """Validate and summarize records without fixed event names or payload leakage."""
    validate_manifest_log_schema(manifest)
    events: Mapping[str, Mapping[str, Any]] = manifest["events"]
    limits: Mapping[str, int] = manifest["limits"]
    event_name_field: str = manifest["event_name_field"]
    sequence_contract: Mapping[str, Any] = manifest["sequence"]
    redaction_fields = set(manifest["redaction"]["field_names"])
    for schema in events.values():
        redaction_fields.update(schema["redacted_fields"])
    replacement: str = manifest["redaction"]["replacement"]

    counts: Counter[str] = Counter()
    byte_counts: Counter[str] = Counter()
    values: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    unknown_events: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    sequence_errors = 0
    malformed = 0
    unknown_count = 0
    processed = 0
    expected_sequence = sequence_contract["start"]
    records_exceeded = False

    def diagnostic(kind: str, record_number: int) -> None:
        if len(diagnostics) < limits["maximum_diagnostics"]:
            diagnostics.append({"kind": kind, "record_number": record_number})

    for record_number, raw_record in enumerate(records, start=1):
        if record_number > limits["maximum_records"]:
            records_exceeded = True
            diagnostic("maximum_records_exceeded", record_number)
            break
        processed += 1
        if not isinstance(raw_record, Mapping):
            malformed += 1
            diagnostic("record_not_object", record_number)
            continue
        record = dict(raw_record)
        sequence_value = record.get(sequence_contract["field"])
        if sequence_value is None and not sequence_contract["required"]:
            pass
        elif (
            not isinstance(sequence_value, int)
            or isinstance(sequence_value, bool)
            or sequence_value != expected_sequence
        ):
            sequence_errors += 1
            diagnostic("sequence_invariant_failed", record_number)
        expected_sequence += sequence_contract["step"]

        event_name = record.get(event_name_field)
        if not isinstance(event_name, str) or not _NAME_RE.fullmatch(event_name):
            malformed += 1
            diagnostic("event_name_invalid", record_number)
            continue
        if event_name not in events:
            unknown_count += 1
            if len(unknown_events) < limits["maximum_unknown_events"]:
                unknown_events.append(
                    {
                        "event_name": event_name,
                        "fields": _safe_unknown_fields(
                            record,
                            excluded={event_name_field, sequence_contract["field"]},
                            redaction_fields=redaction_fields,
                            replacement=replacement,
                            maximum_fields=limits["maximum_unknown_fields"],
                            maximum_string_chars=limits["maximum_string_chars"],
                        ),
                    }
                )
            continue

        schema = events[event_name]
        counts[event_name] += 1
        byte_counts[event_name] += len(
            json.dumps(
                record,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            ).encode("utf-8")
        )
        valid = True
        for field in schema["required_fields"]:
            if field not in record:
                valid = False
                diagnostic("required_field_missing", record_number)
        for field, expected_type in schema["fields"].items():
            if field in record and not _matches_type(
                record[field], expected_type, limits["maximum_string_chars"]
            ):
                valid = False
                diagnostic("field_type_invalid", record_number)
        if valid:
            values[event_name].append(record)
        else:
            malformed += 1

    exceeded_families = sorted(
        event
        for event, schema in events.items()
        if counts[event] > schema["maximum_events"] or byte_counts[event] > schema["maximum_bytes"]
    )
    bounds_exceeded = records_exceeded or bool(exceeded_families)
    sequence_valid = sequence_errors == 0
    completion_details = []
    for marker in manifest["completion_markers"]:
        observed = counts[marker["event"]]
        completion_details.append(
            {
                "event": marker["event"],
                "observed": observed,
                "satisfied": marker["minimum"] <= observed <= marker["maximum"],
            }
        )
    completion_valid = all(item["satisfied"] for item in completion_details)
    capture_valid = sequence_valid and completion_valid and not bounds_exceeded and malformed == 0

    relation_summaries = []
    for relation in manifest["relations"]:
        parent_ids = {
            item.get(relation["parent_field"])
            for item in values[relation["parent_event"]]
            if _safe_relation_id(item.get(relation["parent_field"]))
        }
        child_ids = [
            item.get(relation["child_field"])
            for item in values[relation["child_event"]]
            if _safe_relation_id(item.get(relation["child_field"]))
        ]
        relation_summaries.append(
            {
                "parent_event": relation["parent_event"],
                "child_event": relation["child_event"],
                "parent_count": len(parent_ids),
                "child_count": len(child_ids),
                "orphan_count": sum(child_id not in parent_ids for child_id in child_ids),
            }
        )

    assertions = [
        _evaluate_assertion(
            assertion,
            counts,
            values,
            capture_valid,
            sequence_contract["field"],
        )
        for assertion in manifest["assertions"]
    ]
    if not capture_valid:
        verdict = "capture_inconclusive"
    elif all(item["status"] == "pass" for item in assertions):
        verdict = "pass"
    else:
        verdict = "fail"
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "manifest_schema_id": manifest["schema_id"],
        "verdict": verdict,
        "records_processed": processed,
        "event_counts": {event: counts[event] for event in sorted(events)},
        "sequence": {"valid": sequence_valid, "error_count": sequence_errors},
        "completion": {"complete": completion_valid, "markers": completion_details},
        "bounds": {
            "exceeded": bounds_exceeded,
            "records_exceeded": records_exceeded,
            "event_families_exceeded": exceeded_families,
        },
        "malformed_records": malformed,
        "relations": relation_summaries,
        "assertions": assertions,
        "unknown_events": unknown_events,
        "unknown_events_truncated": unknown_count > len(unknown_events),
        "diagnostics": diagnostics,
        "diagnostics_truncated": (
            sequence_errors + malformed + int(records_exceeded)
        )
        > len(diagnostics),
        "redacted_fields": sorted(redaction_fields),
    }


def diagnose_manifest_log_jsonl(
    manifest: Mapping[str, Any], path: str | Path
) -> dict[str, Any]:
    """Import JSONL under manifest-declared byte/record bounds and diagnose it."""
    validate_manifest_log_schema(manifest)
    limits = manifest["limits"]
    imported = read_bounded_jsonl(
        path,
        limits=BoundedJsonlLimits(
            max_records=limits["maximum_records"],
            max_line_bytes=limits["maximum_line_bytes"],
            max_total_bytes=limits["maximum_total_bytes"],
        ),
    )
    summary = diagnose_manifest_log_records(manifest, imported.records)
    summary["bounds"]["ingestion_truncated"] = imported.truncated
    summary["bounds"]["ingestion_reason"] = imported.reason
    summary["bounds"]["bytes_read"] = imported.bytes_read
    if imported.truncated:
        summary["bounds"]["exceeded"] = True
        summary["verdict"] = "capture_inconclusive"
        for assertion in summary["assertions"]:
            assertion["status"] = "inconclusive"
    return summary


def _evaluate_assertion(
    assertion: Mapping[str, Any],
    counts: Counter[str],
    values: Mapping[str, list[Mapping[str, Any]]],
    capture_valid: bool,
    sequence_field: str,
) -> dict[str, Any]:
    result = {
        "assertion_id": assertion["assertion_id"],
        "kind": assertion["kind"],
        "status": "inconclusive",
    }
    if not capture_valid:
        return result
    kind = assertion["kind"]
    event = assertion["event"]
    if kind == "sequence":
        then_event = assertion["then_event"]
        first_sequences = sorted(item[sequence_field] for item in values[event])
        then_sequences = sorted(item[sequence_field] for item in values[then_event])
        observed_pairs = 0
        first_pair: tuple[int, int] | None = None
        for first in first_sequences:
            then_index = bisect_right(then_sequences, first)
            observed_pairs += len(then_sequences) - then_index
            if first_pair is None and then_index < len(then_sequences):
                first_pair = (first, then_sequences[then_index])
        result.update(
            event=event,
            then_event=then_event,
            observed_pairs=observed_pairs,
            first_sequence=first_pair[0] if first_pair else None,
            then_sequence=first_pair[1] if first_pair else None,
            status="pass" if observed_pairs else "fail",
        )
        return result
    if kind in {"fire", "count"}:
        observed = counts[event]
        minimum = assertion.get("minimum", 1)
        maximum = assertion.get("maximum", 100_000)
        result.update(
            observed=observed,
            status="pass" if minimum <= observed <= maximum else "fail",
        )
        return result
    matched = sum(item.get(assertion["field"]) == assertion["equals"] for item in values[event])
    result.update(observed_matches=matched, status="pass" if matched > 0 else "fail")
    return result


def _safe_unknown_fields(
    record: Mapping[str, Any],
    *,
    excluded: set[str],
    redaction_fields: set[str],
    replacement: str,
    maximum_fields: int,
    maximum_string_chars: int,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for field in sorted(key for key in record if isinstance(key, str) and key not in excluded):
        if len(result) >= maximum_fields:
            break
        if not _NAME_RE.fullmatch(field):
            continue
        value = record[field]
        if field in redaction_fields:
            result[field] = replacement
        elif value is None or isinstance(value, (bool, int)):
            result[field] = value
        elif isinstance(value, float) and math.isfinite(value):
            result[field] = value
        elif isinstance(value, str):
            result[field] = value[:maximum_string_chars]
        else:
            result[field] = "[UNSUPPORTED_VALUE]"
    return result


def _matches_type(value: Any, expected: str, maximum_string_chars: int) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (not isinstance(value, float) or math.isfinite(value))
        )
    if expected == "string":
        return isinstance(value, str) and len(value) <= maximum_string_chars
    if expected == "object":
        return isinstance(value, Mapping)
    if expected == "array":
        return isinstance(value, list)
    return False


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool, int)) or (
        isinstance(value, float) and math.isfinite(value)
    )


def _safe_relation_id(value: Any) -> bool:
    return value is not None and isinstance(value, (str, int)) and not isinstance(value, bool)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestLogSchemaError(f"{label} must be an object")
    return value


def _bounded_list(value: Any, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ManifestLogSchemaError(f"{label} must be an array bounded to {maximum}")
    return value


def _name_list(value: Any, label: str) -> list[str]:
    items = _bounded_list(value, label, 128)
    result = [_name(item, label) for item in items]
    if len(set(result)) != len(result):
        raise ManifestLogSchemaError(f"{label} must contain unique names")
    return result


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise ManifestLogSchemaError(f"{label} must be a bounded name")
    return value


def _bounded_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ManifestLogSchemaError(f"{label} must be between {minimum} and {maximum}")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ManifestLogSchemaError(f"{label} must contain exactly {sorted(expected)}")
