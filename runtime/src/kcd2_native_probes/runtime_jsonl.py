"""Canonical, bounded runtime JSONL v1 writing, conversion, and summarization."""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from kcd2_toolchain_core.jsonl import BoundedJsonlLimits, read_bounded_jsonl

from .legacy_kcse import (
    DEFAULT_MAX_DIAGNOSTICS,
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_PREFIX_TOKENS,
    _bounded_lines,
    parse_int,
    parse_legacy_record,
)
from .limits import RAW_POINTER_RE


SCHEMA_VERSION = "kcd2.runtime-jsonl.v1"
SUMMARY_SCHEMA_VERSION = "kcd2.runtime-jsonl-summary.v1"
CONVERSION_SCHEMA_VERSION = "kcd2.legacy-runtime-jsonl-conversion.v1"
SESSION_ID_RE = re.compile(r"session:[A-Za-z0-9_.:-]{1,247}")
SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}")
NAME_RE = re.compile(r".{1,128}", re.DOTALL)
DATE_TIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)
TIMEZONE_RE = re.compile(r"Z|[+-](?:0\d|1\d|2[0-3]):[0-5]\d")
INTEGER_MIN = -(2**63)
INTEGER_MAX = 2**63 - 1
MAX_FLOAT = 1e308
MAX_HISTOGRAM_VALUES = 256


@dataclass(frozen=True, slots=True)
class RuntimeJsonlLimits:
    """Reviewed runtime-jsonl-v1 defaults with their schema hard ceilings."""

    max_records: int = 10_000
    max_line_bytes: int = 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_string_chars: int = 4096
    max_extension_fields: int = 32

    def __post_init__(self) -> None:
        bounds = {
            "max_records": (1, 100_000),
            "max_line_bytes": (256, 8 * 1024 * 1024),
            "max_total_bytes": (256, 512 * 1024 * 1024),
            "max_string_chars": (1, 65_536),
            "max_extension_fields": (0, 128),
        }
        for name, (minimum, maximum) in bounds.items():
            value = getattr(self, name)
            if not minimum <= value <= maximum:
                raise ValueError(f"{name} must be between {minimum} and {maximum}")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_records": self.max_records,
            "max_line_bytes": self.max_line_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_string_chars": self.max_string_chars,
            "max_extension_fields": self.max_extension_fields,
        }


@dataclass(frozen=True, slots=True)
class RuntimeSessionManifest:
    """Session metadata and event families declared before runtime emission."""

    session_id: str
    producer: str
    started_at: str
    environment_fingerprint_sha256: str
    deployment_binding_sha256: str | None
    declared_event_families: tuple[str, ...]
    limits: RuntimeJsonlLimits = field(default_factory=RuntimeJsonlLimits)
    extensions: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_fullmatch(SESSION_ID_RE, self.session_id, "session_id")
        _require_string(self.producer, "producer", maximum=256)
        _require_datetime(self.started_at, "started_at")
        _require_fullmatch(
            SHA256_RE,
            self.environment_fingerprint_sha256,
            "environment_fingerprint_sha256",
        )
        if self.deployment_binding_sha256 is not None:
            _require_fullmatch(
                SHA256_RE,
                self.deployment_binding_sha256,
                "deployment_binding_sha256",
            )
        families = tuple(sorted(self.declared_event_families))
        if not families:
            raise ValueError("at least one declared event family is required")
        if len(families) > 128 or len(set(families)) != len(families):
            raise ValueError("declared event families must be unique and bounded to 128")
        for family_name in families:
            _require_name(family_name, "declared event family")
        object.__setattr__(self, "declared_event_families", families)
        _validate_extensions(self.extensions, self.limits, "extensions")

    @classmethod
    def from_probe_contract(
        cls,
        probe_contract: Mapping[str, Any],
        *,
        session_id: str,
        producer: str,
        started_at: str,
        environment_fingerprint_sha256: str,
        deployment_binding_sha256: str | None,
        limits: RuntimeJsonlLimits | None = None,
        extensions: Mapping[str, Any] | None = None,
    ) -> RuntimeSessionManifest:
        """Bind a session to the event families in a reviewed probe-contract v2 manifest."""
        if probe_contract.get("schema_version") != "kcd2.probe-contract.v2":
            raise ValueError("expected a kcd2.probe-contract.v2 manifest")
        event_schemas = probe_contract.get("event_schemas")
        event_limits = probe_contract.get("event_limits")
        if not isinstance(event_schemas, dict) or not isinstance(event_limits, dict):
            raise ValueError("probe manifest must declare event_schemas and event_limits")
        if set(event_schemas) != set(event_limits):
            raise ValueError("probe manifest event_schemas/event_limits families differ")
        merged_extensions = dict(extensions or {})
        merged_extensions.setdefault("probe_id", probe_contract.get("probe_id"))
        merged_extensions.setdefault("probe_revision", probe_contract.get("revision"))
        return cls(
            session_id=session_id,
            producer=producer,
            started_at=started_at,
            environment_fingerprint_sha256=environment_fingerprint_sha256,
            deployment_binding_sha256=deployment_binding_sha256,
            declared_event_families=tuple(event_schemas),
            limits=limits or RuntimeJsonlLimits(),
            extensions=merged_extensions,
        )


class RuntimeJsonlWriter:
    """Write one session with writer-owned contiguous sequence numbers."""

    def __init__(self, path: str | Path, manifest: RuntimeSessionManifest) -> None:
        self.path = Path(path)
        self.manifest = manifest
        self._stream: TextIO | None = None
        self._sequence = 0
        self._total_bytes = 0
        self._event_counts: Counter[str] = Counter()
        self._internal_dropped = 0
        self._internal_truncated = False
        self._internal_reasons: set[str] = set()
        self._closed = False
        start = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "session_start",
            "session_id": manifest.session_id,
            "sequence": 0,
            "emitted_at": manifest.started_at,
            "producer": manifest.producer,
            "environment_fingerprint_sha256": manifest.environment_fingerprint_sha256,
            "deployment_binding_sha256": manifest.deployment_binding_sha256,
            "declared_event_families": list(manifest.declared_event_families),
            "limits": manifest.limits.to_dict(),
            "extensions": dict(manifest.extensions),
        }
        encoded = self._encode_record(start)
        if len(encoded) > manifest.limits.max_total_bytes:
            raise ValueError("session_start exceeds max_total_bytes")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = self.path.open("w", encoding="utf-8", newline="\n")
        self._write_encoded(encoded)

    def write_event(
        self,
        *,
        event_family: str,
        event_name: str,
        emitted_at: str,
        monotonic_ns: int,
        payload: Mapping[str, Any],
        extensions: Mapping[str, Any] | None = None,
    ) -> bool:
        """Write an event, or account for it as dropped when an output bound is reached."""
        self._require_open()
        if event_family not in self.manifest.declared_event_families:
            raise ValueError(f"event family is not declared by the manifest: {event_family}")
        _require_name(event_name, "event_name")
        _require_datetime(emitted_at, "emitted_at")
        if not isinstance(monotonic_ns, int) or isinstance(monotonic_ns, bool):
            raise ValueError("monotonic_ns must be an integer")
        if not 0 <= monotonic_ns <= INTEGER_MAX:
            raise ValueError("monotonic_ns is outside the runtime JSONL bound")
        _validate_extensions(payload, self.manifest.limits, "payload")
        event_extensions = extensions or {}
        _validate_extensions(event_extensions, self.manifest.limits, "extensions")

        if self._sequence >= self.manifest.limits.max_records:
            self._record_drop("max_records")
            return False
        next_sequence = self._sequence + 1
        record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "event",
            "session_id": self.manifest.session_id,
            "sequence": next_sequence,
            "emitted_at": emitted_at,
            "event_family": event_family,
            "event_name": event_name,
            "monotonic_ns": monotonic_ns,
            "payload": dict(payload),
            "extensions": dict(event_extensions),
        }
        try:
            encoded = self._encode_record(record)
        except ValueError as error:
            if "max_line_bytes" not in str(error):
                raise
            self._record_drop("max_line_bytes")
            return False
        if self._total_bytes + len(encoded) > self.manifest.limits.max_total_bytes:
            self._record_drop("max_total_bytes")
            return False
        self._write_encoded(encoded)
        self._sequence = next_sequence
        self._event_counts[event_family] += 1
        return True

    def close(
        self,
        *,
        emitted_at: str,
        dropped_events: int = 0,
        truncated: bool = False,
        truncation_reasons: Sequence[str] = (),
        extensions: Mapping[str, Any] | None = None,
    ) -> None:
        """Write the mandatory session_end record and close the stream."""
        self._require_open()
        _require_datetime(emitted_at, "emitted_at")
        if (
            not isinstance(dropped_events, int)
            or isinstance(dropped_events, bool)
            or not 0 <= dropped_events <= 100_000
        ):
            raise ValueError("dropped_events is outside the runtime JSONL bound")
        reasons = sorted(set(truncation_reasons) | self._internal_reasons)
        if len(reasons) > 64:
            raise ValueError("truncation_reasons exceeds 64 entries")
        for reason in reasons:
            _require_string(reason, "truncation reason", maximum=256)
        total_dropped = dropped_events + self._internal_dropped
        if total_dropped > 100_000:
            raise ValueError("combined dropped_events exceeds the runtime JSONL bound")
        is_truncated = truncated or self._internal_truncated
        if total_dropped or is_truncated:
            completeness = "capture_inconclusive"
        else:
            completeness = "complete"
        end_extensions = extensions or {}
        _validate_extensions(end_extensions, self.manifest.limits, "extensions")
        record = {
            "schema_version": SCHEMA_VERSION,
            "record_type": "session_end",
            "session_id": self.manifest.session_id,
            "sequence": self._sequence + 1,
            "emitted_at": emitted_at,
            "event_counts": {
                family: self._event_counts[family] for family in sorted(self._event_counts)
            },
            "dropped_events": total_dropped,
            "truncated": is_truncated,
            "completeness": completeness,
            "truncation_reasons": reasons,
            "extensions": dict(end_extensions),
        }
        encoded = self._encode_record(record)
        if self._total_bytes + len(encoded) > self.manifest.limits.max_total_bytes:
            raise ValueError("session_end exceeds remaining max_total_bytes")
        self._write_encoded(encoded)
        assert self._stream is not None
        self._stream.flush()
        self._stream.close()
        self._stream = None
        self._closed = True

    def _record_drop(self, reason: str) -> None:
        if self._internal_dropped >= 100_000:
            raise ValueError("dropped event counter reached its hard ceiling")
        self._internal_dropped += 1
        self._internal_truncated = True
        self._internal_reasons.add(reason)

    def _encode_record(self, record: Mapping[str, Any]) -> bytes:
        try:
            rendered = json.dumps(
                record,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            )
        except (TypeError, ValueError) as error:
            raise ValueError(f"record is not canonical JSON: {error}") from error
        encoded = (rendered + "\n").encode("utf-8")
        if len(encoded) > self.manifest.limits.max_line_bytes:
            raise ValueError("record exceeds max_line_bytes")
        return encoded

    def _write_encoded(self, encoded: bytes) -> None:
        assert self._stream is not None
        self._stream.write(encoded.decode("utf-8"))
        self._total_bytes += len(encoded)

    def _require_open(self) -> None:
        if self._closed or self._stream is None:
            raise ValueError("runtime JSONL writer is closed")


def convert_legacy_kcse(
    source: str | Path,
    destination: str | Path,
    manifest: RuntimeSessionManifest,
    *,
    legacy_timezone: str,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_prefix_tokens: int = DEFAULT_MAX_PREFIX_TOKENS,
    max_diagnostics: int = DEFAULT_MAX_DIAGNOSTICS,
) -> dict[str, Any]:
    """Convert bounded legacy KCSE tokens without silently discarding unknown fields."""
    _require_fullmatch(TIMEZONE_RE, legacy_timezone, "legacy_timezone")
    if max_line_bytes < 1 or max_prefix_tokens < 1 or max_diagnostics < 0:
        raise ValueError("legacy converter bounds are invalid")
    source_path = Path(source)
    writer = RuntimeJsonlWriter(destination, manifest)
    converted = 0
    dropped = 0
    diagnostics: list[dict[str, Any]] = []
    last_emitted_at = manifest.started_at

    def drop(line_number: int, cause: str) -> None:
        nonlocal dropped
        dropped += 1
        if len(diagnostics) < max_diagnostics:
            diagnostics.append({"line_number": line_number, "cause": cause})

    for line_number, line in _bounded_lines(source_path, max_line_bytes):
        if line is None:
            drop(line_number, f"line exceeds {max_line_bytes} UTF-8 bytes")
            continue
        if not line.strip():
            continue
        parsed, cause = parse_legacy_record(line, max_prefix_tokens=max_prefix_tokens)
        if parsed is None:
            drop(line_number, cause)
            continue
        if parsed.event not in manifest.declared_event_families:
            drop(line_number, f"event family is not manifest-declared: {parsed.event}")
            continue
        emitted_at = _legacy_datetime(parsed.timestamp, legacy_timezone)
        prefix = {key: parse_int(value) for key, value in parsed.prefix_tokens.items()}
        written = writer.write_event(
            event_family=parsed.event,
            event_name=parsed.event,
            emitted_at=emitted_at,
            monotonic_ns=0,
            payload=parsed.body_tokens,
            extensions={
                "legacy_line_number": line_number,
                "legacy_prefix": prefix,
                "monotonic_ns_unavailable": True,
            },
        )
        if written:
            converted += 1
            last_emitted_at = emitted_at

    reasons = ("legacy_records_dropped",) if dropped else ()
    writer.close(
        emitted_at=last_emitted_at,
        dropped_events=dropped,
        truncation_reasons=reasons,
    )
    return {
        "schema_version": CONVERSION_SCHEMA_VERSION,
        "source": str(source_path.resolve()),
        "destination": str(Path(destination).resolve()),
        "converted_events": converted,
        "dropped_events": dropped,
        "diagnostics": diagnostics,
        "diagnostics_truncated": dropped > len(diagnostics),
    }


def summarize_runtime_jsonl(
    path: str | Path,
    probe_contract: Mapping[str, Any],
    *,
    max_records: int = 100_002,
    max_line_bytes: int = 8 * 1024 * 1024,
    max_total_bytes: int = 512 * 1024 * 1024,
) -> dict[str, Any]:
    """Summarize runtime events using only manifest-declared, sanitized semantics."""
    event_schemas, event_limits, matchers = _summary_contract(probe_contract)
    bounded = read_bounded_jsonl(
        path,
        limits=BoundedJsonlLimits(
            max_records=max_records,
            max_line_bytes=max_line_bytes,
            max_total_bytes=max_total_bytes,
        ),
    )
    records = list(bounded.records)
    if not records:
        raise ValueError("runtime JSONL contains no records")
    for line_number, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"line {line_number} is not a JSON object")
        if record.get("schema_version") != SCHEMA_VERSION:
            raise ValueError(f"line {line_number} has an unsupported schema_version")

    start = records[0]
    end = records[-1] if records[-1].get("record_type") == "session_end" else None
    if start.get("record_type") != "session_start":
        raise ValueError("first record is not session_start")
    session_id = start.get("session_id")
    declared = start.get("declared_event_families")
    if not isinstance(declared, list) or not all(isinstance(item, str) for item in declared):
        raise ValueError("session_start declared_event_families is invalid")
    if set(declared) != set(event_schemas):
        raise ValueError("session event families differ from the probe contract")
    sequences: list[int] = []
    event_counts: Counter[str] = Counter()
    event_bytes: Counter[str] = Counter()
    payload_fields: Counter[str] = Counter()
    malformed_counts: Counter[str] = Counter()
    numeric_values: dict[str, dict[str, Counter[int | float]]] = {
        family: {
            field_name: Counter()
            for field_name in schema["numeric_histogram_fields"]
        }
        for family, schema in event_schemas.items()
    }
    identity_counts: dict[str, dict[str, dict[str, dict[str, Any]]]] = {
        family: {
            field_name: {
                matcher_id: {
                    "observed": 0,
                    "matched": 0,
                    "known_values": known_values,
                }
                for matcher_id, known_values in matchers.get(field_name, {}).items()
                if known_values
            }
            for field_name in schema.get("identity_match_fields", [])
        }
        for family, schema in event_schemas.items()
    }
    tracked_id_fields: dict[str, set[str]] = {family: set() for family in event_schemas}
    for family, schema in event_schemas.items():
        parent_family = schema.get("parent_event_family")
        parent_id = schema.get("parent_id_field")
        if parent_family is not None and parent_id is not None:
            tracked_id_fields[family].add(parent_id)
            tracked_id_fields[parent_family].add(parent_id)
    family_ids: dict[str, dict[str, Counter[str]]] = {
        family: {} for family in event_schemas
    }
    structural_errors: list[str] = []
    for line_number, record in enumerate(records, start=1):
        if record.get("session_id") != session_id:
            structural_errors.append(f"line {line_number}: session_id mismatch")
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            structural_errors.append(f"line {line_number}: invalid sequence")
        else:
            sequences.append(sequence)
        record_type = record.get("record_type")
        if record_type == "event":
            family = record.get("event_family")
            if family not in declared:
                structural_errors.append(f"line {line_number}: undeclared event family")
            elif isinstance(family, str):
                event_counts[family] += 1
                event_bytes[family] += len(
                    (
                        json.dumps(
                            record,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                            allow_nan=False,
                        )
                        + "\n"
                    ).encode("utf-8")
                )
            payload = record.get("payload")
            if not isinstance(payload, dict):
                structural_errors.append(f"line {line_number}: payload is not an object")
            else:
                if isinstance(family, str) and family in event_schemas:
                    malformed_counts[family] += _summarize_event_payload(
                        payload,
                        event_schemas[family],
                        numeric_values[family],
                        identity_counts[family],
                        family_ids[family],
                        tracked_id_fields[family],
                        payload_fields,
                    )
        elif record_type == "session_start" and line_number != 1:
            structural_errors.append(f"line {line_number}: duplicate session_start")
        elif record_type == "session_end" and line_number != len(records):
            structural_errors.append(f"line {line_number}: non-final session_end")
        elif record_type not in {"session_start", "session_end"}:
            structural_errors.append(f"line {line_number}: unknown record_type")

    sequence_monotonic = len(sequences) == len(records) and all(
        current > previous for previous, current in zip(sequences, sequences[1:], strict=False)
    )
    if not sequence_monotonic:
        structural_errors.append("sequence numbers are not monotonic")
    ordered_event_counts = {name: event_counts[name] for name in sorted(event_counts)}
    end_counts_match = end is not None and end.get("event_counts") == ordered_event_counts
    if end is not None and not end_counts_match:
        structural_errors.append("session_end event_counts mismatch")
    session_complete = (
        end is not None
        and not bounded.truncated
        and not structural_errors
        and end.get("completeness") == "complete"
        and end.get("dropped_events") == 0
        and end.get("truncated") is False
    )
    parent_child = _parent_child_summary(event_schemas, family_ids)
    saturation = {
        family: {
            "observed_events": event_counts[family],
            "maximum_events": event_limits[family]["maximum_events"],
            "events_reached": (
                event_counts[family] >= event_limits[family]["maximum_events"]
            ),
            "observed_bytes": event_bytes[family],
            "maximum_bytes": event_limits[family]["maximum_bytes"],
            "bytes_reached": event_bytes[family] >= event_limits[family]["maximum_bytes"],
            "reached": (
                event_counts[family] >= event_limits[family]["maximum_events"]
                or event_bytes[family] >= event_limits[family]["maximum_bytes"]
            ),
        }
        for family in sorted(event_schemas)
    }
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source": str(Path(path).resolve()),
        "session_id": session_id,
        "record_count": len(records),
        "event_counts": {
            family: event_counts[family] for family in sorted(event_schemas)
        },
        "event_family_saturation": saturation,
        "numeric_histograms": _render_numeric_histograms(numeric_values),
        "identity_matches": _render_identity_matches(identity_counts),
        "parent_child_cardinality": parent_child,
        "malformed_event_counts": {
            family: malformed_counts[family] for family in sorted(event_schemas)
        },
        "payload_field_counts": {
            name: payload_fields[name] for name in sorted(payload_fields)
        },
        "sequence_monotonic": sequence_monotonic,
        "session_complete": session_complete,
        "dropped_events": end.get("dropped_events") if end is not None else None,
        "truncated": bool(bounded.truncated or (end and end.get("truncated"))),
        "completeness": end.get("completeness") if end is not None else "capture_inconclusive",
        "truncation_reasons": end.get("truncation_reasons", []) if end is not None else [],
        "structural_errors": structural_errors,
        "reader_truncated": bounded.truncated,
        "reader_truncation_reason": bounded.reason,
    }


def _summary_contract(
    probe_contract: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, dict[str, set[str]]]]:
    if probe_contract.get("schema_version") != "kcd2.probe-contract.v2":
        raise ValueError("expected a kcd2.probe-contract.v2 manifest")
    schemas = probe_contract.get("event_schemas")
    limits = probe_contract.get("event_limits")
    if not isinstance(schemas, dict) or not isinstance(limits, dict):
        raise ValueError("probe manifest must declare event_schemas and event_limits")
    if not schemas or set(schemas) != set(limits):
        raise ValueError("probe manifest event_schemas/event_limits families differ")
    normalized_schemas: dict[str, Any] = {}
    for family in sorted(schemas):
        schema = schemas[family]
        limit = limits[family]
        if not isinstance(schema, dict) or not isinstance(limit, dict):
            raise ValueError(f"event family {family!r} has an invalid schema or limit")
        fields = schema.get("fields")
        sensitive = schema.get("sensitive_fields")
        numeric = schema.get("numeric_histogram_fields")
        identities = schema.get("identity_match_fields", [])
        if not isinstance(fields, dict) or not all(
            isinstance(value, list) for value in (sensitive, numeric, identities)
        ):
            raise ValueError(f"event family {family!r} has invalid field declarations")
        declared_lists = set(sensitive) | set(numeric) | set(identities)
        if not declared_lists <= set(fields):
            raise ValueError(f"event family {family!r} references an undeclared field")
        parent_family = schema.get("parent_event_family")
        parent_id = schema.get("parent_id_field")
        if (parent_family is None) != (parent_id is None):
            raise ValueError(f"event family {family!r} has an incomplete parent declaration")
        if parent_family is not None:
            if parent_family not in schemas or parent_id not in fields:
                raise ValueError(f"event family {family!r} has an invalid parent declaration")
            parent_schema = schemas[parent_family]
            parent_fields = parent_schema.get("fields", {})
            unsafe = set(sensitive) | {
                name for name, field_type in fields.items() if field_type == "ephemeral_pointer"
            }
            parent_unsafe = set(parent_schema.get("sensitive_fields", [])) | {
                name
                for name, field_type in parent_fields.items()
                if field_type == "ephemeral_pointer"
            }
            if (
                parent_id not in parent_fields
                or parent_id in unsafe
                or parent_id in parent_unsafe
            ):
                raise ValueError(f"event family {family!r} has an unsafe parent ID field")
        for key in ("maximum_events", "maximum_bytes"):
            if not isinstance(limit.get(key), int) or isinstance(limit.get(key), bool):
                raise ValueError(f"event family {family!r} has an invalid {key}")
            if limit[key] < 1:
                raise ValueError(f"event family {family!r} has an invalid {key}")
        normalized_schemas[family] = {
            **schema,
            "identity_match_fields": identities,
        }
    matcher_map: dict[str, dict[str, set[str]]] = {}
    for matcher in probe_contract.get("identity_matchers", []):
        if not isinstance(matcher, dict):
            raise ValueError("identity_matchers contains a non-object")
        field_name = matcher.get("field_id")
        matcher_id = matcher.get("matcher_id")
        known_values = matcher.get("known_values")
        if field_name is None or not isinstance(matcher_id, str):
            continue
        if not isinstance(known_values, list) or not all(
            isinstance(value, str) for value in known_values
        ):
            raise ValueError(f"identity matcher {matcher_id!r} has invalid known_values")
        matcher_map.setdefault(field_name, {})[matcher_id] = set(known_values)
    return normalized_schemas, limits, matcher_map


def _summarize_event_payload(
    payload: Mapping[str, Any],
    schema: Mapping[str, Any],
    numeric: dict[str, Counter[int | float]],
    identities: dict[str, dict[str, dict[str, Any]]],
    family_ids: dict[str, Counter[str]],
    tracked_id_fields: set[str],
    payload_fields: Counter[str],
) -> int:
    malformed = 0
    fields = schema["fields"]
    sensitive = set(schema["sensitive_fields"])
    unsafe = sensitive | {
        name for name, field_type in fields.items() if field_type == "ephemeral_pointer"
    }
    for field_name, value in payload.items():
        if field_name not in fields:
            malformed += 1
            continue
        if field_name in unsafe:
            continue
        payload_fields[field_name] += 1
        if field_name in numeric:
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                if math.isfinite(value):
                    numeric[field_name][value] += 1
                else:
                    malformed += 1
            else:
                malformed += 1
        for counts in identities.get(field_name, {}).values():
            counts["observed"] += 1
    for field_name in tracked_id_fields:
        if field_name in payload and field_name not in unsafe:
            rendered_id = str(payload[field_name])
            if RAW_POINTER_RE.fullmatch(rendered_id) is None:
                family_ids.setdefault(field_name, Counter())[rendered_id] += 1
            else:
                malformed += 1
    for field_name, matcher_counts in identities.items():
        if field_name not in payload or field_name in unsafe:
            continue
        for counts in matcher_counts.values():
            known_values = counts["known_values"]
            if str(payload[field_name]) in known_values:
                counts["matched"] += 1
    return malformed


def _render_numeric_histograms(
    values: Mapping[str, Mapping[str, Counter[int | float]]],
) -> dict[str, dict[str, dict[str, Any]]]:
    rendered: dict[str, dict[str, dict[str, Any]]] = {}
    for family in sorted(values):
        rendered[family] = {}
        for field_name in sorted(values[family]):
            counter = values[family][field_name]
            ordered = sorted(counter.items(), key=lambda item: item[0])
            rendered[family][field_name] = {
                "count": sum(counter.values()),
                "minimum": ordered[0][0] if ordered else None,
                "maximum": ordered[-1][0] if ordered else None,
                "unique_values": len(ordered),
                "values_truncated": len(ordered) > MAX_HISTOGRAM_VALUES,
                "values": [
                    {"value": value, "count": count}
                    for value, count in ordered[:MAX_HISTOGRAM_VALUES]
                ],
            }
    return rendered


def _render_identity_matches(
    values: Mapping[str, Mapping[str, Mapping[str, Mapping[str, Any]]]],
) -> dict[str, dict[str, dict[str, dict[str, int]]]]:
    return {
        family: {
            field_name: {
                matcher_id: {
                    "matched": counts["matched"],
                    "observed": counts["observed"],
                }
                for matcher_id, counts in sorted(matchers.items())
            }
            for field_name, matchers in sorted(fields.items())
        }
        for family, fields in sorted(values.items())
    }


def _parent_child_summary(
    schemas: Mapping[str, Mapping[str, Any]],
    family_ids: Mapping[str, Mapping[str, Counter[str]]],
) -> dict[str, dict[str, Any]]:
    rendered: dict[str, dict[str, Any]] = {}
    for child_family in sorted(schemas):
        schema = schemas[child_family]
        parent_family = schema.get("parent_event_family")
        parent_id = schema.get("parent_id_field")
        if parent_family is None or parent_id is None:
            continue
        parents = family_ids[parent_family].get(parent_id, Counter())
        children = family_ids[child_family].get(parent_id, Counter())
        orphan_ids = set(children) - set(parents)
        rendered[child_family] = {
            "parent_event_family": parent_family,
            "parent_id_field": parent_id,
            "parent_id_count": len(parents),
            "child_id_count": len(children),
            "matched_parent_count": len(set(children) & set(parents)),
            "orphan_child_count": sum(children[value] for value in orphan_ids),
            "per_parent_child_counts": {
                value: children[value] for value in sorted(children) if value in parents
            },
        }
    return rendered


def _validate_extensions(
    values: Mapping[str, Any], limits: RuntimeJsonlLimits, field_name: str
) -> None:
    if not isinstance(values, Mapping):
        raise ValueError(f"{field_name} must be an object")
    if len(values) > limits.max_extension_fields:
        raise ValueError(f"{field_name} exceeds max_extension_fields")
    for key, value in values.items():
        _require_name(key, f"{field_name} field name")
        _validate_extension_value(value, limits, f"{field_name}.{key}")


def _validate_extension_value(value: Any, limits: RuntimeJsonlLimits, path: str) -> None:
    if isinstance(value, Mapping):
        if len(value) > 128:
            raise ValueError(f"{path} exceeds 128 nested fields")
        for key, child in value.items():
            _require_name(key, f"{path} field name")
            _validate_scalar(child, limits, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            raise ValueError(f"{path} exceeds 256 array items")
        for index, child in enumerate(value):
            _validate_scalar(child, limits, f"{path}[{index}]")
        return
    _validate_scalar(value, limits, path)


def _validate_scalar(value: Any, limits: RuntimeJsonlLimits, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if len(value) > min(limits.max_string_chars, 65_536):
            raise ValueError(f"{path} exceeds max_string_chars")
        return
    if isinstance(value, int):
        if not INTEGER_MIN <= value <= INTEGER_MAX:
            raise ValueError(f"{path} integer is outside the 64-bit bound")
        return
    if isinstance(value, float):
        if not math.isfinite(value) or not -MAX_FLOAT <= value <= MAX_FLOAT:
            raise ValueError(f"{path} number is outside the finite bound")
        return
    raise ValueError(f"{path} is not a bounded JSON scalar")


def _legacy_datetime(timestamp: str, timezone: str) -> str:
    return timestamp.replace(" ", "T", 1) + timezone


def _require_name(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or NAME_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a string of 1 to 128 characters")


def _require_string(value: Any, field_name: str, *, maximum: int) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ValueError(f"{field_name} must be a string of 1 to {maximum} characters")


def _require_datetime(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or len(value) > 64 or DATE_TIME_RE.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a bounded ISO 8601 date-time")


def _require_fullmatch(pattern: re.Pattern[str], value: Any, field_name: str) -> None:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field_name} has an invalid format")
