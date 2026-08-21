"""Schema-backed and semantic validation for bounded probe bundles."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .limits import DEFAULT_LIMITS, evaluate_probe_bundle_limits


SCHEMA_VERSION = "kcd2.probe-bundle.v2"
VALIDATION_VERSION = "kcd2.probe-bundle-validation.v2"
PROBE_STAGES = ("plan", "capture_ready", "captured", "final", "import_ready")
PROBE_STAGE_TRANSITIONS = frozenset(zip(PROBE_STAGES, PROBE_STAGES[1:]))
DEFAULT_MAX_DIAGNOSTICS = 200
SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}")
HEX_RE = re.compile(r"0x[A-Fa-f0-9]{1,16}")
DATE_TIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class ProbeBundleValidation:
    valid: bool
    diagnostics: tuple[Diagnostic, ...]
    diagnostics_truncated: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": VALIDATION_VERSION,
            "status": "PASS" if self.valid else "FAIL",
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
        }


@dataclass(frozen=True, slots=True)
class LegacyV1MigrationContext:
    """Reviewed metadata absent from v1 and therefore required from the caller."""

    environment_fingerprint_sha256: str
    module_pe_timestamp: str
    module_image_size: int
    deployment_binding_sha256: str | None = None
    revision: str = "legacy-v1-derived"

    def __post_init__(self) -> None:
        if SHA256_RE.fullmatch(self.environment_fingerprint_sha256) is None:
            raise ValueError("environment_fingerprint_sha256 is not SHA-256")
        if HEX_RE.fullmatch(self.module_pe_timestamp) is None:
            raise ValueError("module_pe_timestamp is not a hexadecimal value")
        if not isinstance(self.module_image_size, int) or isinstance(self.module_image_size, bool):
            raise ValueError("module_image_size must be an integer")
        if not 1 <= self.module_image_size <= 2**40:
            raise ValueError("module_image_size is outside the schema bound")
        if self.deployment_binding_sha256 is not None and SHA256_RE.fullmatch(
            self.deployment_binding_sha256
        ) is None:
            raise ValueError("deployment_binding_sha256 is not SHA-256")
        if not isinstance(self.revision, str) or not 1 <= len(self.revision) <= 128:
            raise ValueError("revision must contain 1 to 128 characters")


class _Collector:
    def __init__(self, maximum: int) -> None:
        if not 1 <= maximum <= 10_000:
            raise ValueError("max_diagnostics must be between 1 and 10000")
        self.maximum = maximum
        self.items: list[Diagnostic] = []
        self.truncated = False

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.items) < self.maximum:
            self.items.append(Diagnostic(code, path, message))
        else:
            self.truncated = True


def validate_probe_bundle(
    bundle: Any,
    *,
    schema_path: str | Path | None = None,
    max_diagnostics: int = DEFAULT_MAX_DIAGNOSTICS,
    expected_stage: str | None = None,
    previous_stage: str | None = None,
) -> ProbeBundleValidation:
    """Validate the reviewed v2 schema, its declared stage, and an optional transition."""
    collector = _Collector(max_diagnostics)
    path = (
        Path(schema_path)
        if schema_path
        else _repository_root() / "schemas/probe-bundle-v2.schema.json"
    )
    schema = json.loads(path.read_text(encoding="utf-8-sig"))
    _validate_schema(bundle, schema, schema, "$", collector)
    if isinstance(bundle, Mapping):
        _validate_stage_context(bundle, expected_stage, previous_stage, collector)
        _validate_semantics(bundle, collector)
    result = tuple(collector.items)
    return ProbeBundleValidation(
        not result and not collector.truncated, result, collector.truncated
    )


def validate_probe_stage_transition(
    previous_stage: str,
    current_stage: str,
    *,
    max_diagnostics: int = DEFAULT_MAX_DIAGNOSTICS,
) -> ProbeBundleValidation:
    """Validate one adjacent, forward-only probe evidence lifecycle transition."""
    collector = _Collector(max_diagnostics)
    _validate_stage_transition(previous_stage, current_stage, collector)
    result = tuple(collector.items)
    return ProbeBundleValidation(
        not result and not collector.truncated, result, collector.truncated
    )


def _validate_stage_context(
    bundle: Mapping[str, Any],
    expected_stage: str | None,
    previous_stage: str | None,
    collector: _Collector,
) -> None:
    current_stage = bundle.get("stage")
    if expected_stage is not None and current_stage != expected_stage:
        collector.add(
            "STAGE_MISMATCH",
            "$.stage",
            f"declared stage does not match expected stage {expected_stage!r}",
        )
    if previous_stage is not None:
        _validate_stage_transition(previous_stage, current_stage, collector)


def _validate_stage_transition(
    previous_stage: Any, current_stage: Any, collector: _Collector
) -> None:
    stages_are_strings = isinstance(previous_stage, str) and isinstance(current_stage, str)
    if not stages_are_strings or (previous_stage, current_stage) not in PROBE_STAGE_TRANSITIONS:
        collector.add(
            "STAGE_TRANSITION_INVALID",
            "$.stage",
            f"probe stage transition {previous_stage!r} -> {current_stage!r} is not allowed",
        )


def migrate_v1_bundle(
    legacy: Mapping[str, Any], context: LegacyV1MigrationContext
) -> dict[str, Any]:
    """Create derived, inconclusive v2 evidence without changing or promoting v1 claims."""
    if legacy.get("schema_version") != "1.0":
        raise ValueError("expected legacy probe bundle schema_version 1.0")
    canonical = json.dumps(
        legacy, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    ).encode("utf-8")
    source_sha256 = hashlib.sha256(canonical).hexdigest()
    carrier = legacy.get("evidence_source", "x64dbg")
    if carrier not in {"x64dbg", "kcse", "hybrid"}:
        raise ValueError("legacy evidence_source is unsupported")
    module_sha256 = legacy.get("whgame_sha256")
    if not isinstance(module_sha256, str) or SHA256_RE.fullmatch(module_sha256) is None:
        raise ValueError("legacy whgame_sha256 is not SHA-256")
    module_name = legacy.get("module")
    if not isinstance(module_name, str) or not 1 <= len(module_name) <= 260:
        raise ValueError("legacy module must contain 1 to 260 characters")

    locations = [
        {
            "module_sha256": module_sha256,
            "rva": item.get("rva"),
            "absolute": item.get("absolute"),
            "purpose": item.get("purpose"),
        }
        for item in _mapping_items(legacy.get("locations"))
    ]
    observations = [
        _migrate_observation(item, module_sha256)
        for item in _mapping_items(legacy.get("observations"))
    ]
    captures = [
        _migrate_capture(item, index, carrier, module_sha256, legacy.get("module_base"))
        for index, item in enumerate(_mapping_items(legacy.get("captures")), start=1)
    ]
    cleanup = legacy.get("cleanup") if isinstance(legacy.get("cleanup"), Mapping) else {}
    return {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": f"probe-bundle:sha256:{source_sha256}",
        "created_at": legacy.get("created_at"),
        "probe_id": legacy.get("probe_id"),
        "revision": context.revision,
        "stage": "captured",
        "carrier": carrier,
        "hypothesis": legacy.get("hypothesis"),
        "user_action": legacy.get("user_action"),
        "environment_fingerprint_sha256": context.environment_fingerprint_sha256,
        "deployment_binding_sha256": context.deployment_binding_sha256,
        "module": {
            "name": module_name,
            "sha256": module_sha256,
            "pe_timestamp": context.module_pe_timestamp,
            "image_size": context.module_image_size,
        },
        "module_base": legacy.get("module_base"),
        "locations": locations,
        "observations": observations,
        "captures": captures,
        "result": "capture_inconclusive",
        "completeness": "capture_inconclusive",
        "truncation_reasons": ["legacy_v1_unproven_validity"],
        "evidence_refs": [f"legacy-v1:sha256:{source_sha256}"],
        "limits": dict(DEFAULT_LIMITS),
        "debugger_handoff": {
            "requested": False,
            "debugger_state": (
                "unknown" if carrier in {"x64dbg", "hybrid"} else "not_applicable"
            ),
            "debugging": None,
            "running": None,
            "resumed_at": None,
            "verified_at": None,
            "minimum_delay_ms": 750,
            "gameplay_eligible": False,
        },
        "cleanup": {
            "game_running": _bool_or_default(cleanup.get("game_running"), True),
            "breakpoints_cleared": _bool_or_none(cleanup.get("breakpoints_cleared")),
            "debugger_state": (
                "unknown" if carrier in {"x64dbg", "hybrid"} else "not_applicable"
            ),
            "temporary_probe_removed": _bool_or_none(cleanup.get("temporary_probe_removed")),
            "raw_log_archived": _bool_or_default(cleanup.get("raw_log_archived"), False),
        },
    }


def _validate_semantics(bundle: Mapping[str, Any], collector: _Collector) -> None:
    _validate_timestamp(bundle.get("created_at"), "$.created_at", collector)
    module = bundle.get("module")
    if not isinstance(module, Mapping):
        return
    module_sha256 = module.get("sha256")
    image_size = module.get("image_size")
    module_base = _hex_int(bundle.get("module_base"))

    for index, location in enumerate(_mapping_items(bundle.get("locations"))):
        path = f"$.locations[{index}]"
        _identity_matches(location.get("module_sha256"), module_sha256, path, collector)
        rva = _hex_int(location.get("rva"))
        absolute = _hex_int(location.get("absolute"))
        if rva is not None and isinstance(image_size, int) and rva >= image_size:
            collector.add("ADDRESS_RVA_OUTSIDE_IMAGE", f"{path}.rva", "RVA is outside module image")
        if absolute is not None and module_base is None:
            collector.add(
                "ADDRESS_BASE_REQUIRED",
                f"{path}.absolute",
                "absolute address cannot be verified without module_base",
            )
        if module_base is not None and rva is not None and absolute is not None:
            if module_base + rva > 2**64 - 1 or absolute != module_base + rva:
                collector.add(
                    "ADDRESS_ABSOLUTE_MISMATCH",
                    f"{path}.absolute",
                    "absolute address does not equal module_base + rva",
                )

    for index, observation in enumerate(_mapping_items(bundle.get("observations"))):
        path = f"$.observations[{index}]"
        _identity_matches(observation.get("module_sha256"), module_sha256, path, collector)
        _rva_within_image(observation.get("rva"), image_size, f"{path}.rva", collector)

    carrier = bundle.get("carrier")
    sources: set[str] = set()
    captures = _mapping_items(bundle.get("captures"))
    for index, capture in enumerate(captures):
        path = f"$.captures[{index}]"
        source = capture.get("source")
        if isinstance(source, str):
            sources.add(source)
        if not _source_allowed(carrier, source):
            collector.add(
                "CARRIER_SOURCE_INCOMPATIBLE",
                f"{path}.source",
                "capture source is incompatible with the bundle carrier",
            )
        _validate_timestamp(capture.get("timestamp"), f"{path}.timestamp", collector, nullable=True)
        _identity_matches(
            capture.get("module_sha256"), module_sha256, path, collector, nullable=True
        )
        _rva_within_image(capture.get("rip_rva"), image_size, f"{path}.rip_rva", collector)
        for memory_index, memory in enumerate(_mapping_items(capture.get("object_memory"))):
            memory_path = f"{path}.object_memory[{memory_index}]"
            _identity_matches(memory.get("module_sha256"), module_sha256, memory_path, collector)
            size = memory.get("bytes")
            if isinstance(size, int) and not isinstance(size, bool) and size < 0:
                collector.add(
                    "MEMORY_NEGATIVE_SIZE",
                    f"{memory_path}.bytes",
                    "memory size is negative",
                )
            base_rva = _hex_int(memory.get("base_rva"))
            if (
                isinstance(size, int)
                and not isinstance(size, bool)
                and size >= 0
                and base_rva is not None
                and isinstance(image_size, int)
                and base_rva + size > image_size
            ):
                collector.add(
                    "ADDRESS_RANGE_OUTSIDE_IMAGE",
                    memory_path,
                    "memory range extends outside the module image",
                )
            bytes_hex = memory.get("bytes_hex")
            if isinstance(size, int) and size >= 0 and isinstance(bytes_hex, str):
                if len(bytes_hex) != size * 2:
                    collector.add(
                        "MEMORY_LENGTH_MISMATCH",
                        f"{memory_path}.bytes_hex",
                        "bytes_hex length does not match bytes",
                    )
                elif re.fullmatch(r"[A-Fa-f0-9]*", bytes_hex):
                    digest = hashlib.sha256(bytes.fromhex(bytes_hex)).hexdigest()
                    if memory.get("sha256") != digest:
                        collector.add(
                            "MEMORY_SHA256_MISMATCH",
                            f"{memory_path}.sha256",
                            "memory SHA-256 does not match bytes_hex",
                        )

    if carrier == "hybrid" and sources and not {"x64dbg", "kcse"}.issubset(sources):
        collector.add(
            "CARRIER_HYBRID_INCOMPLETE",
            "$.captures",
            "hybrid evidence must contain both x64dbg and kcse captures",
        )
    _validate_limits(bundle, captures, collector)
    _validate_evidence_result(bundle, collector)
    _validate_debugger_handoff(bundle, collector)
    _validate_cleanup(bundle, collector)
    stage = bundle.get("stage")
    if isinstance(stage, str) and stage in {"final", "import_ready"}:
        _validate_final(bundle, captures, collector)


def _validate_final(
    bundle: Mapping[str, Any], captures: Sequence[Mapping[str, Any]], collector: _Collector
) -> None:
    required = {
        "$.deployment_binding_sha256": bundle.get("deployment_binding_sha256"),
        "$.module_base": bundle.get("module_base"),
        "$.observations": bundle.get("observations"),
        "$.captures": bundle.get("captures"),
    }
    for path, value in required.items():
        if value is None or value == "" or value == []:
            collector.add("FINAL_FIELD_REQUIRED", path, "final bundle field must be nonempty")
    if bundle.get("result") == "not_evaluated":
        collector.add("FINAL_FIELD_REQUIRED", "$.result", "final bundle result must be evaluated")
    for index, location in enumerate(_mapping_items(bundle.get("locations"))):
        if location.get("absolute") in {None, ""}:
            collector.add(
                "FINAL_FIELD_REQUIRED",
                f"$.locations[{index}].absolute",
                "final location absolute address must be nonempty",
            )
    for index, capture in enumerate(captures):
        for name in ("thread_id", "timestamp", "module_sha256", "rip_rva"):
            if capture.get(name) in {None, ""}:
                collector.add(
                    "FINAL_FIELD_REQUIRED",
                    f"$.captures[{index}].{name}",
                    "final capture field must be nonempty",
                )


def _validate_cleanup(bundle: Mapping[str, Any], collector: _Collector) -> None:
    cleanup = bundle.get("cleanup")
    if not isinstance(cleanup, Mapping):
        collector.add("CLEANUP_REQUIRED", "$.cleanup", "cleanup record is required")
        return
    stage = bundle.get("stage")
    if not isinstance(stage, str) or stage not in {"final", "import_ready"}:
        return
    carrier = bundle.get("carrier")
    requirements = {"game_running": False, "raw_log_archived": True}
    if carrier in {"x64dbg", "hybrid"}:
        requirements["breakpoints_cleared"] = True
        if cleanup.get("debugger_state") not in {"detached", "not_running"}:
            collector.add(
                "CLEANUP_REQUIRED",
                "$.cleanup.debugger_state",
                "final debugger cleanup state must be detached or not_running",
            )
    if carrier in {"kcse", "hybrid", "lua"}:
        requirements["temporary_probe_removed"] = True
    for field, expected in requirements.items():
        if cleanup.get(field) is not expected:
            collector.add(
                "CLEANUP_REQUIRED",
                f"$.cleanup.{field}",
                f"final cleanup requires {field}={str(expected).lower()}",
            )


def _validate_debugger_handoff(
    bundle: Mapping[str, Any], collector: _Collector
) -> None:
    handoff = bundle.get("debugger_handoff")
    if not isinstance(handoff, Mapping):
        return
    state = handoff.get("debugger_state")
    requested = handoff.get("requested") is True
    eligible = handoff.get("gameplay_eligible") is True
    _validate_timestamp(
        handoff.get("resumed_at"), "$.debugger_handoff.resumed_at", collector, nullable=True
    )
    _validate_timestamp(
        handoff.get("verified_at"), "$.debugger_handoff.verified_at", collector, nullable=True
    )
    if eligible and bundle.get("carrier") not in {"x64dbg", "hybrid"}:
        collector.add(
            "DEBUGGER_HANDOFF_UNSAFE",
            "$.debugger_handoff",
            "debugger gameplay handoff requires an x64dbg or hybrid carrier",
        )
    if state == "connected_running":
        if handoff.get("debugging") is not True or handoff.get("running") is not True:
            collector.add(
                "DEBUGGER_STATE_UNPROVEN",
                "$.debugger_handoff",
                "connected_running requires debugging=true and running=true",
            )
        resumed = _parse_timestamp(handoff.get("resumed_at"))
        verified = _parse_timestamp(handoff.get("verified_at"))
        minimum_delay_ms = handoff.get("minimum_delay_ms")
        if (
            resumed is None
            or verified is None
            or not isinstance(minimum_delay_ms, int)
            or isinstance(minimum_delay_ms, bool)
            or (verified - resumed).total_seconds() * 1000 < minimum_delay_ms
        ):
            collector.add(
                "DEBUGGER_HANDOFF_DELAY_INVALID",
                "$.debugger_handoff.verified_at",
                "connected_running verification must follow resume by the declared delay",
            )
    if eligible and (state != "connected_running" or not requested):
        collector.add(
            "DEBUGGER_HANDOFF_UNSAFE",
            "$.debugger_handoff",
            "gameplay eligibility requires a requested connected_running handoff",
        )


def _validate_evidence_result(bundle: Mapping[str, Any], collector: _Collector) -> None:
    result = bundle.get("result")
    completeness = bundle.get("completeness")
    reasons = bundle.get("truncation_reasons")
    reasons = reasons if isinstance(reasons, list) else []
    if completeness == "complete" and reasons:
        collector.add(
            "EVIDENCE_RESULT_INCONSISTENT",
            "$.truncation_reasons",
            "complete evidence cannot declare truncation reasons",
        )
    if result == "confirmed_negative_in_covered_scope" and (
        completeness != "complete" or reasons
    ):
        collector.add(
            "EVIDENCE_RESULT_INCONSISTENT",
            "$.result",
            "confirmed negative evidence requires complete, untruncated capture",
        )
    if result == "positive_observation":
        observations = _mapping_items(bundle.get("observations"))
        if not any(item.get("confirmed") is True for item in observations):
            collector.add(
                "EVIDENCE_RESULT_INCONSISTENT",
                "$.result",
                "positive_observation requires a confirmed observation",
            )
    if result == "capture_inconclusive" and not reasons:
        collector.add(
            "EVIDENCE_RESULT_INCONSISTENT",
            "$.result",
            "capture_inconclusive requires at least one reason",
        )


def _validate_limits(
    bundle: Mapping[str, Any], captures: Sequence[Mapping[str, Any]], collector: _Collector
) -> None:
    limits = bundle.get("limits")
    if not isinstance(limits, Mapping):
        return
    try:
        state = evaluate_probe_bundle_limits(bundle)
    except (TypeError, ValueError):
        return
    for diagnostic in state.diagnostics:
        collector.add(
            diagnostic.code,
            "$.limits." + diagnostic.limit_name,
            f"{diagnostic.limit_name}: observed {diagnostic.observed}, limit {diagnostic.limit}",
        )
    if bundle.get("result") == "confirmed_negative_in_covered_scope" and (
        not state.absence_claim_allowed
    ):
        collector.add(
            "EVIDENCE_RESULT_INCONSISTENT",
            "$.result",
            "confirmed negative evidence is invalid when any aggregate limit is saturated",
        )


def _validate_schema(
    value: Any,
    schema: Mapping[str, Any],
    root: Mapping[str, Any],
    path: str,
    collector: _Collector,
) -> None:
    if "$ref" in schema:
        target: Any = root
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/"):
            collector.add("SCHEMA_REFERENCE", path, "unsupported schema reference")
            return
        for token in reference[2:].split("/"):
            target = target[token.replace("~1", "/").replace("~0", "~")]
        _validate_schema(value, target, root, path, collector)
        return
    if "oneOf" in schema:
        matches = 0
        for branch in schema["oneOf"]:
            branch_collector = _Collector(collector.maximum)
            _validate_schema(value, branch, root, path, branch_collector)
            if not branch_collector.items and not branch_collector.truncated:
                matches += 1
        if matches != 1:
            collector.add(
                "SCHEMA_ONE_OF",
                path,
                f"value matches {matches} oneOf branches instead of exactly one",
            )
    if "const" in schema and value != schema["const"]:
        collector.add("SCHEMA_CONST", path, "value does not match required constant")
    if "enum" in schema and value not in schema["enum"]:
        collector.add("SCHEMA_ENUM", path, "value is not in the allowed enumeration")
    expected = schema.get("type")
    types = [expected] if isinstance(expected, str) else expected
    if isinstance(types, list) and not any(_matches_type(value, item) for item in types):
        collector.add("SCHEMA_TYPE", path, "value has an unexpected JSON type")
        return
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            collector.add("SCHEMA_MIN_LENGTH", path, "string is shorter than minLength")
        if len(value) > schema.get("maxLength", len(value)):
            collector.add("SCHEMA_MAX_LENGTH", path, "string exceeds maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            collector.add("SCHEMA_PATTERN", path, "string does not match required pattern")
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value):
            collector.add("SCHEMA_MINIMUM", path, "integer is below minimum")
        if value > schema.get("maximum", value):
            collector.add("SCHEMA_MAXIMUM", path, "integer exceeds maximum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            collector.add("SCHEMA_MIN_ITEMS", path, "array has too few items")
        if len(value) > schema.get("maxItems", len(value)):
            collector.add("SCHEMA_MAX_ITEMS", path, "array has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                collector.add("SCHEMA_UNIQUE_ITEMS", path, "array items are not unique")
        for index, item in enumerate(value):
            _validate_schema(item, schema.get("items", {}), root, f"{path}[{index}]", collector)
    if isinstance(value, Mapping):
        properties = schema.get("properties", {})
        for missing in sorted(set(schema.get("required", ())) - set(value)):
            collector.add("SCHEMA_REQUIRED", f"{path}.{missing}", "required property is missing")
        if len(value) > schema.get("maxProperties", len(value)):
            collector.add("SCHEMA_MAX_PROPERTIES", path, "object has too many properties")
        property_names = schema.get("propertyNames")
        for name in sorted(value):
            child_path = f"{path}.{name}"
            if isinstance(property_names, Mapping):
                _validate_schema(name, property_names, root, f"{path}.<property-name>", collector)
            if name in properties:
                child = properties[name]
            else:
                additional = schema.get("additionalProperties", True)
                if additional is False:
                    collector.add("SCHEMA_ADDITIONAL_PROPERTY", child_path, "unknown property")
                    continue
                child = additional if isinstance(additional, Mapping) else {}
            _validate_schema(value[name], child, root, child_path, collector)


def _validate_timestamp(
    value: Any, path: str, collector: _Collector, *, nullable: bool = False
) -> None:
    if value is None and nullable:
        return
    if (
        not isinstance(value, str)
        or len(value) > 64
        or DATE_TIME_RE.fullmatch(value) is None
    ):
        collector.add("TIMESTAMP_INVALID", path, "timestamp must be a bounded ISO 8601 date-time")
        return
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        collector.add("TIMESTAMP_INVALID", path, "timestamp is not a valid ISO 8601 date-time")
        return
    if parsed.tzinfo is None:
        collector.add("TIMESTAMP_INVALID", path, "timestamp must include time and UTC offset")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or DATE_TIME_RE.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _identity_matches(
    actual: Any,
    expected: Any,
    path: str,
    collector: _Collector,
    *,
    nullable: bool = False,
) -> None:
    if actual is None and nullable:
        return
    matches = actual == expected
    if (
        isinstance(actual, str)
        and isinstance(expected, str)
        and SHA256_RE.fullmatch(actual) is not None
        and SHA256_RE.fullmatch(expected) is not None
    ):
        matches = actual.lower() == expected.lower()
    if not matches:
        collector.add(
            "IDENTITY_MODULE_SHA256_MISMATCH",
            f"{path}.module_sha256",
            "evidence module SHA-256 differs from bundle module identity",
        )


def _rva_within_image(value: Any, image_size: Any, path: str, collector: _Collector) -> None:
    rva = _hex_int(value)
    if rva is not None and isinstance(image_size, int) and rva >= image_size:
        collector.add("ADDRESS_RVA_OUTSIDE_IMAGE", path, "RVA is outside module image")


def _source_allowed(carrier: Any, source: Any) -> bool:
    allowed = {
        "x64dbg": {"x64dbg"},
        "kcse": {"kcse"},
        "hybrid": {"x64dbg", "kcse"},
        "lua": {"lua"},
    }
    return carrier in allowed and source in allowed[carrier]


def _migrate_observation(item: Mapping[str, Any], module_sha256: str) -> dict[str, Any]:
    fields = {
        name: value
        for name, value in item.items()
        if name not in {"subject", "module", "offset", "rva", "type", "confirmed"}
        and _is_scalar(value)
    }
    return {
        "subject": item.get("subject"),
        "module_sha256": module_sha256,
        "rva": item.get("rva", item.get("offset")),
        "observation_type": item.get("type"),
        "confirmed": item.get("confirmed"),
        "fields": fields,
    }


def _migrate_capture(
    item: Mapping[str, Any],
    index: int,
    carrier: str,
    module_sha256: str,
    module_base_value: Any,
) -> dict[str, Any]:
    source = item.get("source", carrier if carrier != "hybrid" else None)
    rip_rva = item.get("rip_rva")
    if rip_rva is None:
        rip = _hex_int(item.get("rip"))
        module_base = _hex_int(module_base_value)
        if rip is not None and module_base is not None and rip >= module_base:
            rip_rva = hex(rip - module_base)
    fields = item.get("fields") if isinstance(item.get("fields"), Mapping) else {}
    return {
        "capture_id": item.get("capture_id", f"legacy-{index}"),
        "source": source,
        "event": item.get("event"),
        "thread_id": str(item["thread_id"]) if item.get("thread_id") is not None else None,
        "timestamp": item.get("timestamp"),
        "module_sha256": module_sha256,
        "rip_rva": rip_rva,
        "registers": item.get("registers") if isinstance(item.get("registers"), Mapping) else {},
        "fields": dict(fields),
        "object_memory": [],
    }


def _mapping_items(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _hex_int(value: Any) -> int | None:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        return None
    return int(value, 16)


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _bool_or_default(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, bool))


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]
