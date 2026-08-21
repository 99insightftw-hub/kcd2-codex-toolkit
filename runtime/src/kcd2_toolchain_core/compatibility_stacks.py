"""Versioned, exact-identity cross-mod compatibility stack manifests."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.compatibility-stack.v1"
STACK_ID_PREFIX = "compatibility-stack:sha256:"
MAX_MEMBERS = 256
MAX_VARIANTS = 4_096
MAX_RESOURCES = 16_384
MAX_ASSERTIONS = 4_096
MAX_DEPENDENCIES = 4_096
MAX_CANONICAL_BYTES = 8 * 1024 * 1024

FAMILIES = frozenset(
    {
        "CORE_SCRIPTING",
        "AI_WORLD",
        "BALANCE_TABLE",
        "UI_VISUAL_LOCALIZATION",
        "ANIMATION_AUDIO_HAPTIC",
        "CUSTOM",
    }
)
CHECK_STATUSES = frozenset({"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN"})
COVERAGE_STATUSES = frozenset({"COMPLETE", "PARTIAL", "INVALID"})
RESULTS = frozenset({"PASS", "FAIL", "INCONCLUSIVE"})
STATE_TYPES = frozenset(
    {
        "GAME_BUILD",
        "SAVE",
        "LOCATION",
        "NPC",
        "ITEM",
        "UI",
        "MOUNT_CONTEXT",
        "CONFIGURATION",
        "CUSTOM",
    }
)

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_PROJECT_ID = re.compile(r"^project:sha256:[0-9a-f]{64}$")
_SELECTION_ID = re.compile(r"^variant-selection:sha256:[0-9a-f]{64}$")
_MEMBER_ID = re.compile(r"^variant-member:sha256:[0-9a-f]{64}$")
_SNAPSHOT_ID = re.compile(r"^active-snapshot:sha256:[0-9a-f]{64}$")
_SESSION_ID = re.compile(r"^runtime-session:sha256:[0-9a-f]{64}$")


class CompatibilityStackError(ValueError):
    """A compatibility stack violates the closed, exact-identity contract."""


class CompatibilityStackIdentityMismatchError(CompatibilityStackError):
    """An asserted stack identity differs from the canonical manifest bytes."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field} must be a mapping with string keys")
    return value


def _sequence(
    value: Any,
    field: str,
    maximum: int,
    *,
    minimum: int = 0,
) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if not minimum <= len(value) <= maximum:
        raise CompatibilityStackError(
            f"{field} must contain between {minimum} and {maximum} items"
        )
    return value


def _exact_fields(
    value: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    field: str,
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        raise CompatibilityStackError(
            f"{field} fields do not match contract; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _string(value: Any, field: str, maximum: int = 2048) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise CompatibilityStackError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _digest(value: Any, field: str) -> str:
    digest = _string(value, field, 64)
    if _SHA256.fullmatch(digest) is None:
        raise CompatibilityStackError(f"{field} must be a SHA-256 digest")
    return digest.lower()


def _pattern(value: Any, field: str, pattern: re.Pattern[str]) -> str:
    text = _string(value, field, 256)
    if pattern.fullmatch(text) is None:
        raise CompatibilityStackError(f"{field} is not an exact content identity")
    return text


def _unique_strings(
    value: Any,
    field: str,
    maximum: int,
    *,
    minimum: int = 0,
) -> list[str]:
    result = [
        _string(item, f"{field}[{index}]")
        for index, item in enumerate(
            _sequence(value, field, maximum, minimum=minimum)
        )
    ]
    if len(result) != len(set(result)):
        raise CompatibilityStackError(f"{field} must be unique")
    return sorted(result)


def _normalize_members(value: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    project_ids: set[str] = set()
    candidates: set[tuple[str, str]] = set()
    for index, raw in enumerate(
        _sequence(value, "members", MAX_MEMBERS, minimum=2)
    ):
        field = f"members[{index}]"
        item = _mapping(raw, field)
        _exact_fields(
            item,
            {"project_id", "project_sha256", "candidate_id", "candidate_sha256"},
            set(),
            field,
        )
        project_id = _pattern(item["project_id"], f"{field}.project_id", _PROJECT_ID)
        if project_id in project_ids:
            raise CompatibilityStackError("members must name each project exactly once")
        project_ids.add(project_id)
        candidate_id = _string(item["candidate_id"], f"{field}.candidate_id", 256)
        candidate_sha256 = _digest(
            item["candidate_sha256"], f"{field}.candidate_sha256"
        )
        candidate_key = (candidate_id, candidate_sha256)
        if candidate_key in candidates:
            raise CompatibilityStackError("members contain a duplicate candidate identity")
        candidates.add(candidate_key)
        result.append(
            {
                "project_id": project_id,
                "project_sha256": _digest(
                    item["project_sha256"], f"{field}.project_sha256"
                ),
                "candidate_id": candidate_id,
                "candidate_sha256": candidate_sha256,
            }
        )
    return sorted(result, key=lambda item: item["project_id"])


def _normalize_variants(value: Any, project_ids: set[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    projects: set[str] = set()
    for index, raw in enumerate(_sequence(value, "selected_variants", MAX_VARIANTS)):
        field = f"selected_variants[{index}]"
        item = _mapping(raw, field)
        _exact_fields(
            item,
            {"project_id", "selection_id", "selected_member_ids"},
            set(),
            field,
        )
        project_id = _pattern(item["project_id"], f"{field}.project_id", _PROJECT_ID)
        if project_id not in project_ids:
            raise CompatibilityStackError(f"{field}.project_id is not a stack member")
        if project_id in projects:
            raise CompatibilityStackError(
                "selected_variants must contain at most one selection per project"
            )
        projects.add(project_id)
        member_ids = [
            _pattern(member, f"{field}.selected_member_ids[{member_index}]", _MEMBER_ID)
            for member_index, member in enumerate(
                _sequence(
                    item["selected_member_ids"],
                    f"{field}.selected_member_ids",
                    MAX_VARIANTS,
                    minimum=1,
                )
            )
        ]
        if len(member_ids) != len(set(member_ids)):
            raise CompatibilityStackError(f"{field}.selected_member_ids must be unique")
        result.append(
            {
                "project_id": project_id,
                "selection_id": _pattern(
                    item["selection_id"], f"{field}.selection_id", _SELECTION_ID
                ),
                "selected_member_ids": sorted(member_ids),
            }
        )
    return sorted(result, key=lambda item: item["project_id"])


def _normalize_dependencies(value: Any, project_ids: set[str]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(value, "dependencies", MAX_DEPENDENCIES)):
        field = f"dependencies[{index}]"
        item = _mapping(raw, field)
        _exact_fields(
            item,
            {"project_id", "version", "artifact_sha256"},
            set(),
            field,
        )
        project_id = _pattern(item["project_id"], f"{field}.project_id", _PROJECT_ID)
        if project_id not in project_ids:
            raise CompatibilityStackError(f"{field}.project_id is not a stack member")
        if project_id in seen:
            raise CompatibilityStackError("dependencies must name each project once")
        seen.add(project_id)
        result.append(
            {
                "project_id": project_id,
                "version": _string(item["version"], f"{field}.version", 128),
                "artifact_sha256": _digest(
                    item["artifact_sha256"], f"{field}.artifact_sha256"
                ),
            }
        )
    return sorted(result, key=lambda item: item["project_id"])


def _normalize_resources(
    value: Any,
    field_name: str,
    project_ids: set[str],
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(_sequence(value, field_name, MAX_RESOURCES)):
        field = f"{field_name}[{index}]"
        item = _mapping(raw, field)
        _exact_fields(
            item,
            {"resource", "provider_project_id"},
            set(),
            field,
        )
        try:
            path = canonical_relative_path(item["resource"])
        except (TypeError, ValueError) as exc:
            raise CompatibilityStackError(f"{field}.resource is invalid") from exc
        key = canonical_path_key(path)
        if key in seen:
            raise CompatibilityStackError(f"{field_name} resources must be unique")
        seen.add(key)
        provider = _pattern(
            item["provider_project_id"],
            f"{field}.provider_project_id",
            _PROJECT_ID,
        )
        if provider not in project_ids:
            raise CompatibilityStackError(
                f"{field}.provider_project_id is not a stack member"
            )
        result.append({"resource": path, "provider_project_id": provider})
    return sorted(result, key=lambda item: canonical_path_key(item["resource"]))


def _normalize_checks(
    value: Any,
    field_name: str,
    *,
    state: bool = False,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    maximum = MAX_ASSERTIONS
    for index, raw in enumerate(_sequence(value, field_name, maximum)):
        field = f"{field_name}[{index}]"
        item = _mapping(raw, field)
        identifier = "state_id" if state else "assertion_id"
        required = {identifier, "status", "evidence_ids"}
        if state:
            required.update({"state_type", "expected"})
        _exact_fields(item, required, set(), field)
        check_id = _string(item[identifier], f"{field}.{identifier}", 256)
        if check_id in seen:
            raise CompatibilityStackError(f"{field_name} identifiers must be unique")
        seen.add(check_id)
        status = _string(item["status"], f"{field}.status", 32)
        if status not in CHECK_STATUSES:
            raise CompatibilityStackError(f"{field}.status is not supported")
        evidence_ids = _unique_strings(
            item["evidence_ids"], f"{field}.evidence_ids", 256
        )
        if status in {"PASS", "FAIL"} and not evidence_ids:
            raise CompatibilityStackError(
                f"{field}.evidence_ids is required for an evidentiary status"
            )
        normalized: dict[str, Any] = {
            identifier: check_id,
            "status": status,
            "evidence_ids": evidence_ids,
        }
        if state:
            state_type = _string(item["state_type"], f"{field}.state_type", 64)
            if state_type not in STATE_TYPES:
                raise CompatibilityStackError(f"{field}.state_type is not supported")
            normalized = {
                "state_id": check_id,
                "state_type": state_type,
                "expected": _string(item["expected"], f"{field}.expected", 2048),
                "status": status,
                "evidence_ids": evidence_ids,
            }
        result.append(normalized)
    return sorted(result, key=lambda item: item["state_id" if state else "assertion_id"])


def _normalize_identity(value: Any) -> dict[str, Any]:
    item = _mapping(value, "identity")
    _exact_fields(
        item,
        {
            "package_sha256",
            "active_snapshot_id",
            "runtime_session_ids",
            "mod_order_sha256",
        },
        set(),
        "identity",
    )
    sessions = [
        _pattern(session, f"identity.runtime_session_ids[{index}]", _SESSION_ID)
        for index, session in enumerate(
            _sequence(
                item["runtime_session_ids"],
                "identity.runtime_session_ids",
                256,
                minimum=1,
            )
        )
    ]
    if len(sessions) != len(set(sessions)):
        raise CompatibilityStackError("identity.runtime_session_ids must be unique")
    return {
        "package_sha256": _digest(item["package_sha256"], "identity.package_sha256"),
        "active_snapshot_id": _pattern(
            item["active_snapshot_id"],
            "identity.active_snapshot_id",
            _SNAPSHOT_ID,
        ),
        "runtime_session_ids": sorted(sessions),
        "mod_order_sha256": _digest(
            item["mod_order_sha256"], "identity.mod_order_sha256"
        ),
    }


def _normalize_coverage(value: Any, snapshot_id: str) -> dict[str, Any]:
    item = _mapping(value, "coverage")
    _exact_fields(
        item,
        {
            "snapshot_id",
            "provider_catalog_sha256",
            "status",
            "covered_resources",
            "total_resources",
            "reason_codes",
        },
        set(),
        "coverage",
    )
    coverage_snapshot = _pattern(
        item["snapshot_id"], "coverage.snapshot_id", _SNAPSHOT_ID
    )
    if coverage_snapshot != snapshot_id:
        raise CompatibilityStackError(
            "coverage.snapshot_id must match identity.active_snapshot_id"
        )
    status = _string(item["status"], "coverage.status", 32)
    if status not in COVERAGE_STATUSES:
        raise CompatibilityStackError("coverage.status is not supported")
    covered = item["covered_resources"]
    total = item["total_resources"]
    if (
        not isinstance(covered, int)
        or isinstance(covered, bool)
        or not isinstance(total, int)
        or isinstance(total, bool)
        or not 0 <= covered <= total <= MAX_RESOURCES
    ):
        raise CompatibilityStackError(
            f"coverage counts must satisfy 0 <= covered <= total <= {MAX_RESOURCES}"
        )
    reasons = _unique_strings(item["reason_codes"], "coverage.reason_codes", 256)
    if status == "COMPLETE" and (covered != total or reasons):
        raise CompatibilityStackError(
            "COMPLETE coverage requires equal counts and no reason codes"
        )
    if status != "COMPLETE" and not reasons:
        raise CompatibilityStackError(
            "non-complete coverage requires at least one reason code"
        )
    return {
        "snapshot_id": coverage_snapshot,
        "provider_catalog_sha256": _digest(
            item["provider_catalog_sha256"], "coverage.provider_catalog_sha256"
        ),
        "status": status,
        "covered_resources": covered,
        "total_resources": total,
        "reason_codes": reasons,
    }


def _result(
    required_states: list[dict[str, Any]],
    static_assertions: list[dict[str, Any]],
    runtime_assertions: list[dict[str, Any]],
    coverage: Mapping[str, Any],
) -> str:
    statuses = [
        item["status"]
        for item in [*required_states, *static_assertions, *runtime_assertions]
    ]
    if coverage["status"] == "INVALID" or "FAIL" in statuses:
        return "FAIL"
    if coverage["status"] != "COMPLETE" or any(
        status in {"INCONCLUSIVE", "NOT_RUN"} for status in statuses
    ):
        return "INCONCLUSIVE"
    return "PASS"


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        {
            "schema_version",
            "manifest_version",
            "family",
            "members",
            "selected_variants",
            "composite_declaration_ids",
            "dependencies",
            "excluded_project_ids",
            "intended_winners",
            "protected_resources",
            "required_states",
            "static_assertions",
            "runtime_assertions",
            "identity",
            "coverage",
        },
        {"stack_id", "result"},
        "compatibility stack",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise CompatibilityStackError(f"schema_version must be {SCHEMA_VERSION}")
    manifest_version = value["manifest_version"]
    if not isinstance(manifest_version, int) or isinstance(manifest_version, bool):
        raise CompatibilityStackError("manifest_version must be an integer")
    if not 1 <= manifest_version <= 1_000_000:
        raise CompatibilityStackError("manifest_version is outside the supported bound")
    family = _string(value["family"], "family", 64)
    if family not in FAMILIES:
        raise CompatibilityStackError("family is not supported")
    members = _normalize_members(value["members"])
    project_ids = {item["project_id"] for item in members}
    variants = _normalize_variants(value["selected_variants"], project_ids)
    dependencies = _normalize_dependencies(value["dependencies"], project_ids)
    excluded = [
        _pattern(item, f"excluded_project_ids[{index}]", _PROJECT_ID)
        for index, item in enumerate(
            _sequence(value["excluded_project_ids"], "excluded_project_ids", MAX_MEMBERS)
        )
    ]
    if len(excluded) != len(set(excluded)):
        raise CompatibilityStackError("excluded_project_ids must be unique")
    if project_ids.intersection(excluded):
        raise CompatibilityStackError("a stack member cannot also be excluded")
    composites = _unique_strings(
        value["composite_declaration_ids"],
        "composite_declaration_ids",
        MAX_DEPENDENCIES,
    )
    winners = _normalize_resources(value["intended_winners"], "intended_winners", project_ids)
    protected = _normalize_resources(
        value["protected_resources"], "protected_resources", project_ids
    )
    required_states = _normalize_checks(
        value["required_states"], "required_states", state=True
    )
    static_assertions = _normalize_checks(
        value["static_assertions"], "static_assertions"
    )
    runtime_assertions = _normalize_checks(
        value["runtime_assertions"], "runtime_assertions"
    )
    identity = _normalize_identity(value["identity"])
    coverage = _normalize_coverage(value["coverage"], identity["active_snapshot_id"])
    result = _result(required_states, static_assertions, runtime_assertions, coverage)
    asserted_result = value.get("result")
    if asserted_result is not None:
        if asserted_result not in RESULTS:
            raise CompatibilityStackError("result is not supported")
        if asserted_result != result:
            raise CompatibilityStackError(
                f"result mismatch: asserted {asserted_result!r}, evaluated {result!r}"
            )
    material = {
        "schema_version": SCHEMA_VERSION,
        "manifest_version": manifest_version,
        "family": family,
        "members": members,
        "selected_variants": variants,
        "composite_declaration_ids": composites,
        "dependencies": dependencies,
        "excluded_project_ids": sorted(excluded),
        "intended_winners": winners,
        "protected_resources": protected,
        "required_states": required_states,
        "static_assertions": static_assertions,
        "runtime_assertions": runtime_assertions,
        "identity": identity,
        "coverage": coverage,
        "result": result,
    }
    stack_id = STACK_ID_PREFIX + sha256_json(material)
    asserted_id = value.get("stack_id")
    if asserted_id is not None and asserted_id != stack_id:
        raise CompatibilityStackIdentityMismatchError(
            f"stack_id mismatch: asserted {asserted_id!r}, computed {stack_id!r}"
        )
    normalized = {"schema_version": SCHEMA_VERSION, "stack_id": stack_id}
    normalized.update({key: item for key, item in material.items() if key != "schema_version"})
    if len(canonical_json_bytes(normalized)) > MAX_CANONICAL_BYTES:
        raise CompatibilityStackError("canonical stack exceeds the byte limit")
    return normalized


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return copy.deepcopy(value)


@dataclass(frozen=True, slots=True)
class CompatibilityStackManifest:
    """Deeply immutable, content-addressed compatibility acceptance fixture."""

    _value: Mapping[str, Any]

    @property
    def stack_id(self) -> str:
        return self._value["stack_id"]

    @property
    def manifest_version(self) -> int:
        return self._value["manifest_version"]

    def to_dict(self) -> dict[str, Any]:
        return _plain(self._value)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def evaluate_compatibility_stack(
    value: Mapping[str, Any] | CompatibilityStackManifest,
) -> CompatibilityStackManifest:
    """Evaluate, canonicalize, and content-address one exact compatibility stack."""
    if isinstance(value, CompatibilityStackManifest):
        return value
    return CompatibilityStackManifest(_freeze(_normalize(_mapping(value, "stack"))))


def canonicalize_compatibility_stack(
    value: Mapping[str, Any] | CompatibilityStackManifest,
) -> CompatibilityStackManifest:
    """Verify a transported stack or create its deterministic derived fields."""
    return evaluate_compatibility_stack(value)


def migrate_legacy_compatibility_stack(
    value: Mapping[str, Any],
    *,
    context: Mapping[str, Any],
) -> CompatibilityStackManifest:
    """Migrate a name-only draft only when every missing exact binding is supplied."""
    legacy = _mapping(value, "legacy compatibility stack")
    _exact_fields(
        legacy,
        {
            "schema_version",
            "stack_id",
            "family",
            "projects",
            "selected_variants",
            "intended_winners",
            "protected_resources",
            "checks",
            "result",
        },
        set(),
        "legacy compatibility stack",
    )
    if legacy["schema_version"] != SCHEMA_VERSION:
        raise CompatibilityStackError(
            f"legacy schema_version must be {SCHEMA_VERSION}"
        )
    if legacy["result"] not in {*RESULTS, "NOT_RUN"}:
        raise CompatibilityStackError("legacy result is not supported")
    migration = _mapping(context, "migration context")
    _exact_fields(
        migration,
        {
            "manifest_version",
            "project_identities",
            "variant_identities",
            "composite_declaration_ids",
            "dependencies",
            "excluded_project_ids",
            "required_states",
            "assertion_layers",
            "identity",
            "coverage",
        },
        set(),
        "migration context",
    )
    project_bindings = _mapping(
        migration["project_identities"], "migration context.project_identities"
    )
    members = []
    name_to_project_id: dict[str, str] = {}
    for index, name_value in enumerate(
        _sequence(legacy["projects"], "legacy projects", MAX_MEMBERS, minimum=2)
    ):
        name = _string(name_value, f"legacy projects[{index}]")
        if name not in project_bindings:
            raise CompatibilityStackError(
                f"legacy project {name!r} has no exact project identity binding"
            )
        binding = _mapping(project_bindings[name], f"project identity {name!r}")
        members.append(dict(binding))
        name_to_project_id[name] = _pattern(
            binding.get("project_id"), f"project identity {name!r}.project_id", _PROJECT_ID
        )

    variant_bindings = _mapping(
        migration["variant_identities"], "migration context.variant_identities"
    )
    variants = []
    for index, name_value in enumerate(
        _sequence(legacy["selected_variants"], "legacy selected_variants", MAX_VARIANTS)
    ):
        name = _string(name_value, f"legacy selected_variants[{index}]")
        if name not in variant_bindings:
            raise CompatibilityStackError(
                f"legacy variant {name!r} has no exact variant identity binding"
            )
        variants.append(dict(_mapping(variant_bindings[name], f"variant identity {name!r}")))

    def migrate_resources(field_name: str) -> list[dict[str, str]]:
        resources = []
        for index, raw in enumerate(
            _sequence(legacy[field_name], f"legacy {field_name}", MAX_RESOURCES)
        ):
            item = _mapping(raw, f"legacy {field_name}[{index}]")
            _exact_fields(
                item,
                {"resource", "provider_id"},
                set(),
                f"legacy {field_name}[{index}]",
            )
            provider_name = _string(
                item["provider_id"], f"legacy {field_name}[{index}].provider_id"
            )
            if provider_name not in name_to_project_id:
                raise CompatibilityStackError(
                    f"legacy provider {provider_name!r} has no exact project identity binding"
                )
            resources.append(
                {
                    "resource": item["resource"],
                    "provider_project_id": name_to_project_id[provider_name],
                }
            )
        return resources

    layers = _mapping(migration["assertion_layers"], "migration context.assertion_layers")
    static_assertions = []
    runtime_assertions = []
    for index, raw in enumerate(
        _sequence(legacy["checks"], "legacy checks", MAX_ASSERTIONS)
    ):
        item = _mapping(raw, f"legacy checks[{index}]")
        _exact_fields(
            item,
            {"check_id", "status", "evidence_ids"},
            set(),
            f"legacy checks[{index}]",
        )
        check_id = _string(item.get("check_id"), f"legacy checks[{index}].check_id", 256)
        layer = layers.get(check_id)
        if layer not in {"static", "runtime"}:
            raise CompatibilityStackError(
                f"legacy check {check_id!r} requires an explicit assertion layer"
            )
        migrated = {
            "assertion_id": check_id,
            "status": item.get("status"),
            "evidence_ids": item.get("evidence_ids"),
        }
        (static_assertions if layer == "static" else runtime_assertions).append(migrated)

    return evaluate_compatibility_stack(
        {
            "schema_version": SCHEMA_VERSION,
            "manifest_version": migration["manifest_version"],
            "family": legacy["family"],
            "members": members,
            "selected_variants": variants,
            "composite_declaration_ids": migration["composite_declaration_ids"],
            "dependencies": migration["dependencies"],
            "excluded_project_ids": migration["excluded_project_ids"],
            "intended_winners": migrate_resources("intended_winners"),
            "protected_resources": migrate_resources("protected_resources"),
            "required_states": migration["required_states"],
            "static_assertions": static_assertions,
            "runtime_assertions": runtime_assertions,
            "identity": migration["identity"],
            "coverage": migration["coverage"],
        }
    )


__all__ = [
    "CompatibilityStackError",
    "CompatibilityStackIdentityMismatchError",
    "CompatibilityStackManifest",
    "canonicalize_compatibility_stack",
    "evaluate_compatibility_stack",
    "migrate_legacy_compatibility_stack",
]
