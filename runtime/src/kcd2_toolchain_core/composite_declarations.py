"""Deterministic composite declarations and protected-resource linting."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.composite-intent.v1"
MAX_MEMBERS = 256
MAX_SHARED_RESOURCES = 16_384
MAX_DEPENDENCIES = 4_096
MAX_RUNTIME_ASSERTIONS = 4_096
MAX_CANONICAL_BYTES = 4 * 1024 * 1024

RELATIONSHIP_TYPES = frozenset(
    {
        "COMPOSITE_WITH",
        "SUPERSEDES",
        "REPLACES",
        "COMPATIBILITY_FOR",
        "MIRRORS",
        "UNKNOWN_REQUIRES_DECLARATION",
    }
)
RESOURCE_INTENTS = frozenset(
    {
        "INTENDED_WINNER",
        "INTENDED_MERGE",
        "PROTECTED_UPSTREAM",
        "IDENTICAL_MIRROR",
        "UNRESOLVED",
    }
)
DECLARATION_VERDICTS = frozenset(
    {"DECLARED_VALID", "DECLARED_INVALID", "UNRESOLVED"}
)
RESOLUTIONS = frozenset({"winner", "merge", "parallel", "identical", "unsupported"})
RUNTIME_RESULTS = frozenset({"passed", "failed", "not_observed"})


class CompositeDeclarationError(ValueError):
    """A composite declaration or lint input violates its closed contract."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field} must be a mapping with string keys")
    return value


def _exact_fields(
    value: Mapping[str, Any], required: set[str], optional: set[str], field: str
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        raise CompositeDeclarationError(
            f"{field} fields do not match contract; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _sequence(value: Any, field: str, maximum: int, *, minimum: int = 0) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if not minimum <= len(value) <= maximum:
        raise CompositeDeclarationError(
            f"{field} must contain between {minimum} and {maximum} items"
        )
    return value


def _string(value: Any, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise CompositeDeclarationError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _unique_strings(
    value: Any, field: str, maximum_items: int, *, minimum: int = 0
) -> list[str]:
    result = [
        _string(item, f"{field}[{index}]")
        for index, item in enumerate(
            _sequence(value, field, maximum_items, minimum=minimum)
        )
    ]
    if len(result) != len(set(result)):
        raise CompositeDeclarationError(f"{field} must be unique")
    return sorted(result)


def _normalize_shared_resources(
    value: Any, members: set[str]
) -> list[dict[str, str | None]]:
    resources: list[dict[str, str | None]] = []
    seen: set[str] = set()
    for index, raw in enumerate(
        _sequence(value, "shared_resources", MAX_SHARED_RESOURCES)
    ):
        field = f"shared_resources[{index}]"
        item = _mapping(raw, field)
        _exact_fields(item, {"canonical_path", "intent"}, {"winner_project_id"}, field)
        try:
            path = canonical_relative_path(item["canonical_path"])
        except (TypeError, ValueError) as exc:
            raise CompositeDeclarationError(f"{field}.canonical_path is invalid") from exc
        path_key = canonical_path_key(path)
        if path_key in seen:
            raise CompositeDeclarationError("shared_resources paths must be unique")
        seen.add(path_key)
        intent = _string(item["intent"], f"{field}.intent", 64)
        if intent not in RESOURCE_INTENTS:
            raise CompositeDeclarationError(f"{field}.intent is not supported")
        owner = item.get("winner_project_id")
        if owner is not None:
            owner = _string(owner, f"{field}.winner_project_id")
        if intent in {"INTENDED_WINNER", "PROTECTED_UPSTREAM"}:
            if owner is None:
                raise CompositeDeclarationError(
                    f"{field}.winner_project_id is required for {intent}"
                )
            if owner not in members:
                raise CompositeDeclarationError(
                    f"{field}.winner_project_id must name a composite member"
                )
        elif owner is not None:
            raise CompositeDeclarationError(
                f"{field}.winner_project_id must be null for {intent}"
            )
        resources.append(
            {"canonical_path": path, "intent": intent, "winner_project_id": owner}
        )
    return sorted(resources, key=lambda item: canonical_path_key(str(item["canonical_path"])))


def _dependency_versions(value: Any) -> tuple[list[str], dict[str, str]]:
    declarations = _unique_strings(value, "required_dependency_versions", MAX_DEPENDENCIES)
    parsed: dict[str, str] = {}
    for index, declaration in enumerate(declarations):
        project_id, separator, version = declaration.rpartition("@")
        if not separator or not project_id or not version:
            raise CompositeDeclarationError(
                f"required_dependency_versions[{index}] must use project_id@version"
            )
        if project_id in parsed:
            raise CompositeDeclarationError(
                "required_dependency_versions must name each project once"
            )
        parsed[project_id] = version
    return declarations, parsed


def _normalize_declaration(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        {
            "schema_version",
            "relationship_id",
            "relationship_type",
            "members",
            "shared_resources",
            "verdict",
        },
        {"required_dependency_versions", "runtime_assertions"},
        "composite declaration",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise CompositeDeclarationError(f"schema_version must be {SCHEMA_VERSION}")
    relationship_type = _string(value["relationship_type"], "relationship_type", 64)
    if relationship_type not in RELATIONSHIP_TYPES:
        raise CompositeDeclarationError("relationship_type is not supported")
    members = _unique_strings(value["members"], "members", MAX_MEMBERS, minimum=2)
    resources = _normalize_shared_resources(value["shared_resources"], set(members))
    dependencies, _ = _dependency_versions(value.get("required_dependency_versions", []))
    assertions = _unique_strings(
        value.get("runtime_assertions", []), "runtime_assertions", MAX_RUNTIME_ASSERTIONS
    )
    verdict = _string(value["verdict"], "verdict", 64)
    if verdict not in DECLARATION_VERDICTS:
        raise CompositeDeclarationError("verdict is not supported")
    normalized = {
        "schema_version": SCHEMA_VERSION,
        "relationship_id": _string(value["relationship_id"], "relationship_id"),
        "relationship_type": relationship_type,
        "members": members,
        "shared_resources": resources,
        "required_dependency_versions": dependencies,
        "runtime_assertions": assertions,
        "verdict": verdict,
    }
    if len(canonical_json_bytes(normalized)) > MAX_CANONICAL_BYTES:
        raise CompositeDeclarationError("canonical declaration exceeds byte limit")
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


@dataclass(frozen=True)
class CompositeDeclaration:
    """Immutable canonical composite intent declaration."""

    _value: Mapping[str, Any]

    @property
    def members(self) -> tuple[str, ...]:
        return tuple(self._value["members"])

    @property
    def shared_resources(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._value["shared_resources"])

    def to_dict(self) -> dict[str, Any]:
        return _plain(self._value)

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


@dataclass(frozen=True)
class CompositeLintResult:
    """Deterministic composite lint result with explicit failure and uncertainty."""

    _value: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _plain(self._value)


def canonicalize_composite_declaration(
    value: Mapping[str, Any],
) -> CompositeDeclaration:
    """Validate and canonicalize the reviewed composite-intent v1 draft."""

    return CompositeDeclaration(_freeze(_normalize_declaration(_mapping(value, "value"))))


def _normalize_observations(value: Any, members: set[str]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(
        _sequence(value, "observed_resources", MAX_SHARED_RESOURCES)
    ):
        field = f"observed_resources[{index}]"
        item = _mapping(raw, field)
        _exact_fields(
            item,
            {
                "canonical_path",
                "provider_project_ids",
                "effective_project_ids",
                "resolution",
            },
            set(),
            field,
        )
        try:
            path = canonical_relative_path(item["canonical_path"])
        except (TypeError, ValueError) as exc:
            raise CompositeDeclarationError(f"{field}.canonical_path is invalid") from exc
        key = canonical_path_key(path)
        if key in seen:
            raise CompositeDeclarationError("observed_resources paths must be unique")
        seen.add(key)
        providers = _unique_strings(
            item["provider_project_ids"], f"{field}.provider_project_ids", MAX_MEMBERS, minimum=2
        )
        if not set(providers).issubset(members):
            raise CompositeDeclarationError(
                f"{field}.provider_project_ids must name composite members"
            )
        effective = _unique_strings(
            item["effective_project_ids"], f"{field}.effective_project_ids", MAX_MEMBERS
        )
        if not set(effective).issubset(set(providers)):
            raise CompositeDeclarationError(
                f"{field}.effective_project_ids must be observed providers"
            )
        resolution = _string(item["resolution"], f"{field}.resolution", 64)
        if resolution not in RESOLUTIONS:
            raise CompositeDeclarationError(f"{field}.resolution is not supported")
        observations.append(
            {
                "canonical_path": path,
                "provider_project_ids": providers,
                "effective_project_ids": effective,
                "resolution": resolution,
            }
        )
    return sorted(observations, key=lambda item: canonical_path_key(item["canonical_path"]))


def _resource_outcome(
    declaration: Mapping[str, Any], observation: Mapping[str, Any]
) -> tuple[str, str | None, dict[str, Any] | None]:
    intent = declaration["intent"]
    path = str(observation["canonical_path"])
    resolution = observation["resolution"]
    providers = list(observation["provider_project_ids"])
    effective = list(observation["effective_project_ids"])
    owner = declaration["winner_project_id"]
    if intent == "UNRESOLVED":
        return "DECLARED_UNRESOLVED", "DECLARED_RESOURCE_UNRESOLVED", None
    if resolution == "unsupported":
        reason = (
            "PROTECTED_OUTCOME_UNRESOLVED"
            if intent == "PROTECTED_UPSTREAM"
            else "RESOURCE_OUTCOME_UNRESOLVED"
        )
        return "OUTCOME_UNRESOLVED", reason, None
    if intent == "INTENDED_WINNER":
        if resolution == "winner" and effective == [owner]:
            return "INTENDED_WINNER_RETAINED", None, None
        return "INTENDED_WINNER_MISMATCH", "INTENDED_WINNER_MISMATCH", None
    if intent == "INTENDED_MERGE":
        if resolution == "merge" and effective == providers:
            return "DECLARED_MERGE_RETAINED", None, None
        return "DECLARED_MERGE_MISMATCH", "DECLARED_MERGE_MISMATCH", None
    if intent == "IDENTICAL_MIRROR":
        if resolution == "identical" and effective == providers:
            return "IDENTICAL_MIRROR_RETAINED", None, None
        return "IDENTICAL_MIRROR_MISMATCH", "IDENTICAL_MIRROR_MISMATCH", None
    if owner in effective:
        return "PROTECTED_RETAINED", None, None
    violation = {
        "canonical_path": path,
        "required_project_id": owner,
        "effective_project_ids": effective,
    }
    return "PROTECTED_RESOURCE_LOST", "PROTECTED_RESOURCE_LOSS", violation


def lint_composite_declaration(
    declaration: Mapping[str, Any] | CompositeDeclaration,
    *,
    observed_resources: Sequence[Mapping[str, Any]],
    installed_dependency_versions: Mapping[str, str],
    runtime_assertion_results: Mapping[str, str],
) -> CompositeLintResult:
    """Lint observed overlaps against declared intent without inferring a duplicate verdict."""

    canonical = (
        declaration
        if isinstance(declaration, CompositeDeclaration)
        else canonicalize_composite_declaration(declaration)
    )
    declared = canonical.to_dict()
    observations = _normalize_observations(observed_resources, set(canonical.members))
    dependency_versions = _mapping(
        installed_dependency_versions, "installed_dependency_versions"
    )
    assertion_results = _mapping(runtime_assertion_results, "runtime_assertion_results")
    declarations_by_path = {
        canonical_path_key(item["canonical_path"]): item
        for item in declared["shared_resources"]
    }

    failure_reasons: set[str] = set()
    unresolved_reasons: set[str] = set()
    if declared["verdict"] == "DECLARED_INVALID":
        failure_reasons.add("DECLARATION_INVALID")
    elif declared["verdict"] == "UNRESOLVED":
        unresolved_reasons.add("DECLARATION_UNRESOLVED")
    undeclared: list[str] = []
    protected_violations: list[dict[str, Any]] = []
    resource_results: list[dict[str, Any]] = []
    for observation in observations:
        path = observation["canonical_path"]
        resource_declaration = declarations_by_path.get(canonical_path_key(path))
        if resource_declaration is None:
            undeclared.append(path)
            unresolved_reasons.add("UNDECLARED_OVERLAP")
            outcome = "UNDECLARED_OVERLAP"
            intent = None
        else:
            outcome, reason, violation = _resource_outcome(
                resource_declaration, observation
            )
            intent = resource_declaration["intent"]
            if reason is not None:
                if reason in {
                    "DECLARED_RESOURCE_UNRESOLVED",
                    "PROTECTED_OUTCOME_UNRESOLVED",
                    "RESOURCE_OUTCOME_UNRESOLVED",
                }:
                    unresolved_reasons.add(reason)
                else:
                    failure_reasons.add(reason)
            if violation is not None:
                protected_violations.append(violation)
        resource_results.append(
            {
                **observation,
                "declared_intent": intent,
                "outcome": outcome,
            }
        )

    _, required_versions = _dependency_versions(
        declared["required_dependency_versions"]
    )
    dependency_violations: list[dict[str, str | None]] = []
    for project_id, required_version in sorted(required_versions.items()):
        actual = dependency_versions.get(project_id)
        if actual is not None and not isinstance(actual, str):
            raise TypeError("installed dependency versions must be strings")
        if actual != required_version:
            reason = (
                "DEPENDENCY_VERSION_MISSING"
                if actual is None
                else "DEPENDENCY_VERSION_MISMATCH"
            )
            failure_reasons.add(reason)
            dependency_violations.append(
                {
                    "project_id": project_id,
                    "required_version": required_version,
                    "installed_version": actual,
                }
            )

    runtime_violations: list[dict[str, str]] = []
    for assertion in declared["runtime_assertions"]:
        status = assertion_results.get(assertion, "not_observed")
        if not isinstance(status, str) or status not in RUNTIME_RESULTS:
            raise CompositeDeclarationError(
                f"runtime assertion {assertion!r} has unsupported status"
            )
        if status == "failed":
            failure_reasons.add("RUNTIME_ASSERTION_FAILED")
            runtime_violations.append({"assertion": assertion, "status": status})
        elif status == "not_observed":
            unresolved_reasons.add("RUNTIME_ASSERTION_UNRESOLVED")
            runtime_violations.append({"assertion": assertion, "status": status})

    reason_codes = sorted(failure_reasons | unresolved_reasons)
    result = "FAIL" if failure_reasons else "INCONCLUSIVE" if unresolved_reasons else "PASS"
    payload = {
        "schema_version": "kcd2.composite-lint-result.v1",
        "relationship_id": declared["relationship_id"],
        "result": result,
        "reason_codes": reason_codes,
        "resource_results": resource_results,
        "undeclared_overlaps": undeclared,
        "protected_resource_violations": protected_violations,
        "dependency_violations": dependency_violations,
        "runtime_assertion_violations": runtime_violations,
    }
    return CompositeLintResult(_freeze(payload))
