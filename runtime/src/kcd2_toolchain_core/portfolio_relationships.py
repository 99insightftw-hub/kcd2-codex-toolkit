"""Append-only project relationship registry and conservative legacy migration."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .portfolio_registry import (
    PortfolioRegistry,
    canonicalize_portfolio_registry,
    migrate_portfolio_registry_draft,
)


SCHEMA_VERSION = "kcd2.portfolio-relationship-registry.v1"
MAX_PROJECTS = 4096
MAX_RELATIONSHIPS = 50_000
MAX_CANONICAL_BYTES = 4 * 1024 * 1024

RELATIONSHIP_TYPES = frozenset(
    {
        "PARENT_OF",
        "DERIVED_FROM",
        "SUPERSEDES",
        "REPLACES",
        "COMPOSITE_WITH",
        "BUNDLES",
        "COMPATIBILITY_FOR",
        "OPTIONAL_FEATURE_OF",
        "VARIANT_OF",
        "LANGUAGE_VARIANT_OF",
        "MUTUALLY_EXCLUSIVE_WITH",
        "REQUIRES",
        "CONFLICTS_WITH",
        "MIRRORS",
        "UNKNOWN_REQUIRES_DECLARATION",
    }
)
UNKNOWN_RELATIONSHIP = "UNKNOWN_REQUIRES_DECLARATION"
_SYMMETRIC_TYPES = frozenset(
    {"COMPOSITE_WITH", "MUTUALLY_EXCLUSIVE_WITH", "CONFLICTS_WITH", "MIRRORS"}
)
_SOURCE_TO_TARGET_TYPES = frozenset({"PARENT_OF", "BUNDLES"})
_PROJECT_ID = re.compile(r"^project:sha256:[0-9a-f]{64}$")
_REGISTRY_ID = re.compile(r"^registry:sha256:[0-9a-f]{64}$")
_RELATIONSHIP_ID = re.compile(r"^relationship:sha256:[0-9a-f]{64}$")
_GRAPH_ID = re.compile(r"^relationship-registry:sha256:[0-9a-f]{64}$")
_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class PortfolioRelationshipError(ValueError):
    """A relationship registry violates its closed, bounded graph contract."""


class PortfolioRelationshipCycleError(PortfolioRelationshipError):
    """A directed relationship cycle makes the project DAG invalid."""


class PortfolioRelationshipIdentityMismatchError(PortfolioRelationshipError):
    """An asserted relationship or registry content ID is inconsistent."""


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
        raise PortfolioRelationshipError(
            f"{field} fields do not match contract; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _sequence(value: Any, field: str, maximum: int, *, minimum: int = 0) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if not minimum <= len(value) <= maximum:
        raise PortfolioRelationshipError(
            f"{field} must contain between {minimum} and {maximum} items"
        )
    return value


def _string(value: Any, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise PortfolioRelationshipError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _nullable_string(value: Any, field: str, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    return _string(value, field, maximum)


def _content_id(prefix: str, material: Mapping[str, Any], asserted: Any, field: str) -> str:
    computed = f"{prefix}:sha256:{sha256_json(material)}"
    expected = _RELATIONSHIP_ID if prefix == "relationship" else _GRAPH_ID
    if asserted is not None:
        if not isinstance(asserted, str) or expected.fullmatch(asserted) is None:
            raise PortfolioRelationshipIdentityMismatchError(
                f"{field} is not a content-addressed {prefix} ID"
            )
        if asserted != computed:
            raise PortfolioRelationshipIdentityMismatchError(
                f"{field} mismatch: asserted {asserted!r}, computed {computed!r}"
            )
    return computed


def _project_id(value: Any, field: str) -> str:
    result = _string(value, field, 96)
    if _PROJECT_ID.fullmatch(result) is None:
        raise PortfolioRelationshipError(f"{field} must be a content-addressed project ID")
    return result


def _strings(value: Any, field: str, maximum_items: int) -> list[str]:
    result = [
        _string(item, f"{field}[{index}]", 2048)
        for index, item in enumerate(_sequence(value, field, maximum_items, minimum=1))
    ]
    if len(result) != len(set(result)):
        raise PortfolioRelationshipError(f"{field} must be unique")
    return sorted(result)


def _normalize_relationship(raw: Any, index: int) -> dict[str, Any]:
    field = f"relationships[{index}]"
    item = _mapping(raw, field)
    _exact_fields(
        item,
        {
            "relationship_type",
            "source_project_id",
            "target_project_id",
            "evidence_refs",
            "unknown_reason",
            "legacy_reference",
        },
        {"relationship_id"},
        field,
    )
    relationship_type = _string(item["relationship_type"], f"{field}.relationship_type", 64)
    if relationship_type not in RELATIONSHIP_TYPES:
        raise PortfolioRelationshipError(f"{field}.relationship_type is not supported")
    source = _project_id(item["source_project_id"], f"{field}.source_project_id")
    target = item["target_project_id"]
    if target is not None:
        target = _project_id(target, f"{field}.target_project_id")
        if source == target:
            raise PortfolioRelationshipError(f"{field} cannot relate a project to itself")
    unknown_reason = _nullable_string(
        item["unknown_reason"], f"{field}.unknown_reason", 2048
    )
    if relationship_type == UNKNOWN_RELATIONSHIP:
        if unknown_reason is None:
            raise PortfolioRelationshipError(
                f"{field}.unknown_reason is required for an unknown relationship"
            )
    else:
        if target is None:
            raise PortfolioRelationshipError(
                f"{field}.target_project_id is required for {relationship_type}"
            )
        if unknown_reason is not None:
            raise PortfolioRelationshipError(
                f"{field}.unknown_reason must be null for a typed relationship"
            )
    material = {
        "relationship_type": relationship_type,
        "source_project_id": source,
        "target_project_id": target,
        "evidence_refs": _strings(item["evidence_refs"], f"{field}.evidence_refs", 256),
        "unknown_reason": unknown_reason,
        "legacy_reference": _nullable_string(
            item["legacy_reference"], f"{field}.legacy_reference", 2048
        ),
    }
    return {
        "relationship_id": _content_id(
            "relationship", material, item.get("relationship_id"), f"{field}.relationship_id"
        ),
        **material,
    }


def _validate_targets(
    project_ids: tuple[str, ...], relationships: list[dict[str, Any]]
) -> None:
    known = set(project_ids)
    for item in relationships:
        source = item["source_project_id"]
        target = item["target_project_id"]
        if source not in known:
            raise PortfolioRelationshipError(f"relationship has unknown source project {source}")
        if target is not None and target not in known:
            raise PortfolioRelationshipError(f"relationship has unknown target project {target}")


def _validate_acyclic(
    project_ids: tuple[str, ...], relationships: list[dict[str, Any]]
) -> None:
    outgoing: dict[str, set[str]] = {project_id: set() for project_id in project_ids}
    for item in relationships:
        kind = item["relationship_type"]
        target = item["target_project_id"]
        if kind in _SYMMETRIC_TYPES or kind == UNKNOWN_RELATIONSHIP or target is None:
            continue
        source = item["source_project_id"]
        if kind in _SOURCE_TO_TARGET_TYPES:
            outgoing[source].add(target)
        else:
            outgoing[target].add(source)

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(project_id: str) -> None:
        if project_id in visiting:
            raise PortfolioRelationshipCycleError(
                f"directed relationship cycle includes {project_id}"
            )
        if project_id in visited:
            return
        visiting.add(project_id)
        for target in sorted(outgoing[project_id]):
            visit(target)
        visiting.remove(project_id)
        visited.add(project_id)

    for project_id in project_ids:
        visit(project_id)


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        {
            "schema_version",
            "source_portfolio_registry_id",
            "observed_at",
            "project_ids",
            "relationships",
        },
        {"registry_id"},
        "portfolio relationship registry",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise PortfolioRelationshipError(f"schema_version must be {SCHEMA_VERSION}")
    source_registry_id = _string(
        value["source_portfolio_registry_id"], "source_portfolio_registry_id", 96
    )
    if _REGISTRY_ID.fullmatch(source_registry_id) is None:
        raise PortfolioRelationshipError(
            "source_portfolio_registry_id must be a content-addressed portfolio registry ID"
        )
    observed_at = _string(value["observed_at"], "observed_at", 64)
    if _DATE_TIME.fullmatch(observed_at) is None:
        raise PortfolioRelationshipError("observed_at must be an ISO date-time with an offset")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PortfolioRelationshipError("observed_at must be an ISO date-time") from exc
    project_ids = tuple(
        sorted(
            _project_id(item, f"project_ids[{index}]")
            for index, item in enumerate(
                _sequence(value["project_ids"], "project_ids", MAX_PROJECTS, minimum=1)
            )
        )
    )
    if len(project_ids) != len(set(project_ids)):
        raise PortfolioRelationshipError("project_ids must be unique")
    relationships = [
        _normalize_relationship(item, index)
        for index, item in enumerate(
            _sequence(value["relationships"], "relationships", MAX_RELATIONSHIPS)
        )
    ]
    relationship_ids = [item["relationship_id"] for item in relationships]
    if len(relationship_ids) != len(set(relationship_ids)):
        raise PortfolioRelationshipError("relationships contain duplicate content identities")
    relationships.sort(key=lambda item: item["relationship_id"])
    _validate_targets(project_ids, relationships)
    _validate_acyclic(project_ids, relationships)
    material = {
        "schema_version": SCHEMA_VERSION,
        "source_portfolio_registry_id": source_registry_id,
        "observed_at": observed_at,
        "project_ids": list(project_ids),
        "relationship_ids": [item["relationship_id"] for item in relationships],
    }
    result = {
        "schema_version": SCHEMA_VERSION,
        "registry_id": _content_id(
            "relationship-registry", material, value.get("registry_id"), "registry_id"
        ),
        "source_portfolio_registry_id": source_registry_id,
        "observed_at": observed_at,
        "project_ids": list(project_ids),
        "relationships": relationships,
    }
    if len(canonical_json_bytes(result)) > MAX_CANONICAL_BYTES:
        raise PortfolioRelationshipError(
            f"canonical registry exceeds the {MAX_CANONICAL_BYTES}-byte bound"
        )
    return result


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
    return value


@dataclass(frozen=True, slots=True)
class PortfolioRelationshipRegistry:
    """A deeply immutable, content-addressed snapshot of append-only relationships."""

    _value: Mapping[str, Any]

    @property
    def registry_id(self) -> str:
        return self._value["registry_id"]

    @property
    def project_ids(self) -> tuple[str, ...]:
        return self._value["project_ids"]

    @property
    def relationships(self) -> tuple[Mapping[str, Any], ...]:
        return self._value["relationships"]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def add_relationship(self, relationship: Mapping[str, Any]) -> PortfolioRelationshipRegistry:
        """Return a new registry without altering or dropping any existing record."""
        value = self.to_dict()
        value.pop("registry_id")
        candidate = _normalize_relationship(_mapping(relationship, "relationship"), 0)
        existing = {item["relationship_id"]: item for item in value["relationships"]}
        if existing.get(candidate["relationship_id"]) == candidate:
            return self
        value["relationships"].append(candidate)
        return canonicalize_portfolio_relationship_registry(value)


def canonicalize_portfolio_relationship_registry(
    value: Mapping[str, Any] | PortfolioRelationshipRegistry,
) -> PortfolioRelationshipRegistry:
    """Canonicalize a bounded graph or verify every transported content ID."""
    if isinstance(value, PortfolioRelationshipRegistry):
        return value
    normalized = _normalize(_mapping(value, "portfolio relationship registry"))
    return PortfolioRelationshipRegistry(_freeze(normalized))


def validate_portfolio_relationship_dag(
    value: Mapping[str, Any] | PortfolioRelationshipRegistry,
) -> PortfolioRelationshipRegistry:
    """Validate known endpoints and every directed relationship as one project DAG."""
    return canonicalize_portfolio_relationship_registry(value)


def migrate_legacy_portfolio_relationships(
    value: Mapping[str, Any] | PortfolioRegistry,
) -> PortfolioRelationshipRegistry:
    """Create explicit unknown edges from legacy strings without guessing semantics or targets."""
    if isinstance(value, PortfolioRegistry):
        portfolio = value
    else:
        source = _mapping(value, "legacy portfolio registry")
        if "portfolio_id" in source:
            portfolio = migrate_portfolio_registry_draft(source)
        else:
            portfolio = canonicalize_portfolio_registry(source)
    document = portfolio.to_dict()
    relationships = []
    for project in document["projects"]:
        for legacy_reference in project["relationships"]:
            relationships.append(
                {
                    "relationship_type": UNKNOWN_RELATIONSHIP,
                    "source_project_id": project["project_id"],
                    "target_project_id": None,
                    "evidence_refs": [document["registry_id"]],
                    "unknown_reason": (
                        "legacy relationship lacks a typed target and reviewed semantics"
                    ),
                    "legacy_reference": legacy_reference,
                }
            )
    return canonicalize_portfolio_relationship_registry(
        {
            "schema_version": SCHEMA_VERSION,
            "source_portfolio_registry_id": document["registry_id"],
            "observed_at": document["observed_at"],
            "project_ids": [project["project_id"] for project in document["projects"]],
            "relationships": relationships,
        }
    )
