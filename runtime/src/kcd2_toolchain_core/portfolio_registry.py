"""Content-addressed portfolio registry identities and draft migration."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.portfolio-registry.v1"
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_KIND = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_ID = re.compile(r"^(?P<prefix>[a-z][a-z-]*):sha256:(?P<digest>[0-9a-f]{64})$")
_DATE_TIME = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


class PortfolioIdentityMismatchError(ValueError):
    """An asserted content ID or canonical collection is inconsistent."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field} must be a mapping with string keys")
    return value


def _exact_fields(
    value: Mapping[str, Any], required: set[str], optional: set[str], field: str
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required - optional
    if missing or unknown:
        raise ValueError(
            f"{field} fields do not match contract; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _sequence(value: Any, field: str, maximum: int, *, minimum: int = 0) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if not minimum <= len(value) <= maximum:
        raise ValueError(f"{field} must contain between {minimum} and {maximum} items")
    return value


def _string(value: Any, field: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{field} must be a non-empty string of at most {maximum} characters")
    return value


def _nullable_string(value: Any, field: str, maximum: int = 2048) -> str | None:
    if value is None:
        return None
    return _string(value, field, maximum)


def _digest(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise ValueError(f"{field} must be a SHA-256 hex digest{suffix}")
    return value.lower()


def _kind(value: Any, field: str) -> str:
    result = _string(value, field, 64)
    if _KIND.fullmatch(result) is None:
        raise ValueError(f"{field} must be a lowercase machine kind")
    return result


def _aliases(value: Any, field: str) -> list[str]:
    result = [
        _string(item, f"{field}[{index}]", 256)
        for index, item in enumerate(_sequence(value, field, 64))
    ]
    keys = [item.casefold() for item in result]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{field} must be case-insensitively unique")
    return sorted(result, key=lambda item: (item.casefold(), item))


def _strings(
    value: Any, field: str, maximum_items: int, maximum_length: int = 256
) -> list[str]:
    result = [
        _string(item, f"{field}[{index}]", maximum_length)
        for index, item in enumerate(_sequence(value, field, maximum_items))
    ]
    if len(result) != len(set(result)):
        raise ValueError(f"{field} must be unique")
    return sorted(result)


def _paths(value: Any, field: str, maximum_items: int) -> list[str]:
    result = [
        canonical_relative_path(item)
        for item in _sequence(value, field, maximum_items)
    ]
    keys = [canonical_path_key(item) for item in result]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{field} contains duplicate canonical paths")
    return sorted(result, key=canonical_path_key)


def _content_id(prefix: str, material: Mapping[str, Any], asserted: Any, field: str) -> str:
    computed = f"{prefix}:sha256:{sha256_json(material)}"
    if asserted is not None:
        if not isinstance(asserted, str) or _ID.fullmatch(asserted) is None:
            raise PortfolioIdentityMismatchError(f"{field} is not a content-addressed ID")
        if asserted != computed:
            raise PortfolioIdentityMismatchError(
                f"{field} mismatch: asserted {asserted!r}, computed {computed!r}"
            )
    return computed


def _unique_ids(items: list[dict[str, Any]], id_field: str, field: str) -> None:
    identifiers = [item[id_field] for item in items]
    if len(identifiers) != len(set(identifiers)):
        raise PortfolioIdentityMismatchError(f"{field} contains duplicate content identities")


def _normalize_coverage(value: Any) -> dict[str, Any]:
    item = _mapping(value, "coverage")
    _exact_fields(
        item,
        {"state", "source", "absence_claim_valid"},
        {"notes"},
        "coverage",
    )
    state = item["state"]
    if state not in {"COMPLETE", "PARTIAL_LIMIT_REACHED", "PARTIAL_STALE", "UNKNOWN"}:
        raise ValueError("coverage.state is not supported")
    if not isinstance(item["absence_claim_valid"], bool):
        raise TypeError("coverage.absence_claim_valid must be a boolean")
    return {
        "state": state,
        "source": _string(item["source"], "coverage.source", 2048),
        "absence_claim_valid": item["absence_claim_valid"],
        "notes": _strings(item.get("notes", []), "coverage.notes", 64, 2048),
    }


def _normalize_domain(raw: Any, index: int) -> dict[str, Any]:
    field = f"domains[{index}]"
    item = _mapping(raw, field)
    _exact_fields(item, {"kind"}, {"domain_id", "aliases"}, field)
    kind = _kind(item["kind"], f"{field}.kind")
    material = {"kind": kind}
    return {
        "domain_id": _content_id("domain", material, item.get("domain_id"), f"{field}.domain_id"),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_provider(raw: Any, index: int) -> dict[str, Any]:
    field = f"providers[{index}]"
    item = _mapping(raw, field)
    _exact_fields(
        item,
        {"kind", "locator", "state", "sha256"},
        {"provider_id", "aliases"},
        field,
    )
    kind = item["kind"]
    if kind not in {"LOCAL", "WORKSHOP", "SOURCE_PROJECT", "REFERENCE", "EXTERNAL_COMPONENT"}:
        raise ValueError(f"{field}.kind is not supported")
    locator = _string(item["locator"], f"{field}.locator").replace("\\", "/")
    material = {
        "kind": kind,
        "locator": locator,
        "state": _string(item["state"], f"{field}.state", 128),
        "sha256": _digest(item["sha256"], f"{field}.sha256", nullable=True),
    }
    return {
        "provider_id": _content_id(
            "provider", material, item.get("provider_id"), f"{field}.provider_id"
        ),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_artifact(raw: Any, index: int) -> dict[str, Any]:
    field = f"artifacts[{index}]"
    item = _mapping(raw, field)
    _exact_fields(item, {"path", "sha256", "role"}, {"artifact_id", "aliases"}, field)
    material = {
        "path": canonical_relative_path(item["path"]),
        "sha256": _digest(item["sha256"], f"{field}.sha256"),
        "role": _string(item["role"], f"{field}.role", 64),
    }
    return {
        "artifact_id": _content_id(
            "artifact", material, item.get("artifact_id"), f"{field}.artifact_id"
        ),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_component(raw: Any, index: int) -> dict[str, Any]:
    field = f"expected_components[{index}]"
    item = _mapping(raw, field)
    _exact_fields(
        item,
        {"kind", "required", "paths"},
        {"component_id", "aliases"},
        field,
    )
    if not isinstance(item["required"], bool):
        raise TypeError(f"{field}.required must be a boolean")
    material = {
        "kind": _kind(item["kind"], f"{field}.kind"),
        "required": item["required"],
        "paths": _paths(item["paths"], f"{field}.paths", 256),
    }
    return {
        "component_id": _content_id(
            "component", material, item.get("component_id"), f"{field}.component_id"
        ),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_path(raw: Any, index: int) -> dict[str, Any]:
    field = f"paths[{index}]"
    item = _mapping(raw, field)
    _exact_fields(item, {"path", "role"}, {"path_id"}, field)
    material = {
        "path": canonical_relative_path(item["path"]),
        "role": _string(item["role"], f"{field}.role", 64),
    }
    return {
        "path_id": _content_id("path", material, item.get("path_id"), f"{field}.path_id"),
        **material,
    }


def _normalize_table_key(raw: Any, index: int) -> dict[str, Any]:
    field = f"table_keys[{index}]"
    item = _mapping(raw, field)
    _exact_fields(item, {"table_path", "key_fields"}, {"table_key_id"}, field)
    key_fields = [
        _string(value, f"{field}.key_fields[{position}]", 256)
        for position, value in enumerate(
            _sequence(item["key_fields"], f"{field}.key_fields", 16, minimum=1)
        )
    ]
    if len(key_fields) != len(set(key_fields)):
        raise ValueError(f"{field}.key_fields must be unique")
    material = {
        "table_path": canonical_relative_path(item["table_path"]),
        "key_fields": key_fields,
    }
    return {
        "table_key_id": _content_id(
            "table-key", material, item.get("table_key_id"), f"{field}.table_key_id"
        ),
        **material,
    }


def _normalize_test(raw: Any, index: int) -> dict[str, Any]:
    field = f"tests[{index}]"
    item = _mapping(raw, field)
    _exact_fields(
        item,
        {"kind", "requirement", "target_paths"},
        {"test_id", "aliases"},
        field,
    )
    material = {
        "kind": _kind(item["kind"], f"{field}.kind"),
        "requirement": _string(item["requirement"], f"{field}.requirement", 2048),
        "target_paths": _paths(item["target_paths"], f"{field}.target_paths", 256),
    }
    return {
        "test_id": _content_id("test", material, item.get("test_id"), f"{field}.test_id"),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_conflict(raw: Any, index: int) -> dict[str, Any]:
    field = f"conflict_intent[{index}]"
    item = _mapping(raw, field)
    _exact_fields(
        item,
        {"intent"},
        {"conflict_intent_id", "aliases", "scope", "path", "statement"},
        field,
    )
    scope = item.get("scope", "PATH" if item.get("path") is not None else "PROJECT")
    if scope not in {"PROJECT", "PATH"}:
        raise ValueError(f"{field}.scope is not supported")
    path = item.get("path")
    if scope == "PATH":
        path = canonical_relative_path(path)
    elif path is not None:
        raise ValueError(f"{field}.path must be null for PROJECT scope")
    intent = item["intent"]
    if intent not in {
        "INTENDED_WINNER",
        "INTENDED_MERGE",
        "PROTECTED_UPSTREAM",
        "IDENTICAL_MIRROR",
        "UNRESOLVED",
    }:
        raise ValueError(f"{field}.intent is not supported")
    material = {
        "scope": scope,
        "path": path,
        "intent": intent,
        "statement": _nullable_string(item.get("statement"), f"{field}.statement", 2048),
    }
    return {
        "conflict_intent_id": _content_id(
            "conflict-intent",
            material,
            item.get("conflict_intent_id"),
            f"{field}.conflict_intent_id",
        ),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **material,
    }


def _normalize_project(raw: Any, index: int) -> dict[str, Any]:
    field = f"projects[{index}]"
    item = _mapping(raw, field)
    required = {
        "domains",
        "providers",
        "artifacts",
        "expected_components",
        "paths",
        "table_keys",
        "tests",
        "conflict_intent",
        "relationships",
        "variants",
        "supported_game_builds",
    }
    _exact_fields(item, required, {"project_id", "aliases"}, field)
    collection_specs = (
        ("domains", _normalize_domain, "domain_id", 64, 1),
        ("providers", _normalize_provider, "provider_id", 256, 0),
        ("artifacts", _normalize_artifact, "artifact_id", 8192, 0),
        ("expected_components", _normalize_component, "component_id", 2048, 0),
        ("paths", _normalize_path, "path_id", 8192, 0),
        ("table_keys", _normalize_table_key, "table_key_id", 2048, 0),
        ("tests", _normalize_test, "test_id", 2048, 0),
        ("conflict_intent", _normalize_conflict, "conflict_intent_id", 2048, 0),
    )
    collections: dict[str, list[dict[str, Any]]] = {}
    for name, normalizer, id_field, maximum, minimum in collection_specs:
        values = [
            normalizer(value, position)
            for position, value in enumerate(
                _sequence(item[name], f"{field}.{name}", maximum, minimum=minimum)
            )
        ]
        _unique_ids(values, id_field, f"{field}.{name}")
        collections[name] = sorted(values, key=lambda value: value[id_field])

    relationships = _strings(item["relationships"], f"{field}.relationships", 256)
    variants = _strings(item["variants"], f"{field}.variants", 256)
    builds = _strings(item["supported_game_builds"], f"{field}.supported_game_builds", 256)
    material = {
        name: [value[id_field] for value in collections[name]]
        for name, _, id_field, _, _ in collection_specs
    }
    material.update(
        {
            "relationships": relationships,
            "variants": variants,
            "supported_game_builds": builds,
        }
    )
    return {
        "project_id": _content_id(
            "project", material, item.get("project_id"), f"{field}.project_id"
        ),
        "aliases": _aliases(item.get("aliases", []), f"{field}.aliases"),
        **collections,
        "relationships": relationships,
        "variants": variants,
        "supported_game_builds": builds,
    }


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        {"schema_version", "observed_at", "coverage", "projects"},
        {"registry_id", "aliases"},
        "portfolio registry",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    observed_at = _string(value["observed_at"], "observed_at", 64)
    if _DATE_TIME.fullmatch(observed_at) is None:
        raise ValueError("observed_at must be an ISO date-time with an offset")
    try:
        datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("observed_at must be an ISO date-time") from exc
    coverage = _normalize_coverage(value["coverage"])
    projects = [
        _normalize_project(item, index)
        for index, item in enumerate(_sequence(value["projects"], "projects", 4096, minimum=1))
    ]
    _unique_ids(projects, "project_id", "projects")
    projects.sort(key=lambda item: item["project_id"])
    material = {
        "schema_version": SCHEMA_VERSION,
        "observed_at": observed_at,
        "coverage": coverage,
        "project_ids": [item["project_id"] for item in projects],
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "registry_id": _content_id(
            "registry", material, value.get("registry_id"), "registry_id"
        ),
        "aliases": _aliases(value.get("aliases", []), "aliases"),
        "observed_at": observed_at,
        "coverage": coverage,
        "projects": projects,
    }


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
class PortfolioRegistry:
    """A deeply immutable canonical portfolio registry."""

    _value: Mapping[str, Any]

    @property
    def registry_id(self) -> str:
        return self._value["registry_id"]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def canonicalize_portfolio_registry(
    value: Mapping[str, Any] | PortfolioRegistry,
) -> PortfolioRegistry:
    """Canonicalize registry content or verify every transported content ID."""
    if isinstance(value, PortfolioRegistry):
        return value
    return PortfolioRegistry(_freeze(_normalize(_mapping(value, "portfolio registry"))))


def _legacy_kind(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_.-]+", "-", value.casefold()).strip("-.")
    if not slug or not slug[0].isalpha():
        slug = f"legacy-{slug}" if slug else "legacy-unknown"
    return slug[:64]


def migrate_portfolio_registry_draft(value: Mapping[str, Any]) -> PortfolioRegistry:
    """Migrate the reviewed pre-PORT-001 draft without inventing absent evidence."""
    draft = _mapping(value, "portfolio registry draft")
    _exact_fields(
        draft,
        {"schema_version", "portfolio_id", "observed_at", "coverage", "projects"},
        set(),
        "portfolio registry draft",
    )
    projects: list[dict[str, Any]] = []
    for index, raw in enumerate(_sequence(draft["projects"], "draft.projects", 4096, minimum=1)):
        project = _mapping(raw, f"draft.projects[{index}]")
        _exact_fields(
            project,
            {"project_id", "mod_id", "domains", "providers", "relationships", "variants"},
            {
                "supported_game_builds",
                "internal_paths",
                "runtime_test_requirements",
                "conflict_intent",
            },
            f"draft.projects[{index}]",
        )
        providers = []
        for position, raw_provider in enumerate(
            _sequence(project["providers"], f"draft.projects[{index}].providers", 256)
        ):
            provider = _mapping(raw_provider, f"draft provider {position}")
            _exact_fields(provider, {"kind", "path", "state"}, {"sha256"}, "draft provider")
            providers.append(
                {
                    "kind": provider["kind"],
                    "locator": provider["path"],
                    "state": provider["state"],
                    "sha256": provider.get("sha256"),
                    "aliases": [],
                }
            )
        internal_paths = _paths(
            project.get("internal_paths", []),
            f"draft.projects[{index}].internal_paths",
            8192,
        )
        projects.append(
            {
                "aliases": _aliases(
                    [project["project_id"], project["mod_id"]],
                    f"draft.projects[{index}].aliases",
                ),
                "domains": [
                    {"kind": _legacy_kind(domain), "aliases": [domain]}
                    for domain in _strings(
                        project["domains"], f"draft.projects[{index}].domains", 64
                    )
                ],
                "providers": providers,
                "artifacts": [],
                "expected_components": [],
                "paths": [{"path": path, "role": "UNCLASSIFIED"} for path in internal_paths],
                "table_keys": [],
                "tests": [
                    {
                        "kind": "runtime_requirement",
                        "requirement": requirement,
                        "target_paths": [],
                        "aliases": [],
                    }
                    for requirement in _strings(
                        project.get("runtime_test_requirements", []),
                        f"draft.projects[{index}].runtime_test_requirements",
                        2048,
                        2048,
                    )
                ],
                "conflict_intent": [
                    {
                        "scope": "PROJECT",
                        "path": None,
                        "intent": "UNRESOLVED",
                        "statement": statement,
                        "aliases": [],
                    }
                    for statement in _strings(
                        project.get("conflict_intent", []),
                        f"draft.projects[{index}].conflict_intent",
                        2048,
                        2048,
                    )
                ],
                "relationships": project["relationships"],
                "variants": project["variants"],
                "supported_game_builds": project.get("supported_game_builds", []),
            }
        )
    return canonicalize_portfolio_registry(
        {
            "schema_version": SCHEMA_VERSION,
            "aliases": [draft["portfolio_id"]],
            "observed_at": draft["observed_at"],
            "coverage": draft["coverage"],
            "projects": projects,
        }
    )
