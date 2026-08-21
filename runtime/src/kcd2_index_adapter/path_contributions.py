"""Bounded automatic extraction of typed KCD2 path contributions."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal

from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path


ProviderKind = Literal["vanilla", "local", "workshop", "explicit", "generated", "unknown"]
SourceKind = Literal["pak_member", "loose_file"]

_PROVIDER_KINDS = frozenset(
    {"vanilla", "local", "workshop", "explicit", "generated", "unknown"}
)
_SOURCE_KINDS = frozenset({"pak_member", "loose_file"})
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TEXT = 1024
_MAX_PATHS = 256
_MAX_PROVIDERS = 1024
_MAX_DISCOVERED_PATHS = 8192
_MAX_MANUAL_CONTRIBUTIONS = 4096


class PathContributionError(ValueError):
    """Contribution inputs cannot support a bounded deterministic result."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise PathContributionError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _canonical_path(value: object, name: str) -> str:
    checked = _text(value, name)
    try:
        return canonical_relative_path(checked)
    except (TypeError, ValueError) as exc:
        raise PathContributionError(f"{name} must be a canonical relative path") from exc


def _optional_sha256(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise PathContributionError(f"{name} must be null or a SHA-256 digest")
    return value.lower()


def _sha256(value: object, name: str) -> str:
    checked = _optional_sha256(value, name)
    if checked is None:
        raise PathContributionError(f"{name} must be a SHA-256 digest")
    return checked


def _plain_index(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise PathContributionError(f"{name} must be null or an integer from 0 through 2^31-1")
    return value


def _bounded_sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise PathContributionError(f"{name} must be an array")
    if len(value) > maximum:
        raise PathContributionError(f"{name} exceeds the {maximum}-item hard bound")
    return value


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise PathContributionError("contribution content must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class ResolutionRule:
    """One stable registry result for a supported canonical path family."""

    family: str
    contribution_kind: str
    resolution_semantics: str


RESOLUTION_SEMANTICS_REGISTRY: Mapping[str, ResolutionRule] = MappingProxyType(
    {
        "provider_metadata": ResolutionRule(
            "provider_metadata", "provider_metadata", "no_runtime_override"
        ),
        "lua": ResolutionRule("lua", "lua_mod_init", "parallel_load"),
        "ui": ResolutionRule("ui", "ui_asset_override", "override_last_wins"),
        "config": ResolutionRule("config", "config_override", "override_last_wins"),
        "table": ResolutionRule("table", "table_patch", "ordered_merge"),
        "quest": ResolutionRule("quest", "quest_graph", "component_specific"),
        "storm": ResolutionRule("storm", "storm_merge", "ordered_merge"),
        "localization": ResolutionRule(
            "localization", "localization", "separate_namespace"
        ),
        "asset": ResolutionRule("asset", "exact_override", "override_last_wins"),
        "native": ResolutionRule(
            "native", "native_component", "component_specific"
        ),
        "unknown": ResolutionRule("unknown", "unknown", "unknown"),
    }
)

_ASSET_PREFIXES = (
    "animations/",
    "libs/materials/",
    "materials/",
    "objects/",
    "sounds/",
    "textures/",
)
_ASSET_SUFFIXES = (
    ".anm",
    ".caf",
    ".cdf",
    ".cgf",
    ".chr",
    ".dds",
    ".mtl",
    ".skin",
    ".swf",
)
_NATIVE_SUFFIXES = (".dll", ".exe")


def classify_path_semantics(canonical_path: str) -> ResolutionRule:
    """Classify one path without consulting incident- or mod-specific values."""

    path = _canonical_path(canonical_path, "canonical_path")
    key = path.casefold()
    name = key.rsplit("/", 1)[-1]
    if (
        key == "mod.manifest"
        or ("/" not in key and name.startswith("readme"))
        or ("/" not in key and name.startswith("install-note"))
        or key.startswith(".receipts/")
    ):
        return RESOLUTION_SEMANTICS_REGISTRY["provider_metadata"]
    if re.fullmatch(r"scripts/mods/[^/]+\.lua", key):
        return RESOLUTION_SEMANTICS_REGISTRY["lua"]
    if key.startswith(("libs/ui/", "ui/")) or key.endswith((".gfx", ".swf")):
        return RESOLUTION_SEMANTICS_REGISTRY["ui"]
    if key == "mod.cfg" or key.startswith(("libs/config/", "config/")):
        return RESOLUTION_SEMANTICS_REGISTRY["config"]
    if key.startswith("libs/storm/"):
        return RESOLUTION_SEMANTICS_REGISTRY["storm"]
    if key.startswith("libs/tables/"):
        return RESOLUTION_SEMANTICS_REGISTRY["table"]
    if key.startswith(("quests/", "libs/quests/", "libs/skald/")):
        return RESOLUTION_SEMANTICS_REGISTRY["quest"]
    if key.startswith("localization/"):
        return RESOLUTION_SEMANTICS_REGISTRY["localization"]
    if key.endswith(_NATIVE_SUFFIXES) or key.startswith(("bin/", "plugins/")):
        return RESOLUTION_SEMANTICS_REGISTRY["native"]
    if key.startswith(_ASSET_PREFIXES) or key.endswith(_ASSET_SUFFIXES):
        return RESOLUTION_SEMANTICS_REGISTRY["asset"]
    return RESOLUTION_SEMANTICS_REGISTRY["unknown"]


@dataclass(frozen=True, slots=True)
class ExactProvider:
    """One exact provider eligible for the requested path scope."""

    provider_id: str
    provider_kind: ProviderKind
    mod_id: str | None
    provider_root: str
    load_order_index: int | None

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id")
        if self.provider_kind not in _PROVIDER_KINDS:
            raise PathContributionError("provider_kind is not supported")
        if self.mod_id is not None:
            _text(self.mod_id, "mod_id")
        _text(self.provider_root, "provider_root")
        _plain_index(self.load_order_index, "load_order_index")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ExactProvider":
        expected = {
            "provider_id",
            "provider_kind",
            "mod_id",
            "provider_root",
            "load_order_index",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise PathContributionError("provider fields do not match the exact-provider input")
        provider_kind = value["provider_kind"]
        if provider_kind == "explicit_path":
            provider_kind = "explicit"
        return cls(
            provider_id=value["provider_id"],  # type: ignore[arg-type]
            provider_kind=provider_kind,  # type: ignore[arg-type]
            mod_id=value["mod_id"],  # type: ignore[arg-type]
            provider_root=value["provider_root"],  # type: ignore[arg-type]
            load_order_index=value["load_order_index"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class DiscoveredPath:
    """One automatically enumerated PAK member or exact loose file."""

    provider_id: str
    source_kind: SourceKind
    source_path: str
    member_or_loose_path: str
    content_sha256: str | None

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id")
        if self.source_kind not in _SOURCE_KINDS:
            raise PathContributionError("source_kind must be pak_member or loose_file")
        _text(self.source_path, "source_path")
        _canonical_path(self.member_or_loose_path, "member_or_loose_path")
        _optional_sha256(self.content_sha256, "content_sha256")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "DiscoveredPath":
        expected = {
            "provider_id",
            "source_kind",
            "source_path",
            "member_or_loose_path",
            "content_sha256",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise PathContributionError("discovered-path fields do not match the input contract")
        return cls(
            provider_id=value["provider_id"],  # type: ignore[arg-type]
            source_kind=value["source_kind"],  # type: ignore[arg-type]
            source_path=value["source_path"],  # type: ignore[arg-type]
            member_or_loose_path=value["member_or_loose_path"],  # type: ignore[arg-type]
            content_sha256=value["content_sha256"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ManualContribution:
    """Compatibility-only untyped contribution supplied by a caller."""

    provider_id: str
    provider_kind: ProviderKind
    mod_id: str | None
    source_path: str
    member_or_loose_path: str
    content_sha256: str | None
    load_order_index: int | None = None

    def __post_init__(self) -> None:
        _text(self.provider_id, "manual.provider_id")
        if self.provider_kind not in _PROVIDER_KINDS:
            raise PathContributionError("manual.provider_kind is not supported")
        if self.mod_id is not None:
            _text(self.mod_id, "manual.mod_id")
        _text(self.source_path, "manual.source_path")
        _canonical_path(self.member_or_loose_path, "manual.member_or_loose_path")
        _optional_sha256(self.content_sha256, "manual.content_sha256")
        _plain_index(self.load_order_index, "manual.load_order_index")


@dataclass(frozen=True, slots=True)
class LoadOrderEvidence:
    """Freshness/completeness assertion for the supplied provider indices."""

    complete: bool
    source: str
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.complete, bool):
            raise PathContributionError("load_order.complete must be a boolean")
        _text(self.source, "load_order.source")
        _sha256(self.sha256, "load_order.sha256")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "LoadOrderEvidence":
        expected = {"complete", "source", "sha256"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise PathContributionError("load-order fields do not match the input contract")
        return cls(
            complete=value["complete"],  # type: ignore[arg-type]
            source=value["source"],  # type: ignore[arg-type]
            sha256=value["sha256"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class PathContributionSet:
    """Immutable schema-ready result for one canonical path."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _coverage_payload(value: object) -> Mapping[str, object]:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise PathContributionError("coverage must be a coverage-validity mapping")
    coverage_id = value.get("coverage_id")
    permissions = value.get("claim_permissions")
    _text(coverage_id, "coverage.coverage_id")
    if not isinstance(permissions, Mapping):
        raise PathContributionError("coverage.claim_permissions must be an object")
    for name in ("winner_claim_allowed",):
        if not isinstance(permissions.get(name), bool):
            raise PathContributionError(f"coverage.claim_permissions.{name} must be a boolean")
    return value


def _claim_allowed(coverage: Mapping[str, object], name: str) -> bool:
    permissions = coverage["claim_permissions"]
    assert isinstance(permissions, Mapping)
    return permissions.get(name) is True


def _automatic_contribution(
    provider: ExactProvider,
    source: DiscoveredPath,
    rule: ResolutionRule,
) -> dict[str, object]:
    return {
        "provider_id": provider.provider_id,
        "provider_kind": provider.provider_kind,
        "mod_id": provider.mod_id,
        "source_path": source.source_path,
        "member_or_loose_path": canonical_relative_path(source.member_or_loose_path),
        "content_sha256": _optional_sha256(source.content_sha256, "content_sha256"),
        "contribution_kind": rule.contribution_kind,
        "resolution_semantics": rule.resolution_semantics,
        "load_order_index": provider.load_order_index,
        "selection_state": "unresolved",
    }


def _manual_contribution(
    contribution: ManualContribution,
    rule: ResolutionRule,
) -> dict[str, object]:
    return {
        "provider_id": contribution.provider_id,
        "provider_kind": contribution.provider_kind,
        "mod_id": contribution.mod_id,
        "source_path": contribution.source_path,
        "member_or_loose_path": canonical_relative_path(
            contribution.member_or_loose_path
        ),
        "content_sha256": _optional_sha256(
            contribution.content_sha256, "manual.content_sha256"
        ),
        "contribution_kind": rule.contribution_kind,
        "resolution_semantics": rule.resolution_semantics,
        "load_order_index": contribution.load_order_index,
        "selection_state": "unresolved",
    }


def _sort_key(contribution: Mapping[str, object]) -> tuple[object, ...]:
    index = contribution["load_order_index"]
    return (
        index is None,
        index if index is not None else 2**31,
        str(contribution["provider_id"]).casefold(),
        str(contribution["provider_id"]),
        str(contribution["source_path"]).casefold(),
        str(contribution["source_path"]),
    )


def _order_is_complete(
    contributions: Sequence[Mapping[str, object]],
    load_order: LoadOrderEvidence,
) -> bool:
    indices = [item["load_order_index"] for item in contributions]
    return (
        load_order.complete
        and all(index is not None for index in indices)
        and len(indices) == len(set(indices))
    )


def _resolve_selection(
    contributions: list[dict[str, object]],
    *,
    rule: ResolutionRule,
    discovery_mode: str,
    coverage: Mapping[str, object],
    load_order: LoadOrderEvidence,
) -> dict[str, object]:
    reasons = {f"SEMANTICS_{rule.resolution_semantics.upper()}"}
    if discovery_mode != "automatic":
        reasons.add("MANUAL_FALLBACK" if discovery_mode == "manual" else "HYBRID_MANUAL_FALLBACK")
        return {
            "conclusion": "inconclusive",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons),
        }
    reasons.add("AUTOMATIC_DISCOVERY")
    if not contributions:
        if _claim_allowed(coverage, "absence_claim_allowed"):
            return {
                "conclusion": "no_provider_observed",
                "winner_provider_id": None,
                "reason_codes": sorted(reasons | {"COMPLETE_COVERAGE_NO_PROVIDER"}),
            }
        return {
            "conclusion": "inconclusive",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons | {"ABSENCE_BLOCKED_BY_COVERAGE"}),
        }
    if rule.resolution_semantics == "no_runtime_override":
        for item in contributions:
            item["selection_state"] = "metadata_only"
        return {
            "conclusion": "multiple_contributors",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons | {"PROVIDER_METADATA_EXCLUDED"}),
        }
    if rule.resolution_semantics == "parallel_load":
        for item in contributions:
            item["selection_state"] = "parallel"
        return {
            "conclusion": "parallel_contributors",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons),
        }
    if rule.resolution_semantics == "ordered_merge":
        if not _order_is_complete(contributions, load_order):
            return {
                "conclusion": "inconclusive",
                "winner_provider_id": None,
                "reason_codes": sorted(reasons | {"ORDER_EVIDENCE_INCOMPLETE"}),
            }
        for item in contributions:
            item["selection_state"] = "contributes"
        return {
            "conclusion": "multiple_contributors",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons | {"ORDER_EVIDENCE_COMPLETE"}),
        }
    if rule.resolution_semantics == "override_last_wins":
        if not _claim_allowed(coverage, "winner_claim_allowed"):
            reasons.add("WINNER_BLOCKED_BY_COVERAGE")
        if not _order_is_complete(contributions, load_order):
            reasons.add("WINNER_BLOCKED_BY_ORDER_EVIDENCE")
        if len(reasons & {"WINNER_BLOCKED_BY_COVERAGE", "WINNER_BLOCKED_BY_ORDER_EVIDENCE"}):
            return {
                "conclusion": "inconclusive",
                "winner_provider_id": None,
                "reason_codes": sorted(reasons),
            }
        winner = contributions[-1]
        for item in contributions:
            item["selection_state"] = "winner" if item is winner else "shadowed"
        return {
            "conclusion": "winner",
            "winner_provider_id": winner["provider_id"],
            "reason_codes": sorted(reasons | {"COVERAGE_AND_ORDER_COMPLETE"}),
        }
    if rule.resolution_semantics in {"separate_namespace", "component_specific"}:
        for item in contributions:
            item["selection_state"] = "contributes"
        return {
            "conclusion": "multiple_contributors",
            "winner_provider_id": None,
            "reason_codes": sorted(reasons | {"NO_SINGULAR_WINNER"}),
        }
    return {
        "conclusion": "inconclusive",
        "winner_provider_id": None,
        "reason_codes": sorted(reasons | {"UNSUPPORTED_PATH_SEMANTICS"}),
    }


def resolve_internal_path_contributions(
    *,
    query_id: str,
    canonical_paths: Sequence[str],
    providers: Sequence[ExactProvider],
    discovered_paths: Sequence[DiscoveredPath],
    coverage: object,
    load_order: LoadOrderEvidence,
    manual_contributions: Sequence[ManualContribution] = (),
) -> tuple[PathContributionSet, ...]:
    """Return one typed contribution set per path from machine-discovered inputs."""

    checked_query_id = _text(query_id, "query_id")
    path_values = _bounded_sequence(canonical_paths, "canonical_paths", _MAX_PATHS)
    if not path_values:
        raise PathContributionError("canonical_paths must contain at least one path")
    paths = tuple(
        _canonical_path(path, f"canonical_paths[{index}]")
        for index, path in enumerate(path_values)
    )
    path_keys = [canonical_path_key(path) for path in paths]
    if len(path_keys) != len(set(path_keys)):
        raise PathContributionError("canonical_paths must not contain case-insensitive duplicates")

    provider_values = _bounded_sequence(providers, "providers", _MAX_PROVIDERS)
    if any(not isinstance(item, ExactProvider) for item in provider_values):
        raise PathContributionError("providers must contain ExactProvider values")
    provider_by_id: dict[str, ExactProvider] = {}
    for provider in provider_values:
        assert isinstance(provider, ExactProvider)
        key = provider.provider_id.casefold()
        if key in provider_by_id:
            raise PathContributionError("provider_id values must be case-insensitively unique")
        provider_by_id[key] = provider

    source_values = _bounded_sequence(
        discovered_paths, "discovered_paths", _MAX_DISCOVERED_PATHS
    )
    if any(not isinstance(item, DiscoveredPath) for item in source_values):
        raise PathContributionError("discovered_paths must contain DiscoveredPath values")
    source_keys: set[tuple[str, str, str]] = set()
    for source in source_values:
        assert isinstance(source, DiscoveredPath)
        if source.provider_id.casefold() not in provider_by_id:
            raise PathContributionError(
                f"discovered path names unknown exact provider {source.provider_id!r}"
            )
        key = (
            source.provider_id.casefold(),
            source.source_path.casefold(),
            canonical_path_key(source.member_or_loose_path),
        )
        if key in source_keys:
            raise PathContributionError("discovered_paths contains a duplicate provider source")
        source_keys.add(key)

    manual_values = _bounded_sequence(
        manual_contributions,
        "manual_contributions",
        _MAX_MANUAL_CONTRIBUTIONS,
    )
    if any(not isinstance(item, ManualContribution) for item in manual_values):
        raise PathContributionError(
            "manual_contributions must contain ManualContribution values"
        )
    if not isinstance(load_order, LoadOrderEvidence):
        raise PathContributionError("load_order must be LoadOrderEvidence")
    coverage_payload = _coverage_payload(coverage)

    results: list[PathContributionSet] = []
    for path, path_key in zip(paths, path_keys, strict=True):
        rule = classify_path_semantics(path)
        automatic = [
            _automatic_contribution(
                provider_by_id[source.provider_id.casefold()], source, rule
            )
            for source in source_values
            if canonical_path_key(source.member_or_loose_path) == path_key
        ]
        manual = [
            _manual_contribution(item, rule)
            for item in manual_values
            if canonical_path_key(item.member_or_loose_path) == path_key
        ]
        discovery_mode = "hybrid" if automatic and manual else "manual" if manual else "automatic"
        contributions = sorted(automatic + manual, key=_sort_key)
        resolution = _resolve_selection(
            contributions,
            rule=rule,
            discovery_mode=discovery_mode,
            coverage=coverage_payload,
            load_order=load_order,
        )
        payload = {
            "schema_version": "kcd2.path-contribution-set.v1",
            "query_id": checked_query_id,
            "canonical_path": path,
            "discovery_mode": discovery_mode,
            "coverage_id": coverage_payload["coverage_id"],
            "contributions": contributions,
            "resolution": resolution,
        }
        results.append(PathContributionSet(payload=_json_copy(payload)))
    return tuple(results)


def contribution_input_sha256(
    *,
    providers: Sequence[ExactProvider],
    discovered_paths: Sequence[DiscoveredPath],
    load_order: LoadOrderEvidence,
) -> str:
    """Bind the exact provider/member/order ledger used by the extractor."""

    payload = {
        "providers": [
            {
                "provider_id": item.provider_id,
                "provider_kind": item.provider_kind,
                "mod_id": item.mod_id,
                "provider_root": item.provider_root,
                "load_order_index": item.load_order_index,
            }
            for item in providers
        ],
        "discovered_paths": [
            {
                "provider_id": item.provider_id,
                "source_kind": item.source_kind,
                "source_path": item.source_path,
                "member_or_loose_path": canonical_relative_path(
                    item.member_or_loose_path
                ),
                "content_sha256": item.content_sha256,
            }
            for item in discovered_paths
        ],
        "load_order": {
            "complete": load_order.complete,
            "source": load_order.source,
            "sha256": load_order.sha256,
        },
    }
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()
