"""Evidence-qualified provider metadata and payload conflict classification."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path

from .path_contributions import classify_path_semantics


_MAX_TEXT = 1024
_MAX_PROVIDERS = 1024
_MAX_MANIFESTS_PER_PROVIDER = 32
_MAX_CONTRIBUTION_SETS = 256
_MAX_TOTAL_CONTRIBUTIONS = 8192
_MAX_SEMANTIC_PATHS = 4096
_MAX_TABLE_COMPARISONS = 1024
_MAX_DECLARATIONS = 4096
_PROVIDER_KINDS = frozenset(
    {"vanilla", "local", "workshop", "explicit", "generated", "unknown"}
)
_SEMANTICS = frozenset(
    {
        "no_runtime_override",
        "parallel_load",
        "ordered_merge",
        "override_last_wins",
        "separate_namespace",
        "component_specific",
        "unknown",
    }
)


class ConflictClassificationError(ValueError):
    """Conflict inputs cannot support a bounded deterministic result."""


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise ConflictClassificationError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ConflictClassificationError(f"{name} must be an array")
    if len(value) > maximum:
        raise ConflictClassificationError(f"{name} exceeds the {maximum}-item hard bound")
    return value


def _canonical_path(value: object, name: str) -> str:
    checked = _text(value, name)
    try:
        return canonical_relative_path(checked)
    except (TypeError, ValueError) as exc:
        raise ConflictClassificationError(f"{name} must be a canonical relative path") from exc


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
        raise ConflictClassificationError("conflict content must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class ConflictProvider:
    """Exact provider identity and its bounded manifest inventory."""

    provider_id: str
    provider_kind: str
    mod_id: str | None
    manifest_paths: Sequence[str]

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id")
        if self.provider_kind not in _PROVIDER_KINDS:
            raise ConflictClassificationError("provider_kind is not supported")
        if self.mod_id is not None:
            _text(self.mod_id, "mod_id")
        manifests = _sequence(
            self.manifest_paths,
            "manifest_paths",
            _MAX_MANIFESTS_PER_PROVIDER,
        )
        canonical = tuple(
            _canonical_path(path, f"manifest_paths[{index}]")
            for index, path in enumerate(manifests)
        )
        if any(path.rsplit("/", 1)[-1].casefold() != "mod.manifest" for path in canonical):
            raise ConflictClassificationError("manifest_paths may contain only mod.manifest files")
        if len({canonical_path_key(path) for path in canonical}) != len(canonical):
            raise ConflictClassificationError("manifest_paths must not contain duplicates")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ConflictProvider":
        expected = {"provider_id", "provider_kind", "mod_id", "manifest_paths"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ConflictClassificationError("provider fields do not match the conflict input")
        provider_kind = value["provider_kind"]
        if provider_kind == "explicit_path":
            provider_kind = "explicit"
        return cls(
            provider_id=value["provider_id"],  # type: ignore[arg-type]
            provider_kind=provider_kind,  # type: ignore[arg-type]
            mod_id=value["mod_id"],  # type: ignore[arg-type]
            manifest_paths=value["manifest_paths"],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class ConflictClassification:
    """Immutable schema-ready conflict result."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class CompatibilityDeclaration:
    """Bounded intended-winner and protected-resource declarations."""

    intended_winners: tuple[tuple[str, str], ...]
    protected_resources: tuple[tuple[str, str], ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CompatibilityDeclaration":
        declaration_fields = {"intended_winners", "protected_resources"}
        stack_fields = {
            "schema_version",
            "stack_id",
            "family",
            "projects",
            "selected_variants",
            *declaration_fields,
            "checks",
            "result",
        }
        fields = frozenset(value) if isinstance(value, Mapping) else frozenset()
        if not isinstance(value, Mapping) or fields not in {
            frozenset(declaration_fields),
            frozenset(stack_fields),
        }:
            raise ConflictClassificationError(
                "compatibility must be a declaration pair or a complete v1 stack"
            )
        if fields == stack_fields and value.get("schema_version") != (
            "kcd2.compatibility-stack.v1"
        ):
            raise ConflictClassificationError("compatibility stack version is unsupported")

        def declarations(name: str) -> tuple[tuple[str, str], ...]:
            raw_items = _sequence(value[name], name, _MAX_DECLARATIONS)
            checked: list[tuple[str, str]] = []
            seen: set[str] = set()
            for index, raw_item in enumerate(raw_items):
                if not isinstance(raw_item, Mapping) or set(raw_item) != {
                    "resource",
                    "provider_id",
                }:
                    raise ConflictClassificationError(
                        f"{name}[{index}] must contain resource and provider_id"
                    )
                resource = _canonical_path(raw_item.get("resource"), f"{name}.resource")
                provider_id = _text(raw_item.get("provider_id"), f"{name}.provider_id")
                key = canonical_path_key(resource)
                if key in seen:
                    raise ConflictClassificationError(
                        f"{name} resources must be case-insensitively unique"
                    )
                seen.add(key)
                checked.append((resource, provider_id))
            return tuple(sorted(checked, key=lambda item: canonical_path_key(item[0])))

        intended = declarations("intended_winners")
        protected = declarations("protected_resources")
        intended_by_path = {
            canonical_path_key(path): provider.casefold()
            for path, provider in intended
        }
        for path, provider in protected:
            intended_provider = intended_by_path.get(canonical_path_key(path))
            if intended_provider is not None and intended_provider != provider.casefold():
                raise ConflictClassificationError(
                    "one resource cannot declare different intended and protected providers"
                )
        return cls(intended_winners=intended, protected_resources=protected)


def _coverage_payload(value: object) -> Mapping[str, object]:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise ConflictClassificationError("coverage must be a coverage-validity mapping")
    coverage_id = _text(value.get("coverage_id"), "coverage.coverage_id")
    overall_status = _text(value.get("overall_status"), "coverage.overall_status")
    permissions = value.get("claim_permissions")
    if not isinstance(permissions, Mapping):
        raise ConflictClassificationError("coverage.claim_permissions must be an object")
    absence_allowed = permissions.get("conflict_absence_claim_allowed")
    if not isinstance(absence_allowed, bool):
        raise ConflictClassificationError(
            "coverage.claim_permissions.conflict_absence_claim_allowed must be a boolean"
        )
    return {
        "coverage_id": coverage_id,
        "overall_status": overall_status,
        "absence_allowed": absence_allowed,
    }


def _provider_map(providers: Sequence[ConflictProvider]) -> dict[str, ConflictProvider]:
    values = _sequence(providers, "providers", _MAX_PROVIDERS)
    if any(not isinstance(provider, ConflictProvider) for provider in values):
        raise ConflictClassificationError("providers must contain ConflictProvider values")
    result: dict[str, ConflictProvider] = {}
    for provider in values:
        assert isinstance(provider, ConflictProvider)
        key = provider.provider_id.casefold()
        if key in result:
            raise ConflictClassificationError(
                "provider_id values must be case-insensitively unique"
            )
        result[key] = provider
    return result


def _item(path: str, classification: str, providers: Sequence[str]) -> dict[str, object]:
    return {
        "path": path,
        "classification": classification,
        "providers": sorted(set(providers), key=lambda item: (item.casefold(), item)),
    }


def _add_metadata(
    metadata: dict[str, tuple[str, set[str]]], path: str, provider_id: str
) -> None:
    key = canonical_path_key(path)
    if key not in metadata:
        metadata[key] = (path, set())
    representative, provider_ids = metadata[key]
    if (path.casefold(), path) < (representative.casefold(), representative):
        representative = path
        metadata[key] = (representative, provider_ids)
    provider_ids.add(provider_id)


def _provider_diagnostics(
    providers: Sequence[ConflictProvider],
) -> tuple[list[dict[str, object]], set[str], dict[str, tuple[str, set[str]]]]:
    items: list[dict[str, object]] = []
    reasons: set[str] = set()
    metadata: dict[str, tuple[str, set[str]]] = {}
    by_mod_id: dict[str, list[ConflictProvider]] = defaultdict(list)
    for provider in providers:
        if provider.mod_id is not None:
            by_mod_id[provider.mod_id.casefold()].append(provider)
        for path in provider.manifest_paths:
            _add_metadata(metadata, canonical_relative_path(path), provider.provider_id)
        if len(provider.manifest_paths) > 1:
            items.append(
                _item(
                    "mod.manifest",
                    "INVALID_MULTIPLE_MANIFESTS_IN_PROVIDER",
                    (provider.provider_id,),
                )
            )
            reasons.add("MULTIPLE_MANIFESTS_IN_PROVIDER")
    for group in by_mod_id.values():
        kinds = {provider.provider_kind for provider in group}
        if {"local", "workshop"}.issubset(kinds):
            items.append(
                _item(
                    f"provider-mod-id:{group[0].mod_id}",
                    "DUPLICATE_MOD_PROVIDER",
                    tuple(provider.provider_id for provider in group),
                )
            )
            reasons.add("DUPLICATE_LOCAL_WORKSHOP_PROVIDER")
    return items, reasons, metadata


def _contribution_items(
    contribution_sets: Sequence[object],
    provider_by_id: Mapping[str, ConflictProvider],
    metadata: dict[str, tuple[str, set[str]]],
) -> tuple[list[dict[str, object]], set[str], int]:
    values = _sequence(
        contribution_sets,
        "contribution_sets",
        _MAX_CONTRIBUTION_SETS,
    )
    items: list[dict[str, object]] = []
    reasons: set[str] = set()
    observed = 0
    total_contributions = 0
    seen_paths: set[str] = set()
    for set_index, raw_set in enumerate(values):
        if hasattr(raw_set, "to_dict") and callable(raw_set.to_dict):
            raw_set = raw_set.to_dict()
        if not isinstance(raw_set, Mapping):
            raise ConflictClassificationError("contribution_sets must contain mappings")
        path = _canonical_path(
            raw_set.get("canonical_path"),
            f"contribution_sets[{set_index}].canonical_path",
        )
        path_key = canonical_path_key(path)
        if path_key in seen_paths:
            raise ConflictClassificationError("canonical contribution paths must be unique")
        seen_paths.add(path_key)
        contributions = _sequence(
            raw_set.get("contributions"),
            f"contribution_sets[{set_index}].contributions",
            _MAX_TOTAL_CONTRIBUTIONS,
        )
        total_contributions += len(contributions)
        if total_contributions > _MAX_TOTAL_CONTRIBUTIONS:
            raise ConflictClassificationError(
                f"contributions exceed the {_MAX_TOTAL_CONTRIBUTIONS}-item hard bound"
            )
        provider_ids: list[str] = []
        semantics: set[str] = set()
        for contribution_index, contribution in enumerate(contributions):
            if not isinstance(contribution, Mapping):
                raise ConflictClassificationError("contributions must contain mappings")
            provider_id = _text(
                contribution.get("provider_id"),
                f"contributions[{contribution_index}].provider_id",
            )
            provider = provider_by_id.get(provider_id.casefold())
            if provider is None:
                raise ConflictClassificationError(
                    f"contribution names unknown exact provider {provider_id!r}"
                )
            semantic = _text(
                contribution.get("resolution_semantics"),
                f"contributions[{contribution_index}].resolution_semantics",
            )
            if semantic not in _SEMANTICS:
                raise ConflictClassificationError("resolution_semantics is not supported")
            provider_ids.append(provider.provider_id)
            semantics.add(semantic)
        if len(set(item.casefold() for item in provider_ids)) != len(provider_ids):
            raise ConflictClassificationError("a path has duplicate provider contributions")
        path_rule = classify_path_semantics(path)
        if path_rule.resolution_semantics == "no_runtime_override":
            for provider_id in provider_ids:
                _add_metadata(metadata, path, provider_id)
            reasons.add("PROVIDER_METADATA_EXCLUDED")
            continue
        if len(semantics) > 1:
            raise ConflictClassificationError("a path cannot mix resolution semantics")
        if len(provider_ids) < 2:
            continue
        semantic = next(iter(semantics), path_rule.resolution_semantics)
        if (
            path_rule.resolution_semantics != "unknown"
            and semantic != path_rule.resolution_semantics
        ):
            raise ConflictClassificationError(
                "resolution_semantics does not match the canonical path family"
            )
        if semantic == "override_last_wins":
            items.append(_item(path, "GAME_RELATIVE_OVERRIDE_CONFLICT", provider_ids))
            observed += 1
            reasons.add("GAME_RELATIVE_OVERRIDE_OBSERVED")
        elif semantic == "ordered_merge":
            items.append(_item(path, "MERGE_CONTRIBUTION", provider_ids))
            observed += 1
            reasons.add("ORDERED_MERGE_OVERLAP_OBSERVED")
        elif semantic in {"unknown", "separate_namespace", "component_specific"}:
            items.append(_item(path, "UNKNOWN", provider_ids))
            reasons.add("UNSUPPORTED_CONFLICT_SEMANTICS")
    return items, reasons, observed


def classify_conflicts(
    *,
    providers: Sequence[ConflictProvider],
    contribution_sets: Sequence[object],
    coverage: object,
) -> ConflictClassification:
    """Separate provider diagnostics from comparable runtime path conflicts."""

    provider_by_id = _provider_map(providers)
    coverage_payload = _coverage_payload(coverage)
    provider_values = tuple(
        sorted(
            provider_by_id.values(),
            key=lambda provider: (provider.provider_id.casefold(), provider.provider_id),
        )
    )
    diagnostic_items, reasons, metadata = _provider_diagnostics(provider_values)
    payload_items, payload_reasons, observed = _contribution_items(
        contribution_sets,
        provider_by_id,
        metadata,
    )
    reasons.update(payload_reasons)
    metadata_items = [
        _item(path, "PROVIDER_METADATA_NO_CONFLICT", provider_ids)
        for path, provider_ids in metadata.values()
    ]
    ignored_count = sum(len(provider_ids) for _, provider_ids in metadata.values())
    if metadata:
        reasons.add("MANIFEST_IS_PROVIDER_METADATA")

    structural_failure = "MULTIPLE_MANIFESTS_IN_PROVIDER" in reasons
    unsupported = "UNSUPPORTED_CONFLICT_SEMANTICS" in reasons
    coverage_complete = coverage_payload["overall_status"] in {
        "COMPLETE",
        "COMPLETE_FOR_REQUESTED_SCOPE",
    }
    absence_allowed = bool(
        coverage_payload["absence_allowed"] is True and coverage_complete
    )
    absence_claim_valid = bool(
        absence_allowed and not observed and not structural_failure and not unsupported
    )
    if observed:
        conclusion = "CONFLICTS_OBSERVED"
    elif structural_failure or unsupported:
        conclusion = "INCONCLUSIVE"
    elif absence_claim_valid:
        conclusion = "CONFIRMED_NONE"
        reasons.add("CONFLICT_ABSENCE_SUPPORTED_BY_COVERAGE")
    elif coverage_payload["overall_status"] == "PARTIAL_STALE":
        conclusion = "ZERO_OBSERVED_STALE_COVERAGE"
        reasons.add("CONFLICT_ABSENCE_BLOCKED_BY_STALE_COVERAGE")
    elif coverage_payload["overall_status"] in {
        "PARTIAL_LIMIT_REACHED",
        "INCONCLUSIVE",
    }:
        conclusion = "ZERO_OBSERVED_PARTIAL_COVERAGE"
        reasons.add("CONFLICT_ABSENCE_BLOCKED_BY_PARTIAL_COVERAGE")
    else:
        conclusion = "INCONCLUSIVE"
        reasons.add("CONFLICT_ABSENCE_NOT_ESTABLISHED")

    items = sorted(
        diagnostic_items + metadata_items + payload_items,
        key=lambda item: (
            str(item["path"]).casefold(),
            str(item["path"]),
            str(item["classification"]),
        ),
    )
    payload = {
        "schema_version": "kcd2.conflict-classification.v1",
        "coverage_id": coverage_payload["coverage_id"],
        "observed_conflict_count": observed,
        "ignored_provider_metadata_count": ignored_count,
        "items": items,
        "conclusion": conclusion,
        "absence_claim_valid": absence_claim_valid,
        "reason_codes": sorted(reasons),
    }
    return ConflictClassification(payload=_json_copy(payload))


_DOMAIN_RULES = (
    ("libs/tables/inventory", "inventory"),
    ("libs/tables/shop", "shops"),
    ("libs/tables/processing", "processing"),
    ("libs/tables", "items_stats"),
    ("libs/smartobjects", "smart_objects"),
    ("libs/ui", "ui_icons"),
    ("localization/", "localization"),
    ("scripts/", "lua_lifecycle"),
    ("libs/quests", "quests"),
    ("libs/animation", "animation"),
    ("libs/config", "configuration"),
    ("bin/", "native_components"),
)


def _gameplay_domain(path: str) -> str:
    key = canonical_path_key(path)
    for prefix, domain in _DOMAIN_RULES:
        if key.startswith(prefix):
            return domain
    if any(token in key for token in ("combat", "weapon", "armor")):
        return "combat"
    return "other"


def _path_resolution(value: object, index: int) -> Mapping[str, object]:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    if not isinstance(value, Mapping):
        raise ConflictClassificationError("path_resolutions must contain mappings")
    nested = value.get("canonical_path_resolution")
    if nested is not None:
        if not isinstance(nested, Mapping):
            raise ConflictClassificationError("canonical_path_resolution must be an object")
        value = nested
    _canonical_path(value.get("canonical_path"), f"path_resolutions[{index}].canonical_path")
    if not isinstance(value.get("resolution"), Mapping):
        raise ConflictClassificationError("path resolution must contain a resolution object")
    _sequence(
        value.get("contributions"),
        f"path_resolutions[{index}].contributions",
        _MAX_TOTAL_CONTRIBUTIONS,
    )
    return value


def _provider_ids(contributions: object, name: str) -> list[str]:
    values = _sequence(contributions, name, _MAX_TOTAL_CONTRIBUTIONS)
    result: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            raise ConflictClassificationError(f"{name} must contain mappings")
        result.append(_text(value.get("provider_id"), f"{name}[{index}].provider_id"))
    if len({item.casefold() for item in result}) != len(result):
        raise ConflictClassificationError(f"{name} contains duplicate providers")
    return result


def _effective_outcome(
    resolution: Mapping[str, object], providers: Sequence[str]
) -> tuple[str, list[str], bool]:
    conclusion = _text(resolution.get("conclusion"), "resolution.conclusion")
    reasons = _sequence(resolution.get("reason_codes", ()), "resolution.reason_codes", 128)
    reason_codes = {_text(item, "resolution.reason_code") for item in reasons}
    winner = resolution.get("winner_provider_id")
    if conclusion == "winner":
        winner_id = _text(winner, "resolution.winner_provider_id")
        matches = [item for item in providers if item.casefold() == winner_id.casefold()]
        if len(matches) != 1:
            raise ConflictClassificationError("winner_provider_id must name one contribution")
        return "winner", matches, True
    if winner is not None:
        raise ConflictClassificationError("non-winner resolution cannot name a winner")
    if conclusion == "parallel_contributors":
        return "parallel", list(providers), True
    if conclusion == "multiple_contributors":
        if "SEMANTICS_ORDERED_MERGE" in reason_codes:
            return "ordered_merge", list(providers), True
        if "SEMANTICS_SEPARATE_NAMESPACE" in reason_codes:
            return "separate_namespace", list(providers), True
        if "SEMANTICS_COMPONENT_SPECIFIC" in reason_codes:
            return "component_specific", list(providers), True
        if "SEMANTICS_NO_RUNTIME_OVERRIDE" in reason_codes:
            return "metadata_only", list(providers), True
        return "inconclusive", [], False
    if conclusion == "no_provider_observed":
        return "no_provider", [], True
    if conclusion == "inconclusive":
        return "inconclusive", [], False
    raise ConflictClassificationError(f"unsupported resolution conclusion {conclusion!r}")


def _semantic_counts(comparison: Mapping[str, object]) -> dict[str, int]:
    changes = _sequence(
        comparison.get("semantic_changes", ()), "semantic_changes", _MAX_TOTAL_CONTRIBUTIONS
    )
    counts = {"record": len(changes), "attribute": 0, "child": 0, "reference": 0}
    for change in changes:
        if not isinstance(change, Mapping):
            raise ConflictClassificationError("semantic_changes must contain mappings")
        for key, level in (
            ("attribute_changes", "attribute"),
            ("child_changes", "child"),
            ("reference_changes", "reference"),
        ):
            counts[level] += len(_sequence(change.get(key, ()), key, _MAX_TOTAL_CONTRIBUTIONS))
    return counts


def _shadow_metrics(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ConflictClassificationError(
            "table comparison must contain full_shadow_metrics"
        )

    def count(name: str) -> int:
        item = value.get(name)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise ConflictClassificationError(f"{name} must be a non-negative integer")
        return item

    baseline = count("baseline_total_records")
    changed = count("changed_records")
    duplicated = count("duplicated_records")
    overlap = changed + duplicated
    if overlap > baseline:
        raise ConflictClassificationError(
            "changed plus duplicated records cannot exceed the baseline"
        )
    ratio = value.get("shadow_ratio")
    if (
        not isinstance(ratio, (int, float))
        or isinstance(ratio, bool)
        or not 0 <= ratio <= 1
    ):
        raise ConflictClassificationError("shadow_ratio must be between zero and one")
    expected_ratio = overlap / baseline if baseline else 0.0
    if round(float(ratio), 6) != round(expected_ratio, 6):
        raise ConflictClassificationError("shadow_ratio is inconsistent with record counts")
    full_shadow = value.get("full_file_shadow")
    if not isinstance(full_shadow, bool) or full_shadow != (
        baseline > 0 and overlap == baseline
    ):
        raise ConflictClassificationError(
            "full_file_shadow is inconsistent with record counts"
        )
    source_builds = _sequence(
        value.get("dependency_source_builds", ()),
        "dependency_source_builds",
        _MAX_TABLE_COMPARISONS,
    )
    dependency_hashes = _sequence(
        value.get("dependency_content_sha256", ()),
        "dependency_content_sha256",
        _MAX_TABLE_COMPARISONS,
    )
    builds = [_text(item, "dependency_source_build") for item in source_builds]
    hashes = [_text(item, "dependency_content_sha256") for item in dependency_hashes]
    if any(len(item) != 64 or any(char not in "0123456789abcdef" for char in item) for item in hashes):
        raise ConflictClassificationError(
            "dependency_content_sha256 values must be lowercase SHA-256 digests"
        )
    stale_risk = _text(value.get("stale_shadow_risk"), "stale_shadow_risk")
    expected_risk = "review_required" if full_shadow and builds else "none_observed"
    if stale_risk != expected_risk:
        raise ConflictClassificationError(
            "stale_shadow_risk is inconsistent with full-shadow dependency evidence"
        )
    return {
        "shadow_ratio": round(float(ratio), 6),
        "full_file_shadow": full_shadow,
        "baseline_total_records": baseline,
        "changed_records": changed,
        "duplicated_records": duplicated,
        "dependency_source_builds": builds,
        "dependency_content_sha256": hashes,
        "stale_shadow_risk": stale_risk,
    }


def analyze_semantic_conflicts(
    *,
    query_id: str,
    path_resolutions: Sequence[object],
    table_comparisons: Sequence[object],
    compatibility: CompatibilityDeclaration,
) -> ConflictClassification:
    """Compose exact path and table evidence into compatibility-aware conflicts.

    This function does not infer a winner from path order. It accepts only the
    evidence-qualified conclusion produced by the effective path resolver.
    """

    checked_query = _text(query_id, "query_id")
    if not isinstance(compatibility, CompatibilityDeclaration):
        raise ConflictClassificationError(
            "compatibility must be a CompatibilityDeclaration"
        )
    raw_paths = _sequence(path_resolutions, "path_resolutions", _MAX_SEMANTIC_PATHS)
    path_by_key: dict[str, Mapping[str, object]] = {}
    for index, raw_path in enumerate(raw_paths):
        path_value = _path_resolution(raw_path, index)
        path = _canonical_path(path_value.get("canonical_path"), "canonical_path")
        key = canonical_path_key(path)
        if key in path_by_key:
            raise ConflictClassificationError("path_resolutions paths must be unique")
        path_by_key[key] = path_value

    comparison_values = _sequence(
        table_comparisons, "table_comparisons", _MAX_TABLE_COMPARISONS
    )
    comparison_by_key: dict[str, Mapping[str, object]] = {}
    for index, value in enumerate(comparison_values):
        if hasattr(value, "to_dict") and callable(value.to_dict):
            value = value.to_dict()
        if not isinstance(value, Mapping):
            raise ConflictClassificationError("table_comparisons must contain mappings")
        path = _canonical_path(
            value.get("canonical_path"), f"table_comparisons[{index}].canonical_path"
        )
        key = canonical_path_key(path)
        if key in comparison_by_key:
            raise ConflictClassificationError("table comparison paths must be unique")
        comparison_by_key[key] = value
    if set(comparison_by_key) - set(path_by_key):
        raise ConflictClassificationError(
            "every table comparison must name an analyzed path"
        )

    intended = {
        canonical_path_key(path): (path, provider)
        for path, provider in compatibility.intended_winners
    }
    protected = {
        canonical_path_key(path): (path, provider)
        for path, provider in compatibility.protected_resources
    }
    missing_declarations = sorted((set(intended) | set(protected)) - set(path_by_key))
    if missing_declarations:
        raise ConflictClassificationError(
            "compatibility resources must name an analyzed path"
        )

    semantic_items: list[dict[str, object]] = []
    intentional_wins: list[dict[str, str]] = []
    intended_mismatches: list[dict[str, object]] = []
    protected_violations: list[dict[str, object]] = []
    full_shadows: list[dict[str, object]] = []
    inconclusive = False
    domain_counts: dict[str, dict[str, object]] = {}

    for key, raw_path in sorted(path_by_key.items()):
        path = _canonical_path(raw_path.get("canonical_path"), "canonical_path")
        providers = _provider_ids(raw_path.get("contributions"), "contributions")
        resolution = raw_path["resolution"]
        assert isinstance(resolution, Mapping)
        outcome, effective, supported = _effective_outcome(resolution, providers)
        domain = _gameplay_domain(path)
        comparison = comparison_by_key.get(key)
        conflict_counts = {"file": 1 if len(providers) > 1 else 0}
        if comparison is not None:
            status = _text(comparison.get("comparison_status"), "comparison_status")
            if status != "resolved":
                supported = False
            conflict_counts.update(_semantic_counts(comparison))
            metrics = _shadow_metrics(comparison.get("full_shadow_metrics"))
            full_shadows.append(
                {
                    "path": path,
                    **metrics,
                }
            )
        if not supported:
            inconclusive = True

        intentional = False
        if key in intended:
            _, expected = intended[key]
            if outcome == "winner" and effective[0].casefold() == expected.casefold():
                intentional = True
                intentional_wins.append(
                    {"path": path, "provider_id": effective[0], "domain": domain}
                )
            elif supported:
                intended_mismatches.append(
                    {
                        "path": path,
                        "expected_provider_id": expected,
                        "effective_provider_ids": effective,
                    }
                )
        protected_violation = False
        if key in protected:
            _, required = protected[key]
            if supported and required.casefold() not in {item.casefold() for item in effective}:
                protected_violation = True
                protected_violations.append(
                    {
                        "path": path,
                        "required_provider_id": required,
                        "effective_provider_ids": effective,
                    }
                )
            elif not supported:
                inconclusive = True

        semantic_items.append(
            {
                "path": path,
                "domain": domain,
                "providers": providers,
                "outcome": outcome,
                "effective_provider_ids": effective,
                "effective_outcome_supported": supported,
                "intentional_win": intentional,
                "protected_resource_violation": protected_violation,
                "conflict_counts": conflict_counts,
            }
        )
        group = domain_counts.setdefault(
            domain,
            {"domain": domain, "path_count": 0, "conflict_count": 0, "levels": set()},
        )
        group["path_count"] = int(group["path_count"]) + 1
        group["conflict_count"] = int(group["conflict_count"]) + sum(
            conflict_counts.values()
        )
        assert isinstance(group["levels"], set)
        group["levels"].update(
            level for level, count in conflict_counts.items() if count
        )

    failed = bool(protected_violations or intended_mismatches)
    result = "FAIL" if failed else "INCONCLUSIVE" if inconclusive else "PASS"
    observed = sum(1 for item in semantic_items if len(item["providers"]) > 1)
    basic_items = [
        _item(
            item["path"],
            (
                "MERGE_CONTRIBUTION"
                if item["outcome"] == "ordered_merge"
                else "GAME_RELATIVE_OVERRIDE_CONFLICT"
            ),
            item["providers"],
        )
        for item in semantic_items
        if len(item["providers"]) > 1
    ]
    reasons = []
    if protected_violations:
        reasons.append("PROTECTED_RESOURCE_VIOLATION")
    if intended_mismatches:
        reasons.append("INTENDED_WINNER_MISMATCH")
    if inconclusive:
        reasons.append("SEMANTIC_OUTCOME_INCONCLUSIVE")
    payload = {
        "schema_version": "kcd2.conflict-classification.v1",
        "coverage_id": checked_query,
        "observed_conflict_count": observed,
        "ignored_provider_metadata_count": 0,
        "items": basic_items,
        "conclusion": "CONFLICTS_OBSERVED" if observed else "CONFIRMED_NONE",
        "absence_claim_valid": False,
        "reason_codes": sorted(reasons),
        "query_id": checked_query,
        "semantic_items": semantic_items,
        "domain_groups": [
            {
                **{key: value for key, value in group.items() if key != "levels"},
                "levels": sorted(group["levels"]),
            }
            for _, group in sorted(domain_counts.items())
        ],
        "intentional_wins": intentional_wins,
        "intended_winner_mismatches": intended_mismatches,
        "protected_resource_violations": protected_violations,
        "full_shadow_analyses": sorted(
            full_shadows,
            key=lambda item: canonical_path_key(str(item["path"])),
        ),
        "result": result,
    }
    return ConflictClassification(payload=_json_copy(payload))
