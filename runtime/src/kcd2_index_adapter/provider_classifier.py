"""Deterministic local/Workshop provider classification from explicit catalog evidence."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal


ProviderState = Literal[
    "LOCAL_PRESENT",
    "WORKSHOP_PRESENT",
    "LOCAL_AND_WORKSHOP_PRESENT",
    "POSSIBLY_WORKSHOP_MANAGED",
    "MISSING_CONFIRMED",
    "WORKSHOP_COVERAGE_STALE",
]

_MAX_CATALOG_AGE_SECONDS = 31 * 24 * 60 * 60
_MAX_PROVIDER_PATHS = 64
_MAX_ROOTS = 64
_MAX_TEXT_LENGTH = 1024


def _require_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{name} must be a boolean")
    return value


def _bounded_text(value: object, name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > _MAX_TEXT_LENGTH:
        raise ValueError(f"{name} exceeds the {_MAX_TEXT_LENGTH}-character bound")
    if "\x00" in value:
        raise ValueError(f"{name} contains a NUL character")
    return value


def _path_key(value: str) -> str:
    normalized = value.replace("\\", "/").rstrip("/")
    return normalized.casefold()


def _validate_path(value: object, name: str) -> str:
    path = _bounded_text(value, name)
    assert path is not None
    segments = path.replace("\\", "/").split("/")
    if ".." in segments:
        raise ValueError(f"{name} must not contain parent traversal")
    return path


def _bounded_paths(values: object, name: str, maximum: int) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError(f"{name} must be a sequence of paths")
    if len(values) > maximum:
        raise ValueError(f"{name} exceeds the {maximum}-path bound")
    paths = tuple(_validate_path(value, f"{name}[{index}]") for index, value in enumerate(values))
    keys = [_path_key(path) for path in paths]
    if len(keys) != len(set(keys)):
        raise ValueError(f"{name} contains duplicate paths")
    return tuple(sorted(paths, key=lambda path: (_path_key(path), path)))


def _aware_datetime(value: object, name: str, *, nullable: bool = False) -> datetime | None:
    if value is None and nullable:
        return None
    if not isinstance(value, datetime):
        raise TypeError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="auto").replace("+00:00", "Z")


def _is_within(path: str, root: str) -> bool:
    path_key = _path_key(path)
    root_key = _path_key(root)
    return path_key == root_key or path_key.startswith(f"{root_key}/")


@dataclass(frozen=True, slots=True)
class ProviderFreshnessRules:
    """Version-one freshness ceiling supplied explicitly by the caller."""

    max_catalog_age_seconds: int

    def __post_init__(self) -> None:
        value = self.max_catalog_age_seconds
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError("max_catalog_age_seconds must be a positive integer")
        if value > _MAX_CATALOG_AGE_SECONDS:
            raise ValueError(
                "max_catalog_age_seconds exceeds the adapter hard ceiling of "
                f"{_MAX_CATALOG_AGE_SECONDS}"
            )


@dataclass(frozen=True, slots=True)
class ProviderCatalogEvidence:
    """Bounded catalog evidence for one provider kind without filesystem access."""

    checked: bool
    exhaustive: bool
    configured_roots: tuple[str, ...]
    covered_roots: tuple[str, ...]
    provider_paths: tuple[str, ...]
    catalog_id: str | None
    catalog_captured_at: datetime | None
    limit_reached: bool = False

    def __post_init__(self) -> None:
        checked = _require_bool(self.checked, "checked")
        exhaustive = _require_bool(self.exhaustive, "exhaustive")
        limit_reached = _require_bool(self.limit_reached, "limit_reached")
        configured = _bounded_paths(self.configured_roots, "configured_roots", _MAX_ROOTS)
        covered = _bounded_paths(self.covered_roots, "covered_roots", _MAX_ROOTS)
        providers = _bounded_paths(
            self.provider_paths, "provider_paths", _MAX_PROVIDER_PATHS
        )
        catalog_id = _bounded_text(self.catalog_id, "catalog_id", nullable=True)
        captured_at = _aware_datetime(
            self.catalog_captured_at, "catalog_captured_at", nullable=True
        )

        configured_keys = {_path_key(path) for path in configured}
        uncovered_declarations = [
            path for path in covered if _path_key(path) not in configured_keys
        ]
        if uncovered_declarations:
            raise ValueError("covered_roots must be a subset of configured_roots")
        for provider_path in providers:
            if not any(_is_within(provider_path, root) for root in covered):
                raise ValueError("every provider path must be within a covered provider root")
        if not checked and (
            exhaustive
            or covered
            or providers
            or catalog_id is not None
            or captured_at is not None
            or limit_reached
        ):
            raise ValueError("unchecked evidence cannot claim catalog observations")

        object.__setattr__(self, "configured_roots", configured)
        object.__setattr__(self, "covered_roots", covered)
        object.__setattr__(self, "provider_paths", providers)
        object.__setattr__(self, "catalog_id", catalog_id)
        object.__setattr__(self, "catalog_captured_at", captured_at)


@dataclass(frozen=True, slots=True)
class ModProviderClassification:
    """Schema-ready deterministic provider classification."""

    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _evaluate_catalog(
    provider_kind: Literal["LOCAL", "WORKSHOP"],
    evidence: ProviderCatalogEvidence,
    evaluated_at: datetime,
    rules: ProviderFreshnessRules,
) -> tuple[dict[str, Any], bool, list[str]]:
    diagnostics: list[str] = []
    age_seconds: float | None = None
    fresh = False

    if not evidence.checked:
        diagnostics.append(f"{provider_kind}_NOT_CHECKED")
    elif evidence.catalog_id is None:
        diagnostics.append(f"{provider_kind}_CATALOG_ID_MISSING")
    elif evidence.catalog_captured_at is None:
        diagnostics.append(f"{provider_kind}_CATALOG_TIMESTAMP_MISSING")
    else:
        age = (evaluated_at - evidence.catalog_captured_at).total_seconds()
        if age < 0:
            diagnostics.append(f"{provider_kind}_CATALOG_FROM_FUTURE")
        else:
            age_seconds = age
            fresh = age <= rules.max_catalog_age_seconds
            if not fresh:
                diagnostics.append(f"{provider_kind}_COVERAGE_STALE")

    configured_keys = {_path_key(path) for path in evidence.configured_roots}
    covered_keys = {_path_key(path) for path in evidence.covered_roots}
    roots_complete = bool(configured_keys) and configured_keys == covered_keys
    if evidence.checked and not configured_keys:
        diagnostics.append(f"{provider_kind}_NO_CONFIGURED_ROOTS")
    elif evidence.checked and not roots_complete:
        diagnostics.append(f"{provider_kind}_ROOTS_NOT_FULLY_COVERED")
    if evidence.limit_reached:
        diagnostics.append(f"{provider_kind}_LIMIT_REACHED")
    if evidence.checked and not evidence.exhaustive:
        diagnostics.append(f"{provider_kind}_CHECK_NOT_EXHAUSTIVE")

    exhaustive = (
        evidence.checked
        and evidence.exhaustive
        and roots_complete
        and not evidence.limit_reached
    )
    absence_ready = evidence.checked and fresh and exhaustive
    check = {
        "checked": evidence.checked,
        "fresh": fresh,
        "exhaustive": exhaustive,
        "present": bool(evidence.provider_paths),
        "paths": list(evidence.provider_paths),
        "catalog_id": evidence.catalog_id,
        "catalog_captured_at": (
            _iso_utc(evidence.catalog_captured_at)
            if evidence.catalog_captured_at is not None
            else None
        ),
        "catalog_age_seconds": age_seconds,
        "configured_roots": list(evidence.configured_roots),
        "covered_roots": list(evidence.covered_roots),
        "limit_reached": evidence.limit_reached,
    }
    return check, absence_ready, diagnostics


def classify_mod_providers(
    mod_id: str,
    *,
    local: ProviderCatalogEvidence,
    workshop: ProviderCatalogEvidence,
    evaluated_at: datetime,
    freshness_rules: ProviderFreshnessRules,
) -> ModProviderClassification:
    """Classify provider state without treating a local-folder miss as final absence."""

    bounded_mod_id = _bounded_text(mod_id, "mod_id")
    assert bounded_mod_id is not None
    if not isinstance(local, ProviderCatalogEvidence):
        raise TypeError("local must be ProviderCatalogEvidence")
    if not isinstance(workshop, ProviderCatalogEvidence):
        raise TypeError("workshop must be ProviderCatalogEvidence")
    if not isinstance(freshness_rules, ProviderFreshnessRules):
        raise TypeError("freshness_rules must be ProviderFreshnessRules")
    evaluated = _aware_datetime(evaluated_at, "evaluated_at")
    assert evaluated is not None

    local_check, local_absence_ready, local_diagnostics = _evaluate_catalog(
        "LOCAL", local, evaluated, freshness_rules
    )
    workshop_check, workshop_absence_ready, workshop_diagnostics = _evaluate_catalog(
        "WORKSHOP", workshop, evaluated, freshness_rules
    )

    local_present = local_check["present"]
    workshop_present = workshop_check["present"]
    coverage_complete = local_absence_ready and workshop_absence_ready
    if local_present and workshop_present:
        state: ProviderState = "LOCAL_AND_WORKSHOP_PRESENT"
    elif local_present:
        state = "LOCAL_PRESENT"
    elif workshop_present:
        state = "WORKSHOP_PRESENT"
    elif coverage_complete:
        state = "MISSING_CONFIRMED"
    elif workshop.checked and not workshop_check["fresh"]:
        state = "WORKSHOP_COVERAGE_STALE"
    else:
        state = "POSSIBLY_WORKSHOP_MANAGED"

    payload = {
        "schema_version": "kcd2.mod-provider-classification.v1",
        "mod_id": bounded_mod_id,
        "state": state,
        "classified_at": _iso_utc(evaluated),
        "freshness_rules": {
            "max_catalog_age_seconds": freshness_rules.max_catalog_age_seconds,
        },
        "local_check": local_check,
        "workshop_check": workshop_check,
        "coverage_complete": coverage_complete,
        "diagnostics": local_diagnostics + workshop_diagnostics,
    }
    return ModProviderClassification(payload)
