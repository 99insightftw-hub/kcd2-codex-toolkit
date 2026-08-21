"""Bounded provider inventory derived only from approved metadata records."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal

from kcd2_index_adapter.coverage import CoverageValidity
from kcd2_index_adapter.provider_classifier import (
    ModProviderClassification,
    ProviderCatalogEvidence,
    ProviderFreshnessRules,
    classify_mod_providers,
)
from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path


ProviderKind = Literal["vanilla", "local", "workshop"]

_PROVIDER_KINDS = frozenset({"vanilla", "local", "workshop"})
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TEXT = 1024
_MAX_PROVIDERS = 4096
_MAX_INTERNAL_PATHS = 8192
_MAX_METADATA_AGE_SECONDS = 31 * 24 * 60 * 60


class ProviderInventoryError(ValueError):
    """Approved metadata cannot produce a safe, bounded provider inventory."""


def _text(value: object, name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise ProviderInventoryError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _timestamp(value: object, name: str) -> datetime:
    if not isinstance(value, datetime):
        raise ProviderInventoryError(f"{name} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProviderInventoryError(f"{name} must include a UTC offset")
    return value.astimezone(timezone.utc)


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _provider_path(value: object) -> str:
    path = _text(value, "provider_path")
    assert path is not None
    if ".." in path.replace("\\", "/").split("/"):
        raise ProviderInventoryError("provider_path must not contain parent traversal")
    return path


def _internal_paths(values: object) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ProviderInventoryError("internal_paths must be a sequence")
    if len(values) > _MAX_INTERNAL_PATHS:
        raise ProviderInventoryError(
            f"internal_paths exceeds the {_MAX_INTERNAL_PATHS}-path hard bound"
        )
    try:
        paths = tuple(canonical_relative_path(value) for value in values)
    except (TypeError, ValueError) as exc:
        raise ProviderInventoryError(f"invalid internal path: {exc}") from exc
    if not paths:
        raise ProviderInventoryError("internal_paths must contain at least one exact path")
    keys = [canonical_path_key(path) for path in paths]
    if len(keys) != len(set(keys)):
        raise ProviderInventoryError("internal_paths contains duplicate canonical paths")
    return tuple(sorted(paths, key=lambda path: (canonical_path_key(path), path)))


@dataclass(frozen=True, slots=True)
class ApprovedProviderMetadata:
    """One provider record obtained from an approved metadata source."""

    provider_id: str
    provider_kind: ProviderKind
    mod_id: str | None
    provider_path: str
    provider_sha256: str
    metadata_id: str
    metadata_captured_at: datetime
    internal_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        provider_id = _text(self.provider_id, "provider_id")
        if self.provider_kind not in _PROVIDER_KINDS:
            raise ProviderInventoryError("provider_kind must be vanilla, local, or workshop")
        mod_id = _text(self.mod_id, "mod_id", nullable=True)
        if self.provider_kind != "vanilla" and mod_id is None:
            raise ProviderInventoryError("local and Workshop providers require mod_id")
        path = _provider_path(self.provider_path)
        if not isinstance(self.provider_sha256, str) or not _SHA256.fullmatch(
            self.provider_sha256
        ):
            raise ProviderInventoryError("provider_sha256 must be a 64-character SHA-256")
        metadata_id = _text(self.metadata_id, "metadata_id")
        captured_at = _timestamp(self.metadata_captured_at, "metadata_captured_at")
        internal_paths = _internal_paths(self.internal_paths)

        object.__setattr__(self, "provider_id", provider_id)
        object.__setattr__(self, "mod_id", mod_id)
        object.__setattr__(self, "provider_path", path)
        object.__setattr__(self, "provider_sha256", self.provider_sha256.lower())
        object.__setattr__(self, "metadata_id", metadata_id)
        object.__setattr__(self, "metadata_captured_at", captured_at)
        object.__setattr__(self, "internal_paths", internal_paths)


@dataclass(frozen=True, slots=True)
class ProviderInventory:
    """Immutable deterministic provider inventory and coverage envelope."""

    payload: Mapping[str, Any]

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


def _bound(name: str, value: object, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ProviderInventoryError(f"{name} must be from 1 through {maximum}")
    return value


def build_provider_inventory(
    *,
    inventory_id: str,
    providers: Sequence[ApprovedProviderMetadata],
    coverage: CoverageValidity,
    evaluated_at: datetime,
    max_metadata_age_seconds: int,
    max_providers: int = _MAX_PROVIDERS,
) -> ProviderInventory:
    """Inventory caller-supplied metadata without discovering installation roots."""

    checked_id = _text(inventory_id, "inventory_id")
    evaluated = _timestamp(evaluated_at, "evaluated_at")
    freshness_limit = _bound(
        "max_metadata_age_seconds",
        max_metadata_age_seconds,
        _MAX_METADATA_AGE_SECONDS,
    )
    provider_limit = _bound("max_providers", max_providers, _MAX_PROVIDERS)
    if isinstance(providers, (str, bytes)) or not isinstance(providers, Sequence):
        raise ProviderInventoryError("providers must be a sequence")
    if len(providers) > provider_limit:
        raise ProviderInventoryError("providers exceeds the configured provider hard bound")
    if any(not isinstance(item, ApprovedProviderMetadata) for item in providers):
        raise ProviderInventoryError("providers must contain ApprovedProviderMetadata")
    if not isinstance(coverage, CoverageValidity):
        raise ProviderInventoryError("coverage must be an IDX-009 CoverageValidity result")

    coverage_payload = coverage.to_dict()
    if coverage_payload["operation"] != "inventory_providers":
        raise ProviderInventoryError("coverage operation must be inventory_providers")
    required_kinds = {item.provider_kind for item in providers}
    scoped_kinds = set(coverage_payload["requested_scope"]["provider_kinds"])
    if not required_kinds.issubset(scoped_kinds):
        raise ProviderInventoryError("coverage scope omits an inventoried provider kind")

    provider_ids = [item.provider_id.casefold() for item in providers]
    if len(provider_ids) != len(set(provider_ids)):
        raise ProviderInventoryError("provider_id values must be unique")

    records: list[dict[str, Any]] = []
    stale = False
    future = False
    for item in providers:
        age = (evaluated - item.metadata_captured_at).total_seconds()
        item_future = age < 0
        fresh = not item_future and age <= freshness_limit
        stale = stale or not fresh
        future = future or item_future
        records.append(
            {
                "provider_id": item.provider_id,
                "provider_kind": item.provider_kind,
                "mod_id": item.mod_id,
                "provider_path": item.provider_path,
                "provider_sha256": item.provider_sha256,
                "metadata_id": item.metadata_id,
                "metadata_captured_at": _iso_utc(item.metadata_captured_at),
                "internal_paths": list(item.internal_paths),
                "freshness": {
                    "fresh": fresh,
                    "age_seconds": age if not item_future else None,
                    "max_age_seconds": freshness_limit,
                },
            }
        )
    records.sort(
        key=lambda item: (
            item["provider_kind"],
            item["provider_id"].casefold(),
            item["provider_id"],
        )
    )

    source_permissions = coverage_payload["claim_permissions"]
    complete = coverage_payload["overall_status"] in {
        "COMPLETE",
        "COMPLETE_FOR_REQUESTED_SCOPE",
    }
    reason_codes = set(coverage_payload["reason_codes"])
    if stale:
        reason_codes.add("PROVIDER_METADATA_STALE")
    if future:
        reason_codes.add("PROVIDER_METADATA_FROM_FUTURE")
    claims = {
        "presence_claim_allowed": source_permissions["presence_claim_allowed"],
        "absence_claim_allowed": source_permissions["absence_claim_allowed"] and not stale,
        "winner_claim_allowed": source_permissions["winner_claim_allowed"] and not stale,
        "conflict_absence_claim_allowed": (
            source_permissions["conflict_absence_claim_allowed"] and not stale
        ),
    }

    return ProviderInventory(
        {
            "schema_version": "kcd2.provider-inventory.v1",
            "inventory_id": checked_id,
            "evaluated_at": _iso_utc(evaluated),
            "status": "complete" if complete and not stale else "capture_inconclusive",
            "providers": records,
            "coverage_envelope": {
                "coverage_id": coverage_payload["coverage_id"],
                "basis": coverage_payload["basis"],
                "overall_status": coverage_payload["overall_status"],
                **claims,
                "reason_codes": sorted(reason_codes),
            },
        }
    )


def classify_inventory_mod(
    mod_id: str,
    *,
    local: ProviderCatalogEvidence,
    workshop: ProviderCatalogEvidence,
    evaluated_at: datetime,
    freshness_rules: ProviderFreshnessRules,
) -> ModProviderClassification:
    """Apply the reviewed Workshop-aware classifier to approved inventory catalogs."""

    return classify_mod_providers(
        mod_id,
        local=local,
        workshop=workshop,
        evaluated_at=evaluated_at,
        freshness_rules=freshness_rules,
    )
