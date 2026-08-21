"""Resolve effective internal paths from an approved active-provider inventory."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_index_adapter.path_contributions import (
    DiscoveredPath,
    ExactProvider,
    LoadOrderEvidence,
    PathContributionSet,
    resolve_internal_path_contributions,
)

from .deployment_registry import DeploymentOperation, SnapshotGateDecision
from .provider_inventory import ProviderInventory


_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TEXT = 1024
_MAX_ORDERED_PROVIDERS = 4096


class EffectivePathResolutionError(ValueError):
    """Inventory or order provenance cannot support bounded path resolution."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise EffectivePathResolutionError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


@dataclass(frozen=True, slots=True)
class ActiveLoadOrder:
    """Hash-bound provider order used to interpret an active inventory."""

    provider_ids: tuple[str, ...]
    complete: bool
    source: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.provider_ids, (str, bytes))
            or not isinstance(self.provider_ids, Sequence)
            or len(self.provider_ids) > _MAX_ORDERED_PROVIDERS
        ):
            raise EffectivePathResolutionError(
                f"provider_ids must contain at most {_MAX_ORDERED_PROVIDERS} entries"
            )
        checked = tuple(
            _text(value, f"provider_ids[{index}]")
            for index, value in enumerate(self.provider_ids)
        )
        keys = [value.casefold() for value in checked]
        if len(keys) != len(set(keys)):
            raise EffectivePathResolutionError(
                "provider_ids must be case-insensitively unique"
            )
        if not isinstance(self.complete, bool):
            raise EffectivePathResolutionError("complete must be a boolean")
        _text(self.source, "source")
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise EffectivePathResolutionError("sha256 must be a SHA-256 digest")
        object.__setattr__(self, "provider_ids", checked)
        object.__setattr__(self, "sha256", self.sha256.lower())


@dataclass(frozen=True, slots=True)
class EffectivePathResolutionReport:
    """Schema-ready resolution result with its exact order provenance."""

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


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EffectivePathResolutionError(f"{name} must be an object")
    return value


def _inventory_inputs(
    inventory: ProviderInventory,
    load_order: ActiveLoadOrder,
) -> tuple[tuple[ExactProvider, ...], tuple[DiscoveredPath, ...], Mapping[str, object], bool]:
    if not isinstance(inventory, ProviderInventory):
        raise EffectivePathResolutionError("inventory must be a ProviderInventory")
    if not isinstance(load_order, ActiveLoadOrder):
        raise EffectivePathResolutionError("load_order must be an ActiveLoadOrder")

    payload = _mapping(inventory.to_dict(), "inventory")
    raw_providers = payload.get("providers")
    if isinstance(raw_providers, (str, bytes)) or not isinstance(raw_providers, Sequence):
        raise EffectivePathResolutionError("inventory.providers must be an array")
    if len(raw_providers) > _MAX_ORDERED_PROVIDERS:
        raise EffectivePathResolutionError(
            f"inventory.providers exceeds the {_MAX_ORDERED_PROVIDERS}-provider hard bound"
        )

    order_indices = {
        provider_id.casefold(): index
        for index, provider_id in enumerate(load_order.provider_ids)
    }
    inventory_ids: set[str] = set()
    providers: list[ExactProvider] = []
    paths: list[DiscoveredPath] = []
    for index, raw_provider in enumerate(raw_providers):
        provider = _mapping(raw_provider, f"inventory.providers[{index}]")
        provider_id = _text(provider.get("provider_id"), "provider_id")
        provider_key = provider_id.casefold()
        if provider_key in inventory_ids:
            raise EffectivePathResolutionError(
                "inventory provider IDs must be case-insensitively unique"
            )
        inventory_ids.add(provider_key)
        provider_root = _text(provider.get("provider_path"), "provider_path")
        exact = ExactProvider(
            provider_id=provider_id,
            provider_kind=provider.get("provider_kind"),  # type: ignore[arg-type]
            mod_id=provider.get("mod_id"),  # type: ignore[arg-type]
            provider_root=provider_root,
            load_order_index=order_indices.get(provider_key),
        )
        providers.append(exact)

        internal_paths = provider.get("internal_paths")
        if isinstance(internal_paths, (str, bytes)) or not isinstance(
            internal_paths, Sequence
        ):
            raise EffectivePathResolutionError("provider internal_paths must be an array")
        for internal_path in internal_paths:
            paths.append(
                DiscoveredPath(
                    provider_id=provider_id,
                    source_kind="loose_file",
                    source_path=provider_root,
                    member_or_loose_path=internal_path,  # type: ignore[arg-type]
                    content_sha256=None,
                )
            )

    coverage = _mapping(payload.get("coverage_envelope"), "coverage_envelope")
    status_complete = payload.get("status") == "complete"
    winner_allowed = status_complete and coverage.get("winner_claim_allowed") is True
    absence_allowed = status_complete and coverage.get("absence_claim_allowed") is True
    coverage_payload = {
        "coverage_id": _text(coverage.get("coverage_id"), "coverage_id"),
        "claim_permissions": {
            "winner_claim_allowed": winner_allowed,
            "absence_claim_allowed": absence_allowed,
        },
    }
    exact_order_coverage = set(order_indices) == inventory_ids
    return tuple(providers), tuple(paths), coverage_payload, exact_order_coverage


def resolve_effective_internal_path(
    *,
    query_id: str,
    canonical_path: str,
    inventory: ProviderInventory,
    load_order: ActiveLoadOrder,
    snapshot_gate: SnapshotGateDecision | None = None,
) -> EffectivePathResolutionReport:
    """Automatically resolve one canonical path from DEP-206 inventory evidence.

    Physical provider roots are provenance only. Matching uses the canonical internal
    member path, so extraction layout cannot affect path identity. An order marked
    complete is accepted as complete only when it names every inventoried provider.
    """

    providers, discovered_paths, coverage, exact_order_coverage = _inventory_inputs(
        inventory, load_order
    )
    effective_order = LoadOrderEvidence(
        complete=load_order.complete and exact_order_coverage,
        source=load_order.source,
        sha256=load_order.sha256,
    )
    contribution_set: PathContributionSet = resolve_internal_path_contributions(
        query_id=query_id,
        canonical_paths=(canonical_path,),
        providers=providers,
        discovered_paths=discovered_paths,
        coverage=coverage,
        load_order=effective_order,
    )[0]
    inventory_payload = inventory.to_dict()
    resolution_payload = contribution_set.to_dict()
    resolution = resolution_payload["resolution"]
    if resolution["conclusion"] == "winner":
        gate_matches = (
            isinstance(snapshot_gate, SnapshotGateDecision)
            and snapshot_gate.authorizes(DeploymentOperation.WINNER_CLAIM)
            and snapshot_gate.snapshot_id == inventory_payload["inventory_id"]
        )
        if not gate_matches:
            resolution["conclusion"] = "inconclusive"
            resolution["winner_provider_id"] = None
            resolution["reason_codes"] = sorted(
                set(resolution["reason_codes"])
                | {"WINNER_BLOCKED_BY_FRESH_EXACT_SNAPSHOT"}
            )
            for contribution in resolution_payload["contributions"]:
                contribution["selection_state"] = "unresolved"
    return EffectivePathResolutionReport(
        {
            "schema_version": "kcd2.effective-path-resolution.v1",
            "inventory_id": inventory_payload["inventory_id"],
            "canonical_path_resolution": resolution_payload,
            "load_order_provenance": {
                "provider_ids": list(load_order.provider_ids),
                "declared_complete": load_order.complete,
                "effective_complete": effective_order.complete,
                "source": load_order.source,
                "sha256": load_order.sha256,
            },
        }
    )
