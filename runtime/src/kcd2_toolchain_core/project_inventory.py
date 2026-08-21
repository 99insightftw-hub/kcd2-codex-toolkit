"""Explicit-scope project/provider inventory with coverage-gated conclusions."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal

from .hashing import sha256_json
from .portfolio_registry import PortfolioRegistry, canonicalize_portfolio_registry

if TYPE_CHECKING:
    from kcd2_index_adapter.coverage import CoverageValidity


ProviderKind = Literal[
    "LOCAL", "WORKSHOP", "SOURCE_PROJECT", "REFERENCE", "EXTERNAL_COMPONENT"
]
ObservedProviderState = Literal["present", "loaded", "inactive", "malformed", "unknown"]

_PROVIDER_KINDS = frozenset(
    {"LOCAL", "WORKSHOP", "SOURCE_PROJECT", "REFERENCE", "EXTERNAL_COMPONENT"}
)
_OBSERVED_STATES = frozenset({"present", "loaded", "inactive", "malformed", "unknown"})
_STATE_ORDER = {
    "configured": 0,
    "present": 1,
    "loaded": 2,
    "inactive": 3,
    "malformed": 4,
    "duplicate": 5,
    "unknown": 6,
}
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_PROJECT_ID = re.compile(r"^project:sha256:[0-9a-f]{64}$")
_MAX_TEXT = 2048
_MAX_REQUESTED_PROJECTS = 256
_MAX_RECEIPTS = 4096


class ProjectInventoryError(ValueError):
    """Inventory inputs cannot support a bounded, exact reconciliation."""


def _text(value: object, field: str, maximum: int = _MAX_TEXT) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ProjectInventoryError(
            f"{field} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ProjectInventoryError(f"{field} must be an offset-aware datetime")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _locator(value: object) -> str:
    result = _text(value, "locator").replace("\\", "/")
    if ".." in result.split("/"):
        raise ProjectInventoryError("locator must not contain parent traversal")
    return result


def _states(values: object) -> tuple[ObservedProviderState, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ProjectInventoryError("observed_states must be an array")
    if not 1 <= len(values) <= len(_OBSERVED_STATES):
        raise ProjectInventoryError("observed_states must contain between 1 and 5 states")
    if any(value not in _OBSERVED_STATES for value in values):
        raise ProjectInventoryError("observed_states contains an unsupported state")
    if len(set(values)) != len(values):
        raise ProjectInventoryError("observed_states must be unique")
    selected = set(values)
    if "unknown" in selected and len(selected) != 1:
        raise ProjectInventoryError("unknown cannot be combined with another observed state")
    if "loaded" in selected and "present" not in selected:
        raise ProjectInventoryError("loaded requires present evidence")
    if "loaded" in selected and "inactive" in selected:
        raise ProjectInventoryError("loaded and inactive are mutually exclusive")
    return tuple(sorted(selected, key=_STATE_ORDER.__getitem__))  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class ProviderDiscoveryReceipt:
    """One bounded observation from an explicitly approved provider source."""

    receipt_id: str
    project_id: str
    provider_id: str
    provider_kind: ProviderKind
    locator: str
    observed_states: tuple[ObservedProviderState, ...]
    observed_at: datetime
    sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipt_id", _text(self.receipt_id, "receipt_id", 1024))
        project_id = _text(self.project_id, "project_id", 1024)
        if _PROJECT_ID.fullmatch(project_id) is None:
            raise ProjectInventoryError("project_id must be a content-addressed project ID")
        object.__setattr__(self, "project_id", project_id)
        object.__setattr__(self, "provider_id", _text(self.provider_id, "provider_id", 1024))
        if self.provider_kind not in _PROVIDER_KINDS:
            raise ProjectInventoryError("provider_kind is not supported")
        object.__setattr__(self, "locator", _locator(self.locator))
        object.__setattr__(self, "observed_states", _states(self.observed_states))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        if self.sha256 is not None:
            if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
                raise ProjectInventoryError("sha256 must be a 64-character digest or null")
            object.__setattr__(self, "sha256", self.sha256.lower())


@dataclass(frozen=True, slots=True)
class ProjectInventory:
    """Deterministic inventory result; callers receive a defensive JSON copy."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(json.loads(self.to_json()))

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


def _ordered_states(values: set[str]) -> list[str]:
    return sorted(values, key=_STATE_ORDER.__getitem__)


def inventory_projects(
    *,
    registry: PortfolioRegistry | Mapping[str, Any],
    requested_project_ids: Sequence[str],
    receipts: Sequence[ProviderDiscoveryReceipt],
    coverage: CoverageValidity,
    evaluated_at: datetime,
    max_requested_projects: int = _MAX_REQUESTED_PROJECTS,
    max_receipts: int = _MAX_RECEIPTS,
) -> ProjectInventory:
    """Reconcile only explicitly requested projects; never dump a global snapshot."""

    canonical = canonicalize_portfolio_registry(registry)
    evaluated = _timestamp(evaluated_at, "evaluated_at")
    if not isinstance(max_requested_projects, int) or isinstance(max_requested_projects, bool):
        raise ProjectInventoryError("max_requested_projects must be an integer")
    if not 1 <= max_requested_projects <= _MAX_REQUESTED_PROJECTS:
        raise ProjectInventoryError("max_requested_projects exceeds its hard bound")
    if not isinstance(max_receipts, int) or isinstance(max_receipts, bool):
        raise ProjectInventoryError("max_receipts must be an integer")
    if not 1 <= max_receipts <= _MAX_RECEIPTS:
        raise ProjectInventoryError("max_receipts exceeds its hard bound")
    if isinstance(requested_project_ids, (str, bytes)) or not isinstance(
        requested_project_ids, Sequence
    ):
        raise ProjectInventoryError("requested_project_ids must be an array")
    if not 1 <= len(requested_project_ids) <= max_requested_projects:
        raise ProjectInventoryError(
            "requested_project_ids must contain an explicit bounded project scope"
        )
    requested = tuple(
        _text(value, "requested_project_ids[]", 1024)
        for value in requested_project_ids
    )
    if any(_PROJECT_ID.fullmatch(value) is None for value in requested):
        raise ProjectInventoryError("requested_project_ids must contain content-addressed IDs")
    if len(set(requested)) != len(requested):
        raise ProjectInventoryError("requested_project_ids must be unique")
    requested = tuple(sorted(requested))

    registry_payload = canonical.to_dict()
    projects_by_id = {item["project_id"]: item for item in registry_payload["projects"]}
    unknown_projects = set(requested) - set(projects_by_id)
    if unknown_projects:
        raise ProjectInventoryError(
            f"requested_project_ids are not present in the registry: {sorted(unknown_projects)}"
        )
    if isinstance(receipts, (str, bytes)) or not isinstance(receipts, Sequence):
        raise ProjectInventoryError("receipts must be an array")
    if len(receipts) > max_receipts:
        raise ProjectInventoryError("receipts exceeds the configured hard bound")
    if any(not isinstance(item, ProviderDiscoveryReceipt) for item in receipts):
        raise ProjectInventoryError("receipts must contain ProviderDiscoveryReceipt values")
    receipt_ids = [item.receipt_id.casefold() for item in receipts]
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ProjectInventoryError("receipt_id values must be case-insensitively unique")
    if any(item.project_id not in requested for item in receipts):
        raise ProjectInventoryError("a provider receipt is outside requested project scope")
    if not hasattr(coverage, "to_dict") or not callable(coverage.to_dict):
        raise ProjectInventoryError("coverage must be a coverage-validity result")
    coverage_payload = coverage.to_dict()
    if not isinstance(coverage_payload, Mapping):
        raise ProjectInventoryError("coverage payload must be a mapping")
    if coverage_payload["operation"] != "inventory_projects":
        raise ProjectInventoryError("coverage operation must be inventory_projects")

    declared_kinds = {
        provider["kind"]
        for project_id in requested
        for provider in projects_by_id[project_id]["providers"]
    }
    observed_kinds = {item.provider_kind for item in receipts}
    covered_kinds = set(coverage_payload["requested_scope"]["provider_kinds"])
    if not (declared_kinds | observed_kinds).issubset(covered_kinds):
        raise ProjectInventoryError("coverage scope omits a requested provider kind")

    receipts_by_project: dict[str, list[ProviderDiscoveryReceipt]] = {
        project_id: [] for project_id in requested
    }
    for receipt in receipts:
        receipts_by_project[receipt.project_id].append(receipt)

    output_projects: list[dict[str, Any]] = []
    has_unknown = False
    has_malformed = False
    missing_receipt = False
    for project_id in requested:
        project = projects_by_id[project_id]
        declared = {item["provider_id"]: item for item in project["providers"]}
        observed = receipts_by_project[project_id]
        locator_members: dict[tuple[str, str], set[tuple[str, str]]] = {}
        for provider_id, declaration in declared.items():
            key = (declaration["kind"], declaration["locator"].casefold())
            locator_members.setdefault(key, set()).add(("provider", provider_id))
        for receipt in observed:
            key = (receipt.provider_kind, receipt.locator.casefold())
            member = (
                ("provider", receipt.provider_id)
                if receipt.provider_id in declared
                else ("receipt", receipt.receipt_id)
            )
            locator_members.setdefault(key, set()).add(member)

        records: list[dict[str, Any]] = []
        observed_provider_ids: set[str] = set()
        for receipt in observed:
            observation_states = set(receipt.observed_states)
            declaration = declared.get(receipt.provider_id)
            states = set(observation_states)
            if declaration is not None:
                states.add("configured")
                if declaration["kind"] != receipt.provider_kind or (
                    declaration["locator"].replace("\\", "/").casefold()
                    != receipt.locator.casefold()
                ):
                    states.add("malformed")
            if len(locator_members[(receipt.provider_kind, receipt.locator.casefold())]) > 1:
                states.add("duplicate")
            observed_provider_ids.add(receipt.provider_id)
            has_unknown = has_unknown or "unknown" in states
            has_malformed = has_malformed or "malformed" in states
            records.append(
                {
                    "receipt_id": receipt.receipt_id,
                    "provider_id": receipt.provider_id,
                    "kind": receipt.provider_kind,
                    "locator": receipt.locator,
                    "states": _ordered_states(states),
                    "sha256": receipt.sha256,
                    "observed_at": _iso(receipt.observed_at),
                }
            )
        for provider_id, declaration in declared.items():
            if provider_id in observed_provider_ids:
                continue
            missing_receipt = True
            has_unknown = True
            states = {"configured", "unknown"}
            key = (declaration["kind"], declaration["locator"].casefold())
            if len(locator_members[key]) > 1:
                states.add("duplicate")
            records.append(
                {
                    "receipt_id": None,
                    "provider_id": provider_id,
                    "kind": declaration["kind"],
                    "locator": declaration["locator"],
                    "states": _ordered_states(states),
                    "sha256": declaration["sha256"],
                    "observed_at": None,
                }
            )
        records.sort(
            key=lambda item: (
                item["receipt_id"] is None,
                (item["receipt_id"] or "").casefold(),
                item["provider_id"],
            )
        )
        project_states = {state for record in records for state in record["states"]}
        output_projects.append(
            {
                "project_id": project_id,
                "aliases": list(project["aliases"]),
                "states": _ordered_states(project_states),
                "providers": records,
            }
        )

    permissions = coverage_payload["claim_permissions"]
    absence_allowed = permissions["absence_claim_allowed"]
    reasons = set(coverage_payload["reason_codes"])
    if "WORKSHOP" in covered_kinds and not absence_allowed:
        reasons.add("WORKSHOP_COVERAGE_INCOMPLETE")
    if missing_receipt:
        reasons.add("PROVIDER_RECEIPT_MISSING")
    if has_malformed:
        reasons.add("PROVIDER_RECEIPT_MALFORMED")
    complete = coverage_payload["overall_status"] in {
        "COMPLETE",
        "COMPLETE_FOR_REQUESTED_SCOPE",
    }
    payload: dict[str, Any] = {
        "schema_version": "kcd2.project-provider-inventory.v1",
        "registry_id": canonical.registry_id,
        "evaluated_at": _iso(evaluated),
        "requested_project_ids": list(requested),
        "status": "complete"
        if complete and not has_unknown and not has_malformed
        else "capture_inconclusive",
        "projects": output_projects,
        "coverage": {
            "coverage_id": coverage_payload["coverage_id"],
            "overall_status": coverage_payload["overall_status"],
            "presence_claim_allowed": permissions["presence_claim_allowed"],
            "absence_claim_allowed": absence_allowed,
            "reason_codes": sorted(reasons),
        },
    }
    identity_material = copy.deepcopy(payload)
    payload["inventory_id"] = f"project-inventory:sha256:{sha256_json(identity_material)}"
    return ProjectInventory(payload)
