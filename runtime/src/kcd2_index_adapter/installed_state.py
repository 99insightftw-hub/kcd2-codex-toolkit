"""Reconcile independent configured, provider, index, and latest-load evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal


ConfigurationState = Literal["enabled", "disabled", "not_listed", "unknown"]
ProviderKind = Literal["local", "workshop", "vortex", "disabled", "unknown"]
ProviderObservationState = Literal[
    "present", "missing", "disabled", "unavailable", "unknown"
]
ProviderStatus = Literal[
    "available_local",
    "available_external",
    "available_multiple",
    "disabled_only",
    "not_observed",
    "inconclusive",
]
PakState = Literal["confirmed", "not_observed", "incomplete"]
LuaState = Literal["loaded", "failed", "not_observed", "incomplete"]
LoadedState = Literal[
    "pak_opened_lua_loaded",
    "pak_opened_lua_failed",
    "pak_opened_lua_not_observed",
    "pak_not_opened",
    "capture_inconclusive",
]

_CONFIGURATION_STATES = frozenset({"enabled", "disabled", "not_listed", "unknown"})
_PROVIDER_KINDS = frozenset({"local", "workshop", "vortex", "disabled", "unknown"})
_PROVIDER_STATES = frozenset(
    {"present", "missing", "disabled", "unavailable", "unknown"}
)
_PAK_STATES = frozenset({"confirmed", "not_observed", "incomplete"})
_LUA_STATES = frozenset({"loaded", "failed", "not_observed", "incomplete"})
_MAX_TEXT = 1024
_MAX_PROVIDERS = 5
_MAX_PATHS = 64


def _text(value: object, name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise ValueError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _path(value: object, name: str) -> str:
    checked = _text(value, name)
    assert checked is not None
    normalized = checked.replace("\\", "/")
    if normalized.startswith("/") or any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise ValueError(f"{name} must be a canonical relative path")
    return normalized


@dataclass(frozen=True, slots=True)
class ConfigurationEvidence:
    """The exact mod_order dimension; it says nothing about provider validity."""

    state: ConfigurationState
    mod_order_path: str
    entry_count: int

    def __post_init__(self) -> None:
        if self.state not in _CONFIGURATION_STATES:
            raise ValueError("configuration state is not supported")
        if self.mod_order_path != "mods/mod_order.txt":
            raise ValueError("mod_order_path must be exactly mods/mod_order.txt")
        if not isinstance(self.entry_count, int) or not 0 <= self.entry_count <= 4096:
            raise ValueError("entry_count must be an integer between 0 and 4096")
        if self.state == "enabled" and self.entry_count < 1:
            raise ValueError("enabled configuration requires at least one entry")
        if self.state in {"not_listed", "unknown"} and self.entry_count != 0:
            raise ValueError(f"{self.state} configuration requires entry_count=0")

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_count": self.entry_count,
            "mod_order_path": self.mod_order_path,
            "state": self.state,
        }


@dataclass(frozen=True, slots=True)
class ProviderObservation:
    """One provider taxonomy observation, independent of mod_order and Index state."""

    kind: ProviderKind
    state: ProviderObservationState
    paths: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in _PROVIDER_KINDS:
            raise ValueError("provider kind is not supported")
        if self.state not in _PROVIDER_STATES:
            raise ValueError("provider observation state is not supported")
        if len(self.paths) > _MAX_PATHS:
            raise ValueError(f"provider paths exceed the {_MAX_PATHS}-path hard bound")
        checked = tuple(_path(value, "provider path") for value in self.paths)
        if len({value.casefold() for value in checked}) != len(checked):
            raise ValueError("provider paths must be case-insensitively unique")
        if self.state == "present" and not checked:
            raise ValueError("present provider observation requires at least one path")
        if self.state != "present" and checked:
            raise ValueError("only a present provider observation may contain paths")
        if self.kind == "disabled" and self.state != "disabled":
            raise ValueError("disabled provider kind requires disabled state")
        if self.state == "disabled" and self.kind != "disabled":
            raise ValueError("disabled state requires disabled provider kind")
        object.__setattr__(
            self,
            "paths",
            tuple(sorted(checked, key=lambda value: (value.casefold(), value))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "paths": list(self.paths), "state": self.state}


@dataclass(frozen=True, slots=True)
class SemanticIndexEvidence:
    """Broad semantic inclusion and exact snapshot freshness remain separate flags."""

    indexed: bool
    snapshot_id: str | None
    snapshot_current: bool

    def __post_init__(self) -> None:
        if not isinstance(self.indexed, bool) or not isinstance(self.snapshot_current, bool):
            raise TypeError("indexed and snapshot_current must be booleans")
        _text(self.snapshot_id, "snapshot_id", nullable=True)
        if self.snapshot_current and self.snapshot_id is None:
            raise ValueError("a current snapshot requires snapshot_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "indexed": self.indexed,
            "snapshot_current": self.snapshot_current,
            "snapshot_id": self.snapshot_id,
        }


@dataclass(frozen=True, slots=True)
class LatestLoadEvidence:
    """Correlated latest-boot PAK/Lua evidence with fail-closed resolution."""

    pak_state: PakState
    lua_state: LuaState
    same_complete_boot: bool
    boot_receipt_id: str | None

    def __post_init__(self) -> None:
        if self.pak_state not in _PAK_STATES:
            raise ValueError("pak_state is not supported")
        if self.lua_state not in _LUA_STATES:
            raise ValueError("lua_state is not supported")
        if not isinstance(self.same_complete_boot, bool):
            raise TypeError("same_complete_boot must be a boolean")
        _text(self.boot_receipt_id, "boot_receipt_id", nullable=True)
        if self.same_complete_boot and self.boot_receipt_id is None:
            raise ValueError("correlated latest-load evidence requires boot_receipt_id")

    @classmethod
    def from_boot_receipt(
        cls,
        receipt: Mapping[str, object],
        *,
        lua_state: LuaState,
        lua_observed_in_same_boot: bool,
    ) -> "LatestLoadEvidence":
        """Map a DEP-211 receipt while retaining separately supplied Lua evidence."""

        if not isinstance(receipt, Mapping):
            raise TypeError("receipt must be a mapping")
        if receipt.get("schema_version") != "kcd2.boot-receipt.v1":
            raise ValueError("receipt must use kcd2.boot-receipt.v1")
        scope = receipt.get("scope")
        path_open = receipt.get("path_open_evidence")
        if not isinstance(scope, Mapping) or not isinstance(path_open, Mapping):
            raise ValueError("boot receipt lacks scope or path_open_evidence")
        complete = scope.get("complete_boot")
        latest = scope.get("latest_complete_boot")
        conclusion = path_open.get("conclusion")
        if not isinstance(complete, bool) or not isinstance(latest, bool):
            raise ValueError("boot receipt scope flags must be booleans")
        if conclusion not in {"confirmed", "not_observed", "incomplete"}:
            raise ValueError("boot receipt path-open conclusion is unsupported")
        if not isinstance(lua_observed_in_same_boot, bool):
            raise TypeError("lua_observed_in_same_boot must be a boolean")
        receipt_id = _text(receipt.get("receipt_id"), "boot receipt_id")
        if not complete or not latest or conclusion == "incomplete":
            pak_state: PakState = "incomplete"
        elif conclusion == "confirmed":
            pak_state = "confirmed"
        else:
            pak_state = "not_observed"
        return cls(
            pak_state=pak_state,
            lua_state=lua_state,
            same_complete_boot=complete and latest and lua_observed_in_same_boot,
            boot_receipt_id=receipt_id,
        )

    def resolve_state(self) -> LoadedState:
        if (
            not self.same_complete_boot
            or self.pak_state == "incomplete"
            or self.lua_state == "incomplete"
        ):
            return "capture_inconclusive"
        if self.pak_state == "not_observed":
            return (
                "pak_not_opened"
                if self.lua_state == "not_observed"
                else "capture_inconclusive"
            )
        return {
            "loaded": "pak_opened_lua_loaded",
            "failed": "pak_opened_lua_failed",
            "not_observed": "pak_opened_lua_not_observed",
        }[self.lua_state]  # type: ignore[return-value]

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_receipt_id": self.boot_receipt_id,
            "lua_state": self.lua_state,
            "pak_state": self.pak_state,
            "same_complete_boot": self.same_complete_boot,
            "state": self.resolve_state(),
        }


@dataclass(frozen=True, slots=True)
class InstalledStateReconciliation:
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.to_json())

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


def _provider_status(providers: Sequence[ProviderObservation]) -> ProviderStatus:
    present = {provider.kind for provider in providers if provider.state == "present"}
    if "local" in present and present & {"workshop", "vortex"}:
        return "available_multiple"
    if "local" in present:
        return "available_local"
    if present & {"workshop", "vortex"}:
        return "available_external"
    if any(provider.state in {"unknown", "unavailable"} for provider in providers):
        return "inconclusive"
    if any(provider.state == "disabled" for provider in providers):
        return "disabled_only"
    return "not_observed"


def reconcile_installed_state(
    *,
    reconciliation_id: str,
    mod_id: str,
    configuration: ConfigurationEvidence,
    providers: Sequence[ProviderObservation],
    semantic_index: SemanticIndexEvidence,
    latest_load: LatestLoadEvidence,
) -> InstalledStateReconciliation:
    """Build one deterministic record without collapsing independent dimensions."""

    checked_id = _text(reconciliation_id, "reconciliation_id")
    checked_mod = _text(mod_id, "mod_id")
    if not isinstance(configuration, ConfigurationEvidence):
        raise TypeError("configuration must be ConfigurationEvidence")
    if not isinstance(semantic_index, SemanticIndexEvidence):
        raise TypeError("semantic_index must be SemanticIndexEvidence")
    if not isinstance(latest_load, LatestLoadEvidence):
        raise TypeError("latest_load must be LatestLoadEvidence")
    if not isinstance(providers, Sequence) or isinstance(providers, (str, bytes)):
        raise TypeError("providers must be a sequence")
    if not 1 <= len(providers) <= _MAX_PROVIDERS:
        raise ValueError(f"providers must contain between 1 and {_MAX_PROVIDERS} observations")
    if any(not isinstance(provider, ProviderObservation) for provider in providers):
        raise TypeError("providers must contain ProviderObservation values")
    kinds = [provider.kind for provider in providers]
    if len(kinds) != len(set(kinds)):
        raise ValueError("provider kinds must be unique")
    ordered = tuple(sorted(providers, key=lambda provider: provider.kind))
    return InstalledStateReconciliation(
        {
            "schema_version": "kcd2.installed-state-reconciliation.v1",
            "reconciliation_id": checked_id,
            "mod_id": checked_mod,
            "configuration": configuration.to_dict(),
            "providers": [provider.to_dict() for provider in ordered],
            "provider_status": _provider_status(ordered),
            "semantic_index": semantic_index.to_dict(),
            "latest_load": latest_load.to_dict(),
        }
    )
