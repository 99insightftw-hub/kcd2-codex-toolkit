"""Immutable, content-addressed identity transport shared by every tool."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.cross-tool-identity.v1"
_IDENTITY_PREFIX = "identity:sha256:"
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_FIELDS = {
    "schema_version",
    "candidate_id",
    "parent_id",
    "source",
    "build_spec_sha256",
    "artifacts",
    "manifest_sha256",
    "native_components",
    "mod_order_sha256",
    "active_snapshot_id",
    "game",
    "receipt_ids",
}


class IdentityMismatchError(ValueError):
    """An asserted identity or identity-bound receipt drifted from its envelope."""


def _string(value: Any, field: str, *, nullable: bool = False, maximum: int = 2048) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        suffix = " or null" if nullable else ""
        raise ValueError(
            f"{field} must be a non-empty string of at most {maximum} characters{suffix}"
        )
    return value


def _digest(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        suffix = " or null" if nullable else ""
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest{suffix}")
    return value.lower()


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field} must be a mapping")
    if not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field} keys must be strings")
    return value


def _exact_fields(value: Mapping[str, Any], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ValueError(
            f"{field} fields do not match contract; missing={missing}, unknown={unknown}"
        )


def _sequence(value: Any, field: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds the hard limit of {maximum} items")
    return value


def _normalize(fields: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(fields, _FIELDS, "cross-tool identity")
    if fields["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")

    source = _mapping(fields["source"], "source")
    _exact_fields(source, {"commit", "tree_sha256"}, "source")
    game = _mapping(fields["game"], "game")
    _exact_fields(
        game,
        {"version", "executable_sha256", "whgame_sha256"},
        "game",
    )

    artifacts: list[dict[str, str]] = []
    artifact_keys: set[str] = set()
    for index, raw in enumerate(_sequence(fields["artifacts"], "artifacts", 8192)):
        item = _mapping(raw, f"artifacts[{index}]")
        _exact_fields(item, {"path", "sha256"}, f"artifacts[{index}]")
        path = canonical_relative_path(item["path"])
        key = canonical_path_key(path)
        if key in artifact_keys:
            raise ValueError(f"artifacts contains duplicate canonical path: {path}")
        artifact_keys.add(key)
        artifacts.append({"path": path, "sha256": _digest(item["sha256"], "artifact sha256")})
    artifacts.sort(key=lambda item: canonical_path_key(item["path"]))

    native_components: list[dict[str, str]] = []
    component_ids: set[str] = set()
    for index, raw in enumerate(
        _sequence(fields["native_components"], "native_components", 128)
    ):
        item = _mapping(raw, f"native_components[{index}]")
        _exact_fields(item, {"component_id", "sha256"}, f"native_components[{index}]")
        component_id = _string(item["component_id"], "component_id", maximum=256)
        assert component_id is not None
        if component_id in component_ids:
            raise ValueError(f"native_components contains duplicate component_id: {component_id}")
        component_ids.add(component_id)
        native_components.append(
            {"component_id": component_id, "sha256": _digest(item["sha256"], "component sha256")}
        )
    native_components.sort(key=lambda item: item["component_id"])

    receipt_ids = [
        _string(item, f"receipt_ids[{index}]", maximum=256)
        for index, item in enumerate(_sequence(fields["receipt_ids"], "receipt_ids", 256))
    ]
    if len(receipt_ids) != len(set(receipt_ids)):
        raise ValueError("receipt_ids must be unique")

    return {
        "schema_version": SCHEMA_VERSION,
        "candidate_id": _string(fields["candidate_id"], "candidate_id", nullable=True, maximum=256),
        "parent_id": _string(fields["parent_id"], "parent_id", nullable=True, maximum=256),
        "source": {
            "commit": _string(source["commit"], "source.commit", nullable=True, maximum=128),
            "tree_sha256": _digest(source["tree_sha256"], "source.tree_sha256"),
        },
        "build_spec_sha256": _digest(
            fields["build_spec_sha256"], "build_spec_sha256", nullable=True
        ),
        "artifacts": artifacts,
        "manifest_sha256": _digest(fields["manifest_sha256"], "manifest_sha256", nullable=True),
        "native_components": native_components,
        "mod_order_sha256": _digest(fields["mod_order_sha256"], "mod_order_sha256", nullable=True),
        "active_snapshot_id": _string(
            fields["active_snapshot_id"], "active_snapshot_id", nullable=True, maximum=256
        ),
        "game": {
            "version": _string(game["version"], "game.version", maximum=128),
            "executable_sha256": _digest(game["executable_sha256"], "game.executable_sha256"),
            "whgame_sha256": _digest(game["whgame_sha256"], "game.whgame_sha256"),
        },
        "receipt_ids": sorted(receipt_ids),
    }


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class CrossToolIdentity:
    """A deeply immutable canonical envelope with a self-verifying identity ID."""

    _fields: Mapping[str, Any]
    identity_id: str

    @property
    def source(self) -> Mapping[str, Any]:
        return self._fields["source"]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy({"identity_id": self.identity_id, **self._plain_fields()})

    def _plain_fields(self) -> dict[str, Any]:
        return {
            "schema_version": self._fields["schema_version"],
            "candidate_id": self._fields["candidate_id"],
            "parent_id": self._fields["parent_id"],
            "source": dict(self._fields["source"]),
            "build_spec_sha256": self._fields["build_spec_sha256"],
            "artifacts": [dict(item) for item in self._fields["artifacts"]],
            "manifest_sha256": self._fields["manifest_sha256"],
            "native_components": [dict(item) for item in self._fields["native_components"]],
            "mod_order_sha256": self._fields["mod_order_sha256"],
            "active_snapshot_id": self._fields["active_snapshot_id"],
            "game": dict(self._fields["game"]),
            "receipt_ids": list(self._fields["receipt_ids"]),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def bind_receipt(self, receipt: Mapping[str, Any]) -> dict[str, Any]:
        """Return a copy of a declared receipt with this exact envelope injected."""
        supplied = dict(_mapping(receipt, "receipt"))
        receipt_id = _string(supplied.get("receipt_id"), "receipt.receipt_id", maximum=256)
        if receipt_id not in self._fields["receipt_ids"]:
            raise IdentityMismatchError(f"receipt_id is not declared by identity: {receipt_id}")
        if "identity_id" in supplied and supplied["identity_id"] != self.identity_id:
            raise IdentityMismatchError("receipt identity_id does not match the bound identity")
        if "cross_tool_identity" in supplied:
            asserted = bind_cross_tool_identity(supplied["cross_tool_identity"])
            if asserted != self:
                raise IdentityMismatchError("receipt cross_tool_identity does not match")
        supplied["identity_id"] = self.identity_id
        supplied["cross_tool_identity"] = self.to_dict()
        return copy.deepcopy(supplied)


def bind_cross_tool_identity(value: Mapping[str, Any] | CrossToolIdentity) -> CrossToolIdentity:
    """Canonicalize an identity once, or verify a transported envelope without transcription."""
    if isinstance(value, CrossToolIdentity):
        return value
    supplied = dict(_mapping(value, "cross-tool identity"))
    asserted_id = supplied.pop("identity_id", None)
    normalized = _normalize(supplied)
    identity_id = _IDENTITY_PREFIX + sha256_json(normalized)
    if asserted_id is not None and asserted_id != identity_id:
        raise IdentityMismatchError(
            f"identity_id mismatch: asserted {asserted_id!r}, computed {identity_id!r}"
        )
    return CrossToolIdentity(_fields=_freeze(normalized), identity_id=identity_id)


def _identity_from_transport(value: Mapping[str, Any] | CrossToolIdentity) -> CrossToolIdentity:
    if isinstance(value, CrossToolIdentity):
        return value
    mapping = _mapping(value, "identity transport")
    if "cross_tool_identity" in mapping:
        identity = bind_cross_tool_identity(mapping["cross_tool_identity"])
        asserted_id = mapping.get("identity_id")
        if asserted_id is not None and asserted_id != identity.identity_id:
            raise IdentityMismatchError("transport identity_id differs from cross_tool_identity")
        return identity
    return bind_cross_tool_identity(mapping)


def assert_same_identity(
    first: Mapping[str, Any] | CrossToolIdentity,
    *others: Mapping[str, Any] | CrossToolIdentity,
) -> CrossToolIdentity:
    """Fail closed unless every tool/receipt transports the byte-identical identity."""
    expected = _identity_from_transport(first)
    for position, value in enumerate(others, start=2):
        actual = _identity_from_transport(value)
        if actual.canonical_bytes() != expected.canonical_bytes():
            raise IdentityMismatchError(f"identity transport {position} does not match transport 1")
    return expected
