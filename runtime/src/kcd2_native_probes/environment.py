"""Bounded, non-live environment fingerprints and staleness comparison.

Callers supply every path explicitly.  The collector does not discover game,
plugin, Workshop, snapshot, or Index locations and never writes to them.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Literal


INDEX_ROLES = (
    "fast_source",
    "semantic_xgen",
    "adjacent_ui_gfx",
    "resolution_provenance",
)
PROVIDER_SOURCES = ("local", "workshop")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _checked_text(value: str | None, name: str, maximum: int) -> str | None:
    if value is not None and (not isinstance(value, str) or not value or len(value) > maximum):
        raise ValueError(f"{name} must be a non-empty string of at most {maximum} characters")
    return value


@dataclass(frozen=True)
class ProviderSpec:
    source: Literal["local", "workshop"]
    provider_id: str | None
    artifacts: tuple[Path, ...] = ()

    def __post_init__(self) -> None:
        if self.source not in PROVIDER_SOURCES:
            raise ValueError("provider source must be local or workshop")
        _checked_text(self.provider_id, "provider_id", 256)
        object.__setattr__(self, "artifacts", tuple(Path(item) for item in self.artifacts))


@dataclass(frozen=True)
class IndexInstanceSpec:
    role: Literal[
        "fast_source", "semantic_xgen", "adjacent_ui_gfx", "resolution_provenance"
    ]
    identity_path: Path | None
    version: str | None
    state: Literal["available", "missing", "unavailable", "stale"] = "available"

    def __post_init__(self) -> None:
        if self.role not in INDEX_ROLES:
            raise ValueError(f"unsupported Index role: {self.role}")
        if self.state not in {"available", "missing", "unavailable", "stale"}:
            raise ValueError(f"unsupported Index state: {self.state}")
        _checked_text(self.version, "index version", 128)
        if self.identity_path is not None:
            object.__setattr__(self, "identity_path", Path(self.identity_path))


@dataclass(frozen=True)
class EnvironmentCollectionSpec:
    game_version: str | None = None
    executable: Path | None = None
    whgame: Path | None = None
    providers: tuple[ProviderSpec, ...] = ()
    mod_order: Path | None = None
    kcse_components: tuple[tuple[str, Path], ...] = ()
    active_snapshot: Path | None = None
    active_snapshot_id: str | None = None
    active_snapshot_captured_at: str | None = None
    active_snapshot_state: Literal[
        "fresh_exact", "partial", "stale", "missing", "unavailable"
    ] = "fresh_exact"
    index_instances: tuple[IndexInstanceSpec, ...] = ()
    max_providers: int = 1024
    max_artifacts_per_provider: int = 2048
    max_components: int = 64
    max_path_chars: int = 2048
    max_artifact_bytes: int = 134_217_728

    def __post_init__(self) -> None:
        for field in ("executable", "whgame", "mod_order", "active_snapshot"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, Path(value))
        _checked_text(self.game_version, "game_version", 128)
        _checked_text(self.active_snapshot_id, "active_snapshot_id", 256)
        _checked_text(self.active_snapshot_captured_at, "active_snapshot_captured_at", 64)
        for field, ceiling in (
            ("max_providers", 4096),
            ("max_artifacts_per_provider", 8192),
            ("max_components", 256),
            ("max_path_chars", 4096),
            ("max_artifact_bytes", 1_099_511_627_776),
        ):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= ceiling:
                raise ValueError(f"{field} must be an integer from 1 through {ceiling}")
        if len(self.providers) > self.max_providers:
            raise ValueError("providers exceed max_providers")
        if len(self.kcse_components) > self.max_components:
            raise ValueError("kcse_components exceed max_components")
        if len({item.source for item in self.providers}) != len(self.providers):
            raise ValueError("provider sources must be unique")
        if len({item.role for item in self.index_instances}) != len(self.index_instances):
            raise ValueError("Index roles must be unique")
        component_roles = []
        normalized_components = []
        for role, path in self.kcse_components:
            _checked_text(role, "KCSE component role", 128)
            component_roles.append(role)
            normalized_components.append((role, Path(path)))
        if len(set(component_roles)) != len(component_roles):
            raise ValueError("KCSE component roles must be unique")
        object.__setattr__(self, "kcse_components", tuple(normalized_components))
        if self.active_snapshot_state not in {
            "fresh_exact", "partial", "stale", "missing", "unavailable"
        }:
            raise ValueError("invalid active_snapshot_state")


def _logical_path(path: Path, limit: int) -> str:
    logical = path.name
    if not logical or len(logical) > limit:
        raise ValueError("logical path is empty or exceeds max_path_chars")
    return logical


ReadBytes = Callable[[Path], bytes | None]


def _read_file_identity(
    path: Path,
    spec: EnvironmentCollectionSpec,
    read_bytes: ReadBytes | None,
    *,
    prefix_bytes: int = 0,
) -> tuple[dict[str, Any] | None, bytes]:
    if read_bytes is not None:
        data = read_bytes(path)
        if data is None:
            return None, b""
        if not isinstance(data, bytes):
            raise ValueError("read_bytes must return bytes or None")
        if len(data) > spec.max_artifact_bytes:
            raise ValueError(f"{path.name} exceeds max_artifact_bytes")
        return (
            {
                "logical_path": _logical_path(path, spec.max_path_chars),
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            },
            data[:prefix_bytes],
        )
    if not path.is_file():
        return None, b""
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > spec.max_artifact_bytes:
            raise ValueError(f"{path.name} exceeds max_artifact_bytes")
        digest = hashlib.sha256()
        counted = 0
        prefix = bytearray()
        while chunk := stream.read(1024 * 1024):
            counted += len(chunk)
            if counted > spec.max_artifact_bytes:
                raise ValueError(f"{path.name} exceeds max_artifact_bytes")
            digest.update(chunk)
            if len(prefix) < prefix_bytes:
                prefix.extend(chunk[: prefix_bytes - len(prefix)])
        after = os.fstat(stream.fileno())
    if (
        counted != before.st_size
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
    ):
        raise ValueError(f"{path.name} changed while it was hashed")
    return (
        {
            "logical_path": _logical_path(path, spec.max_path_chars),
            "sha256": digest.hexdigest(),
            "bytes": counted,
        },
        bytes(prefix),
    )


def _file_identity(
    path: Path, spec: EnvironmentCollectionSpec, read_bytes: ReadBytes | None
) -> dict[str, Any] | None:
    identity, _ = _read_file_identity(path, spec, read_bytes)
    return identity


def _pe_identity(
    path: Path | None, spec: EnvironmentCollectionSpec, read_bytes: ReadBytes | None
) -> dict[str, Any] | None:
    if path is None:
        return None
    identity, header = _read_file_identity(path, spec, read_bytes, prefix_bytes=4096)
    if identity is None:
        return None
    if len(header) < 0x40 or header[:2] != b"MZ":
        raise ValueError(f"{path.name} is not a PE file")
    pe_offset = int.from_bytes(header[0x3C:0x40], "little")
    if pe_offset + 88 > len(header) or header[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{path.name} has an invalid or out-of-bounds PE header")
    timestamp = int.from_bytes(header[pe_offset + 8 : pe_offset + 12], "little")
    optional_offset = pe_offset + 24
    magic = int.from_bytes(header[optional_offset : optional_offset + 2], "little")
    if magic not in {0x10B, 0x20B}:
        raise ValueError(f"{path.name} has an unsupported PE optional header")
    image_size = int.from_bytes(header[optional_offset + 56 : optional_offset + 60], "little")
    if image_size < 1:
        raise ValueError(f"{path.name} has an invalid PE image size")
    return {
        "name": identity["logical_path"],
        "sha256": identity["sha256"],
        "bytes": identity["bytes"],
        "pe_timestamp": f"0x{timestamp:08x}",
        "image_size": image_size,
    }


def _provider_payload(
    provider: ProviderSpec, spec: EnvironmentCollectionSpec, read_bytes: ReadBytes | None
) -> tuple[dict[str, Any], bool]:
    if len(provider.artifacts) > spec.max_artifacts_per_provider:
        raise ValueError("provider artifacts exceed max_artifacts_per_provider")
    identities = [_file_identity(path, spec, read_bytes) for path in provider.artifacts]
    artifacts = sorted(
        (item for item in identities if item is not None),
        key=lambda item: (
            item["logical_path"].casefold(),
            item["logical_path"],
            item["sha256"],
        ),
    )
    if not provider.artifacts or not artifacts:
        state = "missing"
    elif len(artifacts) != len(provider.artifacts):
        state = "partial"
    else:
        state = "present"
    inventory = hashlib.sha256(_canonical_bytes(artifacts)).hexdigest() if artifacts else None
    return (
        {
            "source": provider.source,
            "state": state,
            "provider_id": provider.provider_id,
            "inventory_sha256": inventory,
            "artifacts": artifacts,
        },
        state == "present",
    )


def _fingerprint_id(payload: dict[str, Any]) -> str:
    seed = {
        key: value
        for key, value in payload.items()
        if key not in {"fingerprint_id", "collected_at"}
    }
    return "env:sha256:" + hashlib.sha256(_canonical_bytes(seed)).hexdigest()


def collect_environment_fingerprint(
    spec: EnvironmentCollectionSpec,
    *,
    collected_at: str,
    read_bytes: ReadBytes | None = None,
) -> dict[str, Any]:
    """Collect explicit read-only identities without discovering any live path."""

    _checked_text(collected_at, "collected_at", 64)
    missing: set[str] = set()
    executable = _pe_identity(spec.executable, spec, read_bytes)
    whgame = _pe_identity(spec.whgame, spec, read_bytes)
    game_present = executable is not None and whgame is not None and spec.game_version is not None
    if not game_present:
        missing.add("game")

    providers_by_source = {item.source: item for item in spec.providers}
    providers = []
    for source in PROVIDER_SOURCES:
        provider = providers_by_source.get(source, ProviderSpec(source, None))
        payload, present = _provider_payload(provider, spec, read_bytes)
        providers.append(payload)
        if not present:
            missing.add(f"provider:{source}")

    mod_order_identity = (
        _file_identity(spec.mod_order, spec, read_bytes)
        if spec.mod_order is not None
        else None
    )
    if mod_order_identity is None:
        missing.add("mod_order")
        mod_order = {"state": "missing", "logical_path": None, "sha256": None, "bytes": None}
    else:
        mod_order = {"state": "present", **mod_order_identity}

    components = []
    if not spec.kcse_components:
        missing.add("kcse_components")
    for role, path in sorted(
        spec.kcse_components, key=lambda item: (item[0].casefold(), item[0])
    ):
        _checked_text(role, "KCSE component role", 128)
        identity = _file_identity(Path(path), spec, read_bytes)
        if identity is None:
            missing.add(f"kcse:{role}")
            components.append(
                {
                    "role": role,
                    "state": "missing",
                    "logical_path": None,
                    "sha256": None,
                    "bytes": None,
                }
            )
        else:
            components.append({"role": role, "state": "present", **identity})

    snapshot_identity = (
        _file_identity(spec.active_snapshot, spec, read_bytes)
        if spec.active_snapshot is not None
        else None
    )
    if spec.active_snapshot_state in {"missing", "unavailable"}:
        missing.add("active_snapshot")
        snapshot = {
            "state": spec.active_snapshot_state,
            "snapshot_id": None,
            "sha256": None,
            "captured_at": None,
        }
    elif snapshot_identity is None:
        missing.add("active_snapshot")
        snapshot = {"state": "missing", "snapshot_id": None, "sha256": None, "captured_at": None}
    else:
        snapshot = {
            "state": spec.active_snapshot_state,
            "snapshot_id": spec.active_snapshot_id,
            "sha256": snapshot_identity["sha256"],
            "captured_at": spec.active_snapshot_captured_at,
        }

    configured_indexes = {item.role: item for item in spec.index_instances}
    indexes = []
    for role in INDEX_ROLES:
        item = configured_indexes.get(role)
        identity = (
            _file_identity(item.identity_path, spec, read_bytes)
            if item is not None and item.identity_path is not None
            else None
        )
        if item is None or identity is None or item.state in {"missing", "unavailable"}:
            state = item.state if item is not None and item.state == "unavailable" else "missing"
            indexes.append({"role": role, "state": state, "identity_sha256": None, "version": None})
            missing.add(f"index:{role}")
        else:
            indexes.append(
                {
                    "role": role,
                    "state": item.state,
                    "identity_sha256": identity["sha256"],
                    "version": item.version,
                }
            )

    observed_identity = any(
        (
            executable is not None,
            whgame is not None,
            any(item["artifacts"] for item in providers),
            mod_order_identity is not None,
            any(item["state"] == "present" for item in components),
            snapshot["sha256"] is not None,
            any(item["identity_sha256"] is not None for item in indexes),
        )
    )
    if not observed_identity:
        collection_state = "unavailable"
    elif missing or snapshot["state"] in {"partial", "stale"} or any(
        item["state"] == "stale" for item in indexes
    ):
        collection_state = "partial"
    else:
        collection_state = "complete"

    result: dict[str, Any] = {
        "schema_version": "kcd2.environment-fingerprint.v1",
        "fingerprint_id": "",
        "collected_at": collected_at,
        "collection_state": collection_state,
        "game": {
            "state": "present" if game_present else "missing",
            "version": spec.game_version if game_present else None,
            "executable": executable,
            "whgame": whgame,
        },
        "providers": providers,
        "mod_order": mod_order,
        "kcse_components": components,
        "active_snapshot": snapshot,
        "index_instances": indexes,
        "missing_layers": sorted(missing),
        "limits": {
            "max_providers": spec.max_providers,
            "max_artifacts_per_provider": spec.max_artifacts_per_provider,
            "max_components": spec.max_components,
            "max_path_chars": spec.max_path_chars,
            "max_artifact_bytes": spec.max_artifact_bytes,
        },
    }
    result["fingerprint_id"] = _fingerprint_id(result)
    return result


def _stale_reasons(fingerprint: dict[str, Any]) -> list[str]:
    reasons = []
    if fingerprint.get("fingerprint_id") != _fingerprint_id(fingerprint):
        reasons.append("FINGERPRINT_INTEGRITY_INVALID")
    if fingerprint.get("active_snapshot", {}).get("state") == "stale":
        reasons.append("ACTIVE_SNAPSHOT_STALE")
    if any(item.get("state") == "stale" for item in fingerprint.get("index_instances", [])):
        reasons.append("INDEX_IDENTITY_STALE")
    return reasons


def compare_environment_fingerprints(
    evidence: dict[str, Any], current: dict[str, Any]
) -> dict[str, Any]:
    """Quarantine evidence whose bound inputs changed or already declare staleness."""

    layers: Iterable[str] = (
        "game",
        "providers",
        "mod_order",
        "kcse_components",
        "active_snapshot",
        "index_instances",
        "missing_layers",
        "limits",
    )
    changed = [layer for layer in layers if evidence.get(layer) != current.get(layer)]
    reasons = _stale_reasons(evidence) + [
        reason for reason in _stale_reasons(current) if reason not in _stale_reasons(evidence)
    ]
    if evidence.get("fingerprint_id") != current.get("fingerprint_id"):
        reasons.append("FINGERPRINT_MISMATCH")
    reasons = sorted(set(reasons))
    usable = not reasons
    return {
        "schema_version": "kcd2.environment-staleness-comparison.v1",
        "evidence_fingerprint_id": evidence.get("fingerprint_id"),
        "current_fingerprint_id": current.get("fingerprint_id"),
        "disposition": "current" if usable else "quarantined",
        "evidence_usable": usable,
        "changed_layers": changed,
        "reasons": reasons,
    }
