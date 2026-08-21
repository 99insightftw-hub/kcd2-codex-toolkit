"""Bounded static visual/material/effect dependency and override resolution."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .hashing import sha256_json
from .paths import canonical_path_key, canonical_relative_path


_MAX_TEXT = 2048
_MAX_ASSETS = 16384
_MAX_PROVIDERS = 4096
_MAX_REFERENCES = 32768
_ROOT_FIELDS = {"snapshot_id", "target_path", "coverage", "providers", "assets"}
_COVERAGE_FIELDS = {"provider_order_complete", "path_coverage_complete"}
_PROVIDER_FIELDS = {"provider_id", "priority", "state"}
_ASSET_FIELDS = {
    "asset_id",
    "kind",
    "path",
    "provider_id",
    "representation",
    "content_sha256",
    "header",
    "references",
}
_HEADER_FIELDS = {"format", "magic", "version", "payload_bytes"}
_REFERENCE_FIELDS = {"relationship", "target_path", "required", "fallback_path"}
_KINDS = {
    "model",
    "material",
    "texture",
    "dds_stream",
    "particle",
    "effect",
    "archetype",
    "light",
    "emitter",
    "phase",
    "lod",
}
_RELATIONSHIPS = {
    "uses_material",
    "uses_texture",
    "uses_particle",
    "uses_effect",
    "uses_archetype",
    "uses_light",
    "uses_emitter",
    "inherits",
    "phase_link",
    "lod_link",
    "falls_back_to",
}
_FORMATS = {"dds", "cgf", "cga", "chr", "skin", "compiled_effect"}
_STATES = {"loaded", "inactive", "malformed", "unknown"}
_SHA256 = re.compile(r"[0-9a-f]{64}")


class AssetDependencyError(ValueError):
    """Asset declarations violate the exact, bounded provider contract."""


def _mapping(value: object, fields: set[str], name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AssetDependencyError(f"{name} fields do not match the contract")
    return value


def _array(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise AssetDependencyError(f"{name} must be an array")
    if len(value) > maximum:
        raise AssetDependencyError(f"{name} exceeds its {maximum}-item hard bound")
    return value


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise AssetDependencyError(
            f"{field} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _path(value: object, field: str) -> str:
    try:
        return canonical_relative_path(_text(value, field))
    except (TypeError, ValueError) as exc:
        raise AssetDependencyError(f"{field} must be a safe relative path") from exc


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise AssetDependencyError(f"{field} must be boolean")
    return value


def validate_asset_header_mapping(value: object) -> dict[str, Any]:
    """Validate a bounded binary asset header without interpreting its payload."""

    header = _mapping(value, _HEADER_FIELDS, "header")
    asset_format = _text(header["format"], "header.format")
    if asset_format not in _FORMATS:
        raise AssetDependencyError(f"unsupported asset header format: {asset_format}")
    magic = _text(header["magic"], "header.magic")
    if asset_format == "dds" and magic != "DDS ":
        raise AssetDependencyError("DDS header magic must be exactly 'DDS '")
    if not isinstance(header["version"], int) or isinstance(header["version"], bool):
        raise AssetDependencyError("header.version must be an integer")
    if not 0 <= header["version"] <= 65535:
        raise AssetDependencyError("header.version is outside the supported validation bound")
    if not isinstance(header["payload_bytes"], int) or isinstance(
        header["payload_bytes"], bool
    ):
        raise AssetDependencyError("header.payload_bytes must be an integer")
    if not 1 <= header["payload_bytes"] <= 2**40:
        raise AssetDependencyError("header.payload_bytes is outside the hard bound")
    return {
        "format": asset_format,
        "magic": magic,
        "version": header["version"],
        "payload_bytes": header["payload_bytes"],
    }


def validate_asset_references_mapping(value: object) -> list[dict[str, Any]]:
    """Validate exact reference records while preserving declared path casing."""

    rows = _array(value, "references", _MAX_REFERENCES)
    checked: list[dict[str, Any]] = []
    for index, item in enumerate(rows):
        row = _mapping(item, _REFERENCE_FIELDS, f"reference[{index}]")
        relationship = _text(row["relationship"], f"reference[{index}].relationship")
        if relationship not in _RELATIONSHIPS:
            raise AssetDependencyError(f"unsupported asset relationship: {relationship}")
        fallback = row["fallback_path"]
        checked.append(
            {
                "relationship": relationship,
                "target_path": _path(row["target_path"], f"reference[{index}].target_path"),
                "required": _boolean(row["required"], f"reference[{index}].required"),
                "fallback_path": (
                    None
                    if fallback is None
                    else _path(fallback, f"reference[{index}].fallback_path")
                ),
            }
        )
    return checked


@dataclass(frozen=True, slots=True)
class AssetDependencyGraph:
    """Immutable schema-ready static asset graph and target-path resolution."""

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


def _validate_providers(value: object) -> list[dict[str, Any]]:
    providers: list[dict[str, Any]] = []
    rows = _array(value, "providers", _MAX_PROVIDERS)
    if not rows:
        raise AssetDependencyError("providers must contain at least one provider")
    for index, item in enumerate(rows):
        row = _mapping(item, _PROVIDER_FIELDS, f"provider[{index}]")
        state = _text(row["state"], f"provider[{index}].state")
        if state not in _STATES:
            raise AssetDependencyError(f"unsupported provider state: {state}")
        priority = row["priority"]
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise AssetDependencyError(f"provider[{index}].priority must be an integer")
        providers.append(
            {
                "provider_id": _text(row["provider_id"], f"provider[{index}].provider_id"),
                "priority": priority,
                "state": state,
            }
        )
    ids = [item["provider_id"].casefold() for item in providers]
    if len(ids) != len(set(ids)):
        raise AssetDependencyError("provider_id values must be case-insensitively unique")
    return providers


def _validate_assets(
    value: object, provider_ids: set[str]
) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    ids: set[str] = set()
    rows = _array(value, "assets", _MAX_ASSETS)
    if not rows:
        raise AssetDependencyError("assets must contain at least one asset")
    for index, item in enumerate(rows):
        row = _mapping(item, _ASSET_FIELDS, f"asset[{index}]")
        asset_id = _text(row["asset_id"], f"asset[{index}].asset_id")
        if asset_id.casefold() in ids:
            raise AssetDependencyError("asset_id values must be case-insensitively unique")
        ids.add(asset_id.casefold())
        kind = _text(row["kind"], f"asset[{index}].kind")
        if kind not in _KINDS:
            raise AssetDependencyError(f"unsupported asset kind: {kind}")
        provider_id = _text(row["provider_id"], f"asset[{index}].provider_id")
        if provider_id.casefold() not in provider_ids:
            raise AssetDependencyError(f"asset {asset_id} names an unknown provider")
        representation = _text(row["representation"], f"asset[{index}].representation")
        if representation not in {"binary_payload", "reference"}:
            raise AssetDependencyError(f"unsupported asset representation: {representation}")
        content_sha256 = row["content_sha256"]
        header = row["header"]
        if representation == "binary_payload":
            if not isinstance(content_sha256, str) or _SHA256.fullmatch(content_sha256) is None:
                raise AssetDependencyError(f"binary asset {asset_id} requires a lowercase SHA-256")
            checked_header = validate_asset_header_mapping(header)
            if kind == "dds_stream" and checked_header["format"] != "dds":
                raise AssetDependencyError(f"DDS stream {asset_id} requires a DDS header")
            if kind in {"model", "lod"} and checked_header["format"] not in {
                "cgf",
                "cga",
                "chr",
                "skin",
            }:
                raise AssetDependencyError(
                    f"model or LOD asset {asset_id} has an incompatible binary header"
                )
        else:
            if content_sha256 is not None or header is not None:
                raise AssetDependencyError(
                    f"reference asset {asset_id} cannot claim binary content or a header"
                )
            checked_header = None
        assets.append(
            {
                "asset_id": asset_id,
                "kind": kind,
                "path": _path(row["path"], f"asset[{index}].path"),
                "provider_id": provider_id,
                "representation": representation,
                "content_sha256": content_sha256,
                "header": checked_header,
                "references": validate_asset_references_mapping(row["references"]),
            }
        )
    return assets


def resolve_asset_dependencies_mapping(value: Mapping[str, object]) -> AssetDependencyGraph:
    """Build a deterministic static dependency graph and resolve one exact path."""

    root = _mapping(value, _ROOT_FIELDS, "asset dependency input")
    snapshot_id = _text(root["snapshot_id"], "snapshot_id")
    requested_target = _path(root["target_path"], "target_path")
    coverage = _mapping(root["coverage"], _COVERAGE_FIELDS, "coverage")
    checked_coverage = {
        field: _boolean(coverage[field], f"coverage.{field}")
        for field in sorted(_COVERAGE_FIELDS)
    }
    providers = _validate_providers(root["providers"])
    provider_by_id = {item["provider_id"].casefold(): item for item in providers}
    assets = _validate_assets(root["assets"], set(provider_by_id))

    loaded_assets = [
        asset
        for asset in assets
        if provider_by_id[asset["provider_id"].casefold()]["state"] == "loaded"
    ]
    by_path: dict[str, list[dict[str, Any]]] = {}
    for asset in loaded_assets:
        by_path.setdefault(canonical_path_key(asset["path"]), []).append(asset)

    selected: dict[str, dict[str, Any]] = {}
    ambiguous_paths: set[str] = set()
    for key, candidates in by_path.items():
        highest = max(
            provider_by_id[item["provider_id"].casefold()]["priority"] for item in candidates
        )
        winners = [
            item
            for item in candidates
            if provider_by_id[item["provider_id"].casefold()]["priority"] == highest
        ]
        if len(winners) == 1:
            selected[key] = winners[0]
        else:
            ambiguous_paths.add(key)

    nodes = [
        {
            "asset_id": item["asset_id"],
            "kind": item["kind"],
            "path": item["path"],
            "provider_id": item["provider_id"],
            "representation": item["representation"],
            "content_sha256": item["content_sha256"],
            "header": item["header"],
        }
        for _, item in sorted(selected.items())
    ]
    edges: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    for key in sorted(ambiguous_paths):
        diagnostics.append(
            {
                "code": "AMBIGUOUS_WINNER",
                "source_path": None,
                "target_path": by_path[key][0]["path"],
                "fallback_path": None,
                "message": "multiple loaded providers share the highest priority",
            }
        )
    for source_key, source in sorted(selected.items()):
        for reference in source["references"]:
            target_key = canonical_path_key(reference["target_path"])
            target = selected.get(target_key)
            fallback = None
            if reference["fallback_path"] is not None:
                fallback = selected.get(canonical_path_key(reference["fallback_path"]))
            resolved = target or fallback
            edges.append(
                {
                    "from_path": source["path"],
                    "relationship": reference["relationship"],
                    "declared_target_path": reference["target_path"],
                    "to_path": None if resolved is None else resolved["path"],
                    "required": reference["required"],
                    "fallback_path": reference["fallback_path"],
                    "fallback_used": target is None and fallback is not None,
                }
            )
            if target is None and reference["required"]:
                diagnostics.append(
                    {
                        "code": "MISSING_REFERENCE",
                        "source_path": source["path"],
                        "target_path": reference["target_path"],
                        "fallback_path": reference["fallback_path"],
                        "message": (
                            "required primary reference is missing; declared fallback was used"
                            if fallback is not None
                            else "required reference and declared fallback are missing"
                        ),
                    }
                )

    coverage_complete = all(checked_coverage.values())
    target_key = canonical_path_key(requested_target)
    target = selected.get(target_key)
    resolution: dict[str, Any] | None = None
    if coverage_complete and target is not None and target_key not in ambiguous_paths:
        chain = sorted(
            by_path[target_key],
            key=lambda item: (
                provider_by_id[item["provider_id"].casefold()]["priority"],
                item["provider_id"].casefold(),
            ),
        )
        resolution = {
            "asset_id": target["asset_id"],
            "path": target["path"],
            "provider_id": target["provider_id"],
            "provider_chain": [item["provider_id"] for item in chain],
            "resolution_mode": "full_override",
            "full_override_acknowledged": True,
            "representation": target["representation"],
            "content_sha256": target["content_sha256"],
        }
    if not coverage_complete:
        diagnostics.append(
            {
                "code": "INCOMPLETE_COVERAGE",
                "source_path": None,
                "target_path": requested_target,
                "fallback_path": None,
                "message": "provider winner is withheld until path and order coverage are complete",
            }
        )

    if not coverage_complete:
        status = "incomplete_coverage"
    elif target_key in ambiguous_paths:
        status = "ambiguous_winner"
    elif target is None:
        status = "unresolved"
    elif any(item["code"] == "MISSING_REFERENCE" for item in diagnostics):
        status = "missing_dependencies"
    else:
        status = "resolved"

    material = {
        "schema_version": "kcd2.asset-dependency-graph.v1",
        "snapshot_id": snapshot_id,
        "requested_target_path": requested_target,
        "target_path": requested_target if target is None else target["path"],
        "coverage": checked_coverage,
        "status": status,
        "evidence_layer": "static",
        "runtime_state": "unknown",
        "runtime_proof": False,
        "nodes": nodes,
        "edges": sorted(
            edges,
            key=lambda item: (
                item["from_path"].casefold(),
                item["relationship"],
                item["declared_target_path"].casefold(),
            ),
        ),
        "diagnostics": sorted(
            diagnostics,
            key=lambda item: (
                item["code"],
                (item["source_path"] or "").casefold(),
                item["target_path"].casefold(),
            ),
        ),
        "resolution": resolution,
    }
    return AssetDependencyGraph(
        {"graph_id": f"asset-graph:sha256:{sha256_json(material)}", **material}
    )


build_asset_dependency_graph_mapping = resolve_asset_dependencies_mapping
