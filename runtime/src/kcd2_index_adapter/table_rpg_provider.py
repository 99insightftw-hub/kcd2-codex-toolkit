"""Bounded portfolio table/RPG provider over reviewed semantics profiles."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .table_semantics import (
    ExactTableDocument,
    TableSemanticsError,
    TableSemanticsRegistry,
    extract_table_record_contributions,
)


_MAX_TABLES = 256
_DOCUMENT_FIELDS = {
    "provider_id",
    "provider_kind",
    "load_order_index",
    "source_path",
    "member_or_loose_path",
    "content_sha256",
    "game_build",
    "source_build",
    "active",
    "xml_text",
}


class TableRpgProviderError(ValueError):
    """A portfolio request or profile registry is incomplete or inconsistent."""


def _canonical_copy(value: object) -> Any:
    return json.loads(
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise TableRpgProviderError(f"{name} must be a non-empty bounded string")
    return value


def _exact_fields(value: Mapping[str, object], fields: set[str], name: str) -> None:
    if set(value) != fields:
        raise TableRpgProviderError(f"{name} fields do not match the input contract")


@dataclass(frozen=True, slots=True)
class TableRpgContributionBatch:
    """Deterministic results for a build-bound portfolio table batch."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _canonical_copy(self.payload)

    def to_json(self) -> str:
        return json.dumps(
            self.payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True, slots=True)
class TableRpgProvider:
    """Automatic contribution provider for explicitly profiled table families."""

    registry: TableSemanticsRegistry

    @classmethod
    def from_registry_mapping(cls, value: Mapping[str, object]) -> "TableRpgProvider":
        try:
            registry = TableSemanticsRegistry.from_mapping(value)
        except TableSemanticsError as exc:
            raise TableRpgProviderError(str(exc)) from exc
        if not registry.profiles:
            raise TableRpgProviderError("portfolio registry must contain profiles")
        for profile in registry.profiles:
            if not profile.primary_keys:
                raise TableRpgProviderError(
                    f"profile {profile.profile_id!r} has no primary-key binding"
                )
            if not profile.schema_paths:
                raise TableRpgProviderError(
                    f"profile {profile.profile_id!r} has no XSD/schema binding"
                )
            if any(not path.casefold().endswith(".xsd") for path in profile.schema_paths):
                raise TableRpgProviderError(
                    f"profile {profile.profile_id!r} has a non-XSD schema binding"
                )
        return cls(registry=registry)

    @classmethod
    def from_registry_path(cls, path: str | Path) -> "TableRpgProvider":
        try:
            value = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TableRpgProviderError("could not load portfolio profile registry") from exc
        if not isinstance(value, Mapping):
            raise TableRpgProviderError("portfolio profile registry must be an object")
        return cls.from_registry_mapping(value)

    def capabilities(self) -> dict[str, Any]:
        """Describe exact version, primary-key, XSD, and semantics bindings."""

        families = [
            {
                "family": profile.table_name,
                "profile_id": profile.profile_id,
                "game_build": profile.game_build,
                "source_build": profile.source_build,
                "table_type": profile.table_type,
                "primary_keys": list(profile.primary_keys),
                "schema_paths": list(profile.schema_paths),
            }
            for profile in self.registry.profiles
        ]
        return {
            "schema_version": "kcd2.table-rpg-provider-capabilities.v1",
            "provider_id": "table-rpg",
            "revision": "1.0.0",
            "game_builds": sorted({item["game_build"] for item in families}),
            "source_builds": sorted({item["source_build"] for item in families}),
            "families": families,
        }

    def contribute(self, request: Mapping[str, object]) -> TableRpgContributionBatch:
        """Extract contributions for all requested tables without inferring semantics."""

        if not isinstance(request, Mapping):
            raise TableRpgProviderError("request must be an object")
        _exact_fields(
            request,
            {"snapshot_id", "game_build", "source_build", "tables"},
            "request",
        )
        snapshot_id = _text(request["snapshot_id"], "snapshot_id")
        game_build = _text(request["game_build"], "game_build")
        source_build = _text(request["source_build"], "source_build")
        tables = request["tables"]
        if isinstance(tables, (str, bytes)) or not isinstance(tables, Sequence):
            raise TableRpgProviderError("tables must be an array")
        if not tables or len(tables) > _MAX_TABLES:
            raise TableRpgProviderError(f"tables must contain 1 through {_MAX_TABLES} items")

        outputs: list[dict[str, Any]] = []
        paths: set[str] = set()
        for index, table in enumerate(tables):
            if not isinstance(table, Mapping):
                raise TableRpgProviderError("table requests must be objects")
            _exact_fields(table, {"query_id", "canonical_path", "documents"}, "table")
            query_id = _text(table["query_id"], "query_id")
            canonical_path = _text(table["canonical_path"], "canonical_path")
            path_key = canonical_path.replace("\\", "/").casefold()
            if path_key in paths:
                raise TableRpgProviderError("canonical table paths must be unique")
            paths.add(path_key)
            document_values = table["documents"]
            if isinstance(document_values, (str, bytes)) or not isinstance(
                document_values, Sequence
            ):
                raise TableRpgProviderError("documents must be an array")
            documents: list[ExactTableDocument] = []
            for document in document_values:
                if not isinstance(document, Mapping):
                    raise TableRpgProviderError("documents must contain objects")
                _exact_fields(document, _DOCUMENT_FIELDS, "document")
                try:
                    documents.append(ExactTableDocument(**document))
                except (TableSemanticsError, TypeError) as exc:
                    raise TableRpgProviderError(str(exc)) from exc
            try:
                profile = self.registry.resolve(
                    game_build=game_build,
                    source_build=source_build,
                    canonical_path=canonical_path,
                )
                result = extract_table_record_contributions(
                    query_id=query_id,
                    registry=self.registry,
                    game_build=game_build,
                    source_build=source_build,
                    canonical_path=canonical_path,
                    documents=documents,
                ).to_dict()
            except TableSemanticsError as exc:
                raise TableRpgProviderError(f"table {index}: {exc}") from exc
            result["table_name"] = profile.table_name
            result["primary_keys"] = list(profile.primary_keys)
            result["schema_paths"] = list(profile.schema_paths)
            result["tbl_requirement"] = profile.tbl_requirement
            outputs.append(result)

        statuses = {item["semantics_status"] for item in outputs}
        overall = (
            "capture_inconclusive"
            if "capture_inconclusive" in statuses
            else "unresolved"
            if "unresolved" in statuses
            else "resolved"
        )
        return TableRpgContributionBatch(
            payload=_canonical_copy(
                {
                    "schema_version": "kcd2.table-rpg-contribution-batch.v1",
                    "snapshot_id": snapshot_id,
                    "game_build": game_build,
                    "source_build": source_build,
                    "provider_id": "table-rpg",
                    "provider_revision": "1.0.0",
                    "overall_status": overall,
                    "tables": outputs,
                }
            )
        )
