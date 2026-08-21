"""Bounded configuration and action-map contribution auditing."""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .paths import canonical_relative_path
from .variant_selection import VariantSelectionReceipt, validate_variant_selection


_MAX_SOURCES = 512
_MAX_CONTENT_BYTES = 1_048_576
_MAX_ASSIGNMENTS = 16_384
_MAX_TEXT = 1024
_CFG_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]*$")


class ConfigurationAuditError(ValueError):
    """Configuration evidence violates the bounded audit contract."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise ConfigurationAuditError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


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
        raise ConfigurationAuditError("audit result must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class ConfigurationPathRule:
    """Stable path classification independent of incident-specific values."""

    kind: str
    application: str


CONFIGURATION_PATH_SEMANTICS: Mapping[str, ConfigurationPathRule] = MappingProxyType(
    {
        "mod_cfg": ConfigurationPathRule("MOD_CFG", "STARTUP"),
        "pak_cfg": ConfigurationPathRule("PAK_CFG", "ORDERED_MERGE"),
        "default_profile": ConfigurationPathRule("DEFAULT_PROFILE", "RUNTIME"),
        "action_map": ConfigurationPathRule(
            "ACTION_MAP", "PARALLEL_REGISTRATION"
        ),
        "superaction": ConfigurationPathRule(
            "SUPERACTION", "PARALLEL_REGISTRATION"
        ),
        "other": ConfigurationPathRule("OTHER", "UNKNOWN"),
    }
)


def classify_configuration_path(path: str) -> ConfigurationPathRule:
    """Classify one relative path while leaving its display casing untouched."""

    try:
        checked = canonical_relative_path(_text(path, "path"))
    except (TypeError, ValueError) as exc:
        raise ConfigurationAuditError("path must be a canonical relative path") from exc
    key = checked.casefold()
    name = key.rsplit("/", 1)[-1]
    if name == "mod.cfg":
        return CONFIGURATION_PATH_SEMANTICS["mod_cfg"]
    if name == "pak.cfg":
        return CONFIGURATION_PATH_SEMANTICS["pak_cfg"]
    if name == "defaultprofile.xml":
        return CONFIGURATION_PATH_SEMANTICS["default_profile"]
    if "superaction" in key:
        return CONFIGURATION_PATH_SEMANTICS["superaction"]
    if "actionmap" in key:
        return CONFIGURATION_PATH_SEMANTICS["action_map"]
    return CONFIGURATION_PATH_SEMANTICS["other"]


def _parse_scalar(value: str) -> object:
    stripped = value.strip()
    if len(stripped) > _MAX_TEXT:
        raise ConfigurationAuditError("assignment value exceeds the text hard bound")
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in "\"'":
        return stripped[1:-1]
    folded = stripped.casefold()
    if folded in {"true", "false"}:
        return folded == "true"
    if re.fullmatch(r"[-+]?\d+", stripped):
        try:
            return int(stripped)
        except ValueError:
            pass
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][-+]?\d+)?", stripped):
        try:
            return float(stripped)
        except ValueError:
            pass
    return stripped


def _parse_cfg(content: str) -> list[tuple[str, object, str]]:
    assignments: list[tuple[str, object, str]] = []
    for number, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";", "--")):
            continue
        if "=" not in line:
            raise ConfigurationAuditError(f"configuration line {number} is not an assignment")
        key, value = (part.strip() for part in line.split("=", 1))
        if _CFG_KEY.fullmatch(key) is None:
            raise ConfigurationAuditError(
                f"configuration line {number} has an invalid assignment key"
            )
        assignments.append((key, _parse_scalar(value), "assignment"))
    return assignments


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].casefold()


def _attribute(element: ET.Element, name: str) -> str | None:
    wanted = name.casefold()
    for key, value in element.attrib.items():
        if key.casefold() == wanted:
            return value
    return None


def _parse_xml(content: str, rule: ConfigurationPathRule) -> list[tuple[str, object, str]]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ConfigurationAuditError("configuration XML is malformed") from exc
    assignments: list[tuple[str, object, str]] = []
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag == "cvar":
            name = _attribute(element, "name")
            value = _attribute(element, "value")
            if name is None or value is None or _CFG_KEY.fullmatch(name) is None:
                raise ConfigurationAuditError("CVar requires valid name and value attributes")
            assignments.append((name, _parse_scalar(value), "assignment"))
        elif tag == "actionmap":
            map_name = _attribute(element, "name")
            if map_name is None:
                raise ConfigurationAuditError("actionmap requires a name attribute")
            _text(map_name, "actionmap.name")
            for action in element:
                if _local_name(action.tag) != "action":
                    continue
                action_name = _attribute(action, "name")
                if action_name is None:
                    raise ConfigurationAuditError("action requires a name attribute")
                _text(action_name, "action.name")
                assignments.append(
                    (f"{map_name}/{action_name}", None, "parallel_registration")
                )
        elif tag == "superaction":
            name = _attribute(element, "name")
            if name is None:
                raise ConfigurationAuditError("superaction requires a name attribute")
            assignments.append((_text(name, "superaction.name"), None, "parallel_registration"))
    if rule.kind in {"ACTION_MAP", "SUPERACTION"}:
        return [item for item in assignments if item[2] == "parallel_registration"]
    return assignments


@dataclass(frozen=True, slots=True)
class ConfigurationSource:
    """One exact, in-memory configuration source from a reviewed provider inventory."""

    provider_id: str
    path: str
    content: str
    load_order_index: int | None

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id")
        rule = classify_configuration_path(self.path)
        if not isinstance(self.content, str) or "\x00" in self.content:
            raise ConfigurationAuditError("content must be NUL-free text")
        if len(self.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise ConfigurationAuditError("content exceeds the one-MiB hard bound")
        if self.load_order_index is not None and (
            isinstance(self.load_order_index, bool)
            or not isinstance(self.load_order_index, int)
            or not 0 <= self.load_order_index <= 2**31 - 1
        ):
            raise ConfigurationAuditError("load_order_index must be null or a non-negative integer")
        _parse_source(self.content, rule)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ConfigurationSource":
        expected = {"provider_id", "path", "content", "load_order_index"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ConfigurationAuditError("configuration source fields do not match the contract")
        return cls(
            provider_id=value["provider_id"],  # type: ignore[arg-type]
            path=value["path"],  # type: ignore[arg-type]
            content=value["content"],  # type: ignore[arg-type]
            load_order_index=value["load_order_index"],  # type: ignore[arg-type]
        )


def _parse_source(
    content: str, rule: ConfigurationPathRule
) -> list[tuple[str, object, str]]:
    if rule.kind in {"MOD_CFG", "PAK_CFG"}:
        return _parse_cfg(content)
    if rule.kind in {"DEFAULT_PROFILE", "ACTION_MAP", "SUPERACTION"}:
        return _parse_xml(content, rule)
    return []


@dataclass(frozen=True, slots=True)
class ConfigurationAudit:
    """Immutable schema-ready configuration audit."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class ConfigurationResolution:
    """Immutable CONFIG-002 effective configuration resolution."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _source_sort_key(item: tuple[int, ConfigurationSource]) -> tuple[int, int, str, str]:
    position, source = item
    missing = source.load_order_index is None
    return (
        1 if missing else 0,
        source.load_order_index if source.load_order_index is not None else position,
        source.provider_id.casefold(),
        source.path.casefold(),
    )


def audit_configuration(
    *,
    snapshot_id: str,
    sources: Sequence[ConfigurationSource],
    load_order_complete: bool,
) -> ConfigurationAudit:
    """Parse exact sources into deterministic typed contributions."""

    checked_snapshot_id = _text(snapshot_id, "snapshot_id")
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence):
        raise ConfigurationAuditError("sources must be an array")
    if not sources:
        raise ConfigurationAuditError("sources must contain at least one source")
    if len(sources) > _MAX_SOURCES:
        raise ConfigurationAuditError("sources exceeds the 512-item hard bound")
    if any(not isinstance(source, ConfigurationSource) for source in sources):
        raise ConfigurationAuditError("sources must contain ConfigurationSource values")
    if not isinstance(load_order_complete, bool):
        raise ConfigurationAuditError("load_order_complete must be a boolean")

    ordered_sources = [item[1] for item in sorted(enumerate(sources), key=_source_sort_key)]
    source_rows: list[dict[str, object]] = []
    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    assignment_count = 0
    for source in ordered_sources:
        rule = classify_configuration_path(source.path)
        source_rows.append(
            {"path": source.path, "kind": rule.kind, "provider_id": source.provider_id}
        )
        for key, value, contribution_type in _parse_source(source.content, rule):
            assignment_count += 1
            if assignment_count > _MAX_ASSIGNMENTS:
                raise ConfigurationAuditError("assignments exceeds the hard bound")
            application = (
                "PARALLEL_REGISTRATION"
                if contribution_type == "parallel_registration"
                else rule.application
            )
            identity = (key.casefold(), application, contribution_type)
            group = grouped.setdefault(
                identity,
                {"key": key, "application": application, "items": []},
            )
            items = group["items"]
            assert isinstance(items, list)
            items.append((source, value))

    effective: list[dict[str, object]] = []
    for group in grouped.values():
        items = group["items"]
        assert isinstance(items, list)
        contributors = list(dict.fromkeys(source.provider_id for source, _ in items))
        application = group["application"]
        values = [value for _, value in items]
        ordered_inputs = {
            (source.provider_id.casefold(), source.path.casefold()): source.load_order_index
            for source, _ in items
        }
        indices = list(ordered_inputs.values())
        order_proven = len(indices) <= 1 or (
            load_order_complete
            and all(index is not None for index in indices)
            and len(indices) == len(set(indices))
        )
        if application == "PARALLEL_REGISTRATION":
            effective_value: object = None
            verdict = "VALID"
        elif application == "ORDERED_MERGE":
            effective_value = values if order_proven else None
            verdict = "VALID" if order_proven else "UNRESOLVED"
        elif len(items) == 1:
            effective_value = values[0]
            verdict = "VALID"
        else:
            if order_proven:
                effective_value = values[-1]
                verdict = "VALID" if all(value == values[0] for value in values) else "CONFLICT"
            else:
                effective_value = None
                verdict = "UNRESOLVED"
        effective.append(
            {
                "key": group["key"],
                "contributors": contributors,
                "application": application,
                "effective_value": effective_value,
                "verdict": verdict,
            }
        )
    effective.sort(key=lambda item: (str(item["key"]).casefold(), str(item["application"])))
    verdicts = {item["verdict"] for item in effective}
    overall = (
        "INCONCLUSIVE"
        if "UNRESOLVED" in verdicts
        else "INVALID"
        if "CONFLICT" in verdicts
        else "VALID"
    )
    payload = {
        "schema_version": "kcd2.configuration-audit.v1",
        "snapshot_id": checked_snapshot_id,
        "sources": source_rows,
        "effective_assignments": effective,
        "variant_groups": [],
        "verdict": overall,
    }
    return ConfigurationAudit(payload=_json_copy(payload))


def audit_configuration_mapping(value: Mapping[str, object]) -> ConfigurationAudit:
    """Adapt the exact JSON input contract used by the CLI."""

    expected = {"snapshot_id", "load_order_complete", "sources"}
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ConfigurationAuditError("audit input fields do not match the contract")
    raw_sources = value["sources"]
    if isinstance(raw_sources, (str, bytes)) or not isinstance(raw_sources, Sequence):
        raise ConfigurationAuditError("sources must be an array")
    return audit_configuration(
        snapshot_id=value["snapshot_id"],  # type: ignore[arg-type]
        sources=tuple(
            ConfigurationSource.from_mapping(item)  # type: ignore[arg-type]
            for item in raw_sources
        ),
        load_order_complete=value["load_order_complete"],  # type: ignore[arg-type]
    )


def _variant_resource_sets(
    selection: VariantSelectionReceipt | Mapping[str, Any] | None,
) -> tuple[str | None, set[str], set[str], list[str]]:
    if selection is None:
        return None, set(), set(), []
    receipt = validate_variant_selection(selection).to_dict()
    selected_ids = {
        member_id
        for group in receipt["groups"]
        for member_id in group["selected_member_ids"]
    }
    controlled: set[str] = set()
    selected: set[str] = set()
    for group in receipt["groups"]:
        for member in group["members"]:
            resources = {
                canonical_relative_path(path).casefold()
                for path in member["provided_resources"]
            }
            controlled.update(resources)
            if member["member_id"] in selected_ids:
                selected.update(resources)
    return receipt["selection_id"], controlled, selected, sorted(selected_ids)


def resolve_effective_configuration(
    *,
    snapshot_id: str,
    game_build: str,
    sources: Sequence[ConfigurationSource],
    load_order_complete: bool,
    game_build_support: Mapping[str, Sequence[str]],
    variant_selection: VariantSelectionReceipt | Mapping[str, Any] | None = None,
    runtime_assignments: Mapping[str, object] | None = None,
    runtime_assignments_complete: bool = False,
) -> ConfigurationResolution:
    """Resolve selected static settings without promoting unseen runtime state.

    Variant metadata only selects sources by exact provided-resource path. It is
    never itself interpreted as configuration, preventing metadata-path conflict
    findings. Every parsed occurrence remains in the contributor evidence.
    """

    checked_snapshot = _text(snapshot_id, "snapshot_id")
    checked_build = _text(game_build, "game_build")
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence) or not sources:
        raise ConfigurationAuditError("sources must contain at least one source")
    if len(sources) > _MAX_SOURCES or any(
        not isinstance(item, ConfigurationSource) for item in sources
    ):
        raise ConfigurationAuditError("sources violates the bounded source contract")
    if not isinstance(load_order_complete, bool) or not isinstance(
        runtime_assignments_complete, bool
    ):
        raise ConfigurationAuditError("completeness fields must be booleans")
    if not isinstance(game_build_support, Mapping):
        raise ConfigurationAuditError("game_build_support must be a mapping")
    runtime = {} if runtime_assignments is None else runtime_assignments
    if (
        not isinstance(runtime, Mapping)
        or len(runtime) > _MAX_ASSIGNMENTS
        or any(not isinstance(key, str) for key in runtime)
    ):
        raise ConfigurationAuditError("runtime_assignments must be a string-keyed mapping")

    selection_id, controlled_paths, selected_paths, selected_ids = _variant_resource_sets(
        variant_selection
    )
    ordered = [item[1] for item in sorted(enumerate(sources), key=_source_sort_key)]
    active: list[ConfigurationSource] = []
    excluded: list[str] = []
    for source in ordered:
        path_key = canonical_relative_path(source.path).casefold()
        rule = classify_configuration_path(source.path)
        if path_key in controlled_paths and path_key not in selected_paths:
            if rule.kind != "OTHER":
                excluded.append(source.path)
            continue
        active.append(source)

    build_rows: list[dict[str, object]] = []
    for provider_id in sorted({source.provider_id for source in active}, key=str.casefold):
        asserted = game_build_support.get(provider_id)
        if asserted is None:
            supported: list[str] = []
            status = "UNKNOWN"
        else:
            if isinstance(asserted, (str, bytes)) or not isinstance(asserted, Sequence):
                raise ConfigurationAuditError("supported game builds must be arrays")
            if len(asserted) > 256:
                raise ConfigurationAuditError("supported game builds exceeds the hard bound")
            supported = sorted({_text(item, "supported game build") for item in asserted})
            status = "COMPATIBLE" if checked_build in supported else "INCOMPATIBLE"
        build_rows.append(
            {"provider_id": provider_id, "supported_game_builds": supported, "status": status}
        )

    grouped: dict[tuple[str, str, str], dict[str, object]] = {}
    assignment_count = 0
    for source in active:
        rule = classify_configuration_path(source.path)
        for occurrence, (key, value, contribution_type) in enumerate(
            _parse_source(source.content, rule), 1
        ):
            assignment_count += 1
            if assignment_count > _MAX_ASSIGNMENTS:
                raise ConfigurationAuditError("assignments exceeds the hard bound")
            application = (
                "PARALLEL_REGISTRATION"
                if contribution_type == "parallel_registration"
                else rule.application
            )
            identity = (key.casefold(), application, contribution_type)
            group = grouped.setdefault(
                identity, {"key": key, "application": application, "items": []}
            )
            group["items"].append(  # type: ignore[union-attr]
                {
                    "provider_id": source.provider_id,
                    "path": source.path,
                    "load_order_index": source.load_order_index,
                    "occurrence": occurrence,
                    "value": value,
                }
            )

    runtime_by_key = {key.casefold(): value for key, value in runtime.items()}
    settings: list[dict[str, object]] = []
    conflicts: list[dict[str, object]] = []
    for group in grouped.values():
        items = group["items"]
        assert isinstance(items, list)
        application = group["application"]
        values = [item["value"] for item in items]
        diagnostics: list[str] = []
        if len(items) > 1:
            diagnostics.append("REPEATED_ASSIGNMENT")
        distinct_sources = {
            (item["provider_id"].casefold(), item["path"].casefold()): item["load_order_index"]
            for item in items
        }
        indices = list(distinct_sources.values())
        order_proven = len(indices) <= 1 or (
            load_order_complete
            and all(index is not None for index in indices)
            and len(indices) == len(set(indices))
        )
        if application == "PARALLEL_REGISTRATION":
            static_value: object = None
            static_status = "PARALLEL"
        elif order_proven:
            static_value = values[-1]
            static_status = "EFFECTIVE"
            if len(set(_canonical_bytes(value) for value in values)) > 1:
                diagnostics.append("ORDERED_OVERRIDE")
        else:
            static_value = None
            static_status = "UNKNOWN"
            diagnostics.append("ORDER_UNPROVEN")
            conflicts.append(
                {
                    "key": group["key"],
                    "reason": "ORDER_UNPROVEN",
                    "contributors": [dict(item) for item in items],
                }
            )

        folded_key = str(group["key"]).casefold()
        if application == "PARALLEL_REGISTRATION":
            runtime_value: object = None
            runtime_status = "NOT_APPLICABLE"
        elif folded_key in runtime_by_key:
            runtime_value = runtime_by_key[folded_key]
            runtime_status = "OBSERVED"
        elif runtime_assignments_complete:
            runtime_value = static_value
            runtime_status = "UNCHANGED"
        else:
            runtime_value = None
            runtime_status = "UNKNOWN"
            diagnostics.append("RUNTIME_MUTATION_UNKNOWN")
        settings.append(
            {
                "key": group["key"],
                "application": application,
                "contributors": [dict(item) for item in items],
                "static_effective_value": static_value,
                "static_status": static_status,
                "runtime_effective_value": runtime_value,
                "runtime_status": runtime_status,
                "diagnostics": diagnostics,
            }
        )

    settings.sort(key=lambda row: (str(row["key"]).casefold(), str(row["application"])))
    incompatible = any(row["status"] == "INCOMPATIBLE" for row in build_rows)
    unknown = (
        any(row["status"] == "UNKNOWN" for row in build_rows)
        or any(row["static_status"] == "UNKNOWN" for row in settings)
        or any(row["runtime_status"] == "UNKNOWN" for row in settings)
    )
    payload = {
        "schema_version": "kcd2.configuration-resolution.v1",
        "snapshot_id": checked_snapshot,
        "game_build": checked_build,
        "variant_selection": {
            "selection_id": selection_id,
            "selected_member_ids": selected_ids,
        },
        "excluded_variant_sources": sorted(excluded, key=str.casefold),
        "build_compatibility": build_rows,
        "effective_settings": settings,
        "conflicts": conflicts,
        "runtime_assignments_complete": runtime_assignments_complete,
        "verdict": "INVALID" if incompatible else "INCONCLUSIVE" if unknown else "VALID",
    }
    return ConfigurationResolution(payload=_json_copy(payload))


def resolve_effective_configuration_mapping(
    value: Mapping[str, object],
) -> ConfigurationResolution:
    """Adapt the exact JSON contract used by the CONFIG-002 CLI."""

    expected = {
        "snapshot_id",
        "game_build",
        "sources",
        "load_order_complete",
        "game_build_support",
        "variant_selection",
        "runtime_assignments",
        "runtime_assignments_complete",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ConfigurationAuditError("resolution input fields do not match the contract")
    raw_sources = value["sources"]
    if isinstance(raw_sources, (str, bytes)) or not isinstance(raw_sources, Sequence):
        raise ConfigurationAuditError("sources must be an array")
    return resolve_effective_configuration(
        snapshot_id=value["snapshot_id"],  # type: ignore[arg-type]
        game_build=value["game_build"],  # type: ignore[arg-type]
        sources=tuple(
            ConfigurationSource.from_mapping(item)  # type: ignore[arg-type]
            for item in raw_sources
        ),
        load_order_complete=value["load_order_complete"],  # type: ignore[arg-type]
        game_build_support=value["game_build_support"],  # type: ignore[arg-type]
        variant_selection=value["variant_selection"],  # type: ignore[arg-type]
        runtime_assignments=value["runtime_assignments"],  # type: ignore[arg-type]
        runtime_assignments_complete=value[  # type: ignore[arg-type]
            "runtime_assignments_complete"
        ],
    )
