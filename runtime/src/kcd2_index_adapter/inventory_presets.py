"""Bounded InventoryPreset traversal over effective table records."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal


_MAX_TEXT = 1024
_MAX_PRESETS = 20_000
_MAX_CHILDREN = 10_000
_MAX_DEPTH = 128
_MAX_NODES = 10_000
_ENTRY_KINDS = frozenset({"merchant", "npc", "container", "shop"})
_VARIATION_SEMANTICS = frozenset({"unknown", "plus_or_minus"})


class InventoryPresetError(ValueError):
    """Effective table evidence cannot support the requested preset traversal."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_TEXT
        or "\x00" in value
    ):
        raise InventoryPresetError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _bounded_int(value: object, name: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise InventoryPresetError(f"{name} must be an integer from 1 through {maximum}")
    return value


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InventoryPresetError(f"{name} must be an object")
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise InventoryPresetError(f"{name} must be an array")
    if len(value) > maximum:
        raise InventoryPresetError(f"{name} exceeds the {maximum}-item hard bound")
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
        raise InventoryPresetError("inventory result must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


@dataclass(frozen=True, slots=True)
class InventoryPresetResolution:
    """Immutable schema-ready result for one direct or identity-based query."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _table_payload(value: object, name: str) -> Mapping[str, Any]:
    if hasattr(value, "to_dict") and callable(value.to_dict):
        value = value.to_dict()
    payload = _mapping(value, name)
    if payload.get("schema_version") != "kcd2.table-record-contribution-set.v1":
        raise InventoryPresetError(f"{name} has an unsupported schema version")
    _text(payload.get("profile_id"), f"{name}.profile_id")
    _text(payload.get("canonical_path"), f"{name}.canonical_path")
    _sequence(payload.get("provider_documents"), f"{name}.provider_documents", 4096)
    _sequence(payload.get("effective_records"), f"{name}.effective_records", _MAX_PRESETS)
    return payload


def _attributes(value: object, name: str) -> dict[str, str]:
    items = _sequence(value, name, 512)
    result: dict[str, str] = {}
    for index, raw in enumerate(items):
        item = _mapping(raw, f"{name}[{index}]")
        attribute_name = _text(item.get("name"), f"{name}[{index}].name")
        attribute_value = item.get("value")
        if not isinstance(attribute_value, str) or len(attribute_value) > _MAX_TEXT:
            raise InventoryPresetError(f"{name}[{index}].value must be a bounded string")
        if attribute_name in result:
            raise InventoryPresetError(f"{name} contains duplicate attribute {attribute_name!r}")
        result[attribute_name] = attribute_value
    return result


def _record_name(record: Mapping[str, Any], name: str) -> str:
    key_items = _sequence(record.get("record_key"), f"{name}.record_key", 32)
    for index, raw in enumerate(key_items):
        item = _mapping(raw, f"{name}.record_key[{index}]")
        if item.get("name") == "Name":
            return _text(item.get("value"), f"{name}.record_key[{index}].value")
    attributes = _attributes(record.get("attributes"), f"{name}.attributes")
    return _text(attributes.get("Name"), f"{name}.attributes.Name")


def _records_by_name(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw_records = _sequence(payload["effective_records"], "effective_records", _MAX_PRESETS)
    result: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(raw_records):
        record = _mapping(raw, f"effective_records[{index}]")
        name = _record_name(record, f"effective_records[{index}]")
        if name in result:
            raise InventoryPresetError(f"effective preset name {name!r} is ambiguous")
        _sequence(record.get("nested_children"), "nested_children", _MAX_CHILDREN)
        _sequence(record.get("contributing_provider_ids"), "provider_ids", 4096)
        result[name] = record
    return result


def _provider_sources(
    payload: Mapping[str, Any], provider_ids: Sequence[str]
) -> list[dict[str, Any]]:
    selected = set(provider_ids)
    sources: list[dict[str, Any]] = []
    documents = _sequence(payload["provider_documents"], "provider_documents", 4096)
    for index, raw in enumerate(documents):
        document = _mapping(raw, f"provider_documents[{index}]")
        provider_id = _text(document.get("provider_id"), "provider_id")
        if provider_id not in selected:
            continue
        sources.append(
            {
                "provider_id": provider_id,
                "provider_kind": _text(document.get("provider_kind"), "provider_kind"),
                "load_order_index": document.get("load_order_index"),
                "source_path": _text(document.get("source_path"), "source_path"),
                "member_or_loose_path": _text(
                    document.get("member_or_loose_path"), "member_or_loose_path"
                ),
                "content_sha256": _text(document.get("content_sha256"), "content_sha256"),
                "game_build": _text(document.get("game_build"), "game_build"),
                "source_build": _text(document.get("source_build"), "source_build"),
            }
        )
    return sources


def _provenance(
    payload: Mapping[str, Any], record: Mapping[str, Any] | None
) -> dict[str, Any]:
    if record is None:
        provider_ids: list[str] = []
        record_key: list[object] = []
    else:
        raw_ids = _sequence(record.get("contributing_provider_ids"), "provider_ids", 4096)
        provider_ids = [_text(value, "provider_id") for value in raw_ids]
        record_key = list(_sequence(record.get("record_key"), "record_key", 32))
    return {
        "profile_id": payload["profile_id"],
        "canonical_path": payload["canonical_path"],
        "record_key": _json_copy(record_key),
        "sources": _provider_sources(payload, provider_ids),
    }


def _number(raw: str | None) -> float | None:
    if raw is None:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return value


def _integer(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw, 10)
    except ValueError:
        return None
    return value if 0 <= value <= 2**31 - 1 else None


def _quantity(
    attributes: Mapping[str, str],
    *,
    item: bool,
    variation_semantics: str,
) -> tuple[tuple[float, float] | None, str, list[str]]:
    mode = attributes.get("Mode")
    if mode is not None and mode.casefold() not in {"amount", "exact"}:
        return None, "unknown", ["UNKNOWN_QUANTITY_MODE"]
    base_raw = attributes.get("Amount", attributes.get("ModeValue"))
    if base_raw is None:
        if item:
            return None, "unknown", ["MISSING_ITEM_AMOUNT"]
        return (1.0, 1.0), "structural_once", []
    base = _number(base_raw)
    if base is None:
        return None, "unknown", ["INVALID_QUANTITY_VALUE"]
    variation_raw = attributes.get("Variation", attributes.get("ModeValueVariation"))
    if variation_raw is None:
        return (base, base), "exact", []
    variation = _number(variation_raw)
    if variation is None:
        return None, "unknown", ["INVALID_VARIATION_VALUE"]
    if variation_semantics != "plus_or_minus":
        return None, "unknown", ["VARIATION_SEMANTICS_UNKNOWN"]
    return (max(0.0, base - variation), base + variation), "plus_or_minus", []


def _local_restriction(attributes: Mapping[str, str]) -> tuple[int | None, int | None, list[str]]:
    minimum_raw = attributes.get("MinimumCombatLevel", attributes.get("MinCombatLevel"))
    maximum_raw = attributes.get("MaximumCombatLevel", attributes.get("MaxCombatLevel"))
    minimum = _integer(minimum_raw)
    maximum = _integer(maximum_raw)
    reasons: list[str] = []
    if minimum_raw is not None and minimum is None:
        reasons.append("INVALID_MINIMUM_COMBAT_LEVEL")
    if maximum_raw is not None and maximum is None:
        reasons.append("INVALID_MAXIMUM_COMBAT_LEVEL")
    if minimum is not None and maximum is not None and minimum > maximum:
        reasons.append("INVALID_COMBAT_LEVEL_RANGE")
    return minimum, maximum, reasons


def _combine_restriction(
    inherited: tuple[int | None, int | None], local: tuple[int | None, int | None]
) -> tuple[int | None, int | None]:
    minimums = [value for value in (inherited[0], local[0]) if value is not None]
    maximums = [value for value in (inherited[1], local[1]) if value is not None]
    return (max(minimums) if minimums else None, min(maximums) if maximums else None)


def _restriction_payload(
    bounds: tuple[int | None, int | None], combat_level: int | None, invalid: bool
) -> dict[str, Any]:
    minimum, maximum = bounds
    if invalid or (minimum is not None and maximum is not None and minimum > maximum):
        state = "unknown"
    elif minimum is None and maximum is None:
        state = "not_applicable"
    elif combat_level is None:
        state = "not_evaluated"
    elif (minimum is not None and combat_level < minimum) or (
        maximum is not None and combat_level > maximum
    ):
        state = "excluded"
    else:
        state = "eligible"
    return {
        "minimum_combat_level": minimum,
        "maximum_combat_level": maximum,
        "evaluated_combat_level": combat_level,
        "state": state,
    }


def _child_payloads(record: Mapping[str, Any]) -> list[tuple[Mapping[str, Any], dict[str, str]]]:
    children = _sequence(record.get("nested_children"), "nested_children", _MAX_CHILDREN)
    result: list[tuple[Mapping[str, Any], dict[str, str]]] = []
    for index, raw in enumerate(children):
        child = _mapping(raw, f"nested_children[{index}]")
        if child.get("element") not in {"InventoryPresetRef", "PresetItem"}:
            continue
        result.append((child, _attributes(child.get("attributes"), f"child[{index}].attributes")))
    return result


def _local_probabilities(
    children: Sequence[tuple[Mapping[str, Any], Mapping[str, str]]]
) -> list[float | None]:
    weights = [_number(attributes.get("Weight")) for _, attributes in children]
    if not weights or any(weight is None for weight in weights):
        return [None] * len(children)
    total = sum(weight for weight in weights if weight is not None)
    if total <= 0:
        return [None] * len(children)
    return [weight / total if weight is not None else None for weight in weights]


def _entry_root(
    payload: Mapping[str, Any], identity: str
) -> tuple[str, Mapping[str, Any]]:
    matches = [
        record
        for record in _records_by_name(payload).values()
        if _record_name(record, "entry_record") == identity
    ]
    if not matches:
        raise InventoryPresetError(f"entry identity {identity!r} is not effective")
    record = matches[0]
    attributes = _attributes(record.get("attributes"), "entry_record.attributes")
    roots = [
        value
        for field in ("InventoryPreset", "InventoryPresetName")
        if (value := attributes.get(field))
    ]
    for child, child_attributes in _child_payloads(record):
        if child.get("element") == "InventoryPresetRef" and child_attributes.get("Name"):
            roots.append(child_attributes["Name"])
    unique = list(dict.fromkeys(roots))
    if len(unique) != 1:
        raise InventoryPresetError(
            f"entry identity {identity!r} must resolve exactly one effective preset"
        )
    return unique[0], record


def resolve_inventory_preset(
    *,
    resolution_id: str,
    root_preset: str,
    preset_table: object,
    snapshot_id: str,
    coverage_id: str,
    combat_level: int | None = None,
    variation_semantics: Literal["unknown", "plus_or_minus"] = "unknown",
    max_depth: int = 32,
    max_nodes: int = 1000,
    entry_point: Mapping[str, Any] | None = None,
) -> InventoryPresetResolution:
    """Resolve effective preset records without accepting caller-prepared preset rows."""

    checked_resolution = _text(resolution_id, "resolution_id")
    checked_root = _text(root_preset, "root_preset")
    checked_snapshot = _text(snapshot_id, "snapshot_id")
    checked_coverage = _text(coverage_id, "coverage_id")
    checked_depth = _bounded_int(max_depth, "max_depth", _MAX_DEPTH)
    checked_nodes = _bounded_int(max_nodes, "max_nodes", _MAX_NODES)
    if variation_semantics not in _VARIATION_SEMANTICS:
        raise InventoryPresetError("variation_semantics is not supported")
    if combat_level is not None and (
        isinstance(combat_level, bool)
        or not isinstance(combat_level, int)
        or not 0 <= combat_level <= 2**31 - 1
    ):
        raise InventoryPresetError("combat_level must be a non-negative integer")

    table = _table_payload(preset_table, "preset_table")
    records = _records_by_name(table)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    cycles: list[list[str]] = []
    outcomes: list[dict[str, Any]] = []
    report_reasons: set[str] = set()
    limits_reached = False

    table_resolved = table.get("semantics_status") == "resolved"
    if not table_resolved:
        report_reasons.update({"CAPTURE_INCONCLUSIVE", "EFFECTIVE_TABLE_UNRESOLVED"})

    def capacity() -> bool:
        nonlocal limits_reached
        if len(nodes) + len(outcomes) >= checked_nodes:
            limits_reached = True
            report_reasons.add("MAX_NODES_REACHED")
            return False
        return True

    def append_node(
        preset_name: str,
        path: str,
        status: str,
        record: Mapping[str, Any] | None,
    ) -> str | None:
        if not capacity():
            return None
        node_id = f"n{len(nodes) + 1}"
        if record is None:
            provider_ids: list[str] = []
        else:
            provider_ids = [
                _text(value, "provider_id")
                for value in _sequence(
                    record.get("contributing_provider_ids"), "provider_ids", 4096
                )
            ]
        nodes.append(
            {
                "node_id": node_id,
                "preset_name": preset_name,
                "provider_id": provider_ids[-1] if provider_ids else None,
                "contributing_provider_ids": provider_ids,
                "path_instance": path,
                "status": status,
                "provenance": _provenance(table, record),
            }
        )
        return node_id

    def walk(
        preset_name: str,
        *,
        path: str,
        depth: int,
        parent_id: str | None,
        edge_ordinal: int | None,
        ancestors: tuple[tuple[str, str], ...],
        probability: float | None,
        quantity_multiplier: tuple[float, float] | None,
        restriction_bounds: tuple[int | None, int | None],
        inherited_restriction_invalid: bool,
    ) -> None:
        nonlocal limits_reached
        record = records.get(preset_name)
        ancestor_names = [name for name, _ in ancestors]
        status = "resolved"
        if preset_name in ancestor_names:
            status = "cycle"
        elif record is None:
            status = "missing" if table_resolved else "unresolved"
        node_id = append_node(preset_name, path, status, record)
        if node_id is None:
            return
        if parent_id is not None:
            edges.append(
                {
                    "from": parent_id,
                    "to": node_id,
                    "kind": "reference",
                    "path_instance": path,
                    "ordinal": edge_ordinal,
                }
            )
        if status == "cycle":
            start = ancestor_names.index(preset_name)
            cycles.append([node for _, node in ancestors[start:]] + [node_id])
            report_reasons.add("CYCLE_DETECTED")
            return
        if status == "missing":
            report_reasons.add("MISSING_PRESET_REFERENCE")
            return
        if status == "unresolved":
            report_reasons.add("CAPTURE_INCONCLUSIVE")
            return
        if depth >= checked_depth:
            limits_reached = True
            report_reasons.add("MAX_DEPTH_REACHED")
            return
        assert record is not None
        children = _child_payloads(record)
        local_probabilities = _local_probabilities(children)
        for ordinal, ((child, attributes), local_probability) in enumerate(
            zip(children, local_probabilities, strict=True)
        ):
            element = child["element"]
            name = attributes.get("Name")
            if not name:
                report_reasons.add("CHILD_NAME_MISSING")
                continue
            branch_path = (
                f"{path}/ref[{ordinal}]"
                if element == "InventoryPresetRef"
                else f"{path}/item[{ordinal}]"
            )
            branch_probability = (
                probability * local_probability
                if probability is not None and local_probability is not None
                else None
            )
            local_minimum, local_maximum, restriction_reasons = _local_restriction(
                attributes
            )
            combined_bounds = _combine_restriction(
                restriction_bounds, (local_minimum, local_maximum)
            )
            restriction_invalid = inherited_restriction_invalid or bool(restriction_reasons)
            restriction = _restriction_payload(
                combined_bounds, combat_level, restriction_invalid
            )
            branch_quantity, quantity_semantics, quantity_reasons = _quantity(
                attributes,
                item=element == "PresetItem",
                variation_semantics=variation_semantics,
            )
            branch_multiplier = None
            if quantity_multiplier is not None and branch_quantity is not None:
                branch_multiplier = (
                    quantity_multiplier[0] * branch_quantity[0],
                    quantity_multiplier[1] * branch_quantity[1],
                )
            if element == "InventoryPresetRef":
                walk(
                    name,
                    path=f"{branch_path}:{name}",
                    depth=depth + 1,
                    parent_id=node_id,
                    edge_ordinal=ordinal,
                    ancestors=ancestors + ((preset_name, node_id),),
                    probability=branch_probability,
                    quantity_multiplier=branch_multiplier,
                    restriction_bounds=combined_bounds,
                    inherited_restriction_invalid=restriction_invalid,
                )
                continue
            if not capacity():
                continue
            if quantity_multiplier is None:
                quantity_reasons = sorted(
                    set(quantity_reasons) | {"ANCESTOR_QUANTITY_UNKNOWN"}
                )
            if restriction["state"] == "unknown":
                quantity_reasons = sorted(set(quantity_reasons) | set(restriction_reasons))
            if local_probability is None:
                probability_semantics = "unknown"
                probability_reasons = ["SELECTION_WEIGHT_SEMANTICS_UNKNOWN"]
            else:
                probability_semantics = "normalized_weight"
                probability_reasons = []
            if restriction["state"] == "excluded":
                branch_probability = 0.0
            reasons = sorted(set(quantity_reasons + probability_reasons + restriction_reasons))
            health_raw = attributes.get("Health")
            health = _number(health_raw)
            if health_raw is not None and health is None:
                reasons.append("INVALID_HEALTH_VALUE")
                reasons = sorted(set(reasons))
            outcome_id = f"i{len(outcomes) + 1}"
            outcomes.append(
                {
                    "outcome_id": outcome_id,
                    "source_node_id": node_id,
                    "path_instance": f"{branch_path}:{name}",
                    "item_name": name,
                    "quantity_min": branch_multiplier[0] if branch_multiplier else None,
                    "quantity_max": branch_multiplier[1] if branch_multiplier else None,
                    "quantity_semantics": quantity_semantics
                    if quantity_multiplier is not None
                    else "unknown",
                    "selection_probability": branch_probability,
                    "selection_weight": _number(attributes.get("Weight")),
                    "probability_semantics": probability_semantics,
                    "restriction": restriction,
                    "health": health,
                    "semantics_complete": not reasons,
                    "reason_codes": reasons,
                    "provenance": _provenance(table, record),
                }
            )
            edges.append(
                {
                    "from": node_id,
                    "to": outcome_id,
                    "kind": "item",
                    "path_instance": f"{branch_path}:{name}",
                    "ordinal": ordinal,
                }
            )
            report_reasons.update(reasons)

    walk(
        checked_root,
        path="root",
        depth=0,
        parent_id=None,
        edge_ordinal=None,
        ancestors=(),
        probability=1.0,
        quantity_multiplier=(1.0, 1.0),
        restriction_bounds=(None, None),
        inherited_restriction_invalid=False,
    )

    checked_entry: dict[str, Any] | None = None
    if entry_point is not None:
        entry = _mapping(entry_point, "entry_point")
        kind = entry.get("kind")
        if kind not in _ENTRY_KINDS:
            raise InventoryPresetError("entry_point.kind is not supported")
        checked_entry = {
            "kind": str(kind),
            "identity": _text(entry.get("identity"), "entry_point.identity"),
        }
        provenance = entry.get("provenance")
        if provenance is None:
            raise InventoryPresetError("entry_point.provenance is required")
        checked_entry["provenance"] = _json_copy(
            _mapping(provenance, "entry_point.provenance")
        )
    if limits_reached:
        report_reasons.add("OUTPUT_TRUNCATED")
    payload = {
        "schema_version": "kcd2.inventory-preset-resolution.v1",
        "resolution_id": checked_resolution,
        "root_preset": checked_root,
        "snapshot_id": checked_snapshot,
        "coverage_id": checked_coverage,
        "input_mode": "integrated",
        "entry_point": checked_entry,
        "nodes": nodes,
        "edges": edges,
        "cycles": cycles,
        "item_outcomes": outcomes,
        "reason_codes": sorted(report_reasons),
        "limits": {
            "max_depth": checked_depth,
            "max_nodes": checked_nodes,
            "reached": limits_reached,
        },
        "complete": not report_reasons and table_resolved,
    }
    return InventoryPresetResolution(payload=_json_copy(payload))


def _resolve_entry(
    *,
    kind: str,
    resolution_id: str,
    identity: str,
    entry_table: object,
    preset_table: object,
    snapshot_id: str,
    coverage_id: str,
    combat_level: int | None = None,
    variation_semantics: Literal["unknown", "plus_or_minus"] = "unknown",
    max_depth: int = 32,
    max_nodes: int = 1000,
) -> InventoryPresetResolution:
    checked_identity = _text(identity, "identity")
    entry_payload = _table_payload(entry_table, "entry_table")
    if entry_payload.get("semantics_status") != "resolved":
        raise InventoryPresetError("entry_table effective semantics are unresolved")
    root, entry_record = _entry_root(entry_payload, checked_identity)
    return resolve_inventory_preset(
        resolution_id=resolution_id,
        root_preset=root,
        preset_table=preset_table,
        snapshot_id=snapshot_id,
        coverage_id=coverage_id,
        combat_level=combat_level,
        variation_semantics=variation_semantics,
        max_depth=max_depth,
        max_nodes=max_nodes,
        entry_point={
            "kind": kind,
            "identity": checked_identity,
            "provenance": _provenance(entry_payload, entry_record),
        },
    )


def resolve_merchant_inventory(**kwargs: Any) -> InventoryPresetResolution:
    """Resolve a merchant identity through its effective InventoryPreset reference."""

    return _resolve_entry(kind="merchant", **kwargs)


def resolve_npc_inventory(**kwargs: Any) -> InventoryPresetResolution:
    """Resolve an NPC identity through its effective InventoryPreset reference."""

    return _resolve_entry(kind="npc", **kwargs)


def resolve_container_inventory(**kwargs: Any) -> InventoryPresetResolution:
    """Resolve a container identity through its effective InventoryPreset reference."""

    return _resolve_entry(kind="container", **kwargs)


def resolve_shop_inventory(**kwargs: Any) -> InventoryPresetResolution:
    """Resolve a shop identity through its effective InventoryPreset reference."""

    return _resolve_entry(kind="shop", **kwargs)
