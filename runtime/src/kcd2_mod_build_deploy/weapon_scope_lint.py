"""Deterministic, fail-closed weapon item scope audit across route families."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


_REQUIRED_FAMILIES = ("action", "sync", "movement", "pose", "adb")
_MAX_FAMILIES = 64
_MAX_ITEMS = 4096
_MAX_SELECTORS = 1024
_MAX_REFS = 256
_MAX_TEXT = 1024


class WeaponScopeLintError(ValueError):
    """The family registry is malformed or exceeds a hard bound."""


@dataclass(frozen=True, slots=True)
class WeaponScopeLintReport:
    """A detached and deterministically ordered scope-lint report."""

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


def weapon_scope_lint(registry: Mapping[str, Any]) -> WeaponScopeLintReport:
    """Audit exact item reachability across every required selector family.

    ``matched_item_ids`` records the broad/static selector result. A broad selector
    that overlaps any other selector must carry an ``exact_item_ids`` isolation
    equal to its declared intent. Invalid isolation is never trusted as a filter.
    """

    data = _detached_mapping(registry, "registry")
    if data.get("schema_version") != "kcd2.weapon-scope-family-registry.v1":
        raise WeaponScopeLintError("unsupported family registry schema_version")
    registry_id = _text(data.get("registry_id"), "registry_id")
    items = _string_tuple(data.get("item_ids"), "item_ids", _MAX_ITEMS, nonempty=True)
    known_items = set(items)
    raw_families = _sequence(data.get("families"), "families", _MAX_FAMILIES)

    diagnostics: list[dict[str, str]] = []
    families: dict[str, dict[str, Any]] = {}
    selectors: list[dict[str, Any]] = []
    selector_ids: set[str] = set()
    selector_count = 0

    for index, value in enumerate(raw_families):
        family = _mapping(value, f"families[{index}]")
        kind = _text(family.get("family_kind"), "family_kind").casefold()
        if kind not in _REQUIRED_FAMILIES:
            raise WeaponScopeLintError(f"unsupported family_kind: {kind}")
        if kind in families:
            raise WeaponScopeLintError(f"duplicate family_kind: {kind}")
        examined = family.get("examined")
        if not isinstance(examined, bool):
            raise WeaponScopeLintError("examined must be boolean")
        evidence_refs = _string_tuple(
            family.get("evidence_refs"), "evidence_refs", _MAX_REFS
        )
        raw_selectors = _sequence(
            family.get("selectors"), f"{kind}.selectors", _MAX_SELECTORS
        )
        selector_count += len(raw_selectors)
        if selector_count > _MAX_SELECTORS:
            raise WeaponScopeLintError(
                f"selectors exceed the {_MAX_SELECTORS}-entry hard bound"
            )
        if not examined or not evidence_refs:
            _diagnostic(
                diagnostics,
                "FAMILY_UNEXAMINED",
                kind,
                "family is not examined with at least one static evidence reference",
            )

        family_selector_ids: list[str] = []
        for selector_index, raw_selector in enumerate(raw_selectors):
            selector = _mapping(raw_selector, f"{kind}.selectors[{selector_index}]")
            selector_id = _text(selector.get("selector_id"), "selector_id")
            selector_key = selector_id.casefold()
            if selector_key in selector_ids:
                raise WeaponScopeLintError("selector_id values must be globally unique")
            selector_ids.add(selector_key)
            selector_kind = selector.get("selector_kind")
            if selector_kind not in {"exact_item", "broad"}:
                raise WeaponScopeLintError("selector_kind must be exact_item or broad")
            matched = _string_tuple(
                selector.get("matched_item_ids"), "matched_item_ids", _MAX_ITEMS, nonempty=True
            )
            intended = _string_tuple(
                selector.get("intended_item_ids"), "intended_item_ids", _MAX_ITEMS, nonempty=True
            )
            referenced = set(matched) | set(intended)
            unknown = sorted(referenced - known_items, key=_sort_key)
            if unknown:
                _diagnostic(
                    diagnostics,
                    "UNKNOWN_ITEM_REFERENCE",
                    f"{kind}:{selector_id}",
                    "selector references unregistered item IDs: " + ", ".join(unknown),
                )
            if selector_kind == "exact_item" and (
                len(matched) != 1 or matched != intended
            ):
                _diagnostic(
                    diagnostics,
                    "EXACT_SELECTOR_CARDINALITY",
                    f"{kind}:{selector_id}",
                    "exact_item must match and intend the same one item ID",
                )

            isolation = selector.get("isolation")
            isolation_valid = False
            isolated_items: tuple[str, ...] | None = None
            if isolation is not None:
                isolation_map = _mapping(isolation, "isolation")
                if isolation_map.get("kind") != "exact_item_ids":
                    raise WeaponScopeLintError("isolation kind must be exact_item_ids")
                isolated_items = _string_tuple(
                    isolation_map.get("item_ids"),
                    "isolation.item_ids",
                    _MAX_ITEMS,
                    nonempty=True,
                )
                isolation_valid = (
                    isolated_items == intended
                    and set(isolated_items).issubset(matched)
                    and set(isolated_items).issubset(known_items)
                )
                if not isolation_valid:
                    _diagnostic(
                        diagnostics,
                        "EXACT_ISOLATION_MISMATCH",
                        f"{kind}:{selector_id}",
                        "exact isolation must equal intended_item_ids and remain within the match",
                    )
            effective = intended if selector_kind == "broad" and isolation_valid else matched
            if set(effective) - set(intended):
                _diagnostic(
                    diagnostics,
                    "SCOPE_LEAK",
                    f"{kind}:{selector_id}",
                    "effective selector scope reaches item IDs outside declared intent",
                )
            parsed = {
                "family_kind": kind,
                "selector_id": selector_id,
                "selector_kind": selector_kind,
                "matched": matched,
                "intended": intended,
                "effective": effective,
                "isolation_valid": isolation_valid,
            }
            selectors.append(parsed)
            family_selector_ids.append(selector_id)

        families[kind] = {
            "family_kind": kind,
            "examined": examined and bool(evidence_refs),
            "evidence_refs": evidence_refs,
            "selector_ids": tuple(sorted(family_selector_ids, key=_sort_key)),
        }

    for kind in _REQUIRED_FAMILIES:
        if kind not in families:
            _diagnostic(
                diagnostics,
                "FAMILY_MISSING",
                kind,
                "required selector family is absent from the registry",
            )
            families[kind] = {
                "family_kind": kind,
                "examined": False,
                "evidence_refs": (),
                "selector_ids": (),
            }

    selectors.sort(key=lambda row: (_sort_key(row["family_kind"]), _sort_key(row["selector_id"])))
    overlaps: list[dict[str, Any]] = []
    for left_index, left in enumerate(selectors):
        for right in selectors[left_index + 1 :]:
            raw_overlap = tuple(sorted(set(left["matched"]) & set(right["matched"]), key=_sort_key))
            if not raw_overlap:
                continue
            effective_overlap = tuple(
                sorted(set(left["effective"]) & set(right["effective"]), key=_sort_key)
            )
            broad = [row for row in (left, right) if row["selector_kind"] == "broad"]
            exact_satisfied = all(row["isolation_valid"] for row in broad)
            if broad and not exact_satisfied:
                for row in broad:
                    if not row["isolation_valid"]:
                        _diagnostic(
                            diagnostics,
                            "BROAD_SELECTOR_NOT_ISOLATED",
                            f"{row['family_kind']}:{row['selector_id']}",
                            "broad selector overlaps another selector without exact item isolation",
                        )
            overlaps.append(
                {
                    "left": _endpoint(left),
                    "right": _endpoint(right),
                    "raw_item_ids": list(raw_overlap),
                    "effective_item_ids": list(effective_overlap),
                    "exact_isolation_satisfied": exact_satisfied,
                }
            )

    diagnostics.sort(
        key=lambda row: (
            _sort_key(row["code"]),
            _sort_key(row["scope"]),
            row["detail"],
        )
    )
    reason_codes = sorted({row["code"] for row in diagnostics}, key=_sort_key)
    family_audit = [
        {
            "family_kind": kind,
            "examined": families[kind]["examined"],
            "evidence_refs": list(families[kind]["evidence_refs"]),
            "selector_ids": list(families[kind]["selector_ids"]),
        }
        for kind in _REQUIRED_FAMILIES
    ]
    payload = {
        "schema_version": "kcd2.weapon-scope-lint.v1",
        "registry_id": registry_id,
        "status": "FAIL" if diagnostics else "PASS",
        "summary": {
            "required_family_count": len(_REQUIRED_FAMILIES),
            "examined_family_count": sum(row["examined"] for row in family_audit),
            "selector_count": len(selectors),
            "overlap_count": len(overlaps),
            "diagnostic_count": len(diagnostics),
        },
        "family_audit": family_audit,
        "overlaps": overlaps,
        "diagnostics": diagnostics,
        "reason_codes": reason_codes,
    }
    return WeaponScopeLintReport(payload)


def _endpoint(selector: Mapping[str, Any]) -> dict[str, str]:
    return {
        "family_kind": selector["family_kind"],
        "selector_id": selector["selector_id"],
        "selector_kind": selector["selector_kind"],
    }


def _diagnostic(rows: list[dict[str, str]], code: str, scope: str, detail: str) -> None:
    rows.append({"code": code, "scope": scope, "detail": detail, "evidence_layer": "static"})


def _detached_mapping(value: object, name: str) -> Mapping[str, Any]:
    mapping = _mapping(value, name)
    try:
        return json.loads(json.dumps(mapping, ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise WeaponScopeLintError(f"{name} must contain JSON values only") from exc


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise WeaponScopeLintError(f"{name} must be an object")
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise WeaponScopeLintError(f"{name} must be an array")
    if len(value) > maximum:
        raise WeaponScopeLintError(f"{name} exceeds the {maximum}-entry hard bound")
    return value


def _string_tuple(
    value: object,
    name: str,
    maximum: int,
    *,
    nonempty: bool = False,
) -> tuple[str, ...]:
    raw = _sequence(value, name, maximum)
    if nonempty and not raw:
        raise WeaponScopeLintError(f"{name} must contain at least one entry")
    parsed = tuple(_text(item, f"{name} item") for item in raw)
    if len(parsed) != len(set(parsed)):
        raise WeaponScopeLintError(f"{name} must contain unique values")
    return tuple(sorted(parsed, key=_sort_key))


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise WeaponScopeLintError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _sort_key(value: str) -> tuple[str, str]:
    return value.casefold(), value
