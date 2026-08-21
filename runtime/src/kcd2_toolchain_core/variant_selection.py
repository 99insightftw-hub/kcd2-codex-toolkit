"""Content-addressed variant groups and deterministic selection receipts."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .hashing import canonical_json_bytes, sha256_json
from .paths import canonical_path_key, canonical_relative_path


SCHEMA_VERSION = "kcd2.variant-selection.v1"
RULES = frozenset(
    {"EXACTLY_ONE", "ZERO_OR_ONE", "ALL_REQUIRED", "LANGUAGE", "PLATFORM", "PRESET"}
)
SEMANTIC_RULES = frozenset({"LANGUAGE", "PLATFORM", "PRESET"})
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_CONTENT_ID = re.compile(
    r"^(?P<prefix>registry|variant-member|variant-group|variant-selection):sha256:"
    r"(?P<digest>[0-9a-f]{64})$"
)


class VariantSelectionError(ValueError):
    """A variant group or selected set violates the contract."""


class VariantIdentityMismatchError(VariantSelectionError):
    """A transported content identity does not match its canonical material."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise TypeError(f"{field} must be a mapping with string keys")
    return value


def _sequence(value: Any, field: str, maximum: int, minimum: int = 0) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise TypeError(f"{field} must be an array")
    if not minimum <= len(value) <= maximum:
        raise VariantSelectionError(
            f"{field} must contain between {minimum} and {maximum} items"
        )
    return value


def _exact_fields(
    value: Mapping[str, Any], required: set[str], optional: set[str], field: str
) -> None:
    missing = required - set(value)
    unknown = set(value) - required - optional
    if missing or unknown:
        raise VariantSelectionError(
            f"{field} fields do not match contract; "
            f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        )


def _string(value: Any, field: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise VariantSelectionError(
            f"{field} must be a non-empty string of at most {maximum} characters"
        )
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise VariantSelectionError(f"{field} must be a SHA-256 hex digest")
    return value.lower()


def _content_id(prefix: str, material: Mapping[str, Any], asserted: Any, field: str) -> str:
    computed = f"{prefix}:sha256:{sha256_json(material)}"
    if asserted is not None:
        if not isinstance(asserted, str) or _CONTENT_ID.fullmatch(asserted) is None:
            raise VariantIdentityMismatchError(f"{field} is not a content-addressed ID")
        if asserted != computed:
            raise VariantIdentityMismatchError(
                f"{field} mismatch: asserted {asserted!r}, computed {computed!r}"
            )
    return computed


def _registry_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _CONTENT_ID.fullmatch(value) is None
        or not value.startswith("registry:sha256:")
    ):
        raise VariantSelectionError(
            "portfolio_registry_id must be a registry:sha256 content identity"
        )
    return value


def _mount_context(value: Any, field: str) -> dict[str, Any]:
    item = _mapping(value, field)
    _exact_fields(item, {"mount_path", "priority"}, set(), field)
    priority = item["priority"]
    if (
        isinstance(priority, bool)
        or not isinstance(priority, int)
        or not -1_000_000 <= priority <= 1_000_000
    ):
        raise VariantSelectionError(f"{field}.priority must be an integer within hard bounds")
    return {
        "mount_path": canonical_relative_path(item["mount_path"]),
        "priority": priority,
    }


def _resources(value: Any, field: str) -> list[str]:
    resources = [
        canonical_relative_path(item)
        for item in _sequence(value, field, 4096, minimum=1)
    ]
    keys = [canonical_path_key(item) for item in resources]
    if len(keys) != len(set(keys)):
        raise VariantSelectionError(f"{field} contains duplicate canonical paths")
    return sorted(resources, key=canonical_path_key)


def _member(value: Any, field: str) -> dict[str, Any]:
    item = _mapping(value, field)
    _exact_fields(
        item,
        {"artifact_sha256", "mount_context", "provided_resources", "selector"},
        {"member_id"},
        field,
    )
    selector = item["selector"]
    if selector is not None:
        selector = _string(selector, f"{field}.selector", 128)
    material = {
        "artifact_sha256": _digest(item["artifact_sha256"], f"{field}.artifact_sha256"),
        "mount_context": _mount_context(item["mount_context"], f"{field}.mount_context"),
        "provided_resources": _resources(
            item["provided_resources"], f"{field}.provided_resources"
        ),
        "selector": selector,
    }
    return {
        "member_id": _content_id(
            "variant-member", material, item.get("member_id"), f"{field}.member_id"
        ),
        **material,
    }


def _selected_ids(
    item: Mapping[str, Any], members: list[dict[str, Any]], field: str
) -> list[str]:
    if "selected_member_indexes" in item:
        indexes = list(
            _sequence(item["selected_member_indexes"], f"{field}.selected_member_indexes", 4096)
        )
        if any(isinstance(index, bool) or not isinstance(index, int) for index in indexes):
            raise VariantSelectionError(
                f"{field}.selected_member_indexes must contain integers"
            )
        if len(indexes) != len(set(indexes)):
            raise VariantSelectionError(f"{field}.selected_member_indexes must be unique")
        if any(index < 0 or index >= len(members) for index in indexes):
            raise VariantSelectionError(f"{field}.selected_member_indexes is out of range")
        return sorted(members[index]["member_id"] for index in indexes)

    selected = [
        _string(value, f"{field}.selected_member_ids[{index}]", 128)
        for index, value in enumerate(
            _sequence(item["selected_member_ids"], f"{field}.selected_member_ids", 4096)
        )
    ]
    if len(selected) != len(set(selected)):
        raise VariantSelectionError(f"{field}.selected_member_ids must be unique")
    known = {member["member_id"] for member in members}
    if not set(selected) <= known:
        raise VariantSelectionError(f"{field}.selected_member_ids contains an unknown member")
    return sorted(selected)


def _enforce_rule(
    rule: str, members: list[dict[str, Any]], selected: list[str], field: str
) -> None:
    selected_count = len(selected)
    if rule in {"EXACTLY_ONE", "LANGUAGE", "PLATFORM", "PRESET"} and selected_count != 1:
        raise VariantSelectionError(f"{field} rule {rule} requires exactly one member")
    if rule == "ZERO_OR_ONE" and selected_count > 1:
        raise VariantSelectionError(f"{field} rule ZERO_OR_ONE permits at most one member")
    if rule == "ALL_REQUIRED" and selected_count != len(members):
        raise VariantSelectionError(f"{field} rule ALL_REQUIRED requires every member")

    selectors = [member["selector"] for member in members]
    if rule in SEMANTIC_RULES:
        if any(selector is None for selector in selectors):
            raise VariantSelectionError(f"{field} rule {rule} requires a selector on every member")
        normalized = [selector.casefold() for selector in selectors]
        if len(normalized) != len(set(normalized)):
            raise VariantSelectionError(f"{field} rule {rule} requires unique selectors")
    elif any(selector is not None for selector in selectors):
        raise VariantSelectionError(f"{field} rule {rule} does not accept semantic selectors")


def _group(value: Any, index: int) -> dict[str, Any]:
    field = f"groups[{index}]"
    item = _mapping(value, field)
    selection_fields = {"selected_member_indexes", "selected_member_ids"} & set(item)
    if len(selection_fields) != 1:
        raise VariantSelectionError(
            f"{field} must contain exactly one of selected_member_indexes or selected_member_ids"
        )
    _exact_fields(
        item,
        {"rule", "members", next(iter(selection_fields))},
        {"group_id"},
        field,
    )
    rule = item["rule"]
    if rule not in RULES:
        raise VariantSelectionError(f"{field}.rule is not supported")
    members = [
        _member(member, f"{field}.members[{position}]")
        for position, member in enumerate(
            _sequence(item["members"], f"{field}.members", 4096, minimum=1)
        )
    ]
    member_ids = [member["member_id"] for member in members]
    if len(member_ids) != len(set(member_ids)):
        raise VariantSelectionError(f"{field}.members contains duplicate identities")
    selected = _selected_ids(item, members, field)
    _enforce_rule(rule, members, selected, field)
    members.sort(key=lambda member: member["member_id"])
    material = {"rule": rule, "member_ids": sorted(member_ids)}
    return {
        "group_id": _content_id(
            "variant-group", material, item.get("group_id"), f"{field}.group_id"
        ),
        "rule": rule,
        "members": members,
        "selected_member_ids": selected,
    }


def _normalize(value: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(
        value,
        {"schema_version", "portfolio_registry_id", "groups"},
        {"selection_id", "validation"},
        "variant selection",
    )
    if value["schema_version"] != SCHEMA_VERSION:
        raise VariantSelectionError(f"schema_version must be {SCHEMA_VERSION}")
    if value.get("validation", "VALID") != "VALID":
        raise VariantSelectionError("only successfully validated selections can be receipted")
    registry_id = _registry_id(value["portfolio_registry_id"])
    groups = [
        _group(group, index)
        for index, group in enumerate(
            _sequence(value["groups"], "groups", 1024, minimum=1)
        )
    ]
    group_ids = [group["group_id"] for group in groups]
    if len(group_ids) != len(set(group_ids)):
        raise VariantSelectionError("groups contains duplicate identities")
    groups.sort(key=lambda group: group["group_id"])
    material = {
        "schema_version": SCHEMA_VERSION,
        "portfolio_registry_id": registry_id,
        "selections": [
            {
                "group_id": group["group_id"],
                "selected_member_ids": group["selected_member_ids"],
            }
            for group in groups
        ],
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "selection_id": _content_id(
            "variant-selection", material, value.get("selection_id"), "selection_id"
        ),
        "portfolio_registry_id": registry_id,
        "groups": groups,
        "validation": "VALID",
    }


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class VariantSelectionReceipt:
    """Deeply immutable receipt for one valid, identity-bound selected set."""

    _value: Mapping[str, Any]

    @property
    def selection_id(self) -> str:
        return self._value["selection_id"]

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(_plain(self._value))

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.to_dict())


def validate_variant_selection(
    value: Mapping[str, Any] | VariantSelectionReceipt,
) -> VariantSelectionReceipt:
    """Validate all group rules and return a canonical selection receipt."""
    if isinstance(value, VariantSelectionReceipt):
        return value
    return VariantSelectionReceipt(_freeze(_normalize(_mapping(value, "variant selection"))))
