"""Version-bound KCD2 table profiles and bounded record contribution extraction."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from kcd2_toolchain_core.paths import canonical_path_key, canonical_relative_path

from .source_resolution import StructuredTokenAudit


_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")
_MAX_TEXT = 1024
_MAX_PROFILES = 4096
_MAX_PATTERNS = 64
_MAX_RECORD_PATH = 32
_MAX_KEYS = 16
_MAX_DOCUMENTS = 256
_MAX_XML_BYTES = 4 * 1024 * 1024
_MAX_TOTAL_XML_BYTES = 16 * 1024 * 1024
_MAX_ELEMENTS = 100_000
_MAX_RECORDS = 20_000
_MAX_ATTRIBUTES = 256
_MAX_DEPTH = 64
_MAX_ELEMENT_TEXT = 8192

_TABLE_TYPES = frozenset(
    {
        "old",
        "new",
        "unsupported_replace_only",
        "do_not_change",
        "unused",
        "unknown",
    }
)
_PATCH_BEHAVIORS = frozenset(
    {
        "full_row_required",
        "partial_row_merge",
        "replace_whole_file",
        "not_supported",
        "unknown",
    }
)
_OMISSION_BEHAVIORS = frozenset(
    {"preserve_previous", "remove_previous", "invalid", "unknown"}
)
_LIST_BEHAVIORS = frozenset(
    {"append", "per_item_patch", "replace", "not_applicable", "unknown"}
)
_TBL_REQUIREMENTS = frozenset(
    {
        "TBL_REQUIRED_AND_MATCHED",
        "TBL_NOT_REQUIRED_WITH_EVIDENCE",
        "TBL_REQUIREMENT_UNKNOWN",
    }
)


class TableSemanticsError(ValueError):
    """Profile or exact-provider evidence cannot support a table conclusion."""


def _text(value: object, name: str, *, maximum: int = _MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise TableSemanticsError(
            f"{name} must be a non-empty NUL-free string of at most {maximum} characters"
        )
    return value


def _plain_index(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 2**31 - 1:
        raise TableSemanticsError(
            f"{name} must be an integer from 0 through 2^31-1"
        )
    return value


def _xml_value(value: object, name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise TableSemanticsError(
            f"{name} must be a NUL-free string of at most {maximum} characters"
        )
    return value


def _bounded_sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise TableSemanticsError(f"{name} must be an array")
    if len(value) > maximum:
        raise TableSemanticsError(f"{name} exceeds the {maximum}-item hard bound")
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
        raise TableSemanticsError("table result must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _exact_fields(value: Mapping[str, object], expected: set[str], name: str) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise TableSemanticsError(f"{name} fields do not match the input contract")


def _string_sequence(
    value: object,
    name: str,
    maximum: int,
    *,
    allow_empty: bool = False,
    require_unique: bool = True,
) -> tuple[str, ...]:
    items = _bounded_sequence(value, name, maximum)
    if not allow_empty and not items:
        raise TableSemanticsError(f"{name} must not be empty")
    checked = tuple(_text(item, f"{name} item") for item in items)
    if require_unique and len({item.casefold() for item in checked}) != len(checked):
        raise TableSemanticsError(f"{name} values must be case-insensitively unique")
    return checked


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


@dataclass(frozen=True, slots=True)
class TableSemanticsProfile:
    """One exact-build profile containing only reviewed table behavior."""

    profile_id: str
    game_build: str
    source_build: str
    table_name: str
    path_patterns: tuple[str, ...]
    record_path: tuple[str, ...]
    table_type: str
    primary_keys: tuple[str, ...]
    patch_behavior: str
    omission_behavior: str
    list_behavior: str
    case_sensitive: bool
    schema_paths: tuple[str, ...]
    reference_fields: tuple[Mapping[str, str], ...]
    tbl_requirement: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "TableSemanticsProfile":
        expected = {
            "schema_version",
            "profile_id",
            "game_build",
            "source_build",
            "table_name",
            "path_patterns",
            "record_path",
            "table_type",
            "primary_keys",
            "patch_behavior",
            "omission_behavior",
            "list_behavior",
            "case_sensitive",
            "schema_paths",
            "reference_fields",
            "tbl_requirement",
        }
        _exact_fields(value, expected, "profile")
        if value["schema_version"] != "kcd2.table-semantics-profile.v1":
            raise TableSemanticsError("unsupported table-semantics profile version")

        patterns = _string_sequence(value["path_patterns"], "path_patterns", _MAX_PATTERNS)
        for pattern in patterns:
            try:
                canonical_relative_path(pattern)
            except (TypeError, ValueError) as exc:
                raise TableSemanticsError("path_patterns must contain relative paths") from exc
        record_path = _string_sequence(
            value["record_path"],
            "record_path",
            _MAX_RECORD_PATH,
            require_unique=False,
        )
        primary_keys = _string_sequence(value["primary_keys"], "primary_keys", _MAX_KEYS)
        schema_paths = _string_sequence(
            value["schema_paths"], "schema_paths", _MAX_PATTERNS, allow_empty=True
        )

        reference_values = _bounded_sequence(
            value["reference_fields"], "reference_fields", 256
        )
        references: list[Mapping[str, str]] = []
        for item in reference_values:
            if not isinstance(item, Mapping):
                raise TableSemanticsError("reference_fields items must be objects")
            _exact_fields(item, {"field", "target_family"}, "reference field")
            references.append(
                {
                    "field": _text(item["field"], "reference field.field"),
                    "target_family": _text(
                        item["target_family"], "reference field.target_family"
                    ),
                }
            )

        table_type = value["table_type"]
        patch_behavior = value["patch_behavior"]
        omission_behavior = value["omission_behavior"]
        list_behavior = value["list_behavior"]
        tbl_requirement = value["tbl_requirement"]
        if table_type not in _TABLE_TYPES:
            raise TableSemanticsError("table_type is not supported")
        if patch_behavior not in _PATCH_BEHAVIORS:
            raise TableSemanticsError("patch_behavior is not supported")
        if omission_behavior not in _OMISSION_BEHAVIORS:
            raise TableSemanticsError("omission_behavior is not supported")
        if list_behavior not in _LIST_BEHAVIORS:
            raise TableSemanticsError("list_behavior is not supported")
        if tbl_requirement not in _TBL_REQUIREMENTS:
            raise TableSemanticsError("tbl_requirement is not supported")
        if not isinstance(value["case_sensitive"], bool):
            raise TableSemanticsError("case_sensitive must be a boolean")
        if table_type == "old" and (
            patch_behavior != "full_row_required" or omission_behavior != "invalid"
        ):
            raise TableSemanticsError(
                "old table profiles must require full rows and mark omission invalid"
            )
        if table_type == "new" and patch_behavior == "partial_row_merge" and (
            omission_behavior != "preserve_previous"
        ):
            raise TableSemanticsError(
                "partial-row new table profiles must preserve omitted properties"
            )

        return cls(
            profile_id=_text(value["profile_id"], "profile_id"),
            game_build=_text(value["game_build"], "game_build"),
            source_build=_text(value["source_build"], "source_build"),
            table_name=_text(value["table_name"], "table_name"),
            path_patterns=patterns,
            record_path=record_path,
            table_type=table_type,  # type: ignore[arg-type]
            primary_keys=primary_keys,
            patch_behavior=patch_behavior,  # type: ignore[arg-type]
            omission_behavior=omission_behavior,  # type: ignore[arg-type]
            list_behavior=list_behavior,  # type: ignore[arg-type]
            case_sensitive=value["case_sensitive"],  # type: ignore[arg-type]
            schema_paths=schema_paths,
            reference_fields=tuple(references),
            tbl_requirement=tbl_requirement,  # type: ignore[arg-type]
        )

    @property
    def resolution_supported(self) -> bool:
        old_supported = (
            self.table_type == "old"
            and self.patch_behavior == "full_row_required"
            and self.omission_behavior == "invalid"
        )
        new_supported = (
            self.table_type == "new"
            and self.patch_behavior == "partial_row_merge"
            and self.omission_behavior == "preserve_previous"
        )
        return old_supported or new_supported


@dataclass(frozen=True, slots=True)
class TableSemanticsRegistry:
    """Deterministic registry selected by exact build identity and canonical path."""

    profiles: tuple[TableSemanticsProfile, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "TableSemanticsRegistry":
        _exact_fields(value, {"schema_version", "profiles"}, "registry")
        if value["schema_version"] != "kcd2.table-semantics-registry.v1":
            raise TableSemanticsError("unsupported table-semantics registry version")
        items = _bounded_sequence(value["profiles"], "profiles", _MAX_PROFILES)
        profiles = tuple(
            TableSemanticsProfile.from_mapping(item)
            for item in items
            if isinstance(item, Mapping)
        )
        if len(profiles) != len(items):
            raise TableSemanticsError("profiles must contain objects")
        identifiers = [profile.profile_id.casefold() for profile in profiles]
        if len(identifiers) != len(set(identifiers)):
            raise TableSemanticsError("profile_id values must be case-insensitively unique")
        return cls(profiles=tuple(sorted(profiles, key=lambda item: item.profile_id.casefold())))

    def resolve(
        self, *, game_build: str, source_build: str, canonical_path: str
    ) -> TableSemanticsProfile:
        checked_game = _text(game_build, "game_build")
        checked_source = _text(source_build, "source_build")
        try:
            path = canonical_relative_path(canonical_path)
        except (TypeError, ValueError) as exc:
            raise TableSemanticsError("canonical_path must be a relative path") from exc
        path_key = path.casefold()
        matches = [
            profile
            for profile in self.profiles
            if profile.game_build == checked_game
            and profile.source_build == checked_source
            and any(
                fnmatch.fnmatchcase(path_key, pattern.casefold())
                for pattern in profile.path_patterns
            )
        ]
        if not matches:
            raise TableSemanticsError(
                "no table profile matches the exact game/source build and path"
            )
        if len(matches) != 1:
            raise TableSemanticsError(
                "multiple table profiles match the exact game/source build and path"
            )
        return matches[0]


@dataclass(frozen=True, slots=True)
class ExactTableDocument:
    """One exact, active provider document bound to source and content identity."""

    provider_id: str
    provider_kind: str
    load_order_index: int
    source_path: str
    member_or_loose_path: str
    content_sha256: str
    game_build: str
    source_build: str
    active: bool
    xml_text: str

    def __post_init__(self) -> None:
        _text(self.provider_id, "provider_id")
        _text(self.provider_kind, "provider_kind")
        _plain_index(self.load_order_index, "load_order_index")
        _text(self.source_path, "source_path")
        try:
            canonical_relative_path(self.member_or_loose_path)
        except (TypeError, ValueError) as exc:
            raise TableSemanticsError(
                "member_or_loose_path must be a canonical relative path"
            ) from exc
        if not isinstance(self.content_sha256, str) or _SHA256.fullmatch(
            self.content_sha256
        ) is None:
            raise TableSemanticsError("content_sha256 must be a SHA-256 digest")
        _text(self.game_build, "document.game_build")
        _text(self.source_build, "document.source_build")
        if not isinstance(self.active, bool):
            raise TableSemanticsError("active must be a boolean")
        if not isinstance(self.xml_text, str):
            raise TableSemanticsError("xml_text must be a string")
        if len(self.xml_text.encode("utf-8")) > _MAX_XML_BYTES:
            raise TableSemanticsError(
                f"xml_text exceeds the {_MAX_XML_BYTES}-byte hard bound"
            )


@dataclass(frozen=True, slots=True)
class TableRecordContributionSet:
    """Immutable, schema-ready result for one exact table path."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class TableSemanticComparison:
    """Immutable exact-provider semantic comparison result."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _element_payload(element: ET.Element, depth: int, counters: dict[str, int]) -> dict[str, Any]:
    if depth > _MAX_DEPTH:
        raise TableSemanticsError(f"XML nesting exceeds the {_MAX_DEPTH}-level hard bound")
    counters["elements"] += 1
    if counters["elements"] > _MAX_ELEMENTS:
        raise TableSemanticsError(f"XML exceeds the {_MAX_ELEMENTS}-element hard bound")
    if len(element.attrib) > _MAX_ATTRIBUTES:
        raise TableSemanticsError(
            f"XML element exceeds the {_MAX_ATTRIBUTES}-attribute hard bound"
        )
    text = (element.text or "").strip()
    if len(text) > _MAX_ELEMENT_TEXT:
        raise TableSemanticsError(
            f"XML element text exceeds the {_MAX_ELEMENT_TEXT}-character hard bound"
        )
    element_name = _text(_local_name(element.tag), "XML element name", maximum=256)
    attributes = []
    for name, value in element.attrib.items():
        attributes.append(
            {
                "name": _text(_local_name(name), "XML attribute name", maximum=256),
                "value": _xml_value(
                    value, "XML attribute value", maximum=_MAX_ELEMENT_TEXT
                ),
            }
        )
    return {
        "element": element_name,
        "attributes": [
            dict(item) for item in attributes
        ],
        "text": text or None,
        "children": [
            _element_payload(child, depth + 1, counters) for child in list(element)
        ],
    }


def _normalized_element_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize lexical XML variation while preserving meaningful child order."""

    return {
        "element": payload["element"],
        "attributes": sorted(
            (dict(item) for item in payload["attributes"]),
            key=lambda item: (item["name"].casefold(), item["name"], item["value"]),
        ),
        "text": payload.get("text"),
        "children": [
            _normalized_element_payload(child) for child in payload["children"]
        ],
    }


def _record_elements(root: ET.Element, path: tuple[str, ...]) -> list[ET.Element]:
    if _local_name(root.tag) != path[0]:
        return []
    current = [root]
    for expected in path[1:]:
        current = [
            child
            for parent in current
            for child in list(parent)
            if _local_name(child.tag) == expected
        ]
    return current


def _parse_records(
    document: ExactTableDocument,
    profile: TableSemanticsProfile,
    contribution_start: int,
) -> tuple[list[dict[str, Any]], int]:
    upper = document.xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise TableSemanticsError("DTD and entity declarations are not supported")
    try:
        root = ET.fromstring(document.xml_text)
    except ET.ParseError as exc:
        raise TableSemanticsError(
            f"provider {document.provider_id!r} contains malformed XML"
        ) from exc
    records = _record_elements(root, profile.record_path)
    if len(records) > _MAX_RECORDS:
        raise TableSemanticsError(f"XML exceeds the {_MAX_RECORDS}-record hard bound")
    counters = {"elements": 0}
    contributions: list[dict[str, Any]] = []
    for record_index, record in enumerate(records):
        payload = _element_payload(record, 1, counters)
        attributes = payload["attributes"]
        attribute_lookup = {item["name"]: item["value"] for item in attributes}
        key_values: list[dict[str, str]] = []
        missing: list[str] = []
        for key_name in profile.primary_keys:
            value = attribute_lookup.get(key_name)
            if value is None:
                missing.append(key_name)
            else:
                key_values.append({"name": key_name, "value": value})
        reason_codes = ["MISSING_PRIMARY_KEY"] if missing else []
        contributions.append(
            {
                "contribution_index": contribution_start + record_index,
                "provider_id": document.provider_id,
                "provider_kind": document.provider_kind,
                "load_order_index": document.load_order_index,
                "source_path": document.source_path,
                "member_or_loose_path": canonical_relative_path(
                    document.member_or_loose_path
                ),
                "content_sha256": document.content_sha256.lower(),
                "record_index": record_index,
                "record_element": payload["element"],
                "record_key": key_values,
                "attributes": attributes,
                "nested_children": payload["children"],
                "resolution_state": "unresolved" if missing else "contributes",
                "reason_codes": reason_codes,
            }
        )
    return contributions, counters["elements"]


def _record_key(
    contribution: Mapping[str, Any], *, case_sensitive: bool
) -> tuple[tuple[str, str], ...] | None:
    values = contribution["record_key"]
    if not values:
        return None
    if case_sensitive:
        return tuple((item["name"], item["value"]) for item in values)
    return tuple((item["name"].casefold(), item["value"].casefold()) for item in values)


def _merge_effective_records(
    contributions: list[dict[str, Any]], profile: TableSemanticsProfile
) -> tuple[list[dict[str, Any]], list[str]]:
    effective: dict[tuple[tuple[str, str], ...], dict[str, Any]] = {}
    ordering: list[tuple[tuple[str, str], ...]] = []
    reasons: set[str] = set()
    seen_per_provider: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    for contribution in contributions:
        key = _record_key(contribution, case_sensitive=profile.case_sensitive)
        if key is None:
            reasons.add("MISSING_PRIMARY_KEY")
            continue
        provider_record = (contribution["provider_id"].casefold(), key)
        if provider_record in seen_per_provider:
            contribution["resolution_state"] = "unresolved"
            contribution["reason_codes"].append("AMBIGUOUS_DUPLICATE_RECORD")
            reasons.add("AMBIGUOUS_DUPLICATE_RECORD")
            continue
        seen_per_provider.add(provider_record)

        current_attributes = [dict(item) for item in contribution["attributes"]]
        if key not in effective:
            ordering.append(key)
            effective[key] = {
                "record_key": _json_copy(contribution["record_key"]),
                "attributes": current_attributes,
                "nested_children": _json_copy(contribution["nested_children"]),
                "contributing_provider_ids": [contribution["provider_id"]],
                "resolution_state": "resolved",
                "reason_codes": [],
            }
            continue

        previous = effective[key]
        if _record_semantic_payload(previous) == _record_semantic_payload(contribution):
            previous["contributing_provider_ids"].append(contribution["provider_id"])
            continue
        previous_names = {item["name"] for item in previous["attributes"]}
        current_names = {item["name"] for item in current_attributes}
        previous["contributing_provider_ids"].append(contribution["provider_id"])

        if profile.table_type == "old":
            missing = sorted(previous_names - current_names, key=str.casefold)
            previous["attributes"] = current_attributes
            previous["nested_children"] = _json_copy(contribution["nested_children"])
            if missing:
                contribution["resolution_state"] = "unresolved"
                contribution["reason_codes"].append("OLD_TABLE_FULL_ROW_REQUIRED")
                previous["resolution_state"] = "unresolved"
                previous["reason_codes"].append("OLD_TABLE_FULL_ROW_REQUIRED")
                reasons.add("OLD_TABLE_FULL_ROW_REQUIRED")
            continue

        previous_by_name = {item["name"]: item for item in previous["attributes"]}
        for item in current_attributes:
            if item["name"] in previous_by_name:
                previous_by_name[item["name"]]["value"] = item["value"]
            else:
                previous["attributes"].append(item)
        old_children = previous["nested_children"]
        new_children = contribution["nested_children"]
        if profile.list_behavior == "append":
            previous["nested_children"] = old_children + _json_copy(new_children)
        elif profile.list_behavior == "replace":
            previous["nested_children"] = _json_copy(new_children)
        elif new_children and old_children and profile.list_behavior == "per_item_patch":
            contribution["resolution_state"] = "unresolved"
            contribution["reason_codes"].append("NESTED_CHILD_SEMANTICS_UNPROVEN")
            previous["resolution_state"] = "unresolved"
            previous["reason_codes"].append("NESTED_CHILD_SEMANTICS_UNPROVEN")
            reasons.add("NESTED_CHILD_SEMANTICS_UNPROVEN")
        elif profile.list_behavior == "per_item_patch" and new_children:
            previous["nested_children"] = _json_copy(new_children)
        elif profile.list_behavior in {"unknown", "not_applicable"} and (
            old_children or new_children
        ):
            contribution["resolution_state"] = "unresolved"
            contribution["reason_codes"].append("NESTED_CHILD_SEMANTICS_UNPROVEN")
            previous["resolution_state"] = "unresolved"
            previous["reason_codes"].append("NESTED_CHILD_SEMANTICS_UNPROVEN")
            reasons.add("NESTED_CHILD_SEMANTICS_UNPROVEN")

    return [effective[key] for key in ordering], sorted(reasons)


def extract_table_record_contributions(
    *,
    query_id: str,
    registry: TableSemanticsRegistry,
    game_build: str,
    source_build: str,
    canonical_path: str,
    documents: Sequence[ExactTableDocument],
) -> TableRecordContributionSet:
    """Extract ordered structural records and apply only profile-proven semantics."""

    checked_query = _text(query_id, "query_id")
    if not isinstance(registry, TableSemanticsRegistry):
        raise TableSemanticsError("registry must be a TableSemanticsRegistry")
    profile = registry.resolve(
        game_build=game_build,
        source_build=source_build,
        canonical_path=canonical_path,
    )
    path = canonical_relative_path(canonical_path)
    items = _bounded_sequence(documents, "documents", _MAX_DOCUMENTS)
    if any(not isinstance(item, ExactTableDocument) for item in items):
        raise TableSemanticsError("documents must contain ExactTableDocument values")

    provider_ids: set[str] = set()
    order_indices: set[int] = set()
    checked_documents: list[ExactTableDocument] = []
    total_xml_bytes = 0
    for document in items:
        assert isinstance(document, ExactTableDocument)
        if not document.active:
            raise TableSemanticsError("every table document must be an exact active provider")
        if document.game_build != game_build or document.source_build != source_build:
            raise TableSemanticsError("table document build identity does not match the query")
        if canonical_path_key(document.member_or_loose_path) != canonical_path_key(path):
            raise TableSemanticsError("table document path does not match the query")
        digest = hashlib.sha256(document.xml_text.encode("utf-8")).hexdigest()
        if digest != document.content_sha256.casefold():
            raise TableSemanticsError("table document content does not match content_sha256")
        total_xml_bytes += len(document.xml_text.encode("utf-8"))
        if total_xml_bytes > _MAX_TOTAL_XML_BYTES:
            raise TableSemanticsError(
                f"provider XML exceeds the {_MAX_TOTAL_XML_BYTES}-byte total hard bound"
            )
        provider_key = document.provider_id.casefold()
        if provider_key in provider_ids:
            raise TableSemanticsError("provider_id values must be case-insensitively unique")
        if document.load_order_index in order_indices:
            raise TableSemanticsError("load_order_index values must be unique")
        provider_ids.add(provider_key)
        order_indices.add(document.load_order_index)
        checked_documents.append(document)
    checked_documents.sort(key=lambda item: item.load_order_index)
    provider_documents = [
        {
            "provider_id": item.provider_id,
            "provider_kind": item.provider_kind,
            "load_order_index": item.load_order_index,
            "source_path": item.source_path,
            "member_or_loose_path": canonical_relative_path(
                item.member_or_loose_path
            ),
            "content_sha256": item.content_sha256.lower(),
            "game_build": item.game_build,
            "source_build": item.source_build,
        }
        for item in checked_documents
    ]

    contributions: list[dict[str, Any]] = []
    element_count = 0
    empty_record_documents: list[str] = []
    for document in checked_documents:
        parsed, count = _parse_records(document, profile, len(contributions))
        if not parsed:
            empty_record_documents.append(document.provider_id)
        element_count += count
        if len(contributions) + len(parsed) > _MAX_RECORDS:
            raise TableSemanticsError(
                f"provider set exceeds the {_MAX_RECORDS}-record hard bound"
            )
        if element_count > _MAX_ELEMENTS:
            raise TableSemanticsError(
                f"provider set exceeds the {_MAX_ELEMENTS}-element hard bound"
            )
        contributions.extend(parsed)

    if profile.resolution_supported:
        effective, reason_codes = _merge_effective_records(contributions, profile)
    else:
        effective = []
        reason_codes = ["UNSUPPORTED_TABLE_SEMANTICS"]
        for contribution in contributions:
            contribution["resolution_state"] = "unresolved"
            contribution["reason_codes"] = sorted(
                set(contribution["reason_codes"] + reason_codes)
            )
    if not checked_documents:
        reason_codes.append("NO_ACTIVE_PROVIDER_DOCUMENTS")
    if empty_record_documents:
        reason_codes.append("RECORD_PATH_NOT_FOUND")
    reason_codes = sorted(set(reason_codes))
    capture_inconclusive = bool(
        {"NO_ACTIVE_PROVIDER_DOCUMENTS", "RECORD_PATH_NOT_FOUND"}.intersection(
            reason_codes
        )
    )
    unresolved = bool(reason_codes) or any(
        item["resolution_state"] == "unresolved" for item in contributions
    )
    payload = {
        "schema_version": "kcd2.table-record-contribution-set.v1",
        "query_id": checked_query,
        "canonical_path": path,
        "profile_id": profile.profile_id,
        "game_build": profile.game_build,
        "source_build": profile.source_build,
        "input_sha256": hashlib.sha256(
            _canonical_bytes(
                {
                    "profile_id": profile.profile_id,
                    "canonical_path": path,
                    "provider_documents": provider_documents,
                }
            )
        ).hexdigest(),
        "table_type": profile.table_type,
        "semantics_status": (
            "capture_inconclusive"
            if capture_inconclusive
            else "unresolved"
            if unresolved
            else "resolved"
        ),
        "reason_codes": reason_codes,
        "provider_documents": provider_documents,
        "contributions": contributions,
        "effective_records": effective,
    }
    return TableRecordContributionSet(payload=_json_copy(payload))


def _attributes_by_name(record: Mapping[str, Any]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in record["attributes"]}


def _comparison_key(
    record: Mapping[str, Any], profile: TableSemanticsProfile
) -> tuple[tuple[str, str], ...]:
    key = _record_key(record, case_sensitive=profile.case_sensitive)
    if key is None:
        raise TableSemanticsError("semantic comparison requires complete primary keys")
    return key


def _record_semantic_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "attributes": sorted(
            (dict(item) for item in record["attributes"]),
            key=lambda item: (item["name"].casefold(), item["name"], item["value"]),
        ),
        "nested_children": [
            _normalized_element_payload(child) for child in record["nested_children"]
        ],
    }


def _exact_source(document: ExactTableDocument, role: str) -> dict[str, Any]:
    return {
        "comparison_role": role,
        "provider_id": document.provider_id,
        "provider_kind": document.provider_kind,
        "load_order_index": document.load_order_index,
        "source_path": document.source_path,
        "member_or_loose_path": canonical_relative_path(document.member_or_loose_path),
        "content_sha256": document.content_sha256.casefold(),
        "game_build": document.game_build,
        "source_build": document.source_build,
    }


def _attribute_changes(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    old = _attributes_by_name(baseline)
    new = _attributes_by_name(candidate)
    names = sorted(set(old) | set(new), key=lambda item: (item.casefold(), item))
    return [
        {"name": name, "old": old.get(name), "new": new.get(name)}
        for name in names
        if old.get(name) != new.get(name)
    ]


def _child_changes(
    baseline: Mapping[str, Any], candidate: Mapping[str, Any]
) -> list[dict[str, Any]]:
    old = [_normalized_element_payload(item) for item in baseline["nested_children"]]
    new = [_normalized_element_payload(item) for item in candidate["nested_children"]]
    maximum = max(len(old), len(new))
    changes: list[dict[str, Any]] = []
    for index in range(maximum):
        previous = old[index] if index < len(old) else None
        current = new[index] if index < len(new) else None
        if previous != current:
            changes.append(
                {
                    "child_index": index,
                    "change_kind": (
                        "added" if previous is None else "removed" if current is None else "changed"
                    ),
                    "old": previous,
                    "new": current,
                }
            )
    return changes


def _reference_changes(
    baseline: Mapping[str, Any],
    candidate: Mapping[str, Any],
    profile: TableSemanticsProfile,
) -> list[dict[str, Any]]:
    old = _attributes_by_name(baseline)
    new = _attributes_by_name(candidate)
    changes: list[dict[str, Any]] = []
    for definition in sorted(
        profile.reference_fields,
        key=lambda item: (item["field"].casefold(), item["target_family"].casefold()),
    ):
        field = definition["field"]
        previous = old.get(field)
        current = new.get(field)
        if previous == current:
            continue
        changes.append(
            {
                "field": field,
                "target_family": definition["target_family"],
                "old": previous,
                "new": current,
                "change_kind": (
                    "added"
                    if previous is None
                    else "removed"
                    if current is None
                    else "retargeted"
                ),
            }
        )
    return changes


def _semantic_change(
    key: tuple[tuple[str, str], ...],
    baseline: Mapping[str, Any] | None,
    candidate: Mapping[str, Any] | None,
    profile: TableSemanticsProfile,
) -> dict[str, Any]:
    if baseline is None:
        kind = "added"
    elif candidate is None:
        kind = "removed"
    else:
        kind = "changed"
    empty = {"attributes": [], "nested_children": []}
    old = baseline or empty
    new = candidate or empty
    return {
        "record_key": [{"name": name, "value": value} for name, value in key],
        "change_kind": kind,
        "attribute_changes": _attribute_changes(old, new),
        "child_changes": _child_changes(old, new),
        "reference_changes": _reference_changes(old, new, profile),
    }


def compare_table_semantics(
    *,
    query_id: str,
    registry: TableSemanticsRegistry,
    game_build: str,
    source_build: str,
    canonical_path: str,
    vanilla_document: ExactTableDocument,
    dependency_documents: Sequence[ExactTableDocument],
    candidate_document: ExactTableDocument,
    search_consistency: StructuredTokenAudit | None = None,
) -> TableSemanticComparison:
    """Compare one candidate with exact vanilla and ordered dependency semantics.

    Lexical XML differences are reported separately. Structured/token search
    disagreement always makes the comparison inconclusive and can never support
    an absence claim.
    """

    checked_query = _text(query_id, "query_id")
    if not isinstance(vanilla_document, ExactTableDocument) or not isinstance(
        candidate_document, ExactTableDocument
    ):
        raise TableSemanticsError("vanilla and candidate must be ExactTableDocument values")
    dependencies = _bounded_sequence(
        dependency_documents, "dependency_documents", _MAX_DOCUMENTS - 2
    )
    if any(not isinstance(item, ExactTableDocument) for item in dependencies):
        raise TableSemanticsError("dependency_documents must contain ExactTableDocument values")
    if search_consistency is not None and not isinstance(
        search_consistency, StructuredTokenAudit
    ):
        raise TableSemanticsError("search_consistency must be a StructuredTokenAudit")

    profile = registry.resolve(
        game_build=game_build,
        source_build=source_build,
        canonical_path=canonical_path,
    )
    baseline_documents = (vanilla_document, *dependencies)
    all_documents = (*baseline_documents, candidate_document)
    provider_ids = [item.provider_id.casefold() for item in all_documents]
    order_indices = [item.load_order_index for item in all_documents]
    if len(provider_ids) != len(set(provider_ids)):
        raise TableSemanticsError("comparison provider IDs must be unique")
    if len(order_indices) != len(set(order_indices)) or order_indices != sorted(order_indices):
        raise TableSemanticsError(
            "comparison providers must have unique ascending load-order indices"
        )
    baseline = extract_table_record_contributions(
        query_id=f"{checked_query}:baseline",
        registry=registry,
        game_build=game_build,
        source_build=source_build,
        canonical_path=canonical_path,
        documents=baseline_documents,
    ).to_dict()
    candidate = extract_table_record_contributions(
        query_id=f"{checked_query}:candidate",
        registry=registry,
        game_build=game_build,
        source_build=source_build,
        canonical_path=canonical_path,
        documents=(candidate_document,),
    ).to_dict()
    combined = extract_table_record_contributions(
        query_id=f"{checked_query}:combined",
        registry=registry,
        game_build=game_build,
        source_build=source_build,
        canonical_path=canonical_path,
        documents=all_documents,
    ).to_dict()

    baseline_records = {
        _comparison_key(item, profile): item for item in baseline["effective_records"]
    }
    candidate_records = {
        _comparison_key(item, profile): item for item in candidate["effective_records"]
    }
    semantic_changes: list[dict[str, Any]] = []
    changed_keys: set[tuple[tuple[str, str], ...]] = set()
    duplicated = 0
    for key in sorted(candidate_records):
        previous = baseline_records.get(key)
        current = candidate_records[key]
        if previous is not None and _record_semantic_payload(
            previous
        ) == _record_semantic_payload(current):
            duplicated += 1
            continue
        semantic_changes.append(_semantic_change(key, previous, current, profile))
        changed_keys.add(key)
    if profile.patch_behavior == "replace_whole_file":
        for key in sorted(set(baseline_records) - set(candidate_records)):
            semantic_changes.append(
                _semantic_change(key, baseline_records[key], None, profile)
            )
            changed_keys.add(key)

    formatting_only = False
    if not dependencies and not semantic_changes:
        formatting_only = (
            vanilla_document.xml_text != candidate_document.xml_text
            and len(candidate_records) == len(baseline_records)
            and all(
                _record_semantic_payload(baseline_records[key])
                == _record_semantic_payload(candidate_records[key])
                for key in baseline_records
            )
        )

    overlap = len(set(baseline_records) & set(candidate_records))
    shadow_ratio = overlap / len(baseline_records) if baseline_records else 0.0
    full_shadow = bool(baseline_records) and overlap == len(baseline_records)
    reasons = sorted(
        set(
            baseline["reason_codes"]
            + candidate["reason_codes"]
            + combined["reason_codes"]
        )
    )
    absence_claim_allowed = False
    search_payload = {
        "consistency": "not_evaluated",
        "result_status": "capture_inconclusive",
        "diagnostics": [],
    }
    if search_consistency is not None:
        absence_claim_allowed = search_consistency.absence_claim_allowed
        search_payload = {
            "consistency": search_consistency.consistency,
            "result_status": search_consistency.result_status,
            "diagnostics": [item.to_dict() for item in search_consistency.diagnostics],
        }
        if search_consistency.consistency == "disagreement":
            reasons.append("STRUCTURED_TOKEN_DISAGREEMENT")
            absence_claim_allowed = False

    capture_inconclusive = (
        baseline["semantics_status"] == "capture_inconclusive"
        or candidate["semantics_status"] == "capture_inconclusive"
        or combined["semantics_status"] == "capture_inconclusive"
        or (
            search_consistency is not None
            and search_consistency.result_status == "capture_inconclusive"
        )
    )
    unresolved = (
        baseline["semantics_status"] == "unresolved"
        or candidate["semantics_status"] == "unresolved"
        or combined["semantics_status"] == "unresolved"
    )
    exact_sources = [
        _exact_source(vanilla_document, "vanilla"),
        *(_exact_source(item, "dependency") for item in dependencies),
        _exact_source(candidate_document, "candidate"),
    ]
    payload = {
        "schema_version": "kcd2.table-semantic-comparison.v1",
        "query_id": checked_query,
        "canonical_path": canonical_relative_path(canonical_path),
        "profile_id": profile.profile_id,
        "game_build": game_build,
        "source_build": source_build,
        "comparison_status": (
            "capture_inconclusive"
            if capture_inconclusive
            else "unresolved"
            if unresolved
            else "resolved"
        ),
        "reason_codes": sorted(set(reasons)),
        "formatting_only": formatting_only,
        "formatting_changes": ["LEXICAL_XML_DIFF_ONLY"] if formatting_only else [],
        "schema_defects": [],
        "semantic_changes": sorted(
            semantic_changes,
            key=lambda item: _canonical_bytes(item["record_key"]),
        ),
        "exact_sources": exact_sources,
        "full_shadow_metrics": {
            "baseline_total_records": len(baseline_records),
            "candidate_total_records": len(candidate_records),
            "changed_records": len(changed_keys),
            "duplicated_records": duplicated,
            "shadow_ratio": round(shadow_ratio, 6),
            "full_file_shadow": full_shadow,
            "dependency_source_builds": sorted({item.source_build for item in dependencies}),
            "dependency_content_sha256": sorted(
                {item.content_sha256.casefold() for item in dependencies}
            ),
            "stale_shadow_risk": (
                "review_required" if full_shadow and dependencies else "none_observed"
            ),
        },
        "search_consistency": search_payload,
        "absence_claim_allowed": absence_claim_allowed,
        "input_sha256": hashlib.sha256(
            _canonical_bytes(
                {
                    "profile_id": profile.profile_id,
                    "canonical_path": canonical_relative_path(canonical_path),
                    "exact_sources": exact_sources,
                    "search_consistency": search_payload,
                }
            )
        ).hexdigest(),
    }
    return TableSemanticComparison(payload=_json_copy(payload))
