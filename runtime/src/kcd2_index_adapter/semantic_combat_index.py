"""Bounded immutable semantic index for ADB and compiled-table evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping


MAX_RECORDS = 500_000
MAX_RESULTS = 4096
MAX_COMPILED_OFFSET = (1 << 63) - 1
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}")
_KINDS = {"adb_fragment", "adb_timing", "adb_selector", "table_row", "compiled_offset", "pairing"}


class SemanticCombatIndexError(ValueError):
    """Semantic records or a query are ambiguous, malformed, or unbounded."""


@dataclass(frozen=True, slots=True)
class SemanticCombatRecord:
    record_id: str
    kind: str
    source_path: str
    semantic_key: str
    selector: tuple[tuple[str, str], ...]
    fragment_id: str | None
    row_key: str | None
    compiled_offset: int | None
    timing: tuple[tuple[str, float], ...]
    pairing: tuple[tuple[str, str], ...]
    evidence_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "kind": self.kind,
            "source_path": self.source_path,
            "semantic_key": self.semantic_key,
            "selector": dict(self.selector),
            "fragment_id": self.fragment_id,
            "row_key": self.row_key,
            "compiled_offset": self.compiled_offset,
            "timing": dict(self.timing),
            "pairing": dict(self.pairing),
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass(frozen=True, slots=True)
class SemanticCombatIndex:
    index_id: str
    records: tuple[SemanticCombatRecord, ...]

    def query(
        self,
        *,
        kind: str | None = None,
        source_path: str | None = None,
        semantic_key: str | None = None,
        selector: Mapping[str, str] | None = None,
        fragment_id: str | None = None,
        row_key: str | None = None,
        compiled_offset: int | None = None,
        pairing_role: str | None = None,
        max_results: int = 128,
    ) -> dict[str, Any]:
        if kind is not None and kind not in _KINDS:
            raise SemanticCombatIndexError("query kind is unsupported")
        if not isinstance(max_results, int) or isinstance(max_results, bool) or not 1 <= max_results <= MAX_RESULTS:
            raise SemanticCombatIndexError("max_results is outside its hard bound")
        canonical_path = None if source_path is None else _path(source_path)
        expected_selector = None if selector is None else _pairs(selector, "query selector")
        if compiled_offset is not None and (
            not isinstance(compiled_offset, int)
            or isinstance(compiled_offset, bool)
            or not 0 <= compiled_offset <= MAX_COMPILED_OFFSET
        ):
            raise SemanticCombatIndexError("query compiled_offset is invalid")
        matches: list[SemanticCombatRecord] = []
        for record in self.records:
            if kind is not None and record.kind != kind:
                continue
            if canonical_path is not None and record.source_path.casefold() != canonical_path.casefold():
                continue
            if semantic_key is not None and record.semantic_key != semantic_key:
                continue
            if expected_selector is not None and not set(expected_selector).issubset(record.selector):
                continue
            if fragment_id is not None and record.fragment_id != fragment_id:
                continue
            if row_key is not None and record.row_key != row_key:
                continue
            if compiled_offset is not None and record.compiled_offset != compiled_offset:
                continue
            if pairing_role is not None and dict(record.pairing).get("role") != pairing_role:
                continue
            matches.append(record)
        visible = matches[:max_results]
        return {
            "schema_version": "kcd2.semantic-combat-index-query.v1",
            "index_id": self.index_id,
            "status": "FOUND" if visible else "NOT_FOUND_IN_SUPPLIED_EVIDENCE",
            "match_count": len(matches),
            "records": [item.to_dict() for item in visible],
            "truncated": len(visible) < len(matches),
        }


def build_semantic_combat_index(records: Iterable[Mapping[str, Any]]) -> SemanticCombatIndex:
    material = list(records)
    if len(material) > MAX_RECORDS:
        raise SemanticCombatIndexError("semantic record count exceeds its hard bound")
    parsed = tuple(sorted((_record(item) for item in material), key=lambda item: item.record_id))
    if len({item.record_id for item in parsed}) != len(parsed):
        raise SemanticCombatIndexError("semantic record IDs must be unique")
    canonical = [item.to_dict() for item in parsed]
    digest = hashlib.sha256(
        json.dumps(canonical, allow_nan=False, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return SemanticCombatIndex("semantic-combat-index:sha256:" + digest, parsed)


def _record(value: Mapping[str, Any]) -> SemanticCombatRecord:
    if not isinstance(value, Mapping) or set(value) != {
        "record_id", "kind", "source_path", "semantic_key", "selector", "fragment_id",
        "row_key", "compiled_offset", "timing", "pairing", "evidence_sha256"
    }:
        raise SemanticCombatIndexError("semantic record fields are invalid")
    kind = value["kind"]
    if kind not in _KINDS:
        raise SemanticCombatIndexError("semantic record kind is unsupported")
    offset = value["compiled_offset"]
    if offset is not None and (
        not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= MAX_COMPILED_OFFSET
    ):
        raise SemanticCombatIndexError("compiled offset is invalid")
    timing = _timing(value["timing"])
    pairing = _pairing(value["pairing"])
    _kind_requirements(kind, value, timing, pairing)
    return SemanticCombatRecord(
        record_id=_identifier(value["record_id"], "record_id"),
        kind=kind,
        source_path=_path(value["source_path"]),
        semantic_key=_identifier(value["semantic_key"], "semantic_key"),
        selector=_pairs(value["selector"], "selector"),
        fragment_id=_optional_identifier(value["fragment_id"], "fragment_id"),
        row_key=_optional_identifier(value["row_key"], "row_key"),
        compiled_offset=offset,
        timing=timing,
        pairing=pairing,
        evidence_sha256=_digest(value["evidence_sha256"]),
    )


def _kind_requirements(kind: str, value: Mapping[str, Any], timing: tuple, pairing: tuple) -> None:
    if kind.startswith("adb_") and value["fragment_id"] is None:
        raise SemanticCombatIndexError("ADB records require fragment_id")
    if kind == "table_row" and value["row_key"] is None:
        raise SemanticCombatIndexError("table_row records require row_key")
    if kind == "compiled_offset" and (value["row_key"] is None or value["compiled_offset"] is None):
        raise SemanticCombatIndexError("compiled_offset records require row_key and offset")
    if kind == "adb_timing" and not timing:
        raise SemanticCombatIndexError("adb_timing records require timing fields")
    if kind == "pairing" and not pairing:
        raise SemanticCombatIndexError("pairing records require master/slave fields")


def _timing(value: object) -> tuple[tuple[str, float], ...]:
    if not isinstance(value, Mapping):
        raise SemanticCombatIndexError("timing must be an object")
    allowed = ("startup", "active", "withdrawal", "recovery")
    if any(key not in allowed for key in value):
        raise SemanticCombatIndexError("timing field is unsupported")
    result = []
    prior = -1.0
    for key in allowed:
        if key not in value:
            continue
        number = value[key]
        if not isinstance(number, (int, float)) or isinstance(number, bool) or not math.isfinite(number) or number < prior:
            raise SemanticCombatIndexError("timing values must be finite and monotonic")
        prior = float(number)
        result.append((key, float(number)))
    return tuple(result)


def _pairing(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise SemanticCombatIndexError("pairing must be an object")
    if not value:
        return ()
    if set(value) != {"pair_id", "role", "counterpart_id"} or value["role"] not in {"master", "slave"}:
        raise SemanticCombatIndexError("pairing fields are invalid")
    return tuple((key, _identifier(value[key], f"pairing.{key}")) for key in ("pair_id", "role", "counterpart_id"))


def _pairs(value: object, field: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > 64:
        raise SemanticCombatIndexError(f"{field} must be a bounded object")
    result = []
    for key, child in value.items():
        result.append((_identifier(key, field), _identifier(child, field)))
    return tuple(sorted(result))


def _path(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 1024 or "\\" in value:
        raise SemanticCombatIndexError("source_path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise SemanticCombatIndexError("source_path is not canonical and relative")
    return path.as_posix()


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise SemanticCombatIndexError(f"{field} is invalid")
    return value


def _optional_identifier(value: object, field: str) -> str | None:
    return None if value is None else _identifier(value, field)


def _digest(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-fA-F0-9]{64}", value) is None:
        raise SemanticCombatIndexError("evidence_sha256 is invalid")
    return value.lower()


__all__ = ["SemanticCombatIndex", "SemanticCombatIndexError", "SemanticCombatRecord", "build_semantic_combat_index"]
