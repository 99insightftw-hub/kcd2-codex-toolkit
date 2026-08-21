"""Bounded actionable status projection over Index-adjacent evidence sources."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from kcd2_mod_build_deploy.evidence_grade import EvidenceGradeAggregation
from kcd2_toolchain_core.hashing import canonical_json_bytes


Freshness = Literal["fresh", "stale", "partial", "unknown"]

MAX_SOURCES = 32
MAX_GRADE_CHILDREN = 64
MAX_SOURCE_EXCLUSIONS = 64
MAX_RELEVANT_EXCLUSIONS = 16
MAX_RESPONSE_BYTES = 16 * 1024
MAX_COMPOSE_MILLISECONDS = 50
MAX_TEXT = 512

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FRESHNESS_VALUES = frozenset({"fresh", "stale", "partial", "unknown"})


def _text(value: object, field: str, maximum: int = MAX_TEXT) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{field} must be non-empty NUL-free text of at most {maximum} characters")
    return value


def _unique_texts(values: Sequence[str], field: str, maximum: int) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError(f"{field} must be an array")
    if len(values) > maximum:
        raise ValueError(f"{field} exceeds the {maximum}-item hard bound")
    checked = tuple(_text(item, f"{field}[]") for item in values)
    if len({item.casefold() for item in checked}) != len(checked):
        raise ValueError(f"{field} must be case-insensitively unique")
    return tuple(sorted(checked, key=lambda item: (item.casefold(), item)))


@dataclass(frozen=True, slots=True)
class CompactStatusSource:
    """One explicitly named source role; no fixed number of indexes is implied."""

    source_id: str
    role: str
    sha256: str
    freshness: Freshness
    freshness_reason: str | None = None
    relevant_exclusions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _text(self.source_id, "source_id", 256)
        _text(self.role, "role", 128)
        if not isinstance(self.sha256, str) or _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must be a lowercase SHA-256")
        if self.freshness not in _FRESHNESS_VALUES:
            raise ValueError("freshness must be fresh, stale, partial, or unknown")
        if self.freshness == "fresh":
            if self.freshness_reason is not None:
                raise ValueError("fresh sources must not have a freshness_reason")
        else:
            _text(self.freshness_reason, "freshness_reason")
        exclusions = _unique_texts(
            self.relevant_exclusions,
            "relevant_exclusions",
            MAX_SOURCE_EXCLUSIONS,
        )
        object.__setattr__(self, "relevant_exclusions", exclusions)

    def to_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "role": self.role,
            "sha256": self.sha256,
            "freshness": self.freshness,
            "freshness_reason": self.freshness_reason,
        }


@dataclass(frozen=True, slots=True)
class NextAction:
    """One recommendation only; a status projection never grants approval."""

    action_id: str
    summary: str
    reason: str
    requires_separate_approval: bool = False

    def __post_init__(self) -> None:
        _text(self.action_id, "action_id", 256)
        _text(self.summary, "summary")
        _text(self.reason, "reason")
        if not isinstance(self.requires_separate_approval, bool):
            raise ValueError("requires_separate_approval must be a boolean")

    def to_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "summary": self.summary,
            "reason": self.reason,
            "requires_separate_approval": self.requires_separate_approval,
            "approval_granted": False,
        }


def _checked_sources(values: Sequence[CompactStatusSource]) -> tuple[CompactStatusSource, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValueError("sources must be an array")
    if not values or len(values) > MAX_SOURCES:
        raise ValueError(f"sources must contain from 1 through {MAX_SOURCES} records")
    if any(not isinstance(item, CompactStatusSource) for item in values):
        raise ValueError("sources must contain CompactStatusSource records")
    source_ids = [item.source_id.casefold() for item in values]
    if len(source_ids) != len(set(source_ids)):
        raise ValueError("source_id values must be case-insensitively unique")
    return tuple(sorted(values, key=lambda item: (item.source_id.casefold(), item.source_id)))


def compose_compact_actionable_status(
    *,
    sources: Sequence[CompactStatusSource],
    grade_aggregation: EvidenceGradeAggregation,
    next_action: NextAction,
) -> dict[str, object]:
    """Compose deterministic status without reading, refreshing, or naming an index count."""

    checked_sources = _checked_sources(sources)
    if not isinstance(grade_aggregation, EvidenceGradeAggregation):
        raise ValueError("grade_aggregation must be an EvidenceGradeAggregation")
    if len(grade_aggregation.children) > MAX_GRADE_CHILDREN:
        raise ValueError(
            f"grade_aggregation.children exceeds the {MAX_GRADE_CHILDREN}-item hard bound"
        )
    if grade_aggregation.aggregation == "unknown_with_reason" and not grade_aggregation.reason:
        raise ValueError("unknown grade aggregation must have a reason")
    if not isinstance(next_action, NextAction):
        raise ValueError("next_action must be a NextAction")

    counts = {
        state: sum(item.freshness == state for item in checked_sources)
        for state in ("fresh", "stale", "partial", "unknown")
    }
    exclusions = sorted(
        {
            exclusion
            for source in checked_sources
            for exclusion in source.relevant_exclusions
        },
        key=lambda item: (item.casefold(), item),
    )
    selected_exclusions = exclusions[:MAX_RELEVANT_EXCLUSIONS]
    payload: dict[str, object] = {
        "schema_version": "kcd2.compact-actionable-status.v1",
        "sources": [source.to_dict() for source in checked_sources],
        "freshness": {
            "overall": "fresh" if counts["fresh"] == len(checked_sources) else "limited",
            "counts": counts,
        },
        "stale_source_ids": [
            source.source_id for source in checked_sources if source.freshness == "stale"
        ],
        "partial_freshness_source_ids": [
            source.source_id for source in checked_sources if source.freshness == "partial"
        ],
        "unknown_freshness_source_ids": [
            source.source_id for source in checked_sources if source.freshness == "unknown"
        ],
        "grade_aggregation": grade_aggregation.to_dict(),
        "relevant_exclusions": {
            "items": selected_exclusions,
            "total_count": len(exclusions),
            "omitted_count": len(exclusions) - len(selected_exclusions),
        },
        "next_action": next_action.to_dict(),
        "contract": {
            "max_compose_milliseconds": MAX_COMPOSE_MILLISECONDS,
            "max_response_bytes": MAX_RESPONSE_BYTES,
            "max_sources": MAX_SOURCES,
            "max_relevant_exclusions": MAX_RELEVANT_EXCLUSIONS,
        },
    }
    size = len(canonical_json_bytes(payload))
    if size > MAX_RESPONSE_BYTES:
        raise ValueError(
            f"compact status is {size} bytes and exceeds the {MAX_RESPONSE_BYTES}-byte hard bound"
        )
    return payload


__all__ = [
    "MAX_COMPOSE_MILLISECONDS",
    "MAX_RELEVANT_EXCLUSIONS",
    "MAX_RESPONSE_BYTES",
    "CompactStatusSource",
    "NextAction",
    "compose_compact_actionable_status",
]
