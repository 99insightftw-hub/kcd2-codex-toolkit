"""Deterministic wrapper aggregation for preserved upstream evidence grades."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping, Sequence, cast


KnownEvidenceGrade = Literal["E0", "E1", "E2", "E3", "E4", "E5", "E6"]
ChildEvidenceGrade = Literal["E0", "E1", "E2", "E3", "E4", "E5", "E6", "unknown"]
AggregationKind = Literal[
    "exact", "minimum", "mixed", "not_applicable", "unknown_with_reason"
]

KNOWN_EVIDENCE_GRADES: tuple[KnownEvidenceGrade, ...] = (
    "E0",
    "E1",
    "E2",
    "E3",
    "E4",
    "E5",
    "E6",
)
CHILD_EVIDENCE_GRADES = frozenset((*KNOWN_EVIDENCE_GRADES, "unknown"))
MAX_CHILDREN = 10_000
MAX_EVIDENCE_ID_LENGTH = 512
MAX_SCOPE_LENGTH = 512
MAX_REASON_LENGTH = 4_000
MAX_UNKNOWN_REASON_LENGTH = 2_000

_GRADE_RANK = {grade: index for index, grade in enumerate(KNOWN_EVIDENCE_GRADES)}


class EvidenceGradeAggregationError(ValueError):
    """Raised when child records cannot satisfy the reviewed aggregation contract."""


def _bounded_text(value: str, name: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise EvidenceGradeAggregationError(f"{name} must be a string")
    if not value or "\x00" in value or len(value) > maximum:
        raise EvidenceGradeAggregationError(
            f"{name} must be non-empty, NUL-free, and at most {maximum} characters"
        )
    return value


@dataclass(frozen=True, slots=True)
class EvidenceGradeChild:
    """One child whose upstream grade and scope must remain unchanged."""

    evidence_id: str
    grade: ChildEvidenceGrade
    scope: str

    def __post_init__(self) -> None:
        _bounded_text(self.evidence_id, "evidence_id", MAX_EVIDENCE_ID_LENGTH)
        _bounded_text(self.scope, "scope", MAX_SCOPE_LENGTH)
        if self.grade not in CHILD_EVIDENCE_GRADES:
            raise EvidenceGradeAggregationError("grade is outside the upstream E0-E6/unknown set")

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "grade": self.grade,
            "scope": self.scope,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EvidenceGradeChild:
        if set(value) != {"evidence_id", "grade", "scope"}:
            raise EvidenceGradeAggregationError("child fields do not match the v1 contract")
        return cls(
            evidence_id=cast(str, value["evidence_id"]),
            grade=cast(ChildEvidenceGrade, value["grade"]),
            scope=cast(str, value["scope"]),
        )


@dataclass(frozen=True, slots=True)
class EvidenceGradeAggregation:
    """Schema-shaped aggregate that retains every child record verbatim."""

    aggregation: AggregationKind
    reported_grade: KnownEvidenceGrade | None
    children: tuple[EvidenceGradeChild, ...]
    reason: str
    boundary: str | None = None
    schema_version: str = "kcd2.evidence-grade-aggregation.v1"

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.evidence-grade-aggregation.v1":
            raise EvidenceGradeAggregationError("unsupported aggregation schema_version")
        if self.aggregation not in {
            "exact",
            "minimum",
            "mixed",
            "not_applicable",
            "unknown_with_reason",
        }:
            raise EvidenceGradeAggregationError("unsupported aggregation kind")
        if self.reported_grade is not None and self.reported_grade not in KNOWN_EVIDENCE_GRADES:
            raise EvidenceGradeAggregationError("reported_grade is outside the upstream E0-E6 set")
        if len(self.children) > MAX_CHILDREN:
            raise EvidenceGradeAggregationError(
                f"children exceed the {MAX_CHILDREN} record limit"
            )
        if any(not isinstance(child, EvidenceGradeChild) for child in self.children):
            raise EvidenceGradeAggregationError("children must be EvidenceGradeChild records")
        evidence_ids = [child.evidence_id for child in self.children]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise EvidenceGradeAggregationError("evidence_id values must be unique")
        _bounded_text(self.reason, "reason", MAX_REASON_LENGTH)
        if self.boundary is not None:
            _bounded_text(self.boundary, "boundary", 2_000)
        if self.aggregation in {"exact", "minimum"}:
            if self.reported_grade is None or not self.children:
                raise EvidenceGradeAggregationError(
                    "exact/minimum aggregation requires a reported grade and children"
                )
        elif self.reported_grade is not None:
            raise EvidenceGradeAggregationError(
                "mixed/not-applicable/unknown aggregation cannot report a wrapper grade"
            )
        if self.aggregation == "mixed" and len(self.children) < 2:
            raise EvidenceGradeAggregationError("mixed aggregation requires at least two children")
        if self.aggregation == "not_applicable" and self.children:
            raise EvidenceGradeAggregationError(
                "not_applicable aggregation requires an empty child set"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "aggregation": self.aggregation,
            "reported_grade": self.reported_grade,
            "children": [child.to_dict() for child in self.children],
            "reason": self.reason,
            "boundary": self.boundary,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> EvidenceGradeAggregation:
        required = {
            "schema_version",
            "aggregation",
            "reported_grade",
            "children",
            "reason",
        }
        if not required.issubset(value) or set(value) - required - {"boundary"}:
            raise EvidenceGradeAggregationError("aggregation fields do not match the v1 contract")
        raw_children = value["children"]
        if not isinstance(raw_children, list):
            raise EvidenceGradeAggregationError("children must be an array")
        return cls(
            schema_version=cast(str, value["schema_version"]),
            aggregation=cast(AggregationKind, value["aggregation"]),
            reported_grade=cast(KnownEvidenceGrade | None, value["reported_grade"]),
            children=tuple(
                EvidenceGradeChild.from_dict(cast(Mapping[str, object], child))
                for child in raw_children
            ),
            reason=cast(str, value["reason"]),
            boundary=cast(str | None, value.get("boundary")),
        )


def _summarize(values: Sequence[str], *, limit: int = 3) -> str:
    shown = ", ".join(repr(value) for value in values[:limit])
    remaining = len(values) - limit
    if remaining > 0:
        return f"{shown}, and {remaining} more"
    return shown


def aggregate_evidence_grades(
    children: Sequence[EvidenceGradeChild],
    *,
    unknown_reason: str | None = None,
) -> EvidenceGradeAggregation:
    """Aggregate wrapper grades without interpreting or rewriting child grade meanings.

    A homogeneous scope is ``exact`` when all grades match and ``minimum`` when
    they differ. Heterogeneous known scopes are ``mixed``. Any unknown child is
    ``unknown_with_reason`` with its identity reported. An empty child set is
    ``not_applicable``.
    """

    values = tuple(children)
    if len(values) > MAX_CHILDREN:
        raise EvidenceGradeAggregationError(f"children exceed the {MAX_CHILDREN} record limit")
    if any(not isinstance(child, EvidenceGradeChild) for child in values):
        raise EvidenceGradeAggregationError("children must be EvidenceGradeChild records")
    evidence_ids = [child.evidence_id for child in values]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise EvidenceGradeAggregationError("evidence_id values must be unique")
    if unknown_reason is not None:
        _bounded_text(unknown_reason, "unknown_reason", MAX_UNKNOWN_REASON_LENGTH)

    if not values:
        return EvidenceGradeAggregation(
            aggregation="not_applicable",
            reported_grade=None,
            children=values,
            reason="No child evidence applies to this wrapper.",
        )

    unknown_ids = [child.evidence_id for child in values if child.grade == "unknown"]
    known_grades = sorted(
        {cast(KnownEvidenceGrade, child.grade) for child in values if child.grade != "unknown"},
        key=_GRADE_RANK.__getitem__,
    )
    if unknown_ids:
        details = f"Unknown upstream grades remain on children {_summarize(unknown_ids)}."
        if known_grades:
            details += f" Known child grades retained: {', '.join(known_grades)}."
        reason = f"{unknown_reason} {details}" if unknown_reason else details
        return EvidenceGradeAggregation(
            aggregation="unknown_with_reason",
            reported_grade=None,
            children=values,
            reason=reason,
        )

    scopes = sorted({child.scope for child in values})
    if len(scopes) > 1:
        return EvidenceGradeAggregation(
            aggregation="mixed",
            reported_grade=None,
            children=values,
            reason=(
                f"Child scopes differ ({_summarize(scopes)}); nested grades are preserved "
                "without a wrapper grade."
            ),
            boundary="heterogeneous child scopes",
        )

    grades = [cast(KnownEvidenceGrade, child.grade) for child in values]
    distinct_grades = set(grades)
    if len(distinct_grades) == 1:
        grade = grades[0]
        return EvidenceGradeAggregation(
            aggregation="exact",
            reported_grade=grade,
            children=values,
            reason=f"All children in scope {scopes[0]!r} retain exact upstream grade {grade}.",
            boundary=scopes[0],
        )

    minimum = min(grades, key=_GRADE_RANK.__getitem__)
    return EvidenceGradeAggregation(
        aggregation="minimum",
        reported_grade=minimum,
        children=values,
        reason=(
            f"Children in scope {scopes[0]!r} retain their upstream grades; the wrapper reports "
            f"the minimum label {minimum} under the closed E0-E6 ordering."
        ),
        boundary=scopes[0],
    )
