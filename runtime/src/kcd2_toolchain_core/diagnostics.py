"""Versioned diagnostics and deterministic bounded aggregation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal


Severity = Literal["info", "warning", "error"]


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    cause: str
    message: str
    severity: Severity = "warning"
    example: str | None = None
    schema_version: str = "kcd2.diagnostic.v1"

    def __post_init__(self) -> None:
        if not self.code or not self.cause or not self.message:
            raise ValueError("diagnostic code, cause, and message must not be empty")
        if self.severity not in ("info", "warning", "error"):
            raise ValueError("unsupported diagnostic severity")
        if self.schema_version != "kcd2.diagnostic.v1":
            raise ValueError("unsupported diagnostic schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "code": self.code,
            "cause": self.cause,
            "message": self.message,
            "severity": self.severity,
            "example": self.example,
        }


@dataclass(frozen=True, slots=True)
class DiagnosticAggregate:
    code: str
    cause: str
    severity: Severity
    count: int
    messages: tuple[str, ...]
    examples: tuple[str, ...]
    schema_version: str = "kcd2.diagnostic-aggregate.v1"

    def __post_init__(self) -> None:
        if not self.code or not self.cause:
            raise ValueError("diagnostic aggregate code and cause must not be empty")
        if self.severity not in ("info", "warning", "error"):
            raise ValueError("unsupported diagnostic severity")
        if self.count <= 0:
            raise ValueError("diagnostic aggregate count must be positive")
        if self.schema_version != "kcd2.diagnostic-aggregate.v1":
            raise ValueError("unsupported diagnostic aggregate schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "code": self.code,
            "cause": self.cause,
            "severity": self.severity,
            "count": self.count,
            "messages": list(self.messages),
            "examples": list(self.examples),
        }


def aggregate_diagnostics(
    diagnostics: Iterable[Diagnostic],
    *,
    max_examples: int = 3,
    max_messages: int = 3,
) -> tuple[DiagnosticAggregate, ...]:
    """Collapse by code/cause with deterministic, response-wide sample budgets.

    Severity is not part of diagnostic identity.  If repeated observations disagree,
    the aggregate retains the strongest severity.  ``max_examples`` and
    ``max_messages`` are totals across every aggregate, not per-group limits.
    """
    if max_examples < 0 or max_messages < 0:
        raise ValueError("diagnostic bounds must be non-negative")
    groups: dict[tuple[str, str], list[Diagnostic]] = {}
    for item in diagnostics:
        if not isinstance(item, Diagnostic):
            raise TypeError("diagnostics must contain Diagnostic values")
        groups.setdefault((item.code, item.cause), []).append(item)

    output: list[DiagnosticAggregate] = []
    remaining_examples = max_examples
    remaining_messages = max_messages
    severity_rank: dict[Severity, int] = {"info": 0, "warning": 1, "error": 2}
    for (code, cause), items in sorted(groups.items()):
        severity = max((item.severity for item in items), key=severity_rank.__getitem__)
        messages = tuple(sorted({item.message for item in items})[:remaining_messages])
        remaining_messages -= len(messages)
        example_values = {item.example for item in items if item.example is not None}
        examples = tuple(sorted(example_values)[:remaining_examples])
        remaining_examples -= len(examples)
        output.append(
            DiagnosticAggregate(
                code=code,
                cause=cause,
                severity=severity,
                count=len(items),
                messages=messages,
                examples=examples,
            )
        )
    return tuple(output)
