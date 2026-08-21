"""Closed global tool-error taxonomy and its versioned transport value."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Literal, Mapping, Sequence

from .hashing import canonical_json_bytes, sha256_json


ErrorCategory = Literal[
    "invalid_argument",
    "not_configured",
    "not_found",
    "scope_breach",
    "coverage_incomplete",
    "authorization",
    "process_state",
    "source_blocker",
    "internal",
]

ERROR_CODE_CATEGORIES: Mapping[str, ErrorCategory] = {
    "KCD2_INVALID_ARGUMENT": "invalid_argument",
    "KCD2_LIMIT_OUT_OF_RANGE": "invalid_argument",
    "KCD2_NOT_CONFIGURED": "not_configured",
    "KCD2_NOT_FOUND": "not_found",
    "KCD2_SCOPE_BREACH": "scope_breach",
    "KCD2_COVERAGE_INCOMPLETE": "coverage_incomplete",
    "KCD2_AUTHORIZATION_REQUIRED": "authorization",
    "KCD2_PROCESS_STATE_INVALID": "process_state",
    "KCD2_SOURCE_BLOCKER": "source_blocker",
    "KCD2_INTERNAL": "internal",
}


def _require_bounded_text(name: str, value: str, maximum: int, *, empty: bool = False) -> None:
    if not isinstance(value, str) or (not empty and not value):
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")


@dataclass(frozen=True, slots=True)
class ToolError:
    """Typed public error; code/category pairs cannot contradict the taxonomy."""

    error_id: str
    code: str
    category: ErrorCategory
    message: str
    recoverable: bool
    field: str | None
    supplied_value: Any
    allowed_values: Sequence[Any]
    correlation_id: str
    schema_version: str = "kcd2.tool-error.v1"

    MAX_VALUE_BYTES: ClassVar[int] = 16_384
    MAX_ALLOWED_VALUES: ClassVar[int] = 100

    def __post_init__(self) -> None:
        if self.schema_version != "kcd2.tool-error.v1":
            raise ValueError("unsupported tool error schema_version")
        _require_bounded_text("error_id", self.error_id, 256)
        _require_bounded_text("message", self.message, 4_000)
        _require_bounded_text("correlation_id", self.correlation_id, 256)
        if self.field is not None:
            _require_bounded_text("field", self.field, 256)
        expected = ERROR_CODE_CATEGORIES.get(self.code)
        if expected is None:
            raise ValueError(f"unsupported tool error code: {self.code}")
        if self.category != expected:
            raise ValueError(
                f"{self.code} is an {expected} error, not {self.category}; "
                "invalid_argument takes precedence over configuration state"
            )
        if not isinstance(self.recoverable, bool):
            raise TypeError("recoverable must be a boolean")
        if isinstance(self.allowed_values, (str, bytes)):
            raise TypeError("allowed_values must be a sequence of JSON values")
        if len(self.allowed_values) > self.MAX_ALLOWED_VALUES:
            raise ValueError("allowed_values exceeds the global bound")
        try:
            supplied_bytes = canonical_json_bytes(self.supplied_value)
            allowed_bytes = canonical_json_bytes(list(self.allowed_values))
        except (TypeError, ValueError) as exc:
            raise ValueError("tool error values must be finite JSON values") from exc
        if len(supplied_bytes) > self.MAX_VALUE_BYTES or len(allowed_bytes) > self.MAX_VALUE_BYTES:
            raise ValueError("tool error value detail exceeds the global byte bound")

    @classmethod
    def invalid_argument(
        cls,
        *,
        message: str,
        field: str,
        supplied_value: Any,
        allowed_values: Sequence[Any] = (),
        correlation_id: str,
        code: Literal["KCD2_INVALID_ARGUMENT", "KCD2_LIMIT_OUT_OF_RANGE"] = (
            "KCD2_INVALID_ARGUMENT"
        ),
    ) -> "ToolError":
        """Construct an argument error before any configuration classification."""
        identity = {
            "code": code,
            "correlation_id": correlation_id,
            "field": field,
            "supplied_value": supplied_value,
        }
        return cls(
            error_id=f"error:sha256:{sha256_json(identity)}",
            code=code,
            category="invalid_argument",
            message=message,
            recoverable=True,
            field=field,
            supplied_value=supplied_value,
            allowed_values=tuple(allowed_values),
            correlation_id=correlation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "error_id": self.error_id,
            "code": self.code,
            "category": self.category,
            "message": self.message,
            "recoverable": self.recoverable,
            "field": self.field,
            "supplied_value": self.supplied_value,
            "allowed_values": list(self.allowed_values),
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolError":
        expected = {
            "schema_version",
            "error_id",
            "code",
            "category",
            "message",
            "recoverable",
            "field",
            "supplied_value",
            "allowed_values",
            "correlation_id",
        }
        if set(value) != expected:
            raise ValueError("tool error fields do not match v1")
        return cls(
            schema_version=value["schema_version"],
            error_id=value["error_id"],
            code=value["code"],
            category=value["category"],
            message=value["message"],
            recoverable=value["recoverable"],
            field=value["field"],
            supplied_value=value["supplied_value"],
            allowed_values=tuple(value["allowed_values"]),
            correlation_id=value["correlation_id"],
        )
