"""Versioned evidence identities, including exact native locations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from .hashing import sha256_json


EvidenceKind = Literal["static", "runtime", "user_confirmed", "causal"]
NativeLocationKind = Literal["rva", "offset"]
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _validated_sha256(value: str, field: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


@dataclass(frozen=True, slots=True)
class NativeLocation:
    module_sha256: str
    kind: NativeLocationKind
    value: int
    schema_version: str = "kcd2.native-location.v1"

    def __post_init__(self) -> None:
        normalized_hash = _validated_sha256(self.module_sha256, "module_sha256")
        object.__setattr__(self, "module_sha256", normalized_hash)
        if self.kind not in ("rva", "offset"):
            raise ValueError("kind must be 'rva' or 'offset'")
        if isinstance(self.value, bool) or not isinstance(self.value, int) or self.value < 0:
            raise ValueError("value must be a non-negative integer")
        if self.schema_version != "kcd2.native-location.v1":
            raise ValueError("unsupported native location schema_version")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "module_sha256": self.module_sha256,
            "kind": self.kind,
            "value": f"0x{self.value:x}",
        }


@dataclass(frozen=True, slots=True)
class EvidenceIdentity:
    evidence_kind: EvidenceKind
    source_sha256: str
    locator: str
    native_location: NativeLocation | None = None
    schema_version: str = "kcd2.evidence-identity.v1"

    def __post_init__(self) -> None:
        if self.evidence_kind not in ("static", "runtime", "user_confirmed", "causal"):
            raise ValueError("unsupported evidence_kind")
        normalized_hash = _validated_sha256(self.source_sha256, "source_sha256")
        object.__setattr__(self, "source_sha256", normalized_hash)
        if not self.locator:
            raise ValueError("locator must not be empty")
        if self.schema_version != "kcd2.evidence-identity.v1":
            raise ValueError("unsupported evidence identity schema_version")

    @property
    def identity_id(self) -> str:
        return sha256_json(self._identity_fields())

    def _identity_fields(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind,
            "source_sha256": self.source_sha256,
            "locator": self.locator,
            "native_location": self.native_location.to_dict() if self.native_location else None,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "identity_id": self.identity_id,
            **self._identity_fields(),
        }
