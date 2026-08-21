"""Typed content identifiers for distinct build and deployment concepts."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


_SHA256 = re.compile(r"[a-f0-9]{64}")
_KINDS = frozenset({"artifact", "build-output", "installed-tree"})


class TypedIdentityError(ValueError):
    """An identifier used the wrong type, prefix, or digest."""


def typed_identity(kind: str, sha256: str) -> str:
    if kind not in _KINDS:
        raise TypedIdentityError(f"unsupported typed identity kind: {kind!r}")
    if not isinstance(sha256, str) or _SHA256.fullmatch(sha256.lower()) is None:
        raise TypedIdentityError("typed identity digest must be SHA-256")
    return f"{kind}:sha256:{sha256.lower()}"


def validate_typed_identity(value: object, kind: str) -> str:
    if not isinstance(value, str):
        raise TypedIdentityError(f"{kind} identity must be a string")
    prefix = f"{kind}:sha256:"
    if not value.startswith(prefix) or _SHA256.fullmatch(value[len(prefix) :]) is None:
        raise TypedIdentityError(f"identity must use the {prefix} prefix")
    return value


def canonical_build_output_id(material: Mapping[str, Any]) -> str:
    if not isinstance(material, Mapping):
        raise TypedIdentityError("build output identity material must be a mapping")
    try:
        encoded = json.dumps(
            material,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TypedIdentityError("build output identity material must be JSON data") from exc
    return typed_identity("build-output", hashlib.sha256(encoded).hexdigest())


def artifact_id(sha256: str) -> str:
    return typed_identity("artifact", sha256)


def installed_tree_id(sha256: str) -> str:
    return typed_identity("installed-tree", sha256)
