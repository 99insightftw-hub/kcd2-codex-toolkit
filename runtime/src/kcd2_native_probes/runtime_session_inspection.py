"""Exact, deployment-bound inspection of one immutable runtime session."""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from typing import Any, Protocol

from kcd2_toolchain_core.cross_tool_identity import (
    IdentityMismatchError,
    assert_same_identity,
    bind_cross_tool_identity,
)
from kcd2_toolchain_core.hashing import canonical_json_bytes, sha256_json
from kcd2_toolchain_core.results import (
    ContinuationHandle,
    ResponseLimitError,
    decode_continuation_handle,
)


SCHEMA_VERSION = "kcd2.runtime-session-record.v1"
INSPECTION_SCHEMA_VERSION = "kcd2.runtime-session-inspection.v1"
MAX_OBSERVATIONS = 100_000
MAX_RAW_HANDLES = 1_024
MAX_EXCERPT_CHARS = 4_096
MAX_PAGE_SIZE = 1_000
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_RECORD_FIELDS = {
    "schema_version",
    "session_id",
    "cross_tool_identity",
    "latest_boot_id",
    "candidate_sha256",
    "deployment_sha256",
    "source_sha256",
    "observations",
    "raw_handles",
    "session_binding_sha256",
}
_OBSERVATION_FIELDS = {"sequence", "semantic", "payload", "session_binding_sha256"}
_RAW_HANDLE_FIELDS = {
    "handle_id",
    "exact_locator",
    "sha256",
    "byte_size",
    "excerpt",
    "excerpt_truncated",
    "session_binding_sha256",
}


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be non-empty text of at most {maximum} characters")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a 64-character SHA-256 hex digest")
    return value.lower()


def _exact_fields(value: Mapping[str, Any], allowed: set[str], field: str) -> None:
    actual = set(value)
    required = allowed - {"session_binding_sha256"}
    if not required <= actual or actual - allowed:
        raise ValueError(
            f"{field} fields do not match contract; "
            f"missing={sorted(required - actual)}, unknown={sorted(actual - allowed)}"
        )


def _binding_seed(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "session_id": record["session_id"],
        "cross_tool_identity": record["cross_tool_identity"],
        "latest_boot_id": record["latest_boot_id"],
        "candidate_sha256": record["candidate_sha256"],
        "deployment_sha256": record["deployment_sha256"],
        "source_sha256": record["source_sha256"],
    }


def bind_runtime_session_record(value: Mapping[str, Any]) -> dict[str, Any]:
    """Canonicalize one record and bind every observation/raw handle to its identity."""

    if not isinstance(value, Mapping):
        raise TypeError("runtime session record must be a mapping")
    supplied = copy.deepcopy(dict(value))
    _exact_fields(supplied, _RECORD_FIELDS, "runtime session record")
    if supplied["schema_version"] != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    session_id = _text(supplied["session_id"], "session_id", 256)
    latest_boot_id = _text(supplied["latest_boot_id"], "latest_boot_id", 256)
    identity = bind_cross_tool_identity(supplied["cross_tool_identity"])
    candidate_sha256 = _digest(supplied["candidate_sha256"], "candidate_sha256")
    deployment_sha256 = _digest(supplied["deployment_sha256"], "deployment_sha256")
    source_sha256 = _digest(supplied["source_sha256"], "source_sha256")
    identity_fields = identity.to_dict()
    candidate_id = identity_fields["candidate_id"]
    if isinstance(candidate_id, str) and candidate_id.startswith("cand:sha256:"):
        if candidate_id.removeprefix("cand:sha256:").lower() != candidate_sha256:
            raise IdentityMismatchError("candidate_sha256 differs from cross-tool candidate_id")
    if identity_fields["source"]["tree_sha256"].lower() != source_sha256:
        raise IdentityMismatchError("source_sha256 differs from cross-tool source tree")

    observations = supplied["observations"]
    if not isinstance(observations, list) or len(observations) > MAX_OBSERVATIONS:
        raise ValueError(f"observations must be an array bounded to {MAX_OBSERVATIONS}")
    normalized_observations: list[dict[str, Any]] = []
    observation_assertions: dict[int, Any] = {}
    sequences: set[int] = set()
    for index, raw in enumerate(observations):
        if not isinstance(raw, Mapping):
            raise TypeError(f"observations[{index}] must be a mapping")
        item = copy.deepcopy(dict(raw))
        _exact_fields(item, _OBSERVATION_FIELDS, f"observations[{index}]")
        sequence = item["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError(f"observations[{index}].sequence must be a non-negative integer")
        if sequence in sequences:
            raise ValueError("observation sequences must be unique")
        sequences.add(sequence)
        semantic = _text(item["semantic"], f"observations[{index}].semantic", 128)
        try:
            canonical_json_bytes(item["payload"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"observations[{index}].payload is not finite JSON") from exc
        normalized_observations.append(
            {"sequence": sequence, "semantic": semantic, "payload": item["payload"]}
        )
        observation_assertions[sequence] = item.get("session_binding_sha256")
    normalized_observations.sort(key=lambda item: item["sequence"])

    handles = supplied["raw_handles"]
    if not isinstance(handles, list) or len(handles) > MAX_RAW_HANDLES:
        raise ValueError(f"raw_handles must be an array bounded to {MAX_RAW_HANDLES}")
    normalized_handles: list[dict[str, Any]] = []
    handle_assertions: dict[str, Any] = {}
    handle_ids: set[str] = set()
    for index, raw in enumerate(handles):
        if not isinstance(raw, Mapping):
            raise TypeError(f"raw_handles[{index}] must be a mapping")
        item = copy.deepcopy(dict(raw))
        _exact_fields(item, _RAW_HANDLE_FIELDS, f"raw_handles[{index}]")
        handle_id = _text(item["handle_id"], f"raw_handles[{index}].handle_id", 256)
        if handle_id in handle_ids:
            raise ValueError("raw handle IDs must be unique")
        handle_ids.add(handle_id)
        byte_size = item["byte_size"]
        if (
            isinstance(byte_size, bool)
            or not isinstance(byte_size, int)
            or not 0 <= byte_size <= 2**40
        ):
            raise ValueError(f"raw_handles[{index}].byte_size is outside its hard bound")
        excerpt = item["excerpt"]
        if not isinstance(excerpt, str) or len(excerpt) > MAX_EXCERPT_CHARS:
            raise ValueError(
                f"raw_handles[{index}].excerpt must contain at most {MAX_EXCERPT_CHARS} characters"
            )
        truncated = item["excerpt_truncated"]
        if not isinstance(truncated, bool):
            raise TypeError(f"raw_handles[{index}].excerpt_truncated must be boolean")
        normalized_handles.append(
            {
                "handle_id": handle_id,
                "exact_locator": _text(
                    item["exact_locator"], f"raw_handles[{index}].exact_locator", 8192
                ),
                "sha256": _digest(item["sha256"], f"raw_handles[{index}].sha256"),
                "byte_size": byte_size,
                "excerpt": excerpt,
                "excerpt_truncated": truncated,
            }
        )
        handle_assertions[handle_id] = item.get("session_binding_sha256")
    normalized_handles.sort(key=lambda item: item["handle_id"])

    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id,
        "cross_tool_identity": identity_fields,
        "latest_boot_id": latest_boot_id,
        "candidate_sha256": candidate_sha256,
        "deployment_sha256": deployment_sha256,
        "source_sha256": source_sha256,
        "observations": normalized_observations,
        "raw_handles": normalized_handles,
    }
    binding_sha256 = sha256_json(_binding_seed(normalized))
    asserted_binding = supplied.get("session_binding_sha256")
    if asserted_binding is not None and _digest(
        asserted_binding, "session_binding_sha256"
    ) != binding_sha256:
        raise IdentityMismatchError("session_binding_sha256 does not match session identity")
    normalized["session_binding_sha256"] = binding_sha256
    for item in normalized_observations:
        asserted = observation_assertions[item["sequence"]]
        if (
            asserted is not None
            and _digest(asserted, "child session_binding_sha256") != binding_sha256
        ):
            raise IdentityMismatchError("observation/raw handle binding differs from session")
        item["session_binding_sha256"] = binding_sha256
    for item in normalized_handles:
        asserted = handle_assertions[item["handle_id"]]
        if (
            asserted is not None
            and _digest(asserted, "child session_binding_sha256") != binding_sha256
        ):
            raise IdentityMismatchError("observation/raw handle binding differs from session")
        item["session_binding_sha256"] = binding_sha256
    return normalized


class ExactRuntimeSessionProvider(Protocol):
    """Provider contract intentionally exposes no list-all operation."""

    def get_session(self, session_id: str) -> Mapping[str, Any] | None: ...


class InMemoryRuntimeSessionProvider:
    """Deterministic exact-key provider used by fixtures and embedding callers."""

    def __init__(self, records_by_id: Mapping[str, Mapping[str, Any]]) -> None:
        self._records = {
            _text(key, "session key", 256): bind_runtime_session_record(value)
            for key, value in records_by_id.items()
        }
        if any(key != record["session_id"] for key, record in self._records.items()):
            raise ValueError("session provider key differs from record session_id")
        self._requests: list[str] = []

    @property
    def requested_session_ids(self) -> tuple[str, ...]:
        return tuple(self._requests)

    def get_session(self, session_id: str) -> Mapping[str, Any] | None:
        checked = _text(session_id, "session_id", 256)
        self._requests.append(checked)
        record = self._records.get(checked)
        return copy.deepcopy(record) if record is not None else None


def validate_runtime_session_binding(
    record: Mapping[str, Any],
    *,
    expected_cross_tool_identity: Mapping[str, Any],
    expected_latest_boot_id: str,
    expected_candidate_sha256: str,
    expected_deployment_sha256: str,
    expected_source_sha256: str,
) -> dict[str, Any]:
    """Fail closed on identity/latest-boot drift without promoting the session."""

    bound = bind_runtime_session_record(record)
    reasons: list[str] = []
    try:
        assert_same_identity(bound["cross_tool_identity"], expected_cross_tool_identity)
    except (IdentityMismatchError, TypeError, ValueError):
        reasons.append("CROSS_TOOL_IDENTITY_DRIFT")
    expected_values = {
        "latest_boot_id": _text(expected_latest_boot_id, "expected_latest_boot_id", 256),
        "candidate_sha256": _digest(expected_candidate_sha256, "expected_candidate_sha256"),
        "deployment_sha256": _digest(
            expected_deployment_sha256, "expected_deployment_sha256"
        ),
        "source_sha256": _digest(expected_source_sha256, "expected_source_sha256"),
    }
    reason_names = {
        "latest_boot_id": "LATEST_BOOT_DRIFT",
        "candidate_sha256": "CANDIDATE_IDENTITY_DRIFT",
        "deployment_sha256": "DEPLOYMENT_IDENTITY_DRIFT",
        "source_sha256": "SOURCE_IDENTITY_DRIFT",
    }
    for field, expected in expected_values.items():
        if bound[field] != expected:
            reasons.append(reason_names[field])
    return {
        "schema_version": "kcd2.runtime-session-binding-validation.v1",
        "session_id": bound["session_id"],
        "session_binding_sha256": bound["session_binding_sha256"],
        "status": "capture_inconclusive" if reasons else "exact",
        "candidate_promotion_allowed": not reasons,
        "reasons": reasons,
    }


class RuntimeSessionInspector:
    """Inspect exactly one ID and page only that session's observations."""

    def __init__(self, provider: ExactRuntimeSessionProvider) -> None:
        if not callable(getattr(provider, "get_session", None)):
            raise TypeError("provider must implement exact get_session(session_id)")
        self.provider = provider

    def inspect(
        self,
        *,
        session_id: str,
        expected_cross_tool_identity: Mapping[str, Any],
        expected_latest_boot_id: str,
        expected_candidate_sha256: str,
        expected_deployment_sha256: str,
        expected_source_sha256: str,
        page_size: int = 100,
        continuation_token: str | None = None,
        max_excerpt_chars: int = 512,
        max_response_bytes: int = 1_048_576,
    ) -> dict[str, Any]:
        checked_session_id = _text(session_id, "session_id", 256)
        if (
            isinstance(page_size, bool)
            or not isinstance(page_size, int)
            or not 1 <= page_size <= MAX_PAGE_SIZE
        ):
            raise ValueError(f"page_size must be from 1 through {MAX_PAGE_SIZE}")
        if (
            isinstance(max_excerpt_chars, bool)
            or not isinstance(max_excerpt_chars, int)
            or not 0 <= max_excerpt_chars <= MAX_EXCERPT_CHARS
        ):
            raise ValueError(f"max_excerpt_chars must be from 0 through {MAX_EXCERPT_CHARS}")
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 512 <= max_response_bytes <= 2 * 1024 * 1024
        ):
            raise ValueError("max_response_bytes must be from 512 through 2097152")
        record = self.provider.get_session(checked_session_id)
        if record is None:
            if continuation_token is not None:
                raise ValueError("continuation token cannot target a session that was not found")
            return {
                "schema_version": INSPECTION_SCHEMA_VERSION,
                "status": "not_found",
                "session_id": checked_session_id,
                "records": [],
                "candidate_promotion_allowed": False,
                "binding_reasons": ["SESSION_NOT_FOUND"],
                "continuation_token": None,
            }
        bound = bind_runtime_session_record(record)
        validation = validate_runtime_session_binding(
            bound,
            expected_cross_tool_identity=expected_cross_tool_identity,
            expected_latest_boot_id=expected_latest_boot_id,
            expected_candidate_sha256=expected_candidate_sha256,
            expected_deployment_sha256=expected_deployment_sha256,
            expected_source_sha256=expected_source_sha256,
        )
        reasons = list(validation["reasons"])

        observations = bound["observations"]
        scope = f"runtime-session:{checked_session_id}:{bound['session_binding_sha256']}"
        if continuation_token is None:
            offset = 0
            page = 1
        else:
            handle = decode_continuation_handle(
                continuation_token, scope=scope, items=observations
            )
            offset = handle.offset
            page = handle.page
        page_items = copy.deepcopy(observations[offset : offset + page_size])
        next_offset = offset + len(page_items)
        next_token = None
        if next_offset < len(observations):
            next_token = ContinuationHandle(
                scope=scope,
                items_sha256=sha256_json(observations),
                offset=next_offset,
                page=page + 1,
            ).to_token()
        handles = copy.deepcopy(bound["raw_handles"])
        for item in handles:
            excerpt = item["excerpt"]
            if len(excerpt) > max_excerpt_chars:
                item["excerpt"] = excerpt[:max_excerpt_chars]
                item["excerpt_truncated"] = True
        rendered = {
            **bound,
            "observations": page_items,
            "raw_handles": handles,
        }
        response = {
            "schema_version": INSPECTION_SCHEMA_VERSION,
            "status": "capture_inconclusive" if reasons else "exact",
            "session_id": checked_session_id,
            "records": [rendered],
            "candidate_promotion_allowed": not reasons,
            "binding_reasons": reasons,
            "continuation_token": next_token,
        }
        if len(canonical_json_bytes(response)) > max_response_bytes:
            for item in handles:
                if item["excerpt"]:
                    item["excerpt"] = ""
                    item["excerpt_truncated"] = True
        if len(canonical_json_bytes(response)) > max_response_bytes:
            raise ResponseLimitError(
                "exact runtime-session response exceeds max_response_bytes; "
                "reduce page_size or request a larger bounded response"
            )
        return response


__all__ = [
    "ExactRuntimeSessionProvider",
    "InMemoryRuntimeSessionProvider",
    "RuntimeSessionInspector",
    "bind_runtime_session_record",
    "validate_runtime_session_binding",
]
