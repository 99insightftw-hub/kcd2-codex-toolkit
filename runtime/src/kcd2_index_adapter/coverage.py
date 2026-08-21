"""Coverage completeness and claim-permission evaluation for Index evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from .scope_guard import ScopeGuard, TargetScopeReceiptError


CoverageBasis = Literal[
    "active_snapshot",
    "direct_exact_scan",
    "manual_contributions",
    "hybrid",
]
LayerStatus = Literal[
    "COMPLETE",
    "COMPLETE_FOR_REQUESTED_SCOPE",
    "PARTIAL_LIMIT_REACHED",
    "PARTIAL_STALE",
    "NOT_CONFIGURED",
    "UNAVAILABLE",
    "UNKNOWN",
]

_BASES = frozenset(
    {"active_snapshot", "direct_exact_scan", "manual_contributions", "hybrid"}
)
_SCOPE_FIELDS = ("mod_ids", "canonical_paths", "provider_kinds", "artifact_classes")
_CLAIMS = (
    "presence_claim_allowed",
    "absence_claim_allowed",
    "winner_claim_allowed",
    "conflict_absence_claim_allowed",
)
_MAX_LAYERS = 32
_MAX_SCOPE_ITEMS = 256
_MAX_REASON_CODES = 128
_MAX_TEXT = 1024
_MAX_COUNT = 2**63 - 1
_MAX_BOUND_INPUTS = 128
_SHA256 = re.compile(r"^[0-9A-Fa-f]{64}$")


class CoverageValidityError(ValueError):
    """Coverage inputs cannot support a deterministic validity result."""


def _plain_int(value: object, name: str, *, minimum: int = 0) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > _MAX_COUNT
    ):
        raise CoverageValidityError(
            f"{name} must be an integer from {minimum} through {_MAX_COUNT}"
        )
    return value


def _text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT or "\x00" in value:
        raise CoverageValidityError(
            f"{name} must be a non-empty NUL-free string of at most {_MAX_TEXT} characters"
        )
    return value


def _sequence(value: object, name: str, maximum: int) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise CoverageValidityError(f"{name} must be an array")
    if len(value) > maximum:
        raise CoverageValidityError(f"{name} exceeds the {maximum}-item hard bound")
    return value


def _bounded_unique_texts(
    value: object,
    name: str,
    maximum: int,
    *,
    path_like: bool = False,
) -> tuple[str, ...]:
    values = tuple(
        _text(item, f"{name}[{index}]")
        for index, item in enumerate(_sequence(value, name, maximum))
    )
    if path_like and any(".." in item.replace("\\", "/").split("/") for item in values):
        raise CoverageValidityError(f"{name} must not contain parent traversal")
    if len({item.casefold() for item in values}) != len(values):
        raise CoverageValidityError(f"{name} must not contain duplicates")
    return tuple(sorted(values, key=lambda item: (item.casefold(), item)))


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
        raise CoverageValidityError("coverage content must be JSON-compatible") from exc


def _json_copy(value: object) -> Any:
    return json.loads(_canonical_bytes(value))


def _reason_prefix(layer_id: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", layer_id.upper()).strip("_")


@dataclass(frozen=True, slots=True)
class CoverageCap:
    """One explicit scan cap and its observed saturation state."""

    kind: str
    limit: int
    observed: int
    reached: bool

    def __post_init__(self) -> None:
        _text(self.kind, "cap.kind")
        _plain_int(self.limit, "cap.limit")
        _plain_int(self.observed, "cap.observed")
        if not isinstance(self.reached, bool):
            raise CoverageValidityError("cap.reached must be a boolean")
        if self.observed > self.limit and not self.reached:
            raise CoverageValidityError("cap.reached cannot be false when observed exceeds limit")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CoverageCap":
        expected = {"kind", "limit", "observed", "reached"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CoverageValidityError("cap fields do not match coverage-validity-v1")
        return cls(
            kind=value["kind"],  # type: ignore[arg-type]
            limit=value["limit"],  # type: ignore[arg-type]
            observed=value["observed"],  # type: ignore[arg-type]
            reached=value["reached"],  # type: ignore[arg-type]
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "limit": self.limit,
            "observed": self.observed,
            "reached": self.reached,
        }


@dataclass(frozen=True, slots=True)
class CoverageLayerInput:
    """Machine observations for one independently assessed coverage layer."""

    layer_id: str
    fresh: bool
    items_considered: int
    bytes_read: int
    scan_complete: bool
    cap: CoverageCap | None = None
    configured: bool = True
    available: bool = True
    uncovered_reason_codes: Sequence[str] = ()
    representative_uncovered_paths: Sequence[str] = ()

    def __post_init__(self) -> None:
        _text(self.layer_id, "layer_id")
        if not isinstance(self.fresh, bool):
            raise CoverageValidityError("fresh must be a boolean")
        if not isinstance(self.scan_complete, bool):
            raise CoverageValidityError("scan_complete must be a boolean")
        if not isinstance(self.configured, bool) or not isinstance(self.available, bool):
            raise CoverageValidityError("configured and available must be booleans")
        _plain_int(self.items_considered, "items_considered")
        _plain_int(self.bytes_read, "bytes_read")
        if self.cap is not None and not isinstance(self.cap, CoverageCap):
            raise CoverageValidityError("cap must be CoverageCap or None")
        if self.cap is not None and self.cap.reached and self.scan_complete:
            raise CoverageValidityError(
                "a reached cap cannot be paired with scan_complete=true"
            )
        if not self.configured and (
            self.available
            or self.scan_complete
            or self.items_considered
            or self.bytes_read
            or self.cap is not None
        ):
            raise CoverageValidityError(
                "an unconfigured layer cannot report availability, observations, or a cap"
            )
        if not self.available and (
            self.scan_complete or self.items_considered or self.bytes_read
        ):
            raise CoverageValidityError(
                "an unavailable layer cannot report a completed scan or observations"
            )
        _bounded_unique_texts(
            self.uncovered_reason_codes,
            "uncovered_reason_codes",
            _MAX_REASON_CODES,
        )
        _bounded_unique_texts(
            self.representative_uncovered_paths,
            "representative_uncovered_paths",
            20,
            path_like=True,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "CoverageLayerInput":
        required = {
            "layer_id",
            "fresh",
            "items_considered",
            "bytes_read",
            "scan_complete",
        }
        allowed = required | {
            "cap",
            "configured",
            "available",
            "uncovered_reason_codes",
            "representative_uncovered_paths",
        }
        if (
            not isinstance(value, Mapping)
            or not required.issubset(value)
            or not set(value).issubset(allowed)
        ):
            raise CoverageValidityError("layer input fields do not match v1")
        cap_value = value.get("cap")
        if cap_value is not None and not isinstance(cap_value, Mapping):
            raise CoverageValidityError("cap must be an object or null")
        return cls(
            layer_id=value["layer_id"],  # type: ignore[arg-type]
            fresh=value["fresh"],  # type: ignore[arg-type]
            items_considered=value["items_considered"],  # type: ignore[arg-type]
            bytes_read=value["bytes_read"],  # type: ignore[arg-type]
            scan_complete=value["scan_complete"],  # type: ignore[arg-type]
            cap=CoverageCap.from_mapping(cap_value) if cap_value is not None else None,
            configured=value.get("configured", True),  # type: ignore[arg-type]
            available=value.get("available", True),  # type: ignore[arg-type]
            uncovered_reason_codes=value.get(
                "uncovered_reason_codes", ()
            ),  # type: ignore[arg-type]
            representative_uncovered_paths=value.get(
                "representative_uncovered_paths", ()
            ),  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class CoverageValidity:
    """Immutable, schema-ready coverage evaluation."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")

    @property
    def coverage_id(self) -> str:
        return self.payload["coverage_id"]

    @property
    def basis(self) -> CoverageBasis:
        return self.payload["basis"]


@dataclass(frozen=True, slots=True)
class CoverageEvidenceBinding:
    """Explicit broad/direct binding that keeps both coverage records unchanged."""

    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return _json_copy(self.payload)

    def to_json(self) -> str:
        return _canonical_bytes(self.payload).decode("utf-8")


def _requested_scope(value: Mapping[str, object]) -> dict[str, list[str]]:
    if not isinstance(value, Mapping) or set(value) != set(_SCOPE_FIELDS):
        raise CoverageValidityError("requested_scope fields do not match coverage-validity-v1")
    return {
        field: list(
            _bounded_unique_texts(
                value[field],
                f"requested_scope.{field}",
                _MAX_SCOPE_ITEMS,
                path_like=field == "canonical_paths",
            )
        )
        for field in _SCOPE_FIELDS
    }


def _layer_result(layer: CoverageLayerInput, basis: CoverageBasis) -> dict[str, Any]:
    prefix = _reason_prefix(layer.layer_id)
    reasons = set(
        _bounded_unique_texts(
            layer.uncovered_reason_codes,
            "uncovered_reason_codes",
            _MAX_REASON_CODES,
        )
    )
    if not layer.configured:
        status: LayerStatus = "NOT_CONFIGURED"
        reasons.add(f"{prefix}_NOT_CONFIGURED")
    elif not layer.available:
        status = "UNAVAILABLE"
        reasons.add(f"{prefix}_UNAVAILABLE")
    elif layer.cap is not None and layer.cap.reached:
        status = "PARTIAL_LIMIT_REACHED"
        reasons.add(f"{prefix}_CAP_{_reason_prefix(layer.cap.kind)}_REACHED")
    elif not layer.fresh:
        status = "PARTIAL_STALE"
        reasons.add(f"{prefix}_STALE")
    elif not layer.scan_complete:
        status = "UNKNOWN"
        reasons.add(f"{prefix}_SCAN_INCOMPLETE")
    elif layer.items_considered == 0:
        status = "UNKNOWN"
        reasons.add(f"{prefix}_ZERO_ITEMS_CONSIDERED")
    elif basis == "direct_exact_scan":
        status = "COMPLETE_FOR_REQUESTED_SCOPE"
    else:
        status = "COMPLETE"

    return {
        "layer_id": layer.layer_id,
        "status": status,
        "fresh": layer.fresh,
        "items_considered": layer.items_considered,
        "bytes_read": layer.bytes_read,
        "cap": layer.cap.to_dict() if layer.cap is not None else None,
        "uncovered_reason_codes": sorted(reasons),
        "representative_uncovered_paths": list(
            _bounded_unique_texts(
                layer.representative_uncovered_paths,
                "representative_uncovered_paths",
                20,
                path_like=True,
            )
        ),
    }


def _overall_status(layer_results: Sequence[Mapping[str, Any]], basis: CoverageBasis) -> str:
    statuses = {layer["status"] for layer in layer_results}
    if "PARTIAL_LIMIT_REACHED" in statuses:
        return "PARTIAL_LIMIT_REACHED"
    if "PARTIAL_STALE" in statuses:
        return "PARTIAL_STALE"
    if statuses == {"UNAVAILABLE"}:
        return "UNAVAILABLE"
    if basis == "direct_exact_scan" and statuses.issubset(
        {"COMPLETE", "COMPLETE_FOR_REQUESTED_SCOPE"}
    ):
        return "COMPLETE_FOR_REQUESTED_SCOPE"
    if basis == "active_snapshot" and statuses == {"COMPLETE"}:
        return "COMPLETE"
    return "INCONCLUSIVE"


def evaluate_coverage_validity(
    *,
    coverage_id: str,
    operation: str,
    basis: CoverageBasis,
    requested_scope: Mapping[str, object],
    layers: Sequence[CoverageLayerInput],
) -> CoverageValidity:
    """Evaluate coverage and explicit claim permissions from bounded machine inputs."""

    checked_id = _text(coverage_id, "coverage_id")
    checked_operation = _text(operation, "operation")
    if basis not in _BASES:
        raise CoverageValidityError("basis is not supported by coverage-validity-v1")
    layer_values = _sequence(layers, "layers", _MAX_LAYERS)
    if not layer_values:
        raise CoverageValidityError("layers must contain at least one layer")
    if any(not isinstance(layer, CoverageLayerInput) for layer in layer_values):
        raise CoverageValidityError("layers must contain CoverageLayerInput values")
    typed_layers = tuple(layer_values)  # type: ignore[assignment]
    layer_ids = [layer.layer_id.casefold() for layer in typed_layers]
    if len(layer_ids) != len(set(layer_ids)):
        raise CoverageValidityError("layer_id values must be unique")

    scope = _requested_scope(requested_scope)
    results = sorted(
        (_layer_result(layer, basis) for layer in typed_layers),
        key=lambda layer: (layer["layer_id"].casefold(), layer["layer_id"]),
    )
    overall = _overall_status(results, basis)
    complete = overall in {"COMPLETE", "COMPLETE_FOR_REQUESTED_SCOPE"}
    presence_allowed = any(
        layer["items_considered"] > 0 or layer["bytes_read"] > 0 for layer in results
    )
    reason_codes = sorted(
        {
            reason
            for layer in results
            for reason in layer["uncovered_reason_codes"]
        }
    )
    if basis == "manual_contributions":
        complete = False
        overall = "INCONCLUSIVE"
        reason_codes.append("MANUAL_CONTRIBUTIONS_NOT_EXHAUSTIVE")
    elif basis == "hybrid":
        complete = False
        overall = "INCONCLUSIVE"
        reason_codes.append("HYBRID_REQUIRES_EXPLICIT_BASIS_BINDING")
    reason_codes = sorted(set(reason_codes))
    if len(reason_codes) > _MAX_REASON_CODES:
        raise CoverageValidityError("derived reason codes exceed the hard bound")

    payload = {
        "schema_version": "kcd2.coverage-validity.v1",
        "coverage_id": checked_id,
        "operation": checked_operation,
        "basis": basis,
        "requested_scope": scope,
        "layers": results,
        "overall_status": overall,
        "claim_permissions": {
            "presence_claim_allowed": presence_allowed,
            "absence_claim_allowed": complete,
            "winner_claim_allowed": complete,
            "conflict_absence_claim_allowed": complete,
        },
        "reason_codes": reason_codes,
    }
    return CoverageValidity(payload=_json_copy(payload))


def _validated_scope_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
    required_declaration = {
        "receipt_id",
        "operation",
        "requested_target",
        "declared_limits",
        "allowed_roots",
    }
    if not isinstance(receipt, Mapping) or not required_declaration.issubset(receipt):
        raise CoverageValidityError("direct evidence requires a target-scope receipt")
    declaration = {name: receipt[name] for name in required_declaration}
    try:
        guard = ScopeGuard.from_contract(declaration)
        return guard.require_ok(receipt)
    except TargetScopeReceiptError as exc:
        raise CoverageValidityError(
            "direct evidence requires a valid TARGET_SCOPE_OK receipt"
        ) from exc


def _bound_hashes(value: Mapping[str, object]) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise CoverageValidityError("bound_input_sha256s must contain at least one input")
    if len(value) > _MAX_BOUND_INPUTS:
        raise CoverageValidityError(
            f"bound_input_sha256s exceeds the {_MAX_BOUND_INPUTS}-input hard bound"
        )
    result: dict[str, str] = {}
    for name, digest in value.items():
        checked_name = _text(name, "bound input name")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise CoverageValidityError(f"bound input {checked_name!r} is not a SHA-256")
        key = checked_name.casefold()
        if key in {existing.casefold() for existing in result}:
            raise CoverageValidityError("bound input names must be case-insensitively unique")
        result[checked_name] = digest.lower()
    return dict(sorted(result.items(), key=lambda item: (item[0].casefold(), item[0])))


def bind_broad_and_direct_evidence(
    *,
    broad_coverage: CoverageValidity,
    direct_coverage_id: str,
    operation: str,
    requested_scope: Mapping[str, object],
    layers: Sequence[CoverageLayerInput],
    scope_receipt: Mapping[str, Any],
    bound_input_sha256s: Mapping[str, object],
) -> CoverageEvidenceBinding:
    """Bind a direct exact proof without upgrading or merging the broad snapshot."""

    if not isinstance(broad_coverage, CoverageValidity):
        raise CoverageValidityError("broad_coverage must be CoverageValidity")
    if broad_coverage.basis != "active_snapshot":
        raise CoverageValidityError("broad_coverage must retain active_snapshot basis")
    scope = _requested_scope(requested_scope)
    if not any(scope[field] for field in ("mod_ids", "canonical_paths")):
        raise CoverageValidityError("a direct exact request must name a mod ID or canonical path")
    if not scope["provider_kinds"]:
        raise CoverageValidityError("a direct exact request must name eligible provider kinds")

    validated_receipt = _validated_scope_receipt(scope_receipt)
    hashes = _bound_hashes(bound_input_sha256s)
    direct = evaluate_coverage_validity(
        coverage_id=direct_coverage_id,
        operation=operation,
        basis="direct_exact_scan",
        requested_scope=scope,
        layers=layers,
    )
    direct_payload = direct.to_dict()
    if direct_payload["overall_status"] != "COMPLETE_FOR_REQUESTED_SCOPE":
        raise CoverageValidityError(
            "direct inputs do not establish COMPLETE_FOR_REQUESTED_SCOPE"
        )

    receipt_sha256 = hashlib.sha256(_canonical_bytes(validated_receipt)).hexdigest()
    broad_payload = broad_coverage.to_dict()
    broad_sha256 = hashlib.sha256(_canonical_bytes(broad_payload)).hexdigest()
    direct_sha256 = hashlib.sha256(_canonical_bytes(direct_payload)).hexdigest()
    claim_basis = {
        claim: {
            "coverage_id": direct.coverage_id,
            "basis": "direct_exact_scan",
            "allowed": direct_payload["claim_permissions"][claim],
        }
        for claim in _CLAIMS
    }
    identity_seed = {
        "broad_coverage_id": broad_coverage.coverage_id,
        "broad_coverage_sha256": broad_sha256,
        "direct_coverage_id": direct.coverage_id,
        "direct_coverage_sha256": direct_sha256,
        "scope_receipt_sha256": receipt_sha256,
        "bound_input_sha256s": hashes,
    }
    binding_id = "coverage-binding:" + hashlib.sha256(
        _canonical_bytes(identity_seed)
    ).hexdigest()
    payload = {
        "schema_version": "kcd2.coverage-evidence-binding.v1",
        "binding_id": binding_id,
        "basis": "direct_exact_scan",
        "broad_snapshot": broad_payload,
        "broad_snapshot_sha256": broad_sha256,
        "direct_exact": direct_payload,
        "direct_exact_sha256": direct_sha256,
        "scope_receipt_id": validated_receipt["receipt_id"],
        "scope_receipt_sha256": receipt_sha256,
        "bound_input_sha256s": hashes,
        "claim_basis": claim_basis,
    }
    return CoverageEvidenceBinding(payload=_json_copy(payload))
