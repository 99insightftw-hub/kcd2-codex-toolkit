"""Fail-closed validation for native-stage correlation and call routing."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


CORRELATION_VERSION = "kcd2.native-stage-correlation.v1"
MAX_CORRELATIONS = 64
MAX_DIAGNOSTICS = 256
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_RVA = re.compile(r"^0x[A-Fa-f0-9]+$")
_CHECKPOINT = re.compile(r"^[A-Za-z0-9_.-]{1,128}\+0x[A-Fa-f0-9]+$")
_STRATEGIES = frozenset(
    {
        "same_owner_function",
        "exact_caller_return",
        "same_object_lifetime_proven",
        "tls_lifetime_proven",
        "bounded_x64dbg_proof",
    }
)


@dataclass(frozen=True, slots=True)
class CorrelationDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class ConstraintValidationReport:
    valid: bool
    diagnostics: tuple[CorrelationDiagnostic, ...]

    @property
    def diagnostic_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.diagnostics)


@dataclass(frozen=True, slots=True)
class CorrelationResult:
    correlation_id: str
    strategy: str
    valid: bool
    verdict: str
    diagnostics: tuple[CorrelationDiagnostic, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "strategy": self.strategy,
            "valid": self.valid,
            "verdict": self.verdict,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class NativeStageCorrelationReport:
    valid: bool
    verdict: str
    correlations: tuple[CorrelationResult, ...]
    diagnostics: tuple[CorrelationDiagnostic, ...]
    diagnostics_truncated: bool

    @property
    def diagnostic_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.native-stage-correlation-validation.v1",
            "status": "PASS" if self.valid else "FAIL",
            "correlation_contract_valid": self.valid,
            "verdict": self.verdict,
            "correlations": [item.to_dict() for item in self.correlations],
            "diagnostics": [item.to_dict() for item in self.diagnostics],
            "diagnostics_truncated": self.diagnostics_truncated,
        }


class _Collector:
    def __init__(self, maximum: int = MAX_DIAGNOSTICS) -> None:
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 10_000:
            raise ValueError("max_diagnostics must be between 1 and 10000")
        self.maximum = maximum
        self.items: list[CorrelationDiagnostic] = []
        self.truncated = False

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.items) < self.maximum:
            self.items.append(CorrelationDiagnostic(code, path, message))
        else:
            self.truncated = True


def validate_owner_function(
    correlation: Mapping[str, Any], module_sha256: str
) -> ConstraintValidationReport:
    """Validate a same-owner checkpoint against module-relative static proof."""
    collector = _Collector()
    _validate_owner(correlation.get("owner_function"), module_sha256, "$.owner_function", collector)
    return ConstraintValidationReport(not collector.items, tuple(collector.items))


def validate_caller_return_lock(
    correlation: Mapping[str, Any], module_sha256: str
) -> ConstraintValidationReport:
    """Validate an exact caller or return lock and its static citation."""
    collector = _Collector()
    _validate_caller_return(
        correlation.get("caller_return_lock"),
        module_sha256,
        "$.caller_return_lock",
        collector,
    )
    return ConstraintValidationReport(not collector.items, tuple(collector.items))


def validate_native_stage_correlation(
    document: Mapping[str, Any], *, max_diagnostics: int = MAX_DIAGNOSTICS
) -> NativeStageCorrelationReport:
    """Validate standalone or probe-manifest correlation contracts without live access."""
    collector = _Collector(max_diagnostics)
    if not isinstance(document, Mapping):
        collector.add("DOCUMENT_TYPE_INVALID", "$", "correlation input must be an object")
        return _report(collector, [])

    version = document.get("schema_version")
    if version not in {CORRELATION_VERSION, "kcd2.probe-contract.v2"}:
        collector.add(
            "SCHEMA_VERSION_INVALID",
            "$.schema_version",
            f"schema_version must be {CORRELATION_VERSION} or kcd2.probe-contract.v2",
        )
    module_sha256 = _document_module_sha256(document)
    if module_sha256 is None:
        collector.add(
            "MODULE_IDENTITY_INVALID",
            "$.module_sha256",
            "correlation input requires an exact 64-digit module SHA-256",
        )
        module_sha256 = ""

    raw_correlations = document.get("correlations")
    collection_path = "$.correlations"
    if raw_correlations is None and version == "kcd2.probe-contract.v2":
        raw_correlations = document.get("correlation_contracts")
        collection_path = "$.correlation_contracts"
    if not isinstance(raw_correlations, list) or not raw_correlations:
        collector.add(
            "CORRELATION_COLLECTION_INVALID",
            collection_path,
            "correlations must be a non-empty array",
        )
        raw_correlations = []
    if len(raw_correlations) > MAX_CORRELATIONS:
        collector.add(
            "CORRELATION_COLLECTION_LIMIT",
            collection_path,
            f"correlations exceeds {MAX_CORRELATIONS} entries",
        )

    results: list[CorrelationResult] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_correlations[:MAX_CORRELATIONS]):
        path = f"{collection_path}[{index}]"
        before = len(collector.items)
        correlation_id = f"invalid-{index}"
        strategy = "invalid"
        if not isinstance(raw, Mapping):
            collector.add("CORRELATION_TYPE_INVALID", path, "correlation must be an object")
        else:
            correlation_id = _bounded_name(raw.get("correlation_id")) or correlation_id
            strategy_value = raw.get("strategy")
            strategy = strategy_value if isinstance(strategy_value, str) else "invalid"
            if correlation_id in seen_ids:
                collector.add(
                    "CORRELATION_ID_DUPLICATE",
                    f"{path}.correlation_id",
                    "correlation_id must be unique",
                )
            seen_ids.add(correlation_id)
            _validate_correlation(raw, module_sha256, path, collector)
        diagnostics = tuple(collector.items[before:])
        valid = not diagnostics
        results.append(
            CorrelationResult(
                correlation_id=correlation_id,
                strategy=strategy,
                valid=valid,
                verdict="correlation_valid" if valid else "capture_inconclusive",
                diagnostics=diagnostics,
            )
        )
    return _report(collector, results)


validate_correlation_contract = validate_native_stage_correlation
validate_owner_constraint = validate_owner_function
validate_caller_return_constraint = validate_caller_return_lock


def _validate_correlation(
    correlation: Mapping[str, Any],
    module_sha256: str,
    path: str,
    collector: _Collector,
) -> None:
    correlation_id = _bounded_name(correlation.get("correlation_id"))
    if correlation_id is None:
        collector.add(
            "CORRELATION_ID_INVALID",
            f"{path}.correlation_id",
            "correlation_id must contain 1 to 128 bounded characters",
        )
    source = _validate_stage(correlation.get("source_stage"), f"{path}.source_stage", collector)
    target = _validate_stage(correlation.get("target_stage"), f"{path}.target_stage", collector)
    strategy = correlation.get("strategy")
    if strategy not in _STRATEGIES:
        collector.add(
            "CORRELATION_STRATEGY_INVALID",
            f"{path}.strategy",
            "correlation strategy is not recognized",
        )
        return
    observations = correlation.get("observations")
    if not isinstance(observations, Mapping) or set(observations) != {
        "same_thread",
        "same_pointer",
        "tls_storage",
    }:
        collector.add(
            "OBSERVATIONS_INVALID",
            f"{path}.observations",
            "observations must explicitly declare same-thread, same-pointer, and TLS state",
        )
    elif any(not isinstance(value, bool) for value in observations.values()):
        collector.add(
            "OBSERVATIONS_INVALID",
            f"{path}.observations",
            "correlation observations must be boolean",
        )

    owner_collector = _Collector()
    _validate_owner(
        correlation.get("owner_function"),
        module_sha256,
        f"{path}.owner_function",
        owner_collector,
    )
    owner = correlation.get("owner_function")
    owner_proven = isinstance(owner, Mapping) and not owner_collector.items
    if owner_proven and strategy != "same_owner_function":
        collector.add(
            "OWNER_FUNCTION_PREFERRED",
            f"{path}.strategy",
            "use the proven owner function that owns both query and returned output",
        )

    if strategy == "same_owner_function":
        for diagnostic in owner_collector.items:
            collector.add(diagnostic.code, diagnostic.path, diagnostic.message)
    elif strategy == "exact_caller_return":
        _validate_caller_return(
            correlation.get("caller_return_lock"),
            module_sha256,
            f"{path}.caller_return_lock",
            collector,
        )
    elif strategy in {"same_object_lifetime_proven", "tls_lifetime_proven"}:
        storage = "tls" if strategy == "tls_lifetime_proven" else "object"
        _validate_lifetime(
            correlation.get("lifetime_proof"), module_sha256, storage, path, collector
        )
    elif strategy == "bounded_x64dbg_proof":
        _validate_x64dbg(
            correlation.get("x64dbg_proof"), module_sha256, f"{path}.x64dbg_proof", collector
        )

    separated = (
        source is not None
        and target is not None
        and (source[0] != target[0] or source[1] != target[1])
    )
    if separated and strategy != "bounded_x64dbg_proof":
        collector.add(
            "SEPARATED_STAGE_X64DBG_PROOF_REQUIRED",
            f"{path}.strategy",
            "separated native stages require one bounded x64dbg routing and lifetime proof",
        )


def _validate_stage(
    stage: object, path: str, collector: _Collector
) -> tuple[str, str] | None:
    if not isinstance(stage, Mapping):
        collector.add("STAGE_INVALID", path, "stage must be an object")
        return None
    stage_id = _bounded_name(stage.get("stage_id"))
    hook_id = _bounded_name(stage.get("hook_id"))
    if stage_id is None:
        collector.add("STAGE_ID_INVALID", f"{path}.stage_id", "stage_id is invalid")
    if hook_id is None:
        collector.add("HOOK_ID_INVALID", f"{path}.hook_id", "hook_id is invalid")
    return (stage_id, hook_id) if stage_id is not None and hook_id is not None else None


def _validate_owner(
    owner: object, module_sha256: str, path: str, collector: _Collector
) -> None:
    if not isinstance(owner, Mapping):
        collector.add(
            "OWNER_FUNCTION_PROOF_REQUIRED",
            path,
            "same-owner correlation requires structured owner proof",
        )
        return
    _validate_location(owner, module_sha256, "function_rva", path, collector)
    if owner.get("owns_query") is not True or owner.get("owns_output") is not True:
        collector.add(
            "OWNER_QUERY_OUTPUT_NOT_PROVEN",
            path,
            "owner function must own both query and returned output",
        )
    if not _valid_evidence(
        owner.get("static_evidence"), module_sha256, "static", f"{path}.static_evidence"
    ):
        collector.add(
            "OWNER_STATIC_EVIDENCE_REQUIRED",
            f"{path}.static_evidence",
            "owner function requires module-relative static evidence",
        )


def _validate_caller_return(
    lock: object, module_sha256: str, path: str, collector: _Collector
) -> None:
    if not isinstance(lock, Mapping):
        collector.add(
            "CALLER_RETURN_LOCK_REQUIRED",
            path,
            "exact caller/return correlation requires a structured lock",
        )
        return
    if lock.get("lock_kind") not in {"exact_caller_rva", "exact_return_rva"}:
        collector.add(
            "CALLER_RETURN_LOCK_KIND_INVALID",
            f"{path}.lock_kind",
            "lock_kind must select an exact caller or exact return RVA",
        )
    _validate_location(lock, module_sha256, "lock_rva", path, collector)
    if not _valid_evidence(
        lock.get("static_evidence"), module_sha256, "static", f"{path}.static_evidence"
    ):
        collector.add(
            "CALLER_RETURN_STATIC_EVIDENCE_REQUIRED",
            f"{path}.static_evidence",
            "exact caller/return locks require module-relative static evidence",
        )


def _validate_lifetime(
    proof: object,
    module_sha256: str,
    storage: str,
    path: str,
    collector: _Collector,
) -> None:
    code_prefix = "TLS" if storage == "tls" else "OBJECT"
    if not isinstance(proof, Mapping) or proof.get("storage") != storage:
        collector.add(
            f"{code_prefix}_LIFETIME_PROOF_REQUIRED",
            f"{path}.lifetime_proof",
            f"{storage} correlation requires explicit lifetime proof",
        )
        return
    lifetime_valid = _valid_mixed_evidence(
        proof.get("lifetime_evidence"), module_sha256, f"{path}.lifetime_proof.lifetime_evidence"
    )
    routing_valid = _valid_mixed_evidence(
        proof.get("routing_evidence"), module_sha256, f"{path}.lifetime_proof.routing_evidence"
    )
    if not lifetime_valid:
        collector.add(
            f"{code_prefix}_LIFETIME_PROOF_REQUIRED",
            f"{path}.lifetime_proof.lifetime_evidence",
            f"{storage} lifetime must be proven by static or runtime evidence",
        )
    if not routing_valid:
        collector.add(
            "CALL_ROUTING_PROOF_REQUIRED",
            f"{path}.lifetime_proof.routing_evidence",
            "lifetime evidence does not independently prove call routing",
        )


def _validate_x64dbg(
    proof: object, module_sha256: str, path: str, collector: _Collector
) -> None:
    if not isinstance(proof, Mapping):
        collector.add(
            "X64DBG_PROOF_REQUIRED",
            path,
            "bounded_x64dbg_proof requires a structured proof receipt",
        )
        return
    if not _same_hash(proof.get("module_sha256"), module_sha256):
        collector.add(
            "X64DBG_MODULE_MISMATCH",
            f"{path}.module_sha256",
            "x64dbg proof must bind the correlation module SHA-256",
        )
    for name, maximum in (("maximum_breakpoints", 16), ("maximum_events", 10_000)):
        value = proof.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            collector.add(
                "X64DBG_BOUND_INVALID",
                f"{path}.{name}",
                f"{name} must be bounded from 1 to {maximum}",
            )
    if _bounded_string(proof.get("session_id"), 256) is None:
        collector.add(
            "X64DBG_CHECKPOINT_INVALID",
            f"{path}.session_id",
            "session_id must be a bounded non-empty string",
        )
    for name in ("source_checkpoint", "target_checkpoint"):
        value = proof.get(name)
        if not isinstance(value, str) or _CHECKPOINT.fullmatch(value) is None:
            collector.add(
                "X64DBG_CHECKPOINT_INVALID",
                f"{path}.{name}",
                f"{name} must use module-name+RVA form",
            )
    complete = all(
        proof.get(name) is True
        for name in (
            "thread_identity_proven",
            "pointer_lifetime_proven",
            "arguments_proven",
            "call_stack_proven",
        )
    )
    if not complete:
        collector.add(
            "X64DBG_PROOF_INCOMPLETE",
            path,
            "x64dbg proof must cover thread, pointer lifetime, arguments, and call stack",
        )
    if not _valid_evidence(
        proof.get("runtime_evidence"), module_sha256, "runtime", f"{path}.runtime_evidence"
    ):
        collector.add(
            "X64DBG_RUNTIME_EVIDENCE_REQUIRED",
            f"{path}.runtime_evidence",
            "bounded x64dbg proof requires module-bound runtime evidence",
        )


def _validate_location(
    value: Mapping[str, Any],
    module_sha256: str,
    rva_field: str,
    path: str,
    collector: _Collector,
) -> None:
    if not _same_hash(value.get("module_sha256"), module_sha256):
        collector.add(
            "PROOF_MODULE_MISMATCH",
            f"{path}.module_sha256",
            "proof must use the correlation document module SHA-256",
        )
    rva = value.get(rva_field)
    if not isinstance(rva, str) or _RVA.fullmatch(rva) is None:
        collector.add(
            "PROOF_RVA_INVALID",
            f"{path}.{rva_field}",
            "native proof locations must use a module-relative RVA",
        )


def _valid_mixed_evidence(value: object, module_sha256: str, path: str) -> bool:
    return _valid_evidence(value, module_sha256, None, path)


def _valid_evidence(
    value: object, module_sha256: str, required_class: str | None, path: str
) -> bool:
    del path
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        return False
    for citation in value:
        if not isinstance(citation, Mapping):
            return False
        evidence_class = citation.get("evidence_class")
        if evidence_class not in {"static", "runtime"}:
            return False
        if required_class is not None and evidence_class != required_class:
            return False
        if not _same_hash(citation.get("module_sha256"), module_sha256):
            return False
        for name, maximum in (("artifact", 1024), ("locator", 1024), ("claim", 2000)):
            if _bounded_string(citation.get(name), maximum) is None:
                return False
    return True


def _document_module_sha256(document: Mapping[str, Any]) -> str | None:
    value = document.get("module_sha256")
    if value is None:
        expected_module = document.get("expected_module")
        if isinstance(expected_module, Mapping):
            value = expected_module.get("sha256")
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        return None
    return value.lower()


def _same_hash(value: object, expected: str) -> bool:
    return isinstance(value, str) and value.casefold() == expected.casefold()


def _bounded_name(value: object) -> str | None:
    return _bounded_string(value, 128)


def _bounded_string(value: object, maximum: int) -> str | None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        return None
    return value


def _report(
    collector: _Collector, results: list[CorrelationResult]
) -> NativeStageCorrelationReport:
    valid = not collector.items and not collector.truncated and bool(results)
    return NativeStageCorrelationReport(
        valid=valid,
        verdict="correlation_valid" if valid else "capture_inconclusive",
        correlations=tuple(results),
        diagnostics=tuple(collector.items),
        diagnostics_truncated=collector.truncated,
    )
