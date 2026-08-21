"""Aggregate fail-closed machine gates before a probe gameplay handoff."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

from .correlation import validate_native_stage_correlation
from .source_contract import ProbeSourceContractError, generate_probe_contract


INPUT_VERSION = "kcd2.probe-playtest-readiness-input.v1"
RECEIPT_VERSION = "kcd2.probe-playtest-readiness.v1"
MAX_EVENT_FAMILIES = 128
MAX_EVENTS_PER_FAMILY = 100_000
MAX_BYTES_PER_FAMILY = 33_554_432
_SHA256 = re.compile(r"^[A-Fa-f0-9]{64}$")
_HEX = re.compile(r"^0x[A-Fa-f0-9]+$")

FAILURE_REASON_CATALOG = MappingProxyType(
    {
        "MANIFEST_INVALID": "The v2 manifest is incomplete or cannot be canonicalized.",
        "MODULE_PROFILE_MISMATCH": "A prerequisite is not bound to the manifest module hash.",
        "RECORD_LAYOUT_INVALID": "Family-specific record-layout lint did not pass.",
        "ENTRY_LOCK_INVALID": "Raw-PE entry locks are missing, stale, or unsafe.",
        "PROTOTYPE_ABI_UNRESOLVED": "At least one enabled hook ABI remains unresolved.",
        "STOLEN_INSTRUCTIONS_UNSAFE": "At least one stolen-instruction range is unsafe.",
        "TRAMPOLINE_UNSAFE": "At least one enabled hook trampoline is unsafe.",
        "CALLER_OWNER_CORRELATION_UNRESOLVED": (
            "Caller, owner, lifetime, or separated-stage routing is not proven."
        ),
        "SOURCE_MANIFEST_COMPILED_MISMATCH": (
            "Generated source, manifest, and compiled contract do not agree."
        ),
        "CONTROLS_INSUFFICIENT": (
            "Neither bounded unfiltered population nor a same-path positive control is declared."
        ),
        "NEGATIVE_VALIDITY_POLICY_INCOMPLETE": (
            "The reviewed fail-closed negative-evidence policy is incomplete."
        ),
        "EVENT_BOUNDS_INVALID": "Named event schemas and hard-bounded event limits disagree.",
        "BOOT_NOT_CONFIRMED": "The session BOOT machine check did not pass.",
        "INSTALL_OK_INVALID": "INSTALL_OK identity is missing or inconsistent with the manifest.",
        "PROCESS_UNRESPONSIVE": "The target process responsiveness check did not pass.",
        "DEBUGGER_HANDOFF_UNSAFE": "Debugger state is incompatible with the carrier handoff rule.",
        "DEPLOYMENT_IDENTITY_INVALID": "Exact deployment identity is absent or inconsistent.",
    }
)

_CHECK_NAMES = (
    "module_profile",
    "record_layout",
    "entry_lock",
    "prototype_trampoline",
    "caller_owner_correlation",
    "source_manifest_compiled",
    "controls",
    "negative_validity_policy",
    "event_bounds",
    "boot_install_ok",
    "responsiveness",
    "debugger_state",
    "deployment_identity",
)

_POLICY_KEYS = (
    "require_boot",
    "require_install_ok",
    "require_game_fingerprint",
    "require_exact_deployment_binding",
    "require_module_base",
    "require_unfiltered_queries",
    "require_valid_layout",
    "require_valid_identity_filter",
    "require_control_or_population",
    "require_valid_correlation",
    "require_unsaturated_limits",
    "require_complete_log",
    "require_no_dropped_events",
    "require_user_state_confirmation",
)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _enabled_hooks(manifest: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    hooks = manifest.get("hooks")
    if not isinstance(hooks, list) or not 1 <= len(hooks) <= 64:
        return {}
    result: dict[str, Mapping[str, Any]] = {}
    for hook in hooks:
        if not isinstance(hook, Mapping) or hook.get("enabled") is not True:
            continue
        hook_id = hook.get("hook_id")
        if not isinstance(hook_id, str) or not hook_id or hook_id in result:
            return {}
        result[hook_id] = hook
    return result


def _reason(reasons: set[str], condition: bool, code: str) -> bool:
    if not condition:
        reasons.add(code)
    return condition


def _module_bound(value: Mapping[str, Any], module_sha256: object) -> bool:
    return (
        isinstance(module_sha256, str)
        and _SHA256.fullmatch(module_sha256) is not None
        and value.get("module_sha256") == module_sha256
    )


def _entry_lock_valid(
    report: Mapping[str, Any], hooks: Mapping[str, Mapping[str, Any]], module_sha256: object
) -> bool:
    entries = report.get("hooks")
    if (
        report.get("schema_version") != "kcd2.entry-lock-preflight.v1"
        or report.get("valid") is not True
        or report.get("lock_source") != "raw_pe_rva_mapping"
        or report.get("generated_header_matches_manifest") is not True
        or not _module_bound(report, module_sha256)
        or not isinstance(entries, list)
    ):
        return False
    by_id = {
        item.get("hook_id"): item
        for item in entries
        if isinstance(item, Mapping) and isinstance(item.get("hook_id"), str)
    }
    if set(by_id) != set(hooks):
        return False
    for hook_id, hook in hooks.items():
        item = by_id[hook_id]
        lock = _mapping(hook.get("entry_lock")).get("bytes_hex")
        try:
            expected_rva = int(str(hook.get("rva")), 16)
        except (TypeError, ValueError):
            return False
        if (
            item.get("matches") is not True
            or item.get("hidden_prefix_hex") not in (None, "")
            or item.get("manifest_lock_hex") != lock
            or item.get("generated_lock_hex") != lock
            or item.get("raw_bytes_hex") != lock
            or item.get("rva") != expected_rva
        ):
            return False
    return True


def _prototype_checks(
    report: Mapping[str, Any], hooks: Mapping[str, Mapping[str, Any]], module_sha256: object
) -> tuple[bool, bool, bool]:
    entries = report.get("hooks")
    base_valid = (
        report.get("schema_version") == "kcd2.prototype-trampoline-preflight.v1"
        and report.get("status") == "PASS"
        and _module_bound(report, module_sha256)
        and isinstance(entries, list)
    )
    by_id = {
        item.get("hook_id"): item
        for item in (entries if isinstance(entries, list) else [])
        if isinstance(item, Mapping)
    }
    if not base_valid or set(by_id) != set(hooks):
        return False, False, False
    abi = all(
        by_id[name].get("abi_proven") is True
        and by_id[name].get("prototype_profile") == hook.get("prototype_profile")
        for name, hook in hooks.items()
    )
    stolen = all(by_id[name].get("stolen_instructions_safe") is True for name in hooks)
    trampoline = all(by_id[name].get("trampoline_safe") is True for name in hooks)
    return abi, stolen, trampoline


def _source_valid(
    report: Mapping[str, Any], manifest: Mapping[str, Any], contract_sha256: str | None
) -> bool:
    source = _mapping(manifest.get("source_contract"))
    return (
        report.get("schema_version") == "kcd2.probe-source-manifest-check.v1"
        and report.get("valid") is True
        and report.get("status", "PASS") == "PASS"
        and isinstance(contract_sha256, str)
        and report.get("manifest_contract_sha256") == contract_sha256
        and report.get("compiled_contract_sha256") == contract_sha256
        and source.get("manifest_sha256") == contract_sha256
        and source.get("compiled_contract_sha256") == contract_sha256
        and report.get("generated_header_sha256") == source.get("generated_header_sha256")
        and report.get("diagnostics") == []
    )


def _controls_valid(manifest: Mapping[str, Any]) -> bool:
    controls = _mapping(manifest.get("controls"))
    if controls.get("unfiltered_population") is True:
        return True
    event_families = set(_mapping(manifest.get("event_limits")))
    positive = controls.get("positive_controls")
    return isinstance(positive, list) and any(
        isinstance(item, Mapping)
        and item.get("same_filter_path") is True
        and item.get("expected_event_family") in event_families
        for item in positive[:64]
    )


def _event_bounds_valid(manifest: Mapping[str, Any], install_ok: Mapping[str, Any]) -> bool:
    limits = manifest.get("event_limits")
    schemas = manifest.get("event_schemas")
    if (
        not isinstance(limits, Mapping)
        or not 1 <= len(limits) <= MAX_EVENT_FAMILIES
        or not isinstance(schemas, Mapping)
        or set(limits) != set(schemas)
        or install_ok.get("event_limits") != limits
    ):
        return False
    for value in limits.values():
        if not isinstance(value, Mapping):
            return False
        events = value.get("maximum_events")
        byte_limit = value.get("maximum_bytes")
        if (
            not isinstance(events, int)
            or isinstance(events, bool)
            or not 1 <= events <= MAX_EVENTS_PER_FAMILY
            or not isinstance(byte_limit, int)
            or isinstance(byte_limit, bool)
            or not 1 <= byte_limit <= MAX_BYTES_PER_FAMILY
        ):
            return False
    return True


def _install_valid(
    record: Mapping[str, Any], manifest: Mapping[str, Any], contract_sha256: str | None
) -> bool:
    expected = _mapping(manifest.get("expected_module"))
    module = _mapping(record.get("module"))
    probe = _mapping(record.get("probe"))
    scope = _mapping(record.get("scope"))
    return (
        record.get("schema_version") == "kcd2.probe-runtime-identity.v1"
        and record.get("record_type") == "INSTALL_OK"
        and isinstance(record.get("session_id"), str)
        and module.get("name") == expected.get("name")
        and module.get("sha256") == expected.get("sha256")
        and module.get("timestamp") == expected.get("timestamp")
        and module.get("image_size") == expected.get("image_size")
        and isinstance(module.get("base"), str)
        and _HEX.fullmatch(module["base"]) is not None
        and int(module["base"], 16) > 0
        and probe.get("probe_id") == manifest.get("probe_id")
        and probe.get("revision") == manifest.get("revision")
        and probe.get("contract_sha256") == contract_sha256
        and scope.get("event_families") == sorted(_mapping(manifest.get("event_limits")))
        and isinstance(record.get("deployment_binding_sha256"), str)
        and _SHA256.fullmatch(record["deployment_binding_sha256"]) is not None
    )


def _debugger_valid(carrier: object, report: Mapping[str, Any]) -> bool:
    if report.get("schema_version") != "kcd2.debugger-handoff-check.v1":
        return False
    if carrier in {"kcse", "lua"}:
        return report.get("state") == "not_attached" and report.get("debugging") is False
    if carrier in {"x64dbg", "hybrid"}:
        delay = report.get("observed_delay_ms")
        minimum = report.get("minimum_delay_ms")
        return (
            report.get("state") == "connected_running"
            and report.get("debugging") is True
            and report.get("running") is True
            and isinstance(minimum, int)
            and minimum >= 750
            and isinstance(delay, int)
            and delay >= minimum
        )
    return False


def _bounded_proof_request(
    manifest: Mapping[str, Any], uncertainty_reasons: list[str]
) -> dict[str, Any]:
    module = _mapping(manifest.get("expected_module"))
    hooks = _enabled_hooks(manifest)
    checkpoints = [
        {"hook_id": name, "location": f"{module.get('name')}+{hook.get('rva')}"}
        for name, hook in sorted(hooks.items())[:2]
    ]
    return {
        "proof_count": 1,
        "module_sha256": module.get("sha256"),
        "questions": uncertainty_reasons,
        "checkpoint_candidates": checkpoints,
        "maximum_breakpoints": min(2, max(1, len(checkpoints))),
        "maximum_events": 64,
        "maximum_capture_bytes": 65_536,
        "required_observations": [
            "arguments",
            "call_stack",
            "pointer_lifetime",
            "thread_identity",
        ],
        "mutation_policy": "read_only",
    }


def probe_playtest_readiness(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic readiness receipt; never performs a live action."""

    if not isinstance(request, Mapping):
        raise TypeError("readiness request must be an object")
    if request.get("schema_version") != INPUT_VERSION:
        raise ValueError(f"schema_version must be {INPUT_VERSION}")
    request_id = request.get("request_id")
    if not isinstance(request_id, str) or not 1 <= len(request_id) <= 256:
        raise ValueError("request_id must contain 1 to 256 characters")
    manifest = _mapping(request.get("manifest"))
    prerequisites = _mapping(request.get("prerequisites"))
    reasons: set[str] = set()
    checks = {name: False for name in _CHECK_NAMES}

    contract_sha256: str | None = None
    manifest_valid = manifest.get("schema_version") == "kcd2.probe-contract.v2"
    if manifest_valid:
        try:
            contract_sha256 = generate_probe_contract(manifest).contract_sha256
        except (ProbeSourceContractError, TypeError, ValueError):
            manifest_valid = False
    _reason(reasons, manifest_valid, "MANIFEST_INVALID")
    module = _mapping(manifest.get("expected_module"))
    module_sha256 = module.get("sha256")
    hooks = _enabled_hooks(manifest)

    bound_reports = (
        _mapping(prerequisites.get("entry_lock_preflight")),
        _mapping(prerequisites.get("prototype_trampoline_preflight")),
    )
    checks["module_profile"] = manifest_valid and bool(hooks) and all(
        _module_bound(item, module_sha256) for item in bound_reports
    )
    _reason(reasons, checks["module_profile"], "MODULE_PROFILE_MISMATCH")

    layout = _mapping(prerequisites.get("record_layout_lint"))
    checks["record_layout"] = (
        layout.get("schema_version") == "kcd2.record-layout-lint.v1"
        and layout.get("status") == "PASS"
        and layout.get("diagnostics") == []
        and layout.get("diagnostics_truncated") is False
    )
    _reason(reasons, checks["record_layout"], "RECORD_LAYOUT_INVALID")

    entry = bound_reports[0]
    checks["entry_lock"] = _entry_lock_valid(entry, hooks, module_sha256)
    _reason(reasons, checks["entry_lock"], "ENTRY_LOCK_INVALID")

    prototype = bound_reports[1]
    abi, stolen, trampoline = _prototype_checks(prototype, hooks, module_sha256)
    checks["prototype_trampoline"] = abi and stolen and trampoline
    _reason(reasons, abi, "PROTOTYPE_ABI_UNRESOLVED")
    _reason(reasons, stolen, "STOLEN_INSTRUCTIONS_UNSAFE")
    _reason(reasons, trampoline, "TRAMPOLINE_UNSAFE")

    correlation = validate_native_stage_correlation(manifest)
    checks["caller_owner_correlation"] = manifest_valid and correlation.valid
    _reason(
        reasons,
        checks["caller_owner_correlation"],
        "CALLER_OWNER_CORRELATION_UNRESOLVED",
    )

    source = _mapping(prerequisites.get("probe_source_manifest_check"))
    checks["source_manifest_compiled"] = _source_valid(
        source, manifest, contract_sha256
    )
    _reason(
        reasons,
        checks["source_manifest_compiled"],
        "SOURCE_MANIFEST_COMPILED_MISMATCH",
    )

    checks["controls"] = _controls_valid(manifest)
    _reason(reasons, checks["controls"], "CONTROLS_INSUFFICIENT")
    policy = _mapping(manifest.get("negative_evidence_policy"))
    checks["negative_validity_policy"] = all(policy.get(name) is True for name in _POLICY_KEYS)
    _reason(
        reasons,
        checks["negative_validity_policy"],
        "NEGATIVE_VALIDITY_POLICY_INCOMPLETE",
    )

    install = _mapping(prerequisites.get("install_ok"))
    checks["event_bounds"] = _event_bounds_valid(manifest, install)
    _reason(reasons, checks["event_bounds"], "EVENT_BOUNDS_INVALID")

    boot = _mapping(prerequisites.get("boot"))
    install_valid = _install_valid(install, manifest, contract_sha256)
    boot_valid = (
        boot.get("schema_version") == "kcd2.probe-boot-check.v1"
        and boot.get("boot_ok") is True
        and boot.get("session_id") == install.get("session_id")
    )
    _reason(reasons, boot_valid, "BOOT_NOT_CONFIRMED")
    _reason(reasons, install_valid, "INSTALL_OK_INVALID")
    checks["boot_install_ok"] = boot_valid and install_valid

    responsive = _mapping(prerequisites.get("responsiveness"))
    checks["responsiveness"] = (
        responsive.get("schema_version") == "kcd2.process-responsiveness-check.v1"
        and responsive.get("responsive") is True
        and responsive.get("session_id") == install.get("session_id")
    )
    _reason(reasons, checks["responsiveness"], "PROCESS_UNRESPONSIVE")
    debugger = _mapping(prerequisites.get("debugger"))
    checks["debugger_state"] = _debugger_valid(manifest.get("carrier"), debugger)
    _reason(reasons, checks["debugger_state"], "DEBUGGER_HANDOFF_UNSAFE")

    deployment = _mapping(prerequisites.get("deployment_identity"))
    checks["deployment_identity"] = (
        deployment.get("schema_version") == "kcd2.deployment-binding-validation.v1"
        and deployment.get("binding_state") == "EXACT"
        and deployment.get("candidate_promotion_eligible") is True
        and deployment.get("identity_sha256") == install.get("deployment_binding_sha256")
    )
    _reason(reasons, checks["deployment_identity"], "DEPLOYMENT_IDENTITY_INVALID")

    ordered_reasons = sorted(reasons)
    uncertainty = sorted(
        reasons
        & {"PROTOTYPE_ABI_UNRESOLVED", "CALLER_OWNER_CORRELATION_UNRESOLVED"}
    )
    known_defects = set(reasons) - set(uncertainty)
    if not reasons:
        next_action = "user_gameplay"
        proof_request = None
    elif uncertainty and not known_defects:
        next_action = "bounded_x64dbg_proof"
        proof_request = _bounded_proof_request(manifest, uncertainty)
    else:
        next_action = "repair_preflight"
        proof_request = None
    payload: dict[str, Any] = {
        "schema_version": RECEIPT_VERSION,
        "request_id": request_id,
        "input_sha256": _digest(request),
        "probe_id": (
            manifest.get("probe_id") if isinstance(manifest.get("probe_id"), str) else None
        ),
        "session_id": (
            install.get("session_id")
            if isinstance(install.get("session_id"), str)
            else None
        ),
        "module_sha256": module_sha256 if isinstance(module_sha256, str) else None,
        "status": "READY" if not reasons else "BLOCKED",
        "gameplay_handoff_allowed": not reasons,
        "checks": checks,
        "failure_reasons": ordered_reasons,
        "next_action": next_action,
        "x64dbg_proof_request": proof_request,
    }
    receipt_projection = copy.deepcopy(payload)
    payload["receipt_id"] = f"readiness:sha256:{_digest(receipt_projection)}"
    return payload


__all__ = ["FAILURE_REASON_CATALOG", "probe_playtest_readiness"]
