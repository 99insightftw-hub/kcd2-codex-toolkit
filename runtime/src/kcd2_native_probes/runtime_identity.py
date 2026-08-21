"""Import-critical probe-emitted runtime and exact deployment identity.

This module compares supplied records only.  It never derives a live module
base from an absolute address, an RVA, a PE preferred base, or another record.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any

from kcd2_mod_build_deploy.deployment_registry import (
    DeploymentOperation,
    SnapshotGateDecision,
)


SHA256_RE = re.compile(r"[A-Fa-f0-9]{64}")
HEX_RE = re.compile(r"0x[A-Fa-f0-9]+")
SESSION_RE = re.compile(r"session:[A-Za-z0-9_.:-]{1,247}")
RECORD_TYPES = {"INSTALL_OK", "CAPTURE_CLOSE"}
MAX_COMPANIONS = 128
MAX_EVENT_FAMILIES = 128


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _text(value: Any, name: str, maximum: int = 2048) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value.lower()


def _hex(value: Any, name: str, *, nonzero: bool = False) -> str:
    if not isinstance(value, str) or HEX_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be an emitted hexadecimal value")
    number = int(value, 16)
    if number > 2**64 - 1 or (nonzero and number == 0):
        raise ValueError(f"{name} is outside the valid 64-bit range")
    return f"0x{number:X}"


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ValueError(f"{name} must be an integer of at least {minimum}")
    return value


def _file_identity(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a file identity")
    expected = {"path", "sha256", "bytes"}
    if set(value) != expected:
        raise ValueError(f"{name} must contain exactly path, sha256, and bytes")
    return {
        "path": _text(value["path"], f"{name} path"),
        "sha256": _digest(value["sha256"], f"{name} SHA-256"),
        "bytes": _integer(value["bytes"], f"{name} bytes"),
    }


def _pe_identity(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a PE identity")
    expected = {"name", "sha256", "timestamp", "image_size"}
    if set(value) != expected:
        raise ValueError(f"{name} must contain exact PE metadata")
    return {
        "name": _text(value["name"], f"{name} name", 260),
        "sha256": _digest(value["sha256"], f"{name} SHA-256"),
        "timestamp": _hex(value["timestamp"], f"{name} timestamp"),
        "image_size": _integer(value["image_size"], f"{name} image size", minimum=1),
    }


def _deployment_identity(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and select immutable bytes that bind candidate-scoped evidence."""

    if binding.get("schema_version") != "kcd2.runtime-deployment-binding.v1":
        raise ValueError("deployment binding schema version is invalid")
    if binding.get("binding_state") != "EXACT":
        raise ValueError("deployment binding must be EXACT")
    if binding.get("snapshot_freshness") != "fresh_exact":
        raise ValueError("active snapshot must be fresh_exact")
    if binding.get("identity_unchanged") is not True:
        raise ValueError("deployment binding must declare unchanged identity")
    start_fingerprint = _digest(
        binding.get("start_fingerprint_sha256"), "start fingerprint"
    )
    close_fingerprint = _digest(
        binding.get("close_fingerprint_sha256"), "close fingerprint"
    )
    if start_fingerprint != close_fingerprint:
        raise ValueError("deployment binding start and close fingerprints differ")

    target_mod = binding.get("target_mod")
    if not isinstance(target_mod, Mapping) or set(target_mod) != {
        "mod_id",
        "folder_name_exact",
    }:
        raise ValueError("target_mod identity is incomplete")
    game = binding.get("game")
    if not isinstance(game, Mapping) or set(game) != {"version", "executable", "whgame"}:
        raise ValueError("game identity is incomplete")
    probe = binding.get("probe")
    if not isinstance(probe, Mapping) or set(probe) != {
        "probe_id",
        "revision",
        "dll_sha256",
        "source_sha256",
        "contract_sha256",
    }:
        raise ValueError("probe DLL/source identity is required")
    companions = binding.get("companion_components")
    if not isinstance(companions, list) or len(companions) > MAX_COMPANIONS:
        raise ValueError("companion components must be a bounded array")
    normalized_companions = []
    for index, component in enumerate(companions):
        if not isinstance(component, Mapping) or set(component) != {"role", "path", "sha256"}:
            raise ValueError(f"companion component {index} is incomplete")
        normalized_companions.append(
            {
                "role": _text(component["role"], f"companion {index} role", 128),
                "path": _text(component["path"], f"companion {index} path"),
                "sha256": _digest(component["sha256"], f"companion {index} SHA-256"),
            }
        )
    normalized_companions.sort(key=lambda item: (item["role"], item["path"], item["sha256"]))
    keys = [(item["role"], item["path"]) for item in normalized_companions]
    if len(set(keys)) != len(keys):
        raise ValueError("companion component role/path identities must be unique")

    deployment_id = _text(binding.get("deployment_id"), "deployment_id", 96)
    candidate_id = _text(binding.get("candidate_id"), "candidate_id", 94)
    if not deployment_id.startswith("deploy:sha256:") or not candidate_id.startswith(
        "cand:sha256:"
    ):
        raise ValueError("deployment and candidate IDs must be SHA-256 identities")
    _digest(deployment_id.removeprefix("deploy:sha256:"), "deployment ID")
    _digest(candidate_id.removeprefix("cand:sha256:"), "candidate ID")

    return {
        "deployment_id": deployment_id,
        "candidate_id": candidate_id,
        "active_snapshot_id": _text(
            binding.get("active_snapshot_id"), "active_snapshot_id", 256
        ),
        "active_snapshot_sha256": _digest(
            binding.get("active_snapshot_sha256"), "active snapshot SHA-256"
        ),
        "binding_fingerprint_sha256": start_fingerprint,
        "target_mod": {
            "mod_id": _text(target_mod["mod_id"], "target mod ID", 256),
            "folder_name_exact": _text(
                target_mod["folder_name_exact"], "target folder name", 260
            ),
        },
        "target_pak": _file_identity(binding.get("target_pak"), "target PAK"),
        "target_manifest": _file_identity(
            binding.get("target_manifest"), "target manifest"
        ),
        "mod_order": _file_identity(binding.get("mod_order"), "mod order"),
        "companion_components": normalized_companions,
        "game": {
            "version": _text(game["version"], "game version", 128),
            "executable": _pe_identity(game["executable"], "game executable"),
            "whgame": _pe_identity(game["whgame"], "WHGame.dll"),
        },
        "probe": {
            "probe_id": _text(probe["probe_id"], "probe ID", 256),
            "revision": _text(probe["revision"], "probe revision", 128),
            "dll_sha256": _digest(probe["dll_sha256"], "probe DLL SHA-256"),
            "source_sha256": _digest(probe["source_sha256"], "probe source SHA-256"),
            "contract_sha256": _digest(
                probe["contract_sha256"], "probe contract SHA-256"
            ),
        },
    }


def validate_deployment_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical exact identity and its deterministic fingerprint."""

    identity = _deployment_identity(binding)
    return {
        "schema_version": "kcd2.deployment-binding-validation.v1",
        "binding_state": "EXACT",
        "identity": identity,
        "identity_sha256": _sha256(identity),
        "candidate_promotion_eligible": True,
    }


def _enabled_rvas(probe_contract: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    hooks = probe_contract.get("hooks")
    if not isinstance(hooks, list) or len(hooks) > 64:
        raise ValueError("probe contract hooks must be a bounded array")
    hook_rvas: dict[str, str] = {}
    caller_rvas: dict[str, str] = {}
    for hook in hooks:
        if not isinstance(hook, Mapping) or hook.get("enabled") is not True:
            continue
        hook_id = _text(hook.get("hook_id"), "hook ID", 128)
        if hook_id in hook_rvas:
            raise ValueError("enabled hook IDs must be unique")
        hook_rvas[hook_id] = _hex(hook.get("rva"), f"hook {hook_id} RVA")
        caller = hook.get("caller_constraint")
        if isinstance(caller, Mapping) and caller.get("rva") is not None:
            caller_rvas[hook_id] = _hex(
                caller.get("rva"), f"hook {hook_id} caller RVA"
            )
    if not hook_rvas:
        raise ValueError("at least one enabled hook RVA is required")
    return dict(sorted(hook_rvas.items())), dict(sorted(caller_rvas.items()))


def build_runtime_identity_record(
    *,
    record_type: str,
    session_id: str,
    emitted_at: str,
    module_base: str | None,
    game_version: str,
    probe_contract: Mapping[str, Any],
    deployment_binding: Mapping[str, Any],
    snapshot_gate: SnapshotGateDecision | None,
) -> dict[str, Any]:
    """Build an INSTALL_OK or CAPTURE_CLOSE record from probe-emitted inputs."""

    if record_type not in RECORD_TYPES:
        raise ValueError("record_type must be INSTALL_OK or CAPTURE_CLOSE")
    if not isinstance(session_id, str) or SESSION_RE.fullmatch(session_id) is None:
        raise ValueError("session_id is invalid")
    _text(emitted_at, "emitted_at", 64)
    _hex(module_base, "module base", nonzero=True)
    base = module_base
    if probe_contract.get("schema_version") != "kcd2.probe-contract.v2":
        raise ValueError("probe contract must use v2")
    expected = probe_contract.get("expected_module")
    source = probe_contract.get("source_contract")
    event_limits = probe_contract.get("event_limits")
    event_schemas = probe_contract.get("event_schemas")
    identity_matchers = probe_contract.get("identity_matchers")
    if not isinstance(expected, Mapping) or not isinstance(source, Mapping):
        raise ValueError("probe module/source contract identity is incomplete")
    if not isinstance(event_limits, Mapping) or not isinstance(event_schemas, Mapping):
        raise ValueError("probe event schemas and limits are required")
    if set(event_limits) != set(event_schemas) or len(event_limits) > MAX_EVENT_FAMILIES:
        raise ValueError("probe event family limits are inconsistent or unbounded")
    if not isinstance(identity_matchers, list) or len(identity_matchers) > 128:
        raise ValueError("probe identity matchers must be bounded")

    binding_validation = validate_deployment_binding(deployment_binding)
    bound = binding_validation["identity"]
    if (
        snapshot_gate is None
        or not snapshot_gate.authorizes(DeploymentOperation.CANDIDATE_SCOPED_PROBE)
        or snapshot_gate.deployment_id != bound["deployment_id"]
        or snapshot_gate.snapshot_id != bound["active_snapshot_id"]
        or snapshot_gate.snapshot_sha256 != bound["active_snapshot_sha256"]
    ):
        raise ValueError("candidate-scoped probe requires a matching fresh exact snapshot gate")
    probe_id = _text(probe_contract.get("probe_id"), "probe ID", 256)
    revision = _text(probe_contract.get("revision"), "probe revision", 128)
    contract_hash = _digest(
        source.get("compiled_contract_sha256"), "compiled contract SHA-256"
    )
    if bound["probe"]["probe_id"] != probe_id or bound["probe"]["revision"] != revision:
        raise ValueError("deployment binding probe ID/revision differs from the contract")
    if bound["probe"]["contract_sha256"] != contract_hash:
        raise ValueError("deployment binding contract hash differs from the compiled contract")
    module_hash = _digest(expected.get("sha256"), "module SHA-256")
    module_timestamp = _hex(expected.get("timestamp"), "module timestamp")
    module_image_size = _integer(
        expected.get("image_size"), "module image size", minimum=1
    )
    bound_whgame = bound["game"]["whgame"]
    if (
        bound_whgame["sha256"] != module_hash
        or bound_whgame["timestamp"] != module_timestamp
        or bound_whgame["image_size"] != module_image_size
    ):
        raise ValueError("live module metadata differs from the exact deployment binding")
    if bound["game"]["version"] != game_version:
        raise ValueError("game version differs from the exact deployment binding")
    hook_rvas, caller_rvas = _enabled_rvas(probe_contract)
    scope = {
        "hypothesis": _text(probe_contract.get("hypothesis"), "hypothesis", 4000),
        "enabled_hook_ids": list(hook_rvas),
        "identity_matcher_ids": sorted(
            _text(item.get("matcher_id"), "identity matcher ID", 128)
            for item in identity_matchers
            if isinstance(item, Mapping)
        ),
        "event_families": sorted(event_limits),
    }
    return {
        "schema_version": "kcd2.probe-runtime-identity.v1",
        "record_type": record_type,
        "session_id": session_id,
        "emitted_at": emitted_at,
        "module": {
            "name": _text(expected.get("name"), "module name", 260),
            "base": base,
            "sha256": module_hash,
            "timestamp": module_timestamp,
            "image_size": module_image_size,
            "hook_rvas": hook_rvas,
            "caller_rvas": caller_rvas,
        },
        "game_version": game_version,
        "probe": copy.deepcopy(bound["probe"]),
        "scope": scope,
        "event_limits": copy.deepcopy(dict(event_limits)),
        "deployment_binding_sha256": binding_validation["identity_sha256"],
        "deployment_binding": copy.deepcopy(dict(deployment_binding)),
    }


def _runtime_projection(record: Mapping[str, Any]) -> dict[str, Any]:
    required = (
        "module",
        "game_version",
        "probe",
        "scope",
        "event_limits",
        "deployment_binding_sha256",
    )
    return {name: copy.deepcopy(record[name]) for name in required}


def verify_capture_identity(
    install_ok: Mapping[str, Any], capture_close: Mapping[str, Any]
) -> dict[str, Any]:
    """Verify exact start/close identity without filling or reconstructing fields."""

    reasons: set[str] = set()
    if install_ok.get("record_type") != "INSTALL_OK":
        reasons.add("INSTALL_OK_RECORD_MISSING")
    if capture_close.get("record_type") != "CAPTURE_CLOSE":
        reasons.add("CAPTURE_CLOSE_RECORD_MISSING")
    if install_ok.get("session_id") != capture_close.get("session_id"):
        reasons.add("SESSION_ID_CHANGED")
    for prefix, record in (("START", install_ok), ("CLOSE", capture_close)):
        module = record.get("module")
        try:
            if not isinstance(module, Mapping) or "base" not in module:
                raise ValueError("missing")
            _hex(module["base"], "module base", nonzero=True)
        except ValueError:
            reasons.add(f"{prefix}_MODULE_BASE_MISSING")

    deployment_fingerprints: list[str | None] = []
    runtime_fingerprints: list[str | None] = []
    for record in (install_ok, capture_close):
        try:
            validation = validate_deployment_binding(record["deployment_binding"])
            deployment_fingerprints.append(validation["identity_sha256"])
            if record.get("deployment_binding_sha256") != validation["identity_sha256"]:
                reasons.add("DEPLOYMENT_FINGERPRINT_INVALID")
        except (KeyError, TypeError, ValueError):
            deployment_fingerprints.append(None)
            reasons.add("DEPLOYMENT_BINDING_INVALID")
        try:
            runtime_fingerprints.append(_sha256(_runtime_projection(record)))
        except KeyError:
            runtime_fingerprints.append(None)
            reasons.add("RUNTIME_IDENTITY_INCOMPLETE")

    if deployment_fingerprints[0] != deployment_fingerprints[1]:
        reasons.add("DEPLOYMENT_IDENTITY_CHANGED")
    if runtime_fingerprints[0] != runtime_fingerprints[1]:
        reasons.add("RUNTIME_IDENTITY_CHANGED")
    identity_unchanged = (
        deployment_fingerprints[0] is not None
        and deployment_fingerprints[0] == deployment_fingerprints[1]
        and runtime_fingerprints[0] is not None
        and runtime_fingerprints[0] == runtime_fingerprints[1]
    )
    return {
        "schema_version": "kcd2.capture-identity-verification.v1",
        "session_id": install_ok.get("session_id"),
        "start_identity_sha256": runtime_fingerprints[0],
        "close_identity_sha256": runtime_fingerprints[1],
        "start_deployment_sha256": deployment_fingerprints[0],
        "close_deployment_sha256": deployment_fingerprints[1],
        "identity_unchanged": identity_unchanged,
        "candidate_promotion_allowed": identity_unchanged and not reasons,
        "reasons": sorted(reasons),
    }
