"""Bounded read-only source audit and pre-build candidate planning."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from kcd2_index_adapter.exact_inspection import ExactModInspectionRequest, inspect_mod_exact
from kcd2_index_adapter.scope_guard import ScopeLimits
from kcd2_toolchain_core.cross_tool_identity import bind_cross_tool_identity
from kcd2_toolchain_core.hashing import sha256_json
from kcd2_toolchain_core.plugin_surface import _instance_errors

from .build_spec import parse_build_spec_file
from .native_deployment_descriptor import validate_native_deployment_descriptor
from .packaging_profiles import detect_packaging_profile


MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_PATH_CHARS = 2048
MAX_GATES = 16
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ROOT = Path(__file__).resolve().parents[2]
_CONFLICT_SCHEMA = _ROOT / "schemas" / "conflict-classification-v1.schema.json"
_REQUEST_FIELDS = {
    "schema_version",
    "plan_id",
    "target_mod_id",
    "source",
    "build_spec_path",
    "parent_pak_path",
    "provider_inventory_path",
    "conflict_report_path",
    "native_descriptor_path",
    "game",
    "limits",
}


def _text(value: object, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty bounded string")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value.lower()


def _path(value: object, name: str) -> Path:
    text = _text(value, name, MAX_PATH_CHARS)
    return Path(text).resolve(strict=True)


def _read_json(path: Path, name: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if not path.is_file() or size > MAX_JSON_BYTES:
            raise ValueError(f"{name} exceeds its bounded JSON size")
        raw = path.read_bytes()
        if len(raw) != size:
            raise ValueError(f"{name} changed while it was read")
        value = json.loads(raw.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{name} is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{name} root must be an object")
    return value


def _gate(name: str, status: str, reasons: Sequence[str] = ()) -> dict[str, Any]:
    if status not in {"PASS", "FAIL", "CAPTURE_INCONCLUSIVE"}:
        raise ValueError("unsupported planning gate status")
    return {"gate": name, "status": status, "reason_codes": sorted(set(reasons))}


def _inventory_gate(document: Mapping[str, Any], target_mod_id: str) -> dict[str, Any]:
    providers = document.get("providers")
    coverage = document.get("coverage_envelope")
    if (
        document.get("schema_version") != "kcd2.provider-inventory.v1"
        or not isinstance(providers, list)
        or len(providers) > 4096
        or not isinstance(coverage, Mapping)
    ):
        return _gate("providers", "FAIL", ("PROVIDER_INVENTORY_INVALID",))
    matching = [
        item
        for item in providers
        if isinstance(item, Mapping) and item.get("mod_id") == target_mod_id
    ]
    complete = (
        document.get("status") == "complete"
        and coverage.get("overall_status") == "COMPLETE"
        and coverage.get("winner_claim_allowed") is True
        and coverage.get("conflict_absence_claim_allowed") is True
    )
    if not matching:
        return _gate("providers", "FAIL", ("SOURCE_PROVIDER_NOT_IN_INVENTORY",))
    if not complete:
        reasons = coverage.get("reason_codes", ())
        bounded = (
            tuple(str(item)[:128] for item in reasons[:64])
            if isinstance(reasons, list)
            else ()
        )
        return _gate(
            "providers",
            "CAPTURE_INCONCLUSIVE",
            ("PROVIDER_COVERAGE_INCOMPLETE", *bounded),
        )
    return _gate("providers", "PASS")


def _conflict_gate(document: Mapping[str, Any]) -> dict[str, Any]:
    schema = json.loads(_CONFLICT_SCHEMA.read_text(encoding="utf-8"))
    errors = _instance_errors(document, schema)
    if errors:
        return _gate("conflicts", "FAIL", ("CONFLICT_REPORT_INVALID",))
    conclusion = document["conclusion"]
    if conclusion == "CONFIRMED_NONE" and document["absence_claim_valid"] is True:
        return _gate("conflicts", "PASS")
    if conclusion in {
        "ZERO_OBSERVED_PARTIAL_COVERAGE",
        "ZERO_OBSERVED_STALE_COVERAGE",
        "INCONCLUSIVE",
        "NOT_EVALUATED",
    }:
        reasons = tuple(str(item)[:128] for item in document["reason_codes"][:64])
        return _gate("conflicts", "CAPTURE_INCONCLUSIVE", reasons or (conclusion,))
    return _gate("conflicts", "FAIL", ("CONFLICTS_OBSERVED",))


def _limits(value: object) -> ScopeLimits:
    if not isinstance(value, Mapping) or set(value) != {
        "max_files",
        "max_archive_entries",
        "max_physical_bytes",
        "max_response_bytes",
    }:
        raise ValueError("limits must declare exactly the bounded exact-inspection limits")
    return ScopeLimits(**{key: value[key] for key in value})


def plan_candidate_audit(request: Mapping[str, Any]) -> dict[str, Any]:
    """Audit one exact source and return pre-build gates without creating a candidate."""
    if not isinstance(request, Mapping) or set(request) != _REQUEST_FIELDS:
        raise ValueError("candidate plan request fields do not match v1")
    if request["schema_version"] != "kcd2.candidate-plan-request.v1":
        raise ValueError("unsupported candidate plan request schema_version")
    plan_id = _text(request["plan_id"], "plan_id")
    mod_id = _text(request["target_mod_id"], "target_mod_id")
    source = request["source"]
    game = request["game"]
    if not isinstance(source, Mapping) or set(source) != {"provider_kind", "mod_path", "commit"}:
        raise ValueError("source fields do not match the planning contract")
    if not isinstance(game, Mapping) or set(game) != {
        "version",
        "executable_sha256",
        "whgame_sha256",
    }:
        raise ValueError("game fields do not match the planning contract")
    version = _text(game["version"], "game.version", 128)
    executable_sha256 = _digest(game["executable_sha256"], "game.executable_sha256")
    whgame_sha256 = _digest(game["whgame_sha256"], "game.whgame_sha256")
    provider_kind = _text(source["provider_kind"], "source.provider_kind", 32)
    if provider_kind not in {"local", "workshop", "explicit_path"}:
        raise ValueError("source.provider_kind is unsupported")
    source_path = _path(source["mod_path"], "source.mod_path")
    build_spec_path = _path(request["build_spec_path"], "build_spec_path")
    parent_path = _path(request["parent_pak_path"], "parent_pak_path")
    inventory_path = _path(request["provider_inventory_path"], "provider_inventory_path")
    conflict_path = _path(request["conflict_report_path"], "conflict_report_path")
    descriptor_path = _path(request["native_descriptor_path"], "native_descriptor_path")

    scope_receipt_id = f"scope:{plan_id}:source-audit"
    inspection_result = inspect_mod_exact(
        ExactModInspectionRequest(
            target_mod_id=mod_id,
            provider_kind=provider_kind,  # type: ignore[arg-type]
            provider_root=source_path,
            receipt_id=scope_receipt_id,
            limits=_limits(request["limits"]),
        )
    )
    inspection = inspection_result.to_dict()
    scope_status = inspection["scope_receipt"]["status"]
    source_gate = _gate(
        "source",
        "PASS" if scope_status == "TARGET_SCOPE_OK" else "CAPTURE_INCONCLUSIVE",
        () if scope_status == "TARGET_SCOPE_OK" else (scope_status,),
    )
    topology_pass = (
        inspection["selected_mod_count"] == 1
        and inspection["manifest"] is not None
        and inspection["manifest"].get("mod_id_matches_request") is True
        and inspection["pak_count"] > 0
        and all(item.get("structure_valid") for item in inspection["paks"])
        and not inspection["pak_records_truncated"]
        and not inspection["native_component_records_truncated"]
    )
    topology_gate = _gate(
        "topology", "PASS" if topology_pass else "FAIL",
        () if topology_pass else ("SOURCE_TOPOLOGY_INVALID_OR_INCOMPLETE",),
    )

    spec_document = _read_json(build_spec_path, "build spec")
    spec_report = parse_build_spec_file(build_spec_path)
    spec = spec_report.spec
    build_spec_pass = spec_report.valid and spec is not None and spec.mod_id == mod_id
    build_spec_gate = _gate(
        "build_spec", "PASS" if build_spec_pass else "FAIL",
        () if build_spec_pass else ("BUILD_SPEC_INVALID_OR_WRONG_MOD",),
    )

    parent_hash = hashlib.sha256(parent_path.read_bytes()).hexdigest()
    parent = spec_document.get("parent")
    parent_id = parent.get("candidate_id") if isinstance(parent, Mapping) else None
    parent_pass = (
        isinstance(parent, Mapping)
        and parent.get("mode") == "derived_candidate"
        and isinstance(parent_id, str)
        and parent.get("artifact_sha256", "").lower() == parent_hash
        and bool(parent.get("evidence_refs"))
    )
    parent_gate = _gate(
        "parent", "PASS" if parent_pass else "FAIL",
        () if parent_pass else ("PARENT_IDENTITY_UNRESOLVED",),
    )
    profile = detect_packaging_profile(parent_pak=parent_path).to_dict()
    packaging = spec_document.get("packaging")
    profile_pass = (
        profile["status"] == "PASS"
        and isinstance(packaging, Mapping)
        and packaging.get("profile_id") == profile["profile_id"]
        and packaging.get("profile_source") == "parent_inherited"
    )
    profile_gate = _gate(
        "profile", "PASS" if profile_pass else "FAIL",
        () if profile_pass else ("PACKAGING_PROFILE_UNRESOLVED_OR_MISMATCHED",),
    )

    inventory = _read_json(inventory_path, "provider inventory")
    providers_gate = _inventory_gate(inventory, mod_id)
    conflicts = _read_json(conflict_path, "conflict report")
    conflicts_gate = _conflict_gate(conflicts)
    descriptor = _read_json(descriptor_path, "native descriptor")
    expected_components = spec_document.get("external_components", [])
    component_report = validate_native_deployment_descriptor(
        descriptor,
        expected_mod_id=mod_id,
        expected_external_components=expected_components,
    ).to_dict()
    declared_game = descriptor.get("game_profile")
    game_matches = (
        isinstance(declared_game, Mapping)
        and declared_game.get("game_version") == version
        and str(declared_game.get("game_executable_sha256", "")).lower() == executable_sha256
        and str(declared_game.get("whgame_sha256", "")).lower() == whgame_sha256
    )
    components_pass = component_report["status"] == "PASS" and game_matches
    components_gate = _gate(
        "components", "PASS" if components_pass else "FAIL",
        () if components_pass else ("COMPONENT_DESCRIPTOR_INVALID_OR_OBSOLETE",),
    )

    receipt_ids = [scope_receipt_id, f"{plan_id}:readiness"]
    identity = bind_cross_tool_identity(
        {
            "schema_version": "kcd2.cross-tool-identity.v1",
            "candidate_id": None,
            "parent_id": parent_id if isinstance(parent_id, str) else None,
            "source": {
                "commit": _text(source["commit"], "source.commit", 128),
                "tree_sha256": inspection["inventory"]["sha256"],
            },
            "build_spec_sha256": hashlib.sha256(build_spec_path.read_bytes()).hexdigest(),
            "artifacts": [
                {"path": "planning/parent.pak", "sha256": parent_hash},
                {
                    "path": "planning/native-deployment-descriptor.json",
                    "sha256": hashlib.sha256(descriptor_path.read_bytes()).hexdigest(),
                },
                *[
                    {"path": item["path"], "sha256": item["sha256"]}
                    for item in inspection["package_facts"]["paks"]
                ],
            ],
            "manifest_sha256": inspection["package_facts"]["manifest_sha256"],
            "native_components": [
                {"component_id": item["component_id"], "sha256": item["sha256"]}
                for item in descriptor.get("components", [])
            ],
            "mod_order_sha256": None,
            "active_snapshot_id": inventory.get("inventory_id"),
            "game": {
                "version": version,
                "executable_sha256": executable_sha256,
                "whgame_sha256": whgame_sha256,
            },
            "receipt_ids": receipt_ids,
        }
    )
    gates = [
        source_gate,
        parent_gate,
        topology_gate,
        profile_gate,
        providers_gate,
        conflicts_gate,
        components_gate,
        build_spec_gate,
    ]
    if len(gates) > MAX_GATES:
        raise RuntimeError("planning gate count exceeds its hard bound")
    unresolved = [item["gate"] for item in gates if item["status"] != "PASS"]
    unresolved_body = {
        "schema_version": "kcd2.candidate-plan-unresolved-gates.v1",
        "identity_id": identity.identity_id,
        "gates": unresolved,
    }
    unresolved_artifact = {
        **unresolved_body,
        "sha256": sha256_json(unresolved_body),
    }
    return {
        "schema_version": "kcd2.candidate-plan-readiness.v1",
        "plan_id": plan_id,
        "status": "READY_TO_BUILD" if not unresolved else "BLOCKED",
        "evidence_layer": "static",
        "identity_id": identity.identity_id,
        "cross_tool_identity": identity.to_dict(),
        "parent": {"parent_id": parent_id, "artifact_sha256": parent_hash},
        "gates": gates,
        "unresolved_gate_artifact": unresolved_artifact,
        "next_build_requirements": [
            "BUILD_MUTATION_APPROVAL_REQUIRED",
            "CLEAN_STAGING_REQUIRED",
            "DETERMINISTIC_REBUILD_REQUIRED",
            "PARENT_DIFF_REQUIRED",
            "PACKAGE_VALIDATION_REQUIRED",
        ],
        "candidate_created": False,
        "mutation_approval_requested": False,
    }


__all__ = ["plan_candidate_audit"]
