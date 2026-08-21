"""Direct bounded read-only handlers for mod package and provider analysis."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.plugin_surface import PublicTool
from kcd2_toolchain_core.variant_comparison import compare_variants

from .candidate_parent_diff import CandidateParentDiffError, candidate_parent_diff
from .deployment_registry import DeploymentOperation, SnapshotGateDecision
from .effective_path_resolution import ActiveLoadOrder, resolve_effective_internal_path
from .general_candidate_plan import plan_candidate_audit
from .package_validation import validate_candidate_package
from .provider_inventory import ProviderInventory


SURFACE_PATH = Path("examples/mod-build-deploy-plugin-tool-surface.example.json")
SUPPORTED_TOOL_NAMES = (
    "candidate_parent_diff",
    "candidate_package_inspect",
    "provider_inventory_inspect",
    "effective_path_resolve",
    "plan_candidate_audit",
    "compare_variants",
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_PATH_CHARS = 2048
MAX_PROVIDERS = 4096
_SOURCE_PATHS = {
    "candidate_parent_diff": Path("src/kcd2_mod_build_deploy/candidate_parent_diff.py"),
    "candidate_package_inspect": Path("src/kcd2_mod_build_deploy/package_validation.py"),
    "provider_inventory_inspect": Path("src/kcd2_mod_build_deploy/provider_inventory.py"),
    "effective_path_resolve": Path("src/kcd2_mod_build_deploy/effective_path_resolution.py"),
    "plan_candidate_audit": Path("src/kcd2_mod_build_deploy/general_candidate_plan.py"),
    "compare_variants": Path("src/kcd2_toolchain_core/variant_comparison.py"),
}


def _resolve(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH_CHARS:
        raise ValueError(f"path must contain 1 to {MAX_PATH_CHARS} characters")
    path = Path(value)
    return path if path.is_absolute() else root / path


def _read_json(root: Path, value: object) -> dict[str, Any]:
    path = _resolve(root, value)
    try:
        size = path.stat().st_size
        if size > MAX_JSON_BYTES:
            raise ValueError(f"JSON artifact exceeds {MAX_JSON_BYTES} bytes")
        data = path.read_bytes()
        if len(data) != size:
            raise ValueError("JSON artifact changed while it was read")
        decoded = json.loads(data.decode("utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("JSON artifact is unavailable or invalid") from exc
    if not isinstance(decoded, dict):
        raise ValueError("JSON artifact root must be an object")
    return decoded


def load_surface_manifest(repository_root: Path | str) -> dict[str, Any]:
    return _read_json(Path(repository_root).resolve(), str(SURFACE_PATH))


def _parent_diff(root: Path, **arguments: Any) -> dict[str, Any]:
    maximum = arguments.get("max_entries", 128)
    try:
        report = candidate_parent_diff(
            _read_json(root, arguments["build_spec_path"]),
            _resolve(root, arguments["parent_pak_path"]),
            _resolve(root, arguments["candidate_pak_path"]),
            clean_parent_pak=(
                _resolve(root, arguments["clean_parent_pak_path"])
                if arguments.get("clean_parent_pak_path") is not None
                else None
            ),
            expected_clean_parent_sha256=arguments.get("expected_clean_parent_sha256"),
        )
    except (CandidateParentDiffError, KeyError, TypeError, ValueError) as exc:
        return {
            "schema_version": "kcd2.candidate-parent-diff-tool.v1",
            "status": "ERROR",
            "spec_id": None,
            "parent_sha256": None,
            "candidate_sha256": None,
            "parent_contamination_detected": False,
            "entry_count": 0,
            "undeclared_change_count": 0,
            "changed_paths": [],
            "paths_truncated": False,
            "diagnostic": "PARENT_DIFF_INPUT_INVALID",
        }
    payload = report.to_dict()
    changed_paths = sorted(
        {
            item["member_path"]
            for item in payload["entries"]
            if item["kind"] != "byte_identical"
        }
    )
    visible_paths = changed_paths[:maximum]
    return {
        "schema_version": "kcd2.candidate-parent-diff-tool.v1",
        "status": report.status,
        "spec_id": report.spec_id,
        "parent_sha256": report.parent_sha256,
        "candidate_sha256": report.candidate_sha256,
        "parent_contamination_detected": report.parent_contamination_detected,
        "entry_count": payload["summary"]["entry_count"],
        "undeclared_change_count": payload["summary"]["undeclared_change_count"],
        "changed_paths": visible_paths,
        "paths_truncated": len(visible_paths) < len(changed_paths),
        "diagnostic": None,
    }


def _package(root: Path, **arguments: Any) -> dict[str, Any]:
    report = validate_candidate_package(
        _read_json(root, arguments["build_spec_path"]),
        _resolve(root, arguments["package_path"]),
        game_build=arguments["game_build"],
        whgame_sha256=arguments.get("whgame_sha256"),
    )
    payload = report.to_dict()
    return {
        "schema_version": "kcd2.candidate-package-inspection-tool.v1",
        "artifact_sha256": payload["artifact_sha256"],
        "structural_integrity": payload["structural_integrity"],
        "validation_mode": payload["validation_mode"],
        "package_promotion": payload["package_promotion"],
        "xml_tbl_gate": payload["xml_tbl_gate"],
        "overall_static_readiness": payload["overall_static_readiness"],
        "diagnostic_codes": [item["code"] for item in payload["diagnostics"]],
    }


def _inventory(root: Path, **arguments: Any) -> dict[str, Any]:
    payload = _read_json(root, arguments["inventory_path"])
    providers = payload.get("providers")
    coverage = payload.get("coverage_envelope")
    if (
        payload.get("schema_version") != "kcd2.provider-inventory.v1"
        or not isinstance(providers, list)
        or len(providers) > MAX_PROVIDERS
        or not isinstance(coverage, Mapping)
    ):
        raise ValueError("provider inventory is malformed or exceeds its hard bound")
    identifiers = []
    kinds = []
    for provider in providers:
        if not isinstance(provider, Mapping) or not isinstance(provider.get("provider_id"), str):
            raise ValueError("provider inventory contains malformed provider metadata")
        identifiers.append(provider["provider_id"])
        if isinstance(provider.get("provider_kind"), str):
            kinds.append(provider["provider_kind"])
    if len({item.casefold() for item in identifiers}) != len(identifiers):
        raise ValueError("provider inventory contains duplicate provider IDs")
    return {
        "schema_version": "kcd2.provider-inventory-inspection-tool.v1",
        "inventory_id": payload.get("inventory_id"),
        "status": payload.get("status"),
        "provider_count": len(providers),
        "provider_kinds": sorted(set(kinds)),
        "winner_claim_allowed": coverage.get("winner_claim_allowed") is True,
        "absence_claim_allowed": coverage.get("absence_claim_allowed") is True,
        "reason_codes": sorted(set(coverage.get("reason_codes", []))),
    }


def _effective(root: Path, **arguments: Any) -> dict[str, Any]:
    request = _read_json(root, arguments["request_path"])
    order = request["load_order"]
    gate_payload = request.get("snapshot_gate")
    gate = None
    if gate_payload is not None:
        gate = SnapshotGateDecision(
            operation=DeploymentOperation.WINNER_CLAIM,
            deployment_id=gate_payload["deployment_id"],
            snapshot_id=gate_payload["snapshot_id"],
            snapshot_sha256=gate_payload["snapshot_sha256"],
            allowed=gate_payload["allowed"],
            status=gate_payload["status"],
            reason_codes=tuple(gate_payload.get("reason_codes", [])),
        )
    report = resolve_effective_internal_path(
        query_id=request["query_id"],
        canonical_path=request["canonical_path"],
        inventory=ProviderInventory(request["inventory"]),
        load_order=ActiveLoadOrder(
            provider_ids=tuple(order["provider_ids"]),
            complete=order["complete"],
            source=order["source"],
            sha256=order["sha256"],
        ),
        snapshot_gate=gate,
    ).to_dict()
    result = report["canonical_path_resolution"]
    resolution = result["resolution"]
    return {
        "schema_version": "kcd2.effective-path-resolution-tool.v1",
        "inventory_id": report["inventory_id"],
        "canonical_path": result["canonical_path"],
        "discovery_mode": result["discovery_mode"],
        "resolution_semantics": sorted(
            {item["resolution_semantics"] for item in result["contributions"]}
        ),
        "conclusion": resolution["conclusion"],
        "winner_provider_id": resolution["winner_provider_id"],
        "contribution_count": len(result["contributions"]),
        "contributors": [item["provider_id"] for item in result["contributions"]],
        "reason_codes": resolution["reason_codes"],
        "order_complete": report["load_order_provenance"]["effective_complete"],
    }


def _plan(root: Path, **arguments: Any) -> dict[str, Any]:
    try:
        report = plan_candidate_audit(_read_json(root, arguments["request_path"]))
    except (OSError, TypeError, ValueError):
        return {
            "schema_version": "kcd2.candidate-plan-tool.v1",
            "plan_id": "plan:example",
            "status": "BLOCKED",
            "evidence_layer": "static",
            "identity_id": "identity:sha256:" + "0" * 64,
            "parent_id": None,
            "parent_artifact_sha256": "0" * 64,
            "gates": [
                {
                    "gate": "parent",
                    "status": "FAIL",
                    "reason_codes": ["PARENT_IDENTITY_UNRESOLVED"],
                }
            ],
            "unresolved_gates": ["parent"],
            "unresolved_gate_artifact_sha256": "0" * 64,
            "next_build_requirements": ["BUILD_MUTATION_APPROVAL_REQUIRED"],
            "candidate_created": False,
            "mutation_approval_requested": False,
        }
    return {
        "schema_version": "kcd2.candidate-plan-tool.v1",
        "plan_id": report["plan_id"],
        "status": report["status"],
        "evidence_layer": report["evidence_layer"],
        "identity_id": report["identity_id"],
        "parent_id": report["parent"]["parent_id"],
        "parent_artifact_sha256": report["parent"]["artifact_sha256"],
        "gates": report["gates"],
        "unresolved_gates": report["unresolved_gate_artifact"]["gates"],
        "unresolved_gate_artifact_sha256": report["unresolved_gate_artifact"]["sha256"],
        "next_build_requirements": report["next_build_requirements"],
        "candidate_created": report["candidate_created"],
        "mutation_approval_requested": report["mutation_approval_requested"],
    }


def _compare_variants(root: Path, **arguments: Any) -> dict[str, Any]:
    request = _read_json(root, arguments["request_path"])
    required = {
        "before_selection",
        "after_selection",
        "before_providers",
        "after_providers",
        "runtime_comparison",
    }
    if not required <= set(request):
        raise ValueError("variant comparison request is missing required evidence")
    report = compare_variants(
        request["before_selection"],
        request["after_selection"],
        before_providers=request["before_providers"],
        after_providers=request["after_providers"],
        runtime_comparison=request["runtime_comparison"],
        max_differences=arguments.get("max_differences", 128),
    ).to_dict()
    differences = []
    for item in report["differences"]:
        values = {}
        for side in ("before", "after"):
            encoded = json.dumps(
                item[side], ensure_ascii=False, separators=(",", ":"), sort_keys=True
            )
            if len(encoded.encode("utf-8")) > 8192:
                encoded_bytes = encoded.encode("utf-8")
                encoded = json.dumps(
                    {
                        "bytes": len(encoded_bytes),
                        "details_truncated": True,
                        "sha256": hashlib.sha256(encoded_bytes).hexdigest(),
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                )
            values[f"{side}_json"] = encoded
        differences.append(
            {
                "layer": item["layer"],
                "key": item["key"],
                **values,
            }
        )
    report["differences"] = differences
    return report


_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "candidate_parent_diff": _parent_diff,
    "candidate_package_inspect": _package,
    "provider_inventory_inspect": _inventory,
    "effective_path_resolve": _effective,
    "plan_candidate_audit": _plan,
    "compare_variants": _compare_variants,
}


def create_public_registry(
    repository_root: Path | str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, PublicTool]:
    root = Path(repository_root).resolve()
    loaded = load_surface_manifest(root) if manifest is None else manifest
    records = {item["tool_name"]: item for item in loaded["tools"]}
    if set(records) != set(SUPPORTED_TOOL_NAMES):
        raise ValueError("mod-build-deploy surface differs from the supported inventory")
    registry = {}
    for name in SUPPORTED_TOOL_NAMES:
        record = records[name]

        def handler(_name: str = name, **arguments: Any) -> dict[str, Any]:
            return _HANDLERS[_name](root, **arguments)

        source = root / _SOURCE_PATHS[name]
        registry[name] = PublicTool(
            handler=handler,
            input_schema=copy.deepcopy(record["input_schema"]),
            output_schema=copy.deepcopy(record["output_schema"]),
            approval_class="none",
            module_or_symbol=record["library_binding"]["module_or_symbol"],
            source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )
    return registry


__all__ = ["SUPPORTED_TOOL_NAMES", "create_public_registry", "load_surface_manifest"]
