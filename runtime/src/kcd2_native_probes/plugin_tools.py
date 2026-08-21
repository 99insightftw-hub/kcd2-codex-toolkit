"""Direct, bounded plugin handlers for supported native-probe analysis."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.capability_preflight import (
    CapabilityPreflightInputs,
    detect_capabilities,
)
from kcd2_toolchain_core.environment_profiles import load_environment_profile
from kcd2_toolchain_core.plugin_surface import PublicTool

from .guarded_kcse import GuardedProjectError, entry_lock_preflight
from .playtest_readiness import probe_playtest_readiness
from .record_layout import record_layout_lint
from .result_validity import validate_probe_result


SURFACE_RELATIVE_PATH = Path("examples/native-probes-plugin-tool-surface.example.json")
MAX_JSON_INPUT_BYTES = 8 * 1024 * 1024
MAX_HEADER_INPUT_BYTES = 8 * 1024 * 1024
MAX_PATH_CHARS = 2048
SUPPORTED_TOOL_NAMES = (
    "native_capability_preflight",
    "entry_lock_preflight",
    "record_layout_lint",
    "probe_playtest_readiness",
    "validate_probe_result",
)
_SOURCE_PATHS = {
    "native_capability_preflight": Path("src/kcd2_toolchain_core/capability_preflight.py"),
    "entry_lock_preflight": Path("src/kcd2_native_probes/guarded_kcse.py"),
    "record_layout_lint": Path("src/kcd2_native_probes/record_layout.py"),
    "probe_playtest_readiness": Path("src/kcd2_native_probes/playtest_readiness.py"),
    "validate_probe_result": Path("src/kcd2_native_probes/result_validity.py"),
}


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _resolve_path(repository_root: Path, value: str) -> Path:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH_CHARS:
        raise ValueError(f"path must contain 1 to {MAX_PATH_CHARS} characters")
    candidate = Path(value)
    return candidate if candidate.is_absolute() else repository_root / candidate


def _read_bounded(path: Path, maximum: int) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError("input artifact is unavailable") from exc
    if size > maximum:
        raise ValueError(f"input artifact exceeds {maximum} bytes")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ValueError("input artifact is unavailable") from exc
    if len(data) != size:
        raise ValueError("input artifact changed while it was read")
    return data


def _read_json_object(repository_root: Path, value: str) -> dict[str, Any]:
    path = _resolve_path(repository_root, value)
    try:
        decoded = json.loads(_read_bounded(path, MAX_JSON_INPUT_BYTES).decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("input artifact is not a valid JSON object") from exc
    if not isinstance(decoded, dict):
        raise ValueError("input artifact root must be an object")
    return decoded


def load_surface_manifest(repository_root: Path | str) -> dict[str, Any]:
    """Load the source-controlled direct-tool inventory with a hard byte bound."""
    root = Path(repository_root).resolve()
    return _read_json_object(root, str(SURFACE_RELATIVE_PATH))


def _resolve_optional_path(repository_root: Path, value: str | None) -> str | None:
    if value is None:
        return None
    return str(_resolve_path(repository_root, value))


def _resolve_path_list(repository_root: Path, values: list[str]) -> tuple[str, ...]:
    return tuple(str(_resolve_path(repository_root, value)) for value in values)


def _capability_handler(repository_root: Path, **arguments: Any) -> dict[str, Any]:
    current_interpreter = arguments.get("current_interpreter")
    if current_interpreter == "CURRENT_PLUGIN_INTERPRETER":
        current_interpreter = sys.executable
    elif isinstance(current_interpreter, str):
        current_interpreter = str(_resolve_path(repository_root, current_interpreter))
    else:
        raise ValueError("current_interpreter must be a path or CURRENT_PLUGIN_INTERPRETER")
    profile_path = arguments.get("environment_profile_path")
    environment_profile = (
        load_environment_profile(_resolve_path(repository_root, profile_path))
        if isinstance(profile_path, str)
        else None
    )
    inputs = CapabilityPreflightInputs(
        capability_id=arguments["capability_id"],
        regular_ghidra_gui=_resolve_optional_path(
            repository_root, arguments.get("regular_ghidra_gui")
        ),
        regular_ghidra_headless=_resolve_optional_path(
            repository_root, arguments.get("regular_ghidra_headless")
        ),
        current_interpreter=current_interpreter,
        isolated_pyghidra_interpreters=_resolve_path_list(
            repository_root, arguments.get("isolated_pyghidra_interpreters", [])
        ),
        plugin_interpreter=_resolve_optional_path(
            repository_root, arguments.get("plugin_interpreter")
        ),
        pyghidra_required=arguments.get("pyghidra_required", False),
        x64dbg_path=_resolve_optional_path(repository_root, arguments.get("x64dbg_path")),
        kcse_path=_resolve_optional_path(repository_root, arguments.get("kcse_path")),
        compiler_paths=_resolve_path_list(
            repository_root, arguments.get("compiler_paths", [])
        ),
        index_mcp_tools=tuple(arguments.get("index_mcp_tools", [])),
        game_binary_paths=_resolve_path_list(
            repository_root, arguments.get("game_binary_paths", [])
        ),
        reviewed_static_evidence=tuple(arguments.get("reviewed_static_evidence", [])),
        environment_profile=environment_profile,
    )
    report = detect_capabilities(inputs)
    workflows = report["workflow_matrix"]
    profile_receipt = report["environment_profile"]
    component_proofs = None
    if profile_receipt is not None:
        component_proofs = [
            {"component_id": component_id, **receipt}
            for component_id, receipt in profile_receipt["components"].items()
        ]
    return {
        "schema_version": "kcd2.native-capability-preflight-tool.v1",
        "status": "PASS",
        "capability_id": report["capability_id"],
        "regular_ghidra_available": report["regular_ghidra"]["available"],
        "pyghidra_effective_status": report["pyghidra"]["effective_status"],
        "x64dbg_available": report["x64dbg"]["available"],
        "kcse_available": report["kcse"]["available"],
        "raw_pe_available": report["raw_pe_access"]["available"],
        "native_workflow_blocked": report["native_workflow_blocked"],
        "workflow_eligibility": {
            name: workflows[name]["eligible"]
            for name in (
                "ghidra_first",
                "regular_ghidra",
                "pyghidra",
                "x64dbg",
                "kcse",
                "raw_pe_preflight",
            )
        },
        "workflow_blockers": {
            name: workflows[name]["blockers"]
            for name in (
                "ghidra_first",
                "regular_ghidra",
                "pyghidra",
                "x64dbg",
                "kcse",
                "raw_pe_preflight",
            )
        },
        "environment_profile_id": (
            profile_receipt["profile_id"] if profile_receipt is not None else None
        ),
        "compatibility_profile_id": (
            profile_receipt["compatibility_profile_id"]
            if profile_receipt is not None
            else None
        ),
        "component_proofs": component_proofs,
        "reason_codes": report["reason_codes"],
    }


def _entry_lock_handler(repository_root: Path, **arguments: Any) -> dict[str, Any]:
    try:
        manifest = _read_json_object(repository_root, arguments["manifest_path"])
        module_path = _resolve_path(repository_root, arguments["module_path"])
        header_path = _resolve_path(repository_root, arguments["generated_header_path"])
        header = _read_bounded(header_path, MAX_HEADER_INPUT_BYTES)
        raw_report = entry_lock_preflight(
            manifest,
            module_path,
            generated_header=header,
        )
    except (GuardedProjectError, OSError, TypeError, ValueError):
        return {
            "schema_version": "kcd2.entry-lock-preflight-tool.v1",
            "status": "FAIL",
            "valid": False,
            "lock_source": "raw_pe_rva_mapping",
            "module_name": None,
            "module_sha256": None,
            "generated_header_sha256": None,
            "generated_header_matches_manifest": False,
            "hooks": [],
            "diagnostics": [
                {
                    "code": "ENTRY_LOCK_PREFLIGHT_REFUSED",
                    "message": (
                        "Input unavailable, unbounded, or inconsistent with the raw-PE lock."
                    ),
                }
            ],
        }
    hooks = [
        {
            "hook_id": item["hook_id"],
            "rva": item["rva"],
            "file_offset": item["file_offset"],
            "raw_bytes_hex": item["raw_bytes_hex"],
            "matches": item["matches"],
            "hidden_prefix_hex": item["hidden_prefix_hex"],
            "redundant_prefix_hex": item["redundant_prefix_hex"],
        }
        for item in raw_report["hooks"]
    ]
    return {
        "schema_version": "kcd2.entry-lock-preflight-tool.v1",
        "status": "PASS",
        "valid": True,
        "lock_source": raw_report["lock_source"],
        "module_name": raw_report["module_name"],
        "module_sha256": raw_report["module_sha256"],
        "generated_header_sha256": raw_report["generated_header_sha256"],
        "generated_header_matches_manifest": raw_report[
            "generated_header_matches_manifest"
        ],
        "hooks": hooks,
        "diagnostics": [],
    }


def _layout_handler(repository_root: Path, **arguments: Any) -> dict[str, Any]:
    try:
        document = _read_json_object(repository_root, arguments["input_path"])
        return record_layout_lint(
            document,
            max_diagnostics=arguments.get("max_diagnostics", 256),
        ).to_dict()
    except (TypeError, ValueError):
        return {
            "schema_version": "kcd2.record-layout-lint.v1",
            "status": "FAIL",
            "diagnostics": [
                {
                    "code": "INPUT_INVALID",
                    "path": "$",
                    "message": "Input is unavailable, unbounded, or not a JSON object.",
                }
            ],
            "diagnostics_truncated": False,
        }


def _readiness_handler(repository_root: Path, **arguments: Any) -> dict[str, Any]:
    request = _read_json_object(repository_root, arguments["input_path"])
    report = probe_playtest_readiness(request)
    return {
        "schema_version": "kcd2.probe-playtest-readiness-tool.v1",
        "request_id": report["request_id"],
        "input_sha256": report["input_sha256"],
        "receipt_id": report["receipt_id"],
        "probe_id": report["probe_id"],
        "session_id": report["session_id"],
        "module_sha256": report["module_sha256"],
        "status": report["status"],
        "gameplay_handoff_allowed": report["gameplay_handoff_allowed"],
        "checks": report["checks"],
        "failure_reasons": report["failure_reasons"],
        "next_action": report["next_action"],
        "bounded_x64dbg_proof_required": report["x64dbg_proof_request"] is not None,
    }


def _result_handler(repository_root: Path, **arguments: Any) -> dict[str, Any]:
    result_input = _read_json_object(repository_root, arguments["input_path"])
    return validate_probe_result(result_input)


_HANDLERS: dict[str, Callable[..., dict[str, Any]]] = {
    "native_capability_preflight": _capability_handler,
    "entry_lock_preflight": _entry_lock_handler,
    "record_layout_lint": _layout_handler,
    "probe_playtest_readiness": _readiness_handler,
    "validate_probe_result": _result_handler,
}


def _source_sha256(repository_root: Path, tool_name: str) -> str:
    return hashlib.sha256((repository_root / _SOURCE_PATHS[tool_name]).read_bytes()).hexdigest()


def create_public_registry(
    repository_root: Path | str,
    manifest: Mapping[str, Any] | None = None,
) -> dict[str, PublicTool]:
    """Create the exact read-only registry used by MCP discovery and smoke tests."""
    root = Path(repository_root).resolve()
    loaded = load_surface_manifest(root) if manifest is None else manifest
    records = {record["tool_name"]: record for record in loaded["tools"]}
    if set(records) != set(SUPPORTED_TOOL_NAMES):
        raise ValueError("native-probes surface does not match the supported tool inventory")
    registry: dict[str, PublicTool] = {}
    for name in SUPPORTED_TOOL_NAMES:
        record = records[name]

        def handler(_name: str = name, **arguments: Any) -> dict[str, Any]:
            return _HANDLERS[_name](root, **arguments)

        registry[name] = PublicTool(
            handler=handler,
            input_schema=copy.deepcopy(record["input_schema"]),
            output_schema=copy.deepcopy(record["output_schema"]),
            approval_class="none",
            module_or_symbol=record["library_binding"]["module_or_symbol"],
            source_sha256=_source_sha256(root, name),
        )
    return registry


def library_source_binding_report(
    repository_root: Path | str,
    manifest: Mapping[str, Any],
    registry: Mapping[str, PublicTool] | None = None,
) -> dict[str, Any]:
    """Report static source binding only; make no runtime or causal claim."""
    root = Path(repository_root).resolve()
    public = create_public_registry(root, manifest) if registry is None else registry
    records = {record["tool_name"]: record for record in manifest["tools"]}
    bindings = []
    for name in sorted(SUPPORTED_TOOL_NAMES):
        record = records[name]
        source_path = _SOURCE_PATHS[name]
        actual = _source_sha256(root, name)
        expected = record["library_binding"]["source_sha256"].lower()
        registered = public.get(name)
        bindings.append(
            {
                "tool_name": name,
                "module_or_symbol": record["library_binding"]["module_or_symbol"],
                "source_path": source_path.as_posix(),
                "source_sha256": actual,
                "source_sha256_matches": actual == expected,
                "registry_binding_matches": bool(
                    registered
                    and registered.module_or_symbol
                    == record["library_binding"]["module_or_symbol"]
                    and registered.source_sha256.lower() == actual
                ),
                "evidence_layer": "static_source_binding",
            }
        )
    body = {
        "schema_version": "kcd2.native-probes-library-binding-report.v1",
        "plugin": dict(manifest["plugin"]),
        "source_revision": manifest["source_revision"],
        "status": (
            "PASS"
            if all(
                item["source_sha256_matches"] and item["registry_binding_matches"]
                for item in bindings
            )
            else "FAIL"
        ),
        "bindings": bindings,
    }
    return {
        **body,
        "report_sha256": hashlib.sha256(_canonical_bytes(body)).hexdigest(),
    }


__all__ = [
    "SUPPORTED_TOOL_NAMES",
    "create_public_registry",
    "library_source_binding_report",
    "load_surface_manifest",
]
