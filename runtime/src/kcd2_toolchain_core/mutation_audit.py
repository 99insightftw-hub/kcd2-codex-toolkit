"""Machine-readable inventory of public mutation and read-only boundaries."""

from __future__ import annotations

import importlib
import inspect
from typing import Any


MUTATING_ENTRY_POINTS = (
    ("kcd2_native_probes.x64dbg_session:prepare_gameplay_handoff", "debugger_mutation"),
    ("kcd2_native_probes.x64dbg_session:capture_checkpoint", "debugger_mutation"),
    ("kcd2_native_probes.x64dbg_session:close_debug_session", "debugger_mutation"),
    ("kcd2_mod_build_deploy.guarded_operations:build_candidate_guarded", "build_candidate"),
    ("kcd2_mod_build_deploy.guarded_operations:build_candidate_twice_guarded", "build_candidate"),
    ("kcd2_mod_build_deploy.atomic_deployment:install_candidate_atomic", "install_candidate"),
    ("kcd2_mod_build_deploy.atomic_deployment:rollback_install_atomic", "rollback"),
    ("kcd2_index_adapter.exact_refresh:refresh_mod_exact", "persistent_index_write"),
    ("kcd2_index_adapter.exact_refresh:rollback_mod_exact", "persistent_index_write"),
    ("kcd2_research_graph.migrate:apply_migrations", "persistent_graph_write"),
    ("kcd2_research_graph.repository:GraphRepository.open", "persistent_graph_write"),
    ("kcd2_research_graph.repository:GraphRepository.transaction", "persistent_graph_write"),
    ("kcd2_research_graph.index_importer:IndexGraphImporter.import_response", "persistent_graph_write"),
    ("kcd2_research_graph.animation_routing:AnimationRoutingImporter.import_document", "persistent_graph_write"),
    ("kcd2_research_graph.runtime_importer:RuntimeGraphImporter.import_session", "persistent_graph_write"),
)

READ_ONLY_ENTRY_POINTS = (
    "kcd2_mod_build_deploy.plugin_tools.create_public_registry",
    "kcd2_native_probes.plugin_tools.create_public_registry",
    "kcd2_research_graph.queries.GraphQueryService",
    "kcd2_index_adapter.exact_inspection.inspect_mod_exact",
)


def require_entry_point_audit() -> dict[str, Any]:
    """Verify every reviewed public mutation surface exposes only the shared gate."""
    diagnostics: list[str] = []
    for name, _operation in MUTATING_ENTRY_POINTS:
        module_name, separator, attribute_path = name.partition(":")
        if not separator:
            diagnostics.append(f"invalid audit locator: {name}")
            continue
        try:
            value: object = importlib.import_module(module_name)
            for component in attribute_path.split("."):
                value = getattr(value, component)
            parameters = inspect.signature(value).parameters
        except (AttributeError, ImportError, TypeError, ValueError) as exc:
            diagnostics.append(f"entry point unavailable: {name}: {exc}")
            continue
        if "approved_by_user" in parameters:
            diagnostics.append(f"boolean approval bypass remains: {name}")
        if "approval" not in parameters or "approval_verifier" not in parameters:
            diagnostics.append(f"shared approval gate missing: {name}")
    return {
        "schema_version": "kcd2.mutation-entry-point-audit.v1",
        "status": "PASS" if not diagnostics else "FAIL",
        "gate": "kcd2_toolchain_core.approvals.ApprovalVerifier.execute",
        "mutating_entry_points": [
            {"entry_point": name, "operation": operation, "approval_required": True}
            for name, operation in MUTATING_ENTRY_POINTS
        ],
        "read_only_entry_points": [
            {"entry_point": name, "approval_required": False}
            for name in READ_ONLY_ENTRY_POINTS
        ],
        "debugger_mutation_surface": "three_approval_bound_session_operations_only",
        "mutating_plugin_surface": "absent_fail_closed",
        "mutating_cli_surface": "absent_fail_closed",
        "kcse_installer_surface": "staged_plan_only_no_installed_target_mutation",
        "persistent_index_runtime_surface": "source_unavailable_fail_closed",
        "diagnostics": diagnostics,
    }


__all__ = ["MUTATING_ENTRY_POINTS", "READ_ONLY_ENTRY_POINTS", "require_entry_point_audit"]
