"""Deterministic, non-live staging for source-auditable remediation releases."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from kcd2_mod_build_deploy.plugin_deployment import (
    build_plugin_package,
    install_plugin_atomic,
    restore_plugin_atomic,
    verify_installed_catalog,
)
from kcd2_mod_build_deploy.plugin_tools import (
    SUPPORTED_TOOL_NAMES as MOD_BUILD_DEPLOY_TOOLS,
    create_public_registry as create_mod_build_deploy_registry,
    load_surface_manifest as load_mod_build_deploy_surface,
)
from kcd2_native_probes.plugin_deployment import (
    build_plugin_package as build_native_probes_package,
    install_plugin_atomic as install_native_probes_atomic,
    restore_plugin_atomic as restore_native_probes_atomic,
    verify_installed_catalog as verify_native_probes_catalog,
)
from kcd2_native_probes.plugin_tools import (
    SUPPORTED_TOOL_NAMES as NATIVE_PROBE_TOOLS,
    create_public_registry as create_native_probes_registry,
    load_surface_manifest as load_native_probes_surface,
)
from kcd2_research_graph.plugin_deployment import (
    build_plugin_package as build_research_graph_package,
    install_plugin_atomic as install_research_graph_atomic,
    restore_plugin_atomic as restore_research_graph_atomic,
    verify_installed_catalog as verify_research_graph_catalog,
)
from kcd2_toolchain_core.catalog_parity import (
    verify_repository_parity,
    verify_staged_payload_parity,
)
from kcd2_toolchain_core.live_readonly_acceptance import (
    REQUIRED_LIVE_READONLY_CASE_IDS,
)
from kcd2_toolchain_core.plugin_surface import smoke_test_public_surface
from kcd2_toolchain_core.r6_production_acceptance import REQUIRED_R6_CASE_IDS
from kcd2_workflow_orchestrator.mcp_server import TOOL_NAMES as ORCHESTRATOR_TOOL_NAMES


PROFILE_SCHEMA = "kcd2.general-mod-remediation-release-inputs.v1"
MANIFEST_SCHEMA = "kcd2.general-mod-remediation-release.v1"
R4_PROFILE_SCHEMA = "kcd2.r4-general-mod-release-inputs.v1"
R4_MANIFEST_SCHEMA = "kcd2.r4-general-mod-release.v1"
R5_PROFILE_SCHEMA = "kcd2.r5-production-integration-release-inputs.v1"
R5_MANIFEST_SCHEMA = "kcd2.r5-production-integration-release.v1"
R6_PROFILE_SCHEMA = "kcd2.r6-orchestrated-release-inputs.v1"
R6_MANIFEST_SCHEMA = "kcd2.r6-orchestrated-release.v1"
R6_SCHEMA_ID = "https://local/kcd2/schemas/r6-orchestrated-release-v1.schema.json"
R7_PROFILE_SCHEMA = "kcd2.r7-portfolio-release-inputs.v1"
R7_MANIFEST_SCHEMA = "kcd2.r7-portfolio-release.v1"
R7_SCHEMA_ID = "https://local/kcd2/schemas/r7-portfolio-release-v1.schema.json"
INTEGRATED_PROFILE_SCHEMA = "kcd2.integrated-private-release-inputs.v1"
INTEGRATED_MANIFEST_SCHEMA = "kcd2.integrated-private-release.v1"
INTEGRATED_SCHEMA_ID = (
    "https://schemas.local/kcd2/integrated-private-release-v1.schema.json"
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_INPUT_FILES = 20_000
MAX_INPUT_BYTES = 256 * 1024 * 1024
_DEBRIS = {".git", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__"}


class ReleaseStagingError(RuntimeError):
    """Raised when a release cannot be staged without weakening a gate."""


@dataclass(frozen=True)
class ReleaseBuildReceipt:
    output_root: Path
    release_tree_sha256: str
    package_sha256: Mapping[str, str]


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReleaseStagingError("release paths must be non-empty POSIX paths")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ReleaseStagingError(f"unsafe release path: {value!r}")
    return relative


def _repository_path(repository: Path, value: str) -> Path:
    relative = _safe_relative(value)
    path = repository.joinpath(*relative.parts).resolve()
    if not _is_relative_to(path, repository):
        raise ReleaseStagingError(f"input escapes repository: {value}")
    return path


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseStagingError(f"invalid JSON object: {path}") from exc
    if not isinstance(value, dict):
        raise ReleaseStagingError(f"JSON root must be an object: {path}")
    return value


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if completed.returncode:
        raise ReleaseStagingError(
            f"git {' '.join(arguments)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.strip()


def _source_identity(repository: Path) -> dict[str, str]:
    revision = _git(repository, "rev-parse", "HEAD")
    status = _git(repository, "status", "--porcelain")
    return {
        "revision": revision,
        "revision_state": "clean" if not status else "modified_worktree",
    }


def _validate_dependencies(repository: Path, profile: Mapping[str, Any]) -> list[dict[str, str]]:
    backlog = _load_object(repository / "KCD2_TOOLCHAIN_IMPLEMENTATION_BACKLOG_20260807_R7.json")
    tasks = {item.get("id"): item for item in backlog.get("tasks", []) if isinstance(item, dict)}
    dependencies: list[dict[str, str]] = []
    for task_id in profile.get("dependencies", []):
        task = tasks.get(task_id)
        status = task.get("status") if isinstance(task, dict) else None
        if status != "done":
            raise ReleaseStagingError(f"release dependency is not done: {task_id}={status}")
        dependencies.append({"task_id": task_id, "status": status})
    return dependencies


def _changed_file_report(
    repository: Path, profile: Mapping[str, Any], dependencies: list[dict[str, str]]
) -> dict[str, Any]:
    change_sets: list[dict[str, Any]] = []
    all_files: set[str] = set()
    for item in profile.get("change_sets", []):
        task_id = item.get("task_id")
        commits = item.get("commits")
        if not isinstance(task_id, str) or not isinstance(commits, list) or not commits:
            raise ReleaseStagingError("change sets require a task_id and commits")
        task_files: set[str] = set()
        resolved_commits: list[str] = []
        for commit in commits:
            if not isinstance(commit, str) or len(commit) != 40:
                raise ReleaseStagingError(f"invalid change-set commit for {task_id}")
            resolved = _git(repository, "rev-parse", f"{commit}^{{commit}}")
            if resolved != commit:
                raise ReleaseStagingError(f"change-set commit identity drift for {task_id}")
            names = _git(
                repository,
                "show",
                "--format=",
                "--name-only",
                "--diff-filter=ACMR",
                commit,
            ).splitlines()
            task_files.update(name for name in names if name)
            resolved_commits.append(resolved)
        ordered = sorted(task_files)
        change_sets.append({"task_id": task_id, "commits": resolved_commits, "files": ordered})
        all_files.update(ordered)
    forbidden = sorted(path for path in all_files if path.startswith("references/"))
    if forbidden:
        raise ReleaseStagingError(f"release change set mutates immutable references: {forbidden}")
    return {
        "schema_version": "kcd2.changed-file-report.v1",
        "task_id": profile["task_id"],
        "dependencies": dependencies,
        "change_sets": change_sets,
        "changed_files": sorted(all_files),
        "immutable_references_changed": False,
    }


def _input_members(
    repository: Path, inputs: Iterable[Mapping[str, Any]]
) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    total_bytes = 0
    for mapping in inputs:
        source_value = mapping.get("source")
        target_value = mapping.get("target")
        if not isinstance(source_value, str) or not isinstance(target_value, str):
            raise ReleaseStagingError("package inputs require source and target")
        source = _repository_path(repository, source_value)
        target = _safe_relative(target_value)
        if source.is_symlink() or not source.exists():
            raise ReleaseStagingError(f"package source is missing or a symlink: {source_value}")
        sources = [source] if source.is_file() else sorted(source.rglob("*"))
        for path in sources:
            if path.is_dir():
                continue
            relative = Path() if source.is_file() else path.relative_to(source)
            if path.is_symlink() or any(part in _DEBRIS for part in relative.parts):
                if path.is_symlink():
                    raise ReleaseStagingError(f"package source contains a symlink: {path}")
                continue
            member = (target / PurePosixPath(relative.as_posix())).as_posix()
            if member in members:
                raise ReleaseStagingError(f"duplicate package member: {member}")
            data = path.read_bytes()
            total_bytes += len(data)
            members[member] = data
    if len(members) > MAX_INPUT_FILES or total_bytes > MAX_INPUT_BYTES:
        raise ReleaseStagingError("package input bounds exceeded")
    return members


def _build_source_archive(
    repository: Path,
    inputs: Iterable[Mapping[str, Any]],
    archive: Path,
    *,
    role: str,
    profile_sha256: str,
    source_identity: Mapping[str, str],
) -> str:
    members = _input_members(repository, inputs)
    records = [
        {"path": path, "size": len(data), "sha256": _sha256_bytes(data)}
        for path, data in sorted(members.items())
    ]
    package_manifest = {
        "schema_version": "kcd2.remediation-source-package.v1",
        "role": role,
        "classification": "non_live",
        "installation_performed": False,
        "source": dict(source_identity),
        "release_profile_sha256": profile_sha256,
        "files": records,
    }
    members["package-manifest.json"] = _json_bytes(package_manifest)
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as output:
        for name, data in sorted(members.items()):
            info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            output.writestr(info, data)
    return _sha256_file(archive)


def _snapshot(root: Path) -> tuple[tuple[str, bytes], ...]:
    if not root.exists():
        return ()
    return tuple(
        (path.relative_to(root).as_posix(), path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _deployment_dry_runs(
    work_root: Path,
    stage_root: Path,
    package_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    synthetic = work_root / "synthetic-deployment"
    active = synthetic / "plugins" / "kcd2-mod-build-deploy"
    active.joinpath(".codex-plugin").mkdir(parents=True)
    active.joinpath(".codex-plugin/plugin.json").write_bytes(
        b'{"name":"kcd2-mod-build-deploy","version":"0.0.0-synthetic"}\n'
    )
    active.joinpath("prior-marker.txt").write_bytes(b"synthetic-prior-state\r\n")
    catalog = synthetic / "catalog" / "plugins.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_bytes(
        b'{"schema_version":"kcd2.plugin-catalog.v1","plugins":[]}'
    )
    prior_tree = _snapshot(active)
    prior_catalog = catalog.read_bytes()
    installed = install_plugin_atomic(
        stage_root,
        active_plugin_root=active,
        rollback_root=synthetic / "rollback",
        catalog_path=catalog,
        transaction_id="rel-603-synthetic",
    )
    verified = verify_installed_catalog(active, catalog)
    migration = {
        "schema_version": "kcd2.release-migration-dry-run.v1",
        "task_id": "REL-603",
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "package_sha256": package_sha256,
        "staged_tree_sha256": installed.tree_sha256,
        "catalog_verification": verified["status"],
        "transaction_scope": "approved_external_scratch",
    }
    restored = restore_plugin_atomic(installed.receipt_path)
    tree_restored = _snapshot(active) == prior_tree
    catalog_restored = catalog.read_bytes() == prior_catalog
    if restored.get("status") != "restored" or not tree_restored or not catalog_restored:
        raise ReleaseStagingError("synthetic rollback did not restore exact prior bytes")
    rollback = {
        "schema_version": "kcd2.release-rollback-dry-run.v1",
        "task_id": "REL-603",
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "prior_plugin_tree_restored": tree_restored,
        "prior_catalog_bytes_restored": catalog_restored,
        "transaction_scope": "approved_external_scratch",
    }
    return migration, rollback


def _plugin_deployment_dry_runs(
    work_root: Path,
    stage_root: Path,
    package_sha256: str,
    *,
    task_id: str,
    plugin_name: str,
    install: Any,
    restore: Any,
    verify: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Exercise one plugin's install and exact restore against scratch-only state."""
    synthetic = work_root / f"synthetic-{plugin_name}"
    active = synthetic / "plugins" / plugin_name
    active.joinpath(".codex-plugin").mkdir(parents=True)
    active.joinpath(".codex-plugin/plugin.json").write_bytes(
        _json_bytes({"name": plugin_name, "version": "0.0.0-synthetic"})
    )
    active.joinpath("prior-marker.txt").write_bytes(b"synthetic-prior-state\r\n")
    catalog = synthetic / "catalog" / "plugins.json"
    catalog.parent.mkdir(parents=True)
    catalog.write_bytes(b'{"schema_version":"kcd2.plugin-catalog.v1","plugins":[]}')
    prior_tree = _snapshot(active)
    prior_catalog = catalog.read_bytes()
    transaction_id = f"{task_id.lower()}-{plugin_name}-synthetic"
    installed = install(
        stage_root,
        active_plugin_root=active,
        rollback_root=synthetic / "rollback",
        catalog_path=catalog,
        transaction_id=transaction_id,
    )
    catalog_verification = verify(active, catalog)
    migration = {
        "schema_version": "kcd2.release-migration-dry-run.v1",
        "task_id": task_id,
        "plugin_name": plugin_name,
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "package_sha256": package_sha256,
        "staged_tree_sha256": installed.tree_sha256,
        "catalog_verification": catalog_verification["status"],
        "transaction_scope": "approved_external_scratch",
    }
    restored = restore(installed.receipt_path)
    tree_restored = _snapshot(active) == prior_tree
    catalog_restored = catalog.read_bytes() == prior_catalog
    if restored.get("status") != "restored" or not tree_restored or not catalog_restored:
        raise ReleaseStagingError(f"synthetic rollback failed for {plugin_name}")
    rollback = {
        "schema_version": "kcd2.release-rollback-dry-run.v1",
        "task_id": task_id,
        "plugin_name": plugin_name,
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "prior_plugin_tree_restored": tree_restored,
        "prior_catalog_bytes_restored": catalog_restored,
        "transaction_scope": "approved_external_scratch",
    }
    return migration, rollback


def _extract_source_archive(archive: Path, stage: Path) -> None:
    """Extract one repository-produced archive without accepting unsafe members."""

    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = _safe_relative(member.filename)
            target = stage.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read(member))


def _restore_snapshot(root: Path, snapshot: tuple[tuple[str, bytes], ...]) -> None:
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for relative, content in snapshot:
        target = root.joinpath(*PurePosixPath(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def _orchestrator_deployment_dry_runs(
    work_root: Path,
    stage_root: Path,
    package_sha256: str,
    launcher: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Exercise orchestrator migration and exact rollback only in external scratch."""

    synthetic = work_root / "synthetic-kcd2-workflow-orchestrator"
    active = synthetic / "plugins" / "kcd2-workflow-orchestrator"
    active.joinpath(".codex-plugin").mkdir(parents=True)
    active.joinpath(".codex-plugin/plugin.json").write_bytes(
        _json_bytes(
            {
                "name": "kcd2-workflow-orchestrator",
                "version": "0.0.0-synthetic",
            }
        )
    )
    active.joinpath("prior-marker.txt").write_bytes(b"synthetic-prior-state\r\n")
    prior_tree = _snapshot(active)
    shutil.rmtree(active)
    shutil.copytree(stage_root, active)
    visible_tools = _fresh_plugin_tools(active, launcher)
    names = [item["name"] for item in visible_tools]
    if set(names) != set(ORCHESTRATOR_TOOL_NAMES):
        raise ReleaseStagingError("staged orchestrator tool catalog disagrees with source")
    migration = {
        "schema_version": "kcd2.release-migration-dry-run.v1",
        "task_id": "REL-606",
        "plugin_name": "kcd2-workflow-orchestrator",
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "package_sha256": package_sha256,
        "staged_tree_sha256": _sha256_bytes(
            b"".join(
                relative.encode("utf-8") + b"\0" + content
                for relative, content in _snapshot(active)
            )
        ),
        "catalog_verification": "pass",
        "visible_tools": names,
        "transaction_scope": "approved_external_scratch",
    }
    _restore_snapshot(active, prior_tree)
    tree_restored = _snapshot(active) == prior_tree
    if not tree_restored:
        raise ReleaseStagingError("synthetic orchestrator rollback did not restore prior bytes")
    rollback = {
        "schema_version": "kcd2.release-rollback-dry-run.v1",
        "task_id": "REL-606",
        "plugin_name": "kcd2-workflow-orchestrator",
        "status": "pass",
        "synthetic_fixture_only": True,
        "live_writes": False,
        "production_targets_read": False,
        "prior_plugin_tree_restored": True,
        "prior_catalog_bytes_restored": True,
        "transaction_scope": "approved_external_scratch",
    }
    return migration, rollback


def _r4_public_tool_reports(repository: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    plugins = (
        (
            load_mod_build_deploy_surface(repository),
            create_mod_build_deploy_registry,
            MOD_BUILD_DEPLOY_TOOLS,
        ),
        (
            load_native_probes_surface(repository),
            create_native_probes_registry,
            NATIVE_PROBE_TOOLS,
        ),
    )
    tool_records: list[dict[str, Any]] = []
    smoke_receipts: list[dict[str, Any]] = []
    for manifest, registry_factory, supported in plugins:
        receipt = smoke_test_public_surface(
            manifest,
            registry_factory(repository, manifest),
            supported_library_operations=set(supported),
        )
        if receipt.get("verdict") != "passed":
            raise ReleaseStagingError("public analysis surface smoke test failed")
        plugin = manifest["plugin"]
        results = {item["tool_name"]: item for item in receipt["results"]}
        for item in manifest["tools"]:
            name = item["tool_name"]
            result = results.get(name)
            if (
                item.get("operation_class") != "read_only_analysis"
                or item.get("approval_class") != "none"
                or not isinstance(result, Mapping)
                or result.get("status") != "passed"
                or result.get("invoked_through_public_surface") is not True
            ):
                raise ReleaseStagingError(f"analysis tool is not safely smoke-tested: {name}")
            tool_records.append(
                {
                    "plugin_name": plugin["name"],
                    "plugin_version": plugin["version"],
                    "tool_name": name,
                    "operation_class": item["operation_class"],
                    "approval_class": item["approval_class"],
                    "module_or_symbol": item["library_binding"]["module_or_symbol"],
                    "source_sha256": item["library_binding"]["source_sha256"],
                    "input_schema_sha256": _sha256_bytes(
                        _json_bytes(item["input_schema"])
                    ),
                    "output_schema_sha256": _sha256_bytes(
                        _json_bytes(item["output_schema"])
                    ),
                    "smoke_status": result["status"],
                    "invoked_through_public_surface": True,
                }
            )
        smoke_receipts.append(receipt)
    ordered = sorted(tool_records, key=lambda item: (item["plugin_name"], item["tool_name"]))
    inventory = {
        "schema_version": "kcd2.tool-registration-inventory.v1",
        "task_id": "REL-604",
        "status": "pass",
        "registered_analysis_tool_count": len(ordered),
        "all_invoked_through_public_surface": True,
        "tools": ordered,
    }
    smoke = {
        "schema_version": "kcd2.release-public-surface-smoke-receipts.v1",
        "task_id": "REL-604",
        "status": "pass",
        "receipts": sorted(
            smoke_receipts, key=lambda item: item["plugin"]["name"]
        ),
    }
    return inventory, smoke


def _coverage_negative_claim_report(
    repository: Path, profile: Mapping[str, Any]
) -> dict[str, Any]:
    claims = profile.get("coverage_negative_claim_contracts")
    if not isinstance(claims, Mapping):
        raise ReleaseStagingError("coverage and negative-claim contract declaration is missing")
    expected = {
        "coverage_permissions_fail_closed": True,
        "negative_claims_coverage_qualified": True,
        "invalid_capture_conclusion": "capture_inconclusive",
    }
    if any(claims.get(key) != value for key, value in expected.items()):
        raise ReleaseStagingError("coverage and negative-claim contracts do not fail closed")
    evidence = _test_receipts(
        repository,
        {"task_id": "REL-604", "test_receipts": profile.get("contract_receipts", [])},
    )
    if not evidence["receipts"]:
        raise ReleaseStagingError("coverage and negative-claim evidence is empty")
    return {
        "schema_version": "kcd2.coverage-negative-claim-release-receipt.v1",
        "task_id": "REL-604",
        "status": "pass",
        **expected,
        "evidence": evidence["receipts"],
    }


def _test_receipts(repository: Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    receipts: list[dict[str, Any]] = []
    for value in profile.get("test_receipts", []):
        if not isinstance(value, str):
            raise ReleaseStagingError("test receipt paths must be strings")
        path = _repository_path(repository, value)
        if not path.is_file():
            raise ReleaseStagingError(f"test receipt is unavailable: {value}")
        receipts.append({"path": value, "size": path.stat().st_size, "sha256": _sha256_file(path)})
    return {
        "schema_version": "kcd2.release-test-receipts.v1",
        "task_id": profile["task_id"],
        "receipts": receipts,
    }


def _jsonl_process(
    command: list[str],
    *,
    cwd: Path,
    requests: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    environment = dict(os.environ)
    environment.pop("PYTHONPATH", None)
    request_text = "".join(
        json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n"
        for item in requests
    )
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        input=request_text,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    if completed.returncode:
        raise ReleaseStagingError(
            "fresh staged tools/list process failed: " + completed.stderr[:1000]
        )
    try:
        responses = [
            json.loads(line)
            for line in completed.stdout.splitlines()
            if line.strip()
        ]
    except json.JSONDecodeError as exc:
        raise ReleaseStagingError("fresh staged tools/list returned invalid JSON") from exc
    if len(responses) != len(requests) or not all(
        isinstance(item, dict) for item in responses
    ):
        raise ReleaseStagingError("fresh staged tools/list response count disagrees")
    return responses


def _tools_from_response(response: Mapping[str, Any]) -> list[dict[str, Any]]:
    result = response.get("result")
    tools = result.get("tools") if isinstance(result, Mapping) else None
    if not isinstance(tools, list) or not tools:
        raise ReleaseStagingError("fresh staged tools/list returned no tools")
    names = [item.get("name") for item in tools if isinstance(item, Mapping)]
    if len(names) != len(tools) or any(not isinstance(name, str) for name in names):
        raise ReleaseStagingError("fresh staged tools/list returned an invalid tool")
    if len(set(names)) != len(names):
        raise ReleaseStagingError("fresh staged tools/list returned duplicate tools")
    return [dict(item) for item in tools]


def _fresh_plugin_tools(stage: Path, launcher: str) -> list[dict[str, Any]]:
    responses = _jsonl_process(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(stage / launcher),
        ],
        cwd=stage,
        requests=[{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}],
    )
    return _tools_from_response(responses[0])


def _fresh_index_tools(repository: Path, profile: Mapping[str, Any]) -> dict[str, Any]:
    config = profile.get("index_runtime_catalog")
    if not isinstance(config, Mapping):
        raise ReleaseStagingError("Index runtime catalog declaration is missing")
    executable_value = config.get("executable")
    expected_sha256 = config.get("sha256")
    if not isinstance(executable_value, str) or not isinstance(expected_sha256, str):
        raise ReleaseStagingError("Index runtime catalog identity is invalid")
    executable = _repository_path(repository, executable_value)
    actual_sha256 = _sha256_file(executable)
    if actual_sha256.lower() != expected_sha256.lower():
        raise ReleaseStagingError("Index runtime candidate SHA-256 disagrees")
    responses = _jsonl_process(
        [str(executable)],
        cwd=repository,
        requests=[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ],
    )
    initialized = responses[0].get("result")
    if not isinstance(initialized, Mapping):
        raise ReleaseStagingError("Index runtime candidate initialization failed")
    tools = _tools_from_response(responses[1])
    expected_count = config.get("expected_tool_count")
    if not isinstance(expected_count, int) or len(tools) != expected_count:
        raise ReleaseStagingError("Index runtime candidate tool count disagrees")
    server = initialized.get("serverInfo")
    return {
        "surface": "kcd2-index-runtime-candidate",
        "visibility_state": "STAGED_NEW_PROCESS_VISIBLE",
        "evidence_layer": "source_auditable_candidate_fresh_tools_list",
        "candidate_sha256": actual_sha256,
        "protocol_version": initialized.get("protocolVersion"),
        "server": dict(server) if isinstance(server, Mapping) else None,
        "tools": [item["name"] for item in tools],
    }


def _direct_tool_catalog(
    repository: Path,
    profile: Mapping[str, Any],
    stages: Mapping[str, Path],
) -> dict[str, Any]:
    launchers = {
        "kcd2-mod-build-deploy": "scripts/Start-KCD2ModBuildDeployMcp.ps1",
        "kcd2-native-probes": "scripts/Start-KCD2NativeProbesMcp.ps1",
        "kcd2-research-graph": "scripts/Start-KCD2ResearchGraphMcp.ps1",
    }
    repository_parity = verify_repository_parity(repository)
    surfaces: list[dict[str, Any]] = []
    parity_receipts: list[dict[str, Any]] = []
    for plugin_name in sorted(launchers):
        stage = stages.get(plugin_name)
        if stage is None:
            raise ReleaseStagingError(f"staged plugin is missing: {plugin_name}")
        tools = _fresh_plugin_tools(stage, launchers[plugin_name])
        parity = verify_staged_payload_parity(
            repository,
            stage,
            plugin_name,
            tools,
        )
        parity_receipts.append(parity)
        surfaces.append(
            {
                "surface": plugin_name,
                "visibility_state": "STAGED_NEW_PROCESS_VISIBLE",
                "evidence_layer": "fresh_staged_payload_and_new_mcp_process",
                "catalog_sha256": parity["catalog_sha256"],
                "source_revision_sha256": parity["source_revision_sha256"],
                "tools": [item["name"] for item in tools],
            }
        )
    surfaces.append(_fresh_index_tools(repository, profile))
    surfaces.sort(key=lambda item: item["surface"])
    boundaries = profile.get("source_boundaries")
    if not isinstance(boundaries, Mapping):
        raise ReleaseStagingError("release source boundaries are missing")
    source_blockers = boundaries.get("source_blockers")
    deployment_blockers = boundaries.get("deployment_blockers")
    if not isinstance(source_blockers, list) or not isinstance(deployment_blockers, list):
        raise ReleaseStagingError("release source boundary arrays are invalid")
    return {
        "schema_version": "kcd2.r5-direct-tool-catalog.v1",
        "task_id": "REL-605",
        "status": "pass",
        "evidence_layer": "fresh_non_live_staged_processes",
        "direct_tool_count": sum(len(item["tools"]) for item in surfaces),
        "surfaces": surfaces,
        "repository_parity": repository_parity,
        "staged_parity_receipts": parity_receipts,
        "source_blockers": source_blockers,
        "deployment_blockers": deployment_blockers,
        "live_installed_visibility": "NOT_RUN",
    }


def _production_acceptance_dossier(
    repository: Path,
    profile: Mapping[str, Any],
    dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    receipt_value = profile.get("live_readonly_receipt")
    if not isinstance(receipt_value, str):
        raise ReleaseStagingError("live read-only receipt declaration is missing")
    receipt_path = _repository_path(repository, receipt_value)
    receipt = _load_object(receipt_path)
    evidence_states = receipt.get("evidence_states")
    if (
        receipt.get("execution_class") != "non_live_fixture"
        or receipt.get("overall_status") != "PASS"
        or receipt.get("mutation_count") != 0
        or not isinstance(evidence_states, Mapping)
        or evidence_states.get("non_live") != "PASS"
        or evidence_states.get("live_read_only") != "NOT_RUN"
    ):
        raise ReleaseStagingError("TEST-004 receipt cannot support non-live R5 staging")
    boundaries = profile.get("source_boundaries")
    if not isinstance(boundaries, Mapping):
        raise ReleaseStagingError("release source boundaries are missing")
    source_blockers = boundaries.get("source_blockers")
    deployment_blockers = boundaries.get("deployment_blockers")
    if not isinstance(source_blockers, list) or not isinstance(deployment_blockers, list):
        raise ReleaseStagingError("release source boundary arrays are invalid")
    unresolved = [
        {
            "case_id": case_id,
            "state": "NOT_RUN",
            "reason": (
                "No separately authorized live_read_only execution receipt was supplied; "
                "synthetic fixture evidence cannot establish production acceptance."
            ),
            "required_evidence": (
                "content-bound live_read_only authorization and zero-write receipt"
            ),
        }
        for case_id in REQUIRED_LIVE_READONLY_CASE_IDS
    ]
    risks = [dict(item) for item in deployment_blockers if isinstance(item, Mapping)]
    risks.extend(
        {
            "code": f"LIVE_ACCEPTANCE_NOT_RUN:{item['case_id']}",
            "detail": item["reason"],
        }
        for item in unresolved
    )
    return {
        "schema_version": "kcd2.r5-production-acceptance-dossier.v1",
        "task_id": "REL-605",
        "classification": "non_live",
        "release_states": {
            "implemented": "PASS",
            "non_live_tested": "PASS",
            "live_read_only_accepted": "NOT_RUN",
            "accepted_external_risk": "NOT_ACCEPTED",
            "actually_resolved": "OPEN",
            "blocked_source": "YES" if source_blockers else "NO",
        },
        "dependencies": dependencies,
        "non_live_receipt": {
            "path": receipt_value,
            "sha256": _sha256_file(receipt_path),
            "execution_class": receipt["execution_class"],
            "live_read_only_state": evidence_states["live_read_only"],
        },
        "unresolved_live_defects": unresolved,
        "unresolved_production_risks": risks,
        "source_blockers": source_blockers,
        "deployment_blockers": deployment_blockers,
        "live_mutation_count": 0,
        "installation_performed": False,
        "production_targets_read": False,
    }


def _r6_direct_tool_catalog(
    repository: Path,
    profile: Mapping[str, Any],
    base_profile: Mapping[str, Any],
    stages: Mapping[str, Path],
    orchestrator_stage: Path,
    launcher: str,
) -> dict[str, Any]:
    combined_profile = dict(profile)
    combined_profile["index_runtime_catalog"] = base_profile["index_runtime_catalog"]
    catalog = _direct_tool_catalog(repository, combined_profile, stages)
    visible = _fresh_plugin_tools(orchestrator_stage, launcher)
    names = [item["name"] for item in visible]
    if set(names) != set(ORCHESTRATOR_TOOL_NAMES):
        raise ReleaseStagingError("fresh orchestrator catalog disagrees with source tool names")
    source_records = []
    for path in sorted(
        repository.joinpath("src/kcd2_workflow_orchestrator").glob("*.py")
    ):
        source_records.append(
            {
                "path": path.relative_to(repository).as_posix(),
                "sha256": _sha256_file(path),
            }
        )
    source_revision = _sha256_bytes(_json_bytes(source_records))
    catalog["surfaces"].append(
        {
            "surface": "kcd2-workflow-orchestrator",
            "visibility_state": "STAGED_NEW_PROCESS_VISIBLE",
            "evidence_layer": "fresh_staged_payload_and_new_mcp_process",
            "catalog_sha256": _sha256_bytes(_json_bytes(visible)),
            "source_revision_sha256": source_revision,
            "tools": names,
        }
    )
    catalog["surfaces"].sort(key=lambda item: item["surface"])
    catalog.update(
        {
            "schema_version": "kcd2.r6-direct-tool-catalog.v1",
            "task_id": "REL-606",
            "direct_tool_count": sum(
                len(item["tools"]) for item in catalog["surfaces"]
            ),
            "orchestrator_source_records": source_records,
        }
    )
    return catalog


def _r6_acceptance_dossier(
    repository: Path,
    profile: Mapping[str, Any],
    dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    receipt_value = profile.get("live_readonly_receipt")
    audit_value = profile.get("zero_mutation_audit")
    if not isinstance(receipt_value, str) or not isinstance(audit_value, str):
        raise ReleaseStagingError("R6 acceptance receipt declarations are missing")
    receipt_path = _repository_path(repository, receipt_value)
    audit_path = _repository_path(repository, audit_value)
    receipt = _load_object(receipt_path)
    audit = _load_object(audit_path)
    evidence_states = receipt.get("evidence_states")
    if (
        receipt.get("task_id") != "TEST-006"
        or receipt.get("execution_class") != "non_live_fixture"
        or receipt.get("overall_status") != "PASS"
        or receipt.get("mutation_count") != 0
        or not isinstance(evidence_states, Mapping)
        or evidence_states.get("non_live") != "PASS"
        or evidence_states.get("live_read_only") != "NOT_RUN"
    ):
        raise ReleaseStagingError("TEST-006 receipt cannot support non-live R6 staging")
    if (
        audit.get("task_id") != "TEST-006"
        or audit.get("live_execution_state") != "NOT_RUN"
        or audit.get("live_targets_read") != []
        or audit.get("live_targets_written") != []
        or audit.get("synthetic_mutation_count") != 0
    ):
        raise ReleaseStagingError("TEST-006 zero-mutation audit is invalid")
    boundaries = profile.get("source_boundaries")
    if not isinstance(boundaries, Mapping):
        raise ReleaseStagingError("R6 source boundaries are missing")
    source_blockers = boundaries.get("source_blockers")
    deployment_blockers = boundaries.get("deployment_blockers")
    if not isinstance(source_blockers, list) or not isinstance(deployment_blockers, list):
        raise ReleaseStagingError("R6 source boundary arrays are invalid")
    unresolved = [
        {
            "case_id": case_id,
            "state": "NOT_RUN",
            "reason": (
                "No content-bound live observation bundle was supplied; synthetic evidence "
                "cannot establish production acceptance."
            ),
            "required_evidence": "authorized live_read_only observation and zero-write receipt",
        }
        for case_id in REQUIRED_R6_CASE_IDS
    ]
    risks = [dict(item) for item in deployment_blockers if isinstance(item, Mapping)]
    risks.extend(
        {
            "code": f"R6_LIVE_ACCEPTANCE_NOT_RUN:{item['case_id']}",
            "detail": item["reason"],
        }
        for item in unresolved
    )
    return {
        "schema_version": "kcd2.r6-production-acceptance-dossier.v1",
        "task_id": "REL-606",
        "classification": "non_live",
        "release_states": {
            "implemented": "PASS",
            "non_live_tested": "PASS",
            "live_read_only_accepted": "NOT_RUN",
            "accepted_external_risk": "NOT_ACCEPTED",
            "actually_resolved": "OPEN",
            "blocked_source": "YES" if source_blockers else "NO",
        },
        "dependencies": dependencies,
        "non_live_receipt": {
            "path": receipt_value,
            "sha256": _sha256_file(receipt_path),
            "execution_class": receipt["execution_class"],
            "live_read_only_state": evidence_states["live_read_only"],
        },
        "zero_mutation_audit": {
            "path": audit_value,
            "sha256": _sha256_file(audit_path),
            "live_execution_state": audit["live_execution_state"],
        },
        "live_authorization_state": "BOUNDARY_PRESENT_OBSERVATIONS_NOT_SUPPLIED",
        "unresolved_live_cases": unresolved,
        "unresolved_production_risks": risks,
        "source_blockers": source_blockers,
        "deployment_blockers": deployment_blockers,
        "live_mutation_count": 0,
        "installation_performed": False,
        "production_targets_read": False,
    }


def _r6_unresolved_channels(
    repository: Path,
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    capability_value = profile.get("passive_input_capability")
    if not isinstance(capability_value, str):
        raise ReleaseStagingError("passive input capability receipt is missing")
    capability_path = _repository_path(repository, capability_value)
    capability = _load_object(capability_path)
    if (
        capability.get("schema_version") != "kcd2.input-marker-capability.v1"
        or capability.get("status") != "unavailable"
        or capability.get("selected_route_id") is not None
    ):
        raise ReleaseStagingError("passive input capability was not honestly unavailable")
    passive = dict(capability)
    passive.update(
        {
            "receipt_path": capability_value,
            "receipt_sha256": _sha256_file(capability_path),
            "adapter_implemented": False,
            "evidence_layer": "reviewed_non_live_capability_preflight",
        }
    )
    return {
        "schema_version": "kcd2.r6-unresolved-channels.v1",
        "task_id": "REL-606",
        "passive_input_capability": passive,
        "live_read_only_state": "NOT_RUN",
        "live_read_only_case_ids": list(REQUIRED_R6_CASE_IDS),
        "capture_claim": "capture_inconclusive",
        "unresolved_channels_retained": True,
        "installation_authorized": False,
        "live_targets_read": [],
        "live_targets_written": [],
    }


def _r7_portfolio_provider_catalog(
    repository: Path,
    profile: Mapping[str, Any],
) -> dict[str, Any]:
    expected = {
        "provider:ai-quest",
        "provider:asset",
        "provider:audio",
        "provider:combat-native",
        "provider:localization",
        "provider:lua",
        "provider:table-rpg",
        "provider:ui-gfx",
    }
    raw_providers = profile.get("portfolio_providers")
    if not isinstance(raw_providers, list) or len(raw_providers) != len(expected):
        raise ReleaseStagingError("R7 portfolio provider declarations are incomplete")
    providers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_providers:
        if not isinstance(raw, Mapping):
            raise ReleaseStagingError("R7 portfolio provider declaration must be an object")
        provider_id = raw.get("provider_id")
        domains = raw.get("domains")
        roles = raw.get("component_package_roles")
        source_paths = raw.get("source_paths")
        if (
            not isinstance(provider_id, str)
            or provider_id in seen
            or not isinstance(domains, list)
            or not domains
            or not all(isinstance(item, str) and item for item in domains)
            or not isinstance(roles, list)
            or not roles
            or not all(isinstance(item, str) and item for item in roles)
            or not isinstance(source_paths, list)
            or not source_paths
        ):
            raise ReleaseStagingError(f"invalid R7 portfolio provider: {provider_id}")
        seen.add(provider_id)
        source_records: list[dict[str, str]] = []
        for value in source_paths:
            if not isinstance(value, str):
                raise ReleaseStagingError(f"invalid provider source path: {provider_id}")
            path = _repository_path(repository, value)
            if not path.is_file():
                raise ReleaseStagingError(
                    f"portfolio provider source is unavailable: {provider_id}:{value}"
                )
            source_records.append({"path": value, "sha256": _sha256_file(path)})
        source_records.sort(key=lambda item: item["path"])
        providers.append(
            {
                "provider_id": provider_id,
                "domains": sorted(set(domains)),
                "component_package_roles": sorted(set(roles)),
                "source_records": source_records,
                "source_revision_sha256": _sha256_bytes(_json_bytes(source_records)),
                "visibility_state": "STAGED_SOURCE_VISIBLE",
                "blocked_reasons": [],
            }
        )
    if seen != expected:
        raise ReleaseStagingError("R7 portfolio provider identities disagree")
    combat = [item for item in providers if item["provider_id"] == "provider:combat-native"]
    if len(combat) != 1 or combat[0]["domains"] != ["combat", "native"]:
        raise ReleaseStagingError("combat/native must remain exactly one provider")
    providers.sort(key=lambda item: item["provider_id"])
    return {
        "schema_version": "kcd2.r7-portfolio-provider-catalog.v1",
        "task_id": "REL-607",
        "classification": "non_live",
        "providers": providers,
        "provider_count": len(providers),
        "combat_native_provider_count": len(combat),
        "source_blockers": [],
        "live_installed_visibility": "NOT_RUN_NO_INSTALLATION",
    }


def _r7_acceptance_dossier(
    repository: Path,
    profile: Mapping[str, Any],
    dependencies: list[dict[str, str]],
    provider_catalog: Mapping[str, Any],
) -> dict[str, Any]:
    test_value = profile.get("portfolio_test_report")
    compat_value = profile.get("compatibility_receipt")
    if not isinstance(test_value, str) or not isinstance(compat_value, str):
        raise ReleaseStagingError("R7 acceptance evidence declarations are missing")
    test_path = _repository_path(repository, test_value)
    compat_path = _repository_path(repository, compat_value)
    test_report = _load_object(test_path)
    compat = _load_object(compat_path)
    if (
        test_report.get("task_id") != "TEST-007"
        or test_report.get("classification") != "non_live"
        or test_report.get("result") != "passed"
        or test_report.get("acceptance", {}).get("live_mutation") is not False
    ):
        raise ReleaseStagingError("TEST-007 report cannot support REL-607")
    if (
        compat.get("task_id") != "COMPAT-006"
        or compat.get("classification") != "non_live"
        or compat.get("focused_validation", {}).get("result") != "passed"
        or compat.get("all_non_live", {}).get("result") != "passed"
    ):
        raise ReleaseStagingError("COMPAT-006 receipt cannot support REL-607")
    boundaries = profile.get("source_boundaries")
    if not isinstance(boundaries, Mapping):
        raise ReleaseStagingError("R7 source boundaries are missing")
    source_blockers = boundaries.get("source_blockers")
    deployment_blockers = boundaries.get("deployment_blockers")
    if not isinstance(source_blockers, list) or not isinstance(deployment_blockers, list):
        raise ReleaseStagingError("R7 source boundary arrays are invalid")
    unresolved = [dict(item) for item in deployment_blockers if isinstance(item, Mapping)]
    unresolved.append(
        {
            "code": "PORTFOLIO_PROVIDER_INSTALLED_VISIBILITY_NOT_RUN",
            "detail": (
                "Provider sources are visible in staged products, but installed callable "
                "visibility was not exercised because installation is outside REL-607."
            ),
        }
    )
    return {
        "schema_version": "kcd2.r7-portfolio-acceptance-dossier.v1",
        "task_id": "REL-607",
        "classification": "non_live",
        "release_states": {
            "implemented": "PASS",
            "non_live_tested": "PASS",
            "live_read_only_accepted": "NOT_RUN",
            "accepted_external_risk": "NOT_ACCEPTED",
            "actually_resolved": "OPEN",
            "blocked_source": "YES" if source_blockers else "NO",
        },
        "dependencies": dependencies,
        "portfolio_test_evidence": {
            "path": test_value,
            "sha256": _sha256_file(test_path),
        },
        "compatibility_test_evidence": {
            "path": compat_value,
            "sha256": _sha256_file(compat_path),
        },
        "portfolio_provider_count": provider_catalog["provider_count"],
        "combat_native_provider_count": provider_catalog["combat_native_provider_count"],
        "unresolved_blockers": unresolved,
        "source_blockers": source_blockers,
        "live_mutation_count": 0,
        "installation_performed": False,
        "production_targets_read": False,
    }


def _r7_release_plans(package_items: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    identities = [
        {"role": item["role"], "sha256": item["sha256"]}
        for item in sorted(package_items, key=lambda value: value["role"])
    ]
    migration = {
        "schema_version": "kcd2.r7-portfolio-migration-plan.v1",
        "task_id": "REL-607",
        "classification": "non_live",
        "execution_state": "PLANNED_NOT_RUN",
        "installation_authorized": False,
        "package_identities": identities,
        "required_gates": [
            "separate exact-target installation approval",
            "fresh conflict and variant-selection validation",
            "game closed and exact prior-state receipt",
        ],
    }
    rollback = {
        "schema_version": "kcd2.r7-portfolio-rollback-plan.v1",
        "task_id": "REL-607",
        "classification": "non_live",
        "execution_state": "PLANNED_NOT_RUN",
        "rollback_authorized": False,
        "exact_prior_bytes_required": True,
        "package_identities": identities,
        "required_gates": [
            "verified installation receipt",
            "exact target and catalog identity match",
            "separate rollback approval",
        ],
    }
    return migration, rollback


def _write_sha256sums(output: Path) -> None:
    lines = [
        f"{_sha256_file(path)}  {path.relative_to(output).as_posix()}"
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "SHA256SUMS"
    ]
    output.joinpath("SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _tree_sha256(output: Path) -> str:
    records = [
        {
            "path": path.relative_to(output).as_posix(),
            "size": path.stat().st_size,
            "sha256": _sha256_file(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    ]
    return _sha256_bytes(_json_bytes(records))


def _mandatory_task_state(repository: Path, task_id: str) -> dict[str, Any]:
    backlog = _load_object(repository / "KCD2_TOOLCHAIN_IMPLEMENTATION_BACKLOG_20260807_R7.json")
    tasks = {
        item.get("id"): item
        for item in backlog.get("tasks", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    root = tasks.get(task_id)
    if not isinstance(root, Mapping):
        raise ReleaseStagingError(f"release task is missing from backlog: {task_id}")
    pending = list(root.get("dependencies", []))
    visited: set[str] = set()
    records: list[dict[str, Any]] = []
    imprecise: list[str] = []
    while pending:
        dependency_id = pending.pop()
        if dependency_id in visited:
            continue
        dependency = tasks.get(dependency_id)
        if not isinstance(dependency, Mapping):
            raise ReleaseStagingError(f"mandatory dependency is missing: {dependency_id}")
        visited.add(dependency_id)
        status = dependency.get("status")
        reason = dependency.get("blocked_reason")
        precise = status == "done" or (
            status in {"blocked", "blocked_external"}
            and isinstance(reason, str)
            and bool(reason.strip())
        )
        if not precise:
            imprecise.append(dependency_id)
        records.append(
            {
                "task_id": dependency_id,
                "status": status,
                "blocked_reason": reason,
                "acceptance_state_precise": precise,
            }
        )
        pending.extend(dependency.get("dependencies", []))
    report = {
        "schema_version": "kcd2.mandatory-task-state.v1",
        "task_id": task_id,
        "scope": "recursive_dependency_closure",
        "tasks": sorted(records, key=lambda item: item["task_id"]),
        "imprecise_blockers": sorted(imprecise),
        "acceptance_passed": not imprecise,
    }
    if imprecise:
        raise ReleaseStagingError(
            f"mandatory tasks are neither done nor precisely blocked: {sorted(imprecise)}"
        )
    return report


def _integrated_component_lifecycle(
    work_root: Path,
    components: Iterable[tuple[str, Path, Any, Any, Any]],
) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for name, stage, install, restore, verify in components:
        synthetic = work_root / f"synthetic-{name}"
        active = synthetic / "plugins" / name
        active.mkdir(parents=True)
        active.joinpath("prior-marker.txt").write_bytes(b"synthetic-prior-state\r\n")
        catalog = synthetic / "catalog" / "plugins.json"
        catalog.parent.mkdir(parents=True)
        catalog.write_bytes(b'{"schema_version":"kcd2.plugin-catalog.v1","plugins":[]}')
        prior_tree = _snapshot(active)
        prior_catalog = catalog.read_bytes()
        receipt = install(
            stage,
            active_plugin_root=active,
            rollback_root=synthetic / "rollback",
            catalog_path=catalog,
            transaction_id=f"rel-601-{name}",
        )
        verification = verify(active, catalog)
        if str(verification.get("status", "")).lower() != "pass":
            raise ReleaseStagingError(f"synthetic component smoke failed: {name}")
        restored = restore(receipt.receipt_path)
        exact = _snapshot(active) == prior_tree and catalog.read_bytes() == prior_catalog
        if restored.get("status") != "restored" or not exact:
            raise ReleaseStagingError(f"synthetic component rollback failed: {name}")
        records.append(
            {
                "component": name,
                "install": "passed",
                "smoke": "passed",
                "rollback": "passed",
                "synthetic_fixture_only": True,
                "live_writes": False,
                "production_targets_read": False,
                "installed_tree_sha256": receipt.tree_sha256,
            }
        )
    return {
        "schema_version": "kcd2.integrated-component-lifecycle.v1",
        "task_id": "REL-601",
        "status": "pass",
        "components": sorted(records, key=lambda item: item["component"]),
    }


def _artifact_boundary_report(packages: Iterable[Path]) -> dict[str, Any]:
    forbidden_suffixes = {".dll", ".dmp", ".exe", ".pak", ".pdb", ".sav"}
    forbidden_prefixes = (
        "artifacts/codex-runs/",
        "mods/",
        "references/",
        "saves/",
    )
    forbidden: list[str] = []
    inspected = 0
    for package in packages:
        with zipfile.ZipFile(package) as archive:
            for member in archive.namelist():
                normalized = member.lower()
                inspected += 1
                if normalized.startswith(forbidden_prefixes) or any(
                    normalized.endswith(suffix) for suffix in forbidden_suffixes
                ):
                    forbidden.append(f"{package.name}:{member}")
    if forbidden:
        raise ReleaseStagingError(f"game/private artifacts entered release: {forbidden}")
    return {
        "schema_version": "kcd2.release-artifact-boundaries.v1",
        "task_id": "REL-601",
        "status": "pass",
        "archive_members_inspected": inspected,
        "forbidden_members": forbidden,
        "game_artifacts_included": False,
        "private_user_artifacts_included": False,
        "production_targets_read": False,
    }


def build_general_mod_remediation_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Build one complete release without reading or writing live KCD2 state."""
    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if profile.get("schema_version") != PROFILE_SCHEMA or profile.get("task_id") != "REL-603":
        raise ReleaseStagingError("unsupported release input profile")
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.joinpath("packages").mkdir(parents=True)
    work.mkdir(parents=True)

    adapter = profile["adapter"]
    runtime = profile["index_runtime_candidate"]
    adapter_path = output / "packages" / adapter["archive_name"]
    runtime_path = output / "packages" / runtime["archive_name"]
    adapter_hash = _build_source_archive(
        repository,
        adapter["inputs"],
        adapter_path,
        role="adapter",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    runtime_hash = _build_source_archive(
        repository,
        runtime["inputs"],
        runtime_path,
        role="index_runtime_candidate",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    deployer = profile["deployer"]
    deployer_path = output / "packages" / deployer["archive_name"]
    deployer_receipt = build_plugin_package(
        repository,
        stage_root=work / "deployer-stage",
        archive_path=deployer_path,
    )
    deployer_hash = deployer_receipt.package_sha256
    migration, rollback = _deployment_dry_runs(
        work, deployer_receipt.stage_root, deployer_hash
    )

    reports = output / "reports"
    changed_files = _changed_file_report(repository, profile, dependencies)
    _write_json(reports / "changed-files.json", changed_files)
    coverage_source = _repository_path(repository, profile["archetype_coverage_report"])
    coverage = _load_object(coverage_source)
    if coverage.get("status") != "pass" or not coverage.get("no_current_mod_id_required"):
        raise ReleaseStagingError("general archetype coverage is incomplete")
    _write_json(reports / "general-archetype-coverage.json", coverage)
    _write_json(reports / "migration-dry-run.json", migration)
    _write_json(reports / "rollback-dry-run.json", rollback)
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))
    boundaries = dict(profile["source_boundaries"])
    boundaries.update(
        {
            "schema_version": "kcd2.release-source-boundaries.v1",
            "task_id": profile["task_id"],
            "authoritative_source_state": "source_identified_not_reproducible",
        }
    )
    _write_json(reports / "source-boundaries.json", boundaries)

    package_items = [
        {
            "role": "adapter",
            "path": adapter_path.relative_to(output).as_posix(),
            "sha256": adapter_hash,
            "size": adapter_path.stat().st_size,
        },
        {
            "role": "deployer",
            "path": deployer_path.relative_to(output).as_posix(),
            "sha256": deployer_hash,
            "size": deployer_path.stat().st_size,
        },
        {
            "role": "index_runtime_candidate",
            "path": runtime_path.relative_to(output).as_posix(),
            "sha256": runtime_hash,
            "size": runtime_path.stat().st_size,
        },
    ]
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "task_id": profile["task_id"],
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "packages": package_items,
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def build_r4_general_mod_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Stage the non-live R3-plus-R4 adapter and direct-tool release."""
    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if (
        profile.get("schema_version") != R4_PROFILE_SCHEMA
        or profile.get("task_id") != "REL-604"
    ):
        raise ReleaseStagingError("unsupported R4 release input profile")
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.joinpath("packages").mkdir(parents=True)
    work.mkdir(parents=True)

    adapter = profile["adapter"]
    runtime = profile["index_runtime_candidate"]
    adapter_path = output / "packages" / adapter["archive_name"]
    runtime_path = output / "packages" / runtime["archive_name"]
    adapter_hash = _build_source_archive(
        repository,
        adapter["inputs"],
        adapter_path,
        role="adapter",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    runtime_hash = _build_source_archive(
        repository,
        runtime["inputs"],
        runtime_path,
        role="index_runtime_candidate",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )

    mod_config = profile["mod_build_deploy_plugin"]
    mod_path = output / "packages" / mod_config["archive_name"]
    mod_receipt = build_plugin_package(
        repository,
        stage_root=work / "mod-build-deploy-stage",
        archive_path=mod_path,
    )
    native_config = profile["native_probes_plugin"]
    native_path = output / "packages" / native_config["archive_name"]
    native_receipt = build_native_probes_package(
        repository,
        stage_root=work / "native-probes-stage",
        archive_path=native_path,
    )

    mod_migration, mod_rollback = _plugin_deployment_dry_runs(
        work,
        mod_receipt.stage_root,
        mod_receipt.package_sha256,
        task_id="REL-604",
        plugin_name="kcd2-mod-build-deploy",
        install=install_plugin_atomic,
        restore=restore_plugin_atomic,
        verify=verify_installed_catalog,
    )
    native_migration, native_rollback = _plugin_deployment_dry_runs(
        work,
        native_receipt.stage_root,
        native_receipt.package_sha256,
        task_id="REL-604",
        plugin_name="kcd2-native-probes",
        install=install_native_probes_atomic,
        restore=restore_native_probes_atomic,
        verify=verify_native_probes_catalog,
    )
    inventory, smoke_receipts = _r4_public_tool_reports(repository)

    reports = output / "reports"
    _write_json(
        reports / "changed-files.json",
        _changed_file_report(repository, profile, dependencies),
    )
    coverage_source = _repository_path(repository, profile["archetype_coverage_report"])
    coverage = _load_object(coverage_source)
    if coverage.get("status") != "pass" or not coverage.get("no_current_mod_id_required"):
        raise ReleaseStagingError("R3 general archetype coverage is incomplete")
    _write_json(reports / "general-archetype-coverage.json", coverage)
    _write_json(reports / "tool-registration-inventory.json", inventory)
    _write_json(reports / "public-surface-smoke-receipts.json", smoke_receipts)
    _write_json(
        reports / "coverage-negative-claim-contracts.json",
        _coverage_negative_claim_report(repository, profile),
    )
    dry_runs = {
        "kcd2-mod-build-deploy-migration-dry-run.json": mod_migration,
        "kcd2-mod-build-deploy-rollback-dry-run.json": mod_rollback,
        "kcd2-native-probes-migration-dry-run.json": native_migration,
        "kcd2-native-probes-rollback-dry-run.json": native_rollback,
    }
    for name, value in dry_runs.items():
        _write_json(reports / name, value)
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))
    boundaries = dict(profile["source_boundaries"])
    boundaries.update(
        {
            "schema_version": "kcd2.release-source-boundaries.v1",
            "task_id": "REL-604",
            "authoritative_source_state": (
                "completed_adapter_and_plugin_source_with_unproven_deployed_runtime"
            ),
        }
    )
    _write_json(reports / "source-boundaries.json", boundaries)

    package_items = [
        {
            "role": "adapter",
            "path": adapter_path.relative_to(output).as_posix(),
            "sha256": adapter_hash,
            "size": adapter_path.stat().st_size,
        },
        {
            "role": "index_runtime_candidate",
            "path": runtime_path.relative_to(output).as_posix(),
            "sha256": runtime_hash,
            "size": runtime_path.stat().st_size,
        },
        {
            "role": "mod_build_deploy_plugin",
            "path": mod_path.relative_to(output).as_posix(),
            "sha256": mod_receipt.package_sha256,
            "size": mod_path.stat().st_size,
        },
        {
            "role": "native_probes_plugin",
            "path": native_path.relative_to(output).as_posix(),
            "sha256": native_receipt.package_sha256,
            "size": native_path.stat().st_size,
        },
    ]
    manifest = {
        "schema_version": R4_MANIFEST_SCHEMA,
        "task_id": "REL-604",
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "packages": package_items,
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def build_r5_production_integration_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Stage the non-live R5 release and its production-acceptance dossier."""
    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if (
        profile.get("schema_version") != R5_PROFILE_SCHEMA
        or profile.get("task_id") != "REL-605"
        or profile.get("classification") != "non_live"
    ):
        raise ReleaseStagingError("unsupported R5 release input profile")
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.joinpath("packages").mkdir(parents=True)
    reports = output / "reports"
    reports.mkdir()
    work.mkdir(parents=True)

    adapter = profile.get("adapter")
    runtime = profile.get("index_runtime_candidate")
    if not isinstance(adapter, Mapping) or not isinstance(runtime, Mapping):
        raise ReleaseStagingError("R5 adapter or Index runtime package is missing")
    adapter_path = output / "packages" / str(adapter.get("archive_name", ""))
    runtime_path = output / "packages" / str(runtime.get("archive_name", ""))
    adapter_hash = _build_source_archive(
        repository,
        adapter.get("inputs", []),
        adapter_path,
        role="adapter",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    runtime_hash = _build_source_archive(
        repository,
        runtime.get("inputs", []),
        runtime_path,
        role="index_runtime_candidate",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )

    plugin_config = profile.get("plugins")
    if not isinstance(plugin_config, Mapping):
        raise ReleaseStagingError("R5 plugin package declarations are missing")
    builders = {
        "kcd2-mod-build-deploy": build_plugin_package,
        "kcd2-native-probes": build_native_probes_package,
        "kcd2-research-graph": build_research_graph_package,
    }
    installers = {
        "kcd2-mod-build-deploy": install_plugin_atomic,
        "kcd2-native-probes": install_native_probes_atomic,
        "kcd2-research-graph": install_research_graph_atomic,
    }
    restorers = {
        "kcd2-mod-build-deploy": restore_plugin_atomic,
        "kcd2-native-probes": restore_native_probes_atomic,
        "kcd2-research-graph": restore_research_graph_atomic,
    }
    verifiers = {
        "kcd2-mod-build-deploy": verify_installed_catalog,
        "kcd2-native-probes": verify_native_probes_catalog,
        "kcd2-research-graph": verify_research_graph_catalog,
    }
    roles = {
        "kcd2-mod-build-deploy": "mod_build_deploy_plugin",
        "kcd2-native-probes": "native_probes_plugin",
        "kcd2-research-graph": "research_graph_plugin",
    }
    built: dict[str, Any] = {}
    stages: dict[str, Path] = {}
    package_items = [
        {
            "role": "adapter",
            "path": adapter_path.relative_to(output).as_posix(),
            "sha256": adapter_hash,
            "size": adapter_path.stat().st_size,
        },
        {
            "role": "index_runtime_candidate",
            "path": runtime_path.relative_to(output).as_posix(),
            "sha256": runtime_hash,
            "size": runtime_path.stat().st_size,
        },
    ]
    for plugin_name in sorted(builders):
        config = plugin_config.get(plugin_name)
        if not isinstance(config, Mapping) or not isinstance(
            config.get("archive_name"), str
        ):
            raise ReleaseStagingError(f"R5 plugin declaration is invalid: {plugin_name}")
        archive = output / "packages" / config["archive_name"]
        receipt = builders[plugin_name](
            repository,
            stage_root=work / f"{plugin_name}-stage",
            archive_path=archive,
        )
        built[plugin_name] = receipt
        stages[plugin_name] = receipt.stage_root
        package_items.append(
            {
                "role": roles[plugin_name],
                "component": plugin_name,
                "path": archive.relative_to(output).as_posix(),
                "sha256": receipt.package_sha256,
                "size": archive.stat().st_size,
            }
        )

    for plugin_name in sorted(builders):
        receipt = built[plugin_name]
        migration, rollback = _plugin_deployment_dry_runs(
            work,
            receipt.stage_root,
            receipt.package_sha256,
            task_id="REL-605",
            plugin_name=plugin_name,
            install=installers[plugin_name],
            restore=restorers[plugin_name],
            verify=verifiers[plugin_name],
        )
        _write_json(reports / f"{plugin_name}-migration-dry-run.json", migration)
        _write_json(reports / f"{plugin_name}-rollback-dry-run.json", rollback)

    direct_catalog = _direct_tool_catalog(repository, profile, stages)
    dossier = _production_acceptance_dossier(repository, profile, dependencies)
    _write_json(reports / "direct-tool-catalog.json", direct_catalog)
    _write_json(reports / "production-acceptance-dossier.json", dossier)
    _write_json(
        reports / "changed-files.json",
        _changed_file_report(repository, profile, dependencies),
    )
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))
    boundaries = dict(profile["source_boundaries"])
    boundaries.update(
        {
            "schema_version": "kcd2.release-source-boundaries.v1",
            "task_id": "REL-605",
            "authoritative_source_state": (
                "source_auditable_staged_candidates_with_live_acceptance_not_run"
            ),
        }
    )
    _write_json(reports / "source-boundaries.json", boundaries)
    closure_path = _repository_path(repository, str(profile["critique_closure"]))
    current_state_path = _repository_path(repository, str(profile["current_state"]))
    reports.joinpath("critique-closure.json").write_bytes(closure_path.read_bytes())
    reports.joinpath("CURRENT_STATE.md").write_bytes(current_state_path.read_bytes())

    manifest = {
        "schema_version": R5_MANIFEST_SCHEMA,
        "task_id": "REL-605",
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "packages": sorted(package_items, key=lambda item: item["role"]),
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "release_states": dossier["release_states"],
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def build_r6_orchestrated_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Stage the source-auditable, non-live REL-606 release."""

    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if (
        profile.get("schema_version") != R6_PROFILE_SCHEMA
        or profile.get("task_id") != "REL-606"
        or profile.get("classification") != "non_live"
    ):
        raise ReleaseStagingError("unsupported R6 release input profile")
    base_value = profile.get("base_release_profile")
    if not isinstance(base_value, str):
        raise ReleaseStagingError("R6 base release profile is missing")
    base_profile = _load_object(_repository_path(repository, base_value))
    if base_profile.get("schema_version") != R5_PROFILE_SCHEMA:
        raise ReleaseStagingError("R6 base release profile is not the reviewed R5 profile")
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.joinpath("packages").mkdir(parents=True)
    reports = output / "reports"
    reports.mkdir()
    work.mkdir(parents=True)

    package_names = profile.get("package_names")
    if not isinstance(package_names, Mapping):
        raise ReleaseStagingError("R6 package names are missing")
    adapter = base_profile.get("adapter")
    runtime = base_profile.get("index_runtime_candidate")
    if not isinstance(adapter, Mapping) or not isinstance(runtime, Mapping):
        raise ReleaseStagingError("R6 base adapter or Index runtime declaration is missing")
    adapter_path = output / "packages" / str(package_names.get("adapter", ""))
    runtime_path = output / "packages" / str(
        package_names.get("index_runtime_candidate", "")
    )
    adapter_hash = _build_source_archive(
        repository,
        adapter.get("inputs", []),
        adapter_path,
        role="adapter",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    runtime_hash = _build_source_archive(
        repository,
        runtime.get("inputs", []),
        runtime_path,
        role="index_runtime_candidate",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )

    builders = {
        "kcd2-mod-build-deploy": build_plugin_package,
        "kcd2-native-probes": build_native_probes_package,
        "kcd2-research-graph": build_research_graph_package,
    }
    installers = {
        "kcd2-mod-build-deploy": install_plugin_atomic,
        "kcd2-native-probes": install_native_probes_atomic,
        "kcd2-research-graph": install_research_graph_atomic,
    }
    restorers = {
        "kcd2-mod-build-deploy": restore_plugin_atomic,
        "kcd2-native-probes": restore_native_probes_atomic,
        "kcd2-research-graph": restore_research_graph_atomic,
    }
    verifiers = {
        "kcd2-mod-build-deploy": verify_installed_catalog,
        "kcd2-native-probes": verify_native_probes_catalog,
        "kcd2-research-graph": verify_research_graph_catalog,
    }
    roles = {
        "kcd2-mod-build-deploy": "mod_build_deploy_plugin",
        "kcd2-native-probes": "native_probes_plugin",
        "kcd2-research-graph": "research_graph_plugin",
    }
    stages: dict[str, Path] = {}
    package_items = [
        {
            "role": "adapter",
            "path": adapter_path.relative_to(output).as_posix(),
            "sha256": adapter_hash,
            "size": adapter_path.stat().st_size,
        },
        {
            "role": "index_runtime_candidate",
            "path": runtime_path.relative_to(output).as_posix(),
            "sha256": runtime_hash,
            "size": runtime_path.stat().st_size,
        },
    ]
    for plugin_name in sorted(builders):
        archive_name = package_names.get(plugin_name)
        if not isinstance(archive_name, str) or not archive_name:
            raise ReleaseStagingError(f"R6 package name is missing: {plugin_name}")
        archive = output / "packages" / archive_name
        receipt = builders[plugin_name](
            repository,
            stage_root=work / f"{plugin_name}-stage",
            archive_path=archive,
        )
        stages[plugin_name] = receipt.stage_root
        package_items.append(
            {
                "role": roles[plugin_name],
                "component": plugin_name,
                "path": archive.relative_to(output).as_posix(),
                "sha256": receipt.package_sha256,
                "size": archive.stat().st_size,
            }
        )
        migration, rollback = _plugin_deployment_dry_runs(
            work,
            receipt.stage_root,
            receipt.package_sha256,
            task_id="REL-606",
            plugin_name=plugin_name,
            install=installers[plugin_name],
            restore=restorers[plugin_name],
            verify=verifiers[plugin_name],
        )
        _write_json(reports / f"{plugin_name}-migration-dry-run.json", migration)
        _write_json(reports / f"{plugin_name}-rollback-dry-run.json", rollback)

    orchestrator = profile.get("workflow_orchestrator")
    if not isinstance(orchestrator, Mapping):
        raise ReleaseStagingError("R6 orchestrator package declaration is missing")
    orchestrator_archive = output / "packages" / str(orchestrator.get("archive_name", ""))
    orchestrator_hash = _build_source_archive(
        repository,
        orchestrator.get("inputs", []),
        orchestrator_archive,
        role="workflow_orchestrator_plugin",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    orchestrator_stage = work / "kcd2-workflow-orchestrator-stage"
    _extract_source_archive(orchestrator_archive, orchestrator_stage)
    launcher = orchestrator.get("launcher")
    if not isinstance(launcher, str):
        raise ReleaseStagingError("R6 orchestrator launcher is missing")
    migration, rollback = _orchestrator_deployment_dry_runs(
        work,
        orchestrator_stage,
        orchestrator_hash,
        launcher,
    )
    _write_json(
        reports / "kcd2-workflow-orchestrator-migration-dry-run.json",
        migration,
    )
    _write_json(
        reports / "kcd2-workflow-orchestrator-rollback-dry-run.json",
        rollback,
    )
    package_items.append(
        {
            "role": "workflow_orchestrator_plugin",
            "component": "kcd2-workflow-orchestrator",
            "path": orchestrator_archive.relative_to(output).as_posix(),
            "sha256": orchestrator_hash,
            "size": orchestrator_archive.stat().st_size,
        }
    )

    catalog = _r6_direct_tool_catalog(
        repository,
        profile,
        base_profile,
        stages,
        orchestrator_stage,
        launcher,
    )
    dossier = _r6_acceptance_dossier(repository, profile, dependencies)
    unresolved = _r6_unresolved_channels(repository, profile)
    _write_json(reports / "direct-tool-catalog.json", catalog)
    _write_json(reports / "production-acceptance-dossier.json", dossier)
    _write_json(reports / "unresolved-channels.json", unresolved)
    _write_json(
        reports / "changed-files.json",
        _changed_file_report(repository, profile, dependencies),
    )
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))
    boundaries = dict(profile["source_boundaries"])
    boundaries.update(
        {
            "schema_version": "kcd2.release-source-boundaries.v1",
            "task_id": "REL-606",
            "authoritative_source_state": (
                "source_auditable_r6_with_live_acceptance_not_run_and_passive_input_unavailable"
            ),
        }
    )
    _write_json(reports / "source-boundaries.json", boundaries)

    copied_reports = {
        "r6-synthetic-acceptance-receipt.json": profile["live_readonly_receipt"],
        "r6-zero-mutation-audit.json": profile["zero_mutation_audit"],
        "r6-tool-catalog-receipt.json": profile["tool_catalog_receipt"],
        "passive-input-capability.json": profile["passive_input_capability"],
        "r6-orchestrated-release-v1.schema.json": profile["r6_manifest_schema"],
    }
    for target_name, source_value in copied_reports.items():
        source = _repository_path(repository, str(source_value))
        reports.joinpath(target_name).write_bytes(source.read_bytes())

    manifest = {
        "$schema": R6_SCHEMA_ID,
        "schema_version": R6_MANIFEST_SCHEMA,
        "task_id": "REL-606",
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "packages": sorted(package_items, key=lambda item: item["role"]),
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "release_states": dossier["release_states"],
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def build_r7_portfolio_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Stage the source-auditable, non-live REL-607 portfolio release."""

    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if (
        profile.get("schema_version") != R7_PROFILE_SCHEMA
        or profile.get("task_id") != "REL-607"
        or profile.get("classification") != "non_live"
    ):
        raise ReleaseStagingError("unsupported R7 release input profile")
    base_value = profile.get("base_release_profile")
    if not isinstance(base_value, str):
        raise ReleaseStagingError("R7 base release profile is missing")
    base_profile_path = _repository_path(repository, base_value)
    base_profile = _load_object(base_profile_path)
    if base_profile.get("schema_version") != R6_PROFILE_SCHEMA:
        raise ReleaseStagingError("R7 base release profile is not the reviewed R6 profile")
    r5_value = base_profile.get("base_release_profile")
    if not isinstance(r5_value, str):
        raise ReleaseStagingError("R7 base profile does not identify the reviewed R5 profile")
    r5_profile = _load_object(_repository_path(repository, r5_value))
    if r5_profile.get("schema_version") != R5_PROFILE_SCHEMA:
        raise ReleaseStagingError("R7 package lineage does not reach the reviewed R5 profile")

    build_r6_orchestrated_release(
        repository,
        base_profile_path,
        output_root=output,
        work_root=work,
    )
    r6_manifest = _load_object(output / "release-manifest.json")
    r6_packages = {item["role"]: item for item in r6_manifest.get("packages", [])}
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    package_names = profile.get("package_names")
    if not isinstance(package_names, Mapping):
        raise ReleaseStagingError("R7 package names are missing")

    role_by_plugin = {
        "kcd2-mod-build-deploy": "mod_build_deploy_plugin",
        "kcd2-native-probes": "native_probes_plugin",
        "kcd2-research-graph": "research_graph_plugin",
    }
    package_items: list[dict[str, Any]] = []
    for plugin_name, role in sorted(role_by_plugin.items()):
        archive_name = package_names.get(plugin_name)
        prior = r6_packages.get(role)
        if not isinstance(archive_name, str) or not isinstance(prior, Mapping):
            raise ReleaseStagingError(f"R7 package lineage is missing: {plugin_name}")
        prior_path = output / str(prior["path"])
        archive = output / "packages" / archive_name
        prior_path.replace(archive)
        package_items.append(
            {
                "role": role,
                "component": plugin_name,
                "path": archive.relative_to(output).as_posix(),
                "sha256": _sha256_file(archive),
                "size": archive.stat().st_size,
            }
        )

    adapter = r5_profile.get("adapter")
    runtime = r5_profile.get("index_runtime_candidate")
    if not isinstance(adapter, Mapping) or not isinstance(runtime, Mapping):
        raise ReleaseStagingError("R7 base adapter or Index runtime declaration is missing")
    for role, config in (
        ("adapter", adapter),
        ("index_runtime_candidate", runtime),
    ):
        prior = r6_packages.get(role)
        archive_name = package_names.get(role)
        if not isinstance(prior, Mapping) or not isinstance(archive_name, str):
            raise ReleaseStagingError(f"R7 source package declaration is missing: {role}")
        (output / str(prior["path"])).unlink()
        archive = output / "packages" / archive_name
        digest = _build_source_archive(
            repository,
            config.get("inputs", []),
            archive,
            role=role,
            profile_sha256=profile_sha256,
            source_identity=source_identity,
        )
        package_items.append(
            {
                "role": role,
                "path": archive.relative_to(output).as_posix(),
                "sha256": digest,
                "size": archive.stat().st_size,
            }
        )

    orchestrator = profile.get("workflow_orchestrator")
    prior_orchestrator = r6_packages.get("workflow_orchestrator_plugin")
    if not isinstance(orchestrator, Mapping) or not isinstance(prior_orchestrator, Mapping):
        raise ReleaseStagingError("R7 orchestrator package declaration is missing")
    (output / str(prior_orchestrator["path"])).unlink()
    orchestrator_archive = output / "packages" / str(orchestrator.get("archive_name", ""))
    orchestrator_hash = _build_source_archive(
        repository,
        orchestrator.get("inputs", []),
        orchestrator_archive,
        role="workflow_orchestrator_plugin",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    launcher = orchestrator.get("launcher")
    if not isinstance(launcher, str):
        raise ReleaseStagingError("R7 orchestrator launcher is missing")
    orchestrator_stage = work / "kcd2-workflow-orchestrator-stage"
    _extract_source_archive(orchestrator_archive, orchestrator_stage)
    package_items.append(
        {
            "role": "workflow_orchestrator_plugin",
            "component": "kcd2-workflow-orchestrator",
            "path": orchestrator_archive.relative_to(output).as_posix(),
            "sha256": orchestrator_hash,
            "size": orchestrator_archive.stat().st_size,
        }
    )

    bundle = profile.get("portfolio_contracts_bundle")
    if not isinstance(bundle, Mapping):
        raise ReleaseStagingError("R7 portfolio contracts bundle is missing")
    bundle_archive = output / "packages" / str(bundle.get("archive_name", ""))
    bundle_hash = _build_source_archive(
        repository,
        bundle.get("inputs", []),
        bundle_archive,
        role="portfolio_contracts_bundle",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    package_items.append(
        {
            "role": "portfolio_contracts_bundle",
            "component": "kcd2-portfolio-contracts",
            "path": bundle_archive.relative_to(output).as_posix(),
            "sha256": bundle_hash,
            "size": bundle_archive.stat().st_size,
        }
    )

    reports = output / "reports"
    shutil.rmtree(reports)
    reports.mkdir()
    installers = {
        "kcd2-mod-build-deploy": install_plugin_atomic,
        "kcd2-native-probes": install_native_probes_atomic,
        "kcd2-research-graph": install_research_graph_atomic,
    }
    restorers = {
        "kcd2-mod-build-deploy": restore_plugin_atomic,
        "kcd2-native-probes": restore_native_probes_atomic,
        "kcd2-research-graph": restore_research_graph_atomic,
    }
    verifiers = {
        "kcd2-mod-build-deploy": verify_installed_catalog,
        "kcd2-native-probes": verify_native_probes_catalog,
        "kcd2-research-graph": verify_research_graph_catalog,
    }
    stages = {
        plugin_name: work / f"{plugin_name}-stage" for plugin_name in role_by_plugin
    }
    items_by_role = {item["role"]: item for item in package_items}
    for plugin_name, role in sorted(role_by_plugin.items()):
        synthetic = work / f"synthetic-{plugin_name}"
        if synthetic.exists():
            shutil.rmtree(synthetic)
        migration, rollback = _plugin_deployment_dry_runs(
            work,
            stages[plugin_name],
            items_by_role[role]["sha256"],
            task_id="REL-607",
            plugin_name=plugin_name,
            install=installers[plugin_name],
            restore=restorers[plugin_name],
            verify=verifiers[plugin_name],
        )
        _write_json(reports / f"{plugin_name}-migration-dry-run.json", migration)
        _write_json(reports / f"{plugin_name}-rollback-dry-run.json", rollback)
    synthetic_orchestrator = work / "synthetic-kcd2-workflow-orchestrator"
    if synthetic_orchestrator.exists():
        shutil.rmtree(synthetic_orchestrator)
    migration, rollback = _orchestrator_deployment_dry_runs(
        work,
        orchestrator_stage,
        orchestrator_hash,
        launcher,
    )
    migration["task_id"] = "REL-607"
    rollback["task_id"] = "REL-607"
    _write_json(reports / "kcd2-workflow-orchestrator-migration-dry-run.json", migration)
    _write_json(reports / "kcd2-workflow-orchestrator-rollback-dry-run.json", rollback)

    direct_catalog = _r6_direct_tool_catalog(
        repository,
        profile,
        r5_profile,
        stages,
        orchestrator_stage,
        launcher,
    )
    direct_catalog["schema_version"] = "kcd2.r7-direct-tool-catalog.v1"
    direct_catalog["task_id"] = "REL-607"
    provider_catalog = _r7_portfolio_provider_catalog(repository, profile)
    dossier = _r7_acceptance_dossier(
        repository,
        profile,
        dependencies,
        provider_catalog,
    )
    migration_plan, rollback_plan = _r7_release_plans(package_items)
    _write_json(reports / "direct-tool-catalog.json", direct_catalog)
    _write_json(reports / "portfolio-provider-catalog.json", provider_catalog)
    _write_json(reports / "acceptance-dossier.json", dossier)
    _write_json(
        reports / "changed-files.json",
        _changed_file_report(repository, profile, dependencies),
    )
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))
    _write_json(reports / "portfolio-migration-plan.json", migration_plan)
    _write_json(reports / "portfolio-rollback-plan.json", rollback_plan)
    boundaries = dict(profile["source_boundaries"])
    boundaries.update(
        {
            "schema_version": "kcd2.release-source-boundaries.v1",
            "task_id": "REL-607",
            "authoritative_source_state": (
                "source_auditable_r7_with_installed_provider_visibility_not_run"
            ),
        }
    )
    _write_json(reports / "source-boundaries.json", boundaries)
    copied_reports = {
        "r7-portfolio-release-v1.schema.json": profile["r7_manifest_schema"],
        "r7-portfolio-provider-catalog-v1.schema.json": profile[
            "provider_catalog_schema"
        ],
        "r7-synthetic-test-report.json": profile["portfolio_test_report"],
    }
    for target_name, source_value in copied_reports.items():
        source = _repository_path(repository, str(source_value))
        reports.joinpath(target_name).write_bytes(source.read_bytes())

    manifest = {
        "$schema": R7_SCHEMA_ID,
        "schema_version": R7_MANIFEST_SCHEMA,
        "task_id": "REL-607",
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "packages": sorted(package_items, key=lambda item: item["role"]),
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "release_states": dossier["release_states"],
        "portfolio_provider_count": provider_catalog["provider_count"],
        "combat_native_provider_count": provider_catalog["combat_native_provider_count"],
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def build_integrated_private_release(
    repository_root: Path | str,
    profile_path: Path | str,
    *,
    output_root: Path | str,
    work_root: Path | str,
) -> ReleaseBuildReceipt:
    """Build the complete non-live REL-601 private release."""
    repository = Path(repository_root).resolve()
    profile_file = Path(profile_path).resolve()
    output = Path(output_root).resolve()
    work = Path(work_root).resolve()
    if output == repository or _is_relative_to(repository, output):
        raise ReleaseStagingError("release output cannot replace the repository")
    if _is_relative_to(work, repository):
        raise ReleaseStagingError("release work root must be outside the repository")
    profile = _load_object(profile_file)
    if (
        profile.get("schema_version") != INTEGRATED_PROFILE_SCHEMA
        or profile.get("task_id") != "REL-601"
        or profile.get("classification") != "non_live"
    ):
        raise ReleaseStagingError("unsupported integrated release input profile")
    profile_sha256 = _sha256_file(profile_file)
    source_identity = _source_identity(repository)
    dependencies = _validate_dependencies(repository, profile)
    mandatory = _mandatory_task_state(repository, "REL-601")
    if output.exists():
        shutil.rmtree(output)
    if work.exists():
        shutil.rmtree(work)
    output.joinpath("packages").mkdir(parents=True)
    reports = output / "reports"
    reports.mkdir()
    work.mkdir(parents=True)

    package_config = profile.get("packages")
    if not isinstance(package_config, Mapping):
        raise ReleaseStagingError("integrated package configuration is missing")
    expected_components = {
        "kcd2-mod-build-deploy",
        "kcd2-native-probes",
        "kcd2-research-graph",
    }
    if set(package_config) != expected_components:
        raise ReleaseStagingError("integrated release components disagree with metadata")
    builders = {
        "kcd2-mod-build-deploy": build_plugin_package,
        "kcd2-native-probes": build_native_probes_package,
        "kcd2-research-graph": build_research_graph_package,
    }
    role_by_component = {
        "kcd2-mod-build-deploy": "mod_build_deploy_plugin",
        "kcd2-native-probes": "native_probes_plugin",
        "kcd2-research-graph": "research_graph_plugin",
    }
    built: dict[str, Any] = {}
    package_items: list[dict[str, Any]] = []
    for component in sorted(expected_components):
        config = package_config[component]
        if not isinstance(config, Mapping) or not isinstance(config.get("archive_name"), str):
            raise ReleaseStagingError(f"integrated package declaration is invalid: {component}")
        archive = output / "packages" / config["archive_name"]
        receipt = builders[component](
            repository,
            stage_root=work / f"{component}-stage",
            archive_path=archive,
        )
        built[component] = receipt
        package_items.append(
            {
                "role": role_by_component[component],
                "component": component,
                "path": archive.relative_to(output).as_posix(),
                "sha256": receipt.package_sha256,
                "size": archive.stat().st_size,
            }
        )

    bundle_config = profile.get("contract_bundle")
    if not isinstance(bundle_config, Mapping):
        raise ReleaseStagingError("contract bundle declaration is missing")
    bundle = output / "packages" / str(bundle_config.get("archive_name", ""))
    bundle_hash = _build_source_archive(
        repository,
        bundle_config.get("inputs", []),
        bundle,
        role="contract_bundle",
        profile_sha256=profile_sha256,
        source_identity=source_identity,
    )
    package_items.append(
        {
            "role": "contract_bundle",
            "component": "kcd2-toolchain-contracts",
            "path": bundle.relative_to(output).as_posix(),
            "sha256": bundle_hash,
            "size": bundle.stat().st_size,
        }
    )

    lifecycle = _integrated_component_lifecycle(
        work,
        (
            (
                "kcd2-mod-build-deploy",
                built["kcd2-mod-build-deploy"].stage_root,
                install_plugin_atomic,
                restore_plugin_atomic,
                verify_installed_catalog,
            ),
            (
                "kcd2-native-probes",
                built["kcd2-native-probes"].stage_root,
                install_native_probes_atomic,
                restore_native_probes_atomic,
                verify_native_probes_catalog,
            ),
            (
                "kcd2-research-graph",
                built["kcd2-research-graph"].stage_root,
                install_research_graph_atomic,
                restore_research_graph_atomic,
                verify_research_graph_catalog,
            ),
        ),
    )
    migration = _repository_path(repository, profile["migration_guide"])
    closure = _repository_path(repository, profile["critique_closure"])
    output.joinpath("MIGRATION.md").write_bytes(migration.read_bytes())
    reports.joinpath("critique-closure.json").write_bytes(closure.read_bytes())
    _write_json(reports / "mandatory-task-state.json", mandatory)
    _write_json(reports / "component-lifecycle.json", lifecycle)
    _write_json(
        reports / "artifact-boundaries.json",
        _artifact_boundary_report(output / item["path"] for item in package_items),
    )
    _write_json(reports / "test-receipts.json", _test_receipts(repository, profile))

    manifest = {
        "$schema": INTEGRATED_SCHEMA_ID,
        "schema_version": INTEGRATED_MANIFEST_SCHEMA,
        "task_id": "REL-601",
        "release_id": profile["release_id"],
        "classification": "non_live",
        "source": source_identity,
        "release_profile_sha256": profile_sha256,
        "dependencies": dependencies,
        "mandatory_task_acceptance": "passed",
        "packages": sorted(package_items, key=lambda item: item["role"]),
        "reports": sorted(path.relative_to(output).as_posix() for path in reports.iterdir()),
        "migration_guide": "MIGRATION.md",
        "installation_performed": False,
        "production_index_written": False,
        "game_or_plugin_targets_read": False,
    }
    _write_json(output / "release-manifest.json", manifest)
    _write_sha256sums(output)
    validate_staged_release(output)
    hashes = {item["role"]: item["sha256"] for item in package_items}
    return ReleaseBuildReceipt(output, _tree_sha256(output), hashes)


def validate_staged_release(root: Path | str) -> dict[str, Any]:
    """Validate checksums, membership, package identities, and non-live declarations."""
    output = Path(root).resolve()
    manifest = _load_object(output / "release-manifest.json")
    if manifest.get("schema_version") not in {
        MANIFEST_SCHEMA,
        R4_MANIFEST_SCHEMA,
        R5_MANIFEST_SCHEMA,
        R6_MANIFEST_SCHEMA,
        R7_MANIFEST_SCHEMA,
        INTEGRATED_MANIFEST_SCHEMA,
    }:
        raise ReleaseStagingError("release manifest schema is invalid")
    if (
        manifest.get("schema_version") == INTEGRATED_MANIFEST_SCHEMA
        and manifest.get("$schema") != INTEGRATED_SCHEMA_ID
    ):
        raise ReleaseStagingError("integrated release schema identity is invalid")
    if (
        manifest.get("schema_version") == R6_MANIFEST_SCHEMA
        and manifest.get("$schema") != R6_SCHEMA_ID
    ):
        raise ReleaseStagingError("R6 release schema identity is invalid")
    if (
        manifest.get("schema_version") == R7_MANIFEST_SCHEMA
        and manifest.get("$schema") != R7_SCHEMA_ID
    ):
        raise ReleaseStagingError("R7 release schema identity is invalid")
    if (
        manifest.get("classification") != "non_live"
        or manifest.get("installation_performed") is not False
    ):
        raise ReleaseStagingError("release manifest does not prove non-live staging")
    expected: dict[str, str] = {}
    for line in output.joinpath("SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, separator, relative = line.partition("  ")
        if separator != "  " or len(digest) != 64 or relative in expected:
            raise ReleaseStagingError("invalid SHA256SUMS entry")
        expected[relative] = digest
    actual = {
        path.relative_to(output).as_posix(): _sha256_file(path)
        for path in output.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    }
    if expected != actual:
        raise ReleaseStagingError("release checksum membership or hashes disagree")
    for item in manifest.get("packages", []):
        path = output / item["path"]
        if not path.is_file() or _sha256_file(path) != item.get("sha256"):
            raise ReleaseStagingError(f"staged package identity disagrees: {item.get('role')}")
    return manifest
