"""Deterministic packaging and atomic, receipt-backed native-probes deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import uuid
import zipfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from kcd2_toolchain_core.release_metadata import (
    ReleaseMetadataError,
    check_repository_release,
    packaging_source_provenance,
)


CONTRACT = "kcd2.native-probes-plugin-deployment.v1"
CATALOG_SCHEMA = "kcd2.plugin-catalog.v1"
PLUGIN_NAME = "kcd2-native-probes"
MANIFEST_NAME = "deployment-manifest.json"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_PAYLOAD_FILES = 4096
MAX_PAYLOAD_BYTES = 128 * 1024 * 1024
_DEBRIS_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "dist",
}
_DEBRIS_SUFFIXES = (".pyc", ".pyo")


class PluginDeploymentError(RuntimeError):
    """Raised when a package or deployment fails closed."""


class FailurePoint(str, Enum):
    AFTER_BACKUP = "after_backup"
    AFTER_INCOMING_COPY = "after_incoming_copy"
    AFTER_ACTIVE_DISPLACEMENT = "after_active_displacement"
    AFTER_PLUGIN_SWAP = "after_plugin_swap"
    AFTER_CATALOG_REFRESH = "after_catalog_refresh"
    AFTER_SMOKE_TEST = "after_smoke_test"


@dataclass(frozen=True)
class PackageBuildReceipt:
    stage_root: Path
    archive_path: Path
    tree_sha256: str
    package_sha256: str
    manifest_sha256: str


@dataclass(frozen=True)
class InstallReceipt:
    receipt_path: Path
    receipt_sha256: str
    active_plugin_root: Path
    catalog_path: Path
    rollback_unit: Path
    tree_sha256: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            raise PluginDeploymentError(f"JSON input exceeds {MAX_MANIFEST_BYTES} bytes")
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PluginDeploymentError(f"invalid JSON document: {path}") from exc
    if not isinstance(value, dict):
        raise PluginDeploymentError(f"JSON root must be an object: {path}")
    return value


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PluginDeploymentError("manifest paths must be non-empty POSIX paths")
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise PluginDeploymentError(f"unsafe manifest path: {value!r}")
    return relative


def _resolve_child(root: Path, relative: str) -> Path:
    clean = _safe_relative(relative)
    candidate = root.joinpath(*clean.parts).resolve()
    prefix = str(root.resolve()).rstrip("\\/") + os.sep
    if not str(candidate).startswith(prefix):
        raise PluginDeploymentError(f"path escapes root: {relative!r}")
    return candidate


def find_debris(root: Path | str) -> tuple[str, ...]:
    """Return forbidden cache/build entries without following symlinks."""
    base = Path(root)
    if not base.exists():
        return ()
    found: list[str] = []
    for path in sorted(base.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(base).as_posix()
        if path.name in _DEBRIS_NAMES or path.name.lower().endswith(_DEBRIS_SUFFIXES):
            found.append(relative)
    return tuple(found)


def _is_debris_relative(path: Path) -> bool:
    return any(part in _DEBRIS_NAMES for part in path.parts) or path.name.lower().endswith(
        _DEBRIS_SUFFIXES
    )


def _clean_destination(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise PluginDeploymentError(f"destination must be a directory path: {path}")
        shutil.rmtree(path)
    path.mkdir(parents=True)


def _copy_mapping(repository_root: Path, stage_root: Path, mapping: Mapping[str, Any]) -> None:
    source_value = mapping.get("source")
    target_value = mapping.get("target")
    if not isinstance(source_value, str) or not isinstance(target_value, str):
        raise PluginDeploymentError("source mappings require source and target paths")
    source = _resolve_child(repository_root, source_value)
    target = _resolve_child(stage_root, target_value)
    if source.is_symlink():
        raise PluginDeploymentError(f"package source cannot be a symlink: {source_value}")
    if source.is_file():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        return
    if not source.is_dir():
        raise PluginDeploymentError(f"package source is unavailable: {source_value}")
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(source)
        if _is_debris_relative(relative):
            continue
        destination = target / relative
        if path.is_symlink():
            raise PluginDeploymentError(
                f"package source cannot contain symlinks: {source_value}/{relative.as_posix()}"
            )
        if path.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)


def _file_records(root: Path, *, exclude_manifest: bool) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise PluginDeploymentError(f"package tree contains a symlink: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if exclude_manifest and relative == MANIFEST_NAME:
            continue
        size = path.stat().st_size
        total_bytes += size
        records.append({"path": relative, "size": size, "sha256": _sha256_file(path)})
    if len(records) > MAX_PAYLOAD_FILES:
        raise PluginDeploymentError(f"package exceeds {MAX_PAYLOAD_FILES} files")
    if total_bytes > MAX_PAYLOAD_BYTES:
        raise PluginDeploymentError(f"package exceeds {MAX_PAYLOAD_BYTES} bytes")
    return records


def _tree_sha256(records: Sequence[Mapping[str, Any]]) -> str:
    normalized = [
        {"path": item["path"], "size": item["size"], "sha256": item["sha256"]}
        for item in records
    ]
    return _sha256_bytes(_canonical_json_bytes(normalized))


def _manifest_catalog(
    stage_root: Path, recipe_catalog: Mapping[str, Any]
) -> dict[str, Any]:
    skill_values = recipe_catalog.get("skills")
    tool_values = recipe_catalog.get("tools")
    if not isinstance(skill_values, list) or not isinstance(tool_values, list):
        raise PluginDeploymentError("deployment recipe requires skill and tool catalogs")
    skills: list[dict[str, str]] = []
    for value in skill_values:
        if not isinstance(value, Mapping):
            raise PluginDeploymentError("skill catalog entries must be objects")
        name = value.get("name")
        path_value = value.get("path")
        if not isinstance(name, str) or not isinstance(path_value, str):
            raise PluginDeploymentError("skill catalog entries require name and path")
        path = _resolve_child(stage_root, path_value)
        if not path.is_file():
            raise PluginDeploymentError(f"cataloged skill is unavailable: {path_value}")
        skills.append({"name": name, "path": path_value, "sha256": _sha256_file(path)})
    tools = sorted({value for value in tool_values if isinstance(value, str)})
    if len(tools) != len(tool_values):
        raise PluginDeploymentError("tool catalog must contain unique string names")
    return {"skills": sorted(skills, key=lambda item: item["name"]), "tools": tools}


def _validate_recipe(recipe: Mapping[str, Any]) -> tuple[str, list[Mapping[str, Any]]]:
    if recipe.get("contract") != CONTRACT or recipe.get("schema_version") != "1.0":
        raise PluginDeploymentError("native-probes deployment recipe contract is invalid")
    plugin = recipe.get("plugin")
    mappings = recipe.get("source_mappings")
    if not isinstance(plugin, Mapping) or plugin.get("name") != PLUGIN_NAME:
        raise PluginDeploymentError("deployment recipe plugin identity is invalid")
    version = plugin.get("version")
    if not isinstance(version, str) or not version:
        raise PluginDeploymentError("deployment recipe plugin version is invalid")
    if not isinstance(mappings, list) or not mappings:
        raise PluginDeploymentError("deployment recipe source mappings are missing")
    return version, mappings


def _validate_plugin_metadata(stage_root: Path, version: str) -> None:
    plugin_json = _read_json_object(stage_root / ".codex-plugin" / "plugin.json")
    if plugin_json.get("name") != PLUGIN_NAME or plugin_json.get("version") != version:
        raise PluginDeploymentError("plugin manifest name/version disagrees with deployment recipe")


def _write_deterministic_zip(stage_root: Path, archive_path: Path) -> None:
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = archive_path.with_name(f".{archive_path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in sorted(stage_root.rglob("*"), key=lambda item: item.as_posix()):
                if not path.is_file():
                    continue
                relative = path.relative_to(stage_root).as_posix()
                info = zipfile.ZipInfo(relative, FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
        os.replace(temporary, archive_path)
    finally:
        if temporary.exists():
            temporary.unlink()


def build_plugin_package(
    repository_root: Path | str,
    *,
    stage_root: Path | str,
    archive_path: Path | str,
) -> PackageBuildReceipt:
    """Build one self-contained, byte-reproducible plugin package."""
    repository = Path(repository_root).resolve()
    stage = Path(stage_root).resolve()
    archive = Path(archive_path).resolve()
    recipe_path = repository / "plugins" / PLUGIN_NAME / MANIFEST_NAME
    try:
        check_repository_release(repository, component_name=PLUGIN_NAME)
    except ReleaseMetadataError as exc:
        raise PluginDeploymentError(f"release metadata gate failed: {exc}") from exc
    recipe = _read_json_object(recipe_path)
    version, mappings = _validate_recipe(recipe)
    debris = find_debris(repository / "plugins" / PLUGIN_NAME)
    if debris:
        raise PluginDeploymentError(f"plugin source contains debris: {', '.join(debris)}")
    _clean_destination(stage)
    for mapping in mappings:
        _copy_mapping(repository, stage, mapping)
    debris = find_debris(stage)
    if debris:
        raise PluginDeploymentError(f"staged plugin contains debris: {', '.join(debris)}")
    _validate_plugin_metadata(stage, version)
    catalog_value = recipe.get("catalog")
    if not isinstance(catalog_value, Mapping):
        raise PluginDeploymentError("deployment recipe catalog is missing")
    catalog = _manifest_catalog(stage, catalog_value)
    records = _file_records(stage, exclude_manifest=True)
    tree_sha256 = _tree_sha256(records)
    try:
        source_provenance = packaging_source_provenance(
            repository,
            component_name=PLUGIN_NAME,
            staged_tree_sha256=tree_sha256,
            recipe_path=recipe_path,
        )
    except ReleaseMetadataError as exc:
        raise PluginDeploymentError(f"release provenance capture failed: {exc}") from exc
    manifest = {
        "contract": CONTRACT,
        "schema_version": "1.0",
        "plugin": {"name": PLUGIN_NAME, "version": version},
        "build": {
            "archive_format": "zip_stored",
            "archive_member_timestamp": "1980-01-01T00:00:00Z",
            "source_tree_sha256": tree_sha256,
        },
        "catalog": catalog,
        "source_provenance": source_provenance,
        "staged_tree_sha256": tree_sha256,
        "files": records,
    }
    manifest_path = stage / MANIFEST_NAME
    manifest_path.write_bytes(_canonical_json_bytes(manifest))
    validate_deployment_tree(stage)
    _write_deterministic_zip(stage, archive)
    return PackageBuildReceipt(
        stage_root=stage,
        archive_path=archive,
        tree_sha256=tree_sha256,
        package_sha256=_sha256_file(archive),
        manifest_sha256=_sha256_file(manifest_path),
    )


def validate_deployment_tree(root: Path | str) -> dict[str, Any]:
    """Validate exact package membership, per-file hashes, and the tree identity."""
    stage = Path(root).resolve()
    manifest = _read_json_object(stage / MANIFEST_NAME)
    version, _ = _validate_recipe({**manifest, "source_mappings": [{"validated": True}]})
    _validate_plugin_metadata(stage, version)
    if find_debris(stage):
        raise PluginDeploymentError("deployment tree contains cache/build debris")
    file_values = manifest.get("files")
    if not isinstance(file_values, list):
        raise PluginDeploymentError("deployment manifest file ledger is missing")
    expected: list[dict[str, Any]] = []
    for value in file_values:
        if not isinstance(value, Mapping):
            raise PluginDeploymentError("deployment manifest file entry is invalid")
        relative = value.get("path")
        size = value.get("size")
        expected_hash = value.get("sha256")
        if (
            not isinstance(relative, str)
            or not isinstance(size, int)
            or not isinstance(expected_hash, str)
            or len(expected_hash) != 64
        ):
            raise PluginDeploymentError("deployment manifest file identity is invalid")
        path = _resolve_child(stage, relative)
        if not path.is_file() or path.stat().st_size != size:
            raise PluginDeploymentError(f"deployment file missing or size changed: {relative}")
        if _sha256_file(path) != expected_hash.lower():
            raise PluginDeploymentError(f"deployment file hash changed: {relative}")
        expected.append({"path": relative, "size": size, "sha256": expected_hash.lower()})
    actual = _file_records(stage, exclude_manifest=True)
    if actual != expected:
        raise PluginDeploymentError("deployment tree membership differs from its manifest")
    tree_sha256 = _tree_sha256(expected)
    if tree_sha256 != manifest.get("staged_tree_sha256"):
        raise PluginDeploymentError("deployment tree hash differs from its manifest")
    catalog = manifest.get("catalog")
    if not isinstance(catalog, Mapping):
        raise PluginDeploymentError("deployment skill/tool catalog is missing")
    computed_catalog = _manifest_catalog(stage, catalog)
    if computed_catalog != catalog:
        raise PluginDeploymentError("deployment skill/tool catalog hashes disagree")
    return manifest


def _catalog_entry(manifest: Mapping[str, Any], active_plugin_root: Path) -> dict[str, Any]:
    plugin = manifest["plugin"]
    catalog = manifest["catalog"]
    return {
        "name": plugin["name"],
        "version": plugin["version"],
        "path": str(active_plugin_root.resolve()),
        "tree_sha256": manifest["staged_tree_sha256"],
        "manifest_sha256": _sha256_file(active_plugin_root / MANIFEST_NAME),
        "skills": catalog["skills"],
        "tools": catalog["tools"],
    }


def _read_catalog(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": CATALOG_SCHEMA, "plugins": []}
    catalog = _read_json_object(path)
    plugins = catalog.get("plugins")
    if catalog.get("schema_version") != CATALOG_SCHEMA or not isinstance(plugins, list):
        raise PluginDeploymentError("plugin catalog contract is invalid")
    return catalog


def _refresh_catalog(path: Path, entry: Mapping[str, Any]) -> None:
    catalog = _read_catalog(path)
    plugins = catalog["plugins"]
    retained = [
        item
        for item in plugins
        if not isinstance(item, Mapping) or item.get("name") != PLUGIN_NAME
    ]
    retained.append(dict(entry))
    retained.sort(key=lambda item: str(item.get("name", "")) if isinstance(item, Mapping) else "")
    catalog["plugins"] = retained
    _write_atomic(path, _canonical_json_bytes(catalog))


def _catalog_plugin(path: Path) -> Mapping[str, Any]:
    matches = [
        item
        for item in _read_catalog(path)["plugins"]
        if isinstance(item, Mapping) and item.get("name") == PLUGIN_NAME
    ]
    if len(matches) != 1:
        raise PluginDeploymentError("catalog must contain exactly one native-probes entry")
    return matches[0]


def verify_installed_catalog(
    active_plugin_root: Path | str, catalog_path: Path | str
) -> dict[str, Any]:
    """Require installed version/path/tree and skill/tool catalogs to agree exactly."""
    active = Path(active_plugin_root).resolve()
    catalog_file = Path(catalog_path).resolve()
    manifest = validate_deployment_tree(active)
    expected = _catalog_entry(manifest, active)
    actual = _catalog_plugin(catalog_file)
    checks = (
        ("version", "catalog version"),
        ("tree_sha256", "catalog tree hash"),
        ("manifest_sha256", "catalog manifest hash"),
        ("skills", "catalog skill inventory"),
        ("tools", "catalog tool inventory"),
    )
    if actual.get("path") != expected["path"]:
        raise PluginDeploymentError(
            "stale_cache_path: cached plugin path disagrees with installed plugin; "
            f"expected={expected['path']!r}, observed={actual.get('path')!r}"
        )
    for field, label in checks:
        if actual.get(field) != expected[field]:
            raise PluginDeploymentError(
                f"stale_catalog_identity: {label} disagrees with installed plugin"
            )
    return {
        "schema_version": "kcd2.native-probes-catalog-verification.v1",
        "status": "PASS",
        "version": expected["version"],
        "installed_path": expected["path"],
        "tree_sha256": expected["tree_sha256"],
        "manifest_sha256": expected["manifest_sha256"],
        "skills": [item["name"] for item in expected["skills"]],
        "tools": expected["tools"],
        "catalog_sha256": _sha256_file(catalog_file),
        "evidence_layer": "installed_payload_and_fixture_catalog",
    }


def _inject(selected: FailurePoint | None, current: FailurePoint) -> None:
    if selected == current:
        raise PluginDeploymentError(f"injected failure at {current.value}")


def _remove_tree(path: Path) -> None:
    if path.exists():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def _restore_catalog_bytes(path: Path, existed: bool, backup: Path) -> None:
    if existed:
        _write_atomic(path, backup.read_bytes())
    elif path.exists():
        path.unlink()


def install_plugin_atomic(
    stage_root: Path | str,
    *,
    active_plugin_root: Path | str,
    rollback_root: Path | str,
    catalog_path: Path | str,
    transaction_id: str,
    failure_point: FailurePoint | str | None = None,
) -> InstallReceipt:
    """Install a validated staged plugin and restore both prior identities on failure."""
    allowed_id_characters = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
    )
    if not transaction_id or any(
        character not in allowed_id_characters for character in transaction_id
    ):
        raise PluginDeploymentError("transaction_id contains unsafe characters")
    selected = FailurePoint(failure_point) if failure_point is not None else None
    stage = Path(stage_root).resolve()
    active = Path(active_plugin_root).resolve()
    rollback = Path(rollback_root).resolve()
    catalog = Path(catalog_path).resolve()
    manifest = validate_deployment_tree(stage)
    transaction = rollback / transaction_id
    if transaction.exists():
        raise PluginDeploymentError("transaction receipt directory already exists")
    transaction.mkdir(parents=True)
    active.parent.mkdir(parents=True, exist_ok=True)
    incoming = active.parent / f".{PLUGIN_NAME}.incoming-{transaction_id}"
    displaced = active.parent / f".{PLUGIN_NAME}.displaced-{transaction_id}"
    if incoming.exists() or displaced.exists():
        raise PluginDeploymentError("transaction temporary path already exists")
    prior_active = active.is_dir()
    prior_tree = _tree_snapshot_sha256(active) if prior_active else None
    backup_plugin = transaction / "prior-plugin"
    prior_catalog = catalog.exists()
    catalog_backup = transaction / "prior-catalog.bin"
    prior_catalog_sha256 = _sha256_file(catalog) if prior_catalog else None
    displaced_active = False
    swapped = False
    try:
        if prior_active:
            shutil.copytree(active, backup_plugin)
            if _tree_snapshot_sha256(backup_plugin) != prior_tree:
                raise PluginDeploymentError("prior plugin backup verification failed")
        if prior_catalog:
            catalog_backup.write_bytes(catalog.read_bytes())
        _inject(selected, FailurePoint.AFTER_BACKUP)
        shutil.copytree(stage, incoming)
        validate_deployment_tree(incoming)
        _inject(selected, FailurePoint.AFTER_INCOMING_COPY)
        if prior_active:
            active.rename(displaced)
            displaced_active = True
        _inject(selected, FailurePoint.AFTER_ACTIVE_DISPLACEMENT)
        incoming.rename(active)
        swapped = True
        _inject(selected, FailurePoint.AFTER_PLUGIN_SWAP)
        _refresh_catalog(catalog, _catalog_entry(manifest, active))
        _inject(selected, FailurePoint.AFTER_CATALOG_REFRESH)
        verification = verify_installed_catalog(active, catalog)
        _inject(selected, FailurePoint.AFTER_SMOKE_TEST)
        receipt_payload = {
            "schema_version": "kcd2.native-probes-install-receipt.v1",
            "status": "installed",
            "transaction_id": transaction_id,
            "active_plugin_root": str(active),
            "catalog_path": str(catalog),
            "prior_active_plugin": prior_active,
            "prior_tree_sha256": prior_tree,
            "prior_plugin_backup": str(backup_plugin) if prior_active else None,
            "prior_catalog": prior_catalog,
            "prior_catalog_sha256": prior_catalog_sha256,
            "prior_catalog_backup": str(catalog_backup) if prior_catalog else None,
            "installed_tree_sha256": manifest["staged_tree_sha256"],
            "installed_manifest_sha256": _sha256_file(active / MANIFEST_NAME),
            "catalog_verification": verification,
        }
        receipt_path = transaction / "install-receipt.json"
        _write_atomic(receipt_path, _canonical_json_bytes(receipt_payload))
    except Exception as exc:
        rollback_errors: list[str] = []
        try:
            _restore_catalog_bytes(catalog, prior_catalog, catalog_backup)
        except Exception as restore_exc:  # pragma: no cover - catastrophic filesystem failure
            rollback_errors.append(f"catalog:{type(restore_exc).__name__}")
        try:
            if swapped:
                _remove_tree(active)
            if displaced_active and displaced.exists():
                displaced.rename(active)
            _remove_tree(incoming)
        except Exception as restore_exc:  # pragma: no cover - catastrophic filesystem failure
            rollback_errors.append(f"plugin:{type(restore_exc).__name__}")
        restored_tree = _tree_snapshot_sha256(active) if active.exists() else None
        restored_catalog = _sha256_file(catalog) if catalog.exists() else None
        restored = (
            restored_tree == prior_tree
            and restored_catalog == prior_catalog_sha256
            and not rollback_errors
        )
        failure_payload = {
            "schema_version": "kcd2.native-probes-install-failure-receipt.v1",
            "status": "rolled_back_after_install_failure" if restored else "rollback_failed",
            "transaction_id": transaction_id,
            "failure": str(exc)[:1000],
            "failure_type": type(exc).__name__,
            "prior_tree_sha256": prior_tree,
            "restored_tree_sha256": restored_tree,
            "prior_catalog_sha256": prior_catalog_sha256,
            "restored_catalog_sha256": restored_catalog,
            "rollback_errors": rollback_errors,
        }
        _write_atomic(
            transaction / "failure-receipt.json", _canonical_json_bytes(failure_payload)
        )
        if not restored:
            raise PluginDeploymentError(
                f"install failed and exact rollback failed: {rollback_errors}"
            ) from exc
        raise PluginDeploymentError(str(exc)) from exc
    finally:
        _remove_tree(incoming)
    if displaced.exists():
        _remove_tree(displaced)
    return InstallReceipt(
        receipt_path=receipt_path,
        receipt_sha256=_sha256_file(receipt_path),
        active_plugin_root=active,
        catalog_path=catalog,
        rollback_unit=transaction,
        tree_sha256=manifest["staged_tree_sha256"],
    )


def _tree_snapshot_sha256(root: Path) -> str:
    return _tree_sha256(_file_records(root, exclude_manifest=False))


def restore_plugin_atomic(install_receipt_path: Path | str) -> dict[str, Any]:
    """Restore exact prior plugin and catalog bytes from one successful install receipt."""
    receipt_path = Path(install_receipt_path).resolve()
    receipt = _read_json_object(receipt_path)
    if receipt.get("status") != "installed":
        raise PluginDeploymentError("install receipt is not restorable")
    rollback_receipt = receipt_path.parent / "restore-receipt.json"
    if rollback_receipt.exists():
        raise PluginDeploymentError("install receipt has already been restored")
    active = Path(receipt["active_plugin_root"]).resolve()
    catalog = Path(receipt["catalog_path"]).resolve()
    if validate_deployment_tree(active).get("staged_tree_sha256") != receipt.get(
        "installed_tree_sha256"
    ):
        raise PluginDeploymentError("installed plugin drifted after the install receipt")
    verify_installed_catalog(active, catalog)
    transaction_id = receipt["transaction_id"]
    displaced = active.parent / f".{PLUGIN_NAME}.restore-displaced-{transaction_id}"
    incoming = active.parent / f".{PLUGIN_NAME}.restore-incoming-{transaction_id}"
    if displaced.exists() or incoming.exists():
        raise PluginDeploymentError("restore temporary path already exists")
    prior_active = bool(receipt["prior_active_plugin"])
    prior_catalog = bool(receipt["prior_catalog"])
    backup = Path(receipt["prior_plugin_backup"]).resolve() if prior_active else None
    catalog_backup = (
        Path(receipt["prior_catalog_backup"]).resolve() if prior_catalog else None
    )
    active.rename(displaced)
    try:
        if prior_active:
            if backup is None or not backup.is_dir():
                raise PluginDeploymentError("prior plugin backup is unavailable")
            shutil.copytree(backup, incoming)
            if _tree_snapshot_sha256(incoming) != receipt["prior_tree_sha256"]:
                raise PluginDeploymentError("prior plugin backup identity changed")
            incoming.rename(active)
        if prior_catalog:
            if catalog_backup is None or not catalog_backup.is_file():
                raise PluginDeploymentError("prior catalog backup is unavailable")
            _write_atomic(catalog, catalog_backup.read_bytes())
        elif catalog.exists():
            catalog.unlink()
        restored_tree = _tree_snapshot_sha256(active) if active.exists() else None
        restored_catalog = _sha256_file(catalog) if catalog.exists() else None
        if restored_tree != receipt["prior_tree_sha256"]:
            raise PluginDeploymentError("restored plugin identity disagrees with receipt")
        if restored_catalog != receipt["prior_catalog_sha256"]:
            raise PluginDeploymentError("restored catalog identity disagrees with receipt")
        payload = {
            "schema_version": "kcd2.native-probes-restore-receipt.v1",
            "status": "restored",
            "transaction_id": transaction_id,
            "restored_tree_sha256": restored_tree,
            "restored_catalog_sha256": restored_catalog,
            "install_receipt_sha256": _sha256_file(receipt_path),
        }
        _write_atomic(rollback_receipt, _canonical_json_bytes(payload))
    except Exception as exc:
        _remove_tree(active)
        _remove_tree(incoming)
        if displaced.exists():
            displaced.rename(active)
        _refresh_catalog(catalog, _catalog_entry(validate_deployment_tree(active), active))
        raise PluginDeploymentError(str(exc)) from exc
    _remove_tree(displaced)
    return payload


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--repository-root", type=Path, required=True)
    build.add_argument("--stage-root", type=Path, required=True)
    build.add_argument("--archive", type=Path, required=True)
    install = subparsers.add_parser("install")
    install.add_argument("--stage-root", type=Path, required=True)
    install.add_argument("--active-plugin-root", type=Path, required=True)
    install.add_argument("--rollback-root", type=Path, required=True)
    install.add_argument("--catalog", type=Path, required=True)
    install.add_argument("--transaction-id", required=True)
    install.add_argument("--failure-point", choices=[item.value for item in FailurePoint])
    restore = subparsers.add_parser("restore")
    restore.add_argument("--install-receipt", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--active-plugin-root", type=Path, required=True)
    verify.add_argument("--catalog", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "build":
        result: object = build_plugin_package(
            args.repository_root, stage_root=args.stage_root, archive_path=args.archive
        ).__dict__
    elif args.operation == "install":
        result = install_plugin_atomic(
            args.stage_root,
            active_plugin_root=args.active_plugin_root,
            rollback_root=args.rollback_root,
            catalog_path=args.catalog,
            transaction_id=args.transaction_id,
            failure_point=args.failure_point,
        ).__dict__
    elif args.operation == "restore":
        result = restore_plugin_atomic(args.install_receipt)
    else:
        result = verify_installed_catalog(args.active_plugin_root, args.catalog)
    serializable = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in dict(result).items()
    }
    print(json.dumps(serializable, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())


__all__ = [
    "FailurePoint",
    "InstallReceipt",
    "PackageBuildReceipt",
    "PluginDeploymentError",
    "build_plugin_package",
    "find_debris",
    "install_plugin_atomic",
    "restore_plugin_atomic",
    "validate_deployment_tree",
    "verify_installed_catalog",
]
