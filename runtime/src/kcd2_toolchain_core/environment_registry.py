"""Bounded read-only environment discovery, drift comparison, and baseline updates."""

from __future__ import annotations

import copy
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .environment_profiles import EnvironmentProfile, load_environment_profile
from .hashing import sha256_file, sha256_json


MAX_IDENTITY_BYTES = 2 * 1024 * 1024 * 1024
MAX_VERSION_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CATALOG_BYTES = 16 * 1024 * 1024
MAX_GIT_OUTPUT = 4096


def _timestamp(value: str, name: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ValueError(f"{name} must be an ISO date-time") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{name} must include a UTC offset")
    return value


def _bounded_file(path: str, limit: int) -> tuple[str, Path | None]:
    target = Path(path)
    try:
        stat = target.stat()
    except FileNotFoundError:
        return "missing", None
    except OSError:
        return "unavailable", None
    if not target.is_file() or stat.st_size > limit:
        return "unavailable", None
    return "observed", target


def _version(path: str, target_format: str) -> tuple[str, str | None]:
    state, target = _bounded_file(path, MAX_VERSION_BYTES)
    if target is None:
        return state, None
    try:
        text = target.read_text(encoding="utf-8")
        if target_format == "json_version":
            decoded = json.loads(text)
            value = decoded.get("version") if isinstance(decoded, dict) else None
        else:
            value = text.strip()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "unavailable", None
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return "unavailable", None
    return "observed", value


def _event(
    *,
    profile_id: str,
    detected_at: str,
    subject_kind: str,
    subject_id: str,
    drift_kind: str,
    expected: str | None,
    observed: str | None,
) -> dict[str, object]:
    identity = {
        "profile_id": profile_id,
        "detected_at": detected_at,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "drift_kind": drift_kind,
        "expected": expected,
        "observed": observed,
    }
    return {
        "schema_version": "kcd2.environment-drift-event.v1",
        "event_id": f"drift:sha256:{sha256_json(identity)}",
        **identity,
        "evidence_layer": "static_read_only",
        "eligibility_effect": "none",
    }


def _compare(
    events: list[dict[str, object]],
    *,
    profile_id: str,
    detected_at: str,
    subject_kind: str,
    subject_id: str,
    drift_kind: str,
    expected: str | None,
    observed: str | None,
) -> None:
    if expected != observed:
        events.append(
            _event(
                profile_id=profile_id,
                detected_at=detected_at,
                subject_kind=subject_kind,
                subject_id=subject_id,
                drift_kind=drift_kind,
                expected=expected,
                observed=observed,
            )
        )


def _discover_repository(repository: Mapping[str, str | None]) -> dict[str, object]:
    path = Path(str(repository["path"]))
    if not path.is_dir():
        return {
            "name": repository["name"],
            "path": str(path),
            "state": "missing",
            "commit": None,
            "tree_sha256": None,
        }
    values: list[str] = []
    try:
        for revision in ("HEAD", "HEAD^{tree}"):
            completed = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "--verify", revision],
                capture_output=True,
                check=False,
                text=True,
                timeout=10,
            )
            output = completed.stdout.strip()
            if completed.returncode != 0 or not output or len(output) > MAX_GIT_OUTPUT:
                raise RuntimeError("repository identity unavailable")
            values.append(output)
    except (OSError, subprocess.SubprocessError, RuntimeError):
        return {
            "name": repository["name"],
            "path": str(path),
            "state": "unavailable",
            "commit": None,
            "tree_sha256": None,
        }
    return {
        "name": repository["name"],
        "path": str(path),
        "state": "observed",
        "commit": values[0],
        "tree_sha256": sha256_json({"git_tree_object": values[1]}),
    }


def discover_environment(
    profile: EnvironmentProfile,
    *,
    collected_at: str,
) -> dict[str, object]:
    """Read only the explicit stable paths in ``profile`` and compare their identities."""

    collected_at = _timestamp(collected_at, "collected_at")
    events: list[dict[str, object]] = []
    components: list[dict[str, object]] = []
    for component_id in sorted(profile.components):
        component = profile.components[component_id]
        state, target = _bounded_file(component.path, MAX_IDENTITY_BYTES)
        observed_hash = sha256_file(target) if target is not None else None
        version_target = profile.discovery_targets.component_versions[component_id]
        version_state, observed_version = _version(
            version_target["path"], version_target["format"]
        )
        item = {
            "component_id": component_id,
            "path": component.path,
            "state": state,
            "sha256": observed_hash,
            "version_state": version_state,
            "version": observed_version,
        }
        components.append(item)
        if state != "observed":
            events.append(
                _event(
                    profile_id=profile.profile_id,
                    detected_at=collected_at,
                    subject_kind="component",
                    subject_id=component_id,
                    drift_kind="path_missing" if state == "missing" else "identity_unavailable",
                    expected=component.expected_sha256,
                    observed=None,
                )
            )
        else:
            _compare(
                events,
                profile_id=profile.profile_id,
                detected_at=collected_at,
                subject_kind="component",
                subject_id=component_id,
                drift_kind="sha256_changed",
                expected=component.expected_sha256,
                observed=observed_hash,
            )
        if version_state == "observed":
            _compare(
                events,
                profile_id=profile.profile_id,
                detected_at=collected_at,
                subject_kind="component",
                subject_id=component_id,
                drift_kind="version_changed",
                expected=component.expected_version,
                observed=observed_version,
            )
        else:
            events.append(
                _event(
                    profile_id=profile.profile_id,
                    detected_at=collected_at,
                    subject_kind="component",
                    subject_id=component_id,
                    drift_kind="version_unavailable",
                    expected=component.expected_version,
                    observed=None,
                )
            )

    repositories = [_discover_repository(item) for item in profile.repositories]
    expected_repositories = {str(item["name"]): item for item in profile.repositories}
    for item in repositories:
        expected = expected_repositories[str(item["name"])]
        if item["state"] != "observed":
            events.append(
                _event(
                    profile_id=profile.profile_id,
                    detected_at=collected_at,
                    subject_kind="repository",
                    subject_id=str(item["name"]),
                    drift_kind=(
                        "path_missing"
                        if item["state"] == "missing"
                        else "identity_unavailable"
                    ),
                    expected=str(expected["commit"]) if expected["commit"] is not None else None,
                    observed=None,
                )
            )
            continue
        for field, kind in (("commit", "commit_changed"), ("tree_sha256", "sha256_changed")):
            _compare(
                events,
                profile_id=profile.profile_id,
                detected_at=collected_at,
                subject_kind="repository",
                subject_id=str(item["name"]),
                drift_kind=kind,
                expected=str(expected[field]) if expected[field] is not None else None,
                observed=str(item[field]) if item[field] is not None else None,
            )

    expected_plugins = {str(item["plugin_id"]): item for item in profile.plugins}
    plugins: list[dict[str, object]] = []
    for plugin_id in sorted(profile.discovery_targets.plugin_manifests):
        path = profile.discovery_targets.plugin_manifests[plugin_id]
        state, target = _bounded_file(path, MAX_MANIFEST_BYTES)
        manifest_hash: str | None = None
        version: str | None = None
        if target is not None:
            manifest_hash = sha256_file(target)
            try:
                manifest = json.loads(target.read_text(encoding="utf-8"))
                manifest_id = manifest.get("id", manifest.get("name"))
                version_value = manifest.get("version")
                if manifest_id == plugin_id and isinstance(version_value, str) and version_value:
                    version = version_value
                else:
                    state = "unavailable"
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                state = "unavailable"
        item = {
            "plugin_id": plugin_id,
            "manifest_path": path,
            "state": state,
            "version": version,
            "manifest_sha256": manifest_hash,
        }
        plugins.append(item)
        expected = expected_plugins[plugin_id]
        if state != "observed":
            events.append(
                _event(
                    profile_id=profile.profile_id,
                    detected_at=collected_at,
                    subject_kind="plugin",
                    subject_id=plugin_id,
                    drift_kind="path_missing" if state == "missing" else "identity_unavailable",
                    expected=str(expected["manifest_sha256"]),
                    observed=manifest_hash,
                )
            )
            continue
        for expected_value, observed_value, kind in (
            (expected["version"], version, "version_changed"),
            (expected["manifest_sha256"], manifest_hash, "sha256_changed"),
        ):
            _compare(
                events,
                profile_id=profile.profile_id,
                detected_at=collected_at,
                subject_kind="plugin",
                subject_id=plugin_id,
                drift_kind=kind,
                expected=str(expected_value),
                observed=str(observed_value) if observed_value is not None else None,
            )

    catalog_items: list[dict[str, object]] = []
    catalog_complete = True
    for catalog_id in sorted(profile.discovery_targets.catalogs):
        path = profile.discovery_targets.catalogs[catalog_id]
        state, target = _bounded_file(path, MAX_CATALOG_BYTES)
        digest = sha256_file(target) if target is not None else None
        catalog_complete = catalog_complete and state == "observed"
        catalog_items.append(
            {"catalog_id": catalog_id, "path": path, "state": state, "sha256": digest}
        )
    catalog_fingerprint = (
        sha256_json(
            [
                {"catalog_id": item["catalog_id"], "sha256": item["sha256"]}
                for item in catalog_items
            ]
        )
        if catalog_complete
        else None
    )
    catalog = {
        "state": "observed" if catalog_complete else "unavailable",
        "fingerprint": catalog_fingerprint,
        "items": catalog_items,
    }
    if not catalog_complete:
        events.append(
            _event(
                profile_id=profile.profile_id,
                detected_at=collected_at,
                subject_kind="catalog",
                subject_id="catalog",
                drift_kind="identity_unavailable",
                expected=profile.catalog_fingerprint,
                observed=None,
            )
        )
    else:
        _compare(
            events,
            profile_id=profile.profile_id,
            detected_at=collected_at,
            subject_kind="catalog",
            subject_id="catalog",
            drift_kind="catalog_fingerprint_changed",
            expected=profile.catalog_fingerprint,
            observed=catalog_fingerprint,
        )

    events.sort(
        key=lambda item: (
            str(item["subject_kind"]),
            str(item["subject_id"]),
            str(item["drift_kind"]),
        )
    )
    return {
        "schema_version": "kcd2.environment-discovery.v1",
        "profile_id": profile.profile_id,
        "collected_at": collected_at,
        "classification": "non-live_read-only_discovery",
        "components": components,
        "repositories": repositories,
        "plugins": plugins,
        "catalog": catalog,
        "drift_events": events,
        "implies_tool_eligibility": False,
        "limits": {
            "max_identity_bytes": MAX_IDENTITY_BYTES,
            "max_version_bytes": MAX_VERSION_BYTES,
            "max_manifest_bytes": MAX_MANIFEST_BYTES,
            "max_catalog_bytes": MAX_CATALOG_BYTES,
        },
    }


def update_profile_from_discovery(
    source: Mapping[str, Any],
    discovery: Mapping[str, Any],
    *,
    profile_id: str,
    created_at: str,
) -> dict[str, Any]:
    """Accept a complete observed baseline while invalidating every eligibility proof."""

    profile = load_environment_profile(source)
    if discovery.get("profile_id") != profile.profile_id:
        raise ValueError("discovery profile_id does not match the source profile")
    _timestamp(created_at, "created_at")
    updated = copy.deepcopy(dict(source))
    updated["profile_id"] = profile_id
    updated["created_at"] = created_at
    components = {item["component_id"]: item for item in discovery.get("components", [])}
    for component in updated["components"]:
        observed = components.get(component["component_id"])
        if (
            not observed
            or observed.get("state") != "observed"
            or observed.get("version_state") != "observed"
        ):
            raise ValueError(f"component identity is incomplete: {component['component_id']}")
        component["expected"] = {
            "version": observed["version"],
            "sha256": observed["sha256"],
        }
        component["observed"] = {
            "path_present": True,
            "version": observed["version"],
            "sha256": observed["sha256"],
        }
        for check in component["checks"].values():
            if check["status"] != "not_required":
                check.update({"status": "not_run", "checked_at": None, "evidence": None})
        component["checks"]["version_profile"] = {
            "status": "not_run",
            "checked_at": None,
            "evidence": None,
        }
        component["capability_level"] = "PATH_PRESENT"

    repositories = {item["name"]: item for item in discovery.get("repositories", [])}
    for repository in updated["repositories"]:
        observed = repositories.get(repository["name"])
        if not observed or observed.get("state") != "observed":
            raise ValueError(f"repository identity is incomplete: {repository['name']}")
        repository["commit"] = observed["commit"]
        repository["tree_sha256"] = observed["tree_sha256"]

    plugins = {item["plugin_id"]: item for item in discovery.get("plugins", [])}
    for plugin in updated["plugins"]:
        observed = plugins.get(plugin["plugin_id"])
        if not observed or observed.get("state") != "observed":
            raise ValueError(f"plugin identity is incomplete: {plugin['plugin_id']}")
        plugin["version"] = observed["version"]
        plugin["manifest_sha256"] = observed["manifest_sha256"]

    catalog = discovery.get("catalog")
    if not isinstance(catalog, Mapping) or catalog.get("state") != "observed":
        raise ValueError("catalog identity is incomplete")
    updated["catalog_fingerprint"] = catalog["fingerprint"]
    load_environment_profile(updated)
    return updated
