"""Versioned, fail-closed environment profiles and capability proof evaluation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


SCHEMA_VERSION = "kcd2.environment-profile.v2"
MAX_PROFILE_BYTES = 1024 * 1024
MAX_COMPONENTS = 64
MAX_WORKFLOWS = 64
MAX_TEXT = 2048
SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
DOWNLOADS_PATTERN = re.compile(r"(?:^|[\\/])downloads(?:[\\/]|$)", re.IGNORECASE)
ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\)")
CHECK_NAMES = ("launch", "provider", "catalog", "version_profile")
CHECK_STATUSES = {"not_required", "not_run", "passed", "failed"}
CAPABILITY_LEVELS = {
    "PATH_PRESENT",
    "LAUNCH_VERIFIED",
    "PROVIDER_CONNECTED",
    "TOOL_CATALOG_VISIBLE",
    "VERSION_PROFILE_MATCHED",
    "WORKFLOW_ELIGIBLE",
    "UNAVAILABLE_OPTIONAL",
    "UNAVAILABLE_REQUIRED",
}
CANONICAL_COMPONENTS = {
    "ghidra",
    "java",
    "x64dbg",
    "compiler",
    "kcse",
    "python_current",
    "pyghidra_isolated",
    "game",
    "whgame",
}
COMPONENT_TYPES = {
    "tool",
    "runtime",
    "python_interpreter",
    "game_executable",
    "game_module",
}


class EnvironmentProfileError(ValueError):
    """Raised when a profile is malformed or its evidence contradicts its claims."""


@dataclass(frozen=True, slots=True)
class CheckReceipt:
    status: str
    checked_at: str | None
    evidence: str | None


@dataclass(frozen=True, slots=True)
class ComponentProfile:
    component_id: str
    component_type: str
    required: bool
    path: str
    interpreter_scope: str | None
    expected_version: str
    expected_sha256: str
    path_present: bool
    observed_version: str | None
    observed_sha256: str | None
    checks: Mapping[str, CheckReceipt]
    capability_level: str
    workflow_eligible: bool


@dataclass(frozen=True, slots=True)
class WorkflowProfile:
    workflow_id: str
    required_components: tuple[str, ...]
    optional_components: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoveryTargets:
    component_versions: Mapping[str, Mapping[str, str]]
    plugin_manifests: Mapping[str, str]
    catalogs: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class EnvironmentProfile:
    schema_version: str
    profile_id: str
    compatibility_profile_id: str
    created_at: str
    components: Mapping[str, ComponentProfile]
    repositories: tuple[Mapping[str, str | None], ...]
    plugins: tuple[Mapping[str, str], ...]
    catalog_fingerprint: str
    discovery_targets: DiscoveryTargets
    workflows: Mapping[str, WorkflowProfile]


def _bounded_text(value: object, name: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_TEXT:
        raise EnvironmentProfileError(f"{name} must contain 1 to {MAX_TEXT} characters")
    return value


def _timestamp(value: object, name: str) -> str:
    text = _bounded_text(value, name)
    assert text is not None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise EnvironmentProfileError(f"{name} must be an ISO date-time") from error
    if parsed.tzinfo is None:
        raise EnvironmentProfileError(f"{name} must include a UTC offset")
    return text


def _stable_path(value: object, name: str) -> str:
    path = _bounded_text(value, name)
    assert path is not None
    if ABSOLUTE_PATH_PATTERN.match(path) is None:
        raise EnvironmentProfileError(f"{name} must be an absolute stable path")
    if DOWNLOADS_PATTERN.search(path):
        raise EnvironmentProfileError(f"{name} uses a fragile Downloads path")
    return path


def _closed_object(
    value: object,
    name: str,
    *,
    required: set[str],
    allowed: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EnvironmentProfileError(f"{name} must be an object")
    permitted = allowed or required
    missing = required - set(value)
    unknown = set(value) - permitted
    if missing:
        raise EnvironmentProfileError(f"{name} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise EnvironmentProfileError(f"{name} has unknown fields: {', '.join(sorted(unknown))}")
    return value


def _duplicate_rejecting_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnvironmentProfileError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_source(source: str | bytes | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Mapping):
        encoded = json.dumps(source, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_PROFILE_BYTES:
            raise EnvironmentProfileError("environment profile exceeds byte limit")
        return dict(source)
    if isinstance(source, Path):
        try:
            raw = source.read_bytes()
        except OSError as error:
            raise EnvironmentProfileError(f"cannot read environment profile: {error}") from error
    elif isinstance(source, bytes):
        raw = source
    elif isinstance(source, str):
        stripped = source.lstrip()
        if stripped.startswith("{"):
            raw = source.encode("utf-8")
        else:
            try:
                raw = Path(source).read_bytes()
            except OSError as error:
                raise EnvironmentProfileError(
                    f"cannot read environment profile: {error}"
                ) from error
    else:
        raise EnvironmentProfileError("environment profile source has an unsupported type")
    if len(raw) > MAX_PROFILE_BYTES:
        raise EnvironmentProfileError("environment profile exceeds byte limit")
    try:
        decoded = json.loads(raw.decode("utf-8"), object_pairs_hook=_duplicate_rejecting_object)
    except EnvironmentProfileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnvironmentProfileError(f"invalid UTF-8 JSON environment profile: {error}") from error
    if not isinstance(decoded, dict):
        raise EnvironmentProfileError("environment profile root must be an object")
    return decoded


def _parse_check(value: object, name: str) -> CheckReceipt:
    data = _closed_object(
        value,
        name,
        required={"status", "checked_at", "evidence"},
    )
    status = data["status"]
    if status not in CHECK_STATUSES:
        raise EnvironmentProfileError(f"{name}.status is unsupported")
    checked_at_value = data["checked_at"]
    checked_at = (
        None if checked_at_value is None else _timestamp(checked_at_value, f"{name}.checked_at")
    )
    evidence = _bounded_text(data["evidence"], f"{name}.evidence", nullable=True)
    if status in {"passed", "failed"}:
        if checked_at is None or evidence is None:
            raise EnvironmentProfileError(f"{name} must record time and evidence")
    elif checked_at is not None or evidence is not None:
        raise EnvironmentProfileError(f"{name} cannot claim evidence when it did not run")
    return CheckReceipt(status, checked_at, evidence)


def _derived_level(
    *,
    required: bool,
    path_present: bool,
    checks: Mapping[str, CheckReceipt],
) -> tuple[str, bool]:
    if not path_present:
        return ("UNAVAILABLE_REQUIRED" if required else "UNAVAILABLE_OPTIONAL"), False
    passed = {name for name, receipt in checks.items() if receipt.status == "passed"}
    all_applicable_passed = all(
        receipt.status in {"passed", "not_required"} for receipt in checks.values()
    )
    eligible = all_applicable_passed and checks["version_profile"].status == "passed"
    if eligible:
        return "WORKFLOW_ELIGIBLE", True
    for proof, level in (
        ("version_profile", "VERSION_PROFILE_MATCHED"),
        ("catalog", "TOOL_CATALOG_VISIBLE"),
        ("provider", "PROVIDER_CONNECTED"),
        ("launch", "LAUNCH_VERIFIED"),
    ):
        if proof in passed:
            return level, False
    return "PATH_PRESENT", False


def _parse_component(value: object, index: int) -> ComponentProfile:
    name = f"components[{index}]"
    data = _closed_object(
        value,
        name,
        required={
            "component_id",
            "component_type",
            "required",
            "path",
            "interpreter_scope",
            "expected",
            "observed",
            "checks",
            "capability_level",
        },
    )
    component_id = _bounded_text(data["component_id"], f"{name}.component_id")
    assert component_id is not None
    if component_id not in CANONICAL_COMPONENTS:
        raise EnvironmentProfileError(f"{name}.component_id is not canonical")
    component_type = data["component_type"]
    if component_type not in COMPONENT_TYPES:
        raise EnvironmentProfileError(f"{name}.component_type is unsupported")
    if not isinstance(data["required"], bool):
        raise EnvironmentProfileError(f"{name}.required must be boolean")
    required = data["required"]
    path = _stable_path(data["path"], f"{name}.path")

    scope = data["interpreter_scope"]
    if scope not in {None, "current", "isolated"}:
        raise EnvironmentProfileError(f"{name}.interpreter_scope is unsupported")
    if component_type == "python_interpreter":
        expected_scope = "current" if component_id == "python_current" else "isolated"
        if scope != expected_scope:
            raise EnvironmentProfileError(f"{name} has the wrong interpreter scope")
    elif scope is not None:
        raise EnvironmentProfileError(f"{name} is not an interpreter")

    expected = _closed_object(
        data["expected"], f"{name}.expected", required={"version", "sha256"}
    )
    expected_version = _bounded_text(expected["version"], f"{name}.expected.version")
    expected_hash = _bounded_text(expected["sha256"], f"{name}.expected.sha256")
    assert expected_version is not None and expected_hash is not None
    if SHA256_PATTERN.fullmatch(expected_hash) is None:
        raise EnvironmentProfileError(f"{name}.expected.sha256 is invalid")

    observed = _closed_object(
        data["observed"],
        f"{name}.observed",
        required={"path_present", "version", "sha256"},
    )
    if not isinstance(observed["path_present"], bool):
        raise EnvironmentProfileError(f"{name}.observed.path_present must be boolean")
    observed_version = _bounded_text(
        observed["version"], f"{name}.observed.version", nullable=True
    )
    observed_hash = _bounded_text(
        observed["sha256"], f"{name}.observed.sha256", nullable=True
    )
    if observed_hash is not None and SHA256_PATTERN.fullmatch(observed_hash) is None:
        raise EnvironmentProfileError(f"{name}.observed.sha256 is invalid")
    if not observed["path_present"] and (observed_version is not None or observed_hash is not None):
        raise EnvironmentProfileError(f"{name} cannot observe identity for a missing path")

    check_data = _closed_object(data["checks"], f"{name}.checks", required=set(CHECK_NAMES))
    checks = {
        check: _parse_check(check_data[check], f"{name}.checks.{check}")
        for check in CHECK_NAMES
    }
    if checks["version_profile"].status == "passed" and (
        observed_version != expected_version
        or observed_hash is None
        or observed_hash.casefold() != expected_hash.casefold()
    ):
        raise EnvironmentProfileError(
            f"{name} passed version_profile without exact version/hash compatibility"
        )
    claimed_level = data["capability_level"]
    if claimed_level not in CAPABILITY_LEVELS:
        raise EnvironmentProfileError(f"{name}.capability_level is unsupported")
    level, eligible = _derived_level(
        required=required,
        path_present=observed["path_present"],
        checks=checks,
    )
    if claimed_level != level:
        raise EnvironmentProfileError(
            f"{name} claimed capability_level {claimed_level}, derived {level}"
        )
    return ComponentProfile(
        component_id=component_id,
        component_type=component_type,
        required=required,
        path=path,
        interpreter_scope=scope,
        expected_version=expected_version,
        expected_sha256=expected_hash.casefold(),
        path_present=observed["path_present"],
        observed_version=observed_version,
        observed_sha256=observed_hash.casefold() if observed_hash else None,
        checks=MappingProxyType(checks),
        capability_level=level,
        workflow_eligible=eligible,
    )


def load_environment_profile(
    source: str | bytes | Path | Mapping[str, Any],
) -> EnvironmentProfile:
    """Load and validate one bounded profile without probing or discovering installations."""

    data = _closed_object(
        _decode_source(source),
        "profile",
        required={
            "schema_version",
            "profile_id",
            "compatibility_profile_id",
            "created_at",
            "components",
            "repositories",
            "plugins",
            "catalog_fingerprint",
            "discovery_targets",
            "workflows",
        },
    )
    if data["schema_version"] != SCHEMA_VERSION:
        raise EnvironmentProfileError("unsupported environment profile schema_version")
    profile_id = _bounded_text(data["profile_id"], "profile.profile_id")
    compatibility_id = _bounded_text(
        data["compatibility_profile_id"], "profile.compatibility_profile_id"
    )
    created_at = _timestamp(data["created_at"], "profile.created_at")
    assert profile_id is not None and compatibility_id is not None

    component_values = data["components"]
    if not isinstance(component_values, list) or not 1 <= len(component_values) <= MAX_COMPONENTS:
        raise EnvironmentProfileError("components must be a bounded non-empty array")
    components: dict[str, ComponentProfile] = {}
    for index, value in enumerate(component_values):
        component = _parse_component(value, index)
        if component.component_id in components:
            raise EnvironmentProfileError(f"duplicate component_id: {component.component_id}")
        components[component.component_id] = component
    missing_components = CANONICAL_COMPONENTS - set(components)
    if missing_components:
        raise EnvironmentProfileError(
            f"profile is missing canonical components: {', '.join(sorted(missing_components))}"
        )
    if components["python_current"].path.casefold() == components[
        "pyghidra_isolated"
    ].path.casefold():
        raise EnvironmentProfileError("current and isolated interpreters must be distinct paths")

    repository_values = data["repositories"]
    if not isinstance(repository_values, list) or len(repository_values) > MAX_COMPONENTS:
        raise EnvironmentProfileError("repositories must be a bounded array")
    repositories: list[Mapping[str, str | None]] = []
    repository_names: set[str] = set()
    for index, value in enumerate(repository_values):
        name = f"repositories[{index}]"
        repository = _closed_object(
            value,
            name,
            required={"name", "path", "commit", "tree_sha256"},
        )
        repository_name = _bounded_text(repository["name"], f"{name}.name")
        repository_path = _stable_path(repository["path"], f"{name}.path")
        commit = _bounded_text(repository["commit"], f"{name}.commit", nullable=True)
        tree_hash = _bounded_text(repository["tree_sha256"], f"{name}.tree_sha256")
        assert repository_name is not None and repository_path is not None
        assert tree_hash is not None
        if repository_name in repository_names:
            raise EnvironmentProfileError(f"duplicate repository name: {repository_name}")
        if SHA256_PATTERN.fullmatch(tree_hash) is None:
            raise EnvironmentProfileError(f"{name}.tree_sha256 is invalid")
        repository_names.add(repository_name)
        repositories.append(
            MappingProxyType(
                {
                    "name": repository_name,
                    "path": repository_path,
                    "commit": commit,
                    "tree_sha256": tree_hash.casefold(),
                }
            )
        )

    plugin_values = data["plugins"]
    if not isinstance(plugin_values, list) or len(plugin_values) > MAX_COMPONENTS:
        raise EnvironmentProfileError("plugins must be a bounded array")
    plugins: list[Mapping[str, str]] = []
    plugin_ids: set[str] = set()
    for index, value in enumerate(plugin_values):
        name = f"plugins[{index}]"
        plugin = _closed_object(
            value,
            name,
            required={"plugin_id", "version", "manifest_sha256"},
        )
        plugin_id = _bounded_text(plugin["plugin_id"], f"{name}.plugin_id")
        plugin_version = _bounded_text(plugin["version"], f"{name}.version")
        manifest_hash = _bounded_text(
            plugin["manifest_sha256"], f"{name}.manifest_sha256"
        )
        assert plugin_id is not None and plugin_version is not None
        assert manifest_hash is not None
        if plugin_id in plugin_ids:
            raise EnvironmentProfileError(f"duplicate plugin_id: {plugin_id}")
        if SHA256_PATTERN.fullmatch(manifest_hash) is None:
            raise EnvironmentProfileError(f"{name}.manifest_sha256 is invalid")
        plugin_ids.add(plugin_id)
        plugins.append(
            MappingProxyType(
                {
                    "plugin_id": plugin_id,
                    "version": plugin_version,
                    "manifest_sha256": manifest_hash.casefold(),
                }
            )
        )

    catalog_fingerprint = _bounded_text(
        data["catalog_fingerprint"], "profile.catalog_fingerprint"
    )
    assert catalog_fingerprint is not None
    if SHA256_PATTERN.fullmatch(catalog_fingerprint) is None:
        raise EnvironmentProfileError("profile.catalog_fingerprint is invalid")

    discovery = _closed_object(
        data["discovery_targets"],
        "profile.discovery_targets",
        required={"component_versions", "plugin_manifests", "catalogs"},
    )
    component_version_values = discovery["component_versions"]
    if (
        not isinstance(component_version_values, list)
        or len(component_version_values) > MAX_COMPONENTS
    ):
        raise EnvironmentProfileError("component_versions must be a bounded array")
    component_versions: dict[str, Mapping[str, str]] = {}
    for index, value in enumerate(component_version_values):
        name = f"discovery_targets.component_versions[{index}]"
        target = _closed_object(
            value, name, required={"component_id", "path", "format"}
        )
        component_id = _bounded_text(target["component_id"], f"{name}.component_id")
        path = _stable_path(target["path"], f"{name}.path")
        target_format = target["format"]
        if component_id not in components:
            raise EnvironmentProfileError(f"{name}.component_id is unknown")
        if component_id in component_versions:
            raise EnvironmentProfileError(f"duplicate component version target: {component_id}")
        if target_format not in {"text", "json_version"}:
            raise EnvironmentProfileError(f"{name}.format is unsupported")
        component_versions[component_id] = MappingProxyType(
            {"path": path, "format": target_format}
        )
    missing_version_targets = set(components) - set(component_versions)
    if missing_version_targets:
        raise EnvironmentProfileError(
            "discovery targets are missing component versions: "
            + ", ".join(sorted(missing_version_targets))
        )

    plugin_manifest_values = discovery["plugin_manifests"]
    if not isinstance(plugin_manifest_values, list) or len(plugin_manifest_values) > MAX_COMPONENTS:
        raise EnvironmentProfileError("plugin_manifests must be a bounded array")
    plugin_manifests: dict[str, str] = {}
    for index, value in enumerate(plugin_manifest_values):
        name = f"discovery_targets.plugin_manifests[{index}]"
        target = _closed_object(value, name, required={"plugin_id", "path"})
        plugin_id = _bounded_text(target["plugin_id"], f"{name}.plugin_id")
        path = _stable_path(target["path"], f"{name}.path")
        if plugin_id not in plugin_ids:
            raise EnvironmentProfileError(f"{name}.plugin_id is unknown")
        if plugin_id in plugin_manifests:
            raise EnvironmentProfileError(f"duplicate plugin manifest target: {plugin_id}")
        plugin_manifests[plugin_id] = path
    missing_plugin_targets = plugin_ids - set(plugin_manifests)
    if missing_plugin_targets:
        raise EnvironmentProfileError(
            "discovery targets are missing plugin manifests: "
            + ", ".join(sorted(missing_plugin_targets))
        )

    catalog_values = discovery["catalogs"]
    if not isinstance(catalog_values, list) or not 1 <= len(catalog_values) <= MAX_COMPONENTS:
        raise EnvironmentProfileError("catalogs must be a bounded non-empty array")
    catalogs: dict[str, str] = {}
    for index, value in enumerate(catalog_values):
        name = f"discovery_targets.catalogs[{index}]"
        target = _closed_object(value, name, required={"catalog_id", "path"})
        catalog_id = _bounded_text(target["catalog_id"], f"{name}.catalog_id")
        path = _stable_path(target["path"], f"{name}.path")
        assert catalog_id is not None
        if catalog_id in catalogs:
            raise EnvironmentProfileError(f"duplicate catalog target: {catalog_id}")
        catalogs[catalog_id] = path

    workflow_values = data["workflows"]
    if not isinstance(workflow_values, list) or not 1 <= len(workflow_values) <= MAX_WORKFLOWS:
        raise EnvironmentProfileError("workflows must be a bounded non-empty array")
    workflows: dict[str, WorkflowProfile] = {}
    for index, value in enumerate(workflow_values):
        name = f"workflows[{index}]"
        workflow = _closed_object(
            value,
            name,
            required={"workflow_id", "required_components", "optional_components"},
        )
        workflow_id = _bounded_text(workflow["workflow_id"], f"{name}.workflow_id")
        assert workflow_id is not None
        if workflow_id in workflows:
            raise EnvironmentProfileError(f"duplicate workflow_id: {workflow_id}")
        collections: list[tuple[str, tuple[str, ...]]] = []
        for field in ("required_components", "optional_components"):
            values = workflow[field]
            if not isinstance(values, list) or len(values) > MAX_COMPONENTS:
                raise EnvironmentProfileError(f"{name}.{field} must be a bounded array")
            if any(not isinstance(item, str) or item not in components for item in values):
                raise EnvironmentProfileError(f"{name}.{field} names an unknown component")
            if len(values) != len(set(values)):
                raise EnvironmentProfileError(f"{name}.{field} contains duplicates")
            collections.append((field, tuple(values)))
        required_components = collections[0][1]
        optional_components = collections[1][1]
        if not required_components:
            raise EnvironmentProfileError(f"{name} must require at least one component")
        if set(required_components) & set(optional_components):
            raise EnvironmentProfileError(f"{name} component roles overlap")
        workflows[workflow_id] = WorkflowProfile(
            workflow_id, required_components, optional_components
        )

    return EnvironmentProfile(
        schema_version=SCHEMA_VERSION,
        profile_id=profile_id,
        compatibility_profile_id=compatibility_id,
        created_at=created_at,
        components=MappingProxyType(components),
        repositories=tuple(repositories),
        plugins=tuple(plugins),
        catalog_fingerprint=catalog_fingerprint.casefold(),
        discovery_targets=DiscoveryTargets(
            component_versions=MappingProxyType(component_versions),
            plugin_manifests=MappingProxyType(plugin_manifests),
            catalogs=MappingProxyType(catalogs),
        ),
        workflows=MappingProxyType(workflows),
    )


def evaluate_environment_profile(profile: EnvironmentProfile) -> dict[str, object]:
    """Return deterministic component proof levels and fail-closed workflow eligibility."""

    component_results: dict[str, object] = {}
    for component_id in sorted(profile.components):
        component = profile.components[component_id]
        component_results[component_id] = {
            "capability_level": component.capability_level,
            "workflow_eligible": component.workflow_eligible,
            "passed_proofs": [
                name for name in CHECK_NAMES if component.checks[name].status == "passed"
            ],
        }
    workflow_results: dict[str, object] = {}
    for workflow_id in sorted(profile.workflows):
        workflow = profile.workflows[workflow_id]
        blockers = sorted(
            f"COMPONENT_NOT_WORKFLOW_ELIGIBLE:{component_id}"
            for component_id in workflow.required_components
            if not profile.components[component_id].workflow_eligible
        )
        workflow_results[workflow_id] = {
            "eligible": not blockers,
            "required_components": list(workflow.required_components),
            "optional_components": list(workflow.optional_components),
            "blockers": blockers,
        }
    return {
        "schema_version": "kcd2.environment-capability-evaluation.v1",
        "profile_id": profile.profile_id,
        "compatibility_profile_id": profile.compatibility_profile_id,
        "components": component_results,
        "interpreters": {
            "current": "python_current",
            "isolated": "pyghidra_isolated",
        },
        "workflows": workflow_results,
    }
