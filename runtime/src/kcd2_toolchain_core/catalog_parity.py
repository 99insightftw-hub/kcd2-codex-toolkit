"""Generate and verify public plugin catalog, schema, skill, and payload parity."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from kcd2_mod_build_deploy.mcp_server import ModBuildDeployMcpServer
from kcd2_native_probes.mcp_server import NativeProbesMcpServer
from kcd2_research_graph.mcp_server import ResearchGraphMcpServer

from .plugin_surface import _schema_errors


GENERATED_SCHEMA = "kcd2.generated-public-tool-catalog.v1"
BEGIN_MARKER = "<!-- BEGIN GENERATED PUBLIC TOOLS: API-004 -->"
END_MARKER = "<!-- END GENERATED PUBLIC TOOLS: API-004 -->"


class CatalogParityError(ValueError):
    """Raised when any claimed public plugin surface differs from its payload."""


@dataclass(frozen=True)
class _PluginSpec:
    name: str
    plugin_root: Path
    schema_path: Path
    skill_paths: tuple[Path, ...]
    surface_path: Path | None
    server_type: type[Any]
    server_root_attribute: str
    runtime_module: Path


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _specs(root: Path) -> tuple[_PluginSpec, ...]:
    return (
        _PluginSpec(
            "kcd2-mod-build-deploy",
            root / "plugins/kcd2-mod-build-deploy",
            root / "plugins/kcd2-mod-build-deploy/generated/public-tool-schemas.json",
            (root / "plugins/kcd2-mod-build-deploy/skills/analyze-kcd2-mod/SKILL.md",),
            root / "examples/mod-build-deploy-plugin-tool-surface.example.json",
            ModBuildDeployMcpServer,
            "root",
            root / "src/kcd2_mod_build_deploy/mcp_server.py",
        ),
        _PluginSpec(
            "kcd2-native-probes",
            root / "plugins/kcd2-native-probes",
            root / "plugins/kcd2-native-probes/generated/public-tool-schemas.json",
            (root / "plugins/kcd2-native-probes/skills/capture-kcd2-native-probes/SKILL.md",),
            root / "examples/native-probes-plugin-tool-surface.example.json",
            NativeProbesMcpServer,
            "repository_root",
            root / "src/kcd2_native_probes/mcp_server.py",
        ),
        _PluginSpec(
            "kcd2-research-graph",
            root / "plugins/kcd2-research-graph",
            root / "plugins/kcd2-research-graph/generated/public-tool-schemas.json",
            (),
            None,
            ResearchGraphMcpServer,
            "repository_root",
            root / "src/kcd2_research_graph/mcp_server.py",
        ),
    )


def _fresh_tools(spec: _PluginSpec, root: Path) -> list[dict[str, Any]]:
    server = spec.server_type(root)
    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    if not isinstance(response, Mapping) or not isinstance(response.get("result"), Mapping):
        raise CatalogParityError(f"{spec.name}: fresh tools/list failed")
    tools = response["result"].get("tools")
    if not isinstance(tools, list) or not tools:
        raise CatalogParityError(f"{spec.name}: fresh tools/list returned no tools")
    return copy.deepcopy(tools)


def _validate_tools(plugin: str, tools: list[dict[str, Any]]) -> None:
    names: list[str] = []
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str) or not name:
            raise CatalogParityError(f"{plugin}: invalid public tool name")
        names.append(name)
        for field, input_schema in (("inputSchema", True), ("outputSchema", False)):
            errors = _schema_errors(tool.get(field), input_schema=input_schema)
            if errors:
                raise CatalogParityError(
                    f"{plugin}.{name}: {field} is not a concrete schema: {errors[0]}"
                )
    if len(names) != len(set(names)):
        raise CatalogParityError(f"{plugin}: duplicate public tool names")


def _source_records(spec: _PluginSpec, root: Path) -> list[dict[str, str]]:
    records = [{
        "module_or_symbol": spec.runtime_module.relative_to(root).as_posix(),
        "source_sha256": _sha256(spec.runtime_module.read_bytes()),
    }]
    if spec.surface_path is None:
        return records
    surface = json.loads(spec.surface_path.read_text(encoding="utf-8"))
    for tool in surface["tools"]:
        binding = tool["library_binding"]
        module_name = binding["module_or_symbol"].split(":", 1)[0]
        source_path = root / "src" / Path(*module_name.split(".")).with_suffix(".py")
        actual = _sha256(source_path.read_bytes())
        if actual.lower() != binding["source_sha256"].lower():
            raise CatalogParityError(
                f"{spec.name}.{tool['tool_name']}: claimed source hash differs from repository"
            )
        records.append({
            "module_or_symbol": binding["module_or_symbol"],
            "source_sha256": actual,
        })
    return sorted(records, key=lambda item: item["module_or_symbol"])


def _tool_section(tools: list[dict[str, Any]]) -> str:
    lines = [BEGIN_MARKER, "", "## Generated public tool catalog", ""]
    for tool in tools:
        schema = tool["inputSchema"]
        required = set(schema.get("required", []))
        arguments = []
        for name in schema.get("properties", {}):
            arguments.append(f"`{name}` ({'required' if name in required else 'optional'})")
        rendered = ", ".join(arguments) if arguments else "no arguments"
        lines.append(f"- `{tool['name']}` — {rendered}")
        lines.append("")
    lines.extend([END_MARKER, ""])
    return "\n".join(lines)


def _replace_section(original: str, section: str) -> str:
    if BEGIN_MARKER not in original and END_MARKER not in original:
        return original.rstrip() + "\n\n" + section
    if original.count(BEGIN_MARKER) != 1 or original.count(END_MARKER) != 1:
        raise CatalogParityError("generated skill markers are malformed")
    before, remainder = original.split(BEGIN_MARKER, 1)
    _, after = remainder.split(END_MARKER, 1)
    return before.rstrip() + "\n\n" + section.rstrip() + "\n" + after.lstrip("\n")


def generate_public_artifacts(repository_root: Path | str) -> dict[Path, bytes]:
    """Return deterministic public schema and skill bytes derived from fresh tools/list."""
    root = Path(repository_root).resolve()
    generated: dict[Path, bytes] = {}
    for spec in _specs(root):
        tools = _fresh_tools(spec, root)
        _validate_tools(spec.name, tools)
        sources = _source_records(spec, root)
        catalog_hash = _sha256(_canonical(tools))
        source_revision = _sha256(_canonical({"catalog_sha256": catalog_hash, "sources": sources}))
        document = {
            "schema_version": GENERATED_SCHEMA,
            "plugin": spec.name,
            "catalog_sha256": catalog_hash,
            "source_revision_sha256": source_revision,
            "sources": sources,
            "tools": tools,
        }
        generated[spec.schema_path] = _canonical(document)
        section = _tool_section(tools)
        for skill_path in spec.skill_paths:
            generated[skill_path] = _replace_section(
                skill_path.read_text(encoding="utf-8"), section
            ).encode("utf-8")
    return generated


def _mapping_covers(root: Path, mapping: Mapping[str, Any], source_path: Path) -> bool:
    source = (root / str(mapping.get("source", ""))).resolve()
    return source_path == source or source in source_path.parents


def verify_repository_parity(
    repository_root: Path | str,
    *,
    expected_artifacts: Mapping[Path, bytes] | None = None,
) -> dict[str, Any]:
    """Fail closed unless catalogs, generated artifacts, and package mappings agree."""
    root = Path(repository_root).resolve()
    canonical = generate_public_artifacts(root)
    expected = dict(canonical if expected_artifacts is None else expected_artifacts)
    plugins: list[dict[str, Any]] = []
    for spec in _specs(root):
        expected_schema = expected.get(spec.schema_path)
        if expected_schema is None:
            raise CatalogParityError(f"{spec.name}: generated schema artifact is missing")
        document = json.loads(expected_schema.decode("utf-8"))
        _validate_tools(spec.name, document.get("tools", []))
        for path in (spec.schema_path, *spec.skill_paths):
            current_matches = path.is_file() and path.read_bytes() == canonical[path]
            if expected.get(path) != canonical[path] or not current_matches:
                raise CatalogParityError(f"{spec.name}: generated artifact drift: {path}")

        tools = _fresh_tools(spec, root)
        names = [item["name"] for item in tools]
        recipe_path = spec.plugin_root / "deployment-manifest.json"
        recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
        if sorted(recipe["catalog"]["tools"]) != sorted(names):
            raise CatalogParityError(f"{spec.name}: deployment catalog differs from tools/list")
        plugin_json = json.loads(
            (spec.plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
        )
        if plugin_json.get("version") != recipe.get("plugin", {}).get("version"):
            raise CatalogParityError(
                f"{spec.name}: plugin version claim differs from package recipe"
            )
        mappings = recipe.get("source_mappings", [])
        claimed_paths = [spec.runtime_module, spec.schema_path, *spec.skill_paths]
        if not all(
            any(_mapping_covers(root, item, path) for item in mappings)
            for path in claimed_paths
        ):
            raise CatalogParityError(
                f"{spec.name}: claimed runtime/generated payload is not bundled"
            )
        plugins.append({
            "plugin": spec.name,
            "version": plugin_json["version"],
            "tool_count": len(names),
            "catalog_sha256": document["catalog_sha256"],
            "source_revision_sha256": document["source_revision_sha256"],
            "new_session_visibility": "PASS",
            "installed_payload_binding": "PASS",
        })
    body = {
        "schema_version": "kcd2.plugin-catalog-parity-receipt.v1",
        "verdict": "PASS",
        "evidence_layer": "source_controlled_catalog_and_staged_payload",
        "plugins": plugins,
    }
    return {**body, "receipt_sha256": _sha256(_canonical(body))}


def verify_staged_payload_parity(
    repository_root: Path | str,
    stage_root: Path | str,
    plugin_name: str,
    visible_tools: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bind a clean staged payload and a new MCP process's tools/list to source control."""
    root = Path(repository_root).resolve()
    stage = Path(stage_root).resolve()
    matches = [item for item in _specs(root) if item.name == plugin_name]
    if len(matches) != 1:
        raise CatalogParityError(f"unknown governed plugin: {plugin_name}")
    spec = matches[0]
    _validate_tools(plugin_name, visible_tools)
    generated = json.loads(
        (stage / "generated/public-tool-schemas.json").read_text(encoding="utf-8")
    )
    if visible_tools != generated.get("tools"):
        raise CatalogParityError(
            f"{plugin_name}: new-session tools/list differs from staged schemas"
        )
    if (stage / "generated/public-tool-schemas.json").read_bytes() != spec.schema_path.read_bytes():
        raise CatalogParityError(f"{plugin_name}: staged generated schemas differ from source")
    for skill in spec.skill_paths:
        relative = skill.relative_to(spec.plugin_root)
        if (stage / relative).read_bytes() != skill.read_bytes():
            raise CatalogParityError(f"{plugin_name}: staged skill differs from source")
    for source in generated.get("sources", []):
        identity = source["module_or_symbol"]
        if ":" in identity:
            module = identity.split(":", 1)[0]
            payload_path = stage / "runtime/src" / Path(*module.split(".")).with_suffix(".py")
        else:
            repository_path = Path(identity)
            if not repository_path.parts or repository_path.parts[0] != "src":
                raise CatalogParityError(f"{plugin_name}: invalid runtime source identity")
            payload_path = stage / "runtime" / repository_path
        payload_matches = (
            payload_path.is_file()
            and _sha256(payload_path.read_bytes()) == source["source_sha256"]
        )
        if not payload_matches:
            raise CatalogParityError(
                f"{plugin_name}: staged runtime source binding failed: {identity}"
            )
    return {
        "plugin": plugin_name,
        "tool_count": len(visible_tools),
        "catalog_sha256": generated["catalog_sha256"],
        "source_revision_sha256": generated["source_revision_sha256"],
        "new_session_visibility": "PASS",
        "installed_payload_binding": "PASS",
    }


__all__ = [
    "CatalogParityError",
    "generate_public_artifacts",
    "verify_repository_parity",
    "verify_staged_payload_parity",
]
