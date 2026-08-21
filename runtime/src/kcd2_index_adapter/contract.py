"""Version-locked validation for the captured KCD2 Index MCP contract."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.index_contract import validate_concrete_input_schema


_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = {
    "schema_version",
    "runtime_identity",
    "server_schema",
    "client_exposure",
    "classification",
}
_RUNTIME_IDENTITY_FIELDS = {
    "plugin_id",
    "plugin_version",
    "runtime_version",
    "executable_sha256",
    "deployment_manifest_sha256",
    "server_name",
    "server_version",
    "protocol_version",
}
_TOOL_FIELDS = {"name", "description", "input_schema", "annotations"}
_RAW_TOOL_FIELDS = {"name", "description", "inputSchema", "annotations"}
_ANNOTATION_FIELDS = {
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "readOnlyHint",
}


class ContractMismatchError(RuntimeError):
    """The runtime or discovery catalog does not match the reviewed capture."""


def _require_mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise ContractMismatchError(f"{path} must be an object with string keys")
    return value


def _canonical_copy(value: object, path: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return json.loads(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ContractMismatchError(f"{path} is not bounded JSON-compatible data") from exc


@dataclass(frozen=True, slots=True)
class ToolContract:
    name: str
    description: str
    input_schema: Mapping[str, Any]
    annotations: Mapping[str, Any]

    def as_raw_tool(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": _canonical_copy(self.input_schema, f"tool {self.name} schema"),
            "annotations": _canonical_copy(self.annotations, f"tool {self.name} annotations"),
        }


@dataclass(frozen=True, slots=True)
class IndexContract:
    runtime_executable_sha256: str
    deployment_manifest_sha256: str
    server_name: str
    server_version: str
    protocol_version: str
    tools: tuple[ToolContract, ...]
    source_path: Path
    schema_version: str = "kcd2.index-tools-contract.v1"

    @classmethod
    def load(cls, path: Path) -> "IndexContract":
        """Load one reviewed normalized capture and reject any ambiguous contract state."""

        try:
            decoded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContractMismatchError(f"cannot load Index contract: {exc}") from exc
        root = _require_mapping(decoded, "contract")
        if set(root) != _TOP_LEVEL_FIELDS:
            raise ContractMismatchError("normalized contract top-level fields do not match v1")
        if root.get("schema_version") != "kcd2.index-tools-contract.v1":
            raise ContractMismatchError("unsupported normalized Index contract version")

        classification = _require_mapping(root["classification"], "classification")
        if (
            classification.get("cause") != "match"
            or classification.get("capture_complete") is not True
            or classification.get("runtime_identity_matches") is not True
            or classification.get("server_schema_valid") is not True
            or classification.get("trial_tool_calls_required") is not False
        ):
            raise ContractMismatchError("captured Index contract is not an approved match")

        identity = _require_mapping(root["runtime_identity"], "runtime_identity")
        if set(identity) != _RUNTIME_IDENTITY_FIELDS:
            raise ContractMismatchError(
                "runtime identity fields do not match the reviewed contract"
            )
        for field in _RUNTIME_IDENTITY_FIELDS:
            if not isinstance(identity[field], str) or not identity[field]:
                raise ContractMismatchError(f"runtime_identity.{field} must be a non-empty string")
        for field in ("executable_sha256", "deployment_manifest_sha256"):
            if not _SHA256_PATTERN.fullmatch(identity[field]):
                raise ContractMismatchError(f"runtime_identity.{field} must be lowercase SHA-256")
        if identity["plugin_id"] != identity["server_name"]:
            raise ContractMismatchError("plugin and initialize server names differ in the capture")
        if identity["runtime_version"] != identity["server_version"]:
            raise ContractMismatchError(
                "runtime and initialize server versions differ in the capture"
            )

        server_schema = _require_mapping(root["server_schema"], "server_schema")
        if set(server_schema) != {"tool_count", "tool_names", "schema_errors", "tools"}:
            raise ContractMismatchError("server_schema fields do not match the reviewed contract")
        if server_schema["schema_errors"] != {}:
            raise ContractMismatchError("captured server schema contains validation errors")
        raw_tools = server_schema["tools"]
        if not isinstance(raw_tools, list) or not raw_tools:
            raise ContractMismatchError("server_schema.tools must be a non-empty array")

        tools: list[ToolContract] = []
        for index, value in enumerate(raw_tools):
            tool = _require_mapping(value, f"server_schema.tools[{index}]")
            if set(tool) != _TOOL_FIELDS:
                raise ContractMismatchError(f"server_schema.tools[{index}] fields changed")
            name = tool["name"]
            description = tool["description"]
            if not isinstance(name, str) or not name.startswith("kcd2_"):
                raise ContractMismatchError(f"server_schema.tools[{index}].name is invalid")
            if not isinstance(description, str):
                raise ContractMismatchError(f"server_schema.tools[{index}].description is invalid")
            input_schema = _require_mapping(tool["input_schema"], f"tool {name} input schema")
            schema_errors = validate_concrete_input_schema(input_schema)
            if schema_errors:
                raise ContractMismatchError(
                    f"tool {name} input schema is not concrete: {schema_errors[0]}"
                )
            annotations = _require_mapping(tool["annotations"], f"tool {name} annotations")
            if set(annotations) != _ANNOTATION_FIELDS:
                raise ContractMismatchError(f"tool {name} annotations changed")
            if (
                annotations.get("readOnlyHint") is not True
                or annotations.get("destructiveHint") is not False
            ):
                raise ContractMismatchError(f"tool {name} is not declared read-only")
            tools.append(
                ToolContract(
                    name=name,
                    description=description,
                    input_schema=_canonical_copy(input_schema, f"tool {name} input schema"),
                    annotations=_canonical_copy(annotations, f"tool {name} annotations"),
                )
            )

        names = [tool.name for tool in tools]
        if len(names) != len(set(names)):
            raise ContractMismatchError("captured Index tool names are not unique")
        if server_schema["tool_count"] != len(tools):
            raise ContractMismatchError("captured Index tool count is inconsistent")
        if server_schema["tool_names"] != sorted(names):
            raise ContractMismatchError("captured Index tool name list is inconsistent")
        if names != sorted(names):
            raise ContractMismatchError("normalized Index tools are not deterministically sorted")

        client_exposure = _require_mapping(root["client_exposure"], "client_exposure")
        if client_exposure.get("server_tool_names") != sorted(names):
            raise ContractMismatchError("captured client exposure differs from the server catalog")
        if client_exposure.get("tool_count") != len(tools):
            raise ContractMismatchError("captured client exposure count is inconsistent")

        return cls(
            runtime_executable_sha256=identity["executable_sha256"],
            deployment_manifest_sha256=identity["deployment_manifest_sha256"],
            server_name=identity["server_name"],
            server_version=identity["server_version"],
            protocol_version=identity["protocol_version"],
            tools=tuple(tools),
            source_path=path.resolve(),
        )

    @property
    def tool_names(self) -> frozenset[str]:
        return frozenset(tool.name for tool in self.tools)

    def validate_initialize(self, result: object) -> None:
        initialize = _require_mapping(result, "initialize result")
        server_info = _require_mapping(initialize.get("serverInfo"), "initialize serverInfo")
        observed = (
            initialize.get("protocolVersion"),
            server_info.get("name"),
            server_info.get("version"),
        )
        expected = (self.protocol_version, self.server_name, self.server_version)
        if observed != expected:
            raise ContractMismatchError(
                "initialize runtime identity does not match the locked contract"
            )

    def validate_tools_list(self, result: object) -> None:
        tools_result = _require_mapping(result, "tools/list result")
        if set(tools_result) != {"tools"}:
            raise ContractMismatchError("tools/list result fields changed")
        observed = tools_result["tools"]
        if not isinstance(observed, list):
            raise ContractMismatchError("tools/list tools must be an array")
        normalized: list[dict[str, Any]] = []
        for index, value in enumerate(observed):
            tool = _require_mapping(value, f"tools/list tools[{index}]")
            if set(tool) != _RAW_TOOL_FIELDS:
                raise ContractMismatchError(f"tools/list tool[{index}] fields changed")
            normalized.append(_canonical_copy(tool, f"tools/list tool[{index}]"))
        if any(not isinstance(tool.get("name"), str) for tool in normalized):
            raise ContractMismatchError("tools/list contains an invalid tool name")
        normalized.sort(key=lambda tool: tool["name"])
        expected = [tool.as_raw_tool() for tool in self.tools]
        if normalized != expected:
            raise ContractMismatchError("tools/list does not match the locked schema")
