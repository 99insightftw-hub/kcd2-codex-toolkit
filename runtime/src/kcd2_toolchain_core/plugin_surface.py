"""Contract checks for schema-backed public plugin tool registrations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Mapping, Set as AbstractSet
from dataclasses import dataclass
from typing import Any, Literal


ApprovalClass = Literal["none", "build", "install", "rollback"]


class ToolSurfaceContractError(ValueError):
    """Raised when a library operation is not safely represented by the public surface."""


@dataclass(frozen=True, slots=True)
class PublicTool:
    """The metadata visible at the actual plugin/MCP registration boundary."""

    handler: Callable[..., Mapping[str, Any]]
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    approval_class: ApprovalClass
    module_or_symbol: str
    source_sha256: str


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _expected_approval(operation_class: str) -> ApprovalClass:
    approvals: dict[str, ApprovalClass] = {
        "read_only_analysis": "none",
        "build_write": "build",
        "install_write": "install",
        "rollback_write": "rollback",
    }
    try:
        return approvals[operation_class]
    except KeyError as error:
        raise ToolSurfaceContractError(f"unsupported operation class: {operation_class}") from error


def _schema_errors(schema: object, *, input_schema: bool) -> tuple[str, ...]:
    """Return deterministic errors for the bounded public JSON Schema subset."""

    errors: list[str] = []

    def visit(node: object, path: str, *, require_default: bool = False) -> None:
        if not isinstance(node, Mapping) or not node:
            errors.append(f"{path}: schema must be a non-empty object")
            return
        if require_default and "default" not in node:
            errors.append(f"{path}: optional input property requires a default")

        branches_present = False
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in node:
                continue
            branches_present = True
            branches = node[keyword]
            if not isinstance(branches, list) or not branches:
                errors.append(f"{path}.{keyword}: must be a non-empty schema array")
                continue
            for index, branch in enumerate(branches):
                visit(branch, f"{path}.{keyword}[{index}]")

        declared = node.get("type")
        declared_types = {declared} if isinstance(declared, str) else set()
        if (
            isinstance(declared, list)
            and declared
            and all(isinstance(item, str) for item in declared)
        ):
            declared_types = set(declared)
        if not declared_types and not branches_present:
            errors.append(f"{path}: schema requires an explicit type or composition")
            return
        supported = {"array", "boolean", "integer", "null", "number", "object", "string"}
        if declared_types - supported:
            errors.append(f"{path}.type: unsupported values {sorted(declared_types - supported)!r}")

        if "object" in declared_types:
            properties = node.get("properties")
            if not isinstance(properties, Mapping):
                errors.append(f"{path}.properties: object schemas require a properties object")
                properties = {}
            required = node.get("required", [])
            if not isinstance(required, list) or not all(
                isinstance(item, str) for item in required
            ):
                errors.append(f"{path}.required: must be a string array")
                required_names: set[str] = set()
            else:
                required_names = set(required)
                if len(required_names) != len(required):
                    errors.append(f"{path}.required: entries must be unique")
                missing = required_names - set(properties)
                if missing:
                    errors.append(f"{path}.required: unknown properties {sorted(missing)!r}")
            for name, child in properties.items():
                if not isinstance(name, str):
                    errors.append(f"{path}.properties: names must be strings")
                    continue
                visit(
                    child,
                    f"{path}.properties.{name}",
                    require_default=input_schema and name not in required_names,
                )
            additional = node.get("additionalProperties")
            if additional is not False:
                if not isinstance(additional, Mapping):
                    errors.append(f"{path}: object schema must close additionalProperties")
                else:
                    if not isinstance(node.get("maxProperties"), int):
                        errors.append(f"{path}: extensible object requires maxProperties")
                    names = node.get("propertyNames")
                    if not isinstance(names, Mapping) or not isinstance(
                        names.get("maxLength"), int
                    ):
                        errors.append(f"{path}: extensible object requires bounded propertyNames")
                    visit(additional, f"{path}.additionalProperties")

        if "array" in declared_types:
            if not isinstance(node.get("maxItems"), int):
                errors.append(f"{path}: array schema requires maxItems")
            if "items" not in node:
                errors.append(f"{path}: array schema requires items")
            else:
                visit(node["items"], f"{path}.items")

        if "string" in declared_types:
            fixed = "const" in node or "enum" in node
            if not fixed and not isinstance(node.get("maxLength"), int):
                errors.append(f"{path}: string schema requires maxLength")
        if declared_types & {"integer", "number"}:
            if "minimum" not in node or "maximum" not in node:
                errors.append(f"{path}: numeric schema requires minimum and maximum")

    visit(schema, "$")
    if isinstance(schema, Mapping):
        if schema.get("type") != "object":
            errors.append("$: public tool schema type must be object")
        if schema.get("additionalProperties") is not False:
            errors.append("$: public tool schema must set additionalProperties to false")
    return tuple(errors)


def _instance_errors(value: object, schema: Mapping[str, Any], path: str = "$") -> tuple[str, ...]:
    """Validate examples and results against the supported schema subset."""

    errors: list[str] = []
    if "allOf" in schema:
        for branch in schema["allOf"]:
            errors.extend(_instance_errors(value, branch, path))
    if "anyOf" in schema and not any(
        not _instance_errors(value, branch, path) for branch in schema["anyOf"]
    ):
        errors.append(f"{path}: does not match anyOf")
    if "oneOf" in schema:
        matches = sum(not _instance_errors(value, branch, path) for branch in schema["oneOf"])
        if matches != 1:
            errors.append(f"{path}: matches {matches} oneOf branches")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: does not match const")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: is not in enum")

    declared = schema.get("type")
    types = [declared] if isinstance(declared, str) else declared or []
    matches_type = {
        "array": lambda item: isinstance(item, list),
        "boolean": lambda item: isinstance(item, bool),
        "integer": lambda item: isinstance(item, int) and not isinstance(item, bool),
        "null": lambda item: item is None,
        "number": lambda item: isinstance(item, (int, float)) and not isinstance(item, bool),
        "object": lambda item: isinstance(item, Mapping),
        "string": lambda item: isinstance(item, str),
    }
    if types and not any(matches_type[item](value) for item in types):
        return (*errors, f"{path}: unexpected type")

    if isinstance(value, Mapping) and "object" in types:
        properties = schema.get("properties", {})
        missing = set(schema.get("required", [])) - set(value)
        if missing:
            errors.append(f"{path}: missing required properties {sorted(missing)!r}")
        for name, child in value.items():
            child_schema = properties.get(name, schema.get("additionalProperties", True))
            if child_schema is False:
                errors.append(f"{path}: unknown property {name}")
            elif isinstance(child_schema, Mapping):
                errors.extend(_instance_errors(child, child_schema, f"{path}.{name}"))
        maximum = schema.get("maxProperties")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path}: too many properties")
    if isinstance(value, list) and "array" in types:
        maximum = schema.get("maxItems")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path}: too many items")
        if isinstance(schema.get("items"), Mapping):
            for index, item in enumerate(value):
                errors.extend(_instance_errors(item, schema["items"], f"{path}[{index}]"))
    if isinstance(value, str) and "string" in types:
        maximum = schema.get("maxLength")
        if isinstance(maximum, int) and len(value) > maximum:
            errors.append(f"{path}: string exceeds maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, value) is None:
            errors.append(f"{path}: string does not match pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: number is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: number exceeds maximum")
    return tuple(errors)


def smoke_test_public_surface(
    manifest: Mapping[str, Any],
    registry: Mapping[str, PublicTool],
    *,
    supported_library_operations: AbstractSet[str],
) -> dict[str, Any]:
    """Discover registrations and invoke only read-only examples through the public registry.

    ``supported_library_operations`` is the reviewed library inventory. Every name must have a
    manifest record and must be registered; a Python import is deliberately not accepted here.
    Write-class handlers are metadata-checked but never invoked by this non-live harness.
    """

    records = {str(record["tool_name"]): record for record in manifest.get("tools", [])}
    if len(records) != len(manifest.get("tools", [])):
        raise ToolSurfaceContractError("duplicate tool names in manifest")
    missing = sorted(supported_library_operations - records.keys())
    if missing:
        raise ToolSurfaceContractError(f"missing library operations: {', '.join(missing)}")

    results: list[dict[str, Any]] = []
    for name in sorted(records):
        record = records[name]
        if name in supported_library_operations and record["exposure_status"] != "REGISTERED":
            raise ToolSurfaceContractError(f"supported operation is not exposed: {name}")
        if record["exposure_status"] == "NOT_EXPOSED_WITH_REASON":
            reason = record.get("not_exposed_reason")
            if not isinstance(reason, Mapping) or not reason.get("reason"):
                raise ToolSurfaceContractError(f"NOT_EXPOSED_WITH_REASON lacks reason: {name}")
            results.append(
                {
                    "tool_name": name,
                    "status": "not_exposed",
                    "invoked_through_public_surface": False,
                    "response_bytes": 0,
                }
            )
            continue

        if record.get("registered") is not True or record.get("callable_via") != "mcp_plugin":
            raise ToolSurfaceContractError(f"registered tool is not an MCP plugin tool: {name}")

        input_errors = _schema_errors(record.get("input_schema"), input_schema=True)
        if input_errors:
            raise ToolSurfaceContractError(
                f"input schema is not concrete: {name}: {'; '.join(input_errors)}"
            )
        output_errors = _schema_errors(record.get("output_schema"), input_schema=False)
        if output_errors:
            raise ToolSurfaceContractError(
                f"output schema is not concrete: {name}: {'; '.join(output_errors)}"
            )
        example_input_errors = _instance_errors(
            record["example"]["input"], record["input_schema"]
        )
        if example_input_errors:
            raise ToolSurfaceContractError(
                f"example input violates schema: {name}: {'; '.join(example_input_errors)}"
            )
        example_output_errors = _instance_errors(
            record["example"]["output"], record["output_schema"]
        )
        if example_output_errors:
            raise ToolSurfaceContractError(
                f"example output violates schema: {name}: {'; '.join(example_output_errors)}"
            )

        public = registry.get(name)
        if public is None:
            raise ToolSurfaceContractError(f"registered tool is not discoverable: {name}")
        expected_approval = _expected_approval(str(record["operation_class"]))
        if record["approval_class"] != expected_approval:
            raise ToolSurfaceContractError(f"manifest approval class mismatch: {name}")
        if public.approval_class != expected_approval:
            raise ToolSurfaceContractError(f"public approval class mismatch: {name}")
        if dict(public.input_schema) != record["input_schema"]:
            raise ToolSurfaceContractError(f"input schema mismatch: {name}")
        if dict(public.output_schema) != record["output_schema"]:
            raise ToolSurfaceContractError(f"output schema mismatch: {name}")
        if public.module_or_symbol != record["library_binding"]["module_or_symbol"]:
            raise ToolSurfaceContractError(f"source symbol mismatch: {name}")
        if public.source_sha256.lower() != record["library_binding"]["source_sha256"].lower():
            raise ToolSurfaceContractError(f"source binding mismatch: {name}")

        invoked = expected_approval == "none"
        smoke = record.get("smoke_test", {})
        if (
            smoke.get("status") != "passed"
            or smoke.get("invoked_through_public_surface") is not invoked
            or not isinstance(smoke.get("receipt_id"), str)
        ):
            raise ToolSurfaceContractError(f"public smoke metadata mismatch: {name}")
        response_bytes = 0
        if invoked:
            output = dict(public.handler(**record["example"]["input"]))
            output_errors = _instance_errors(output, record["output_schema"])
            if output_errors:
                raise ToolSurfaceContractError(
                    f"public output violates schema: {name}: {'; '.join(output_errors)}"
                )
            if output != record["example"]["output"]:
                raise ToolSurfaceContractError(f"public example output mismatch: {name}")
            response_bytes = len(_canonical_bytes(output))
            if response_bytes > record["output_bounds"]["max_response_bytes"]:
                raise ToolSurfaceContractError(f"public response exceeds byte bound: {name}")

        results.append(
            {
                "tool_name": name,
                "status": "passed",
                "invoked_through_public_surface": invoked,
                "response_bytes": response_bytes,
            }
        )

    receipt_body = {
        "schema_version": "kcd2.public-surface-smoke-receipt.v1",
        "plugin": dict(manifest["plugin"]),
        "source_revision": manifest["source_revision"],
        "verdict": "passed",
        "results": results,
    }
    return {
        **receipt_body,
        "receipt_sha256": hashlib.sha256(_canonical_bytes(receipt_body)).hexdigest(),
    }
