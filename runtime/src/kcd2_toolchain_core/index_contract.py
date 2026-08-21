"""Pure validation and mismatch classification for captured Index MCP contracts."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any


_JSON_SCHEMA_TYPES = {"array", "boolean", "integer", "null", "number", "object", "string"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_schema_node(schema: object, path: str, errors: list[str]) -> None:
    if not isinstance(schema, Mapping):
        errors.append(f"{path}: schema must be an object")
        return
    if not schema:
        errors.append(f"{path}: unconstrained empty schemas are not concrete")
        return

    declared_type = schema.get("type")
    types: set[str] = set()
    if declared_type is not None:
        if isinstance(declared_type, str):
            types = {declared_type}
        elif isinstance(declared_type, list) and all(
            isinstance(item, str) for item in declared_type
        ):
            types = set(declared_type)
            if len(types) != len(declared_type):
                errors.append(f"{path}.type: entries must be unique")
        else:
            errors.append(f"{path}.type: must be a string or string array")
        unknown = types - _JSON_SCHEMA_TYPES
        if unknown:
            errors.append(f"{path}.type: unsupported values {sorted(unknown)!r}")

    properties = schema.get("properties")
    if properties is not None:
        if not isinstance(properties, Mapping):
            errors.append(f"{path}.properties: must be an object")
        else:
            for name, child in properties.items():
                if not isinstance(name, str):
                    errors.append(f"{path}.properties: names must be strings")
                    continue
                _validate_schema_node(child, f"{path}.properties.{name}", errors)

    required = schema.get("required")
    if required is not None:
        if not isinstance(required, list) or not all(isinstance(item, str) for item in required):
            errors.append(f"{path}.required: must be a string array")
        elif len(set(required)) != len(required):
            errors.append(f"{path}.required: entries must be unique")
        elif isinstance(properties, Mapping):
            missing = set(required) - set(properties)
            if missing:
                errors.append(f"{path}.required: unknown properties {sorted(missing)!r}")

    if "items" in schema:
        _validate_schema_node(schema["items"], f"{path}.items", errors)

    additional = schema.get("additionalProperties")
    if additional is not None and not isinstance(additional, bool):
        _validate_schema_node(additional, f"{path}.additionalProperties", errors)

    for keyword in ("allOf", "anyOf", "oneOf"):
        if keyword not in schema:
            continue
        branches = schema[keyword]
        if not isinstance(branches, list) or not branches:
            errors.append(f"{path}.{keyword}: must be a non-empty schema array")
            continue
        for index, branch in enumerate(branches):
            _validate_schema_node(branch, f"{path}.{keyword}[{index}]", errors)

    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or not enum:
            errors.append(f"{path}.enum: must be a non-empty array")
        elif any(item == previous for index, item in enumerate(enum) for previous in enum[:index]):
            errors.append(f"{path}.enum: entries must be unique")

    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            errors.append(f"{path}.pattern: must be a string")
        else:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"{path}.pattern: invalid regular expression: {exc}")

    bounded_pairs = (("minLength", "maxLength"), ("minItems", "maxItems"))
    for keyword in (item for pair in bounded_pairs for item in pair):
        value = schema.get(keyword)
        if value is not None and (not _is_int(value) or value < 0):
            errors.append(f"{path}.{keyword}: must be a non-negative integer")
    for minimum, maximum in bounded_pairs:
        if (
            _is_int(schema.get(minimum))
            and _is_int(schema.get(maximum))
            and schema[minimum] > schema[maximum]
        ):
            errors.append(f"{path}: {minimum} exceeds {maximum}")

    for keyword in ("minimum", "maximum"):
        value = schema.get(keyword)
        if value is not None and (not isinstance(value, (int, float)) or isinstance(value, bool)):
            errors.append(f"{path}.{keyword}: must be a number")
    if (
        isinstance(schema.get("minimum"), (int, float))
        and not isinstance(schema.get("minimum"), bool)
        and isinstance(schema.get("maximum"), (int, float))
        and not isinstance(schema.get("maximum"), bool)
        and schema["minimum"] > schema["maximum"]
    ):
        errors.append(f"{path}: minimum exceeds maximum")


def validate_concrete_input_schema(schema: object) -> tuple[str, ...]:
    """Return deterministic errors for the concrete JSON Schema subset used by MCP inputs."""

    errors: list[str] = []
    _validate_schema_node(schema, "$", errors)
    if isinstance(schema, Mapping):
        if schema.get("type") != "object":
            errors.append("$: input schema type must be object")
        if schema.get("additionalProperties") is not False:
            errors.append("$: input schema must set additionalProperties to false")
    return tuple(errors)


def classify_contract_state(
    *,
    capture_complete: bool,
    runtime_identity_matches: bool,
    server_schema_valid: bool,
    expected_tool_names: Iterable[str],
    server_tools: Sequence[Mapping[str, Any]],
    client_tool_names: Iterable[str],
) -> str:
    """Classify discovery-layer drift without invoking any advertised Index tool."""

    if not capture_complete:
        return "capture_inconclusive"
    if not runtime_identity_matches:
        return "runtime_identity_mismatch"

    expected = set(expected_tool_names)
    server_names = [tool.get("name") for tool in server_tools]
    if (
        not server_schema_valid
        or any(not isinstance(name, str) for name in server_names)
        or len(server_names) != len(set(server_names))
        or set(server_names) != expected
    ):
        return "server_schema_mismatch"
    if set(client_tool_names) != set(server_names):
        return "stale_client_catalog"
    return "match"
