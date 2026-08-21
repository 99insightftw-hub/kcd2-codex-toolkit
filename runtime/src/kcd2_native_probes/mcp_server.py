"""Dependency-free MCP STDIO surface for native-probe read-only analysis."""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.plugin_surface import _instance_errors

from .plugin_tools import (
    SUPPORTED_TOOL_NAMES,
    create_public_registry,
    load_surface_manifest,
)


PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "kcd2-native-probes"
SERVER_VERSION = "0.2.1+codex.r2-package"
TOOL_NAMES = SUPPORTED_TOOL_NAMES
_DESCRIPTIONS = {
    "native_capability_preflight": (
        "Evaluate explicit native-tool observations against an environment profile."
    ),
    "entry_lock_preflight": "Validate module-hash-bound entry locks against raw PE bytes.",
    "record_layout_lint": "Lint bounded family-specific record-layout evidence.",
    "probe_playtest_readiness": "Aggregate probe prerequisites without causing gameplay.",
    "validate_probe_result": "Classify bounded probe evidence without overstating negatives.",
}


def _apply_defaults(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(arguments)
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        for name, child in properties.items():
            if name not in result and isinstance(child, Mapping) and "default" in child:
                result[name] = copy.deepcopy(child["default"])
    return result


class NativeProbesMcpServer:
    """Expose the reviewed five-tool registry through MCP tools/list and tools/call."""

    def __init__(self, repository_root: Path | str) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.manifest = load_surface_manifest(self.repository_root)
        self.registry = create_public_registry(self.repository_root, self.manifest)
        self.records = {item["tool_name"]: item for item in self.manifest["tools"]}

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        if request_id is None:
            return None
        method = request.get("method")
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": (
                        "Bounded, read-only native-probe analysis. Results do not authorize "
                        "installation, debugger mutation, gameplay, or causal claims."
                    ),
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [self._tool(name) for name in TOOL_NAMES]}
            elif method == "tools/call":
                result = self._call(request.get("params"))
            else:
                return self._error(request_id, -32601, f"method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc)[:1000])
        except Exception as exc:  # pragma: no cover - defensive redaction boundary
            return self._error(
                request_id,
                -32603,
                f"read-only native analysis failure: {type(exc).__name__}",
            )

    def _tool(self, name: str) -> dict[str, Any]:
        return {
            "name": name,
            "title": name.replace("_", " ").title(),
            "description": _DESCRIPTIONS[name],
            "inputSchema": self.records[name]["input_schema"],
            "outputSchema": self.records[name]["output_schema"],
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }

    def _call(self, params: object) -> dict[str, Any]:
        if not isinstance(params, Mapping):
            raise ValueError("tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments", {})
        if name not in self.registry:
            raise ValueError("unknown native-probes tool")
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be an object")
        schema = self.records[name]["input_schema"]
        normalized = _apply_defaults(arguments, schema)
        errors = _instance_errors(normalized, schema)
        if errors:
            raise ValueError(f"invalid tool arguments: {errors[0]}")
        output = dict(self.registry[name].handler(**normalized))
        output_errors = _instance_errors(output, self.records[name]["output_schema"])
        if output_errors:
            raise ValueError(f"tool output violates its schema: {output_errors[0]}")
        encoded = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
        maximum = self.records[name]["output_bounds"]["max_response_bytes"]
        if len(encoded.encode("utf-8")) > maximum:
            raise ValueError("tool output exceeds its response byte bound")
        return {
            "structuredContent": output,
            "content": [{"type": "text", "text": encoded}],
            "isError": False,
        }

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    def serve(self) -> None:
        for raw in sys.stdin.buffer:
            try:
                request = json.loads(raw)
                if not isinstance(request, dict):
                    raise ValueError("request is not an object")
                response = self.handle(request)
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                response = self._error(None, -32700, f"parse error: {exc}")
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()


def main(repository_root: Path | str) -> None:
    NativeProbesMcpServer(repository_root).serve()


__all__ = ["NativeProbesMcpServer", "TOOL_NAMES", "main"]
