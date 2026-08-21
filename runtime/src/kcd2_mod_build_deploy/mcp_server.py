"""Dependency-free MCP STDIO server for read-only build/deploy analysis."""

from __future__ import annotations

import copy
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from kcd2_toolchain_core.plugin_surface import _instance_errors

from .plugin_tools import SUPPORTED_TOOL_NAMES, create_public_registry, load_surface_manifest


TOOL_NAMES = SUPPORTED_TOOL_NAMES
_DESCRIPTIONS = {
    "candidate_parent_diff": "Compare explicit parent and candidate PAK artifacts.",
    "candidate_package_inspect": "Inspect candidate package structure and static readiness.",
    "provider_inventory_inspect": "Summarize an artifact-backed provider inventory.",
    "effective_path_resolve": "Resolve bounded contributions and qualified effective winners.",
    "plan_candidate_audit": (
        "Audit one exact canonical source and report pre-build candidate readiness without "
        "creating a candidate or requesting mutation approval."
    ),
    "compare_variants": (
        "Compare bounded selected semantics, effective providers, and runtime observations."
    ),
}


def _defaults(arguments: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(arguments)
    for name, child in schema.get("properties", {}).items():
        if name not in result and isinstance(child, Mapping) and "default" in child:
            result[name] = copy.deepcopy(child["default"])
    return result


class ModBuildDeployMcpServer:
    def __init__(self, repository_root: Path | str) -> None:
        self.root = Path(repository_root).resolve()
        self.manifest = load_surface_manifest(self.root)
        self.registry = create_public_registry(self.root, self.manifest)
        self.records = {item["tool_name"]: item for item in self.manifest["tools"]}

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        if request_id is None:
            return None
        try:
            method = request.get("method")
            if method == "initialize":
                result = {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "kcd2-mod-build-deploy", "version": "0.1.0+var.004"},
                    "instructions": "Read-only artifact analysis; no build, install, or rollback.",
                }
            elif method == "tools/list":
                result = {"tools": [self._tool(name) for name in TOOL_NAMES]}
            elif method == "tools/call":
                result = self._call(request.get("params"))
            elif method == "ping":
                result = {}
            else:
                raise ValueError(f"method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except (KeyError, TypeError, ValueError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32602, "message": str(exc)[:1000]},
            }

    def _tool(self, name: str) -> dict[str, Any]:
        record = self.records[name]
        return {
            "name": name,
            "title": name.replace("_", " ").title(),
            "description": _DESCRIPTIONS[name],
            "inputSchema": record["input_schema"],
            "outputSchema": record["output_schema"],
            "annotations": {
                "readOnlyHint": True,
                "destructiveHint": False,
                "idempotentHint": True,
                "openWorldHint": False,
            },
        }

    def _call(self, params: object) -> dict[str, Any]:
        if not isinstance(params, Mapping) or params.get("name") not in self.registry:
            raise ValueError("unknown mod-build-deploy tool")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, Mapping):
            raise ValueError("tool arguments must be an object")
        name = params["name"]
        record = self.records[name]
        normalized = _defaults(arguments, record["input_schema"])
        errors = _instance_errors(normalized, record["input_schema"])
        if errors:
            raise ValueError(f"invalid tool arguments: {errors[0]}")
        output = dict(self.registry[name].handler(**normalized))
        errors = _instance_errors(output, record["output_schema"])
        if errors:
            raise ValueError(f"tool output violates its schema: {errors[0]}")
        encoded = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > record["output_bounds"]["max_response_bytes"]:
            raise ValueError("tool output exceeds its response byte bound")
        return {
            "structuredContent": output,
            "content": [{"type": "text", "text": encoded}],
            "isError": False,
        }

    def serve(self) -> None:
        for raw in sys.stdin.buffer:
            try:
                request = json.loads(raw)
                if not isinstance(request, dict):
                    raise ValueError("request is not an object")
                response = self.handle(request)
            except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
                response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": str(exc)},
                }
            if response is not None:
                sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
                sys.stdout.flush()


def main(repository_root: Path | str) -> None:
    ModBuildDeployMcpServer(repository_root).serve()


__all__ = ["ModBuildDeployMcpServer", "TOOL_NAMES", "main"]
