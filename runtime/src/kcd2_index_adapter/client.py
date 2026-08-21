"""Bounded synchronous stdio MCP client for the version-locked KCD2 Index runtime."""

from __future__ import annotations

import hashlib
import json
import math
import queue
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Literal

from .contract import ContractMismatchError, IndexContract


_MAX_CONTENT_BLOCKS = 256
_MAX_JSON_DEPTH = 64
_MAX_UNSOLICITED_MESSAGES = 16
_DRY_RUN_TOOLS = frozenset({"kcd2_refresh_active_mod", "kcd2_runtime_import"})
_KNOWN_CONTENT_TYPES = frozenset({"audio", "image", "resource", "resource_link", "text"})
_EOF = object()


class IndexAdapterError(RuntimeError):
    """Base class for deterministic adapter failures."""


class RpcTimeoutError(IndexAdapterError):
    """The server did not return a complete response before the configured deadline."""


class MalformedRpcError(IndexAdapterError):
    """The server emitted invalid, oversized, or unexpected JSON-RPC data."""


class RemoteRpcError(IndexAdapterError):
    """The server returned a valid JSON-RPC error object."""


class ReadOnlyViolationError(IndexAdapterError):
    """A requested tool invocation could cause adapter-visible persistent state changes."""


class ProcessError(IndexAdapterError):
    """The stdio runtime could not be started or exited unexpectedly."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_copy(value: object, *, context: str) -> Any:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError, RecursionError, json.JSONDecodeError) as exc:
        raise MalformedRpcError(f"{context} is not bounded JSON-compatible data") from exc
    _validate_json_shape(decoded, context=context)
    return decoded


def _validate_json_shape(value: object, *, context: str, depth: int = 0) -> None:
    if depth > _MAX_JSON_DEPTH:
        raise MalformedRpcError(f"{context} exceeds the JSON nesting bound")
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise MalformedRpcError(f"{context} contains a non-string object key")
        for child in value.values():
            _validate_json_shape(child, context=context, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            _validate_json_shape(child, context=context, depth=depth + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise MalformedRpcError(f"{context} contains a non-finite number")
    elif value is not None and not isinstance(value, (bool, int, float, str)):
        raise MalformedRpcError(f"{context} contains a non-JSON value")


def _validate_content_block(block: Mapping[str, Any], *, index: int) -> None:
    context = f"tools/call content[{index}]"
    block_type = block.get("type")
    if block_type not in _KNOWN_CONTENT_TYPES:
        raise MalformedRpcError(f"{context} has an unsupported type")
    common_optional = {"annotations", "_meta"}
    if "annotations" in block and not isinstance(block["annotations"], Mapping):
        raise MalformedRpcError(f"{context}.annotations must be an object")
    if "_meta" in block and not isinstance(block["_meta"], Mapping):
        raise MalformedRpcError(f"{context}._meta must be an object")

    if block_type == "text":
        allowed = {"type", "text"} | common_optional
        if not isinstance(block.get("text"), str):
            raise MalformedRpcError(f"{context}.text must be a string")
    elif block_type in {"audio", "image"}:
        allowed = {"type", "data", "mimeType"} | common_optional
        if not isinstance(block.get("data"), str) or not isinstance(
            block.get("mimeType"), str
        ):
            raise MalformedRpcError(f"{context} data and mimeType must be strings")
    elif block_type == "resource_link":
        allowed = {
            "type",
            "name",
            "title",
            "uri",
            "description",
            "mimeType",
            "icons",
            "size",
        } | common_optional
        if not isinstance(block.get("name"), str) or not isinstance(block.get("uri"), str):
            raise MalformedRpcError(f"{context} name and uri must be strings")
    else:
        allowed = {"type", "resource"} | common_optional
        resource = block.get("resource")
        if not isinstance(resource, Mapping):
            raise MalformedRpcError(f"{context}.resource must be an object")
        if not isinstance(resource.get("uri"), str):
            raise MalformedRpcError(f"{context}.resource.uri must be a string")
        payload_fields = {"text", "blob"} & set(resource)
        if len(payload_fields) != 1 or not isinstance(resource[next(iter(payload_fields))], str):
            raise MalformedRpcError(f"{context}.resource must contain text or blob")
        if not set(resource).issubset({"uri", "mimeType", "_meta", "text", "blob"}):
            raise MalformedRpcError(f"{context}.resource fields changed")
    if not set(block).issubset(allowed):
        raise MalformedRpcError(f"{context} fields changed")


class _StdoutReader(threading.Thread):
    def __init__(self, stream: BinaryIO, output: queue.Queue[object], max_bytes: int) -> None:
        super().__init__(name="kcd2-index-stdout", daemon=True)
        self._stream = stream
        self._output = output
        self._max_bytes = max_bytes

    def run(self) -> None:
        try:
            while True:
                line = self._stream.readline(self._max_bytes + 1)
                if not line:
                    self._output.put(_EOF)
                    return
                if len(line) > self._max_bytes or not line.endswith(b"\n"):
                    self._output.put(MalformedRpcError("JSON-RPC response exceeded the byte bound"))
                    return
                self._output.put(line)
        except (OSError, ValueError) as exc:
            self._output.put(ProcessError(f"failed reading MCP stdout: {exc}"))


class _StderrReader(threading.Thread):
    def __init__(self, stream: BinaryIO, max_bytes: int) -> None:
        super().__init__(name="kcd2-index-stderr", daemon=True)
        self._stream = stream
        self._max_bytes = max_bytes
        self.data = bytearray()
        self.overflow = False

    def run(self) -> None:
        try:
            while chunk := self._stream.read(4096):
                remaining = self._max_bytes - len(self.data)
                if remaining > 0:
                    self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow = True
        except (OSError, ValueError):
            self.overflow = True

    def summary(self) -> str:
        decoded = bytes(self.data).decode("utf-8", errors="replace").strip()
        suffix = " [truncated]" if self.overflow else ""
        return f"{decoded}{suffix}".strip()


@dataclass(frozen=True, slots=True)
class NormalizedToolResponse:
    tool_name: str
    status: Literal["ok", "tool_error"]
    content: tuple[Mapping[str, Any], ...]
    structured_content: Mapping[str, Any] | None
    meta: Mapping[str, Any] | None
    schema_version: str = "kcd2.index-adapter-response.v1"

    def to_dict(self) -> dict[str, Any]:
        value = {
            "schema_version": self.schema_version,
            "tool_name": self.tool_name,
            "status": self.status,
            "content": list(self.content),
            "structured_content": self.structured_content,
            "meta": self.meta,
        }
        return _canonical_copy(value, context="normalized tool response")

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )


class IndexMcpClient:
    """One-process, single-request-at-a-time MCP client with a locked discovery contract."""

    def __init__(
        self,
        *,
        command: Sequence[str],
        runtime_executable: Path,
        contract: IndexContract,
        cwd: Path | None = None,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 1024 * 1024,
        max_request_bytes: int = 1024 * 1024,
    ) -> None:
        if not command or not all(isinstance(item, str) and item for item in command):
            raise ValueError("command must contain non-empty string arguments")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("timeout_seconds must be greater than zero and at most 30")
        if not 1024 <= max_response_bytes <= 2 * 1024 * 1024:
            raise ValueError("max_response_bytes must be between 1 KiB and 2 MiB")
        if not 1024 <= max_request_bytes <= 2 * 1024 * 1024:
            raise ValueError("max_request_bytes must be between 1 KiB and 2 MiB")
        self._command = tuple(command)
        self._runtime_executable = runtime_executable
        self._contract = contract
        self._cwd = cwd
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_request_bytes = max_request_bytes
        self._process: subprocess.Popen[bytes] | None = None
        self._stdout_queue: queue.Queue[object] = queue.Queue(maxsize=32)
        self._stdout_reader: _StdoutReader | None = None
        self._stderr_reader: _StderrReader | None = None
        self._request_lock = threading.Lock()
        self._next_id = 1
        self._ready = False

    def __enter__(self) -> "IndexMcpClient":
        self.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def start(self) -> None:
        if self._process is not None:
            raise ProcessError("MCP client has already been started")
        try:
            runtime_path = self._runtime_executable.resolve(strict=True)
            actual_hash = _sha256(runtime_path)
        except OSError as exc:
            raise ContractMismatchError(f"cannot hash the runtime executable: {exc}") from exc
        if actual_hash != self._contract.runtime_executable_sha256:
            raise ContractMismatchError(
                "runtime executable SHA-256 does not match the locked contract"
            )

        try:
            self._process = subprocess.Popen(
                self._command,
                cwd=self._cwd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            self._process = None
            raise ProcessError(f"cannot start Index MCP runtime: {exc}") from exc
        assert self._process.stdout is not None
        assert self._process.stderr is not None
        self._stdout_reader = _StdoutReader(
            self._process.stdout,
            self._stdout_queue,
            self._max_response_bytes,
        )
        self._stderr_reader = _StderrReader(
            self._process.stderr,
            self._max_response_bytes,
        )
        self._stdout_reader.start()
        self._stderr_reader.start()

        try:
            initialize = self._request(
                "initialize",
                {
                    "protocolVersion": self._contract.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "kcd2-index-adapter", "version": "1.0.0"},
                },
            )
            self._contract.validate_initialize(initialize)
            self._notify("notifications/initialized", {})
            tools_list = self._request("tools/list", {})
            self._contract.validate_tools_list(tools_list)
            self._ready = True
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        process = self._process
        self._ready = False
        if process is None:
            return
        self._process = None
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for reader in (self._stdout_reader, self._stderr_reader):
            if reader is not None:
                reader.join(timeout=1.0)

    def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> NormalizedToolResponse:
        if not self._ready:
            raise ProcessError("MCP client has not completed locked discovery")
        if tool_name not in self._contract.tool_names:
            raise ContractMismatchError(f"tool {tool_name!r} is not in the locked contract")
        safe_arguments = self._enforce_read_only(tool_name, arguments)
        result = self._request(
            "tools/call",
            {"name": tool_name, "arguments": safe_arguments},
        )
        return self._normalize_tool_result(tool_name, result)

    def call_exact_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        scope_guard: "ScopeGuard",
    ) -> "ExactToolResponse":
        """Call through the locked adapter and require a complete, successful scope receipt."""
        from .scope_guard import ExactToolResponse, ScopeGuard, TargetScopeReceiptError

        if not isinstance(scope_guard, ScopeGuard):
            raise TypeError("scope_guard must be ScopeGuard")
        response = self.call_tool(tool_name, arguments)
        structured = response.structured_content
        if not isinstance(structured, Mapping) or "scope_receipt" not in structured:
            raise TargetScopeReceiptError(
                "exact tool response must contain structured_content.scope_receipt"
            )
        receipt = structured["scope_receipt"]
        if not isinstance(receipt, Mapping):
            raise TargetScopeReceiptError("structured_content.scope_receipt must be an object")
        validated = scope_guard.require_ok(receipt)
        return ExactToolResponse(response=response, scope_receipt=validated)

    def _enforce_read_only(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(arguments, Mapping) or not all(
            isinstance(key, str) for key in arguments
        ):
            raise ReadOnlyViolationError("tool arguments must be an object with string keys")
        try:
            safe = _canonical_copy(dict(arguments), context=f"{tool_name} arguments")
        except MalformedRpcError as exc:
            raise ReadOnlyViolationError(str(exc)) from exc
        if tool_name in _DRY_RUN_TOOLS:
            if safe.get("dry_run") is False:
                raise ReadOnlyViolationError(f"{tool_name} requires dry_run=true")
            safe["dry_run"] = True
        if tool_name == "kcd2_active_snapshot" and safe.get("mode") == "capture":
            raise ReadOnlyViolationError("kcd2_active_snapshot capture is disabled by this adapter")
        return safe

    def _normalize_tool_result(self, tool_name: str, result: object) -> NormalizedToolResponse:
        if not isinstance(result, Mapping) or not all(isinstance(key, str) for key in result):
            raise MalformedRpcError("tools/call result must be an object")
        allowed = {"content", "isError", "structuredContent", "_meta"}
        if not set(result).issubset(allowed) or "content" not in result:
            raise MalformedRpcError("tools/call result fields changed")
        content = result["content"]
        if not isinstance(content, list):
            raise MalformedRpcError("tools/call content must be an array")
        if len(content) > _MAX_CONTENT_BLOCKS:
            raise MalformedRpcError("tools/call content exceeds the block bound")
        normalized_content: list[Mapping[str, Any]] = []
        for index, block in enumerate(content):
            if not isinstance(block, Mapping) or not all(isinstance(key, str) for key in block):
                raise MalformedRpcError(f"tools/call content[{index}] must be an object")
            _validate_content_block(block, index=index)
            normalized_content.append(
                _canonical_copy(block, context=f"tools/call content[{index}]")
            )

        is_error = result.get("isError", False)
        if not isinstance(is_error, bool):
            raise MalformedRpcError("tools/call isError must be a boolean")
        structured = result.get("structuredContent")
        if structured is not None and not isinstance(structured, Mapping):
            raise MalformedRpcError("tools/call structuredContent must be an object")
        meta = result.get("_meta")
        if meta is not None and not isinstance(meta, Mapping):
            raise MalformedRpcError("tools/call _meta must be an object")
        return NormalizedToolResponse(
            tool_name=tool_name,
            status="tool_error" if is_error else "ok",
            content=tuple(normalized_content),
            structured_content=(
                _canonical_copy(structured, context="tools/call structuredContent")
                if structured is not None
                else None
            ),
            meta=(
                _canonical_copy(meta, context="tools/call _meta") if meta is not None else None
            ),
        )

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._write_message({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _request(self, method: str, params: Mapping[str, Any]) -> object:
        with self._request_lock:
            request_id = self._next_id
            self._next_id += 1
            self._write_message(
                {"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)}
            )
            deadline = time.monotonic() + self._timeout_seconds
            for _ in range(_MAX_UNSOLICITED_MESSAGES + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RpcTimeoutError(f"{method} exceeded the RPC timeout")
                try:
                    item = self._stdout_queue.get(timeout=remaining)
                except queue.Empty as exc:
                    raise RpcTimeoutError(f"{method} exceeded the RPC timeout") from exc
                if isinstance(item, BaseException):
                    raise item
                if item is _EOF:
                    stderr = self._stderr_reader.summary() if self._stderr_reader else ""
                    detail = f": {stderr}" if stderr else ""
                    raise ProcessError(f"Index MCP runtime closed stdout{detail}")
                assert isinstance(item, bytes)
                response = self._decode_response(item)
                if response.get("id") != request_id:
                    raise MalformedRpcError("JSON-RPC response ID does not match the request")
                has_result = "result" in response
                has_error = "error" in response
                if has_result == has_error:
                    raise MalformedRpcError("JSON-RPC response must contain result or error")
                if has_error:
                    error = response["error"]
                    if not isinstance(error, Mapping):
                        raise MalformedRpcError("JSON-RPC error must be an object")
                    code = error.get("code")
                    message = error.get("message")
                    if (
                        not isinstance(code, int)
                        or isinstance(code, bool)
                        or not isinstance(message, str)
                    ):
                        raise MalformedRpcError("JSON-RPC error code or message is invalid")
                    raise RemoteRpcError(f"JSON-RPC error {code}: {message}")
                return response["result"]
            raise MalformedRpcError("too many unsolicited JSON-RPC messages")

    def _write_message(self, message: Mapping[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None or process.poll() is not None:
            raise ProcessError("Index MCP runtime is not running")
        try:
            payload = (
                json.dumps(
                    message,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise MalformedRpcError("JSON-RPC request is not JSON-compatible") from exc
        if len(payload) > self._max_request_bytes:
            raise MalformedRpcError("JSON-RPC request exceeded the byte bound")
        try:
            process.stdin.write(payload)
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise ProcessError("failed writing to Index MCP stdin") from exc

    @staticmethod
    def _decode_response(line: bytes) -> Mapping[str, Any]:
        try:
            decoded = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise MalformedRpcError("Index MCP emitted malformed JSON") from exc
        _validate_json_shape(decoded, context="JSON-RPC response")
        if not isinstance(decoded, Mapping) or not all(isinstance(key, str) for key in decoded):
            raise MalformedRpcError("JSON-RPC response must be an object")
        if not set(decoded).issubset({"jsonrpc", "id", "result", "error"}):
            raise MalformedRpcError("JSON-RPC response fields changed")
        if decoded.get("jsonrpc") != "2.0" or "id" not in decoded:
            raise MalformedRpcError("JSON-RPC response version or ID is invalid")
        return decoded
