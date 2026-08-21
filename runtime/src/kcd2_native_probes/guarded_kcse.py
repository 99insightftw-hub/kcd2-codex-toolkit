"""Fail-closed, non-live generation and validation for guarded KCSE projects."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Mapping, Sequence

from .correlation import validate_native_stage_correlation
from .record_layout import record_layout_lint
from .source_contract import (
    ProbeSourceContractError,
    generate_probe_contract,
    probe_source_manifest_check,
)


MAX_PE_BYTES = 512 * 1024 * 1024
MAX_EXPORTS = 4096
MAX_EXPORT_NAME_BYTES = 512
MAX_BUILD_OUTPUTS = 128
_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_X64_PREFIX_BYTES = frozenset(
    {
        0xF0,
        0xF2,
        0xF3,
        0x2E,
        0x36,
        0x3E,
        0x26,
        0x64,
        0x65,
        0x66,
        0x67,
        *range(0x40, 0x50),
    }
)
_MANIFEST_REQUIRED = {
    "schema_version",
    "probe_id",
    "revision",
    "carrier",
    "hypothesis",
    "expected_module",
    "deployment_binding_required",
    "hooks",
    "record_layout_evidence",
    "identity_matchers",
    "event_schemas",
    "event_limits",
    "correlation_contracts",
    "controls",
    "negative_evidence_policy",
    "source_contract",
    "cleanup",
}
_PROFILE_REQUIRED = {
    "schema_version",
    "profile_id",
    "module_name",
    "module_sha256",
    "module_timestamp",
    "module_image_size",
    "adapter_source",
    "adapter_source_sha256",
    "required_exports",
    "kcse_api_version",
}


class GuardedProjectError(ValueError):
    """Raised when a project or transaction cannot pass its non-live guards."""


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _checked_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _HEX_64.fullmatch(value) is None:
        raise GuardedProjectError(f"{label} must be a 64-digit SHA-256")
    return value.lower()


def _checked_component(value: object, label: str) -> str:
    if not isinstance(value, str) or _SAFE_COMPONENT.fullmatch(value) is None:
        raise GuardedProjectError(f"{label} must be one bounded path-safe component")
    return value


def _checked_relative_path(value: object, label: str) -> Path:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise GuardedProjectError(f"{label} must be a bounded relative path")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise GuardedProjectError(f"{label} must remain inside its declared root")
    return path


class RawPEImageMapper:
    """Bounded raw-PE parser with explicit RVA-to-file-offset mapping."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise GuardedProjectError("PE input is missing the DOS MZ header")
        pe_offset = self._u32(data, 0x3C)
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
            raise GuardedProjectError("PE input is missing a bounded PE signature")
        coff = pe_offset + 4
        self.machine = self._u16(data, coff)
        self.timestamp = self._u32(data, coff + 4)
        section_count = self._u16(data, coff + 2)
        optional_size = self._u16(data, coff + 16)
        if section_count < 1 or section_count > 96:
            raise GuardedProjectError("PE section count is outside the supported bound")
        optional = coff + 20
        if optional + optional_size > len(data):
            raise GuardedProjectError("PE optional header exceeds the file")
        magic = self._u16(data, optional)
        if magic == 0x20B:
            directory_count_offset, directory_offset = 108, 112
        elif magic == 0x10B:
            directory_count_offset, directory_offset = 92, 96
        else:
            raise GuardedProjectError("PE optional-header architecture is unsupported")
        self.image_size = self._u32(data, optional + 56)
        if self.image_size < 1:
            raise GuardedProjectError("PE image size is invalid")
        directory_count = self._u32(data, optional + directory_count_offset)
        if directory_count and optional_size >= directory_offset + 8:
            self.export_rva = self._u32(data, optional + directory_offset)
            self.export_size = self._u32(data, optional + directory_offset + 4)
        else:
            self.export_rva = 0
            self.export_size = 0
        section_table = optional + optional_size
        if section_table + section_count * 40 > len(data):
            raise GuardedProjectError("PE section table exceeds the file")
        self.data = data
        self.sections: list[tuple[str, int, int, int, int]] = []
        for index in range(section_count):
            offset = section_table + index * 40
            raw_name = data[offset : offset + 8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size = self._u32(data, offset + 8)
            virtual_address = self._u32(data, offset + 12)
            raw_size = self._u32(data, offset + 16)
            raw_offset = self._u32(data, offset + 20)
            if raw_offset + raw_size > len(data):
                raise GuardedProjectError(f"PE section {name!r} exceeds the file")
            self.sections.append(
                (name, virtual_address, max(virtual_size, raw_size), raw_offset, raw_size)
            )

    @staticmethod
    def _u16(data: bytes, offset: int) -> int:
        if offset < 0 or offset + 2 > len(data):
            raise GuardedProjectError("PE 16-bit read exceeds the file")
        return struct.unpack_from("<H", data, offset)[0]

    @staticmethod
    def _u32(data: bytes, offset: int) -> int:
        if offset < 0 or offset + 4 > len(data):
            raise GuardedProjectError("PE 32-bit read exceeds the file")
        return struct.unpack_from("<I", data, offset)[0]

    def rva_to_file_offset(self, rva: int, size: int = 1) -> int:
        if rva < 0 or size < 0:
            raise GuardedProjectError("PE RVA and size must be non-negative")
        for name, start, span, raw_offset, raw_size in self.sections:
            if start <= rva and rva + size <= start + span:
                delta = rva - start
                if delta + size > raw_size:
                    raise GuardedProjectError(
                        f"RVA 0x{rva:X} maps beyond raw bytes in section {name!r}"
                    )
                return raw_offset + delta
        raise GuardedProjectError(f"RVA 0x{rva:X} is not mapped by a raw PE section")

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_file_offset(rva, size)
        return self.data[offset : offset + size]

    def hidden_prefix_before_rva(self, rva: int) -> bytes:
        """Return contiguous x64 instruction-prefix bytes immediately before an RVA."""

        for _name, start, _span, raw_offset, raw_size in self.sections:
            delta = rva - start
            if 0 < delta <= raw_size:
                cursor = raw_offset + delta
                lower = max(raw_offset, cursor - 14)
                while cursor > lower and self.data[cursor - 1] in _X64_PREFIX_BYTES:
                    cursor -= 1
                return self.data[cursor : raw_offset + delta]
        return b""

    def read_ascii_rva(self, rva: int) -> str:
        offset = self.rva_to_file_offset(rva)
        end = min(len(self.data), offset + MAX_EXPORT_NAME_BYTES)
        terminator = self.data.find(b"\0", offset, end)
        if terminator < 0:
            raise GuardedProjectError("PE export name is unterminated or overlong")
        try:
            return self.data[offset:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise GuardedProjectError("PE export name is not ASCII") from exc

    def exports(self) -> tuple[str, ...]:
        if self.export_rva == 0:
            return ()
        directory = self.read_rva(self.export_rva, 40)
        count = self._u32(directory, 24)
        names_rva = self._u32(directory, 32)
        if count > MAX_EXPORTS:
            raise GuardedProjectError("PE export count exceeds the supported bound")
        names = [self._u32(self.read_rva(names_rva + index * 4, 4), 0) for index in range(count)]
        exports = [self.read_ascii_rva(rva) for rva in names]
        if len(set(exports)) != len(exports):
            raise GuardedProjectError("PE export names must be unique")
        return tuple(sorted(exports))


def _load_pe(path: Path) -> tuple[bytes, RawPEImageMapper]:
    if not path.is_file():
        raise GuardedProjectError(f"PE input does not exist: {path}")
    size = path.stat().st_size
    if size < 1 or size > MAX_PE_BYTES:
        raise GuardedProjectError("PE input size is outside the supported bound")
    data = path.read_bytes()
    return data, RawPEImageMapper(data)


def entry_lock_preflight(
    manifest: Mapping[str, Any],
    module_path: Path,
    *,
    generated_header: bytes | str,
) -> dict[str, Any]:
    """Compare manifest and generated-source entry locks with raw mapped PE bytes."""

    expected_module = manifest.get("expected_module")
    if not isinstance(expected_module, Mapping):
        raise GuardedProjectError("manifest expected_module is required")
    module_path = Path(module_path)
    data, pe = _load_pe(module_path)
    expected_hash = _checked_sha256(
        expected_module.get("sha256"), "manifest module SHA-256"
    )
    actual_hash = _sha256_bytes(data)
    if actual_hash != expected_hash:
        raise GuardedProjectError(
            "module SHA-256 does not match the manifest entry-lock profile"
        )
    if module_path.name.casefold() != str(expected_module.get("name", "")).casefold():
        raise GuardedProjectError("module name does not match the manifest entry-lock profile")
    try:
        expected_timestamp = int(str(expected_module.get("timestamp")), 16)
    except (TypeError, ValueError) as exc:
        raise GuardedProjectError("manifest module timestamp is invalid") from exc
    if pe.timestamp != expected_timestamp or pe.image_size != expected_module.get("image_size"):
        raise GuardedProjectError(
            "raw PE timestamp/image size do not match the manifest entry-lock profile"
        )

    hooks = manifest.get("hooks")
    if not isinstance(hooks, list) or not hooks or len(hooks) > 64:
        raise GuardedProjectError("manifest hooks must be a bounded non-empty list")
    for hook in hooks:
        if not isinstance(hook, Mapping):
            raise GuardedProjectError("every manifest hook must be an object")
        entry_lock = hook.get("entry_lock")
        if not isinstance(entry_lock, Mapping):
            raise GuardedProjectError("every manifest hook must declare an entry lock")
        if entry_lock.get("source") != "raw_pe_rva_mapping":
            raise GuardedProjectError(
                "entry locks must use raw PE RVA mapping, never formatted bytes"
            )
        if entry_lock.get("raw_pe_preflight_required") is not True:
            raise GuardedProjectError("every entry lock must require raw PE preflight")

    try:
        generated = generate_probe_contract(manifest)
    except ProbeSourceContractError as exc:
        raise GuardedProjectError(f"manifest cannot generate an entry-lock header: {exc}") from exc
    header_bytes = (
        generated_header.encode("utf-8")
        if isinstance(generated_header, str)
        else generated_header
    )
    if not isinstance(header_bytes, bytes) or len(header_bytes) > 8 * 1024 * 1024:
        raise GuardedProjectError("generated header is missing or exceeds its byte ceiling")
    expected_header = generated.header.encode("utf-8")
    if header_bytes != expected_header:
        raise GuardedProjectError("generated header entry locks do not match the manifest")

    hook_reports: list[dict[str, Any]] = []
    seen: set[str] = set()
    for hook in hooks:
        if hook.get("enabled") is not True:
            continue
        hook_id = _checked_component(hook.get("hook_id"), "hook_id")
        if hook_id in seen:
            raise GuardedProjectError("enabled hook IDs must be unique")
        seen.add(hook_id)
        try:
            rva = int(str(hook.get("rva")), 16)
        except (TypeError, ValueError) as exc:
            raise GuardedProjectError(f"hook {hook_id} has an invalid RVA") from exc
        entry_lock = hook["entry_lock"]
        try:
            locked = bytes.fromhex(str(entry_lock.get("bytes_hex", "")))
        except ValueError as exc:
            raise GuardedProjectError(f"hook {hook_id} entry lock is invalid hex") from exc
        if not locked or len(locked) > 256:
            raise GuardedProjectError(f"hook {hook_id} entry lock has an invalid size")
        file_offset = pe.rva_to_file_offset(rva, len(locked))
        observed = data[file_offset : file_offset + len(locked)]
        if observed != locked:
            for prefix_size in range(1, 15):
                try:
                    prefixed = pe.read_rva(rva, len(locked) + prefix_size)
                except GuardedProjectError:
                    break
                if (
                    prefixed[prefix_size:] == locked
                    and all(byte in _X64_PREFIX_BYTES for byte in prefixed[:prefix_size])
                ):
                    rendered = prefixed[:prefix_size].hex(" ").upper()
                    raise GuardedProjectError(
                        f"hook {hook_id} raw lock omitted hidden/redundant prefix: {rendered}"
                    )
            raise GuardedProjectError(f"hook {hook_id} raw PE entry lock does not match")
        hidden_prefix = pe.hidden_prefix_before_rva(rva)
        if hidden_prefix:
            rendered = hidden_prefix.hex(" ").upper()
            raise GuardedProjectError(
                f"hook {hook_id} has hidden instruction prefix bytes before RVA: {rendered}"
            )
        hook_reports.append(
            {
                "hook_id": hook_id,
                "rva": rva,
                "file_offset": file_offset,
                "manifest_lock_hex": locked.hex(" ").upper(),
                "generated_lock_hex": locked.hex(" ").upper(),
                "raw_bytes_hex": observed.hex(" ").upper(),
                "matches": True,
                "hidden_prefix_hex": "",
                "redundant_prefix_hex": (
                    locked[:1].hex(" ").upper()
                    if len(locked) > 1
                    and locked[0] in range(0x40, 0x50)
                    and locked[1] in range(0x40, 0x50)
                    else ""
                ),
            }
        )
    if not hook_reports:
        raise GuardedProjectError("manifest has no enabled entry lock to preflight")
    return {
        "schema_version": "kcd2.entry-lock-preflight.v1",
        "valid": True,
        "lock_source": "raw_pe_rva_mapping",
        "module_name": module_path.name,
        "module_path": str(module_path.resolve()),
        "module_sha256": actual_hash,
        "generated_header_sha256": _sha256_bytes(header_bytes),
        "generated_header_matches_manifest": True,
        "hooks": hook_reports,
    }


def inspect_pe_exports(path: Path, expected_exports: Sequence[str] = ()) -> dict[str, Any]:
    """Parse PE exports as data and compare them to an exact allowlist."""

    data, pe = _load_pe(Path(path))
    observed = pe.exports()
    expected = tuple(
        sorted(_checked_component(item, "expected export") for item in expected_exports)
    )
    if len(set(expected)) != len(expected):
        raise GuardedProjectError("expected exports must be unique")
    architecture = {0x8664: "x64", 0x14C: "x86"}.get(pe.machine, f"unknown_0x{pe.machine:04X}")
    missing = sorted(set(expected) - set(observed))
    unexpected = sorted(set(observed) - set(expected))
    return {
        "schema_version": "kcd2.pe-export-inspection.v1",
        "path": str(Path(path).resolve()),
        "sha256": _sha256_bytes(data),
        "architecture": architecture,
        "observed_exports": list(observed),
        "expected_exports": list(expected),
        "missing_exports": missing,
        "unexpected_exports": unexpected,
        "matches_expected": not missing and not unexpected,
    }


def _modrm_length(code: bytes, start: int) -> tuple[int, bool]:
    if start >= len(code):
        return 0, False
    modrm = code[start]
    mod = modrm >> 6
    rm = modrm & 7
    length = 1
    rip_relative = mod == 0 and rm == 5
    if mod != 3 and rm == 4:
        if start + length >= len(code):
            return 0, False
        sib = code[start + length]
        length += 1
        base = sib & 7
        if mod == 0 and base == 5:
            length += 4
    if mod == 0 and rm == 5:
        length += 4
    elif mod == 1:
        length += 1
    elif mod == 2:
        length += 4
    return length, rip_relative


def _inspect_stolen_instructions(code: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    instructions: list[dict[str, Any]] = []
    hazards: set[str] = set()
    cursor = 0
    while cursor < len(code):
        start = cursor
        rex_w = False
        while cursor < len(code) and (
            code[cursor] in (0x66, 0x67, 0xF2, 0xF3)
            or 0x40 <= code[cursor] <= 0x4F
        ):
            rex_w = rex_w or (0x48 <= code[cursor] <= 0x4F)
            cursor += 1
        if cursor >= len(code):
            hazards.add("truncated_instruction")
            length = len(code) - start
        else:
            opcode = code[cursor]
            cursor += 1
            hazard: str | None = None
            immediate = 0
            if opcode in (0xE8, 0xE9):
                immediate, hazard = 4, "relative_control_flow"
            elif opcode == 0xEB or 0x70 <= opcode <= 0x7F:
                immediate, hazard = 1, "relative_control_flow"
            elif opcode == 0x0F:
                if cursor >= len(code):
                    hazard = "truncated_instruction"
                else:
                    second = code[cursor]
                    cursor += 1
                    if 0x80 <= second <= 0x8F:
                        immediate, hazard = 4, "relative_control_flow"
                    elif second in (0xAF, 0xB6, 0xB7, 0xBE, 0xBF):
                        modrm_size, rip = _modrm_length(code, cursor)
                        if modrm_size == 0:
                            hazard = "truncated_instruction"
                        else:
                            cursor += modrm_size
                            if rip:
                                hazard = "rip_relative_operand"
                    else:
                        hazard = "unsupported_instruction"
            elif opcode in (0x68,):
                immediate = 4
            elif opcode in (0x6A,):
                immediate = 1
            elif opcode in range(0xB8, 0xC0):
                immediate = 8 if rex_w else 4
            elif opcode in (
                0x01, 0x03, 0x21, 0x23, 0x29, 0x2B, 0x31, 0x33, 0x39, 0x3B,
                0x63, 0x80, 0x81, 0x83, 0x85, 0x87, 0x89, 0x8B, 0x8D, 0xC7, 0xFF,
            ):
                modrm_size, rip = _modrm_length(code, cursor)
                if modrm_size == 0:
                    hazard = "truncated_instruction"
                else:
                    cursor += modrm_size
                    if opcode in (0x80, 0x83):
                        immediate = 1
                    elif opcode in (0x81, 0xC7):
                        immediate = 4
                    if rip:
                        hazard = "rip_relative_operand"
            elif opcode in range(0x50, 0x60) or opcode in (0x90, 0xC3, 0xCC):
                pass
            else:
                hazard = "unsupported_instruction"
            if cursor + immediate > len(code):
                cursor = len(code)
                hazard = "truncated_instruction"
            else:
                cursor += immediate
            if hazard:
                hazards.add(hazard)
            length = cursor - start
        instructions.append(
            {"offset": start, "length": length, "bytes_hex": code[start:cursor].hex(" ").upper()}
        )
        if length <= 0:
            break
    return instructions, sorted(hazards)


def _validate_generation_inputs(
    manifest: Mapping[str, Any], profile: Mapping[str, Any], module_path: Path
) -> tuple[str, str, str, Path, tuple[str, ...], bytes, RawPEImageMapper]:
    if manifest.get("schema_version") != "kcd2.probe-contract.v2":
        raise GuardedProjectError("manifest must use kcd2.probe-contract.v2")
    if set(manifest) != _MANIFEST_REQUIRED:
        raise GuardedProjectError(
            "manifest must satisfy the closed probe-contract v2 top-level shape"
        )
    if manifest.get("carrier") not in ("kcse", "hybrid"):
        raise GuardedProjectError("guarded KCSE generation requires a kcse or hybrid manifest")
    if manifest.get("deployment_binding_required") is not True:
        raise GuardedProjectError("manifest must require exact deployment binding")
    source_contract = manifest.get("source_contract")
    if not isinstance(source_contract, Mapping) or source_contract.get(
        "module_base_logging_required"
    ) is not True:
        raise GuardedProjectError("manifest must require module-base logging")
    negative_policy = manifest.get("negative_evidence_policy")
    if not isinstance(negative_policy, Mapping) or not negative_policy:
        raise GuardedProjectError("manifest negative-evidence policy is required")
    if any(value is not True for value in negative_policy.values()):
        raise GuardedProjectError("every declared negative-evidence gate must be enabled")
    layout_report = record_layout_lint(manifest)
    if not layout_report.valid:
        first = layout_report.diagnostics[0]
        raise GuardedProjectError(
            f"record-layout lint failed: {first.code} at {first.path}: {first.message}"
        )
    correlation_report = validate_native_stage_correlation(manifest)
    if not correlation_report.valid:
        first = correlation_report.diagnostics[0]
        raise GuardedProjectError(
            f"native-stage correlation failed: {first.code} at {first.path}: {first.message}"
        )
    probe_id = _checked_component(manifest.get("probe_id"), "probe_id")
    expected = manifest.get("expected_module")
    if not isinstance(expected, Mapping):
        raise GuardedProjectError("manifest expected_module is required")
    profile_id = _checked_component(expected.get("profile_id"), "manifest profile_id")
    manifest_module_hash = _checked_sha256(expected.get("sha256"), "manifest module SHA-256")
    try:
        manifest_timestamp = int(str(expected.get("timestamp")), 16)
    except (TypeError, ValueError) as exc:
        raise GuardedProjectError("manifest module timestamp is invalid") from exc
    manifest_image_size = expected.get("image_size")
    if not isinstance(manifest_image_size, int) or isinstance(manifest_image_size, bool):
        raise GuardedProjectError("manifest module image size is invalid")
    if profile.get("schema_version") != "kcd2.kcse-project-profile.v1":
        raise GuardedProjectError("profile must use kcd2.kcse-project-profile.v1")
    if set(profile) != _PROFILE_REQUIRED:
        raise GuardedProjectError("project profile must satisfy its closed v1 shape")
    if profile.get("profile_id") != profile_id:
        raise GuardedProjectError("manifest and project profile IDs differ")
    profile_module_hash = _checked_sha256(profile.get("module_sha256"), "profile module SHA-256")
    if profile_module_hash != manifest_module_hash:
        raise GuardedProjectError("manifest and profile module SHA-256 values differ")
    if profile.get("module_timestamp") != expected.get("timestamp"):
        raise GuardedProjectError("manifest and profile module timestamps differ")
    if profile.get("module_image_size") != manifest_image_size:
        raise GuardedProjectError("manifest and profile module image sizes differ")
    module_name = expected.get("name")
    if module_name != profile.get("module_name") or module_path.name.casefold() != str(
        module_name
    ).casefold():
        raise GuardedProjectError("module name is not locked to the manifest and profile")
    data, pe = _load_pe(module_path)
    actual_hash = _sha256_bytes(data)
    if actual_hash != manifest_module_hash:
        raise GuardedProjectError("module SHA-256 does not match the manifest/profile lock")
    if pe.timestamp != manifest_timestamp or pe.image_size != manifest_image_size:
        raise GuardedProjectError("raw PE timestamp/image size do not match the module lock")
    adapter_value = profile.get("adapter_source")
    if not isinstance(adapter_value, str) or not adapter_value or len(adapter_value) > 4096:
        raise GuardedProjectError("profile adapter_source must be a bounded explicit path")
    adapter_path = Path(adapter_value)
    if not adapter_path.is_file():
        raise GuardedProjectError("profile adapter_source must identify a reviewed source file")
    adapter_hash = _checked_sha256(profile.get("adapter_source_sha256"), "adapter SHA-256")
    if _sha256_file(adapter_path) != adapter_hash:
        raise GuardedProjectError("adapter source does not match its profile SHA-256")
    exports_value = profile.get("required_exports")
    if not isinstance(exports_value, list) or not exports_value or len(exports_value) > 256:
        raise GuardedProjectError("profile required_exports must be a non-empty list")
    exports = tuple(_checked_component(item, "required export") for item in exports_value)
    if len(set(exports)) != len(exports):
        raise GuardedProjectError("profile required_exports must be unique")
    api_version = profile.get("kcse_api_version")
    if not isinstance(api_version, str) or not api_version or len(api_version) > 128:
        raise GuardedProjectError("profile kcse_api_version must be bounded and non-empty")
    return probe_id, profile_id, actual_hash, adapter_path, exports, data, pe


def _project_files(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    adapter_path: Path,
    report: Mapping[str, Any],
) -> dict[str, bytes]:
    generated = generate_probe_contract(manifest)
    resolved_manifest = dict(generated.resolved_manifest)
    manifest_bytes = _canonical_bytes(resolved_manifest)
    profile_bytes = _canonical_bytes(profile)
    profile_hash = _sha256_bytes(profile_bytes)
    header = generated.header.encode("utf-8")
    profile_header = (
        "#pragma once\n\nnamespace kcd2::generated {\n"
        f'inline constexpr char kProjectProfileSha256[] = "{profile_hash}";\n'
        "}  // namespace kcd2::generated\n"
    ).encode("utf-8")
    blob_literal = json.dumps(generated.blob.decode("utf-8"), ensure_ascii=True)
    contract_source = (
        '#include "generated_probe_contract.hpp"\n'
        'extern "C" __declspec(selectany) const char kcd2_compiled_contract_sha256[] =\n'
        f'    "{generated.contract_sha256}";\n'
        'extern "C" __declspec(selectany) const char kcd2_compiled_contract_blob[] =\n'
        f"    {blob_literal};\n"
    ).encode("utf-8")
    carrier_source = (
        '#include "generated_probe_contract.hpp"\n'
        '#include "generated_project_profile.hpp"\n'
    ).encode("utf-8") + adapter_path.read_bytes()
    target = re.sub(r"[^A-Za-z0-9_]", "_", str(manifest["probe_id"]))
    cmake = (
        "cmake_minimum_required(VERSION 3.24)\n"
        f"project({target} LANGUAGES CXX)\n"
        f"add_library({target} SHARED probe_adapter.cpp generated_contract.cpp)\n"
        f"target_compile_features({target} PRIVATE cxx_std_20)\n"
        f"set_target_properties({target} PROPERTIES OUTPUT_NAME \"{target}\")\n"
    ).encode("utf-8")
    install_script = (
        "param([Parameter(Mandatory=$true)][string]$ToolchainRoot, "
        "[Parameter(Mandatory=$true)][string]$GuardReport, "
        "[Parameter(Mandatory=$true)][string]$BuildReport, "
        "[Parameter(Mandatory=$true)][string]$PeReport, "
        "[Parameter(Mandatory=$true)][string]$Dll, "
        "[Parameter(Mandatory=$true)][string]$Target, "
        "[Parameter(Mandatory=$true)][string]$Rollback, "
        "[Parameter(Mandatory=$true)][string]$Output)\n"
        "$ErrorActionPreference='Stop'\n"
        "$stager=Join-Path $ToolchainRoot 'scripts/stage_kcse_probe_transaction.py'\n"
        "python $stager --guard-report $GuardReport "
        "--build-report $BuildReport --pe-report $PeReport --dll $Dll --target $Target "
        "--rollback $Rollback --output $Output\n"
        "if ($LASTEXITCODE -ne 0) { throw 'Guarded install staging refused.' }\n"
        "Write-Host 'Plan staged only; no installed target was changed.'\n"
    ).encode("utf-8")
    rollback_script = (
        "param([Parameter(Mandatory=$true)][string]$TransactionPlan)\n"
        "$ErrorActionPreference='Stop'\n"
        "$plan=Get-Content -Raw -LiteralPath $TransactionPlan | ConvertFrom-Json\n"
        "if ($plan.schema_version -ne 'kcd2.kcse-staged-transaction.v1') "
        "{ throw 'Rollback plan schema mismatch.' }\n"
        "Write-Host 'Rollback is staged and hash-bound; no installed target was changed.'\n"
    ).encode("utf-8")
    return {
        "probe_contract.json": manifest_bytes,
        "probe_contract.blob": generated.blob,
        "compiled_contract.sha256": (generated.contract_sha256 + "\n").encode("ascii"),
        "project_profile.json": profile_bytes,
        "generated_probe_contract.hpp": header,
        "generated_project_profile.hpp": profile_header,
        "generated_contract.cpp": contract_source,
        "probe_adapter.cpp": carrier_source,
        "CMakeLists.txt": cmake,
        "Install-GuardedProbe.ps1": install_script,
        "Rollback-GuardedProbe.ps1": rollback_script,
    }


def generate_guarded_project(
    manifest: Mapping[str, Any],
    profile: Mapping[str, Any],
    module_path: Path,
    destination: Path,
) -> dict[str, Any]:
    """Generate one exact-profile KCSE project without compiling or installing it."""

    module_path = Path(module_path)
    destination = Path(destination)
    probe_id, profile_id, module_hash, adapter_path, exports, _data, pe = (
        _validate_generation_inputs(manifest, profile, module_path)
    )
    generated = generate_probe_contract(manifest)
    preflight = entry_lock_preflight(
        manifest,
        module_path,
        generated_header=generated.header,
    )
    if destination.name != probe_id:
        raise GuardedProjectError("destination directory must preserve the exact probe_id")
    if destination.exists() and any(destination.iterdir()):
        raise GuardedProjectError("destination must be absent or empty")
    hooks_value = manifest.get("hooks")
    if not isinstance(hooks_value, list) or not hooks_value:
        raise GuardedProjectError("manifest must declare at least one hook")
    hook_reports: list[dict[str, Any]] = []
    all_hazards: set[str] = set()
    seen: set[str] = set()
    for hook in hooks_value:
        if not isinstance(hook, Mapping) or not hook.get("enabled"):
            continue
        hook_id = _checked_component(hook.get("hook_id"), "hook_id")
        if hook_id in seen:
            raise GuardedProjectError("enabled hook IDs must be unique")
        seen.add(hook_id)
        rva_text = hook.get("rva")
        try:
            rva = int(str(rva_text), 16)
        except (TypeError, ValueError) as exc:
            raise GuardedProjectError(f"hook {hook_id} has an invalid RVA") from exc
        entry_lock = hook.get("entry_lock")
        if not isinstance(entry_lock, Mapping):
            raise GuardedProjectError(f"hook {hook_id} has no raw entry lock")
        if entry_lock.get("source") != "raw_pe_rva_mapping" or entry_lock.get(
            "raw_pe_preflight_required"
        ) is not True:
            raise GuardedProjectError(f"hook {hook_id} does not require raw PE preflight")
        try:
            locked = bytes.fromhex(str(entry_lock.get("bytes_hex", "")))
        except ValueError as exc:
            raise GuardedProjectError(f"hook {hook_id} entry lock is invalid hex") from exc
        if not locked or len(locked) > 256:
            raise GuardedProjectError(f"hook {hook_id} entry lock has an invalid size")
        observed = pe.read_rva(rva, len(locked))
        if observed != locked:
            raise GuardedProjectError(f"hook {hook_id} raw PE entry lock does not match")
        instructions, hazards = _inspect_stolen_instructions(locked)
        all_hazards.update(hazards)
        hook_reports.append(
            {
                "hook_id": hook_id,
                "rva": rva,
                "entry_lock_hex": locked.hex(" ").upper(),
                "instructions": instructions,
                "hazards": hazards,
                "trampoline_eligible": not hazards,
            }
        )
    if not hook_reports:
        raise GuardedProjectError("manifest has no enabled hook to generate")
    report: dict[str, Any] = {
        "schema_version": "kcd2.kcse-project-guard.v1",
        "probe_id": probe_id,
        "profile_id": profile_id,
        "profile_sha256": _sha256_bytes(_canonical_bytes(profile)),
        "module_name": module_path.name,
        "module_sha256": module_hash,
        "module_timestamp": f"0x{pe.timestamp:X}",
        "module_image_size": pe.image_size,
        "adapter_source_sha256": _sha256_file(adapter_path),
        "required_exports": list(exports),
        "pe_architecture": {0x8664: "x64", 0x14C: "x86"}.get(pe.machine, "unsupported"),
        "entry_lock_preflight": preflight,
        "hooks": hook_reports,
        "hazards": sorted(all_hazards),
        "install_eligible": not all_hazards and pe.machine == 0x8664,
    }
    files = _project_files(manifest, profile, adapter_path, report)
    resolved_manifest = json.loads(files["probe_contract.json"].decode("utf-8"))
    source_check = probe_source_manifest_check(
        resolved_manifest,
        generated_header=files["generated_probe_contract.hpp"],
        contract_blob=files["probe_contract.blob"],
        carrier_source=files["probe_adapter.cpp"],
        compiled_contract_sha256=files["compiled_contract.sha256"].decode("ascii").strip(),
    )
    if not source_check.valid:
        first = source_check.diagnostics[0]
        raise GuardedProjectError(
            f"source/manifest contract failed: {first.code} at {first.path}: {first.message}"
        )
    report["source_manifest_check"] = source_check.to_dict()
    report["manifest_contract_sha256"] = source_check.manifest_contract_sha256
    report["generated_header_sha256"] = source_check.generated_header_sha256
    report["compiled_contract_sha256"] = source_check.compiled_contract_sha256
    destination.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        (destination / relative).write_bytes(content)
    file_hashes = {name: _sha256_bytes(content) for name, content in sorted(files.items())}
    report["generated_files"] = file_hashes
    report["project_sha256"] = _sha256_bytes(_canonical_bytes(file_hashes))
    (destination / "guard-report.json").write_bytes(_canonical_bytes(report))
    return report


def _render_command(command: Sequence[str], source: Path, build: Path) -> list[str]:
    if not command or len(command) > 128:
        raise GuardedProjectError("build command must contain between 1 and 128 arguments")
    rendered = []
    for argument in command:
        if not isinstance(argument, str) or not argument or len(argument) > 8192:
            raise GuardedProjectError("build arguments must be bounded non-empty strings")
        rendered.append(argument.replace("{source}", str(source)).replace("{build}", str(build)))
    return rendered


def _clean_build_directory(build_root: Path, name: str) -> Path:
    resolved_root = build_root.resolve()
    target = (resolved_root / name).resolve()
    if target.parent != resolved_root:
        raise GuardedProjectError("clean build directory escaped its declared root")
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    return target


def _require_entry_lock_guard(guard_report: Mapping[str, Any]) -> Mapping[str, Any]:
    preflight = guard_report.get("entry_lock_preflight")
    if not isinstance(preflight, Mapping):
        raise GuardedProjectError("guard report is missing entry-lock preflight")
    if (
        preflight.get("schema_version") != "kcd2.entry-lock-preflight.v1"
        or preflight.get("valid") is not True
        or preflight.get("lock_source") != "raw_pe_rva_mapping"
        or preflight.get("generated_header_matches_manifest") is not True
    ):
        raise GuardedProjectError("guard report entry-lock preflight is invalid")
    module_hash = _checked_sha256(
        guard_report.get("module_sha256"), "guard module SHA-256"
    )
    if preflight.get("module_sha256") != module_hash:
        raise GuardedProjectError("entry-lock preflight module identity differs from guard report")
    hooks = preflight.get("hooks")
    if not isinstance(hooks, list) or not hooks or any(
        not isinstance(hook, Mapping) or hook.get("matches") is not True for hook in hooks
    ):
        raise GuardedProjectError("entry-lock preflight has no complete matching hook set")
    return preflight


def _recheck_project_entry_locks(
    project_directory: Path, guard_report: Mapping[str, Any]
) -> dict[str, Any]:
    stored = _require_entry_lock_guard(guard_report)
    project = Path(project_directory).resolve()
    if not project.is_dir():
        raise GuardedProjectError("entry-lock project directory does not exist")
    module_value = stored.get("module_path")
    if not isinstance(module_value, str) or not module_value or len(module_value) > 4096:
        raise GuardedProjectError("entry-lock preflight has no bounded module path")
    try:
        manifest = json.loads((project / "probe_contract.json").read_text(encoding="utf-8"))
        header = (project / "generated_probe_contract.hpp").read_bytes()
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardedProjectError("entry-lock project inputs are missing or invalid") from exc
    if not isinstance(manifest, Mapping):
        raise GuardedProjectError("project probe contract must be an object")
    current = entry_lock_preflight(
        manifest,
        Path(module_value),
        generated_header=header,
    )
    if (
        current.get("module_sha256") != stored.get("module_sha256")
        or current.get("generated_header_sha256") != stored.get("generated_header_sha256")
        or current.get("hooks") != stored.get("hooks")
    ):
        raise GuardedProjectError("current entry-lock preflight differs from the guard report")
    return current


def validate_double_build(
    project_directory: Path,
    build_root: Path,
    command: Sequence[str],
    output_relative_paths: Sequence[str],
    *,
    timeout_seconds: int = 600,
) -> dict[str, Any]:
    """Run two isolated clean builds and compare every declared output byte-for-byte."""

    source = Path(project_directory).resolve()
    if not source.is_dir():
        raise GuardedProjectError("project_directory must exist")
    guard_path = source / "guard-report.json"
    try:
        guard_report = json.loads(guard_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GuardedProjectError("project guard report is missing or invalid") from exc
    if not isinstance(guard_report, Mapping):
        raise GuardedProjectError("project guard report must be an object")
    _recheck_project_entry_locks(source, guard_report)
    if timeout_seconds < 1 or timeout_seconds > 3600:
        raise GuardedProjectError("build timeout must be between 1 and 3600 seconds")
    if not output_relative_paths or len(output_relative_paths) > MAX_BUILD_OUTPUTS:
        raise GuardedProjectError("declared build outputs are missing or exceed the bound")
    outputs = tuple(_checked_relative_path(item, "build output") for item in output_relative_paths)
    if len(set(outputs)) != len(outputs):
        raise GuardedProjectError("declared build outputs must be unique")
    build_root = Path(build_root)
    build_root.mkdir(parents=True, exist_ok=True)
    builds: list[dict[str, Any]] = []
    for name in ("clean-a", "clean-b"):
        build = _clean_build_directory(build_root, name)
        rendered = _render_command(command, source, build)
        completed = subprocess.run(
            rendered,
            cwd=source,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise GuardedProjectError(
                f"{name} failed with exit {completed.returncode}: {completed.stderr[-2000:]}"
            )
        identities: dict[str, dict[str, Any]] = {}
        for relative in outputs:
            path = (build / relative).resolve()
            if not path.is_relative_to(build.resolve()) or not path.is_file():
                raise GuardedProjectError(f"{name} did not produce {relative.as_posix()}")
            identities[relative.as_posix()] = {
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
        builds.append({"name": name, "outputs": identities})
    first = builds[0]["outputs"]
    second = builds[1]["outputs"]
    mismatched = [name for name in sorted(first) if first[name] != second[name]]
    matched = not mismatched
    if len(first) == 1:
        output_sha256 = next(iter(first.values()))["sha256"] if matched else None
    else:
        output_sha256 = _sha256_bytes(_canonical_bytes(first)) if matched else None
    return {
        "schema_version": "kcd2.double-build-validation.v1",
        "project_directory": str(source),
        "command": list(command),
        "builds": builds,
        "matched": matched,
        "mismatched_outputs": mismatched,
        "output_sha256": output_sha256,
        "install_eligible": matched,
    }


def stage_install_and_rollback(
    guard_report: Mapping[str, Any],
    build_report: Mapping[str, Any],
    pe_report: Mapping[str, Any],
    dll_path: Path,
    target_path: Path,
    rollback_path: Path,
    *,
    project_directory: Path,
) -> dict[str, Any]:
    """Create a hash-bound transaction plan; this function never mutates target paths."""

    if guard_report.get("install_eligible") is not True:
        raise GuardedProjectError("guard report blocks installation")
    _recheck_project_entry_locks(project_directory, guard_report)
    if build_report.get("matched") is not True:
        raise GuardedProjectError("two clean builds did not match")
    if pe_report.get("matches_expected") is not True or pe_report.get("architecture") != "x64":
        raise GuardedProjectError("PE architecture or exact export validation failed")
    dll_path = Path(dll_path).resolve()
    if not dll_path.is_file():
        raise GuardedProjectError("compiled DLL does not exist")
    dll_hash = _sha256_file(dll_path)
    if build_report.get("output_sha256") != dll_hash:
        raise GuardedProjectError("build output digest does not match the staged DLL")
    if pe_report.get("sha256") != dll_hash:
        raise GuardedProjectError("PE inspection digest does not match the staged DLL")
    target = Path(target_path).resolve()
    rollback = Path(rollback_path).resolve()
    if target == rollback or target == dll_path or rollback == dll_path:
        raise GuardedProjectError("source, target, and rollback paths must be distinct")
    plan: dict[str, Any] = {
        "schema_version": "kcd2.kcse-staged-transaction.v1",
        "operation_state": "staged_non_live",
        "module_sha256": _checked_sha256(
            guard_report.get("module_sha256"), "guard module SHA-256"
        ),
        "profile_id": _checked_component(
            guard_report.get("profile_id"), "guard profile_id"
        ),
        "profile_sha256": _checked_sha256(
            guard_report.get("profile_sha256"), "guard profile SHA-256"
        ),
        "install": {
            "source_path": str(dll_path),
            "source_sha256": dll_hash,
            "target_path": str(target),
            "precondition": "target identity must be captured before separate install approval",
        },
        "rollback": {
            "rollback_path": str(rollback),
            "target_path": str(target),
            "installed_sha256": dll_hash,
            "precondition": "restore only exact bytes captured by the approved install receipt",
        },
        "live_side_effects": "none",
    }
    plan["plan_sha256"] = _sha256_bytes(_canonical_bytes(plan))
    return plan
