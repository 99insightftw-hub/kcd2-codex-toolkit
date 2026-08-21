"""Deterministic manifest-generated source and compiled-contract agreement checks."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


MAX_CONTRACT_BYTES = 8 * 1024 * 1024
MAX_CARRIER_SOURCE_BYTES = 4 * 1024 * 1024
_HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
_SOURCE_HOOK = re.compile(r"\bKCD2_SOURCE_HOOK\(\s*([A-Za-z][A-Za-z0-9_.-]{0,127})\s*\)")
_DORMANT_HOOK = re.compile(r"\bKCD2_DORMANT_HOOK\(\s*([A-Za-z][A-Za-z0-9_.-]{0,127})\s*\)")
_SOURCE_EVENT = re.compile(r"\bKCD2_SOURCE_EVENT\(\s*([A-Za-z][A-Za-z0-9_.-]{0,127})\s*\)")
_RVA_LITERAL = re.compile(r"\b0[xX][0-9A-Fa-f]+\b")
_CONTRACT_REDECLARATION = re.compile(
    r"\b(?:constexpr|const)\b[^;\n]*(?:kHook_|kEventLimit_|kEventSchema_|"
    r"kIdentityMatcher_|kContractSha256|kExpectedModule|kModuleBaseLoggingRequired)"
)
_HEADER_INCLUDE = re.compile(
    r'^\s*#\s*include\s*[<\"]generated_probe_contract\.hpp[>\"]\s*$', re.MULTILINE
)


class ProbeSourceContractError(ValueError):
    """Raised when a manifest cannot produce one bounded deterministic contract."""


@dataclass(frozen=True, slots=True)
class SourceContractDiagnostic:
    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True, slots=True)
class GeneratedProbeContract:
    contract: Mapping[str, Any]
    blob: bytes
    header: str
    contract_sha256: str
    header_sha256: str
    resolved_manifest: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ProbeSourceManifestReport:
    manifest_contract_sha256: str
    generated_header_sha256: str
    compiled_contract_sha256: str
    diagnostics: tuple[SourceContractDiagnostic, ...]

    @property
    def valid(self) -> bool:
        return not self.diagnostics

    @property
    def diagnostic_codes(self) -> tuple[str, ...]:
        return tuple(item.code for item in self.diagnostics)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.probe-source-manifest-check.v1",
            "valid": self.valid,
            "manifest_contract_sha256": self.manifest_contract_sha256,
            "generated_header_sha256": self.generated_header_sha256,
            "compiled_contract_sha256": self.compiled_contract_sha256,
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProbeSourceContractError("manifest must contain bounded JSON values") from exc
    if len(encoded) > MAX_CONTRACT_BYTES:
        raise ProbeSourceContractError("generated contract exceeds the byte ceiling")
    return encoded


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ProbeSourceContractError(f"{label} must be a bounded non-empty string")
    identifier = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not identifier or identifier[0].isdigit():
        identifier = "_" + identifier
    return identifier


def _contract_payload(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != "kcd2.probe-contract.v2":
        raise ProbeSourceContractError("manifest must use kcd2.probe-contract.v2")
    try:
        payload = copy.deepcopy(dict(manifest))
    except (TypeError, ValueError) as exc:
        raise ProbeSourceContractError("manifest must be a JSON object") from exc
    source_contract = payload.get("source_contract")
    if not isinstance(source_contract, dict):
        raise ProbeSourceContractError("manifest source_contract must be an object")
    if source_contract.get("module_base_logging_required") is not True:
        raise ProbeSourceContractError("manifest must require module-base logging")
    policy = source_contract.get("unused_hook_policy")
    if policy not in {"reject", "allow_explicit_dormant_only"}:
        raise ProbeSourceContractError("manifest unused-hook policy is invalid")
    payload["source_contract"] = {
        "module_base_logging_required": True,
        "unused_hook_policy": policy,
    }
    return payload


def _checked_named_objects(manifest: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    value = manifest.get(name)
    if not isinstance(value, Mapping) or not value or len(value) > 128:
        raise ProbeSourceContractError(f"manifest {name} must be a bounded non-empty map")
    if any(not isinstance(key, str) or not key or len(key) > 128 for key in value):
        raise ProbeSourceContractError(f"manifest {name} has an invalid name")
    return value


def _unique_identifiers(names: list[str], label: str) -> dict[str, str]:
    identifiers = {name: _identifier(name, label) for name in names}
    if len(set(identifiers.values())) != len(identifiers):
        raise ProbeSourceContractError(f"{label} names collide after C++ identifier encoding")
    return identifiers


def _cpp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _render_header(payload: Mapping[str, Any], contract_sha256: str) -> str:
    expected_module = payload.get("expected_module")
    if not isinstance(expected_module, Mapping):
        raise ProbeSourceContractError("manifest expected_module must be an object")
    hooks = payload.get("hooks")
    identities = payload.get("identity_matchers")
    if not isinstance(hooks, list) or not hooks or len(hooks) > 64:
        raise ProbeSourceContractError("manifest hooks must be a bounded non-empty list")
    if not isinstance(identities, list) or len(identities) > 128:
        raise ProbeSourceContractError("manifest identity_matchers must be a bounded list")
    event_schemas = _checked_named_objects(payload, "event_schemas")
    event_limits = _checked_named_objects(payload, "event_limits")
    if set(event_schemas) != set(event_limits):
        raise ProbeSourceContractError("event_schemas and event_limits must name the same families")

    hook_names: list[str] = []
    for hook in hooks:
        if not isinstance(hook, Mapping) or not isinstance(hook.get("hook_id"), str):
            raise ProbeSourceContractError("every hook must have a string hook_id")
        hook_names.append(hook["hook_id"])
    if len(set(hook_names)) != len(hook_names):
        raise ProbeSourceContractError("hook IDs must be unique")
    identity_names: list[str] = []
    for identity in identities:
        if not isinstance(identity, Mapping) or not isinstance(identity.get("matcher_id"), str):
            raise ProbeSourceContractError("every identity matcher must have a string matcher_id")
        identity_names.append(identity["matcher_id"])
    if len(set(identity_names)) != len(identity_names):
        raise ProbeSourceContractError("identity matcher IDs must be unique")

    hook_ids = _unique_identifiers(hook_names, "hook")
    event_ids = _unique_identifiers(list(event_schemas), "event family")
    identity_ids = _unique_identifiers(identity_names, "identity matcher")
    lines = [
        "#pragma once",
        "#include <cstdint>",
        "",
        "#define KCD2_SOURCE_HOOK(name)",
        "#define KCD2_DORMANT_HOOK(name)",
        "#define KCD2_SOURCE_EVENT(name)",
        "",
        "namespace kcd2::generated {",
        "struct HookContract {",
        "  const char* hook_id;",
        "  std::uint64_t rva;",
        "  const char* entry_lock_hex;",
        "  bool enabled;",
        "  bool dormant_helper;",
        "};",
        "struct EventLimit { std::uint64_t maximum_events; std::uint64_t maximum_bytes; };",
        f"inline constexpr char kProbeId[] = {_cpp_string(str(payload.get('probe_id')))};",
        f"inline constexpr char kProbeRevision[] = {_cpp_string(str(payload.get('revision')))};",
        f"inline constexpr char kContractSha256[] = {_cpp_string(contract_sha256)};",
        "inline constexpr bool kModuleBaseLoggingRequired = true;",
        "inline constexpr char kExpectedModuleName[] = "
        f"{_cpp_string(str(expected_module.get('name')))};",
        "inline constexpr char kExpectedModuleSha256[] = "
        f"{_cpp_string(str(expected_module.get('sha256')))};",
        "inline constexpr char kExpectedProfileId[] = "
        f"{_cpp_string(str(expected_module.get('profile_id')))};",
    ]
    for hook in sorted(hooks, key=lambda item: item["hook_id"]):
        entry_lock = hook.get("entry_lock")
        if not isinstance(entry_lock, Mapping):
            raise ProbeSourceContractError(f"hook {hook['hook_id']} has no entry_lock")
        try:
            rva = int(str(hook.get("rva")), 16)
        except (TypeError, ValueError) as exc:
            raise ProbeSourceContractError(f"hook {hook['hook_id']} has an invalid RVA") from exc
        name = hook_ids[hook["hook_id"]]
        lines.append(
            f"inline constexpr HookContract kHook_{name}{{"
            f"{_cpp_string(hook['hook_id'])}, 0x{rva:X}, "
            f"{_cpp_string(str(entry_lock.get('bytes_hex')))}, "
            f"{'true' if hook.get('enabled') is True else 'false'}, "
            f"{'true' if hook.get('dormant_helper') is True else 'false'}}};"
        )
        lines.append(
            f"inline constexpr char kHookContract_{name}[] = "
            f"{_cpp_string(json.dumps(hook, sort_keys=True, separators=(',', ':')))};"
        )
    for event_name in sorted(event_schemas):
        limit = event_limits[event_name]
        if not isinstance(limit, Mapping):
            raise ProbeSourceContractError(f"event limit {event_name} must be an object")
        maximum_events = limit.get("maximum_events")
        maximum_bytes = limit.get("maximum_bytes")
        if (
            not isinstance(maximum_events, int)
            or isinstance(maximum_events, bool)
            or not 1 <= maximum_events <= 100_000
            or not isinstance(maximum_bytes, int)
            or isinstance(maximum_bytes, bool)
            or not 1 <= maximum_bytes <= 33_554_432
        ):
            raise ProbeSourceContractError(f"event limit {event_name} exceeds its hard bounds")
        name = event_ids[event_name]
        lines.append(
            f"inline constexpr EventLimit kEventLimit_{name}{{{maximum_events}, {maximum_bytes}}};"
        )
        schema_json = json.dumps(
            event_schemas[event_name], sort_keys=True, separators=(",", ":")
        )
        lines.append(
            f"inline constexpr char kEventSchema_{name}[] = "
            f"{_cpp_string(schema_json)};"
        )
    for identity in sorted(identities, key=lambda item: item["matcher_id"]):
        name = identity_ids[identity["matcher_id"]]
        lines.append(
            f"inline constexpr char kIdentityMatcher_{name}[] = "
            f"{_cpp_string(json.dumps(identity, sort_keys=True, separators=(',', ':')))};"
        )
    lines.extend(["}  // namespace kcd2::generated", ""])
    return "\n".join(lines)


def generate_probe_contract(manifest: Mapping[str, Any]) -> GeneratedProbeContract:
    """Generate the canonical blob/header and resolved derived hashes from one manifest."""

    payload = _contract_payload(manifest)
    blob = _canonical_bytes(payload)
    contract_sha256 = _sha256(blob)
    header = _render_header(payload, contract_sha256)
    header_bytes = header.encode("utf-8")
    if len(header_bytes) > MAX_CONTRACT_BYTES:
        raise ProbeSourceContractError("generated header exceeds the byte ceiling")
    header_sha256 = _sha256(header_bytes)
    resolved = copy.deepcopy(dict(manifest))
    resolved_source = resolved["source_contract"]
    resolved_source["manifest_sha256"] = contract_sha256
    resolved_source["generated_header_sha256"] = header_sha256
    resolved_source["compiled_contract_sha256"] = contract_sha256
    return GeneratedProbeContract(
        MappingProxyType(payload),
        blob,
        header,
        contract_sha256,
        header_sha256,
        MappingProxyType(resolved),
    )


def _source_diagnostics(manifest: Mapping[str, Any], source: str) -> list[SourceContractDiagnostic]:
    diagnostics: list[SourceContractDiagnostic] = []
    hooks_value = manifest.get("hooks")
    schemas_value = manifest.get("event_schemas")
    source_value = manifest.get("source_contract")
    hooks = hooks_value if isinstance(hooks_value, list) else []
    schemas = schemas_value if isinstance(schemas_value, Mapping) else {}
    source_contract = source_value if isinstance(source_value, Mapping) else {}
    active_hooks = {
        hook.get("hook_id")
        for hook in hooks
        if isinstance(hook, Mapping) and hook.get("enabled") is True
    }
    dormant_hooks = {
        hook.get("hook_id")
        for hook in hooks
        if isinstance(hook, Mapping)
        and hook.get("enabled") is False
        and hook.get("dormant_helper") is True
    }
    observed_active = set(_SOURCE_HOOK.findall(source))
    observed_dormant = set(_DORMANT_HOOK.findall(source))
    observed_events = set(_SOURCE_EVENT.findall(source))
    for hook_id in sorted(observed_active - active_hooks):
        diagnostics.append(
            SourceContractDiagnostic(
                "UNMANIFESTED_SOURCE_HOOK",
                "carrier_source",
                f"active source hook {hook_id!r} is absent or not enabled in the manifest",
            )
        )
    for hook_id in sorted(active_hooks - observed_active):
        diagnostics.append(
            SourceContractDiagnostic(
                "UNUSED_MANIFEST_HOOK",
                f"hooks[{hook_id}]",
                "enabled manifest hook has no KCD2_SOURCE_HOOK carrier declaration",
            )
        )
    policy = source_contract.get("unused_hook_policy")
    for hook_id in sorted(observed_dormant):
        if hook_id not in dormant_hooks:
            diagnostics.append(
                SourceContractDiagnostic(
                    "UNDECLARED_DORMANT_HOOK",
                    "carrier_source",
                    f"dormant source hook {hook_id!r} is not explicitly dormant in the manifest",
                )
            )
        elif policy != "allow_explicit_dormant_only":
            diagnostics.append(
                SourceContractDiagnostic(
                    "DORMANT_HOOK_POLICY_REJECTS",
                    f"hooks[{hook_id}]",
                    "manifest unused-hook policy does not allow dormant helpers",
                )
            )
    for hook_id in sorted(dormant_hooks - observed_dormant):
        diagnostics.append(
            SourceContractDiagnostic(
                "UNUSED_DORMANT_MANIFEST_HOOK",
                f"hooks[{hook_id}]",
                "manifest declares a dormant helper that is absent from carrier source",
            )
        )
    event_names = set(schemas)
    for event_name in sorted(observed_events - event_names):
        diagnostics.append(
            SourceContractDiagnostic(
                "UNMANIFESTED_SOURCE_EVENT",
                "carrier_source",
                f"source event {event_name!r} is absent from manifest event_schemas",
            )
        )
    for event_name in sorted(event_names - observed_events):
        diagnostics.append(
            SourceContractDiagnostic(
                "UNUSED_MANIFEST_EVENT",
                f"event_schemas.{event_name}",
                "manifest event family has no KCD2_SOURCE_EVENT carrier declaration",
            )
        )
    if _HEADER_INCLUDE.search(source) is None:
        diagnostics.append(
            SourceContractDiagnostic(
                "GENERATED_HEADER_NOT_INCLUDED",
                "carrier_source",
                "carrier source must include generated_probe_contract.hpp",
            )
        )
    for literal in sorted(set(_RVA_LITERAL.findall(source))):
        diagnostics.append(
            SourceContractDiagnostic(
                "CARRIER_RVA_LITERAL",
                "carrier_source",
                f"carrier source duplicates RVA literal {literal}; use a generated hook constant",
            )
        )
    if _CONTRACT_REDECLARATION.search(source) is not None:
        diagnostics.append(
            SourceContractDiagnostic(
                "CARRIER_CONTRACT_REDECLARATION",
                "carrier_source",
                "carrier source redeclares generated contract data",
            )
        )
    return diagnostics


def probe_source_manifest_check(
    manifest: Mapping[str, Any],
    *,
    generated_header: bytes | str,
    contract_blob: bytes,
    carrier_source: bytes | str,
    compiled_contract_sha256: str,
) -> ProbeSourceManifestReport:
    """Fail closed on manifest/header/blob/carrier/compiled contract drift."""

    expected = generate_probe_contract(manifest)
    header_bytes = (
        generated_header.encode("utf-8") if isinstance(generated_header, str) else generated_header
    )
    source_bytes = (
        carrier_source.encode("utf-8") if isinstance(carrier_source, str) else carrier_source
    )
    if not isinstance(header_bytes, bytes) or len(header_bytes) > MAX_CONTRACT_BYTES:
        raise ProbeSourceContractError("generated header input exceeds its byte ceiling")
    if not isinstance(contract_blob, bytes) or len(contract_blob) > MAX_CONTRACT_BYTES:
        raise ProbeSourceContractError("contract blob input exceeds its byte ceiling")
    if not isinstance(source_bytes, bytes) or len(source_bytes) > MAX_CARRIER_SOURCE_BYTES:
        raise ProbeSourceContractError("carrier source input exceeds its byte ceiling")
    try:
        source = source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProbeSourceContractError("carrier source must be UTF-8") from exc
    diagnostics: list[SourceContractDiagnostic] = []
    if header_bytes != expected.header.encode("utf-8"):
        diagnostics.append(
            SourceContractDiagnostic(
                "GENERATED_HEADER_MISMATCH",
                "generated_probe_contract.hpp",
                "generated header bytes do not match the manifest",
            )
        )
    if contract_blob != expected.blob:
        diagnostics.append(
            SourceContractDiagnostic(
                "CONTRACT_BLOB_MISMATCH",
                "probe_contract.blob",
                "canonical contract blob bytes do not match the manifest",
            )
        )
    declared = manifest.get("source_contract")
    declared_source = declared if isinstance(declared, Mapping) else {}
    declared_checks = (
        ("manifest_sha256", expected.contract_sha256, "MANIFEST_CONTRACT_HASH_MISMATCH"),
        ("generated_header_sha256", expected.header_sha256, "MANIFEST_HEADER_HASH_MISMATCH"),
        ("compiled_contract_sha256", expected.contract_sha256, "MANIFEST_COMPILED_HASH_MISMATCH"),
    )
    for field, wanted, code in declared_checks:
        if declared_source.get(field) != wanted:
            diagnostics.append(
                SourceContractDiagnostic(
                    code,
                    f"source_contract.{field}",
                    f"declared {field} does not match generated contract output",
                )
            )
    normalized_compiled = (
        compiled_contract_sha256.lower()
        if isinstance(compiled_contract_sha256, str)
        and _HEX_64.fullmatch(compiled_contract_sha256) is not None
        else ""
    )
    if normalized_compiled != expected.contract_sha256:
        diagnostics.append(
            SourceContractDiagnostic(
                "COMPILED_CONTRACT_HASH_MISMATCH",
                "compiled_contract_sha256",
                "compiled contract hash does not equal the manifest contract hash",
            )
        )
    diagnostics.extend(_source_diagnostics(manifest, source))
    ordered = tuple(sorted(diagnostics, key=lambda item: (item.code, item.path, item.message)))
    return ProbeSourceManifestReport(
        expected.contract_sha256,
        _sha256(header_bytes),
        normalized_compiled,
        ordered,
    )
