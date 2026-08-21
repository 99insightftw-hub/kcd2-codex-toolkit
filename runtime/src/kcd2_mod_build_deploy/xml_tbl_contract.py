"""Path- and build-specific XML/TBL package-promotion contract."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping


MAX_TABLES = 256
MAX_PATH_CHARS = 2048
_HEX = frozenset("0123456789abcdefABCDEF")
_VERDICT_KEYS = frozenset(
    {
        "schema_version",
        "game_build",
        "whgame_sha256",
        "internal_path",
        "xml_sha256",
        "verdict",
        "package_promotion",
        "tbl_artifacts",
        "evidence_refs",
        "waiver",
    }
)
_WAIVER_KEYS = frozenset(
    {
        "schema_version",
        "waiver_id",
        "game_build",
        "whgame_sha256",
        "internal_path",
        "xml_sha256",
        "approved_by_user",
        "reason",
        "evidence_refs",
    }
)


class XmlTblContractError(ValueError):
    """The supplied path-specific contract is incomplete or internally inconsistent."""


class PackagePromotion(str, Enum):
    BLOCKED = "BLOCKED"
    PACKAGE_VALIDATED = "PACKAGE_VALIDATED"
    PACKAGE_VALIDATED_WITH_SCOPED_WAIVER = (
        "PACKAGE_VALIDATED_WITH_SCOPED_WAIVER"
    )


class TblVerdict(str, Enum):
    REQUIRED_AND_MATCHED = "TBL_REQUIRED_AND_MATCHED"
    NOT_REQUIRED_WITH_EVIDENCE = "TBL_NOT_REQUIRED_WITH_EVIDENCE"
    REQUIREMENT_UNKNOWN = "TBL_REQUIREMENT_UNKNOWN"


@dataclass(frozen=True, slots=True)
class ChangedXmlTable:
    internal_path: str
    xml_sha256: str


@dataclass(frozen=True, slots=True)
class XmlTblContractReport:
    game_build: str
    whgame_sha256: str | None
    package_promotion: PackagePromotion
    xml_tbl_gate: str
    changed_paths: tuple[str, ...]
    waived_paths: tuple[str, ...]
    verdict_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.xml-tbl-contract-report.v1",
            "game_build": self.game_build,
            "whgame_sha256": self.whgame_sha256,
            "package_promotion": self.package_promotion.value,
            "xml_tbl_gate": self.xml_tbl_gate,
            "changed_paths": list(self.changed_paths),
            "waived_paths": list(self.waived_paths),
            "verdict_refs": list(self.verdict_refs),
            "reason_codes": list(self.reason_codes),
        }


def changed_xml_tables_from_parent_diff(report: Any) -> tuple[ChangedXmlTable, ...]:
    """Extract candidate-side XML byte changes from a DEP-204 machine ledger."""
    if isinstance(report, Mapping):
        entries = report.get("entries")
    else:
        entries = getattr(report, "ledger", None)
    if not isinstance(entries, (list, tuple)):
        raise XmlTblContractError("parent diff report must expose a bounded ledger")
    if len(entries) > 100_000:
        raise XmlTblContractError("parent diff ledger exceeds 100000 entries")
    by_path: dict[str, str] = {}
    for entry in entries:
        if isinstance(entry, Mapping):
            comparison = entry.get("comparison")
            kind = entry.get("kind")
            raw_path = entry.get("member_path")
            after_hash = entry.get("after_sha256")
        else:
            comparison = getattr(entry, "comparison", None)
            kind = getattr(entry, "kind", None)
            raw_path = getattr(entry, "member_path", None)
            after_hash = getattr(entry, "after_sha256", None)
        if comparison != "declared_parent_to_candidate" or kind != "byte_changed":
            continue
        if not isinstance(raw_path, str) or not raw_path.casefold().endswith(".xml"):
            continue
        path = _path(raw_path, "parent diff member_path")
        digest = _sha256(after_hash, "parent diff after_sha256").lower()
        prior = by_path.setdefault(path, digest)
        if prior != digest:
            raise XmlTblContractError(f"parent diff has conflicting XML hashes for {path}")
    return tuple(
        ChangedXmlTable(path, digest)
        for path, digest in sorted(by_path.items(), key=lambda item: item[0].encode("utf-8"))
    )


def validate_xml_tbl_contract(
    changed_xml_tables: Iterable[Mapping[str, Any] | ChangedXmlTable],
    verdict_documents: Iterable[Mapping[str, Any]],
    *,
    game_build: str,
    whgame_sha256: str | None = None,
) -> XmlTblContractReport:
    """Require exactly one verdict for each changed XML path and candidate byte hash.

    A verdict is never reused as a global rule: its path, game build, optional module
    hash, and candidate XML hash must all match the table under review. Unknown
    requirements remain blocked unless that same tuple has an explicit user waiver.
    """
    build = _text(game_build, "game_build", 128)
    module_hash = _optional_sha256(whgame_sha256, "whgame_sha256")
    changed = _parse_changed(changed_xml_tables)
    documents = _detach_documents(verdict_documents)
    if len(documents) > MAX_TABLES:
        raise XmlTblContractError(f"at most {MAX_TABLES} verdict documents are allowed")

    by_path: dict[str, list[dict[str, Any]]] = {}
    for document in documents:
        path = _path(document.get("internal_path"), "verdict internal_path")
        by_path.setdefault(path, []).append(document)

    changed_paths = {table.internal_path for table in changed}
    extra = sorted(set(by_path) - changed_paths, key=str.encode)
    if extra:
        raise XmlTblContractError(f"verdict supplied for unchanged XML path: {extra[0]}")

    waived: list[str] = []
    blocked: list[str] = []
    refs: list[str] = []
    for table in changed:
        matches = by_path.get(table.internal_path, [])
        if not matches:
            raise XmlTblContractError(
                f"missing verdict for changed XML path: {table.internal_path}"
            )
        if len(matches) != 1:
            raise XmlTblContractError(
                f"duplicate verdict for changed XML path: {table.internal_path}"
            )
        document = matches[0]
        promotion = _validate_verdict(document, table, build, module_hash)
        ref_identity = json.dumps(
            {
                "game_build": build,
                "internal_path": table.internal_path,
                "xml_sha256": table.xml_sha256,
                "whgame_sha256": module_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        refs.append(f"xml-tbl-verdict:sha256:{hashlib.sha256(ref_identity).hexdigest()}")
        if promotion is PackagePromotion.BLOCKED:
            blocked.append(table.internal_path)
        elif promotion is PackagePromotion.PACKAGE_VALIDATED_WITH_SCOPED_WAIVER:
            waived.append(table.internal_path)

    ordered_paths = tuple(table.internal_path for table in changed)
    ordered_refs = tuple(refs)
    if blocked:
        return XmlTblContractReport(
            build,
            module_hash,
            PackagePromotion.BLOCKED,
            "BLOCKED",
            ordered_paths,
            tuple(waived),
            ordered_refs,
            ("UNKNOWN_WITHOUT_WAIVER",),
        )
    if waived:
        return XmlTblContractReport(
            build,
            module_hash,
            PackagePromotion.PACKAGE_VALIDATED_WITH_SCOPED_WAIVER,
            "UNKNOWN_WITH_SCOPED_WAIVER",
            ordered_paths,
            tuple(waived),
            ordered_refs,
            ("SCOPED_WAIVER_APPLIED",),
        )
    return XmlTblContractReport(
        build,
        module_hash,
        PackagePromotion.PACKAGE_VALIDATED,
        "NOT_APPLICABLE" if not changed else "CLEAR",
        ordered_paths,
        (),
        ordered_refs,
        ("NO_CHANGED_XML_TABLES",) if not changed else (),
    )


def _parse_changed(
    values: Iterable[Mapping[str, Any] | ChangedXmlTable],
) -> tuple[ChangedXmlTable, ...]:
    try:
        raw = list(values)
    except TypeError as exc:
        raise XmlTblContractError("changed_xml_tables must be iterable") from exc
    if len(raw) > MAX_TABLES:
        raise XmlTblContractError(f"at most {MAX_TABLES} changed XML tables are allowed")
    parsed: list[ChangedXmlTable] = []
    seen: set[str] = set()
    for item in raw:
        if isinstance(item, ChangedXmlTable):
            path = _path(item.internal_path, "changed internal_path")
            digest = _sha256(item.xml_sha256, "changed xml_sha256")
        elif isinstance(item, Mapping):
            path = _path(item.get("internal_path"), "changed internal_path")
            digest = _sha256(item.get("xml_sha256"), "changed xml_sha256")
        else:
            raise XmlTblContractError("changed XML table entries must be mappings")
        if path in seen:
            raise XmlTblContractError(f"duplicate changed XML path: {path}")
        seen.add(path)
        parsed.append(ChangedXmlTable(path, digest.lower()))
    return tuple(sorted(parsed, key=lambda item: item.internal_path.encode("utf-8")))


def _detach_documents(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    try:
        raw = list(values)
    except TypeError as exc:
        raise XmlTblContractError("verdict_documents must be iterable") from exc
    detached: list[dict[str, Any]] = []
    for value in raw:
        if not isinstance(value, Mapping):
            raise XmlTblContractError("verdict documents must be mappings")
        try:
            copy = json.loads(
                json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            )
        except (TypeError, ValueError) as exc:
            raise XmlTblContractError("verdict documents must contain JSON values") from exc
        detached.append(copy)
    return detached


def _validate_verdict(
    document: Mapping[str, Any],
    table: ChangedXmlTable,
    game_build: str,
    whgame_sha256: str | None,
) -> PackagePromotion:
    _exact_keys(
        document,
        _VERDICT_KEYS,
        "verdict",
        required=_VERDICT_KEYS - {"whgame_sha256", "tbl_artifacts"},
    )
    if document.get("schema_version") != "kcd2.xml-tbl-verdict.v1":
        raise XmlTblContractError("unsupported XML/TBL verdict schema_version")
    if _text(document.get("game_build"), "verdict game_build", 128) != game_build:
        raise XmlTblContractError(f"verdict game build mismatch for {table.internal_path}")
    if _sha256(document.get("xml_sha256"), "verdict xml_sha256").lower() != table.xml_sha256:
        raise XmlTblContractError(f"verdict XML hash mismatch for {table.internal_path}")
    verdict_module = _optional_sha256(document.get("whgame_sha256"), "verdict whgame_sha256")
    if whgame_sha256 is not None and verdict_module != whgame_sha256:
        raise XmlTblContractError(f"verdict WHGame hash mismatch for {table.internal_path}")
    evidence = document.get("evidence_refs")
    if not isinstance(evidence, list) or not evidence or len(evidence) > 256:
        raise XmlTblContractError("verdict evidence_refs must be a non-empty bounded list")
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in evidence):
        raise XmlTblContractError("verdict evidence_refs contain an invalid reference")
    if len(set(evidence)) != len(evidence):
        raise XmlTblContractError("verdict evidence_refs must be unique")
    artifacts = _validate_tbl_artifacts(document.get("tbl_artifacts", []))
    try:
        verdict = TblVerdict(document.get("verdict"))
        promotion = PackagePromotion(document.get("package_promotion"))
    except (TypeError, ValueError) as exc:
        raise XmlTblContractError("invalid verdict or package_promotion") from exc
    waiver = document.get("waiver")
    if verdict is TblVerdict.REQUIREMENT_UNKNOWN:
        if promotion is PackagePromotion.PACKAGE_VALIDATED:
            raise XmlTblContractError("UNKNOWN cannot promote to PACKAGE_VALIDATED")
        if promotion is PackagePromotion.BLOCKED:
            if waiver is not None:
                raise XmlTblContractError("a blocked UNKNOWN verdict cannot carry a waiver")
            return promotion
        _validate_waiver(waiver, table, game_build, verdict_module)
        return promotion
    if promotion is not PackagePromotion.PACKAGE_VALIDATED or waiver is not None:
        raise XmlTblContractError("known verdicts require unwaived PACKAGE_VALIDATED")
    if verdict is TblVerdict.REQUIRED_AND_MATCHED:
        if not any(item[2] == "compiled_counterpart" for item in artifacts):
            raise XmlTblContractError("TBL_REQUIRED_AND_MATCHED needs a compiled counterpart")
    return promotion


def _validate_waiver(
    value: Any,
    table: ChangedXmlTable,
    game_build: str,
    whgame_sha256: str | None,
) -> None:
    if not isinstance(value, Mapping):
        raise XmlTblContractError("qualified UNKNOWN verdict requires a scoped waiver")
    _exact_keys(value, _WAIVER_KEYS, "waiver")
    if value.get("schema_version") != "kcd2.xml-tbl-waiver.v1":
        raise XmlTblContractError("unsupported XML/TBL waiver schema_version")
    _text(value.get("waiver_id"), "waiver_id", 128)
    if _text(value.get("game_build"), "waiver game_build", 128) != game_build:
        raise XmlTblContractError("waiver game build does not match its verdict")
    if _path(value.get("internal_path"), "waiver internal_path") != table.internal_path:
        raise XmlTblContractError("waiver path does not match its verdict")
    if _sha256(value.get("xml_sha256"), "waiver xml_sha256").lower() != table.xml_sha256:
        raise XmlTblContractError("waiver XML hash does not match its verdict")
    waiver_module = _optional_sha256(value.get("whgame_sha256"), "waiver whgame_sha256")
    if waiver_module != whgame_sha256:
        raise XmlTblContractError("waiver WHGame hash does not match its verdict")
    if value.get("approved_by_user") is not True:
        raise XmlTblContractError("waiver must be explicitly approved by the user")
    _text(value.get("reason"), "waiver reason", 4000)
    refs = value.get("evidence_refs")
    if not isinstance(refs, list) or not refs or len(refs) > 256:
        raise XmlTblContractError("waiver evidence_refs must be a non-empty bounded list")
    if any(not isinstance(item, str) or not item or len(item) > 512 for item in refs):
        raise XmlTblContractError("waiver evidence_refs contain an invalid reference")
    if len(set(refs)) != len(refs):
        raise XmlTblContractError("waiver evidence_refs must be unique")


def _validate_tbl_artifacts(value: Any) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list) or len(value) > 64:
        raise XmlTblContractError("tbl_artifacts must be a bounded list")
    parsed = []
    for item in value:
        if not isinstance(item, Mapping):
            raise XmlTblContractError("TBL artifact entries must be objects")
        _exact_keys(item, frozenset({"path", "sha256", "relationship"}), "TBL artifact")
        path = _text(item.get("path"), "TBL artifact path", MAX_PATH_CHARS)
        digest = _sha256(item.get("sha256"), "TBL artifact sha256").lower()
        relationship = item.get("relationship")
        if relationship not in {
            "compiled_counterpart",
            "generator_input",
            "unrelated_candidate",
        }:
            raise XmlTblContractError("invalid TBL artifact relationship")
        parsed.append((path, digest, relationship))
    return tuple(parsed)


def _path(value: Any, field: str) -> str:
    path = _text(value, field, MAX_PATH_CHARS)
    parsed = PurePosixPath(path)
    if (
        "\\" in path
        or "\x00" in path
        or parsed.is_absolute()
        or parsed.as_posix() != path
        or any(part in {"", ".", ".."} for part in parsed.parts)
        or (len(path) > 1 and path[1] == ":")
        or not path.casefold().endswith(".xml")
    ):
        raise XmlTblContractError(f"{field} must be a canonical internal XML path")
    return path


def _text(value: Any, field: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise XmlTblContractError(f"{field} must be a non-empty string up to {maximum} chars")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HEX for char in value):
        raise XmlTblContractError(f"{field} must be a SHA-256 hex digest")
    return value


def _optional_sha256(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, field).lower()


def _exact_keys(
    value: Mapping[str, Any],
    allowed: frozenset[str],
    label: str,
    *,
    required: frozenset[str] | None = None,
) -> None:
    actual = set(value)
    missing = sorted((required if required is not None else allowed) - actual)
    extra = sorted(actual - allowed)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing {', '.join(missing)}")
        if extra:
            details.append(f"unknown {', '.join(extra)}")
        raise XmlTblContractError(f"{label} fields are invalid: {'; '.join(details)}")
