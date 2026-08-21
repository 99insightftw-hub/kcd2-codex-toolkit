"""Deterministic KCD2 candidate-manifest generation and semantic validation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping
from xml.etree import ElementTree
from xml.sax.saxutils import escape


_MOD_ID = re.compile(r"[a-z0-9_]{1,200}")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


class CandidateManifestError(ValueError):
    """Manifest metadata or bytes violate the canonical candidate contract."""


@dataclass(frozen=True, slots=True)
class CandidateManifestMetadata:
    candidate_number: int
    mod_id: str
    folder_name_exact: str
    load_order_identity: str
    name: str
    description_template: str
    author: str
    created_on: str

    @property
    def version(self) -> str:
        return candidate_version(self.candidate_number)

    @property
    def description(self) -> str:
        return self.description_template.replace("{version}", self.version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.candidate-manifest-metadata.v1",
            "candidate_number": self.candidate_number,
            "version": self.version,
            "mod_id": self.mod_id,
            "folder_name_exact": self.folder_name_exact,
            "load_order_identity": self.load_order_identity,
            "name": self.name,
            "description": self.description,
            "description_template": self.description_template,
            "author": self.author,
            "created_on": self.created_on,
        }


@dataclass(frozen=True, slots=True)
class CandidateManifestValidationReport:
    status: str
    expected: CandidateManifestMetadata
    observed: tuple[tuple[str, str], ...]
    diagnostics: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return self.status == "PASS"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "kcd2.candidate-manifest-validation.v1",
            "status": self.status,
            "expected": self.expected.to_dict(),
            "observed": dict(self.observed),
            "diagnostics": list(self.diagnostics),
        }


def candidate_version(candidate_number: int) -> str:
    """Map the canonical three-digit candidate number to its semantic version."""
    if (
        not isinstance(candidate_number, int)
        or isinstance(candidate_number, bool)
        or not 100 <= candidate_number <= 999
    ):
        raise CandidateManifestError(
            "candidate_number must be a three-digit integer between 100 and 999"
        )
    digits = f"{candidate_number:03d}"
    return ".".join(digits)


def parse_candidate_manifest_metadata(
    value: Mapping[str, Any], *, mod_id: str, folder_name_exact: str
) -> CandidateManifestMetadata:
    """Parse and cross-bind manifest metadata to the canonical mod identity."""
    expected = {
        "candidate_number",
        "load_order_identity",
        "name",
        "description_template",
        "author",
        "created_on",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CandidateManifestError("manifest_metadata fields are invalid")
    candidate_number = value["candidate_number"]
    candidate_version(candidate_number)
    if not isinstance(mod_id, str) or _MOD_ID.fullmatch(mod_id) is None:
        raise CandidateManifestError("mod_id must be a canonical lowercase identity")
    load_order_identity = value["load_order_identity"]
    if (
        not isinstance(folder_name_exact, str)
        or folder_name_exact != mod_id
        or load_order_identity != mod_id
    ):
        raise CandidateManifestError(
            "folder_name_exact, mod_id, and load_order_identity must be identical lowercase values"
        )
    fields = ("name", "description_template", "author", "created_on")
    if any(not isinstance(value[field], str) or not value[field] for field in fields):
        raise CandidateManifestError("manifest text fields must be non-empty strings")
    if any(len(value[field]) > 1024 for field in ("name", "author")):
        raise CandidateManifestError("manifest name or author exceeds its size limit")
    template = value["description_template"]
    if len(template) > 4096 or template.count("{version}") != 1:
        raise CandidateManifestError(
            "description_template must contain exactly one {version} placeholder"
        )
    if _DATE.fullmatch(value["created_on"]) is None:
        raise CandidateManifestError("created_on must use YYYY-MM-DD")
    return CandidateManifestMetadata(
        candidate_number=candidate_number,
        mod_id=mod_id,
        folder_name_exact=folder_name_exact,
        load_order_identity=load_order_identity,
        name=value["name"],
        description_template=template,
        author=value["author"],
        created_on=value["created_on"],
    )


def generate_candidate_manifest(metadata: CandidateManifestMetadata) -> bytes:
    """Generate canonical UTF-8 manifest bytes from one validated identity."""
    # Reparse the serialized fields so callers cannot construct an invalid dataclass manually.
    metadata = parse_candidate_manifest_metadata(
        {
            "candidate_number": metadata.candidate_number,
            "load_order_identity": metadata.load_order_identity,
            "name": metadata.name,
            "description_template": metadata.description_template,
            "author": metadata.author,
            "created_on": metadata.created_on,
        },
        mod_id=metadata.mod_id,
        folder_name_exact=metadata.folder_name_exact,
    )
    values = {
        "name": metadata.name,
        "modid": metadata.mod_id,
        "description": metadata.description,
        "author": metadata.author,
        "version": metadata.version,
        "created_on": metadata.created_on,
    }
    lines = ["<?xml version='1.0' encoding='UTF-8'?>", "<kcd_mod>", "  <info>"]
    for tag in ("name", "modid", "description", "author", "version", "created_on"):
        lines.append(f"    <{tag}>{escape(values[tag])}</{tag}>")
    lines.extend(("  </info>", "</kcd_mod>", ""))
    return "\n".join(lines).encode("utf-8")


def validate_candidate_manifest(
    data: bytes, metadata: CandidateManifestMetadata
) -> CandidateManifestValidationReport:
    """Validate exact semantic fields; malformed or duplicate fields fail closed."""
    diagnostics: list[str] = []
    observed: dict[str, str] = {}
    try:
        root = ElementTree.fromstring(data)
        if root.tag.rsplit("}", 1)[-1] != "kcd_mod":
            diagnostics.append("MANIFEST_ROOT_INVALID")
        info = [child for child in root if child.tag.rsplit("}", 1)[-1] == "info"]
        if len(info) != 1:
            diagnostics.append("MANIFEST_INFO_CARDINALITY_INVALID")
        else:
            for field in ("name", "modid", "description", "author", "version", "created_on"):
                matches = [
                    child
                    for child in info[0]
                    if child.tag.rsplit("}", 1)[-1] == field
                ]
                if len(matches) != 1 or matches[0].text is None:
                    diagnostics.append(f"MANIFEST_{field.upper()}_CARDINALITY_INVALID")
                else:
                    observed[field] = matches[0].text
    except (ElementTree.ParseError, UnicodeError):
        diagnostics.append("MANIFEST_XML_INVALID")

    expected = {
        "name": metadata.name,
        "modid": metadata.mod_id,
        "description": metadata.description,
        "author": metadata.author,
        "version": metadata.version,
        "created_on": metadata.created_on,
    }
    for field, expected_value in expected.items():
        if field in observed and observed[field] != expected_value:
            diagnostics.append(f"MANIFEST_{field.upper()}_MISMATCH")
    if observed.get("modid") not in {None, metadata.folder_name_exact}:
        diagnostics.append("MANIFEST_FOLDER_IDENTITY_MISMATCH")
    if observed.get("modid") not in {None, metadata.load_order_identity}:
        diagnostics.append("MANIFEST_LOAD_ORDER_IDENTITY_MISMATCH")
    return CandidateManifestValidationReport(
        status="FAIL" if diagnostics else "PASS",
        expected=metadata,
        observed=tuple(sorted(observed.items())),
        diagnostics=tuple(sorted(set(diagnostics))),
    )
