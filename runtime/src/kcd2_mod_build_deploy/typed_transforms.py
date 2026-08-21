"""Byte-preserving typed ADB and XML/TBL element transforms."""

from __future__ import annotations

import hashlib
import re
import xml.parsers.expat
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Mapping

from .combat_candidate_spec import CombatTransformDeclaration


MAX_DOCUMENT_BYTES = 256 * 1024 * 1024
MAX_XML_DEPTH = 256
MAX_ELEMENTS = 2_000_000
_SHA256 = re.compile(r"[a-f0-9]{64}")


class TypedTransformError(ValueError):
    """A declared transform cannot prove exact scope and byte preservation."""


@dataclass(frozen=True, slots=True)
class ElementSpan:
    name: str
    attributes: tuple[tuple[str, str], ...]
    start: int
    end: int
    depth: int


@dataclass(frozen=True, slots=True)
class TypedTransformReceipt:
    transform_id: str
    kind: str
    target_path: str
    selector: Mapping[str, Any]
    input_sha256: str
    selected_target_sha256: str
    donor_id: str | None
    selected_donor_sha256: str | None
    output_sha256: str
    selected_target_span: tuple[int, int]
    unchanged_prefix_sha256: str
    unchanged_suffix_sha256: str
    byte_identical_non_target: bool
    output_bytes: bytes

    def to_dict(self, *, include_output: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "kcd2.typed-transform-receipt.v1",
            "transform_id": self.transform_id,
            "kind": self.kind,
            "target_path": self.target_path,
            "selector": dict(self.selector),
            "input_sha256": self.input_sha256,
            "selected_target_sha256": self.selected_target_sha256,
            "donor_id": self.donor_id,
            "selected_donor_sha256": self.selected_donor_sha256,
            "output_sha256": self.output_sha256,
            "output_bytes": len(self.output_bytes),
            "selected_target_span": list(self.selected_target_span),
            "unchanged_ranges": [
                {
                    "range": [0, self.selected_target_span[0]],
                    "sha256": self.unchanged_prefix_sha256,
                },
                {
                    "range": [self.selected_target_span[1], None],
                    "sha256": self.unchanged_suffix_sha256,
                },
            ],
            "byte_identical_non_target": self.byte_identical_non_target,
        }
        if include_output:
            payload["output_hex"] = self.output_bytes.hex()
        return payload


def apply_typed_transform(
    declaration: CombatTransformDeclaration,
    *,
    target_bytes: bytes,
    donor_bytes: bytes | None = None,
) -> TypedTransformReceipt:
    """Apply one exact transform while retaining all bytes outside its selected span."""
    if not isinstance(declaration, CombatTransformDeclaration):
        raise TypedTransformError("declaration must be a parsed combat transform")
    _bounded_document(target_bytes, "target")
    input_sha256 = _sha256(target_bytes)
    if input_sha256 != declaration.expected_target_sha256:
        raise TypedTransformError("target bytes differ from the declared expected SHA-256")
    extension = PurePosixPath(declaration.target_path).suffix.casefold()
    if declaration.kind.startswith("adb_") and extension != ".adb":
        raise TypedTransformError("ADB transform target must have an .adb path")
    if declaration.kind.startswith(("xml_", "tbl_")) and extension not in {".xml", ".tbl"}:
        raise TypedTransformError("XML/TBL transform target must have an .xml or .tbl path")
    target_span = _select_unique_span(target_bytes, declaration.selector, "target")
    selected_target = target_bytes[target_span.start : target_span.end]
    if declaration.kind.endswith("delete"):
        if donor_bytes is not None or declaration.donor_id is not None:
            raise TypedTransformError("delete transform must not carry donor bytes or identity")
        replacement = b""
        donor_sha256 = None
    else:
        if donor_bytes is None or declaration.donor_id is None:
            raise TypedTransformError("replacement transform requires exact donor bytes and identity")
        _bounded_document(donor_bytes, "donor")
        donor_span = _select_unique_span(donor_bytes, declaration.selector, "donor")
        replacement = donor_bytes[donor_span.start : donor_span.end]
        donor_sha256 = _sha256(replacement)
    prefix = target_bytes[: target_span.start]
    suffix = target_bytes[target_span.end :]
    output = prefix + replacement + suffix
    if output[: len(prefix)] != prefix or output[len(prefix) + len(replacement) :] != suffix:
        raise TypedTransformError("non-target byte preservation check failed")
    return TypedTransformReceipt(
        transform_id=declaration.transform_id,
        kind=declaration.kind,
        target_path=declaration.target_path,
        selector=declaration.selector,
        input_sha256=input_sha256,
        selected_target_sha256=_sha256(selected_target),
        donor_id=declaration.donor_id,
        selected_donor_sha256=donor_sha256,
        output_sha256=_sha256(output),
        selected_target_span=(target_span.start, target_span.end),
        unchanged_prefix_sha256=_sha256(prefix),
        unchanged_suffix_sha256=_sha256(suffix),
        byte_identical_non_target=True,
        output_bytes=output,
    )


def _select_unique_span(data: bytes, selector: Mapping[str, Any], label: str) -> ElementSpan:
    if not isinstance(selector, Mapping) or set(selector) != {"element", "attributes"}:
        raise TypedTransformError("selector must contain exactly element and attributes")
    element = selector["element"]
    attributes = selector["attributes"]
    if not isinstance(element, str) or not 1 <= len(element) <= 256:
        raise TypedTransformError("selector element is invalid")
    if not isinstance(attributes, Mapping) or not attributes or len(attributes) > 64:
        raise TypedTransformError("selector attributes must be a non-empty bounded object")
    expected: dict[str, str] = {}
    for key, value in attributes.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypedTransformError("selector attributes must contain string pairs")
        if not key or len(key) > 256 or len(value) > 4096:
            raise TypedTransformError("selector attribute exceeds its bound")
        expected[key] = value
    matches = [
        span
        for span in _element_spans(data)
        if span.name == element and all(dict(span.attributes).get(key) == value for key, value in expected.items())
    ]
    if len(matches) != 1:
        raise TypedTransformError(f"{label} selector matched {len(matches)} elements; exactly one is required")
    return matches[0]


def _element_spans(data: bytes) -> tuple[ElementSpan, ...]:
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise TypedTransformError("DTD and entity declarations are not accepted")
    parser = xml.parsers.expat.ParserCreate()
    stack: list[tuple[str, tuple[tuple[str, str], ...], int, int, bool]] = []
    spans: list[ElementSpan] = []
    count = 0

    def start(name: str, attrs: Mapping[str, str]) -> None:
        nonlocal count
        count += 1
        if count > MAX_ELEMENTS or len(stack) >= MAX_XML_DEPTH:
            raise TypedTransformError("XML structure exceeds its element or depth bound")
        offset = parser.CurrentByteIndex
        open_end = _tag_end(data, offset)
        self_closing = data[offset:open_end].rstrip().endswith(b"/>")
        stack.append((name, tuple(sorted(attrs.items())), offset, open_end, self_closing))

    def end(name: str) -> None:
        if not stack:
            raise TypedTransformError("XML element stack underflow")
        opened_name, attrs, start_offset, open_end, self_closing = stack.pop()
        if opened_name != name:
            raise TypedTransformError("XML element nesting is inconsistent")
        end_offset = open_end if self_closing else _tag_end(data, parser.CurrentByteIndex)
        spans.append(ElementSpan(name, attrs, start_offset, end_offset, len(stack)))

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(data, True)
    except (xml.parsers.expat.ExpatError, UnicodeError) as exc:
        raise TypedTransformError("document is not bounded well-formed XML") from exc
    if stack:
        raise TypedTransformError("XML element stack did not close")
    return tuple(spans)


def _tag_end(data: bytes, start: int) -> int:
    quote: int | None = None
    for index in range(start, len(data)):
        value = data[index]
        if quote is None and value in {34, 39}:
            quote = value
        elif quote == value:
            quote = None
        elif quote is None and value == 62:
            return index + 1
    raise TypedTransformError("XML tag has no bounded closing delimiter")


def _bounded_document(value: object, label: str) -> None:
    if not isinstance(value, bytes) or not value or len(value) > MAX_DOCUMENT_BYTES:
        raise TypedTransformError(f"{label} document is empty or exceeds its byte bound")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "ElementSpan",
    "MAX_DOCUMENT_BYTES",
    "TypedTransformError",
    "TypedTransformReceipt",
    "apply_typed_transform",
]
