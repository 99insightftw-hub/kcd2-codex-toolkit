"""Summarize bounded legacy KCSE probe logs without retaining raw pointers."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_DIAGNOSTICS = 100
DEFAULT_MAX_PREFIX_TOKENS = 16
TIMESTAMP_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}) (?P<rest>\S.*)$"
)
EVENT_RE = re.compile(r"[A-Z][A-Z0-9_]*")
TOKEN_RE = re.compile(r"(?P<key>[A-Za-z][A-Za-z0-9_]*)=(?P<value>\S+)")


@dataclass(frozen=True, slots=True)
class LegacyKcseRecord:
    """One bounded legacy record with every parsed token retained."""

    timestamp: str
    thread: int
    event: str
    body: str
    prefix_tokens: dict[str, str]
    body_tokens: dict[str, int | str]


def parse_int(value: str) -> int | str:
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        if re.fullmatch(r"-?\d+", value):
            return int(value, 10)
        if re.fullmatch(r"[0-9A-Fa-f]{8}", value):
            return int(value, 16)
    except ValueError:
        pass
    return value


def ordered_counts(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter, key=str)}


def _bounded_lines(path: Path, max_line_bytes: int) -> Iterator[tuple[int, str | None]]:
    """Yield decoded physical lines while never retaining an over-limit line."""
    with path.open("rb") as stream:
        line_number = 0
        while True:
            raw = stream.readline(max_line_bytes + 2)
            if not raw:
                return
            line_number += 1
            complete = raw.endswith(b"\n")
            content = raw.rstrip(b"\r\n") if complete else raw
            if len(content) > max_line_bytes:
                while not complete:
                    remainder = stream.readline(max_line_bytes + 2)
                    if not remainder:
                        break
                    complete = remainder.endswith(b"\n")
                yield line_number, None
                continue
            yield line_number, content.decode("utf-8", errors="replace")


def _parse_line(
    line: str, *, max_prefix_tokens: int
) -> tuple[tuple[str, int, str, str] | None, str]:
    record, cause = parse_legacy_record(
        line, max_prefix_tokens=max_prefix_tokens, require_token_body=False
    )
    if record is None:
        return None, cause
    return (record.timestamp, record.thread, record.event, record.body), ""


def parse_legacy_record(
    line: str,
    *,
    max_prefix_tokens: int = DEFAULT_MAX_PREFIX_TOKENS,
    require_token_body: bool = True,
) -> tuple[LegacyKcseRecord | None, str]:
    """Parse a legacy line while preserving bounded prefix and body fields."""
    timestamp_match = TIMESTAMP_RE.fullmatch(line)
    if timestamp_match is None:
        return None, "expected timestamp followed by prefix tokens, tid, and event"

    parts = timestamp_match.group("rest").split()
    event_index = next(
        (index for index, part in enumerate(parts) if EVENT_RE.fullmatch(part)), None
    )
    if event_index is None:
        return None, "missing event token"
    prefix = parts[:event_index]
    if not prefix:
        return None, "missing tid token"
    if len(prefix) > max_prefix_tokens:
        return None, "prefix token limit exceeded"

    prefix_tokens: dict[str, str] = {}
    for part in prefix:
        token = TOKEN_RE.fullmatch(part)
        if token is None:
            return None, "malformed prefix token"
        key = token.group("key")
        if key in prefix_tokens:
            return None, f"duplicate prefix token: {key}"
        prefix_tokens[key] = token.group("value")

    thread_text = prefix_tokens.get("tid")
    if thread_text is None or re.fullmatch(r"\d+", thread_text) is None:
        return None, "missing or invalid tid token"
    body_parts = parts[event_index + 1 :]
    body_tokens: dict[str, int | str] = {}
    for part in body_parts:
        token = TOKEN_RE.fullmatch(part)
        if token is None:
            if require_token_body:
                return None, "malformed body token"
            continue
        key = token.group("key")
        if key in body_tokens:
            if require_token_body:
                return None, f"duplicate body token: {key}"
        body_tokens[key] = parse_int(token.group("value"))
    return LegacyKcseRecord(
        timestamp=timestamp_match.group("timestamp"),
        thread=int(thread_text),
        event=parts[event_index],
        body=" ".join(body_parts),
        prefix_tokens=prefix_tokens,
        body_tokens=body_tokens,
    ), ""


def summarize(
    path: Path,
    *,
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
    max_diagnostics: int = DEFAULT_MAX_DIAGNOSTICS,
    max_prefix_tokens: int = DEFAULT_MAX_PREFIX_TOKENS,
) -> dict[str, Any]:
    if max_line_bytes < 1 or max_diagnostics < 0 or max_prefix_tokens < 1:
        raise ValueError("parser bounds are invalid")

    event_counts: Counter[Any] = Counter()
    thread_counts: Counter[Any] = Counter()
    action_counts: Counter[Any] = Counter()
    predicate_results: Counter[Any] = Counter()
    selector_outputs: Counter[Any] = Counter()
    field_values: defaultdict[str, Counter[Any]] = defaultdict(Counter)
    first_timestamp = None
    last_timestamp = None
    malformed = 0
    diagnostics: list[dict[str, Any]] = []

    def record_diagnostic(line_number: int, cause: str) -> None:
        nonlocal malformed
        malformed += 1
        if len(diagnostics) < max_diagnostics:
            diagnostics.append(
                {
                    "schema_version": "kcd2.legacy-kcse-line-diagnostic.v1",
                    "code": "LEGACY_LINE_MALFORMED",
                    "severity": "warning",
                    "line_number": line_number,
                    "cause": cause,
                }
            )

    for line_number, line in _bounded_lines(path, max_line_bytes):
        if line is None:
            record_diagnostic(line_number, f"line exceeds {max_line_bytes} UTF-8 bytes")
            continue
        if not line.strip():
            continue
        parsed, cause = _parse_line(line, max_prefix_tokens=max_prefix_tokens)
        if parsed is None:
            record_diagnostic(line_number, cause)
            continue

        timestamp, thread, event, body = parsed
        first_timestamp = first_timestamp or timestamp
        last_timestamp = timestamp
        event_counts[event] += 1
        thread_counts[thread] += 1
        tokens = {
            token.group("key"): parse_int(token.group("value"))
            for token in TOKEN_RE.finditer(body)
        }
        if "action" in tokens:
            action_counts[tokens["action"]] += 1
        if event == "FULL_PREDICATE" and "result" in tokens:
            predicate_results[tokens["result"]] += 1
        if event == "TYPE_SELECTOR" and "output_after" in tokens:
            selector_outputs[tokens["output_after"]] += 1
        for key in (
            "actor_r",
            "actor_l",
            "opponent_r",
            "opponent_l",
            "actor_guard",
            "actor_guard_stance",
            "actor_guard_type",
            "opponent_guard",
            "opponent_guard_type",
            "actor_zone",
            "actor_guard_zone",
            "query_mode",
            "mode",
            "target",
        ):
            if key in tokens:
                field_values[key][tokens[key]] += 1

    return {
        "schema_version": "1.0",
        "source": str(path.resolve()),
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "event_counts": ordered_counts(event_counts),
        "thread_count": len(thread_counts),
        "action_counts": ordered_counts(action_counts),
        "predicate_results": ordered_counts(predicate_results),
        "selector_output_counts": ordered_counts(selector_outputs),
        "field_values": {
            key: ordered_counts(values) for key, values in sorted(field_values.items())
        },
        "malformed_nonempty_lines": malformed,
        "diagnostics": diagnostics,
        "diagnostics_truncated": malformed > len(diagnostics),
    }


def to_markdown(data: dict[str, Any]) -> str:
    lines = [
        "# KCSE probe summary",
        "",
        f"- Source: `{data['source']}`",
        f"- Window: `{data['first_timestamp']}` to `{data['last_timestamp']}`",
        f"- Threads observed: `{data['thread_count']}`",
        f"- Malformed non-empty lines: `{data['malformed_nonempty_lines']}`",
        "",
        "## Event counts",
        "",
    ]
    for key, value in data["event_counts"].items():
        lines.append(f"- `{key}`: {value}")
    for title, key in (
        ("Action IDs", "action_counts"),
        ("Full-predicate results", "predicate_results"),
        ("Selector output counts", "selector_output_counts"),
    ):
        lines.extend(["", f"## {title}", ""])
        values = data[key]
        if not values:
            lines.append("- None observed")
        else:
            for name, count in values.items():
                lines.append(f"- `{name}`: {count}")
    lines.extend(["", "## Selected field values", ""])
    for field, values in data["field_values"].items():
        rendered = ", ".join(f"`{value}` × {count}" for value, count in values.items())
        lines.append(f"- `{field}`: {rendered}")
    return "\n".join(lines) + "\n"
