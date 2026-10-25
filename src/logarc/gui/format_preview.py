"""What a directive reads out of one pasted log line.

Free of Qt, like the notice wording beside it, and for a sharper reason than
testability. This is the answer a reader trusts before saving a format, and a
preview that says "worked" about a directive that reads nothing produces a case
with every line quarantined and nothing on screen explaining why. The
quarantine notice calls that this tool's worst failure mode; this is where it
gets caught, before it is a case.

So `ok` is deliberately narrow: it means a `NormalizedEvent` came back, not
that the regex matched. A directive can match a line and still be refused — a
timestamp that will not parse does exactly that — and ingest would quarantine
every such line. Anything short of a real event is a failure here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.parsers.columns import FIELDS_DIRECTIVE, ColumnsFormatError
from logarc.parsers.json_format import JsonFormatError, flatten
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.pattern import PatternFormatError
from logarc.parsers.registry import detect_format
from logarc.parsers.spec import (
    ColumnsFormatSpec,
    JsonFormatSpec,
    LogFormatSpec,
    PatternFormatSpec,
)
from logarc.style import plural

__all__ = ["Preview", "preview", "preview_columns", "preview_mapping", "preview_pattern"]

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.event import NormalizedEvent

_REF: Final = EvidenceRef(source_file_id="<preview>", line_no=1)

#: Every field the reader is deciding about, in the order they appear in a log
#: line. Fixed rather than built from what parsed, because a row that vanishes
#: reads as "I forgot to look" where an empty one reads as "this format does
#: not carry it" — and which fields a format carries is the whole decision.
_SHOWN: Final = (
    "Client",
    "When",
    "Method",
    "Path",
    "Query",
    "Protocol",
    "Status",
    "Bytes",
    "Referer",
    "User agent",
    "Host",
)


@dataclass(frozen=True, slots=True)
class Preview:
    """What to put under the sample line, once a directive has been tried."""

    ok: bool
    """A real event came back. Not merely that the pattern matched."""

    status: str
    """One sentence: what happened, and where to go next if it failed."""

    fields: tuple[tuple[str, str], ...] = ()
    """Field name and value, in log order. Empty whenever `ok` is false."""

    extra: tuple[tuple[str, str], ...] = ()
    """Fields this format carries that the canonical schema has no place for.

    Usually why a site has its own format at all — a forwarded-for header, a
    request id, an upstream time. They are kept on the event, so a table that
    listed the eleven and silently dropped the twelfth would read as "this was
    not captured", which is the opposite of the truth."""


def _already_read_by(sample: str) -> str | None:
    """A built-in that reads this line, if there is one.

    The most useful thing that can be said to someone hand-writing a directive
    for a log that never needed one — they are about to duplicate a preset, and
    will maintain it forever.
    """
    detection = detect_format([sample])
    return detection.name if detection is not None else None


def preview(directive: str, sample: str) -> Preview:
    """Try `directive` against one `sample` line and say what came of it."""
    sample = sample.strip()
    if not directive.strip():
        return Preview(ok=False, status="Enter a LogFormat above.")
    if not sample:
        return Preview(ok=False, status="Paste one line from your log.")

    try:
        parser = LogFormatSpec(name="preview", directive=directive).build()
    except LogFormatError as exc:
        return Preview(ok=False, status=str(exc))

    event = parser.parse_line(sample, _REF)
    if event is None:
        known = _already_read_by(sample)
        found = f" This line is already read by {known}." if known else ""
        return Preview(
            ok=False,
            status=(
                "This directive does not read that line. Check the order of the "
                "fields and the characters between them." + found
            ),
        )
    return _read(event)


def preview_mapping(fields: Sequence[tuple[str, str]], time_format: str, sample: str) -> Preview:
    """Try a JSON mapping against one `sample` line and say what came of it.

    The failing message is where the two kinds differ most. For a directive the
    useful answer is "the fields are in another order"; for a mapping it is
    "your log calls them these", which the reader can read straight off and
    correct.
    """
    sample = sample.strip()
    if not fields:
        return Preview(ok=False, status="Map at least a timestamp and a client address.")
    if not sample:
        return Preview(ok=False, status="Paste one line from your log.")

    try:
        parser = JsonFormatSpec(
            name="preview", fields=tuple(fields), time_format=time_format
        ).build()
    except JsonFormatError as exc:
        return Preview(ok=False, status=str(exc))

    event = parser.parse_line(sample, _REF)
    if event is None:
        return Preview(ok=False, status=_why_the_mapping_missed(sample))
    return _read(event)


def preview_columns(
    fields: Sequence[tuple[str, str]],
    columns: Sequence[str],
    separator: str,
    time_format: str,
    sample: str,
) -> Preview:
    """Try a table format against pasted lines and say what came of it.

    Takes several lines where the other kinds take one, because for this kind
    the header *is* half the definition: a W3C log names its columns in a
    `#Fields:` line, so the reader pastes a piece of the log rather than a
    single row. The row previewed is the first that is not bookkeeping — read
    as data, the header would say the format is broken when it is only that the
    reader pasted more than one kind of line.
    """
    lines = [line for line in sample.splitlines() if line.strip()]
    if not fields:
        return Preview(ok=False, status="Map at least a timestamp and a client address.")
    if not lines:
        return Preview(ok=False, status="Paste a few lines from your log, header and all.")

    spec = ColumnsFormatSpec(
        name="preview",
        fields=tuple(fields),
        columns=tuple(columns),
        separator=separator,
        time_format=time_format,
    )
    settled = spec.resolved(lines)
    try:
        parser = settled.build()
    except ColumnsFormatError as exc:
        return Preview(ok=False, status=_why_the_columns_missed(spec, settled, lines, exc))

    rows = [line for line in lines if not parser.is_metadata(line)]
    if not rows:
        return Preview(
            ok=False,
            status="Every line pasted is the log's own header. Paste a row of data too.",
        )

    event = parser.parse_line(rows[0], _REF)
    if event is None:
        return Preview(
            ok=False,
            status=(
                "Nothing was read from that row. Check the separator, and that the "
                "columns line up with the header above it."
            ),
        )
    return _read(event)


def preview_pattern(pattern: str, time_format: str, sample: str, escapes: str = "") -> Preview:
    """Try a regular expression against one pasted line and say what came of it.

    `escapes` is the format's own, which the screen does not show: a preview
    that left HAProxy's `#22` in place would not be what ingest reads.
    """
    sample = sample.strip()
    if not pattern.strip():
        return Preview(ok=False, status="Write a regular expression above.")
    if not sample:
        return Preview(ok=False, status="Paste one line from your log.")

    try:
        parser = PatternFormatSpec(
            name="preview", pattern=pattern, time_format=time_format, escapes=escapes
        ).build()
    except PatternFormatError as exc:
        return Preview(ok=False, status=str(exc))

    event = parser.parse_line(sample.splitlines()[0], _REF)
    if event is None:
        return Preview(
            ok=False,
            status=(
                "This pattern does not read that line. It is matched from the start "
                "of the line, so begin with .* if you mean to skip a prefix."
            ),
        )
    return _read(event)


def _why_the_columns_missed(
    asked: ColumnsFormatSpec,
    settled: ColumnsFormatSpec,
    lines: Sequence[str],
    trouble: ColumnsFormatError,
) -> str:
    """Say what went wrong in terms of what the reader can see.

    One case earns its own sentence: a log with no `#Fields:` line, whose first
    row of data was taken for a header. The plain message then lists that row's
    *values* as though they were column names, which reads as nonsense — and
    the answer is not to fix the mapping but to give the column names.
    """
    took_a_row = (
        not asked.columns
        and settled.columns
        and not any(line.strip().startswith(FIELDS_DIRECTIVE) for line in lines)
    )
    if took_a_row:
        return (
            "These lines have no #Fields: header, so the first row was read as one — "
            "and its names are not the ones your mapping uses. If this log has no "
            "header at all, write the column names in yourself."
        )
    return str(trouble)


def _why_the_mapping_missed(sample: str) -> str:
    """Name the keys the line actually has, which is the whole answer here."""
    try:
        payload = json.loads(sample)
    except json.JSONDecodeError:
        return "That line is not JSON. This kind of format reads one JSON object per line."
    if not isinstance(payload, dict):
        return "That line is JSON but not an object, so it has no keys to map."

    keys = ", ".join(sorted(path for path, _value in flatten(payload)))
    return f"Nothing was read from that line. Your log calls its fields: {keys}"


def _read(event: NormalizedEvent) -> Preview:
    """The fields an event carries, as the table under the sample line."""
    values = {
        "Client": event.client_ip,
        "When": event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Method": event.method or "",
        "Path": event.path or "",
        "Query": event.query or "",
        "Protocol": event.protocol or "",
        "Status": str(event.status) if event.status is not None else "",
        "Bytes": str(event.bytes_sent) if event.bytes_sent is not None else "",
        "Referer": event.referer or "",
        "User agent": event.user_agent or "",
        "Host": event.host or "",
    }
    carried = sum(1 for name in _SHOWN if values[name])
    extra = tuple(sorted(event.extra.items()))
    also = f", and {plural(len(extra), 'field')} besides" if extra else ""
    return Preview(
        ok=True,
        status=f"Read this line, and found {carried} of {len(_SHOWN)} fields in it{also}.",
        fields=tuple((name, values[name]) for name in _SHOWN),
        extra=extra,
    )
