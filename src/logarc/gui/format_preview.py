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

from dataclasses import dataclass
from typing import Final

from logarc.core.evidence import EvidenceRef
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.registry import detect_format
from logarc.parsers.spec import LogFormatSpec

__all__ = ["Preview", "preview"]

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
        return Preview(ok=False, status="Write a LogFormat directive above.")
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
    return Preview(
        ok=True,
        status=f"Read this line, and found {carried} of {len(_SHOWN)} fields in it.",
        fields=tuple((name, values[name]) for name in _SHOWN),
    )
