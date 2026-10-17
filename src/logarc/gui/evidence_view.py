"""What the evidence table says, as plain data.

No Qt here, for the same reason `logarc.style` has none. These are the decisions
that determine whether a piece of evidence reads correctly — whether a served
injection stands out from a refused one, whether a payload is legible, whether a
number sorts as a number — and they should be checkable without starting a
window.

Nothing here rebuilds evidence. Values come from the `NormalizedEvent` the
case's own parser produced, which is the same reading the detection ran against;
showing those fields is how a reader checks the tool's reading rather than
performing their own and hoping the two agree.

Every string derived from a request passes through `display_safe` before it
leaves this module. The request was written by whoever is being investigated,
and a table cell is a single line: a decoded newline would draw over the row
beneath it, and a right-to-left override would reverse how a hostile path reads.
"""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from typing import TYPE_CHECKING, Final

from logarc.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    THEME,
    decode_target,
    display_safe,
    format_bytes,
    status_colour,
)

if TYPE_CHECKING:
    from logarc.evidence import EvidenceLine

__all__ = ["ALERT_COLOUR", "COLUMNS", "Cell", "Detail", "cells_for", "detail_for"]

#: Something is wrong with this piece of evidence, and the reader has to see
#: that rather than an empty row. From the theme, because a red chosen against
#: pale paper is the wrong red on a dark one — and this is the colour that says
#: a piece of evidence could not be read at all.
ALERT_COLOUR: Final = THEME.alert

#: Headings, in order. `Request` is the one that grows: every other value is a
#: handful of characters and a payload is sixty.
#:
#: The method lives inside `Request` rather than in a column of its own. It is
#: three characters and almost always the same three, but a column costs its
#: heading's width whatever it holds — and at a 400px panel the five other
#: columns left the payload 80px, which is the fault this table was built to
#: fix. `GET /search?q=…` is also simply how a request is written.
COLUMNS: Final[tuple[str, ...]] = ("Source", "Time", "Request", "Status", "Size")


@dataclass(frozen=True, slots=True)
class Cell:
    """One value in the table, with everything a renderer needs to draw it."""

    text: str

    sort_key: float | None = None
    """Sorted on this rather than on the text. "1,000" sorts before "9" as a
    string, which would silently mis-rank the table — and sorting by size is
    how the request that returned the most data gets found."""

    colour: str = EVIDENCE_INK
    bold: bool = False
    tooltip: str = ""
    """Empty means none. The `Target` column is too narrow for a long payload
    however the panel is sized, so it carries its full value here."""


def cells_for(line: EvidenceLine, *, decode: bool) -> tuple[Cell, ...]:
    """One row of the table.

    Always `len(COLUMNS)` cells, so no value can appear under the wrong heading.
    """
    event = line.event
    served = event is not None and event.status is not None and 200 <= event.status < 400
    status = event.status if event else None

    return (
        Cell(text=str(line.ref), sort_key=line.ref.line_no, colour=EVIDENCE_MUTED),
        Cell(
            text=f"{event.timestamp:%H:%M:%S}" if event else "",
            sort_key=event.timestamp.timestamp() if event else None,
            colour=THEME.timestamp,
        ),
        _request_cell(line, decode=decode),
        Cell(
            text=str(status) if status is not None else "",
            sort_key=float(status) if status is not None else None,
            colour=status_colour(str(status)) if status is not None else EVIDENCE_MUTED,
            bold=served,
        ),
        Cell(
            text=format_bytes(event.bytes_sent) if event and event.bytes_sent is not None else "",
            sort_key=float(event.bytes_sent) if event and event.bytes_sent is not None else None,
            colour=EVIDENCE_MUTED,
        ),
    )


@dataclass(frozen=True, slots=True)
class Detail:
    """Everything known about one piece of evidence."""

    source: str

    fields: tuple[tuple[str, str, str], ...]
    """`(label, value, colour)`, with full field names for readers new to logs."""

    raw: str | None
    """The source line, exactly as the log holds it.

    Deliberately *not* passed through `display_safe`: this is the proof, and the
    proof has to be the bytes. It is safe to print as one block because a line
    is what the reader split the file on — by construction it holds no newline.
    """

    note: str | None


def detail_for(line: EvidenceLine, *, decode: bool) -> Detail:
    """The full record for one piece of evidence.

    The table shows what fits; this shows everything, including the agent at
    full length — the table has no room for one and this has plenty, and a
    scanner signature must not be cut in the one place it can be read whole.
    """
    fields: list[tuple[str, str, str]] = []
    event = line.event

    if event is not None:
        target = event.target
        shown = decode_target(target) if decode else display_safe(target)
        method = display_safe(event.method or "(method not recorded)")
        fields.append(
            (
                "Request (method + target)",
                f"{method} {shown or '(target not recorded)'}",
                EVIDENCE_INK,
            )
        )
        fields.append(("Client IP (logged address)", display_safe(event.client_ip), THEME.identity))
        fields.append(("Time (UTC)", f"{event.timestamp:%Y-%m-%d %H:%M:%S}", THEME.timestamp))
        if event.protocol:
            fields.append(("HTTP version", display_safe(event.protocol), EVIDENCE_MUTED))
        if event.status is not None:
            try:
                status = f"{event.status} — {HTTPStatus(event.status).phrase}"
            except ValueError:
                status = str(event.status)
            fields.append(("Response status", status, status_colour(str(event.status))))
        else:
            fields.append(("Response status", "Not recorded", EVIDENCE_MUTED))
        fields.append(
            (
                "Response size (bytes sent)",
                format_bytes(event.bytes_sent) if event.bytes_sent is not None else "Not recorded",
                EVIDENCE_MUTED,
            )
        )
        if event.referer and event.referer != "-":
            fields.append(("Referrer (previous page)", display_safe(event.referer), EVIDENCE_MUTED))
        if event.user_agent and event.user_agent != "-":
            fields.append(
                ("User agent (reported software)", display_safe(event.user_agent), EVIDENCE_MUTED)
            )
        if event.host and event.host != "-":
            fields.append(("Host (requested site)", display_safe(event.host), THEME.identity))
    elif line.text is None:
        note = display_safe(line.note or "source not readable")
        fields.append(("", f"unavailable — {note}", ALERT_COLOUR))

    return Detail(
        source=str(line.ref),
        fields=tuple(fields),
        raw=line.text,
        note=None if line.verified else line.note,
    )


def _request_cell(line: EvidenceLine, *, decode: bool) -> Cell:
    """The request, which is the column the reader came for.

    Three cases, and each is worth telling apart: a request, a line the parser
    would not read, and a line that could not be read at all. The last two get
    a row like any other — a gap in the evidence with nothing to say a gap is
    there would be the worst of the three.
    """
    if line.text is None:
        return Cell(
            text=f"unavailable — {display_safe(line.note or 'source not readable')}",
            colour=ALERT_COLOUR,
        )
    if line.event is None:
        # No fields to lay out, so the line stands as it is — made safe for a
        # single-line cell. The original is in the detail pane, untouched.
        safe = display_safe(line.text)
        return Cell(text=safe, tooltip=safe, colour=EVIDENCE_MUTED)

    target = line.event.target
    shown = decode_target(target) if decode else display_safe(target)
    method = display_safe(line.event.method or "")
    written = f"{method} {shown}".strip()
    return Cell(text=written, tooltip=written, bold=True)
