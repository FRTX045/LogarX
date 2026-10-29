"""What the evidence table says, as plain data.

No Qt here, for the same reason `logarx.style` has none. These are the decisions
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

from dataclasses import dataclass, replace
from http import HTTPStatus
from typing import TYPE_CHECKING, Final

from logarx.gui.folding import spread
from logarx.search import ANY_DAY, Scope, parse
from logarx.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    THEME,
    decode_target,
    display_safe,
    format_bytes,
    status_colour,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import date

    from logarx.analysis import AnalysisResult, RequestAssignment
    from logarx.evidence import EvidenceLine
    from logarx.gui.folding import Fold, Spread
    from logarx.search import Query

__all__ = [
    "ALERT_COLOUR",
    "ARROW_CLOSED",
    "ARROW_OPEN",
    "COLUMNS",
    "MIXED",
    "Cell",
    "Detail",
    "Filtered",
    "RequestFilter",
    "cells_for",
    "detail_for",
    "filter_strip",
    "fold_cells",
    "member_cells",
    "no_results",
]

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
#:
#: `Line` holds the whole reference, `excerpt.log:2014`, and shows the number
#: alone while the column is too narrow for it and every line is from one file.
COLUMNS: Final[tuple[str, ...]] = ("Line", "Time", "Request", "Status", "Size")


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
    italic: bool = False
    tooltip: str = ""
    """Empty means none. The `Target` column is too narrow for a long payload
    however the panel is sized, so it carries its full value here."""

    short: str = ""
    """What to show while the column is too narrow for `text`; empty means elide it."""


def cells_for(line: EvidenceLine, *, decode: bool) -> tuple[Cell, ...]:
    """One row of the table.

    Always `len(COLUMNS)` cells, so no value can appear under the wrong heading.
    """
    event = line.event
    served = event is not None and event.status is not None and 200 <= event.status < 400
    status = event.status if event else None

    return (
        Cell(
            text=str(line.ref),
            sort_key=line.ref.line_no,
            colour=EVIDENCE_MUTED,
            short=str(line.ref.line_no),
        ),
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


def detail_for(line: EvidenceLine, *, decode: bool, client_name: str | None = None) -> Detail:
    """The full record for one piece of evidence.

    The table shows what fits; this shows everything, including the agent at
    full length — the table has no room for one and this has plenty, and a
    scanner signature must not be cut in the one place it can be read whole.

    `client_name` is the name a reader gave the client, shown on a row of its
    own above the logged address and whatever the window's names switch says:
    this is where a reader comes to see exactly what the log holds, so the
    address is never replaced here.
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
        if client_name:
            fields.append(("Name", display_safe(client_name), THEME.identity))
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


#: A folded row's arrow, closed and open.
ARROW_CLOSED: Final = "\u25b8"
ARROW_OPEN: Final = "\u25be"

#: What a folded row's cell says when its lines do not share one value. Showing
#: one line's value there would have the row misstate the others.
MIXED: Final = "mixed"


def fold_cells(
    lines: Sequence[EvidenceLine], fold: Fold, *, decode: bool, opened: bool
) -> tuple[Cell, ...]:
    """The row a fold is drawn as: its first line, the count, and what every line shares.

    A run of one is drawn exactly as `cells_for` draws it today. A longer run
    keeps its first line's reference and time, puts the count in front of the
    request — the column the reader came for — and shows Status and Size only
    where every line has the same value; otherwise the cell reads `mixed` and its
    tooltip lists the values (`gui.folding.Spread`).
    """
    head = lines[fold.head]
    base = cells_for(head, decode=decode)
    if len(fold) == 1:
        return base
    members = [lines[i] for i in fold.members]
    events = [member.event for member in members if member.event is not None]
    arrow = ARROW_OPEN if opened else ARROW_CLOSED
    count = f"{len(fold)}x  "
    line_cell = replace(
        base[0],
        text=f"{arrow} {head.ref}",
        short=f"{arrow} {head.ref.line_no}",
        tooltip=_lines_tip(members),
    )
    time_cell = replace(
        base[1],
        tooltip=f"{events[0].timestamp:%H:%M:%S} to {events[-1].timestamp:%H:%M:%S}",
    )
    requests = spread(
        [(event.method or "", event.target) for event in events],
        lambda request: _written(request[0], request[1], decode=decode),
    )
    if requests.shared:
        request = replace(base[2], text=count + base[2].text)
    else:
        first = events[0]
        request = replace(
            base[2],
            text=f"{count}{_written(first.method or '', first.path or '', decode=decode)}?\u2026",
            tooltip=f"{len(requests.values)} different requests: {requests.tip()}",
        )
    status = _shared_or_mixed(base[3], spread([event.status for event in events], _status_text))
    size = _shared_or_mixed(base[4], spread([event.bytes_sent for event in events], _bytes_text))
    return (line_cell, time_cell, request, status, size)


def member_cells(line: EvidenceLine, *, decode: bool) -> tuple[Cell, ...]:
    """A line inside an open fold: its own number and time, the repeated values quieter."""
    base = cells_for(line, decode=decode)
    quiet = tuple(replace(cell, colour=EVIDENCE_MUTED, bold=False) for cell in base[2:])
    return (
        replace(base[0], text=f"   {line.ref}", short=f"   {line.ref.line_no}"),
        base[1],
        *quiet,
    )


def _shared_or_mixed(cell: Cell, values: Spread) -> Cell:
    if values.shared:
        return cell
    return Cell(text=MIXED, colour=EVIDENCE_MUTED, italic=True, tooltip=values.tip())


def _written(method: str, target: str, *, decode: bool) -> str:
    shown = decode_target(target) if decode else display_safe(target)
    return f"{display_safe(method)} {shown}".strip()


def _status_text(status: int | None) -> str:
    return "not recorded" if status is None else str(status)


def _bytes_text(size: int | None) -> str:
    return "not recorded" if size is None else f"{size:,} B"


def _lines_tip(members: Sequence[EvidenceLine]) -> str:
    """`5 lines: 2014 to 2018` when they follow each other in one file."""
    refs = [member.ref for member in members]
    one_file = len({ref.source_file_id for ref in refs}) == 1
    first, last = (refs[0].line_no, refs[-1].line_no) if one_file else (refs[0], refs[-1])
    consecutive = one_file and refs[-1].line_no - refs[0].line_no == len(refs) - 1
    if consecutive:
        return f"{len(refs)} lines: {first} to {last}"
    return f"{len(refs)} lines, from {first} to {last}"


@dataclass(frozen=True, slots=True)
class Filtered:
    """What a filter did to one activity: what was asked, found, and searched."""

    query: str
    matched: int
    searched: int
    """Every line of the activity, not the ones the panel loaded: the filter reads all."""


class RequestFilter:
    """A filter on the evidence, read against one client's reconstruction.

    A time of day is read on the day of the activity its request belongs to:
    `after:10:00` on a visit from the 11th means ten o'clock on the 11th, and on
    one from the 12th, ten on the 12th. The canvas and the panel both ask here,
    so an activity the canvas leaves bright is one the panel finds lines in.
    """

    def __init__(self, text: str, result: AnalysisResult) -> None:
        self.text = text
        self._days = {episode.episode_id: episode.start.date() for episode in result.episodes}
        self._queries: dict[date | None, Query] = {}

    @classmethod
    def read(cls, text: str, result: AnalysisResult) -> RequestFilter | None:
        """The filter `text` asks for, or `None` when it narrows nothing yet.

        Nothing yet: empty, or a key still waiting for its value. Either is the
        whole activity, and a strip saying "33 of 33 lines match" would be noise.
        """
        # Any day will do to ask whether there is a filter at all: a time of day
        # is one on every day. So nothing typed costs nothing, which matters
        # because this is asked on every selection.
        if parse(text, Scope.EVIDENCE, day=ANY_DAY).is_empty:
            return None
        return cls(text, result)

    def keeps(self, request: RequestAssignment) -> bool:
        return self._query(self._days.get(request.episode_id)).matches(request.labelled.event)

    def episodes(self, requests: Iterable[RequestAssignment]) -> frozenset[str]:
        """The episodes holding at least one request this filter keeps."""
        found: set[str] = set()
        for request in requests:
            if request.episode_id not in found and self.keeps(request):
                found.add(request.episode_id)
        return frozenset(found)

    def _query(self, day: date | None) -> Query:
        query = self._queries.get(day)
        if query is None:
            query = self._queries[day] = parse(self.text, Scope.EVIDENCE, day=day)
        return query


def filter_strip(filtered: Filtered, *, shown: int) -> str:
    """The line above a filtered table, which stops it being read as the whole.

    A reader who forgets a filter is on, and reports the filtered count as the
    activity, is the mistake this sentence exists to prevent; so it names both.
    """
    noun = "line" if filtered.searched == 1 else "lines"
    verb = "matches" if filtered.matched == 1 else "match"
    text = (
        f"Filtered \u00b7 {filtered.matched:,} of {filtered.searched:,} {noun} "
        f"{verb} {filtered.query}"
    )
    if filtered.matched > shown:
        text += f" \u00b7 showing the first {shown:,}"
    return text


def no_results(filtered: Filtered) -> str:
    """What an empty filtered table says, so it does not read as a panel that failed."""
    if filtered.searched == 1:
        return f"The one line in this activity does not match {filtered.query}."
    return f"None of the {filtered.searched:,} lines in this activity match {filtered.query}."
