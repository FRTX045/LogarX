"""What the evidence table says, as plain data.

No Qt here, for the same reason `gui.style` has none. These are the decisions
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
from typing import TYPE_CHECKING, Final

from logarc.gui.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    decode_target,
    display_safe,
    format_bytes,
    status_colour,
)

if TYPE_CHECKING:
    from logarc.evidence import EvidenceLine

__all__ = ["COLUMNS", "Cell", "cells_for"]

#: Headings, in order. `Target` is the one that grows: every other value is a
#: handful of characters and a payload is sixty.
COLUMNS: Final[tuple[str, ...]] = ("Source", "Time", "Method", "Target", "Status", "Size")


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
            colour=EVIDENCE_MUTED,
        ),
        Cell(text=display_safe(event.method or "") if event else ""),
        _target_cell(line, decode=decode),
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


def _target_cell(line: EvidenceLine, *, decode: bool) -> Cell:
    """The request, which is the column the reader came for."""
    event = line.event
    target = event.target if event else ""
    shown = decode_target(target) if decode else display_safe(target)
    return Cell(text=shown, tooltip=shown, bold=True)
