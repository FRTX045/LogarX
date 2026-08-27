"""Reading a table by its headings, because its column numbers have moved once.

`e9f3b15` gave the case chooser a pin-mark column at the front, which pushed
every other column one to the right. The tests written in that commit used the
new numbers; one written before it did not, and went on reading column 0 in the
belief that it held the case name. Column 0 was by then the mark, empty unless
the case is pinned, so the assertion underneath was made against `""` and could
not fail either way.

Nothing caught it because nothing could: an index is a fact about the layout,
and a test that states one is not saying which column it means. A heading is.

The headings come off the widget rather than out of `COLUMNS`, so what a test
asks for is what the reader sees at the top of the column - one table's
`_COLUMNS` is private, and both are copied into the widget the same way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QTableWidget, QTableWidgetItem

__all__ = ["cell", "column_of"]


def _headings(table: QTableWidget) -> list[str]:
    return [
        "" if item is None else item.text()
        for item in (table.horizontalHeaderItem(n) for n in range(table.columnCount()))
    ]


def column_of(table: QTableWidget, heading: str) -> int:
    """Which column the reader sees under this heading."""
    headings = _headings(table)
    assert heading in headings, f"no {heading!r} column in this table; it has {headings}"
    return headings.index(heading)


def cell(table: QTableWidget, row: int, heading: str) -> QTableWidgetItem:
    """The item in one row, under the heading naming what it holds.

    The item, not its text: a cell also carries the colour and the mark a test
    may be asking about. Missing is an assertion rather than a `None` a caller
    has to ignore its way past - `item()` returning `None` used to surface
    several lines later as an `AttributeError` on whatever was done with it.
    """
    item = table.item(row, column_of(table, heading))
    assert item is not None, f"no cell at row {row} under {heading!r}"
    return item
