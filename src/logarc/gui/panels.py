"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLayoutItem,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import SORT_KEY, SortableItem, required
from logarc.gui.style import (
    SIZE_NOTE,
    outcome_legend,
    severity_legend,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from logarc.storage.base import IpSummary

__all__ = ["ClientTable", "LegendBar"]

#: Headers kept short because a header wider than its values sets the column
#: width, and six columns of prose did not fit the panel however the values
#: were sized. "Requests" alone was wider than any count it ever holds.
_COLUMNS = ("Client", "Reqs", "Paths", "4xx", "First", "Last")


def format_seen(when: datetime) -> str:
    """A timestamp for the client table, short enough to leave room beside it.

    The year and the seconds both go. Two full timestamps took about 280px of
    a 330px panel between them, which is what pushed the 4xx ratio — the
    column this table is sorted by when looking for something worth opening —
    off the edge entirely.

    Nothing is lost by it. This column is for ordering and orientation; the
    exact times, to the second, are in the evidence panel beside every line.
    """
    return when.strftime("%d %b %H:%M")


class ClientTable(QWidget):
    """Every client in the case, sortable, one click to reconstruct."""

    client_chosen = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        required(self._table.verticalHeader(), "row header").setVisible(False)
        header = required(self._table.horizontalHeader(), "column header")
        # Every column sized to what it holds, and none of them stretched.
        #
        # Stretching the address column was what hid the rest: it claims the
        # space left over, and with five other columns at a default width the
        # panel could not afford, three of the six sat behind a scrollbar —
        # including the 4xx ratio, which is the column the table is sorted by
        # when looking for something worth opening. Sizing every column to its
        # content and shortening the timestamps fits all six instead.
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        header.setStretchLastSection(True)
        self._table.itemSelectionChanged.connect(self._emit_choice)

        self._caption = QLabel("No case open.")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._caption)
        layout.addWidget(self._table)

    def show_clients(self, summaries: Sequence[IpSummary]) -> None:
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(summaries))
        for row, summary in enumerate(summaries):
            self._set(row, 0, summary.client_ip)
            self._set(row, 1, f"{summary.request_count:,}", sort_key=summary.request_count)
            self._set(row, 2, f"{summary.distinct_paths:,}", sort_key=summary.distinct_paths)
            self._set(
                row, 3, f"{summary.client_error_ratio:.0%}", sort_key=summary.client_error_ratio
            )
            self._set(row, 4, format_seen(summary.first_seen))
            self._set(row, 5, format_seen(summary.last_seen))
        self._table.setSortingEnabled(True)
        self._caption.setText(
            f"{len(summaries):,} client(s). Select one to reconstruct what it did."
        )

    def _set(self, row: int, column: int, text: str, *, sort_key: float | None = None) -> None:
        item = SortableItem(text)
        if sort_key is not None:
            # Sort on the number, not on the formatted text: "1,000" sorts
            # before "9" as a string, which would silently mis-rank the table.
            #
            # In a role of its own. This used to go in `EditRole`, which on a
            # table item is the same slot as the text — so the 4xx column, the
            # one this table is sorted by when looking for something worth
            # opening, was showing `0.8888888888888888` instead of `89%`.
            item.setData(SORT_KEY, sort_key)
        self._table.setItem(row, column, item)

    def _emit_choice(self) -> None:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        if rows:
            cell = self._table.item(rows[0].row(), 0)
            if cell is not None:
                self.client_chosen.emit(cell.text())


class _FlowLayout(QLayout):
    """Items in a row that wraps onto further rows when the width runs out.

    Qt ships nothing like it, and the legend needs one. Laid out as a single
    horizontal row the key reported a minimum width of **1,729px** — wider than
    the window it sits in — and a minimum is a demand, not a preference. The
    centre column inherited it, both side panels were pinned at their own
    minimums to pay for it, and with no slack left anywhere the splitter handles
    stopped moving: the client panel could be its minimum or collapsed, and
    nothing in between.

    A key is a set of small independent items. It should take as many rows as it
    needs and ask for no more width than its widest single entry.
    """

    def __init__(self, parent: QWidget | None = None, spacing: int = 10) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self.setSpacing(spacing)

    # -- the five methods QLayout requires a subclass to provide -------------

    def addItem(self, item: QLayoutItem | None) -> None:  # noqa: N802 - Qt's naming
        if item is not None:
            self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> QLayoutItem | None:  # noqa: N802 - Qt's naming
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> QLayoutItem | None:  # noqa: N802 - Qt's naming
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    # -- how it sizes --------------------------------------------------------

    def expandingDirections(self) -> Qt.Orientation:  # noqa: N802 - Qt's naming
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt's naming
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802 - Qt's naming
        return self._lay_out(QRect(0, 0, width, 0), place=False)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802 - Qt's naming
        super().setGeometry(rect)
        self._lay_out(rect, place=True)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt's naming
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802 - Qt's naming
        """One item wide. This is the number the whole window was hostage to."""
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _lay_out(self, rect: QRect, *, place: bool) -> int:
        """Place each item, wrapping at the edge; returns the height used."""
        margins = self.contentsMargins()
        left = rect.x() + margins.left()
        right = rect.right() - margins.right()
        x, y, row_height = left, rect.y() + margins.top(), 0

        for item in self._items:
            hint = item.sizeHint()
            if x > left and x + hint.width() > right:
                x, y = left, y + row_height + self.spacing()
                row_height = 0
            if place:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self.spacing()
            row_height = max(row_height, hint.height())

        return y + row_height + margins.bottom() - rect.y()


class LegendBar(QWidget):
    """The key to the canvas: what colour, outline and size each mean.

    None of it was written anywhere a user could see, so a dotted grey circle
    meant nothing to whoever was looking at one. The encoding is what makes the
    graph more than a picture, and an unexplained encoding is decoration.

    Built from `gui.style`, which is the same source the canvas draws from, so
    the key cannot describe a colour the canvas no longer uses.
    """

    def __init__(self) -> None:
        super().__init__()
        column = QVBoxLayout(self)
        column.setContentsMargins(4, 2, 4, 2)
        column.setSpacing(2)

        # One item per entry, not two. Added separately, a swatch and the word
        # it explains are independent items in the flow and a row break can land
        # between them — at 1500px it did, leaving `Unknown` on a row of its own.
        # A colour on one line and its meaning on another is the one thing a key
        # cannot do, so the pair is a single widget and wraps whole.
        self.flow = _FlowLayout(spacing=8)
        self.flow.addWidget(self._caption("Severity:"))
        for item in severity_legend():
            self.flow.addWidget(self._entry(self._swatch(item.colour, filled=True), item.label))

        self.flow.addWidget(self._caption("Outcome:"))
        for item in outcome_legend():
            border = item.border
            swatch = self._swatch(item.colour, filled=False, style=border.style if border else None)
            self.flow.addWidget(self._entry(swatch, item.label))

        column.addLayout(self.flow)

        # On its own line, and wrapped. It is a sentence rather than a swatch,
        # and as one item in the flow its 600px was the whole key's minimum —
        # a wrapping row is only as narrow as its widest single entry.
        note = self._caption(SIZE_NOTE)
        note.setWordWrap(True)
        column.addWidget(note)

        # Tell the parent layout that this widget's height depends on the width
        # it is given, or it is asked for one height, keeps it, and the wrapped
        # rows are drawn outside the space reserved for them.
        policy = self.sizePolicy()
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

    def _entry(self, swatch: QLabel, label: str) -> QWidget:
        """A swatch and its word as one thing the flow cannot take apart."""
        entry = QWidget()
        pair = QHBoxLayout(entry)
        pair.setContentsMargins(0, 0, 0, 0)
        pair.setSpacing(4)
        pair.addWidget(swatch)
        pair.addWidget(self._caption(label))
        return entry

    @staticmethod
    def _caption(text: str) -> QLabel:
        label = QLabel(text)
        font = label.font()
        font.setPointSizeF(max(font.pointSizeF() - 1.0, 7.0))
        label.setFont(font)
        return label

    @staticmethod
    def _swatch(colour: str, *, filled: bool, style: str | None = None) -> QLabel:
        """A drawn sample rather than a colour named in words.

        Naming it would ask the reader to match a word against a picture, which
        is the work the key exists to save.
        """
        sample = QLabel()
        sample.setFixedSize(16, 12)
        if filled:
            sample.setStyleSheet(f"background:{colour};border:1px solid #616e7c;")
        else:
            pen = {"solid": "solid", "dashed": "dashed", "dotted": "dotted"}.get(
                style or "", "solid"
            )
            sample.setStyleSheet(f"border:2px {pen} {colour};")
        return sample
