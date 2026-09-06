"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, QRect, QRectF, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLayoutItem,
    QLineEdit,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import SORT_KEY, SortableItem, required
from logarc.gui.client_filter import caption as filter_caption
from logarc.gui.client_filter import matches
from logarc.gui.theme import PAD, TIGHT, caption_font, mono_font
from logarc.style import (
    SIZE_NOTE,
    THEME,
    outcome_legend,
    severity_legend,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from datetime import datetime

    from PyQt6.QtGui import QMouseEvent

    from logarc.storage.base import IpSummary

__all__ = ["ClientTable", "LegendBar"]

#: Headers kept short because a header wider than its values sets the column
#: width, and six columns of prose did not fit the panel however the values
#: were sized. "Requests" alone was wider than any count it ever holds.
_COLUMNS = ("Client", "Reqs", "Paths", "4xx", "First", "Last")

#: The columns holding numbers. Right-aligned so their digits line up under a
#: heading wider than any of them — the evidence table beside this one has done
#: that for `Status` and `Size` since it was written, while these three, in the
#: table whose whole purpose is being sorted by `4xx`, stayed ragged left.
_NUMERIC = (_COLUMNS.index("Reqs"), _COLUMNS.index("Paths"), _COLUMNS.index("4xx"))

#: The address column. Monospace, because an address is a column of numbers
#: pretending to be a word: `100.66.1.152` and `100.66.2.9` only sit under each
#: other if the digits are the same width, and this list is read by scanning it.
_ADDRESS = _COLUMNS.index("Client")


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


class _Rows(QTableWidget):
    """The rows themselves, with one gesture the base class does not offer.

    Pressing the row that is already selected lets go of it. Qt keeps such a
    press as a no-op — the row stays selected and nothing is emitted — which
    leaves no way back out of a client once one has been opened, and the band
    drawn against that client's life stays with it.

    The gesture is decided when the button goes down and carried out when it
    comes up, which is not a detail. `QAbstractItemView` finishes selecting on
    the release: it re-applies the selection to whatever the press landed on.
    Letting go during the press was therefore undone a moment later, in the same
    gesture — the row came back, `client_chosen` was emitted a second time, and
    the window answered it by reconstructing the client it had just dropped.
    """

    def __init__(self, rows: int, columns: int) -> None:
        super().__init__(rows, columns)
        self._letting_go: int | None = None

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None:  # pragma: no cover - Qt always supplies one
            return
        # The left button only. The right one opens a context menu, and a menu
        # that dropped what it was opened on would be unusable.
        already = (
            self.currentRow()
            if event.button() == Qt.MouseButton.LeftButton
            and (model := self.selectionModel()) is not None
            and model.hasSelection()
            else -1
        )
        pressed = self.indexAt(event.pos())
        self._letting_go = pressed.row() if pressed.isValid() and pressed.row() == already else None
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None:  # pragma: no cover - Qt always supplies one
            return
        letting_go = self._letting_go
        self._letting_go = None
        super().mouseReleaseEvent(event)
        released = self.indexAt(event.pos())
        # The same row the press was on. A button that came up somewhere else
        # was dragged, and a drag is not a second press on the row.
        if letting_go is not None and released.isValid() and released.row() == letting_go:
            self.clearSelection()


class ClientTable(QWidget):
    """Every client in the case, sortable, one click to reconstruct."""

    client_chosen = pyqtSignal(str)

    client_released = pyqtSignal()
    """The reader pressed the row they were already on.

    A signal of its own rather than an empty `client_chosen`: letting go is not
    choosing nobody, it is a different instruction, and the window answers it by
    putting the case back rather than by reconstructing anything.
    """

    def __init__(self) -> None:
        super().__init__()
        # How large the case is, which is not how many rows were drawn from
        # it. Zero until a case is opened, which is what the caption already
        # words as "No clients."
        self._total = 0
        self._table = _Rows(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSortingEnabled(True)
        # Striped, not gridded. A rule between every pair of cells draws a box
        # around each value and turns a list of clients into a spreadsheet; the
        # eye then has to find the row again on every horizontal move. Alternate
        # grounds carry the row across the panel without drawing anything.
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(True)
        required(self._table.verticalHeader(), "row header").setVisible(False)
        header = required(self._table.horizontalHeader(), "column header")
        # Headings are structure, not content, and were set at the same size and
        # weight as the values beneath them — six words competing with the data
        # they label. This is the treatment the exported report already gives its
        # own table headings.
        header.setFont(caption_font(self._table.font()))
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
        # Room for the sort chevron, which is drawn above the label. The header
        # came out 16px tall for 12px of text, and the top edge cut the indicator
        # in half — leaving the one thing this header says beyond its six words,
        # which column the table is ordered by, half drawn.
        header.setMinimumHeight(header.fontMetrics().height() + 14)
        self._table.itemSelectionChanged.connect(self._emit_choice)

        self._filter = QLineEdit()
        self._filter.setPlaceholderText("Filter clients…")
        self._filter.setClearButtonEnabled(True)
        # Monospace to match the column it searches: an address is a column of
        # digits pretending to be a word, and what is typed should look like
        # what it is being compared against.
        self._filter.setFont(mono_font(self._filter.font().pointSizeF()))
        self._filter.setAccessibleName("Filter clients by address")
        self._filter.textChanged.connect(self._apply_filter)

        self._caption = QLabel("No case open.")
        self._caption.setFont(caption_font(self._caption.font()))
        self._caption.setStyleSheet(f"color:{THEME.muted};")
        layout = QVBoxLayout(self)
        # Not flush against the frame. At zero the caption and the first column
        # both start at x=0, and the window edge cut the leading character off
        # each: the panel opened on half a `5` of `500 clients`.
        layout.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        layout.setSpacing(TIGHT)
        layout.addWidget(self._filter)
        layout.addWidget(self._caption)
        layout.addWidget(self._table)

    def show_clients(self, summaries: Sequence[IpSummary], *, total: int | None = None) -> None:
        """Draw these rows, and say how large the case they came from is.

        `total` because the two are not the same number. This list is capped so
        a case of a hundred thousand clients does not become a hundred thousand
        rows, and the caption is the only place a reader learns how large the
        case is — handed the row count, it said a case of 119,880 clients had
        500 in it.
        """
        # A filter typed for the last case would hide most of this one, and the
        # reader has no reason to suspect a box they filled in for something
        # else — the table would simply look like a case with almost nothing in
        # it. Cleared here rather than carried across.
        self._filter.clear()

        # Silent for the whole rebuild. A refill is the window replacing its own
        # furniture, not the reader choosing or dropping anything — and left to
        # speak it does both, one of them wrongly: shrinking the list moves the
        # selection onto a surviving row and emits a choice carrying whatever
        # address that row still held, from the list being replaced.
        blocked = self._table.blockSignals(True)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(summaries))
        with self._sized_once():
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
        for row in range(self._table.rowCount()):
            self._table.setRowHidden(row, False)
        self._table.blockSignals(blocked)
        self._total = len(summaries) if total is None else total
        self._write_caption(shown=len(summaries))

    @contextmanager
    def _sized_once(self) -> Iterator[None]:
        """Fill the table without the header re-measuring on every cell.

        `ResizeToContents` walks the whole column each time a cell changes. Into
        an *empty* table Qt takes a fast path and 3,000 cells cost 0.2s; once the
        rows already hold items it does not, and the same 3,000 cost 66 seconds
        — on the interface thread, which is what made opening a case the window
        already had open freeze it for over a minute.

        So the mode is dropped for the duration and restored afterwards, which
        measures once instead of three thousand times. The columns come out the
        same width they always did; what goes is the repetition. Measured at
        66.54s before and 0.08s after.
        """
        header = required(self._table.horizontalHeader(), "column header")
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        try:
            yield
        finally:
            header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)

    def _apply_filter(self) -> None:
        """Hide the rows that do not match what has been typed.

        Hiding rows deliberately leaves the selection where it is, even when
        the selected client is the one hidden. Filtering is a change to what is
        listed, not to what is being read: the canvas goes on showing the
        reconstruction the investigator opened, and clearing the box brings its
        row back still selected.

        That holds without help here — measured rather than assumed. Qt neither
        moves the selection off a hidden row nor emits `itemSelectionChanged`
        for one, so the guards first written around this loop (blocking the
        table's signals, restoring the selected row afterwards) were defending
        against nothing and were removed. `test_filtering_does_not_reconstruct_a
        _different_client` still holds the property, because it is Qt's promise
        and not ours.
        """
        query = self._filter.text()
        shown = 0
        for row in range(self._table.rowCount()):
            cell = self._table.item(row, _ADDRESS)
            keep = cell is not None and matches(cell.text(), query)
            self._table.setRowHidden(row, not keep)
            shown += keep
        self._write_caption(shown=shown)

    def _write_caption(self, *, shown: int) -> None:
        self._caption.setText(
            filter_caption(shown=shown, total=self._total, query=self._filter.text())
        )

    def _set(self, row: int, column: int, text: str, *, sort_key: float | None = None) -> None:
        item = SortableItem(text)
        if column in _NUMERIC:
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if column == _ADDRESS:
            item.setFont(mono_font(self._table.font().pointSizeF()))
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
        if not rows:
            self.client_released.emit()
            return
        cell = self._table.item(rows[0].row(), 0)
        if cell is not None:
            self.client_chosen.emit(cell.text())


#: How big an outcome sample is drawn. Larger than the severity swatch beside
#: it, because a dash pattern needs perimeter to read as a pattern: at 14px a
#: circle carries about five dashes, which is a ragged edge rather than a dashed
#: one, and dotted and dashed came out looking like each other.
_SWATCH = 20

#: The rhythm a patterned outline is drawn with in the key, and the weight it is
#: drawn at.
#:
#: Spelled out rather than left to Qt, which measures a dash in multiples of the
#: pen width: a `DashLine` at the canvas's 3px means 12px of dash on a circle
#: whose whole perimeter is 56px, so `Mixed` came out as a ring with two bites
#: taken out of it rather than as a dashed one, and dotted was not far behind.
#: Patterned samples therefore take one fixed weight and an explicit rhythm.
_PATTERN_WIDTH = 2.0
_DASHES = {"dashed": (2.0, 2.0), "dotted": (1.0, 2.0)}

#: What a solid sample may be drawn at. Solid outlines keep their real weight,
#: because with every outcome now sharing one colour that weight is the only
#: thing separating `Success` from `Unknown` — a heavy ring from a light one.
#:
#: The floor is above `Unknown`'s own 1.0. On a node that is a hairline around
#: something 44 to 124 pixels across and reads as deliberately faint; on an
#: 18-pixel sample it reads as nothing at all, and a key entry nobody can see is
#: the failure this whole sample was redrawn to fix. At 1.5 against `Success`'s
#: 3.0 the two are still plainly a heavy ring and a light one.
_SOLID_RANGE = (1.5, 4.0)

#: What separates one key entry from the next, and a swatch from its own word.
#:
#: Off the spacing scale, and deliberately. The key is the one row in the window
#: whose contents are fixed and whose width is not: growing the outcome samples
#: enough to be legible took it to 634px in a 620px column, and it wrapped —
#: putting `Unknown` alone on a second row, which is precisely the fault
#: `_FlowLayout` was written to fix. Six and three buy the width back while
#: keeping the ratio that groups a swatch with its label rather than with its
#: neighbour, which four and four would not.
_ENTRY_GAP = 6
_PAIR_GAP = 3


def _outline_sample(colour: str, style: str, width: float) -> QPixmap:
    """One outcome, drawn as the ring alone, in the colour the canvas draws it.

    Unfilled. Given a fill — a pale disc with a dark rim, which is what a node
    used to be — the fill is what the eye gets: twenty pixels of disc against two
    of edge, so all four outcomes read as *a pale dot* and dotted, dashed and
    solid cannot be told apart without magnifying the window. Which is how it
    survived two rounds of being called fixed: it was checked at four times size,
    where the difference is obvious, and shipped at one times size, where it is
    not.

    Without the fill the ring is the whole sample, and it needs no colour of its
    own: an outcome outline is now light because it has to be seen against the
    canvas, and the panel behind this sample is darker still.
    """
    pixmap = QPixmap(_SWATCH, _SWATCH)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(Qt.BrushStyle.NoBrush)

    pen = QPen(QColor(colour))
    if style in _DASHES:
        pen.setWidthF(_PATTERN_WIDTH)
        pen.setDashPattern(list(_DASHES[style]))
    else:
        low, high = _SOLID_RANGE
        pen.setWidthF(min(max(width, low), high))
    painter.setPen(pen)

    inset = pen.widthF() / 2 + 0.5
    painter.drawEllipse(QRectF(inset, inset, _SWATCH - inset * 2, _SWATCH - inset * 2))
    painter.end()
    return pixmap


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

    Built from `logarc.style`, which is the same source the canvas draws from, so
    the key cannot describe a colour the canvas no longer uses.
    """

    def __init__(self) -> None:
        super().__init__()
        column = QVBoxLayout(self)
        column.setContentsMargins(TIGHT, 2, TIGHT, 2)
        column.setSpacing(2)

        # One item per entry, not two. Added separately, a swatch and the word
        # it explains are independent items in the flow and a row break can land
        # between them — at 1500px it did, leaving `Unknown` on a row of its own.
        # A colour on one line and its meaning on another is the one thing a key
        # cannot do, so the pair is a single widget and wraps whole.
        self.flow = _FlowLayout(spacing=_ENTRY_GAP)
        self.flow.addWidget(self._label("Severity"))
        for item in severity_legend():
            self.flow.addWidget(self._entry(self._swatch(item.colour, filled=True), item.label))

        self.flow.addWidget(self._label("Outcome"))
        for item in outcome_legend():
            border = item.border
            swatch = self._swatch(
                item.colour,
                filled=False,
                style=border.style if border else None,
                width=border.width if border else _PATTERN_WIDTH,
            )
            self.flow.addWidget(self._entry(swatch, item.label))

        column.addLayout(self.flow)

        # Still on its own line, and still wrapped. Moving it into the flow was
        # tried and reverted: shortened to `Size = request count, by square
        # root` it measured 404px, and a flow demands no less than its widest
        # single item, so the legend's minimum went from 232px to 404px and
        # `test_the_legend_does_not_dictate_how_wide_the_window_must_be` caught
        # it at 320. A wrapping label asks only for its longest word. The
        # shortening was kept — it makes this one line instead of two.
        note = self._caption(SIZE_NOTE)
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{THEME.faint};")
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
        pair.setSpacing(_PAIR_GAP)
        pair.addWidget(swatch)
        pair.addWidget(self._caption(label))
        return entry

    @staticmethod
    def _caption(text: str) -> QLabel:
        label = QLabel(text)
        label.setFont(caption_font(label.font()))
        return label

    @staticmethod
    def _label(text: str) -> QLabel:
        """A word that names a channel rather than an entry in one.

        Quieter than the entries it introduces, and without the trailing colon
        it used to carry: `Severity:` reads as a field with a value after it,
        and what follows is a row of five samples.
        """
        label = LegendBar._caption(text)
        label.setStyleSheet(f"color:{THEME.faint};")
        return label

    @staticmethod
    def _swatch(
        colour: str, *, filled: bool, style: str | None = None, width: float = 2.0
    ) -> QLabel:
        """A drawn sample rather than a colour named in words.

        Naming it would ask the reader to match a word against a picture, which
        is the work the key exists to save.

        A severity is a flat colour and a stylesheet draws that perfectly well.
        An outcome is an *outline*, and a stylesheet drew it badly: a 2px dashed
        border on a 14 by 11 box gives about three dashes a side, landing as a
        chipped rectangle rather than a dashed one, and CSS renders the corners
        of a dotted border as blobs. So the outcome sample is painted instead —
        a small circle with the same pen the canvas uses, which is both legible
        at this size and literally the thing being explained.
        """
        sample = QLabel()
        if filled:
            sample.setFixedSize(14, 11)
            sample.setStyleSheet(f"background:{colour};border:1px solid {THEME.line};")
            return sample
        sample.setFixedSize(_SWATCH, _SWATCH)
        sample.setPixmap(_outline_sample(colour, style or "solid", width))
        return sample
