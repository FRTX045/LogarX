"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, QRectF, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHBoxLayout,
    QLabel,
    QMenu,
    QPushButton,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from logarc.caseview import CLIENT_LIMIT
from logarc.gui._qt import SORT_KEY, SortableItem, required
from logarc.gui.client_filter import caption as filter_caption
from logarc.gui.client_filter import match_caption, matches
from logarc.gui.columns import ColumnWidths
from logarc.gui.filter_box import FilterBox
from logarc.gui.flow import FlowLayout
from logarc.gui.ribbon import Mark, ribbon_icon, ribbon_tip
from logarc.gui.theme import PAD, TIGHT, caption_font, colour_text, mono_font
from logarc.search import ANY_DAY, Scope, is_time, parse
from logarc.style import (
    SIZE_NOTE,
    THEME,
    outcome_legend,
    severity_legend,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

    from PyQt6.QtGui import QMouseEvent

    from logarc.storage.base import ClientMatchPage, IpSummary, IpSummaryPage

__all__ = ["ClientTable", "LegendBar"]

#: Headers kept short because a header wider than its values sets the column
#: width, and six columns of prose did not fit the panel however the values
#: were sized. "Requests" alone was wider than any count it ever holds.
_COLUMNS = ("Client", "Reqs", "Paths", "4xx", "First", "Last", "Match")

#: The columns holding numbers. Right-aligned so their digits line up under a
#: heading wider than any of them — the evidence table beside this one has done
#: that for `Status` and `Size` since it was written, while these three, in the
#: table whose whole purpose is being sorted by `4xx`, stayed ragged left.
_NUMERIC = (
    _COLUMNS.index("Reqs"),
    _COLUMNS.index("Paths"),
    _COLUMNS.index("4xx"),
    _COLUMNS.index("Match"),
)

#: The address column. Monospace, because an address is a column of numbers
#: pretending to be a word: `100.66.1.152` and `100.66.2.9` only sit under each
#: other if the digits are the same width, and this list is read by scanning it.
_ADDRESS = _COLUMNS.index("Client")

#: How many of a client's requests a search of the case found. Last among the
#: columns, so none of the others moves, and shown beside the address: it is
#: what the list is ordered by while a search is on.
_MATCH = _COLUMNS.index("Match")

#: What the client box says before anything is typed: that it searches the
#: case, and the filters it takes.
CASE_HINT = "Search the case\u2026   ip:   status:   path:   activity:"


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
    """Every client in the case, a page at a time, sortable, one click to reconstruct.

    The list holds one page of the case by request count. Filtering narrows that
    page at once; when the page is not the whole case, the table then asks, through
    `page_requested`, for the matching clients from all of it, and whoever answers
    hands the page back to `show_page`.
    """

    #: Rows per page, the same cap the window reads the busiest clients with.
    PAGE_SIZE = CLIENT_LIMIT

    #: How long the filter must rest before the whole case is searched.
    SEARCH_DELAY_MS = 150

    client_chosen = pyqtSignal(str)

    filter_edited = pyqtSignal()
    """The filter text changed. Any search answer on its way is now stale, and the
    answerer should drop it: sent before the pause, not after it."""

    page_requested = pyqtSignal(str, int)
    """A page is wanted: the filter text (empty for the whole case) and its offset
    by request count. Answer with `show_page` or `show_failure`."""

    range_typed = pyqtSignal(str)
    """`after:` or `before:` was finished in the box: the range's to take. Carries
    those filters. Once the range has moved, the window puts `query_without_times`
    back with `set_query`, read then rather than now: typing goes on meanwhile."""

    client_released = pyqtSignal()
    """The reader pressed the row they were already on.

    A signal of its own rather than an empty `client_chosen`: letting go is not
    choosing nobody, it is a different instruction, and the window answers it by
    putting the case back rather than by reconstructing anything.
    """

    bookmark_requested = pyqtSignal(str)
    """A client's row asked to be bookmarked, from its right-click menu."""

    bookmark_search_requested = pyqtSignal()
    """The search answered on screen asked to be bookmarked."""

    def __init__(self) -> None:
        super().__init__()
        # How large the case is, which is not how many rows were drawn from
        # it. Zero until a case is opened, which is what the caption already
        # words as "No clients."
        self._total = 0
        # The page on screen: where it starts, what it was asked for, and, for a
        # search, how many clients in the whole case match.
        self._first = 1
        self._query = ""
        self._matching: int | None = None
        self._page_total = 0
        self._searching = False
        # The busiest page, as the case or range opened with it: where a cleared
        # search goes back to, whichever page was on screen before it.
        self._busiest: list[IpSummary] = []
        # What the rows on screen are, when a search of requests chose them:
        # counted (a Match column) or not (an activity the scan answered),
        # and how many requests the whole search found. None otherwise.
        self._counted: bool | None = None
        self._requests = 0
        # Why the search on screen has no answer, and in what colour, until
        # the text changes or an answer arrives. Kept, not only drawn, so a
        # redraw of the caption cannot replace it with a count of nothing.
        self._message: tuple[str, str] | None = None
        self._open: str | None = None
        # Which clients carry a bookmark, kept so every refill can mark them again.
        self._marks: dict[str, Mark] = {}
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
        # The spare width goes to Last, the rightmost column on screen. Match is
        # the last column by index but sits beside the address, and is hidden
        # until a search counts requests: given the spare width, it left a
        # blank band at the right of every list without one.
        self._column_sizes = ColumnWidths(self._table, fill=_COLUMNS.index("Last"))
        # Room for the sort chevron, which is drawn above the label. The header
        # came out 16px tall for 12px of text, and the top edge cut the indicator
        # in half — leaving the one thing this header says beyond its six words,
        # which column the table is ordered by, half drawn.
        header.setMinimumHeight(header.fontMetrics().height() + 14)
        # A bound method, not a lambda: Qt made this header, so the collector
        # cannot reach a lambda through it, and one closing over the table kept
        # the table alive for good (test_window_lifetime).
        header.sortIndicatorChanged.connect(self._sort_changed)
        header.moveSection(_MATCH, _ADDRESS + 1)
        self._table.setColumnHidden(_MATCH, True)
        self._table.itemSelectionChanged.connect(self._emit_choice)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_menu)

        # Addresses as before, typed and found at once on the page; filters on
        # what clients sent, as chips, answered from the whole case. Monospace,
        # as the box sets it: an address is a column of digits pretending to be
        # a word, and what is typed should look like what it is compared with.
        self._filter = FilterBox(
            scope=Scope.CASE, placeholder=CASE_HINT, accessible_name="Search the case"
        )
        self._filter.textChanged.connect(lambda _text: self._filter_changed())
        self._filter.committed.connect(self._committed)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(self.SEARCH_DELAY_MS)
        self._search_timer.timeout.connect(self._ask)
        self._previous = QPushButton("Previous")
        self._next = QPushButton("Next")
        self._previous.clicked.connect(lambda: self._step(-1))
        self._next.clicked.connect(lambda: self._step(1))

        self._caption = QLabel("No case open.")
        # A search's caption is a sentence, and was cut at the panel's edge.
        self._caption.setWordWrap(True)
        self._caption.setFont(caption_font(self._caption.font()))
        colour_text(self._caption, THEME.muted)
        # Beside the caption of a search's answer, and only then: a search is
        # worth keeping once it has found something to keep.
        self.search_bookmark = QPushButton("Bookmark this search")
        self.search_bookmark.setIcon(ribbon_icon(THEME.accent, hollow=True))
        self.search_bookmark.setFlat(True)
        self.search_bookmark.setCursor(Qt.CursorShape.PointingHandCursor)
        self.search_bookmark.setStyleSheet(f"color:{THEME.accent}; padding:0 4px;")
        self.search_bookmark.clicked.connect(self.bookmark_search_requested.emit)
        self.search_bookmark.hide()
        layout = QVBoxLayout(self)
        # Not flush against the frame. At zero the caption and the first column
        # both start at x=0, and the window edge cut the leading character off
        # each: the panel opened on half a `5` of `500 clients`.
        layout.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        layout.setSpacing(TIGHT)
        layout.addWidget(self._filter)
        layout.addWidget(self._caption)
        layout.addWidget(self.search_bookmark, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._table)
        paging = QHBoxLayout()
        paging.addWidget(self._previous)
        paging.addWidget(self._next)
        layout.addLayout(paging)
        self._update_paging()

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
        self._search_timer.stop()
        was = self._filter.blockSignals(True)
        self._filter.clear()
        self._filter.blockSignals(was)
        self._total = len(summaries) if total is None else total
        self._busiest = list(summaries)
        self._searching = False
        self._message = None
        self._counted = None
        self._show_rows(summaries, first=1, query="", matching=None, page_total=self._total)

    def _show_rows(
        self,
        summaries: Sequence[IpSummary],
        *,
        first: int,
        query: str,
        matching: int | None,
        page_total: int,
        hits: Sequence[int] = (),
    ) -> None:
        """Replace the rows with one page, busiest first, and describe it.

        `hits` fills the Match column, row for row, when a search of requests
        chose the page; it is then ordered by that, most first.
        """
        self._first, self._query, self._matching = first, query, matching
        self._page_total = page_total
        # Silent for the whole rebuild. A refill is the window replacing its own
        # furniture, not the reader choosing or dropping anything — and left to
        # speak it does both, one of them wrongly: shrinking the list moves the
        # selection onto a surviving row and emits a choice carrying whatever
        # address that row still held, from the list being replaced.
        blocked = self._table.blockSignals(True)
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(summaries))
        # Every row shown before the columns are measured: Qt measures the rows
        # it can see, and a search hides them all while it runs, so the answer
        # was measured as though it were empty and a long address cut short.
        for row in range(self._table.rowCount()):
            self._table.setRowHidden(row, False)
        # Shown or hidden before the columns are measured, so a Match column
        # that appears is sized to its counts with the rest.
        self._table.setColumnHidden(_MATCH, not self._counted)
        # The indicator before sorting is turned back on, which sorts by it at
        # once, and ties keep whatever order that leaves. Left on the reader's
        # last column, ties came out in that column's order rather than the
        # page's own.
        required(self._table.horizontalHeader(), "column header").setSortIndicator(
            self._natural_order(), Qt.SortOrder.DescendingOrder
        )
        for row, summary in enumerate(summaries):
            self._set(row, 0, summary.client_ip)
            self._set(row, 1, f"{summary.request_count:,}", sort_key=summary.request_count)
            self._set(row, 2, f"{summary.distinct_paths:,}", sort_key=summary.distinct_paths)
            self._set(
                row, 3, f"{summary.client_error_ratio:.0%}", sort_key=summary.client_error_ratio
            )
            self._set(row, 4, format_seen(summary.first_seen))
            self._set(row, 5, format_seen(summary.last_seen))
            found = hits[row] if row < len(hits) else 0
            self._set(row, _MATCH, f"{found:,}", sort_key=found)
        # Marked before the columns are measured, so a ribbon's width is counted
        # and never cuts the address beside it.
        self._apply_marks()
        # Measured once, with sorting off: Qt then leaves the sort arrow's room
        # out of every heading, which keeps the list inside its panel.
        self._column_sizes.fit_unset()
        self._table.setSortingEnabled(True)
        # Busiest first, the order pages are cut in, so a later page visibly
        # continues the one before it; most matches first for a search.
        self._table.sortItems(self._natural_order(), Qt.SortOrder.DescendingOrder)
        # The one heading that draws the arrow gets its room back: without it,
        # `Match` above a count of 55 read `atc`.
        self._column_sizes.fit_heading(self._natural_order())
        self._mark_open()
        self._table.blockSignals(blocked)
        self._hide_unmatched()
        self._update_paging()
        self._refresh_caption()

    def show_page(self, page: IpSummaryPage, query: str) -> bool:
        """Show a page a search or a page request returned; False if it is stale.

        Stale means the filter no longer says `query`. The window drops answers
        for an earlier case or range itself; this catches the ones for earlier text.
        """
        wanted = query.strip()
        if wanted != self._filter.text().strip():
            return False
        self._search_timer.stop()
        self._searching = False
        self._counted = None
        self._message = None
        self._filter.give_way()
        self._show_rows(
            page.rows,
            first=page.offset + 1,
            query=wanted,
            matching=page.total if wanted else None,
            page_total=page.total,
        )
        return True

    def show_matches(self, page: ClientMatchPage, query: str, *, counted: bool = True) -> bool:
        """Show the clients a search of requests found; False if it is stale.

        `counted` is false when the Where to start scan answered on its own: it
        says which clients an activity reached, not in how many requests, so
        there is no Match number to show.
        """
        wanted = query.strip()
        if wanted != self._filter.text().strip():
            return False
        self._search_timer.stop()
        self._searching = False
        self._counted = counted
        self._message = None
        self._filter.give_way()
        self._requests = page.requests
        self._show_rows(
            page.rows,
            first=page.offset + 1,
            query=wanted,
            matching=page.total,
            page_total=page.total,
            hits=page.hits,
        )
        return True

    def query_text(self) -> str:
        """What the box holds: its filters, then whatever is typed."""
        return self._filter.text()

    def query_without_times(self) -> str:
        """The box without the times it has finished: what is searched once they
        have moved the range. A time still being typed stays."""
        typed = self._filter.typed().strip()
        kept = [chip for chip in self._filter.chips() if not is_time(chip)]
        return " ".join(kept + ([typed] if typed else []))

    def set_query(self, text: str) -> None:
        """Put `text` in the box and search for it at once: nothing was typed, so
        there is no typing to wait out."""
        self._filter.setText(text)
        self._ask_now()

    def search_again(self) -> None:
        """Ask for what the box holds once more, at once: the answer it had has changed."""
        self._filter_changed()
        self._ask_now()

    def _ask_now(self) -> None:
        """Ask for a search waiting on the typing to rest without waiting for it."""
        if self._search_timer.isActive():
            self._search_timer.stop()
            self._ask()

    def set_suggestion_values(
        self, values: Mapping[str, Sequence[tuple[str, str]]], title: str
    ) -> None:
        """The values the box offers after `status:`, `method:` or `activity:`."""
        self._filter.set_values(values, title)

    def show_failure(self, query: str, message: str) -> None:
        """Say that a search could not be answered, if it is still the one on screen."""
        wanted = query.strip()
        if wanted != self._filter.text().strip():
            return
        self._searching = False
        self._message = (f"Could not search the whole case for {wanted}: {message}", THEME.alert)
        self._filter.give_way()
        self._refresh_caption()

    def show_pending(self, query: str, message: str) -> None:
        """Say why a search cannot be answered yet, if it is still the one on screen.

        No rows are shown meanwhile: none of them is known to be the answer.
        """
        wanted = query.strip()
        if wanted != self._filter.text().strip():
            return
        self._search_timer.stop()
        self._searching = False
        self._message = (message, THEME.muted)
        self._filter.give_way()
        self._hide_unmatched()
        self._refresh_caption()

    def set_open_client(self, client_ip: str | None) -> None:
        """Say which client is being read, so the list can mark it or say it is absent."""
        self._open = client_ip
        self._mark_open()
        self._refresh_caption()

    def select_quietly(self, client_ip: str) -> bool:
        """Put the table back on `client_ip` without emitting a choice.

        `False` when that client is not in the list at all.

        The block is the point. `client_chosen` comes from
        `itemSelectionChanged`, and a selection put back unblocked emits the
        choice a second time, so the window reconstructs the client it has
        just dropped. The window needs this on three paths, so it lives here
        with the table that owns the signal.
        """
        table = self._table
        for row in range(table.rowCount()):
            cell = table.item(row, _ADDRESS)
            if cell is not None and cell.text() == client_ip:
                blocked = table.blockSignals(True)
                table.selectRow(row)
                table.blockSignals(blocked)
                return True
        return False

    # -- bookmarks -------------------------------------------------------------

    def set_marks(self, marks: Mapping[str, Mark]) -> None:
        """Ribbon the clients in `marks`, and keep doing so through every refill."""
        self._marks = dict(marks)
        blocked = self._table.blockSignals(True)
        self._table.setSortingEnabled(False)
        self._apply_marks()
        self._column_sizes.fit_unset()
        self._table.setSortingEnabled(True)
        header = required(self._table.horizontalHeader(), "column header")
        self._column_sizes.fit_heading(header.sortIndicatorSection())
        self._table.blockSignals(blocked)

    def _apply_marks(self) -> None:
        for row in range(self._table.rowCount()):
            cell = self._table.item(row, _ADDRESS)
            if cell is None:
                continue
            mark = self._marks.get(cell.text())
            cell.setIcon(ribbon_icon(mark[0]) if mark is not None else QIcon())
            cell.setToolTip(ribbon_tip(mark[1]) if mark is not None else "")

    def _sort_changed(self, section: int, _order: Qt.SortOrder) -> None:
        """Ordered by another column: the caption says so, and its heading fits."""
        self._refresh_caption()
        self._column_sizes.fit_heading(section)

    def box_has_focus(self) -> bool:
        """Whether the keyboard is in the client box rather than the list."""
        focus = QApplication.focusWidget()
        return focus is not None and (focus is self._filter or self._filter.isAncestorOf(focus))

    def selected_client(self) -> str | None:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        cell = self._table.item(rows[0].row(), _ADDRESS) if rows else None
        return cell.text() if cell is not None else None

    def answered_search(self) -> tuple[str, int, int | None] | None:
        """The search whose answer is on screen: its text, clients, and requests if counted."""
        if (
            self._counted is None
            or self._searching
            or self._matching is None
            or self._message is not None
            or self._query != self._filter.text().strip()
        ):
            return None
        return self._query, self._matching, self._requests if self._counted else None

    def _menu_at(self, point: QPoint) -> QMenu | None:
        """The menu a right-click at `point` opens, or None off the rows."""
        index = self._table.indexAt(point)
        cell = self._table.item(index.row(), _ADDRESS) if index.isValid() else None
        if cell is None:
            return None
        address = cell.text()
        menu = QMenu(self)
        menu.addAction("Bookmark this client\u2026", lambda: self.bookmark_requested.emit(address))
        return menu

    def _show_menu(self, point: QPoint) -> None:
        menu = self._menu_at(point)
        if menu is not None:
            menu.popup(required(self._table.viewport(), "viewport").mapToGlobal(point))

    def _filter_changed(self) -> None:
        """Narrow the page at once, then search the whole case if the page is not all of it.

        Hiding rows deliberately leaves the selection where it is, even when the
        selected client is the one hidden. Filtering is a change to what is listed,
        not to what is being read, and Qt neither moves the selection off a hidden
        row nor emits `itemSelectionChanged` for one.
        """
        self.filter_edited.emit()
        self._search_timer.stop()
        self._message = None
        # Any day will do: a time of day is a filter, whichever day the
        # window reads it on.
        query = parse(self._filter.text(), Scope.CASE, day=ANY_DAY)
        if query.is_empty:
            # Nothing to search for yet: an empty box, or `status:` waiting for
            # its value. The busiest page, as the case opened with it.
            self._searching = False
            self._counted = None
            if self._query or self._first != 1:
                self._show_rows(
                    self._busiest, first=1, query="", matching=None, page_total=self._total
                )
            else:
                self._hide_unmatched()
                self._refresh_caption()
            return
        self._hide_unmatched()
        # A page holds clients, not their requests, so only an address can be
        # answered from it; anything else asks the whole case, however small.
        complete = query.is_address_only and len(self._busiest) >= self._total
        self._searching = not complete
        if not complete:
            # The page on screen belongs to the previous text, so stepping from it
            # would skip the new search's own first page.
            self._previous.setEnabled(False)
            self._next.setEnabled(False)
            self._search_timer.start()
        self._refresh_caption()

    def _hide_unmatched(self) -> None:
        """Hide what the box rules out, as far as this page can tell.

        Addresses are matched here, each as the old box matched one, and any of
        them will do. Rows a search of requests chose stay; while one is still
        being answered nothing is shown, so no row can be read as its answer.
        """
        query = parse(self._filter.text(), Scope.CASE, day=ANY_DAY)
        answered = self._counted is not None and self._query == self._filter.text().strip()
        waiting = not (query.is_empty or query.is_address_only or answered)
        for row in range(self._table.rowCount()):
            cell = self._table.item(row, _ADDRESS)
            if query.is_empty or answered:
                hidden = False
            elif waiting or cell is None:
                hidden = True
            else:
                hidden = not any(matches(cell.text(), address) for address in query.ips)
            self._table.setRowHidden(row, hidden)

    def _ask(self) -> None:
        """The box has rested: hand over its finished times, or ask for its search.

        Only a time made a chip moves the range. One still being typed may be the
        start of a longer one, `after:2024-05-01` on its way to a time on that
        day, and is searched meanwhile like any other filter.
        """
        times = [chip for chip in self._filter.chips() if is_time(chip)]
        if times:
            self.range_typed.emit(" ".join(times))
        else:
            self.page_requested.emit(self._filter.text().strip(), 0)

    def _committed(self) -> None:
        """A filter was finished without the text changing; a time is acted on now."""
        if any(is_time(chip) for chip in self._filter.chips()):
            self._filter_changed()

    def _step(self, direction: int) -> None:
        """Ask for the page before or after this one, of what this page was asked for."""
        if self._filter.text().strip() != self._query:
            return
        offset = max(0, self._first - 1 + direction * self.PAGE_SIZE)
        self.page_requested.emit(self._query, offset)

    def _update_paging(self) -> None:
        shown = self._table.rowCount()
        more = self._first - 1 + shown < self._page_total
        self._previous.setEnabled(self._first > 1)
        self._next.setEnabled(more)
        paged = self._first > 1 or more
        self._previous.setVisible(paged)
        self._next.setVisible(paged)

    def _mark_open(self) -> bool:
        """Select the open client's row, quietly, if it is listed; whether it is."""
        return self._open is None or self.select_quietly(self._open)

    def _natural_order(self) -> int:
        """The column a page is cut by: matches for a counted search, requests otherwise."""
        return _MATCH if self._counted else _COLUMNS.index("Reqs")

    def _refresh_caption(self) -> None:
        self.search_bookmark.setVisible(self.answered_search() is not None)
        if self._message is not None:
            text, colour = self._message
            self._caption.setText(text)
            colour_text(self._caption, colour)
            return
        colour_text(self._caption, THEME.muted)
        shown = sum(not self._table.isRowHidden(row) for row in range(self._table.rowCount()))
        header = required(self._table.horizontalHeader(), "column header")
        reordered = (
            header.sortIndicatorSection() != self._natural_order()
            or header.sortIndicatorOrder() != Qt.SortOrder.DescendingOrder
        )
        listed = self._open is None or any(
            (cell := self._table.item(row, _ADDRESS)) is not None and cell.text() == self._open
            for row in range(self._table.rowCount())
        )
        if self._counted is not None and not self._searching and self._matching is not None:
            self._caption.setText(
                match_caption(
                    shown=shown,
                    total=self._total,
                    query=self._query,
                    first=self._first,
                    matching=self._matching,
                    requests=self._requests,
                    counted=self._counted,
                    reordered=reordered,
                    missing_open=None if listed else self._open,
                )
            )
            return
        self._caption.setText(
            filter_caption(
                shown=shown,
                total=self._total,
                query=self._filter.text(),
                first=self._first,
                matching=self._matching if self._query else None,
                searching=self._searching,
                reordered=reordered,
                missing_open=None if listed else self._open,
            )
        )

    def _set(self, row: int, column: int, text: str, *, sort_key: float | None = None) -> None:
        item = SortableItem(text)
        if column in _NUMERIC:
            item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if column == _ADDRESS:
            item.setFont(mono_font(self._table.font().pointSizeF()))
            item.setForeground(QColor(THEME.identity))
        elif column in (4, 5):
            item.setForeground(QColor(THEME.timestamp))
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
#: `FlowLayout` was written to fix. Six and three buy the width back while
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
        self.flow = FlowLayout(spacing=_ENTRY_GAP)
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
