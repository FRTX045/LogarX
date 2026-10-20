"""The evidence beside the graph: a table of requests, and one of them in full.

A column of text turned twenty-five pieces of evidence into 175 wrapped rows
that could only be read in the order they arrived. A table can be scanned, and
sorted — by size to find what returned the most data, by status to find what was
served rather than refused. Those are the two questions a blue team asks of an
episode, and neither could be answered before without reading every line.

What each cell says is decided in `gui.evidence_view`, which has no Qt in it and
is tested without a display. This file only draws.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, QObject, QPoint, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QKeyEvent, QMouseEvent, QPalette
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QLabel,
    QMenu,
    QPushButton,
    QStyle,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import SORT_KEY, SortableItem, required
from logarc.gui.columns import SHORT_TEXT, ColumnWidths, ShortWhenNarrow
from logarc.gui.disclosure import Disclosure
from logarc.gui.evidence_details import EvidenceDetails
from logarc.gui.evidence_view import (
    ARROW_CLOSED,
    COLUMNS,
    Cell,
    Detail,
    Filtered,
    cells_for,
    detail_for,
    filter_strip,
    fold_cells,
    member_cells,
    no_results,
)
from logarc.gui.filter_box import FilterBox
from logarc.gui.folding import Fold, FoldRule, fold
from logarc.gui.ribbon import Mark, ribbon_icon, ribbon_tip
from logarc.gui.splitter import PanelSplitter
from logarc.gui.theme import FLOOR, PAD, TIGHT, caption_font, mono_font
from logarc.search import Scope
from logarc.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    PAPER,
    PAPER_EDGE,
    PAPER_STRIPE,
    SELECTION_TINT,
    THEME,
    format_requests,
    plural,
    severity_text_colour,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from logarc.core.evidence import EvidenceRef
    from logarc.core.graph import GraphNode
    from logarc.evidence import EvidenceLine

__all__ = ["EvidencePanel"]

#: The two columns whose values are numbers, and the one of them that is often
#: absent. Right-aligned so their digits line up under a heading wider than any
#: of them.
_STATUS = COLUMNS.index("Status")
_SIZE = COLUMNS.index("Size")
_LINE = COLUMNS.index("Line")


#: A short field hint; filter examples are available in its tooltip and suggestions.
EVIDENCE_HINT = "Filter these lines\u2026"


class EvidencePanel(QWidget):
    """What the selected activity is made of, one row per request."""

    filter_changed = pyqtSignal(str)
    """The filter text, once the reader stops typing; at once when it is cleared."""

    bookmark_requested = pyqtSignal()
    """The activity on show asked to be bookmarked, from the button under its heading."""

    bookmark_line_requested = pyqtSignal(object)
    """A line asked to be bookmarked, from its right-click menu; carries the `EvidenceLine`."""

    #: How long typing must rest before the filter is applied.
    FILTER_DELAY_MS = 150

    def __init__(self) -> None:
        super().__init__()
        self._decode = True
        self._shown: tuple[GraphNode, Sequence[EvidenceLine], Filtered | None] | None = None
        # Which lines carry a bookmark, kept so every refill can mark them again.
        self._marks: dict[EvidenceRef, Mark] = {}
        # Folding repeated lines (`gui.folding`). Off until the window applies the
        # reader's rule: a panel on its own shows every line, as it always has.
        self._fold_rule = FoldRule.OFF
        self._visits: dict[EvidenceRef, str] = {}
        self._folds: tuple[Fold, ...] = ()
        self._open: set[int] = set()
        # Folds follow log order, so they are drawn only while the table is sorted
        # by Line ascending, the order it opens in.
        self._in_log_order = True
        # Each drawn row: its fold's position, and the line it shows. Position -1
        # while every line is drawn on its own.
        self._rows: list[tuple[int, int]] = []
        self._filling = False
        # The lines of an open fold sit on a ground between the paper and the
        # selection, taken from the theme rather than a literal.
        self._fold_ground = _between(PAPER, SELECTION_TINT)

        # Above the table, the filter: every line of the activity it reads, not
        # only the ones loaded. What matches is the window's to work out; this
        # only takes the words in and says what came of them.
        self.filter_box = FilterBox(
            scope=Scope.EVIDENCE, placeholder=EVIDENCE_HINT, accessible_name="Filter these lines"
        )
        self.filter_box.setToolTip("Filter by text, status:404, path:/admin, or other log fields")
        self.filter_box.textChanged.connect(lambda _: self._rest.start())
        self._rest = QTimer(self)
        self._rest.setSingleShot(True)
        self._rest.setInterval(self.FILTER_DELAY_MS)
        self._rest.timeout.connect(lambda: self.filter_changed.emit(self.filter_box.text()))
        # In place of the line count while a filter is on. A reader who forgot a
        # filter was on and reported its count as the activity's is the mistake
        # this strip is here to stop.
        self.strip = QLabel()
        self.strip.setWordWrap(True)
        self.strip.setTextFormat(Qt.TextFormat.RichText)
        self.strip.setStyleSheet(
            f"background:{THEME.tint}; color:{THEME.ink}; border-left:3px solid {THEME.accent};"
            " padding:4px 8px;"
        )
        self.strip.linkActivated.connect(lambda _: self._clear_filter())
        self.strip.hide()
        # How many rows the lines take, and by which rule. A quiet line of its own:
        # the strip above belongs to the filter, and the heading counts lines.
        self.fold_note = QLabel()
        self.fold_note.setWordWrap(True)
        self.fold_note.setTextFormat(Qt.TextFormat.PlainText)
        self.fold_note.setFont(caption_font(self.fold_note.font()))
        self.fold_note.setStyleSheet(f"color:{THEME.muted};")
        self.fold_note.hide()

        # Empty, not inviting. At startup there is no case, no client and so no
        # activity to select; the canvas is asking for a case and this panel
        # asking for something two steps further on was noise over it.
        self._heading = QLabel("")
        self._heading.setWordWrap(True)
        self._metadata = QLabel()
        self._metadata.setWordWrap(True)
        self._metadata.setTextFormat(Qt.TextFormat.RichText)
        self._metadata.setFont(caption_font(self._metadata.font()))
        self.activity_details = Disclosure("Activity details", self._metadata)
        self.activity_details.hide()

        font = mono_font()

        self._table = _build_table(font)
        # The line number alone while the column is narrow; the file as well
        # once it is widened, or when the lines come from more than one file.
        self._table.setItemDelegateForColumn(_LINE, ShortWhenNarrow(self._table))
        # Size starts hidden: at the default width its 66px left Request 38px.
        # The heading's menu shows it; it is in the details below as well.
        self._column_sizes = ColumnWidths(
            self._table, fill=COLUMNS.index("Request"), optional=(_SIZE,)
        )
        self._column_sizes.wanted_changed.connect(self._show_size)
        # Whether the activity on show has any size to put in that column.
        self._sizes = False
        # The sorted heading gets room for its arrow; the others need none.
        required(self._table.horizontalHeader(), "column header").sortIndicatorChanged.connect(
            self._sort_changed
        )
        self._table.itemSelectionChanged.connect(self._selection_changed)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_menu)
        # A folded row opens on a double-click, Enter, the arrow keys or its arrow.
        self._table.cellDoubleClicked.connect(lambda row, _column: self.toggle_row(row))
        self._table.installEventFilter(self)
        # Under the heading, while there is an activity to keep.
        self.bookmark_button = QPushButton("Bookmark")
        self.bookmark_button.setIcon(ribbon_icon(THEME.accent, hollow=True))
        self.bookmark_button.setToolTip("Bookmark this activity (Ctrl+D)")
        self.bookmark_button.setFlat(True)
        self.bookmark_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.bookmark_button.setStyleSheet(f"color:{THEME.accent}; padding:0 4px;")
        self.bookmark_button.clicked.connect(self.bookmark_requested.emit)
        self.bookmark_button.hide()
        self.no_results = self._build_no_results()
        self._detail = EvidenceDetails(font)

        # Split, so the reader decides how much of each they want: a wide
        # episode wants more table, a long payload more detail.
        split = PanelSplitter(Qt.Orientation.Vertical)
        split.addWidget(self._table)
        split.addWidget(self._detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setChildrenCollapsible(False)
        self._table.setMinimumHeight(80)
        self._detail.setMinimumHeight(70)

        layout = QVBoxLayout(self)
        # As on the client panel: at zero the heading sits against the window
        # edge and loses its first character to the frame.
        layout.setContentsMargins(PAD, TIGHT, PAD, TIGHT)
        layout.setSpacing(PAD)
        layout.addWidget(self._heading)
        layout.addWidget(self.bookmark_button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.activity_details)
        layout.addWidget(self.filter_box)
        layout.addWidget(self.strip)
        layout.addWidget(self.fold_note)
        layout.addWidget(split)

    # -- what is on show -----------------------------------------------------

    def clear(self, *, prompt: bool = True) -> None:
        """Empty the panel, and either invite a selection or say nothing.

        `prompt` is false when there is nothing to select from yet — no case
        open, or a case open and no client picked. The panel used to invite a
        selection regardless, so a freshly opened window said "Open a case" on
        the canvas, "No client selected" above it, and "Select an activity to
        see the lines behind it" here: three instructions, two of them for steps
        the reader cannot take, competing with the one they can.

        The table and the detail stay up either way. Hiding them was tried and
        is wrong: an empty table under its own headings reads as a panel waiting
        for content, while an empty rectangle reads as a panel that failed to
        draw one — and it takes the whole right-hand side of the window with it.
        The headings also say what is coming, which is worth something before
        anything has been chosen.
        """
        self._shown = None
        self._heading.setText("Select an activity." if prompt else "")
        self._metadata.clear()
        self.activity_details.hide()
        self.bookmark_button.hide()
        self._table.setRowCount(0)
        self._detail.clear()
        self.strip.hide()
        self.no_results.hide()
        # The filter itself stays: it is the reader's, and outlives the activity.
        # What it was offering does not: those were the last activity's values.
        self.set_suggestion_values({})

    def set_decode(self, decode: bool) -> None:
        """Show targets decoded, or exactly as the log holds them."""
        if decode != self._decode:
            self._decode = decode
            if self._shown is not None:
                node, lines, filtered = self._shown
                self.show_evidence(node, lines, filtered=filtered, visits=self._visits)

    def show_evidence(
        self,
        node: GraphNode,
        lines: Sequence[EvidenceLine],
        *,
        filtered: Filtered | None = None,
        visits: Mapping[EvidenceRef, str] | None = None,
    ) -> None:
        """Describe one activity on the canvas, and list what it is made of.

        `filtered` says the lines are what a filter kept, and how many of the
        activity's it searched. The heading still describes the whole activity.
        `visits` names each line's episode, so a fold never joins two visits.

        The node, not an episode of it. The rows below have always come from
        `node.evidence`, while this heading was built from the first episode the
        node happened to name — which on the behaviour map, where a node is
        every visit to one activity, meant a 35-request circle captioned with
        the 12 of its first burst, above evidence drawn from all 35. A summary
        that understates the evidence beneath it is worse than no summary, and
        this panel is what gets read into a case file.
        """
        self._shown = (node, lines, filtered)
        self._visits = dict(visits or {})
        colour = severity_text_colour(node.severity)
        # A behaviour node is several visits to one activity; a trace node is
        # always one, and saying "across 1 activities" on every node of the view
        # that opens by default would be noise.
        across = f" across {node.episode_count:,} activities" if node.episode_count > 1 else ""
        # An episode keeps a bounded sample of its references and the true count
        # beside it, so the table below is often a part of the activity rather
        # than all of it. Unsaid, twenty rows under a heading reading 51 requests
        # leaves the reader to decide whether lines are missing or the count is
        # wrong — and it is neither.
        #
        # Said every time, including `3 of 3`. Printed only on a shortfall, its
        # absence would itself be a claim — that the table is complete — and one
        # the reader has to know how to read. Always present, it is a fact about
        # the table rather than a warning about it, and a complete list is
        # confirmed rather than merely unremarked.
        shown = f"{len(lines):,} of {node.evidence_total:,}"
        # `1 of 1 lines` is the fault `format_requests` exists to stop, one noun
        # along. The noun agrees with the total, which is what it counts.
        noun = "line" if node.evidence_total == 1 else "lines"

        # Three weights, not six identical lines. Every fact used to be set at
        # the same size as every other, so the activity's name — the one thing
        # that says what you are looking at — carried no more emphasis than the
        # rule id that matched it, and the block had to be read start to finish
        # to find anything in it.
        #
        # The labels stay. `Outcome: blocked` reads as a labelled fact and not
        # as a loose word, which is what stopped the outcome being buried in a
        # sentence in the first place; a chip that dropped the label would have
        # undone that to gain a few pixels.
        chips = []
        chips.append(_chip(node.severity.name.title(), colour))
        # The value stays as the taxonomy spells it. Title case here would have
        # the panel reading `Blocked` beside a canvas caption reading `blocked`
        # for the same activity — one name for one thing, in one case.
        chips.append(_chip(f"Outcome: {node.outcome.value}"))
        metadata = [
            f'<span style="color:{THEME.timestamp}">'
            f"Time (UTC): {node.start:%Y-%m-%d %H:%M:%S} → {node.end:%Y-%m-%d %H:%M:%S}</span>",
            f"Matched by: {html.escape(', '.join(node.rule_ids))}",
        ]
        if node.owasp:
            metadata.append(f"OWASP: {html.escape(node.owasp)}")
        self._metadata.setText(
            f'<span style="color:{EVIDENCE_MUTED}">' + "<br>".join(metadata) + "</span>"
        )
        self.activity_details.show()
        self.bookmark_button.show()

        base = self._heading.font().pointSizeF()
        self._heading.setText(
            f'<div style="font-size:{base + 3.0:.1f}pt;color:{colour}">'
            f"<b>{html.escape(node.label)}</b></div>"
            f'<div style="color:{EVIDENCE_MUTED}">'
            f"{format_requests(node.request_count)}{across}</div>"
            f'<div style="font-size:{max(base - 1.0, FLOOR):.1f}pt">{" ".join(chips)}</div>'
            + (
                f'<div style="font-size:{max(base - 1.0, FLOOR):.1f}pt;color:{THEME.faint}">'
                f"Showing {shown} {noun}</div>"
                if filtered is None
                else ""
            )
        )
        self._say_filtered(filtered, shown=len(lines))

        self._folds = self._fold(lines)
        self._open = set()
        self._in_log_order = True
        self._fill(fit=True)

        if lines:
            self.select_row(0)
            # Then read that selection back into the detail, rather than waiting
            # to be told about it.
            #
            # `selectRow` only emits `itemSelectionChanged` when the selection
            # actually changes, and row 0 of the activity being left is row 0 of
            # the activity being opened — so on a panel that already had a row
            # selected, Qt saw no change, said nothing, and the detail went on
            # describing the previous activity underneath the new one's rows.
            #
            # Worst where it was found: a one-request activity has no second row
            # to click, so nothing could correct it and the pane simply showed
            # the wrong request for as long as it was open.
            self._selection_changed()
        else:
            self._detail.clear()

    # -- folding repeated lines ----------------------------------------------

    def set_fold_rule(self, rule: FoldRule) -> None:
        """Fold by `rule` from now on, and fold what is on show again, every row closed."""
        if rule is self._fold_rule:
            return
        self._fold_rule = rule
        if self._shown is not None:
            self._folds = self._fold(self._shown[1])
            self._open = set()
            self._refill_keeping(None)

    def _fold(self, lines: Sequence[EvidenceLine]) -> tuple[Fold, ...]:
        visits = self._visits
        return fold(lines, self._fold_rule, visits.get if visits else None)

    @property
    def _folded(self) -> bool:
        """Whether the rows are drawn folded now: a rule, and the table in log order."""
        return self._fold_rule is not FoldRule.OFF and self._in_log_order

    def _fill(self, *, fit: bool) -> None:
        """Draw the rows: folds and open lines in log order, or every line as it sorts.

        Sorting is off while filling: with it on, each row is re-sorted against
        the rows already placed and the remaining values land in other rows.
        Untouched widths are fitted once, when `fit` says this is a new activity,
        so opening a row does not make the columns jump. Line is the exception,
        and only grows: an opened row's lines are indented past the arrow it was
        fitted to, and their numbers were cut short.
        """
        assert self._shown is not None
        lines = self._shown[1]
        # The number alone stands for the line only while one file is behind them.
        one_file = len({line.ref.source_file_id for line in lines}) <= 1
        drawn: list[tuple[Cell, ...]] = []
        self._rows = []
        folded = self._folded
        if folded:
            for position, run in enumerate(self._folds):
                opened = position in self._open and len(run) > 1
                drawn.append(fold_cells(lines, run, decode=self._decode, opened=opened))
                self._rows.append((position, run.head))
                for index in run.members[1:] if opened else ():
                    drawn.append(member_cells(lines[index], decode=self._decode))
                    self._rows.append((position, index))
        else:
            for index, line in enumerate(lines):
                drawn.append(cells_for(line, decode=self._decode))
                self._rows.append((-1, index))
        header = required(self._table.horizontalHeader(), "column header")
        section, order = header.sortIndicatorSection(), header.sortIndicatorOrder()
        self._filling = True
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(drawn))
        for row, cells in enumerate(drawn):
            position, index = self._rows[row]
            member = position >= 0 and index != self._folds[position].head
            for column, cell in enumerate(cells):
                item = _item(cell, index=index, column=column, short=one_file)
                if folded and column == _LINE:
                    # Drawn in log order; the Line sort keeps the drawn order.
                    item.setData(SORT_KEY, float(row))
                    if not member and len(self._folds[position]) > 1:
                        item.setData(_FOLD_TIP, cell.tooltip)
                if member:
                    item.setBackground(self._fold_ground)
                self._table.setItem(row, column, item)
        self._apply_marks()
        # A column costs its heading's width whatever it holds, and several log
        # formats carry no response size at all. Read from the lines rather than
        # the drawn rows: a closed fold still holds its sizes.
        self._sizes = any(
            line.event is not None and line.event.bytes_sent is not None for line in lines
        )
        self._show_size(fit=False)
        # Measured with sorting still off. With it on, Qt sizes every heading for
        # a sort arrow only one of them draws, and the room comes out of Request.
        if fit:
            self._column_sizes.fit_unset()
        else:
            self._column_sizes.widen(_LINE)
        self._table.setSortingEnabled(True)
        # A new activity opens in the order the log holds, not in whatever order
        # the widget last happened to be sorted by: evidence is a sequence of
        # events, and sorting by size or status is a question asked afterwards.
        if folded or fit:
            self._table.sortItems(_LINE, Qt.SortOrder.AscendingOrder)
        else:
            self._table.sortItems(section, order)
        self._filling = False
        if fit:
            self._column_sizes.fit_heading(_LINE)
        self._say_folded()

    def toggle_row(self, row: int) -> None:
        """Open or close the folded row at `row`; nothing for any other row."""
        if not self._folded or not 0 <= row < len(self._rows):
            return
        position, index = self._rows[row]
        # A line inside an open row is just a line: a tree does not close when
        # one of its leaves is double-clicked.
        if len(self._folds[position]) < 2 or index != self._folds[position].head:
            return
        self._open ^= {position}
        self._refill_keeping(self._folds[position].head)

    def _refill_keeping(self, line_index: int | None) -> None:
        """Draw again, then select the row of `line_index`, or the first row."""
        if self._shown is None:
            return
        self._fill(fit=False)
        rows = [row for row, (_position, index) in enumerate(self._rows) if index == line_index]
        if self._rows:
            self.select_row(rows[0] if rows else 0)
            # Read back at once: `selectRow` says nothing when the row number is
            # the one already selected, and the detail would describe the old row.
            self._selection_changed()
        else:
            self._detail.clear()

    def _say_folded(self) -> None:
        lines = len(self._shown[1]) if self._shown is not None else 0
        repeats = any(len(run) > 1 for run in self._folds)
        if self._fold_rule is FoldRule.OFF or not repeats:
            self.fold_note.hide()
            return
        if self._folded:
            said = (
                f"{plural(lines, 'line')} in {plural(len(self._folds), 'row')} · lines "
                f"next to each other with the same {self._fold_rule.says} share a row"
            )
        else:
            header = required(self._table.horizontalHeader(), "column header")
            heading = COLUMNS[header.sortIndicatorSection()]
            said = f"Sorted by {heading}: every line on its own row. Sort by Line to fold repeats."
        self.fold_note.setText(_no_widow(said))
        self.fold_note.show()

    def _key(self, event: QKeyEvent) -> bool:
        """Enter or the right arrow opens the selected fold; the left arrow closes it."""
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        if not rows or not self._folded:
            return False
        row = rows[0].row()
        position, index = self._rows[row]
        run = self._folds[position]
        head = index == run.head and len(run) > 1
        opened = position in self._open
        key = event.key()
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and head:
            self.toggle_row(row)
            return True
        if key == Qt.Key.Key_Right and head and not opened:
            self.toggle_row(row)
            return True
        if key == Qt.Key.Key_Left and opened:
            self._open.discard(position)
            self._refill_keeping(run.head)
            return True
        return False

    def _arrow_clicked(self, event: QMouseEvent) -> bool:
        """A click on a folded row's arrow opens or closes it; elsewhere it selects."""
        index = self._table.indexAt(event.position().toPoint())
        if not index.isValid() or index.column() != _LINE or not self._folded:
            return False
        position, line_index = self._rows[index.row()]
        run = self._folds[position]
        if line_index != run.head or len(run) < 2:
            return False
        # From where Qt draws the text, which a bookmark's ribbon pushes right:
        # its own text margin, then the arrow and its space, measured from the
        # cell's font rather than counted in pixels.
        option = QStyleOptionViewItem()
        self._table.initViewItemOption(option)
        option.rect = self._table.visualRect(index)
        delegate = self._table.itemDelegateForColumn(_LINE)
        assert isinstance(delegate, ShortWhenNarrow)
        delegate.initStyleOption(option, index)
        style = required(self._table.style(), "style")
        text = style.subElementRect(QStyle.SubElement.SE_ItemViewItemText, option, self._table)
        margin = style.pixelMetric(QStyle.PixelMetric.PM_FocusFrameHMargin, None, self._table) + 1
        reach = margin + option.fontMetrics.horizontalAdvance(ARROW_CLOSED + " ")
        if not 0 <= event.position().x() - text.left() <= reach:
            return False
        self.toggle_row(index.row())
        return True

    # -- the filter ------------------------------------------------------------

    def filter_text(self) -> str:
        return self.filter_box.text()

    def set_filter_text(self, text: str) -> None:
        """Put `text` in the box without reporting it: whoever set it draws next."""
        self.filter_box.setText(text)
        self._rest.stop()

    def set_suggestion_values(self, values: Mapping[str, Sequence[tuple[str, str]]]) -> None:
        """The values the activity on show holds, for the box's list."""
        self.filter_box.set_values(values, "VALUES IN THIS ACTIVITY")

    def _clear_filter(self) -> None:
        """Clear, as a decision rather than as typing: heard at once."""
        self.set_filter_text("")
        self.filter_changed.emit("")

    def _say_filtered(self, filtered: Filtered | None, *, shown: int) -> None:
        if filtered is None:
            self.strip.hide()
            self.no_results.hide()
            return
        empty = filtered.matched == 0
        clear = (
            ""
            if empty
            else f' &nbsp;<a href="clear" style="color:{THEME.accent}">Clear&nbsp;filter</a>'
        )
        self.strip.setText(html.escape(filter_strip(filtered, shown=shown)) + clear)
        self.strip.show()
        self._no_results_detail.setText(no_results(filtered))
        self.no_results.setGeometry(required(self._table.viewport(), "viewport").rect())
        self.no_results.setVisible(empty)

    def _build_no_results(self) -> QWidget:
        """What the table says when a filter leaves nothing in it.

        An empty table under its headings reads as a panel that failed to fill.
        This says what was searched for and offers the way back.
        """
        port = required(self._table.viewport(), "viewport")
        holder = QWidget(port)
        title = QLabel("No results found")
        title.setTextFormat(Qt.TextFormat.PlainText)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"color:{EVIDENCE_INK}; font-size:13pt; font-weight:600;")
        self._no_results_detail = QLabel()
        self._no_results_detail.setTextFormat(Qt.TextFormat.PlainText)
        self._no_results_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._no_results_detail.setWordWrap(True)
        self._no_results_detail.setStyleSheet(f"color:{EVIDENCE_MUTED};")
        button = QPushButton("Clear filter")
        button.clicked.connect(self._clear_filter)
        layout = QVBoxLayout(holder)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(PAD)
        layout.addWidget(title)
        layout.addWidget(self._no_results_detail)
        layout.addWidget(button, 0, Qt.AlignmentFlag.AlignCenter)
        holder.hide()
        port.installEventFilter(self)
        return holder

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        """Keep the message the size of the table it stands in for."""
        # Looked up, not assumed: the collector can let go of `_table` while Qt
        # is still delivering its viewport's last events, and an exception raised
        # in here is one PyQt answers by ending the process.
        if "_table" not in vars(self):
            return False
        port = self._table.viewport()
        if watched is port and event is not None and event.type() == QEvent.Type.Resize:
            self.no_results.setGeometry(required(port, "viewport").rect())
        if event is not None and self._shown is not None:
            if watched is self._table and event.type() == QEvent.Type.KeyPress:
                return self._key(event)  # type: ignore[arg-type]
            if watched is port and event.type() == QEvent.Type.MouseButtonPress:
                return self._arrow_clicked(event)  # type: ignore[arg-type]
        return False

    def select_row(self, row: int) -> None:
        """Select a table row and show its evidence in full."""
        self._table.selectRow(row)

    # -- bookmarks -------------------------------------------------------------

    def set_marks(self, marks: Mapping[EvidenceRef, Mark]) -> None:
        """Ribbon the lines in `marks`, and keep doing so through every refill."""
        self._marks = dict(marks)
        self._apply_marks()
        self._column_sizes.fit_unset()

    def _apply_marks(self) -> None:
        lines = self._shown[1] if self._shown is not None else ()
        for row in range(self._table.rowCount()):
            marker = self._table.item(row, 0)
            index = marker.data(_INDEX) if marker is not None else None
            if marker is None or not isinstance(index, int) or not 0 <= index < len(lines):
                continue
            # A closed fold answers for every line it stands for: a bookmark on
            # its third line is still a bookmark on what this row shows.
            closed = self._closed_fold_at(row)
            covered = [lines[i] for i in closed.members] if closed else [lines[index]]
            marks = [(line, self._marks[line.ref]) for line in covered if line.ref in self._marks]
            marker.setIcon(ribbon_icon(marks[0][1][0]) if marks else QIcon())
            if closed is not None and marks:
                said = "\n".join(f"line {line.ref.line_no}: {mark[1]}" for line, mark in marks)
                marker.setToolTip(ribbon_tip(said))
            elif closed is not None:
                marker.setToolTip(ribbon_tip(str(marker.data(_FOLD_TIP) or "")))
            elif marks:
                marker.setToolTip(ribbon_tip(marks[0][1][1]))
            else:
                # A bookmark's note, or else the whole reference a narrow column cuts.
                whole = ribbon_tip(marker.text()) if marker.data(SHORT_TEXT) else ""
                marker.setToolTip(whole)

    def _closed_fold_at(self, row: int) -> Fold | None:
        """The fold a closed head row stands for; None for any other row."""
        if not self._folded or not 0 <= row < len(self._rows):
            return None
        position, index = self._rows[row]
        run = self._folds[position]
        if len(run) < 2 or index != run.head or position in self._open:
            return None
        return run

    def _show_size(self, *, fit: bool = True) -> None:
        """Size, while the reader has asked for it and the activity has sizes."""
        wanted = self._sizes and self._column_sizes.wanted(_SIZE)
        self._table.setColumnHidden(_SIZE, not wanted)
        if fit:
            self._column_sizes.fit_unset()

    def _sort_changed(self, section: int, order: Qt.SortOrder) -> None:
        self._column_sizes.fit_heading(section)
        # Folds follow log order. Sorted by anything else every line is drawn on
        # its own; sorted by Line ascending again they fold back, closed.
        if self._filling or self._shown is None or self._fold_rule is FoldRule.OFF:
            return
        in_log_order = section == _LINE and order == Qt.SortOrder.AscendingOrder
        if in_log_order != self._in_log_order:
            self._in_log_order = in_log_order
            self._open = set()
            self._refill_keeping(None)

    def shown_node(self) -> GraphNode | None:
        return self._shown[0] if self._shown is not None else None

    def _line_at(self, row: int) -> EvidenceLine | None:
        marker = self._table.item(row, 0)
        index = marker.data(_INDEX) if marker is not None else None
        if self._shown is None or not isinstance(index, int):
            return None
        lines = self._shown[1]
        return lines[index] if 0 <= index < len(lines) else None

    def selected_line(self) -> EvidenceLine | None:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        return self._line_at(rows[0].row()) if rows else None

    def select_line(self, ref: EvidenceRef) -> bool:
        """Select the row holding `ref`, opening its fold; False when it is not on show."""
        if self._shown is None:
            return False
        found = next((i for i, line in enumerate(self._shown[1]) if line.ref == ref), None)
        if found is None:
            return False
        if self._folded:
            position = next(p for p, run in enumerate(self._folds) if found in run.members)
            if found != self._folds[position].head and position not in self._open:
                self._open.add(position)
                self._refill_keeping(found)
                return True
        for row in range(self._table.rowCount()):
            line = self._line_at(row)
            if line is not None and line.ref == ref:
                self.select_row(row)
                return True
        return False

    def _menu_at(self, point: QPoint) -> QMenu | None:
        """The menu a right-click at `point` opens, or None off the rows."""
        index = self._table.indexAt(point)
        line = self._line_at(index.row()) if index.isValid() else None
        if line is None:
            return None
        menu = QMenu(self)
        # A closed fold stands for several lines; say which one this bookmarks.
        wording = (
            f"Bookmark line {line.ref.line_no}\u2026"
            if self._closed_fold_at(index.row()) is not None
            else "Bookmark this line\u2026"
        )
        menu.addAction(wording, lambda: self.bookmark_line_requested.emit(line))
        return menu

    def _show_menu(self, point: QPoint) -> None:
        menu = self._menu_at(point)
        if menu is not None:
            menu.popup(required(self._table.viewport(), "viewport").mapToGlobal(point))

    # -- the detail ----------------------------------------------------------

    def _selection_changed(self) -> None:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        if not rows or self._shown is None:
            self._detail.clear()
            return
        marker = self._table.item(rows[0].row(), 0)
        if marker is None:  # pragma: no cover - a selected row always has one
            return
        # Where this row sits in the evidence, read back from the item rather
        # than from its position: sorting moves rows, and a detail that
        # described a different request from the highlighted one would be worse
        # than showing nothing at all.
        index = marker.data(_INDEX)
        _episode, lines, _filtered = self._shown
        # The index came from this panel, over the lines it is still holding, so
        # it cannot be out of step with them while the two are in step.
        if not isinstance(index, int) or not 0 <= index < len(lines):  # pragma: no cover - guarded
            return
        self._show_detail(detail_for(lines[index], decode=self._decode))

    def _show_detail(self, detail: Detail) -> None:
        self._detail.show_detail(detail)


def _build_table(font: QFont) -> QTableWidget:
    table = QTableWidget(0, len(COLUMNS))
    table.setHorizontalHeaderLabels(list(COLUMNS))
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSortingEnabled(True)
    table.setAlternatingRowColors(True)
    # The stripe already carries the row across the panel; a grid on top of it
    # boxes every cell and turns evidence into a spreadsheet. One or the other.
    table.setShowGrid(False)
    table.setFont(font)
    required(table.verticalHeader(), "row header").setVisible(False)
    # Pinned light for the same reason the detail below it is: the cell colours
    # are chosen against a pale ground, and on a machine themed dark a muted
    # grey lands on dark grey. Evidence nobody can read is the one failure this
    # panel cannot have, and it would not look like a fault.
    paper = table.palette()
    paper.setColor(QPalette.ColorRole.Base, QColor(PAPER))
    paper.setColor(QPalette.ColorRole.AlternateBase, QColor(PAPER_STRIPE))
    paper.setColor(QPalette.ColorRole.Text, QColor(EVIDENCE_INK))
    # The selected row, pinned for the same reason as the rest. Left to the
    # system it was dark teal, and every cell in this table carries its own
    # colour — chosen against pale paper — so the status on the selected row came
    # out grey on teal at 2.25:1. `HighlightedText` cannot rescue it: an item's
    # own foreground wins over the palette's.
    paper.setColor(QPalette.ColorRole.Highlight, QColor(SELECTION_TINT))
    paper.setColor(QPalette.ColorRole.HighlightedText, QColor(EVIDENCE_INK))
    table.setPalette(paper)
    # Framed for the same reason the canvas is: the ground is pinned light
    # whatever the machine is themed, and an unframed sheet of it against dark
    # chrome reads as a hole rather than as a document. Border only — the ground
    # and the ink stay on the palette above, where the theme tests read them.
    table.setStyleSheet(f"QTableWidget {{ border: 1px solid {PAPER_EDGE}; }}")

    header = required(table.horizontalHeader(), "column header")
    # The headings come off the monospace font the evidence itself is set in,
    # and `Status` and `Size` in Consolas are wider than any value they ever
    # hold — width taken from `Request`, where a payload was wrapping to two
    # lines. Headings are not evidence, so they need not be monospace — and
    # being structure rather than content, they are set a step quieter than the
    # rows they label rather than competing with them.
    header.setFont(caption_font(QFont()))
    return table


def _chip(text: str, colour: str | None = None) -> str:
    """One fact, drawn as a bounded thing rather than another line of prose.

    A filled span rather than a bordered one: Qt's rich text honours
    `background-color` on an inline element and ignores `padding` and `border`
    there, so the box is made of the fill and the spaces are made of `&nbsp;`.
    Cheaper than laying out real widgets, and it keeps the whole heading a
    single `QLabel` — which is what the panel's tests read, and what makes the
    heading one thing to clear rather than four.
    """
    tinted = f";color:{colour}" if colour else f";color:{EVIDENCE_MUTED}"
    return f'<span style="background-color:{THEME.raised}{tinted}">&nbsp;{text}&nbsp;</span>'


#: Where a row keeps its place in the evidence, so sorting cannot move it.
_INDEX = Qt.ItemDataRole.UserRole

#: A folded row's own tooltip, naming its lines, kept beside the bookmark one.
_FOLD_TIP = Qt.ItemDataRole.UserRole + 3


def _item(cell: Cell, *, index: int, column: int, short: bool) -> QTableWidgetItem:
    item = SortableItem(cell.text)
    if short and cell.short:
        item.setData(SHORT_TEXT, cell.short)
    if cell.sort_key is not None:
        item.setData(SORT_KEY, cell.sort_key)
    item.setForeground(QColor(cell.colour))
    if column in {_STATUS, _SIZE}:
        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    if cell.bold:
        font = item.font()
        font.setBold(True)
        item.setFont(font)
    if cell.italic:
        font = item.font()
        font.setItalic(True)
        item.setFont(font)
    if cell.tooltip:
        # Escaped and wrapped so Qt cannot read it as markup. A tooltip is rich
        # text whenever it looks like it, and this text came out of a request:
        # `<img src=x onerror=…>` in a path would otherwise be rendered inside
        # the panel the case is read from rather than shown as what it is.
        item.setToolTip(f"<span style='white-space:pre-wrap'>{html.escape(cell.tooltip)}</span>")
    # Kept where sorting cannot move it, so a selection still finds the line it
    # belongs to after the table has been re-ordered.
    item.setData(_INDEX, index)
    return item


def _no_widow(text: str) -> str:
    """`text` with its last two words joined by a no-break space.

    A wrapped note whose last line is one word reads as cut off: the fold note
    left `row` alone at some panel widths.
    """
    head, space, tail = text.rpartition(" ")
    return f"{head}\u00a0{tail}" if space else text


def _between(one: str, other: str) -> QColor:
    """The colour halfway between two, for a ground that sits between them."""
    a, b = QColor(one), QColor(other)
    return QColor(
        (a.red() + b.red()) // 2, (a.green() + b.green()) // 2, (a.blue() + b.blue()) // 2
    )
