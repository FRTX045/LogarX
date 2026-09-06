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

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPalette, QTextCursor, QTextOption
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import SORT_KEY, SortableItem, required
from logarc.gui.evidence_view import ALERT_COLOUR, COLUMNS, Cell, Detail, cells_for, detail_for
from logarc.gui.theme import PAD, TIGHT, caption_font, mono_font
from logarc.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    PAPER,
    PAPER_EDGE,
    PAPER_STRIPE,
    SELECTION_TINT,
    THEME,
    format_requests,
    severity_colour,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.graph import GraphNode
    from logarc.evidence import EvidenceLine

__all__ = ["EvidencePanel"]

#: The two columns whose values are numbers, and the one of them that is often
#: absent. Right-aligned so their digits line up under a heading wider than any
#: of them.
_STATUS = COLUMNS.index("Status")
_SIZE = COLUMNS.index("Size")


class EvidencePanel(QWidget):
    """What the selected activity is made of, one row per request."""

    def __init__(self) -> None:
        super().__init__()
        self._decode = True
        self._shown: tuple[GraphNode, Sequence[EvidenceLine]] | None = None

        # Empty, not inviting. At startup there is no case, no client and so no
        # activity to select; the canvas is asking for a case and this panel
        # asking for something two steps further on was noise over it.
        self._heading = QLabel("")
        self._heading.setWordWrap(True)

        font = mono_font(8.5)

        self._table = _build_table(font)
        self._table.itemSelectionChanged.connect(self._selection_changed)
        self._detail = _build_detail(font)

        # Split, so the reader decides how much of each they want: a wide
        # episode wants more table, a long payload more detail.
        split = QSplitter(Qt.Orientation.Vertical)
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
        self._heading.setText("Select an activity to see the lines behind it." if prompt else "")
        self._table.setRowCount(0)
        self._detail.clear()

    def set_decode(self, decode: bool) -> None:
        """Show targets decoded, or exactly as the log holds them."""
        if decode != self._decode:
            self._decode = decode
            if self._shown is not None:
                self.show_evidence(*self._shown)

    def show_evidence(self, node: GraphNode, lines: Sequence[EvidenceLine]) -> None:
        """Describe one activity on the canvas, and list what it is made of.

        The node, not an episode of it. The rows below have always come from
        `node.evidence`, while this heading was built from the first episode the
        node happened to name — which on the behaviour map, where a node is
        every visit to one activity, meant a 35-request circle captioned with
        the 12 of its first burst, above evidence drawn from all 35. A summary
        that understates the evidence beneath it is worse than no summary, and
        this panel is what gets read into a case file.
        """
        self._shown = (node, lines)
        colour = severity_colour(node.severity)
        # A behaviour node is several visits to one activity; a trace node is
        # always one, and saying "across 1 activities" on every node of the view
        # that opens by default would be noise.
        visits = f" across {node.episode_count:,} activities" if node.episode_count > 1 else ""
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
        if node.owasp:
            chips.append(_chip(f"OWASP: {html.escape(node.owasp)}"))
        chips.append(_chip(f"Matched by: {html.escape(', '.join(node.rule_ids))}"))

        base = self._heading.font().pointSizeF()
        self._heading.setText(
            f'<div style="font-size:{base + 3.0:.1f}pt;color:{colour}">'
            f"<b>{html.escape(node.label)}</b></div>"
            f'<div style="color:{EVIDENCE_MUTED}">'
            f"{format_requests(node.request_count)}{visits} · "
            f"{node.start:%Y-%m-%d %H:%M:%S} → {node.end:%H:%M:%S}</div>"
            f'<div style="font-size:{max(base - 1.0, 7.5):.1f}pt">{" ".join(chips)}</div>'
            f'<div style="font-size:{max(base - 1.0, 7.5):.1f}pt;color:{THEME.faint}">'
            f"Showing {shown} {noun}</div>"
        )

        # Sorting off while filling. With it on, each row is re-sorted against
        # the rows already placed and the remaining values land in other rows.
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(lines))
        sizes = False
        for row, line in enumerate(lines):
            for column, cell in enumerate(cells_for(line, decode=self._decode)):
                self._table.setItem(row, column, _item(cell, index=row, column=column))
                sizes = sizes or (column == _SIZE and bool(cell.text))
        self._table.setSortingEnabled(True)
        # A column costs its heading's width whatever it holds, and several log
        # formats carry no response size at all. Empty on every row it was taking
        # that width from `Request`, which is where the payload goes. Hidden only
        # while there is nothing in it — one size anywhere brings it back.
        self._table.setColumnHidden(_SIZE, not sizes)
        # Opened in the order the log holds, not in whatever order the widget
        # last happened to be sorted by. Evidence is a sequence of events and
        # the first thing a reader wants is the sequence; sorting by size or
        # status is a question they ask afterwards.
        self._table.sortItems(COLUMNS.index("Source"), Qt.SortOrder.AscendingOrder)

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

    def select_row(self, row: int) -> None:
        """Select a table row and show its evidence in full."""
        self._table.selectRow(row)

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
        _episode, lines = self._shown
        # The index came from this panel, over the lines it is still holding, so
        # it cannot be out of step with them while the two are in step.
        if not isinstance(index, int) or not 0 <= index < len(lines):  # pragma: no cover - guarded
            return
        self._show_detail(detail_for(lines[index], decode=self._decode))

    def _show_detail(self, detail: Detail) -> None:
        self._detail.clear()
        self._write(detail.source, EVIDENCE_MUTED, bold=True)
        for label, value, colour in detail.fields:
            self._write(f"{label:<4} {value}" if label else value, colour)
        if detail.note:
            self._write(f"! {detail.note}", ALERT_COLOUR)
        if detail.raw is not None:
            self._write("")
            self._write("as logged", EVIDENCE_MUTED)
            self._write(detail.raw, EVIDENCE_INK)
        self._detail.moveCursor(QTextCursor.MoveOperation.Start)
        self._detail.ensureCursorVisible()

    def _write(self, text: str, colour: str = EVIDENCE_INK, *, bold: bool = False) -> None:
        self._detail.setTextColor(QColor(colour))
        self._detail.setFontWeight(QFont.Weight.Bold if bold else QFont.Weight.Normal)
        self._detail.append(text)


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
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    # `Target` takes whatever is left over. It is the only column whose content
    # is unbounded, and the only one worth widening the panel for.
    header.setSectionResizeMode(COLUMNS.index("Request"), QHeaderView.ResizeMode.Stretch)
    return table


def _build_detail(font: QFont) -> QTextEdit:
    detail = QTextEdit()
    detail.setReadOnly(True)
    detail.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
    # Break mid-token where there is nothing to break at: a 59-character
    # injection payload is one unbroken word, and wrapping politely would send
    # exactly the line worth reading off the edge.
    detail.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
    detail.setFont(font)
    # Pinned light, not inherited. The colours written here are chosen against a
    # pale ground, so on a machine themed dark an inherited background renders
    # the evidence dark on dark — illegible evidence is the one failure this
    # panel cannot have, and it would not look like a fault. Set on the palette
    # rather than through a stylesheet so it stays inspectable: a stylesheet
    # leaves `palette()` reporting the inherited colour, which would make a test
    # of this pass while the panel is unreadable.
    paper = detail.palette()
    paper.setColor(QPalette.ColorRole.Base, QColor(PAPER))
    paper.setColor(QPalette.ColorRole.Text, QColor(EVIDENCE_INK))
    detail.setPalette(paper)
    detail.setStyleSheet(f"QTextEdit {{ border: 1px solid {PAPER_EDGE}; }}")
    return detail


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


def _item(cell: Cell, *, index: int, column: int) -> QTableWidgetItem:
    item = SortableItem(cell.text)
    if cell.sort_key is not None:
        item.setData(SORT_KEY, cell.sort_key)
    item.setForeground(QColor(cell.colour))
    if column in {_STATUS, _SIZE}:
        item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    if cell.bold:
        font = item.font()
        font.setBold(True)
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
