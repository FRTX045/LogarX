"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import (
    QColor,
    QFont,
    QPalette,
    QTextBlockFormat,
    QTextCharFormat,
    QTextCursor,
    QTextOption,
)
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QLayout,
    QLayoutItem,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import required
from logarc.gui.style import (
    EVIDENCE_INK,
    EVIDENCE_MUTED,
    SIZE_NOTE,
    decode_target,
    format_bytes,
    format_requests,
    highlight_spans,
    outcome_legend,
    severity_colour,
    severity_legend,
    shorten_agent,
    status_colour,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from logarc.core.episode import Episode
    from logarc.core.event import NormalizedEvent
    from logarc.evidence import EvidenceLine
    from logarc.storage.base import IpSummary

__all__ = ["ClientTable", "EvidencePanel", "LegendBar"]

#: Headers kept short because a header wider than its values sets the column
#: width, and six columns of prose did not fit the panel however the values
#: were sized. "Requests" alone was wider than any count it ever holds.
_COLUMNS = ("Client", "Reqs", "Paths", "4xx", "First", "Last")

#: The evidence surface. Matches the canvas ground and the exported report, so
#: the same finding reads the same way on screen and on paper.
_PAPER = "#f5f7fa"
_INK = "#1f2933"


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
        item = QTableWidgetItem(text)
        if sort_key is not None:
            # Sort on the number, not on the formatted text: "1,000" sorts
            # before "9" as a string, which would silently mis-rank the table.
            item.setData(Qt.ItemDataRole.UserRole, sort_key)
            item.setData(Qt.ItemDataRole.EditRole, sort_key)
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

        row = _FlowLayout(spacing=8)
        row.addWidget(self._caption("Severity:"))
        for item in severity_legend():
            row.addWidget(self._swatch(item.colour, filled=True))
            row.addWidget(self._caption(item.label))

        row.addWidget(self._caption("Outcome:"))
        for item in outcome_legend():
            border = item.border
            row.addWidget(
                self._swatch(item.colour, filled=False, style=border.style if border else None)
            )
            row.addWidget(self._caption(item.label))

        column.addLayout(row)

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


def _char_format(colour: str, *, bold: bool = False) -> QTextCharFormat:
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(colour))
    if bold:
        fmt.setFontWeight(QFont.Weight.Bold)
    return fmt


def _field_block() -> QTextBlockFormat:
    """A row of the structured view: indented under its reference, tight to
    the rows around it so one entry reads as one block."""
    block = QTextBlockFormat()
    block.setLeftMargin(12.0)
    block.setBottomMargin(1.0)
    return block


def _source_block() -> QTextBlockFormat:
    """Indented under its `file:line` reference, with room beneath it.

    The indent is a block margin rather than spaces in the text, so a wrapped
    line keeps its shape and the characters in the document stay exactly the
    characters the log holds.
    """
    block = QTextBlockFormat()
    block.setLeftMargin(12.0)
    block.setBottomMargin(7.0)
    return block


class EvidencePanel(QWidget):
    """What the selected activity is made of, down to the raw lines."""

    def __init__(self) -> None:
        super().__init__()
        #: Reading preferences, and the evidence currently on show so a change
        #: to either can be applied without the caller fetching it again.
        self._decode = True
        self._show_raw = False
        self._shown: tuple[Episode, Sequence[EvidenceLine]] | None = None

        self._heading = QLabel("Select an activity to see the lines behind it.")
        self._heading.setWordWrap(True)

        self._body = QTextEdit()
        self._body.setReadOnly(True)
        # Wrapped, not scrolled sideways. The panel is about fifty characters
        # wide and a Combined line spends its first forty-five on the client
        # address and the timestamp — an address the reader picked from the
        # table themselves and a time already printed in the heading. Unwrapped,
        # every line of evidence ended at `"GET` and the payload, which is the
        # thing this panel exists to show, sat off the right-hand edge.
        #
        # Vertical space is what this panel has spare; horizontal space is what
        # it has none of.
        self._body.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        # Break mid-token where there is no space to break at. Wrapping on word
        # boundaries alone leaves a URL untouched, and a URL is precisely what
        # the interesting evidence is: a 59-character injection payload has no
        # spaces in it, so word wrapping would send exactly the line worth
        # reading back off the edge it was just rescued from.
        self._body.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        font = QFont("Consolas")
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSizeF(8.5)
        self._body.setFont(font)
        # Pinned light, not inherited. The severity colours written into this
        # panel are chosen against a pale ground — the same ones the report is
        # printed with — so on a machine themed dark an inherited background
        # renders the evidence dark on dark. Illegible evidence is the one
        # failure this panel cannot have, and it would not look like a fault.
        #
        # Set on the palette rather than through a stylesheet so it is
        # inspectable: a stylesheet leaves `palette()` reporting the inherited
        # colour, which would make a test of this pass while the panel is
        # unreadable.
        paper = self._body.palette()
        paper.setColor(QPalette.ColorRole.Base, QColor(_PAPER))
        paper.setColor(QPalette.ColorRole.Text, QColor(_INK))
        self._body.setPalette(paper)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._heading)
        layout.addWidget(self._body)

    def set_decode(self, decode: bool) -> None:
        """Show request targets decoded, or exactly as the log holds them.

        Decoded is the default because that is the reading an analyst needs:
        `%27+OR+%271%27%3D%271` is a textbook tautology that reads as line
        noise. Turned off when the encoding itself is the finding, or when the
        exact bytes are wanted to quote elsewhere.
        """
        if decode != self._decode:
            self._decode = decode
            self._redraw()

    def set_show_raw(self, show: bool) -> None:
        """Print the whole source line beneath each entry, verbatim."""
        if show != self._show_raw:
            self._show_raw = show
            self._redraw()

    def _redraw(self) -> None:
        if self._shown is not None:
            self.show_evidence(*self._shown)

    def clear(self) -> None:
        self._shown = None
        self._heading.setText("Select an activity to see the lines behind it.")
        self._body.clear()

    def show_evidence(self, episode: Episode, lines: Sequence[EvidenceLine]) -> None:
        self._shown = (episode, lines)
        colour = severity_colour(episode.severity)
        self._heading.setText(
            f'<span style="color:{colour}"><b>{episode.label}</b></span><br>'
            f"{format_requests(episode.request_count)} · outcome {episode.outcome.value} · "
            f"{episode.start:%Y-%m-%d %H:%M:%S} → {episode.end:%H:%M:%S}"
            + (f"<br>OWASP {episode.activity.owasp}" if episode.activity.owasp else "")
            + f"<br>matched by: {', '.join(episode.rule_ids)}"
        )

        self._body.clear()
        # The agent is carried forward between entries so an unchanged one is
        # said once. On a per-client reconstruction it is usually identical on
        # every line — six copies filled twelve of twenty-six rows — and stating
        # it only where it changes turns the field from noise into a signal: a
        # client that switches tool part way through has told you something.
        previous_agent: str | None = None
        for line in lines:
            previous_agent = self._append_entry(line, previous_agent)

        shown = len(lines)
        if episode.evidence_total > shown:
            self._append(
                f"\n{episode.evidence_total - shown:,} further line(s) in this activity; "
                f"the first {shown} are sampled as evidence.",
                "#616e7c",
            )

        # Appending leaves the view where the last write ended, which on an
        # unwrapped log line is the tail of a user agent. Rewind, so the panel
        # opens on the address and the request rather than "Safari/537.36".
        self._body.moveCursor(QTextCursor.MoveOperation.Start)
        self._body.ensureCursorVisible()
        required(self._body.horizontalScrollBar(), "scroll bar").setValue(0)

    def _append(self, text: str, colour: str) -> None:
        self._body.setTextColor(QColor(colour))
        self._body.append(text)

    def _append_entry(self, line: EvidenceLine, previous_agent: str | None) -> str | None:
        """One piece of evidence: where it came from, then what it says.

        Returns the agent it showed, so the next entry can tell whether the
        client changed tool. The reference goes first and always, whatever else
        is shown — it is the thing that makes a finding checkable, and no
        reading preference may hide it.
        """
        when = f"   {line.event.timestamp:%H:%M:%S}" if line.event else ""
        self._append(f"{line.ref}{when}", "#616e7c")

        if not line.available or line.text is None:
            self._append(f"  unavailable — {line.note or 'source not readable'}", "#b5273a")
            return previous_agent

        if line.event is None:
            # Nothing to lay out — and a line the parser cannot read is itself
            # worth seeing, so it gets shown whole rather than summarised away.
            self._append_source_line(line.text)
        else:
            self._append_fields(line.event, previous_agent)
            if self._show_raw:
                self._append_source_line(line.text)
            previous_agent = line.event.user_agent or previous_agent

        if not line.verified and line.note:
            self._append(f"  ! {line.note}", "#b5273a")
        return previous_agent

    def _append_fields(self, event: NormalizedEvent, previous_agent: str | None) -> None:
        """The request, laid out as the engine itself read it.

        Not a paraphrase of the evidence: these are the fields the detection
        ran against. Printing them is what lets a reader check the tool's
        reading rather than perform their own and hope the two agree.
        """
        target = event.target or "—"
        self._field(
            (event.method or "?")[:6],
            decode_target(target) if self._decode else target,
            EVIDENCE_INK,
            bold=True,
        )

        if event.status is not None:
            served = 200 <= event.status < 400
            size = format_bytes(event.bytes_sent) if event.bytes_sent is not None else ""
            verdict = "served" if served else "refused"
            self._field(
                str(event.status),
                f"{size} {verdict}".strip(),
                status_colour(str(event.status)),
                bold=served,
            )

        if event.referer and event.referer != "-":
            self._field("ref", event.referer, EVIDENCE_MUTED)
        agent = event.user_agent
        if agent and agent != "-" and agent != previous_agent:
            self._field("ua", shorten_agent(agent), EVIDENCE_MUTED)

    def _field(self, label: str, value: str, colour: str, *, bold: bool = False) -> None:
        """One labelled row. The label carries the emphasis for the status,
        which is where a served response has to catch the eye."""
        cursor = self._body.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertBlock(_field_block())
        cursor.insertText(f"{label:<4} ", _char_format(colour, bold=bold))
        cursor.insertText(value, _char_format(EVIDENCE_INK if bold else colour))

    def _append_source_line(self, text: str) -> None:
        """One raw log line, with the parts worth reading marked in place.

        Written as consecutive slices of `text`, in order, with nothing between
        them: what reaches the document is the string that came out of the log,
        so the marking decides appearance and cannot decide content. Building a
        tidier line to display would make this panel a paraphrase of the
        evidence rather than the evidence.

        A line whose shape is not recognised gets no marks and is drawn in full
        strength rather than dimmed — the dimming is only meaningful next to
        something brighter, and a JSON log would otherwise be uniformly faint.
        """
        spans = highlight_spans(text)
        plain = EVIDENCE_MUTED if spans else EVIDENCE_INK

        cursor = self._body.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertBlock(_source_block())

        at = 0
        for span in spans:
            marked = text[span.start : span.end]
            colour = EVIDENCE_INK if span.role == "target" else status_colour(marked)
            cursor.insertText(text[at : span.start], _char_format(plain))
            cursor.insertText(marked, _char_format(colour, bold=True))
            at = span.end
        cursor.insertText(text[at:], _char_format(plain))
