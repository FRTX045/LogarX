"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
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
    QHBoxLayout,
    QHeaderView,
    QLabel,
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
    format_requests,
    highlight_spans,
    outcome_legend,
    severity_colour,
    severity_legend,
    status_colour,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from logarc.core.episode import Episode
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
        row = QHBoxLayout(self)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(10)

        row.addWidget(self._caption("Severity:"))
        for item in severity_legend():
            row.addWidget(self._swatch(item.colour, filled=True))
            row.addWidget(self._caption(item.label))

        row.addSpacing(12)
        row.addWidget(self._caption("Outcome:"))
        for item in outcome_legend():
            border = item.border
            row.addWidget(
                self._swatch(item.colour, filled=False, style=border.style if border else None)
            )
            row.addWidget(self._caption(item.label))

        row.addSpacing(12)
        row.addWidget(self._caption(SIZE_NOTE))
        row.addStretch(1)

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

    def clear(self) -> None:
        self._heading.setText("Select an activity to see the lines behind it.")
        self._body.clear()

    def show_evidence(self, episode: Episode, lines: Sequence[EvidenceLine]) -> None:
        colour = severity_colour(episode.severity)
        self._heading.setText(
            f'<span style="color:{colour}"><b>{episode.label}</b></span><br>'
            f"{format_requests(episode.request_count)} · outcome {episode.outcome.value} · "
            f"{episode.start:%Y-%m-%d %H:%M:%S} → {episode.end:%H:%M:%S}"
            + (f"<br>OWASP {episode.activity.owasp}" if episode.activity.owasp else "")
            + f"<br>matched by: {', '.join(episode.rule_ids)}"
        )

        self._body.clear()
        for line in lines:
            self._append(f"{line.ref}", "#616e7c")
            if line.available and line.text is not None:
                self._append_source_line(line.text)
                if not line.verified and line.note:
                    self._append(f"  ! {line.note}", "#b5273a")
            else:
                self._append(f"  unavailable — {line.note or 'source not readable'}", "#b5273a")

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
