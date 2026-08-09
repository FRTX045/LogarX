"""The two panels either side of the canvas.

`ClientTable` picks who to look at; `EvidencePanel` shows what a finding is made
of. Both are deliberately thin — they display what the engine returned and hold
no analysis of their own.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QPalette, QTextCursor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import required
from logarc.gui.style import severity_colour

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.episode import Episode
    from logarc.evidence import EvidenceLine
    from logarc.storage.base import IpSummary

__all__ = ["ClientTable", "EvidencePanel"]

_COLUMNS = ("Client", "Requests", "Paths", "4xx", "First seen", "Last seen")

#: The evidence surface. Matches the canvas ground and the exported report, so
#: the same finding reads the same way on screen and on paper.
_PAPER = "#f5f7fa"
_INK = "#1f2933"


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
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
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
            self._set(row, 4, summary.first_seen.strftime("%Y-%m-%d %H:%M:%S"))
            self._set(row, 5, summary.last_seen.strftime("%Y-%m-%d %H:%M:%S"))
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


class EvidencePanel(QWidget):
    """What the selected activity is made of, down to the raw lines."""

    def __init__(self) -> None:
        super().__init__()
        self._heading = QLabel("Select an activity to see the lines behind it.")
        self._heading.setWordWrap(True)

        self._body = QTextEdit()
        self._body.setReadOnly(True)
        self._body.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
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
            f"{episode.request_count:,} requests · outcome {episode.outcome.value} · "
            f"{episode.start:%Y-%m-%d %H:%M:%S} → {episode.end:%H:%M:%S}"
            + (f"<br>OWASP {episode.activity.owasp}" if episode.activity.owasp else "")
            + f"<br>matched by: {', '.join(episode.rule_ids)}"
        )

        self._body.clear()
        for line in lines:
            self._append(f"{line.ref}", "#616e7c")
            if line.available:
                self._append(f"  {line.text}", "#1f2933")
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
