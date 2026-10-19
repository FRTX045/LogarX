"""Who else a rule matched, asked of an activity on the canvas.

Answered from the index the "Where to start" scan publishes, not by
reconstructing every client again: that scan already labels every client once,
and a second pass per question measured two and a half minutes on a case of
2,761 clients.

`describe` and `unavailable` are free of Qt so what the window says can be
checked without a display, and what it says is the part that can mislead. The
index exists only once a scan completes. Until then there is no answer, and
"no other IP" would be a claim about the whole case made from none of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QMenu,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from logarc.gui.columns import ColumnWidths
from logarc.gui.theme import PAD
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.triage.scan import RuleMatch, TriageProgress


def others(matches: Sequence[RuleMatch], client_ip: str) -> list[RuleMatch]:
    """The matches for every client but the one being looked at."""
    return [match for match in matches if match.client_ip != client_ip]


def describe(rule_id: str, matches: Sequence[RuleMatch], *, client_ip: str) -> str:
    """One line over the list, counting the other clients and nobody else."""
    count = len(others(matches, client_ip))
    if not count:
        return f"No other IP matched {rule_id} in this time range."
    return f"{count:,} other {'IP' if count == 1 else 'IPs'} matched {rule_id} in this time range."


def unavailable(progress: TriageProgress | None, *, scanning: bool) -> str:
    """Why there is no answer yet, never phrased as though there were one."""
    if scanning and progress is not None:
        return (
            f"Still checking IPs: {progress.processed:,} of {progress.total:,} so far. "
            "Ask again when the scan in Where to start finishes."
        )
    if scanning:
        return "Still checking IPs. Ask again when the scan in Where to start finishes."
    return (
        "Every IP has to be checked before this can be answered, and that scan has not "
        "finished. Run it from Where to start."
    )


class WhoElseDialog(QDialog):
    """The other clients one rule matched. Double-click a row to open that client."""

    open_client = pyqtSignal(str)
    bookmark_requested = pyqtSignal(str)
    """A listed client asked to be bookmarked, from its right-click menu."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Who else did this?")
        self.caption = QLabel()
        self.caption.setWordWrap(True)
        self.caption.setTextFormat(Qt.TextFormat.PlainText)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(("IP address", "Matched", "Named here", "Requests"))
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._column_sizes = ColumnWidths(self.table, fill=0)
        self.table.cellDoubleClicked.connect(self._opened)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        # Says what the two counts mean, because the difference between them is
        # the reason a client is on this list at all when its own activity is
        # called something else.
        self.note = QLabel(
            "Matched: requests this rule matched. Named here: how many of those the "
            "activity is named after; the rest were named by a stronger rule. "
            "Double-click an IP to open it."
        )
        self.note.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(PAD, PAD, PAD, PAD)
        layout.addWidget(self.caption)
        layout.addWidget(self.table, 1)
        layout.addWidget(self.note)
        layout.addWidget(buttons)
        self.resize(560, 420)

    def show_matches(self, rule_id: str, matches: Sequence[RuleMatch], *, client_ip: str) -> None:
        rows = others(matches, client_ip)
        self.setWindowTitle(f"Who else matched {rule_id}?")
        self.caption.setText(describe(rule_id, matches, client_ip=client_ip))
        self.table.setRowCount(len(rows))
        for index, match in enumerate(rows):
            for column, value in enumerate(
                (match.client_ip, f"{match.matched:,}", f"{match.won:,}", f"{match.requests:,}")
            ):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setForeground(QColor(THEME.identity))
                self.table.setItem(index, column, item)
        self.table.setVisible(bool(rows))
        self._column_sizes.fit_unset()
        self.note.setVisible(bool(rows))

    def show_unavailable(self, rule_id: str, text: str) -> None:
        self.setWindowTitle(f"Who else matched {rule_id}?")
        self.caption.setText(text)
        self.table.setRowCount(0)
        self.table.hide()
        self.note.hide()

    def _menu_at(self, point: QPoint) -> QMenu | None:
        """The menu a right-click at `point` opens, or None off the rows."""
        index = self.table.indexAt(point)
        item = self.table.item(index.row(), 0) if index.isValid() else None
        if item is None:
            return None
        address = item.text()
        menu = QMenu(self)
        menu.addAction("Bookmark this client\u2026", lambda: self.bookmark_requested.emit(address))
        return menu

    def _show_menu(self, point: QPoint) -> None:
        menu = self._menu_at(point)
        viewport = self.table.viewport()
        if menu is not None and viewport is not None:
            menu.popup(viewport.mapToGlobal(point))

    def _opened(self, row: int, _column: int) -> None:
        item = self.table.item(row, 0)
        if item is not None:
            self.open_client.emit(item.text())
