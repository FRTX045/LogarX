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

from zodiarc import client_names
from zodiarc.gui._qt import required
from zodiarc.gui.columns import CLIENT_ADDRESS, ColumnWidths
from zodiarc.gui.theme import PAD
from zodiarc.style import THEME, display_safe

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from zodiarc.analysis import AnalysisResult
    from zodiarc.triage.scan import RuleMatch, TriageProgress


def others(matches: Sequence[RuleMatch], client_ip: str) -> list[RuleMatch]:
    """The matches for every client but the one being looked at."""
    return [match for match in matches if match.client_ip != client_ip]


def describe(
    rule_id: str, matches: Sequence[RuleMatch], *, client_ip: str, name: str | None = None
) -> str:
    """One line over the list, counting the other clients and nobody else."""
    count = len(others(matches, client_ip))
    called = name or rule_id
    if not count:
        return f"No other client matched {called} in this time range."
    noun = "client" if count == 1 else "clients"
    return f"{count:,} other {noun} matched {called} in this time range."


def rule_names(result: AnalysisResult) -> dict[str, str]:
    """What each rule in `result` is called, by its id.

    Read off the labels the result already carries, which are what the graph
    and the evidence panel name an activity after; no rules are loaded for it.
    """
    names: dict[str, str] = {}
    for assignment in result.assignments:
        labelled = assignment.labelled
        for label in (labelled.label, *labelled.all_labels):
            names.setdefault(label.rule_id, label.name)
    return names


def unavailable(progress: TriageProgress | None, *, scanning: bool) -> str:
    """Why there is no answer yet, never phrased as though there were one."""
    if scanning and progress is not None:
        return (
            f"Still checking clients: {progress.processed:,} of {progress.total:,} so far. "
            "Ask again when the Triage scan finishes."
        )
    if scanning:
        return "Still checking clients. Ask again when the Triage scan finishes."
    return (
        "Every client has to be checked before this can be answered, and that scan has not "
        "finished. Run it from Triage."
    )


class WhoElseDialog(QDialog):
    """The other clients one rule matched. Double-click a row to open that client."""

    open_client = pyqtSignal(str)
    bookmark_requested = pyqtSignal(str)
    """A listed client asked to be bookmarked, from its right-click menu."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Who else did this?")
        # The names readers gave addresses, and whether they are shown in place
        # of the addresses; each row keeps its address in `CLIENT_ADDRESS`.
        self._names: dict[str, str] = {}
        self._names_shown = True
        self.caption = QLabel()
        self.caption.setWordWrap(True)
        self.caption.setTextFormat(Qt.TextFormat.PlainText)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(("Client", "Matched", "Named", "Requests"))
        # What the two counts mean, on the columns themselves. The difference
        # between them is why a client is on this list at all when its own
        # activity is called something else; it was a footnote under the table.
        for column, explained in (
            (1, "Requests this rule matched."),
            (
                2,
                "How many of those the activity is named after; the rest were named by "
                "a stronger rule.",
            ),
        ):
            required(self.table.horizontalHeaderItem(column)).setToolTip(explained)
        required(self.table.verticalHeader()).hide()
        self.table.setToolTip("Double-click a client to open it.")
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._column_sizes = ColumnWidths(self.table, fill=0)
        self.table.cellDoubleClicked.connect(self._opened)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_menu)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(PAD, PAD, PAD, PAD)
        layout.addWidget(self.caption)
        layout.addWidget(self.table, 1)
        layout.addWidget(buttons)
        self.resize(560, 420)

    def show_matches(
        self,
        rule_id: str,
        matches: Sequence[RuleMatch],
        *,
        client_ip: str,
        name: str | None = None,
    ) -> None:
        rows = others(matches, client_ip)
        self.setWindowTitle(f"Who else matched {name or rule_id}?")
        self.caption.setText(describe(rule_id, matches, client_ip=client_ip, name=name))
        self.table.setRowCount(len(rows))
        for index, match in enumerate(rows):
            for column, value in enumerate(
                (match.client_ip, f"{match.matched:,}", f"{match.won:,}", f"{match.requests:,}")
            ):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setForeground(QColor(THEME.identity))
                    item.setData(CLIENT_ADDRESS, value)
                self.table.setItem(index, column, item)
            self._label(index)
        self.table.setVisible(bool(rows))
        self._column_sizes.fit_unset()

    def set_names(self, names: Mapping[str, str], *, shown: bool) -> None:
        """Label each listed client by the name a reader gave it while `shown`."""
        self._names, self._names_shown = dict(names), shown
        for index in range(self.table.rowCount()):
            self._label(index)

    def _label(self, index: int) -> None:
        item = self.table.item(index, 0)
        if item is None:
            return
        address = item.data(CLIENT_ADDRESS)
        item.setText(display_safe(client_names.shown(address, self._names, on=self._names_shown)))
        item.setToolTip(address)

    def show_unavailable(self, rule_id: str, text: str) -> None:
        self.setWindowTitle(f"Who else matched {rule_id}?")
        self.caption.setText(text)
        self.table.setRowCount(0)
        self.table.hide()

    def _menu_at(self, point: QPoint) -> QMenu | None:
        """The menu a right-click at `point` opens, or None off the rows."""
        index = self.table.indexAt(point)
        item = self.table.item(index.row(), 0) if index.isValid() else None
        if item is None:
            return None
        address = item.data(CLIENT_ADDRESS)
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
            self.open_client.emit(item.data(CLIENT_ADDRESS))
