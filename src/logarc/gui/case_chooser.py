"""Pick up a case that has been worked on before.

Chosen over a `Recent cases` submenu after drawing both: a submenu offers only a
name, and two cases called `case-001` and `case-002` are not told apart by one.
What distinguishes them — when they were last opened, how much is in them, which
log they were built from, and above all which folder they are — needs columns.

Shown when the window opens with nothing to show, and from `Case ▸ Recently
opened…` at any time. It is not a gate: with the last case reopening on start,
most launches go straight to the case and never see this.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from logarc.gui._qt import required
from logarc.gui.style import EVIDENCE_MUTED, display_safe, format_requests
from logarc.gui.theme import GAP, PAD, caption_font, heading_font, ui_font

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.gui.recent import RecentCase

__all__ = ["COLUMNS", "CaseChooser"]

COLUMNS: Final[tuple[str, ...]] = ("Case", "Opened", "Events", "Source", "Folder")

#: Said next to a case whose folder is no longer where it was. The entry stays —
#: it is a record of what was worked on — but it cannot be opened.
MISSING_NOTE: Final = "   (folder is missing)"


class CaseChooser(QDialog):
    """The cases opened lately, and a way back to the ones that are not here."""

    def __init__(
        self,
        cases: Sequence[RecentCase],
        *,
        exists: Callable[[str], bool],
    ) -> None:
        super().__init__()
        self.setWindowTitle("Open a case")
        self.setMinimumWidth(760)

        self._cases = tuple(cases)
        self._present = tuple(exists(case.path) for case in self._cases)
        self.chosen_path: str | None = None
        self.forgotten = False
        self.wants_other_case = False
        self.wants_new_case = False

        column = QVBoxLayout(self)
        column.setContentsMargins(GAP, GAP, GAP, GAP)
        column.setSpacing(PAD)

        title = QLabel("Recently opened")
        title.setFont(heading_font(ui_font()))
        column.addWidget(title)

        hint = QLabel("Pick up where you left off, or open something that is not here.")
        hint.setFont(caption_font(ui_font()))
        column.addWidget(hint)

        self._table = self._build_table()
        column.addWidget(self._table)
        column.addLayout(self._build_buttons())

        self._table.itemSelectionChanged.connect(self._selection_changed)
        if self._cases:
            self._table.selectRow(0)
            self._selection_changed()

    # -- construction ------------------------------------------------------

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(len(self._cases), len(COLUMNS))
        table.setHorizontalHeaderLabels(list(COLUMNS))
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        required(table.verticalHeader(), "row header").setVisible(False)
        header = required(table.horizontalHeader(), "column header")
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        # The folder takes what is left. It is the one value with no bound and
        # the one that finally tells two identically named cases apart.
        header.setSectionResizeMode(COLUMNS.index("Folder"), QHeaderView.ResizeMode.Stretch)
        # Sized to what it holds rather than to a guessed height: five entries in
        # a fixed-height table left two thirds of it empty, which is what the
        # drawn demo of this showed and the one thing it needed fixing.
        table.setMinimumHeight(120)

        for row, (case, present) in enumerate(zip(self._cases, self._present, strict=True)):
            name = display_safe(case.case_id) + ("" if present else MISSING_NOTE)
            values = (
                name,
                f"{case.opened_at:%d %b %H:%M}",
                format_requests(case.events).replace("request", "event"),
                display_safe(", ".join(case.sources)) or "—",
                display_safe(case.path),
            )
            for index, value in enumerate(values):
                item = QTableWidgetItem(value)
                if not present:
                    item.setForeground(QColor(EVIDENCE_MUTED))
                table.setItem(row, index, item)
        table.resizeRowsToContents()
        return table

    def _build_buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        self._open_button = QPushButton("Open")
        self._open_button.setDefault(True)
        self._open_button.clicked.connect(self._accept_selection)
        row.addWidget(self._open_button)

        other = QPushButton("Open another case…")
        other.clicked.connect(self._choose_other)
        row.addWidget(other)

        fresh = QPushButton("Ingest logs into a new case…")
        fresh.clicked.connect(self._choose_new)
        row.addWidget(fresh)

        row.addStretch(1)
        forget = QPushButton("Forget these")
        forget.setToolTip(
            "Remove this list from this machine. It records which cases were opened here."
        )
        forget.clicked.connect(self._forget)
        row.addWidget(forget)
        return row

    # -- what the reader chose ---------------------------------------------

    def _selected_row(self) -> int | None:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        return rows[0].row() if rows else None

    def _selection_changed(self) -> None:
        row = self._selected_row()
        self._open_button.setEnabled(row is not None and self._present[row])

    def _accept_selection(self) -> None:
        row = self._selected_row()
        if row is None or not self._present[row]:
            return
        self.chosen_path = self._cases[row].path
        self.accept()

    def _choose_other(self) -> None:
        self.wants_other_case = True
        self.accept()

    def _choose_new(self) -> None:
        self.wants_new_case = True
        self.accept()

    def _forget(self) -> None:
        self.forgotten = True
        self.accept()
