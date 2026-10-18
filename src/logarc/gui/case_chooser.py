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

from PyQt6.QtCore import QPoint, Qt, QUrl
from PyQt6.QtGui import QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QMenu,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from logarc.gui import recent
from logarc.gui._qt import required
from logarc.gui.theme import GAP, PAD, caption_font, heading_font, ui_font
from logarc.style import (
    EVIDENCE_MUTED,
    PIN_COLOUR,
    PIN_MARK,
    THEME,
    display_safe,
    format_requests,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.gui.recent import RecentCase

__all__ = ["COLUMNS", "CaseChooser"]

#: The first column is unnamed and holds only a pin mark. A heading over a
#: column of glyphs is a word explaining a picture that is already clear.
COLUMNS: Final[tuple[str, ...]] = ("", "Case", "Opened", "Events", "Source", "Folder")

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

        self.cases = tuple(cases)
        self._exists = exists
        self._present = tuple(exists(case.path) for case in self.cases)
        self.changed = False
        """Something in the list was pinned, renamed or dropped, so the window
        has to store it. Kept apart from the dialog's result: a reader can pin a
        case and then close without opening anything."""

        self.chosen_path: str | None = None
        self.wants_other_case = False
        self.wants_new_case = False

        column = QVBoxLayout(self)
        column.setContentsMargins(GAP, GAP, GAP, GAP)
        column.setSpacing(PAD)

        title = QLabel("Recently opened")
        title.setFont(heading_font(ui_font()))
        column.addWidget(title)

        hint = QLabel(
            "Pick up where you left off, or open something that is not here. "
            "Ctrl-click to choose several, then Forget these."
        )
        hint.setFont(caption_font(ui_font()))
        column.addWidget(hint)

        self._table = self._build_table()
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_menu)
        column.addWidget(self._table)
        column.addLayout(self._build_buttons())

        self._table.itemSelectionChanged.connect(self._selection_changed)
        self._refill()

    # -- construction ------------------------------------------------------

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(len(self.cases), len(COLUMNS))
        table.setHorizontalHeaderLabels(list(COLUMNS))
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        # Several at a time, because forgetting is what is done in bulk here: a
        # list holding seven unwanted entries was seven openings of this dialog,
        # one per entry, since the only visible control shut it.
        table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
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
        return table

    def _refill(self) -> None:
        """Redraw every row from `self.cases`."""
        table = self._table
        table.setRowCount(len(self.cases))
        for row, (case, present) in enumerate(zip(self.cases, self._present, strict=True)):
            name = display_safe(case.display_name) + ("" if present else MISSING_NOTE)
            values = (
                PIN_MARK if case.pinned else "",
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
                elif index == 0 and value:
                    # The pin mark, coloured by the palette rather than by
                    # whatever the font decides a glyph should look like.
                    item.setForeground(QColor(PIN_COLOUR))
                elif index == COLUMNS.index("Opened"):
                    item.setForeground(QColor(THEME.timestamp))
                table.setItem(row, index, item)
        # Not `resizeRowsToContents()`. Every row here is one line, so sizing
        # to the text bought nothing and made the table come back tighter on
        # every redraw — 33px rows becoming 20px on a redraw that removed
        # nothing. The header's default section size is what the rows keep.
        if self.cases:
            table.selectRow(0)
        self._selection_changed()

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
        self._forget_button = QPushButton("Forget these")
        self._forget_button.setToolTip(
            "Take the highlighted cases off this list, which records which cases were "
            "opened on this machine. Ctrl+A selects all of them."
        )
        self._forget_button.clicked.connect(self._forget)
        row.addWidget(self._forget_button)
        return row

    # -- what the reader chose ---------------------------------------------

    def _selected_rows(self) -> tuple[int, ...]:
        rows = required(self._table.selectionModel(), "selection model").selectedRows()
        return tuple(sorted(index.row() for index in rows))

    def _selected_row(self) -> int | None:
        """The one selected row, or None when that is not what is selected.

        The per-row commands — pin, rename, show the folder — act on one case
        and have no meaning for three. They ask for one and get nothing rather
        than taking the first, which would act on a case nobody singled out.
        """
        rows = self._selected_rows()
        return rows[0] if len(rows) == 1 else None

    def _selection_changed(self) -> None:
        rows = self._selected_rows()
        # Bounds-checked: a row can be dropped while it is the selected one, and
        # the selection signal arrives before the table has caught up.
        openable = len(rows) == 1 and rows[0] < len(self._present) and self._present[rows[0]]
        self._open_button.setEnabled(openable)
        self._forget_button.setEnabled(bool(rows))

    def _accept_selection(self) -> None:
        row = self._selected_row()
        if row is None or not self._present[row]:
            return
        self.chosen_path = self.cases[row].path
        self.accept()

    def _choose_other(self) -> None:
        self.wants_other_case = True
        self.accept()

    def _choose_new(self) -> None:
        self.wants_new_case = True
        self.accept()

    def _forget(self) -> None:
        """Drop the highlighted cases. The dialog stays open.

        It used to wipe the whole list and close, which made the one visible
        control in this dialog both wider in effect than its name suggested and
        usable exactly once per opening. Ctrl+A still reaches the old effect,
        and now the name is true: `these` are the ones highlighted.
        """
        rows = self._selected_rows()
        if not rows:
            return
        self._amend(recent.forget(self.cases, [self.cases[row].path for row in rows]))

    # -- one row at a time --------------------------------------------------

    def _aim_menu_at(self, row: int) -> None:
        """Point the per-row commands at `row`, keeping a selection it is in.

        Right-clicking one of several highlighted rows must not throw the rest
        away: the reader has just built that selection and is about to act on
        it. Outside the selection it replaces it, which is what every file list
        does.
        """
        if row not in self._selected_rows():
            self._table.selectRow(row)

    def _show_menu(self, where: QPoint) -> None:
        row = self._table.rowAt(where.y())
        if row < 0:
            return
        self._aim_menu_at(row)

        menu = QMenu(self)
        pinned = self.cases[row].pinned
        _entry(menu, "Unpin" if pinned else "Pin to the top", self._toggle_pin)
        menu.addSeparator()
        _entry(menu, "Rename in this list…", self._rename)
        # Offered even when the folder has gone: the reader may be trying to
        # work out where it went.
        _entry(menu, "Show the folder", self._show_folder)
        menu.addSeparator()
        _entry(menu, "Remove from this list", self._remove)
        menu.exec(required(self._table.viewport(), "table viewport").mapToGlobal(where))

    def _amend(self, cases: tuple[RecentCase, ...]) -> None:
        """Take the new list, redraw, and remember that it needs storing."""
        self.cases = cases
        self.changed = True
        self._present = tuple(self._exists(case.path) for case in self.cases)
        self._refill()

    def _toggle_pin(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        case = self.cases[row]
        self._amend(recent.set_pinned(self.cases, case.path, pinned=not case.pinned))

    def _rename(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        case = self.cases[row]
        name = _ask_for_a_name(self, case.display_name)
        if name is None:
            return
        self._amend(recent.set_label(self.cases, case.path, name))

    def _remove(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        self._amend(recent.forget_one(self.cases, self.cases[row].path))

    def _show_folder(self) -> None:
        row = self._selected_row()
        if row is None:
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(self.cases[row].path))


def _entry(menu: QMenu, text: str, slot: Callable[[], None]) -> None:
    """One menu entry. `addAction` is typed as optional; it never is here."""
    required(menu.addAction(text), f"menu entry {text!r}").triggered.connect(slot)


def _ask_for_a_name(parent: CaseChooser, current: str) -> str | None:
    """The new name, or `None` if the reader thought better of it.

    A function rather than the call spelled out inline, so a test has one seam
    to substitute instead of a modal dialog that waits for a click nobody makes.
    """
    name, accepted = QInputDialog.getText(
        parent,
        "Rename in this list",
        "Show this case as:",
        text=current,
    )
    return name if accepted else None
