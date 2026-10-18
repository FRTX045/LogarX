"""Content-sized defaults with column widths the reader can change."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QObject, Qt
from PyQt6.QtWidgets import QHeaderView, QMenu, QTableWidget

from logarc.gui._qt import required

if TYPE_CHECKING:
    from PyQt6.QtCore import QPoint


class ColumnWidths(QObject):
    """Size untouched columns once per refill, preserving the reader's widths.

    The optional fill column uses spare panel width until resized by the reader.
    All sections remain interactive, including the fill column and the last one.
    """

    def __init__(self, table: QTableWidget, *, fill: int | None = None) -> None:
        super().__init__(table)
        self._fill = fill
        self._manual: set[int] = set()
        self._sizing = False
        self._header.setStretchLastSection(False)
        self._header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._header.setToolTip(
            "Drag column edges to resize. Double-click an edge to fit its column. "
            "Right-click a heading for width options."
        )
        self._header.sectionResized.connect(self._resized)
        self._header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._header.customContextMenuRequested.connect(self._show_menu)
        self._header.geometriesChanged.connect(self._space_changed)
        self.fit_unset()

    @property
    def _table(self) -> QTableWidget:
        # Qt owns this helper through the table. Avoid a Python reference back
        # to the owner, which creates a cycle across Qt's destruction boundary.
        table = self.parent()
        assert isinstance(table, QTableWidget)
        return table

    @property
    def _header(self) -> QHeaderView:
        return required(self._table.horizontalHeader())

    def fit_unset(self) -> None:
        """Measure untouched columns after filling, without locking their handles."""
        self._sizing = True
        try:
            for column in range(self._table.columnCount()):
                if (
                    column != self._fill
                    and column not in self._manual
                    and not self._table.isColumnHidden(column)
                ):
                    self._table.resizeColumnToContents(column)
            self._fill_remaining()
        finally:
            self._sizing = False

    def fit_column(self, column: int) -> None:
        """Fit this column now and keep its width on subsequent refills."""
        self._sizing = True
        try:
            self._table.resizeColumnToContents(column)
            self._manual.add(column)
            self._fill_remaining()
        finally:
            self._sizing = False

    def fit_heading(self, column: int) -> None:
        """Give `column` room for its heading as drawn now, sort arrow included.

        Content sizing leaves the arrow out when the table measures with sorting
        off, and the arrow then covers the words of the one heading that draws
        it. Only widens, and never a column the reader sized.
        """
        if (
            column < 0
            or column == self._fill
            or column in self._manual
            or self._table.isColumnHidden(column)
        ):
            return
        needed = self._header.sectionSizeHint(column)
        if self._header.sectionSize(column) >= needed:
            return
        self._sizing = True
        try:
            self._header.resizeSection(column, needed)
            self._fill_remaining()
        finally:
            self._sizing = False

    def reset(self) -> None:
        """Return every column to content sizing and the default fill column."""
        self._manual.clear()
        self.fit_unset()

    def _fill_remaining(self) -> None:
        column = self._fill
        if column is None or column in self._manual or self._table.isColumnHidden(column):
            return
        occupied = sum(
            self._header.sectionSize(other)
            for other in range(self._header.count())
            if other != column and not self._table.isColumnHidden(other)
        )
        width = max(
            self._header.minimumSectionSize(), required(self._table.viewport()).width() - occupied
        )
        self._header.resizeSection(column, width)

    def _resized(self, column: int, before: int, after: int) -> None:
        # Hiding and restoring an optional column is not a manual width choice.
        if self._sizing or before == 0 or after == 0:
            return
        self._manual.add(column)
        self._sizing = True
        try:
            self._fill_remaining()
        finally:
            self._sizing = False

    def _space_changed(self) -> None:
        if self._sizing:
            return
        self._sizing = True
        try:
            self._fill_remaining()
        finally:
            self._sizing = False

    def _show_menu(self, position: QPoint) -> None:
        column = self._header.logicalIndexAt(position)
        menu = QMenu(self._header)
        fit = menu.addAction("Fit this column to contents")
        required(fit).setEnabled(column >= 0)
        reset = menu.addAction("Reset column widths")
        chosen = menu.exec(self._header.mapToGlobal(position))
        if chosen is fit:
            self.fit_column(column)
        elif chosen is reset:
            self.reset()
