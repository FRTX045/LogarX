"""Content-sized defaults with column widths the reader can change."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QModelIndex, QObject, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QHeaderView,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableWidget,
)

from logarc.gui._qt import required

if TYPE_CHECKING:
    from collections.abc import Iterable

    from PyQt6.QtCore import QPoint

#: Where a cell keeps the shorter form it shows while its column is too narrow
#: for its text: a date without its time, a line number without its file.
SHORT_TEXT = Qt.ItemDataRole.UserRole + 2


class ShortWhenNarrow(QStyledItemDelegate):
    """Draws a cell's short form while its whole text does not fit the column.

    Measured by the short form, so a column fitted to its contents starts at
    that width, and one the reader drags wider shows the whole value again.
    The item keeps its whole text: that is what sorts and what is copied.
    """

    def initStyleOption(  # noqa: N802 - Qt's naming
        self, option: QStyleOptionViewItem | None, index: QModelIndex
    ) -> None:
        super().initStyleOption(option, index)
        short = index.data(SHORT_TEXT)
        # No width yet means being measured, which `sizeHint` does for itself.
        if option is None or not short or option.rect.width() <= 0:
            return
        if _needs(option, option.text or "") > option.rect.width():
            option.text = short

    def sizeHint(  # noqa: N802 - Qt's naming
        self, option: QStyleOptionViewItem, index: QModelIndex
    ) -> QSize:
        short = index.data(SHORT_TEXT)
        if not short:
            return super().sizeHint(option, index)
        measured = QStyleOptionViewItem(option)
        # The base's, not this class's: the whole text, whatever the width.
        super().initStyleOption(measured, index)
        return _measure(measured, short)


def _style(option: QStyleOptionViewItem) -> QStyle:
    widget = option.widget
    return required(widget.style() if widget is not None else QApplication.style(), "style")


def _measure(option: QStyleOptionViewItem, text: str) -> QSize:
    """The size a cell drawn as `option` needs for `text` on one line, icon and margins included.

    Unbounded and unwrapped. Given the cell's own rect and the view's word
    wrapping, Qt measures the text wrapped to that width, so it always fits:
    First drew `09 M\u2026` in the window while every measurement said it fitted.
    """
    measured = QStyleOptionViewItem(option)
    measured.text = text
    measured.rect = QRect()
    measured.features &= ~QStyleOptionViewItem.ViewItemFeature.WrapText
    return _style(measured).sizeFromContents(
        QStyle.ContentsType.CT_ItemViewItem, measured, QSize(), measured.widget
    )


def _needs(option: QStyleOptionViewItem, text: str) -> int:
    """The width a cell drawn as `option` needs for `text`."""
    return _measure(option, text).width()


class ColumnWidths(QObject):
    """Size untouched columns once per refill, preserving the reader's widths.

    The optional fill column uses spare panel width until resized by the reader.
    All sections remain interactive, including the fill column and the last one.
    `optional` columns start hidden; the heading's menu lets the reader show them.
    """

    wanted_changed = pyqtSignal()
    """The reader showed or hid one of the optional columns from the heading's menu."""

    def __init__(
        self, table: QTableWidget, *, fill: int | None = None, optional: Iterable[int] = ()
    ) -> None:
        super().__init__(table)
        self._fill = fill
        self._optional = tuple(optional)
        self._wanted: set[int] = set()
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

    def widen(self, column: int) -> None:
        """Give `column` room for the rows drawn now, if it has too little.

        For a refill that draws rows the last fit never measured. Only widens,
        so the columns do not shrink and grow as rows come and go, and never a
        column the reader sized.
        """
        if column == self._fill or column in self._manual or self._table.isColumnHidden(column):
            return
        needed = self._table.sizeHintForColumn(column)
        if self._header.sectionSize(column) >= needed:
            return
        self._sizing = True
        try:
            self._header.resizeSection(column, needed)
            self._fill_remaining()
        finally:
            self._sizing = False

    def wanted(self, column: int) -> bool:
        """Whether the reader asked to see `column`, one of the optional ones."""
        return column in self._wanted

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

    def _torn_down(self) -> bool:
        """Whether the table is being destroyed: its header still reports once more.

        An exception in a slot is one PyQt answers by ending the program, so
        `_space_changed` looks before it reaches for the table.
        """
        return not isinstance(self.parent(), QTableWidget)

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
        if self._sizing or self._torn_down():
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
        toggles = {}
        if self._optional:
            menu.addSeparator()
        for optional in self._optional:
            heading = self._table.horizontalHeaderItem(optional)
            toggle = required(menu.addAction(f"Show {heading.text() if heading else optional}"))
            toggle.setCheckable(True)
            toggle.setChecked(optional in self._wanted)
            toggles[optional] = toggle
        chosen = menu.exec(self._header.mapToGlobal(position))
        if chosen is fit:
            self.fit_column(column)
        elif chosen is reset:
            self.reset()
        for optional, toggle in toggles.items():
            if chosen is toggle:
                self._wanted ^= {optional}
                self.wanted_changed.emit()
