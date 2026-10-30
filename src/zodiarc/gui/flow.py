"""A row of items that wraps onto further rows when the width runs out.

Qt ships nothing like it. Written for the graph key, which as a single
horizontal row reported a minimum width of 1,729px; used again for the Bookmarks
tab's buttons, which in one row set the narrowest the middle of the window could
be on Linux. A minimum is a demand, not a preference, and every tab page's
minimum is the whole workspace's.
"""

from __future__ import annotations

from PyQt6.QtCore import QPoint, QRect, QSize, Qt
from PyQt6.QtWidgets import QLayout, QLayoutItem, QWidget

__all__ = ["FlowLayout"]


class FlowLayout(QLayout):
    """Items in a row that wraps onto further rows when the width runs out.

    Laid out as a single horizontal row the graph key reported a minimum width
    of **1,729px**, wider than the window it sits in. The centre column
    inherited it, both side panels were pinned at their own minimums to pay for
    it, and with no slack left anywhere the splitter handles stopped moving: the
    client panel could be its minimum or collapsed, and nothing in between.

    A key is a set of small independent items. It should take as many rows as
    it needs and ask for no more width than its widest single entry.

    `right` sets each row against the right edge, as a row of buttons sits.
    `one_row` asks for the width of a single row when there is room: the key,
    alone in its column, is handed the width anyway, but beside a stretching
    neighbour a layout is given what it asks for, and asking for its widest
    entry would stack the buttons one under another at every width.
    """

    def __init__(
        self,
        parent: QWidget | None = None,
        spacing: int = 10,
        *,
        right: bool = False,
        one_row: bool = False,
    ) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self._right = right
        self._one_row = one_row
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
        if not self._one_row:
            return self.minimumSize()
        hints = [item.sizeHint() for item in self._items]
        margins = self.contentsMargins()
        width = sum(hint.width() for hint in hints) + self.spacing() * max(len(hints) - 1, 0)
        height = max((hint.height() for hint in hints), default=0)
        return QSize(
            width + margins.left() + margins.right(),
            height + margins.top() + margins.bottom(),
        )

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

        rows: list[list[tuple[QLayoutItem, QSize]]] = [[]]
        x = left
        for item in self._items:
            hint = item.sizeHint()
            # `right` is the last pixel inside, so an item that ends on it fits.
            if x > left and x + hint.width() - 1 > right:
                rows.append([])
                x = left
            rows[-1].append((item, hint))
            x += hint.width() + self.spacing()

        y = rect.y() + margins.top()
        bottom = y
        for placed in rows:
            if not placed:
                continue
            width = sum(hint.width() for _, hint in placed) + self.spacing() * (len(placed) - 1)
            x = right - width + 1 if self._right else left
            for item, hint in placed:
                if place:
                    item.setGeometry(QRect(QPoint(x, y), hint))
                x += hint.width() + self.spacing()
            bottom = y + max(hint.height() for _, hint in placed)
            y = bottom + self.spacing()

        return bottom + margins.bottom() - rect.y()
