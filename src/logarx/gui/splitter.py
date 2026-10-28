"""Panel dividers with a small centered grip and a full draggable handle."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QRectF, Qt
from PyQt6.QtGui import QColor, QPainter
from PyQt6.QtWidgets import QSplitter, QSplitterHandle, QWidget

from logarx.style import THEME

if TYPE_CHECKING:
    from PyQt6.QtCore import QEvent
    from PyQt6.QtGui import QEnterEvent, QPaintEvent


class _Grip(QSplitterHandle):
    def __init__(self, orientation: Qt.Orientation, parent: QSplitter) -> None:
        super().__init__(orientation, parent)
        self._hovered = False
        self.setToolTip("Drag to resize panels")
        self.setAccessibleName("Resize panels")

    def enterEvent(self, event: QEnterEvent | None) -> None:  # noqa: N802
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event: QEvent | None) -> None:  # noqa: N802
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event: QPaintEvent | None) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(THEME.chrome))
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Accent only under the pointer: accent means "chosen" everywhere else,
        # and a grip drawn in it at rest read as a selected panel edge.
        colour = QColor(THEME.accent if self._hovered else THEME.edge)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(colour)
        vertical = self.orientation() == Qt.Orientation.Horizontal
        length = min(32.0, max(0.0, (self.height() if vertical else self.width()) - 8.0))
        width, height = (2.0, length) if vertical else (length, 2.0)
        grip = QRectF((self.width() - width) / 2, (self.height() - height) / 2, width, height)
        painter.drawRoundedRect(grip, 1.0, 1.0)
        painter.end()


class PanelSplitter(QSplitter):
    """Keep the resize target usable while drawing only a short blue grip."""

    def __init__(self, orientation: Qt.Orientation, parent: QWidget | None = None) -> None:
        super().__init__(orientation, parent)
        self.setHandleWidth(7)

    def createHandle(self) -> QSplitterHandle:  # noqa: N802
        return _Grip(self.orientation(), self)
