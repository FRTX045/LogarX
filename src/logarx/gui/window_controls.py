"""Large WSL window buttons, with native moving and resizing through Qt."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, QObject, QSize, Qt
from PyQt6.QtGui import QColor, QIcon, QMouseEvent, QPainter, QPen, QPixmap
from PyQt6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget

from logarx.gui.display import is_wsl
from logarx.style import THEME

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QMainWindow

BUTTON_SIZE = QSize(34, 28)
ICON_SIZE = 15
_EDGE = 6
_CORNER = 10


def _icon(mark: str) -> QIcon:
    """Draw the marks rather than relying on a font or an installed icon theme."""
    icon = QIcon()
    for ratio in (1, 2, 3):
        pixmap = QPixmap(ICON_SIZE * ratio, ICON_SIZE * ratio)
        pixmap.setDevicePixelRatio(ratio)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        # Keep the marks' original 22-unit geometry while scaling the whole symbol.
        painter.scale(ICON_SIZE / 22, ICON_SIZE / 22)
        painter.setPen(QPen(QColor(THEME.ink), 1.8))
        if mark == "minimise":
            painter.drawLine(4, 14, 18, 14)
        elif mark == "maximise":
            painter.drawRect(4, 4, 14, 14)
        elif mark == "restore":
            painter.drawLine(8, 4, 18, 4)
            painter.drawLine(18, 4, 18, 14)
            painter.drawLine(18, 14, 15, 14)
            painter.drawRect(4, 8, 10, 10)
        else:
            painter.drawLine(5, 5, 17, 17)
            painter.drawLine(5, 17, 17, 5)
        painter.end()
        icon.addPixmap(pixmap)
    return icon


class _ResizeEdge(QWidget):
    """A narrow border that hands resizing to the window manager."""

    def __init__(self, window: QMainWindow, edges: Qt.Edge, cursor: Qt.CursorShape) -> None:
        super().__init__(window)
        self._window = window
        self._edges = edges
        self.setCursor(cursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802
        if event is not None and event.button() == Qt.MouseButton.LeftButton:
            handle = self._window.windowHandle()
            if handle is not None and handle.startSystemResize(self._edges):
                event.accept()
                return
        super().mousePressEvent(event)


class WindowControls(QObject):
    """A menu-bar title strip whose three buttons cannot be hidden by a theme."""

    def __init__(self, window: QMainWindow) -> None:
        super().__init__(window)
        self._window = window
        window.setWindowFlag(Qt.WindowType.FramelessWindowHint)
        bar = window.menuBar()
        assert bar is not None
        self._bar = bar
        bar.setNativeMenuBar(False)
        bar.setMinimumHeight(34)
        bar.setStyleSheet(
            "QMenuBar::item { padding: 5px 7px; }"
            f"QMenuBar::item:selected {{ background: {THEME.tint}; }}"
        )
        bar.installEventFilter(self)

        title = QLabel(window.windowTitle(), bar)
        title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        title.setStyleSheet(f"color: {THEME.muted}; padding: 0 8px;")
        window.windowTitleChanged.connect(title.setText)
        bar.setCornerWidget(title, Qt.Corner.TopLeftCorner)

        buttons = QWidget(bar)
        buttons.setObjectName("windowControls")
        buttons.setStyleSheet(f"""
            QToolButton {{ background: {THEME.raised}; color: {THEME.ink};
                border: 1px solid {THEME.edge}; border-radius: 3px; }}
            QToolButton:hover {{ background: {THEME.edge}; border-color: {THEME.muted}; }}
            QToolButton:pressed {{ background: {THEME.tint}; }}
            QToolButton#windowClose:hover {{ background: {THEME.alert}; }}
        """)
        row = QHBoxLayout(buttons)
        row.setContentsMargins(3, 3, 6, 3)
        row.setSpacing(3)
        self.minimise = self._button(buttons, "Minimize", "minimise")
        self.maximise = self._button(buttons, "Maximize", "maximise")
        self.close = self._button(buttons, "Close", "close")
        self.close.setObjectName("windowClose")
        for button in (self.minimise, self.maximise, self.close):
            row.addWidget(button)
        self.minimise.clicked.connect(window.showMinimized)
        self.maximise.clicked.connect(self.toggle_maximised)
        self.close.clicked.connect(window.close)
        bar.setCornerWidget(buttons, Qt.Corner.TopRightCorner)

        edge, cursor = Qt.Edge, Qt.CursorShape
        borders = (
            (edge.TopEdge, cursor.SizeVerCursor),
            (edge.BottomEdge, cursor.SizeVerCursor),
            (edge.LeftEdge, cursor.SizeHorCursor),
            (edge.RightEdge, cursor.SizeHorCursor),
            (edge.TopEdge | edge.LeftEdge, cursor.SizeFDiagCursor),
            (edge.TopEdge | edge.RightEdge, cursor.SizeBDiagCursor),
            (edge.BottomEdge | edge.LeftEdge, cursor.SizeBDiagCursor),
            (edge.BottomEdge | edge.RightEdge, cursor.SizeFDiagCursor),
        )
        self._borders = [_ResizeEdge(window, edges, shape) for edges, shape in borders]
        window.installEventFilter(self)
        self._refresh()

    @staticmethod
    def _button(parent: QWidget, label: str, mark: str) -> QToolButton:
        button = QToolButton(parent)
        button.setFixedSize(BUTTON_SIZE)
        button.setIconSize(QSize(ICON_SIZE, ICON_SIZE))
        button.setIcon(_icon(mark))
        button.setToolTip(label)
        button.setAccessibleName(label)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        return button

    def toggle_maximised(self) -> None:
        if self._window.isMaximized():
            self._window.showNormal()
        else:
            self._window.showMaximized()

    def _refresh(self) -> None:
        maximised = self._window.isMaximized()
        label = "Restore" if maximised else "Maximize"
        self.maximise.setToolTip(label)
        self.maximise.setAccessibleName(label)
        self.maximise.setIcon(_icon("restore" if maximised else "maximise"))
        width, height = self._window.width(), self._window.height()
        c, e = _CORNER, _EDGE
        rectangles = (
            (c, 0, max(0, width - 2 * c), e),
            (c, height - e, max(0, width - 2 * c), e),
            (0, c, e, max(0, height - 2 * c)),
            (width - e, c, e, max(0, height - 2 * c)),
            (0, 0, c, c),
            (width - c, 0, c, c),
            (0, height - c, c, c),
            (width - c, height - c, c, c),
        )
        for border, rectangle in zip(self._borders, rectangles, strict=True):
            border.setGeometry(*rectangle)
            border.setVisible(not maximised and not self._window.isFullScreen())
            border.raise_()

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        # Looked up, not assumed: the collector can clear these attributes while
        # Qt is still delivering the window's last events, and an exception raised
        # in here is one PyQt answers by ending the process.
        if event is None or "_window" not in vars(self):
            return False
        if watched is self._window and event.type() in (
            QEvent.Type.Resize,
            QEvent.Type.Show,
            QEvent.Type.WindowStateChange,
        ):
            self._refresh()
        if (
            watched is self._bar
            and isinstance(event, QMouseEvent)
            and event.button() == Qt.MouseButton.LeftButton
            and self._bar.actionAt(event.pos()) is None
        ):
            if event.type() == QEvent.Type.MouseButtonDblClick:
                self.toggle_maximised()
                return True
            if event.type() == QEvent.Type.MouseButtonPress:
                handle = self._window.windowHandle()
                if handle is not None:
                    return handle.startSystemMove()
        return super().eventFilter(watched, event)


def install_window_controls(window: QMainWindow) -> WindowControls | None:
    """Replace only WSL's undersized window frame."""
    return WindowControls(window) if is_wsl() else None
