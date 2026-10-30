"""Optional explanations that the reader can open without leaving the view."""

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QSizePolicy, QToolButton, QVBoxLayout, QWidget

from zodiarc.gui.theme import TIGHT, caption_font
from zodiarc.style import THEME


class Disclosure(QWidget):
    """A keyboard-accessible heading and a body that starts closed."""

    def __init__(self, title: str, content: QWidget) -> None:
        super().__init__()
        self.content = content
        self.button = QToolButton()
        self.button.setText(title)
        self.button.setFont(caption_font(self.button.font()))
        self.button.setCheckable(True)
        self.button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button.setAccessibleName(title)
        self.button.setStyleSheet(
            f"QToolButton {{ color: {THEME.muted}; border: none; padding: 2px; }}"
            f"QToolButton:hover, QToolButton:checked {{ color: {THEME.accent}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(TIGHT)
        layout.addWidget(self.button, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(content)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        self.button.toggled.connect(self._open)
        self._open(False)

    def _open(self, opened: bool) -> None:
        self.content.setVisible(opened)
        self.button.setArrowType(Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow)
        self.button.setToolTip(f"{'Hide' if opened else 'Show'} {self.button.text().lower()}")
        self.updateGeometry()
