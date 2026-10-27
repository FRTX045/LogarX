"""Request details that readers open one section at a time."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QColor, QPalette, QTextCharFormat, QTextCursor, QTextOption
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from logarx.gui._qt import required
from logarx.gui.evidence_view import ALERT_COLOUR
from logarx.gui.theme import TIGHT, caption_font
from logarx.style import EVIDENCE_INK, EVIDENCE_MUTED, PAPER, PAPER_EDGE, THEME

if TYPE_CHECKING:
    from PyQt6.QtGui import QFont, QResizeEvent

    from logarx.gui.evidence_view import Detail


class _Content(QTextEdit):
    """Wrap selectable, literal evidence inside the detail pane's one scrollbar."""

    def __init__(self, font: QFont) -> None:
        super().__init__()
        self.setFont(font)
        self.setReadOnly(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        colours = self.palette()
        colours.setColor(QPalette.ColorRole.Base, QColor(PAPER))
        colours.setColor(QPalette.ColorRole.Text, QColor(EVIDENCE_INK))
        self.setPalette(colours)
        document = required(self.document(), "evidence document")
        layout = required(document.documentLayout(), "text layout")
        layout.documentSizeChanged.connect(self._fit_height)

    def set_lines(self, lines: list[tuple[str, str]]) -> None:
        self.clear()
        cursor = self.textCursor()
        for index, (text, colour) in enumerate(lines):
            if index:
                cursor.insertBlock()
            formatting = QTextCharFormat()
            formatting.setForeground(QColor(colour))
            cursor.insertText(text, formatting)
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.setTextCursor(cursor)
        self._fit_height()

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._fit_height()

    def _fit_height(self) -> None:
        document = required(self.document(), "evidence document")
        height = math.ceil(document.size().height()) + 2 * self.frameWidth() + 2
        if self.height() != height:
            self.setFixedHeight(height)


class _Section(QWidget):
    def __init__(self, title: str, font: QFont) -> None:
        super().__init__()
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.button = QToolButton()
        self.button.setText(title)
        self.button.setFont(caption_font(self.button.font()))
        self.button.setCheckable(True)
        self.button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.button.setStyleSheet(
            f"QToolButton {{ color: {THEME.ink}; background: {THEME.raised};"
            f" border: none; border-bottom: 1px solid {THEME.line}; padding: 5px; text-align: left; }}"
            f"QToolButton:hover {{ background: {THEME.tint}; }}"
        )
        self.content = _Content(font)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.button)
        layout.addWidget(self.content)
        self.button.toggled.connect(self._open)
        self._open(False)

    def _open(self, opened: bool) -> None:
        self.button.setArrowType(Qt.ArrowType.DownArrow if opened else Qt.ArrowType.RightArrow)
        self.button.setToolTip(f"{'Hide' if opened else 'Show'} {self.button.text().lower()}")
        self.content.setVisible(opened)


class EvidenceDetails(QScrollArea):
    """All sections start closed; each keeps the reader's choice across rows."""

    def __init__(self, font: QFont) -> None:
        super().__init__()
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        colours = self.palette()
        colours.setColor(QPalette.ColorRole.Base, QColor(PAPER))
        colours.setColor(QPalette.ColorRole.Window, QColor(PAPER))
        colours.setColor(QPalette.ColorRole.Text, QColor(EVIDENCE_INK))
        self.setPalette(colours)
        self.setObjectName("evidenceDetails")
        self.setStyleSheet(f"QScrollArea#evidenceDetails {{ border: 1px solid {PAPER_EDGE}; }}")
        body = QWidget()
        body.setPalette(colours)
        body.setAutoFillBackground(True)
        layout = QVBoxLayout(body)
        layout.setContentsMargins(TIGHT, TIGHT, TIGHT, TIGHT)
        layout.setSpacing(TIGHT)
        self.warning = QLabel()
        self.warning.setWordWrap(True)
        self.warning.setTextFormat(Qt.TextFormat.PlainText)
        self.warning.setStyleSheet(f"color: {ALERT_COLOUR};")
        layout.addWidget(self.warning)
        self.sections = {
            key: _Section(title, font)
            for key, title in (
                ("source", "Source"),
                ("request", "Request"),
                ("response", "Response"),
                ("client", "Client"),
                ("raw", "Raw line"),
            )
        }
        for section in self.sections.values():
            layout.addWidget(section)
        layout.addStretch(1)
        self.setWidget(body)
        self.clear()

    def sizeHint(self) -> QSize:  # noqa: N802
        # An empty scroll area otherwise asks for almost no height, leaving
        # the shared splitter's detail pane at its minimum on first opening.
        return QSize(256, 192)

    def clear(self) -> None:
        self.warning.clear()
        self.warning.hide()
        for section in self.sections.values():
            section.content.clear()
            section.hide()

    def show_detail(self, detail: Detail) -> None:
        groups: dict[str, list[tuple[str, str]]] = {key: [] for key in self.sections}
        groups["source"].append((f"Source (log file:line): {detail.source}", EVIDENCE_MUTED))
        warnings = [f"Source warning: {detail.note}"] if detail.note else []
        for label, value, colour in detail.fields:
            if not label and colour == ALERT_COLOUR:
                warnings.append(value)
                continue
            if label.startswith("Time"):
                key = "source"
            elif label.startswith("Response"):
                key = "response"
            elif label.startswith(("Client IP", "User agent")):
                key = "client"
            else:
                key = "request"
            groups[key].append((f"{label}: {value}" if label else value, colour))
        if detail.raw is not None:
            groups["raw"] = [
                ("Exact text from the source log (as logged):", EVIDENCE_MUTED),
                (detail.raw, EVIDENCE_INK),
            ]
        self.warning.setText("\n".join(warnings))
        self.warning.setVisible(bool(warnings))
        for key, section in self.sections.items():
            section.content.set_lines(groups[key])
            section.setVisible(bool(groups[key]))
