"""The bookmark ribbon: one shape, drawn wherever a saved thing appears.

Drawn rather than taken from a font or an icon theme, for the reason the window
buttons are: a glyph is painted in the font's own colours where it has them, and
the colour here is the point — it says which category.
"""

from __future__ import annotations

import html
from typing import Final

from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtGui import QBrush, QColor, QIcon, QPainter, QPen, QPixmap, QPolygonF

__all__ = ["Mark", "ribbon_icon", "ribbon_polygon", "ribbon_tip"]

#: How a panel is told to mark something: the category's colour, and the words
#: its tooltip gives (which bookmark, in which category).
Mark = tuple[str, str]

#: How far up the ribbon's notch rises, as a share of its height.
_NOTCH: Final = 0.32


def ribbon_tip(text: str) -> str:
    """A mark's words as a tooltip Qt shows exactly as written, line breaks kept.

    A note is typed by a reader and a request's path by whoever sent it, and Qt
    reads any tooltip that looks like markup as markup: unescaped, a path of
    `/<h1>...` would draw a heading. Escaped as the evidence cells' tooltips are.
    """
    if not text:
        return ""
    return f"<span style='white-space:pre-wrap'>{html.escape(text)}</span>"


def ribbon_polygon(x: float, y: float, width: float, height: float) -> QPolygonF:
    """A ribbon hanging from `(x, y)`, its foot cut into a notch."""
    return QPolygonF(
        [
            QPointF(x, y),
            QPointF(x + width, y),
            QPointF(x + width, y + height),
            QPointF(x + width / 2, y + height * (1 - _NOTCH)),
            QPointF(x, y + height),
        ]
    )


def ribbon_icon(colour: str, *, size: int = 14, hollow: bool = False) -> QIcon:
    """The ribbon as an icon, filled to say "saved", hollow to offer saving."""
    icon = QIcon()
    for ratio in (1, 2, 3):
        pixmap = QPixmap(size * ratio, size * ratio)
        pixmap.setDevicePixelRatio(ratio)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(colour))
        pen.setWidthF(1.4)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush if hollow else QBrush(QColor(colour)))
        painter.drawPolygon(ribbon_polygon(size * 0.24, size * 0.08, size * 0.52, size * 0.84))
        painter.end()
        icon.addPixmap(pixmap)
    return icon
