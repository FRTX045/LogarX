"""The interface tests measure text in a real font, or their geometry is about no screen.

Offscreen Qt on Windows has no fonts of its own: it draws every character as a
box as wide as it is tall, so a caption measured there is twice as wide and a
quarter shorter than in the window. The conftest loads the system's Segoe UI
for that platform, and this holds it in place.
"""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QFont, QFontInfo, QFontMetricsF
from PyQt6.QtWidgets import QApplication


def test_text_is_measured_in_a_real_font(qt_app: QApplication) -> None:
    font = QFont()
    font.setPointSizeF(8)
    metrics = QFontMetricsF(font)

    assert QFontInfo(font).family(), "no font resolved: text is being measured as boxes"
    assert metrics.horizontalAdvance("iiii") < metrics.horizontalAdvance("MMMM")
