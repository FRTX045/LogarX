"""The reconstruction canvas keeps its grid while waiting for a selection."""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import QApplication

from logarc.gui.canvas import STARTUP_MESSAGE, WAITING_MESSAGE, ActivityCanvas
from logarc.style import PAPER


@pytest.mark.parametrize("message", [STARTUP_MESSAGE, WAITING_MESSAGE])
@pytest.mark.parametrize("scale", [0.15, 1.0, 6.0])
def test_grid_covers_empty_canvas_at_every_zoom(
    qt_app: QApplication, message: str, scale: float
) -> None:
    canvas = ActivityCanvas()
    canvas.resize(640, 480)
    canvas.show_graph_placeholder(message)
    canvas.show()
    qt_app.processEvents()
    canvas.resetTransform()
    canvas.scale(scale, scale)
    qt_app.processEvents()

    viewport = canvas.viewport()
    assert viewport is not None
    image = viewport.grab().toImage()
    ground = QColor(PAPER)
    # Clear patches near all four corners, away from the prompt and corner
    # button. Each should contain a similar density of subtle dots even when
    # the content is greatly enlarged or reduced.
    for left in (20, image.width() - 120):
        for top in (20, image.height() - 120):
            marked = sum(
                image.pixelColor(x, y).red() > ground.red() + 5
                for x in range(left, left + 80)
                for y in range(top, top + 80)
            )
            assert marked >= 32, f"Grid missing or too sparse at {scale=} in {(left, top)}"

    canvas.close()
