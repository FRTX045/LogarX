"""Driving a drag on the canvas, for tests that need a real gesture.

A plain module rather than a fixture: `tests/gui/test_window.py` and
`tests/gui/test_canvas_drag.py` both need these, and the mouse plumbing copied
into each would be two chances for a test to press somewhere it did not mean to.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from on_canvas import node_item
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication

if TYPE_CHECKING:
    from logarx.gui.canvas import ActivityCanvas

__all__ = ["drag", "hold", "let_go", "mouse", "press_on"]


def mouse(canvas: ActivityCanvas, kind: QEvent.Type, at: QPoint, *, held: bool) -> None:
    button = Qt.MouseButton.LeftButton
    QApplication.sendEvent(
        canvas.viewport(),
        QMouseEvent(
            kind,
            QPointF(at),
            canvas.viewport().mapToGlobal(at).toPointF(),
            Qt.MouseButton.NoButton if kind == QEvent.Type.MouseMove else button,
            button if held else Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
        ),
    )


def press_on(canvas: ActivityCanvas, node_id: str) -> QPoint:
    """Put the mouse down on a node, and prove that is where it landed.

    Checked rather than assumed: the viewport is inset from the view by the
    canvas border, so a point mapped from the scene can miss by a pixel or two.
    A press that lands on empty ground pans instead of dragging, and every test
    below would then pass while testing nothing.
    """
    item = node_item(canvas, node_id)
    at = canvas.viewport().mapFrom(canvas, canvas.mapFromScene(item.scenePos()))
    assert canvas.itemAt(at) in (item, *item.childItems()), "premise: the press lands on the node"
    mouse(canvas, QEvent.Type.MouseButtonPress, at, held=True)
    return at


def hold(canvas: ActivityCanvas, node_id: str, by: QPoint) -> QPoint:
    """Press and move, without letting go. Returns where the mouse now is."""
    at = press_on(canvas, node_id)
    mouse(canvas, QEvent.Type.MouseMove, at + by, held=True)
    return at + by


def let_go(canvas: ActivityCanvas, at: QPoint) -> None:
    mouse(canvas, QEvent.Type.MouseButtonRelease, at, held=False)


def drag(canvas: ActivityCanvas, node_id: str, by: QPoint) -> QPointF:
    """Press, move, release. Returns how far that is in scene units."""
    at = press_on(canvas, node_id)
    mouse(canvas, QEvent.Type.MouseMove, at + by, held=True)
    mouse(canvas, QEvent.Type.MouseButtonRelease, at + by, held=False)
    return canvas.mapToScene(at + by) - canvas.mapToScene(at)
