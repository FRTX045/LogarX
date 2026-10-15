"""Compact grips stay centered, and the full divider still resizes panels."""

from __future__ import annotations

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QColor, QEnterEvent, QMouseEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QWidget

from logarc.gui.splitter import PanelSplitter
from logarc.style import THEME


@pytest.fixture(params=[Qt.Orientation.Horizontal, Qt.Orientation.Vertical])
def splitter(qt_app: QApplication, request: pytest.FixtureRequest):
    widget = PanelSplitter(request.param)
    widget.resize(400, 400)
    widget.addWidget(QWidget())
    widget.addWidget(QWidget())
    widget.show()
    qt_app.processEvents()
    yield widget
    widget.close()


def test_only_a_short_centered_grip_is_blue(qt_app: QApplication, splitter: PanelSplitter) -> None:
    handle = splitter.handle(1)
    assert handle is not None
    QApplication.sendEvent(handle, QEvent(QEvent.Type.Leave))
    image = handle.grab().toImage()
    blue = [
        QPoint(x, y)
        for x in range(image.width())
        for y in range(image.height())
        if image.pixelColor(x, y).blue() > 100
    ]
    assert blue, "the divider needs a visible resize affordance"
    xs, ys = [point.x() for point in blue], [point.y() for point in blue]
    ratio = image.devicePixelRatio()
    long_span, short_span = (
        (max(ys) - min(ys) + 1, max(xs) - min(xs) + 1)
        if splitter.orientation() == Qt.Orientation.Horizontal
        else (max(xs) - min(xs) + 1, max(ys) - min(ys) + 1)
    )
    assert 28 * ratio <= long_span <= 34 * ratio
    assert short_span <= 4 * ratio
    assert abs((min(xs) + max(xs)) / 2 - (image.width() - 1) / 2) <= 1
    assert abs((min(ys) + max(ys)) / 2 - (image.height() - 1) / 2) <= 1
    assert image.pixelColor(0, 0) == QColor(THEME.chrome)


def test_hover_brightens_only_the_grip(qt_app: QApplication, splitter: PanelSplitter) -> None:
    handle = splitter.handle(1)
    assert handle is not None
    QApplication.sendEvent(handle, QEvent(QEvent.Type.Leave))
    before = handle.grab().toImage()
    at = handle.rect().center()
    QApplication.sendEvent(
        handle, QEnterEvent(QPointF(at), QPointF(at), QPointF(handle.mapToGlobal(at)))
    )
    after = handle.grab().toImage()
    center = QPoint(after.width() // 2, after.height() // 2)
    assert after.pixelColor(center).blue() > before.pixelColor(center).blue()
    assert after.pixelColor(0, 0) == QColor(THEME.chrome)


def test_dragging_away_from_the_grip_still_resizes_panels(
    qt_app: QApplication, splitter: PanelSplitter
) -> None:
    handle = splitter.handle(1)
    assert handle is not None
    horizontal = splitter.orientation() == Qt.Orientation.Horizontal
    at = QPoint(handle.width() // 2, 10) if horizontal else QPoint(10, handle.height() // 2)
    moved = at + (QPoint(60, 0) if horizontal else QPoint(0, 60))
    before = splitter.sizes()
    QTest.mousePress(handle, Qt.MouseButton.LeftButton, pos=at)
    QApplication.sendEvent(
        handle,
        QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(moved),
            QPointF(handle.mapToGlobal(moved)),
            Qt.MouseButton.NoButton,
            Qt.MouseButton.LeftButton,
            Qt.KeyboardModifier.NoModifier,
        ),
    )
    QTest.mouseRelease(handle, Qt.MouseButton.LeftButton)
    qt_app.processEvents()
    assert splitter.sizes()[0] >= before[0] + 50
    assert splitter.handleWidth() == 7
