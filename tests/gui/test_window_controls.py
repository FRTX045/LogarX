"""The enlarged window buttons operate the window and preserve menu gestures."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PyQt6.QtCore import QPoint, QSize, Qt
from PyQt6.QtGui import QResizeEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QMainWindow

from logarc.gui import window_controls
from logarc.gui.window_controls import WindowControls


@pytest.fixture
def frame(qt_app: QApplication) -> Iterator[tuple[QMainWindow, WindowControls]]:
    window = QMainWindow()
    window.setWindowTitle("logarc")
    window.resize(900, 500)
    window.menuBar().addMenu("Case").addAction("Open case…")
    controls = WindowControls(window)
    window.show()
    qt_app.processEvents()
    yield window, controls
    window.close()
    qt_app.processEvents()


def test_all_three_buttons_have_compact_visible_marks(
    frame: tuple[QMainWindow, WindowControls],
) -> None:
    _, controls = frame
    for button in (controls.minimise, controls.maximise, controls.close):
        assert button.isVisible()
        assert button.width() == 34 and button.height() == 28
        assert button.iconSize().width() == 15
        assert not button.icon().isNull()
        assert button.accessibleName()


def test_maximise_toggles_restore(
    frame: tuple[QMainWindow, WindowControls], qt_app: QApplication
) -> None:
    window, controls = frame
    QTest.mouseClick(controls.maximise, Qt.MouseButton.LeftButton)
    qt_app.processEvents()
    assert window.isMaximized()
    assert controls.maximise.accessibleName() == "Restore"
    assert all(border.isHidden() for border in controls._borders)

    QTest.mouseClick(controls.maximise, Qt.MouseButton.LeftButton)
    qt_app.processEvents()
    assert not window.isMaximized()
    assert controls.maximise.accessibleName() == "Maximize"
    assert all(border.isVisible() for border in controls._borders)


def test_minimise_and_close_operate_the_window(
    frame: tuple[QMainWindow, WindowControls], qt_app: QApplication
) -> None:
    window, controls = frame
    QTest.mouseClick(controls.minimise, Qt.MouseButton.LeftButton)
    qt_app.processEvents()
    assert window.isMinimized()
    window.showNormal()
    qt_app.processEvents()
    QTest.mouseClick(controls.close, Qt.MouseButton.LeftButton)
    assert not window.isVisible()


def test_empty_title_strip_drags_but_menu_press_does_not(
    frame: tuple[QMainWindow, WindowControls], monkeypatch: pytest.MonkeyPatch
) -> None:
    window, _ = frame
    move = Mock(return_value=True)
    monkeypatch.setattr(window, "windowHandle", lambda: SimpleNamespace(startSystemMove=move))
    bar = window.menuBar()
    empty = QPoint(bar.width() // 2, bar.height() // 2)
    assert bar.actionAt(empty) is None
    QTest.mouseClick(bar, Qt.MouseButton.LeftButton, pos=empty)
    move.assert_called_once()

    move.reset_mock()
    action = bar.actions()[0]
    QTest.mouseClick(bar, Qt.MouseButton.LeftButton, pos=bar.actionGeometry(action).center())
    move.assert_not_called()
    assert action.menu().isVisible()
    action.menu().close()


def test_double_clicking_title_strip_maximises(
    frame: tuple[QMainWindow, WindowControls], qt_app: QApplication
) -> None:
    window, _ = frame
    bar = window.menuBar()
    QTest.mouseDClick(bar, Qt.MouseButton.LeftButton, pos=QPoint(bar.width() // 2, 20))
    qt_app.processEvents()
    assert window.isMaximized()


@pytest.mark.parametrize("index", range(8))
def test_each_resize_border_requests_native_resize(
    frame: tuple[QMainWindow, WindowControls], monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    window, controls = frame
    resize = Mock(return_value=True)
    monkeypatch.setattr(window, "windowHandle", lambda: SimpleNamespace(startSystemResize=resize))
    border = controls._borders[index]
    QTest.mousePress(border, Qt.MouseButton.LeftButton, pos=border.rect().center())
    resize.assert_called_once_with(border._edges)


def test_fullscreen_hides_resize_borders(
    frame: tuple[QMainWindow, WindowControls], qt_app: QApplication
) -> None:
    window, controls = frame
    window.showFullScreen()
    qt_app.processEvents()
    assert all(border.isHidden() for border in controls._borders)


def test_other_desktops_keep_their_window_frame(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(window_controls, "is_wsl", lambda: False)
    window = QMainWindow()
    before = window.windowFlags()
    assert window_controls.install_window_controls(window) is None
    assert window.windowFlags() == before
    window.close()


def test_an_event_after_the_controls_let_go_of_the_window_is_ignored(
    frame: tuple[QMainWindow, WindowControls], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The collector clears the controls' attributes while Qt is still delivering
    the window's last events. The filter assumed `_window` was there and raised
    inside Qt, which PyQt answers by ending the process."""
    window, controls = frame
    raised: list[object] = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: raised.append(exc))
    kept = dict(vars(controls))
    vars(controls).clear()
    try:
        QApplication.sendEvent(window, QResizeEvent(QSize(800, 400), QSize(900, 500)))
    finally:
        vars(controls).update(kept)

    assert raised == []
