"""The window and the taskbar draw the application's own icon, not Qt's blank one."""

from __future__ import annotations

import inspect

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from zodiarc.gui import app
from zodiarc.gui.app_icon import application_icon, install_application_icon


def test_the_application_icon_is_the_zodiarc_mark(qt_app: QApplication) -> None:
    icon = application_icon()

    assert not icon.isNull()
    assert any(size.width() >= 256 for size in icon.availableSizes())
    assert not icon.pixmap(32).isNull()


def test_installing_it_sets_the_icon_every_window_inherits(qt_app: QApplication) -> None:
    before = qt_app.windowIcon()
    try:
        qt_app.setWindowIcon(QIcon())
        assert qt_app.windowIcon().isNull()

        install_application_icon(qt_app)

        assert not qt_app.windowIcon().isNull()
    finally:
        qt_app.setWindowIcon(before)


def test_the_entry_point_installs_it_before_the_window_exists() -> None:
    """Read from the source: `main` runs the event loop, which a test cannot enter."""
    source = inspect.getsource(app.main)

    assert "install_application_icon(app)" in source
    assert source.index("install_application_icon(app)") < source.index("MainWindow()")
