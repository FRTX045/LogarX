"""Text roles must retain disabled states and follow operation state changes."""

import threading

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QLabel, QMessageBox

from zodiarc.gui.app import MainWindow
from zodiarc.gui.theme import colour_text
from zodiarc.style import THEME


def test_role_changes_preserve_disabled_text(qt_app):
    label = QLabel("Logged address")
    role = QPalette.ColorRole.WindowText
    disabled = label.palette().color(QPalette.ColorGroup.Disabled, role)
    colour_text(label, THEME.identity)
    colour_text(label, THEME.timestamp)
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive):
        assert label.palette().color(group, role) == QColor(THEME.timestamp)
    assert label.palette().color(QPalette.ColorGroup.Disabled, role) == disabled
    label.close()


def test_status_color_follows_error_running_stopping_and_idle(qt_app, monkeypatch):
    monkeypatch.setattr(QMessageBox, "exec", lambda self: 0)
    window = MainWindow()
    role = QPalette.ColorRole.WindowText

    def colour():
        return window._status.palette().color(QPalette.ColorGroup.Active, role)

    window.report_error("Could not read source", "")
    assert colour() == QColor(THEME.alert)
    window._busy("Reading", stop=threading.Event())
    assert colour() == QColor(THEME.accent)
    window._request_cancel()
    assert colour() == QColor(THEME.warning)
    window._idle("Stopped")
    assert colour() == QColor(THEME.muted)
    window.close()
