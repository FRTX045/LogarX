"""Laptop defaults, explicit text sizes, and consistent table and monospace text."""

import os
import subprocess
import sys
from datetime import UTC, datetime
from threading import Event

import pytest
from PyQt6.QtGui import QFont, QFontInfo

from logarc.gui import prefs
from logarc.gui.app import MainWindow
from logarc.gui.panels import ClientTable
from logarc.gui.text_size import (
    MAX_POINTS,
    TextSize,
    automatic_points,
    points_for,
    remembered,
    stepped,
)
from logarc.gui.theme import caption_font, mono_font, ui_font
from logarc.storage.base import IpSummary


@pytest.mark.parametrize(
    ("width", "height", "expected"),
    [(1920, 1040, 12), (1536, 824, 11), (1280, 680, 11), (2560, 1400, 14), (0, 0, 12)],
)
def test_automatic_fits_logical_available_space(width, height, expected):
    assert points_for(TextSize.AUTOMATIC, width=width, height=height, system_points=9) == expected


def test_automatic_preserves_larger_system_text_but_explicit_size_can_override_it():
    assert points_for(TextSize.AUTOMATIC, width=1920, height=1040, system_points=18) == 18
    assert points_for(TextSize.COMPACT, width=1920, height=1040, system_points=18) == 11


@pytest.mark.parametrize(
    ("width", "height", "expected"),
    [(1920, 1040, 12), (1536, 824, 11), (1280, 680, 11), (2560, 1400, 14), (0, 0, 12)],
)
def test_automatic_points_fit_logical_available_space(width, height, expected):
    assert automatic_points(width=width, height=height, system_points=9) == expected


def test_automatic_points_keep_larger_system_text_within_the_range():
    assert automatic_points(width=1920, height=1040, system_points=15) == 15
    assert automatic_points(width=1920, height=1040, system_points=18) == MAX_POINTS


@pytest.mark.parametrize(
    ("points", "by", "expected"),
    [(11, 1, 12), (11, -1, 10), (16, 1, 16), (8, -1, 8), (11.4, 1, 12)],
)
def test_zoom_steps_are_whole_points_inside_the_range(points, by, expected):
    assert stepped(points, by) == expected


@pytest.mark.parametrize(
    ("points", "legacy", "expected"),
    [
        (10, None, 10),
        ("9", None, 9),
        ("11.0", None, 11),
        (40, None, 16),
        (-3, None, 8),
        ("abc", "compact", 11),
        (None, "Comfortable ", 12),
        (None, "large", 14),
        (None, "automatic", 13),
        (None, "nonsense", 13),
        (None, None, 13),
    ],
)
def test_remembered_zoom_falls_back_to_the_old_size_then_automatic(points, legacy, expected):
    assert remembered(points, legacy, automatic=13) == expected


@pytest.mark.parametrize("points", [11, 12, 14, 18])
def test_ip_font_matches_its_table_instead_of_a_separate_minimum(qt_app, points):
    before = qt_app.font()
    chosen = ui_font(before)
    chosen.setPointSizeF(points)
    qt_app.setFont(chosen)
    panel = None
    try:
        now = datetime(2026, 10, 20, tzinfo=UTC)
        panel = ClientTable()
        panel.show_clients([IpSummary("192.0.2.123", 5, now, now, 3, 0.2, 1000)])
        address = panel._table.item(0, 0)
        assert address is not None
        assert address.font().pointSizeF() == panel._table.font().pointSizeF() == points
        assert QFontInfo(address.font()).pixelSize() == QFontInfo(panel._table.font()).pixelSize()
        assert mono_font(8.5).pointSizeF() == points - 1
        assert caption_font(QFont()).pointSizeF() == points - 1
        assert ui_font().pointSizeF() == points
    finally:
        if panel is not None:
            panel.close()
        qt_app.setFont(before)


def test_changing_text_size_is_saved_and_explains_restart(qt_app):
    window = MainWindow()
    before = window.font().pointSizeF()
    window._apply_preferences({**window._prefs, prefs.TEXT_SIZE: TextSize.COMPACT})
    assert "Restart logarc" in window._status.text()
    assert window.font().pointSizeF() == before
    window.close()
    again = MainWindow()
    assert prefs.text_size_in(again._prefs) is TextSize.COMPACT
    again.close()


def test_saving_text_size_keeps_background_progress_and_cancellation(qt_app):
    window = MainWindow()
    stop = Event()
    window._busy("Processing logs", stop=stop)
    window._apply_preferences({**window._prefs, prefs.TEXT_SIZE: TextSize.COMPACT})
    assert window._stop is stop
    assert not window._progress.isHidden()
    assert not window._cancel.isHidden()
    window._request_cancel()
    assert stop.is_set()
    window.close()


THEMED_CLIENT = """
from datetime import UTC, datetime
from types import SimpleNamespace
import sys
from PyQt6.QtCore import QRect
from PyQt6.QtGui import QFontInfo
from PyQt6.QtWidgets import QApplication
from logarc.gui.panels import ClientTable
from logarc.gui.text_size import TextSize
from logarc.gui.theme import apply_theme
from logarc.storage.base import IpSummary

width, height, expected = map(int, sys.argv[1:4])
qt = QApplication([])
system = qt.font()
system.setPointSizeF(9)
qt.setFont(system)
qt.primaryScreen = lambda: SimpleNamespace(availableGeometry=lambda: QRect(0, 0, width, height))
apply_theme(qt, text_size=TextSize[sys.argv[4]])
panel = ClientTable()
now = datetime(2026, 10, 20, tzinfo=UTC)
panel.show_clients([IpSummary('192.0.2.123', 5, now, now, 3, 0.2, 1000)])
address = panel._table.item(0, 0)
assert qt.font().pointSizeF() == expected
assert address.font().pointSizeF() == panel._table.font().pointSizeF() == expected
assert QFontInfo(address.font()).pixelSize() == QFontInfo(panel._table.font()).pixelSize()
panel.close()
"""


@pytest.mark.parametrize(
    ("width", "height", "expected", "size"),
    [
        (1920, 1040, 12, TextSize.AUTOMATIC),
        (1536, 832, 11, TextSize.AUTOMATIC),
        (2560, 1400, 14, TextSize.AUTOMATIC),
        (2560, 1400, 11, TextSize.COMPACT),
        (1920, 1040, 14, TextSize.LARGE),
    ],
)
def test_startup_theme_sizes_the_ip_table_for_the_workspace(width, height, expected, size):
    # A separate application keeps Fusion, its palette and startup font out of
    # the shared test application used by unrelated geometry checks.
    result = subprocess.run(
        [sys.executable, "-c", THEMED_CLIENT, str(width), str(height), str(expected), size.name],
        capture_output=True,
        text=True,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "QT_SCALE_FACTOR": "1"},
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
