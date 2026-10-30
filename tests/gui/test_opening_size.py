"""How big the window first opens: from the screen it opens on, not one number.

At a fixed 1400 by 880 the graph opened barely wider than the client list, on
a screen with room to spare, and taller than a laptop's work area. A first
launch now takes most of a big screen, the extra going to the graph, and never
more than the screen has. A window that has been closed before reopens as it
was left.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QRect, QSize
from PyQt6.QtWidgets import QApplication

from zodiarc.gui.app import OPENING_PANELS, MainWindow, opening_size


@pytest.mark.parametrize(
    ("area", "size"),
    [
        (QRect(0, 0, 1920, 1032), QSize(1728, 929)),
        (QRect(0, 0, 3840, 2100), QSize(3456, 1890)),
        (QRect(0, 0, 1366, 728), QSize(1326, 688)),
        (QRect(0, 0, 1280, 680), QSize(1240, 640)),
    ],
)
def test_the_opening_size_follows_the_screen_and_never_passes_it(area: QRect, size: QSize) -> None:
    assert opening_size(area) == size


def test_a_first_launch_on_a_big_screen_gives_the_extra_width_to_the_graph(
    qt_app: QApplication,
) -> None:
    window = MainWindow()
    window.open_to(QRect(0, 0, 1920, 1032))
    window.show()
    qt_app.processEvents()

    clients, graph, evidence = window._splitter.sizes()
    assert (window.width(), window.height()) == (1728, 929)
    assert (clients, evidence) == (OPENING_PANELS[0], OPENING_PANELS[2])
    assert graph > OPENING_PANELS[1] + 300
    window.close()


def test_a_window_closed_before_reopens_as_it_was_left(qt_app: QApplication) -> None:
    first = MainWindow()
    first.resize(700, 600)
    first.show()
    qt_app.processEvents()
    left = (first.width(), first.height())
    first.close()
    qt_app.processEvents()

    again = MainWindow()
    again.open_to(QRect(0, 0, 1920, 1032))

    assert (again.width(), again.height()) == left
    again.close()
