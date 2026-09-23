"""Every window a test built is destroyed when that test ends.

Not by the garbage collector, which is what used to happen. A closed window is
held in a reference cycle — menu lambdas and helpers such as `FullScreen` point
back at it — so it outlived its test and was freed whenever the collector next
ran. That could be in the middle of Qt delivering an event to some other widget,
and on the Linux runners, under coverage, that crashed the process about once in
every thirteen jobs: always in a different test, never in the one at fault.

The two tests below run in order. The first walks away from an open window; the
second checks nothing from it is still alive in Qt.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QApplication

from logarc.gui.app import MainWindow


def test_a_test_may_walk_away_from_an_open_window(qt_app: QApplication) -> None:
    window = MainWindow()
    window.show()
    qt_app.processEvents()
    assert window.isVisible()


def test_the_next_test_finds_no_window_left_alive(qt_app: QApplication) -> None:
    leftover = [type(widget).__name__ for widget in qt_app.topLevelWidgets()]
    assert leftover == [], f"still alive from an earlier test: {leftover}"
