"""The strip that offers to keep how the graph has been arranged.

Run without a display. What is checked is which widget is showing and what it
says, none of which the offscreen platform's missing fonts can hide. How wide
the words come out is a fact about the platform's font and is not asserted on.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from zodiarc.gui.arrangement_bar import ArrangementBar


def test_it_starts_with_nothing_to_say(qt_app: QApplication) -> None:
    """Built with the window, long before a graph is drawn. Visible from the
    start, it would announce an unsaved arrangement over an empty canvas.
    """
    bar = ArrangementBar()

    assert not bar.isVisible()
    assert bar.text() == ""


def test_it_appears_and_says_how_many_moved(qt_app: QApplication) -> None:
    bar = ArrangementBar()
    bar.show()

    bar.show_moved(2)

    assert bar.isVisible()
    assert "2 activities" in bar.text()


def test_nothing_moved_takes_it_away_again(qt_app: QApplication) -> None:
    """The reader saves, and the strip has to go. Left up, it would say the
    arrangement is unsaved directly after saving it.
    """
    bar = ArrangementBar()
    bar.show()
    bar.show_moved(2)
    assert bar.isVisible(), "premise: it was offering"

    bar.show_moved(0)

    assert not bar.isVisible()


def test_the_buttons_ask_rather_than_act(qt_app: QApplication) -> None:
    """The strip owns no behaviour.

    What saving *is* belongs to the window, which already does it for the menu
    entry and the shortcut. Done here as well, it would be a second
    implementation to keep in step with the key and the store.
    """
    bar = ArrangementBar()
    asked: list[str] = []
    bar.save_requested.connect(lambda: asked.append("save"))
    bar.reset_requested.connect(lambda: asked.append("reset"))

    bar._save.click()
    bar._reset.click()

    assert asked == ["save", "reset"]


def test_both_buttons_say_what_they_will_do(qt_app: QApplication) -> None:
    """`Reset` throws away a saved arrangement as well as the moves on screen,
    which is not something to find out by pressing it.
    """
    bar = ArrangementBar()

    assert bar._save.toolTip()
    assert "forget" in bar._reset.toolTip()
