"""The window's side of activity icons: what it hands the canvas, the legend and
Preferences, and what it keeps.

A module of its own so the settings these tests write stay out of
`test_window.py`'s, which several of its tests clear by hand.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory
from logarc.detect.ruleset import PackText, RuleSet
from logarc.gui import app
from logarc.gui.app import MainWindow
from logarc.rules_library import Library

MINE = """\
version: 1
rules:
  - id: mine_rule
    name: Mine
    category: injection
    severity: high
    icon: skull
    match:
      any:
        - {field: path, contains: "/mine"}
"""


@pytest.fixture(autouse=True)
def no_icons_kept() -> None:
    """Every test starts from the shipped icons."""
    stored = app._settings()
    for kind in ActivityCategory:
        stored.remove(f"icons/{kind.value}")


def test_the_window_hands_the_canvas_the_readers_kind_icons(qt_app: QApplication) -> None:
    app._settings().setValue("icons/injection", "bug")
    window = MainWindow()
    try:
        assert dict(window._canvas.icons.kinds) == {ActivityCategory.INJECTION: "bug"}
    finally:
        window.close()


def test_the_window_hands_the_canvas_its_rules_icons(qt_app: QApplication) -> None:
    window = MainWindow()
    try:
        window._take_rules(Library(RuleSet((PackText("mine", MINE),)), ()))
        assert dict(window._canvas.icons.rules) == {"mine_rule": "skull"}
    finally:
        window.close()
