"""The window's side of activity icons: what it hands the canvas, the legend and
Preferences, and what it keeps.

A module of its own so the settings these tests write stay out of
`test_window.py`'s, which several of its tests clear by hand.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.case import Case
from logarc.core.activity import ActivityCategory
from logarc.detect.ruleset import PackText, RuleSet
from logarc.gui import app
from logarc.gui.app import MainWindow
from logarc.gui.icon_set import KIND_NAMES
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


IP = "203.0.113.5"
LINES = [
    f'{IP} - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 2326 "-" "Mozilla/5.0"',
    f'{IP} - - [10/Oct/2020:13:55:04 +0000] "GET /?id=1%27%20UNION%20SELECT%20pw HTTP/1.1" 200 12 "-" "Mozilla/5.0"',
]


@pytest.fixture
def case_root(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return tmp_path / "case"


def _opened(qt_app: QApplication, root: Path) -> MainWindow:
    window = MainWindow()
    window.show()
    window._load_case(root)
    settled(qt_app)
    window._reconstruct(IP)
    settled(qt_app)
    return window


def test_the_legend_names_the_kinds_of_the_graph_on_show(
    qt_app: QApplication, case_root: Path
) -> None:
    window = _opened(qt_app, case_root)
    try:
        assert window._result is not None
        on_graph = {node.category for node in window._result.trace.nodes}
        assert ActivityCategory.INJECTION in on_graph, "premise: the probe was caught"
        assert window._legend.kinds() == tuple(
            KIND_NAMES[kind] for kind in ActivityCategory if kind in on_graph
        )
    finally:
        window.close()


def test_the_legend_has_no_kinds_before_a_client(qt_app: QApplication) -> None:
    window = MainWindow()
    try:
        assert window._legend.kinds() == ()
    finally:
        window.close()
