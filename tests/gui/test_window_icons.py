"""The window's side of activity icons: what it hands the canvas, the legend and
Preferences, and what it keeps.

A module of its own so the settings these tests write stay out of
`test_window.py`'s, which several of its tests clear by hand.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QDialog

from conftest import settled
from logarc.case import Case
from logarc.core.activity import ActivityCategory
from logarc.detect.ruleset import PackText, RuleSet
from logarc.gui import app
from logarc.gui.app import MainWindow
from logarc.gui.icon_set import KIND_NAMES, icons_dir
from logarc.gui.icons import read_kind_icons
from logarc.gui.preferences import PreferencesDialog
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


SQUARE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">'
    '<rect x="1" y="1" width="8" height="8" fill="#00ff00"/></svg>'
)


def _preferences_answer(
    monkeypatch: pytest.MonkeyPatch,
    picked: object,
    *,
    accepted: bool,
    before_ok: Callable[[], None] = lambda: None,
) -> None:
    """Open Preferences as the window does; pick `picked` for Injection, then OK or Cancel."""

    def run(dialog: PreferencesDialog) -> int:
        monkeypatch.setattr(dialog.icons, "_pick", lambda kind: picked)
        dialog.icons.buttons[ActivityCategory.INJECTION].click()
        before_ok()
        code = QDialog.DialogCode.Accepted if accepted else QDialog.DialogCode.Rejected
        return int(code.value)

    monkeypatch.setattr(PreferencesDialog, "exec", run)


def test_preferences_open_showing_the_icons_in_force(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    app._settings().setValue("icons/ssrf", "zap")
    seen: list[dict[ActivityCategory, object]] = []

    def run(dialog: PreferencesDialog) -> int:
        seen.append(dialog.chosen_icons())
        return int(QDialog.DialogCode.Rejected.value)

    monkeypatch.setattr(PreferencesDialog, "exec", run)
    window = MainWindow()
    try:
        window._show_preferences()
        assert seen == [{ActivityCategory.SSRF: "zap"}]
    finally:
        window.close()


def test_a_kind_icon_applies_on_ok(qt_app: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    _preferences_answer(monkeypatch, "bug", accepted=True)
    window = MainWindow()
    try:
        window._show_preferences()
        assert read_kind_icons(app._settings().value) == {ActivityCategory.INJECTION: "bug"}
        assert dict(window._canvas.icons.kinds) == {ActivityCategory.INJECTION: "bug"}
    finally:
        window.close()


def test_a_kind_icon_does_not_apply_on_cancel(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    _preferences_answer(monkeypatch, "bug", accepted=False)
    window = MainWindow()
    try:
        window._show_preferences()
        assert read_kind_icons(app._settings().value) == {}
        assert dict(window._canvas.icons.kinds) == {}
    finally:
        window.close()


def test_a_file_is_copied_on_ok_and_not_on_cancel(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    logo = tmp_path / "logo.svg"
    logo.write_text(SQUARE, encoding="utf-8")
    window = MainWindow()
    try:
        _preferences_answer(monkeypatch, logo, accepted=False)
        window._show_preferences()
        assert not icons_dir().exists()

        _preferences_answer(monkeypatch, logo, accepted=True)
        window._show_preferences()
        assert (icons_dir() / "logo.svg").read_text(encoding="utf-8") == SQUARE
        assert read_kind_icons(app._settings().value) == {
            ActivityCategory.INJECTION: "file:logo.svg"
        }
    finally:
        window.close()


def test_a_file_gone_before_ok_keeps_the_kinds_icon(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Picked, then deleted before OK: the copy cannot be made. The kind keeps
    the icon it had rather than falling back to its default, and the window
    says why."""
    app._settings().setValue("icons/injection", "bug")
    logo = tmp_path / "logo.svg"
    logo.write_text(SQUARE, encoding="utf-8")
    _preferences_answer(monkeypatch, logo, accepted=True, before_ok=logo.unlink)
    window = MainWindow()
    try:
        window._show_preferences()
        assert read_kind_icons(app._settings().value) == {ActivityCategory.INJECTION: "bug"}
        assert window._status.text() == (
            "logo.svg could not be copied into your icons folder, "
            "so Injection keeps the icon it had."
        )
    finally:
        window.close()
