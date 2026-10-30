"""The window remembers its panel sizes and its own shape, and puts the panels
back when asked, after asking.

Run without a display. The offscreen platform has one 800 by 800 screen.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QByteArray
from PyQt6.QtWidgets import QApplication, QMessageBox
from test_window import _laid_out

from zodiarc.gui import app
from zodiarc.gui._qt import required
from zodiarc.gui.app import OPENING_PANELS, MainWindow

DRAGGED = [300, 700, 400]


def asked(
    monkeypatch: pytest.MonkeyPatch, *, reset: bool
) -> list[tuple[str, str, QMessageBox.StandardButton]]:
    """Answer the reset question, keeping what it said and what Enter would do."""
    said: list[tuple[str, str, QMessageBox.StandardButton]] = []

    def answer(box: QMessageBox) -> int:
        said.append((box.text(), box.informativeText(), box.standardButton(box.defaultButton())))
        if reset:
            (button,) = [b for b in box.buttons() if b.text() == "Reset"]
            button.click()
        return 0

    monkeypatch.setattr(QMessageBox, "exec", answer)
    return said


def test_panel_sizes_survive_a_restart(qt_app: QApplication) -> None:
    window, splitter = _laid_out()
    splitter.setSizes(DRAGGED)
    qt_app.processEvents()
    left = splitter.sizes()[0]
    assert left < 400, "premise: the drag took"
    window.close()

    again, splitter = _laid_out()
    assert splitter.sizes()[0] == left
    again.close()


def test_triage_and_evidence_splits_survive_a_restart(qt_app: QApplication) -> None:
    window, _splitter = _laid_out()
    window._triage.split.setSizes([100, 400])
    window._evidence.split.setSizes([300, 90])
    qt_app.processEvents()
    triage, evidence = window._triage.split.sizes(), window._evidence.split.sizes()
    window.close()

    again, _splitter = _laid_out()
    assert again._triage.split.sizes() == triage
    assert again._evidence.split.sizes() == evidence
    again.close()


def test_the_window_keeps_its_size_and_place(qt_app: QApplication) -> None:
    """Size and height on screen come back exactly. Across, the window cannot
    be tested here: its minimum width, 802 px, is wider than the offscreen
    screen, so Qt slides it left to keep it on screen."""
    window = MainWindow()
    window.resize(700, 520)
    window.move(30, 40)
    window.show()
    qt_app.processEvents()
    shape = window.geometry()
    window.close()

    again = MainWindow()
    again.show()
    qt_app.processEvents()
    assert again.size() == shape.size()
    assert again.geometry().y() == shape.y()
    again.close()


def test_a_maximised_window_reopens_maximised(qt_app: QApplication) -> None:
    window = MainWindow()
    window.showMaximized()
    qt_app.processEvents()
    window.close()

    again = MainWindow()
    again.show()
    qt_app.processEvents()
    assert again.isMaximized()
    again.close()


def test_nothing_saved_opens_as_today(qt_app: QApplication) -> None:
    window, splitter = _laid_out()
    assert splitter.sizes()[0] >= OPENING_PANELS[0] == 480
    window.close()


def test_a_saved_state_qt_cannot_read_is_ignored(qt_app: QApplication) -> None:
    stored = app._settings()
    stored.setValue("window/panels", QByteArray(b"nonsense"))
    stored.setValue("window/geometry", QByteArray(b"nonsense"))
    stored.setValue("window/triage_split", "not even bytes")
    window, splitter = _laid_out()
    assert splitter.sizes()[0] >= 480
    window.close()


def test_closing_in_full_screen_reopens_out_of_it(qt_app: QApplication) -> None:
    """Qt keeps full screen in a saved geometry, and full screen is a mode for a
    moment: closing in it saves the window as it was just before."""
    window = MainWindow()
    window.resize(700, 520)
    window.show()
    qt_app.processEvents()
    before = window.geometry()
    window._full_screen.apply(True)
    qt_app.processEvents()
    assert window.isFullScreen(), "premise"
    window.close()

    again = MainWindow()
    again.show()
    qt_app.processEvents()
    assert not again.isFullScreen()
    assert again.size() == before.size(), "the size it had before full screen, not the screen's"
    again.close()


def test_a_window_saved_off_screen_opens_on_a_screen(qt_app: QApplication) -> None:
    window = MainWindow()
    window.resize(700, 520)
    window.move(20_000, 20_000)
    window.show()
    qt_app.processEvents()
    window.close()

    again = MainWindow()
    again.show()
    qt_app.processEvents()
    frame = again.frameGeometry()
    assert any(screen.availableGeometry().intersects(frame) for screen in qt_app.screens())
    again.close()


def test_reset_asks_and_cancel_is_the_default(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    window, splitter = _laid_out()
    splitter.setSizes(DRAGGED)
    qt_app.processEvents()
    dragged = splitter.sizes()
    said = asked(monkeypatch, reset=False)

    assert window.reset_panel_sizes() is False

    assert said == [
        (
            "Put the panels back to the sizes Zodiarc opens with?",
            "The widths you dragged are forgotten. The window keeps its own size.",
            QMessageBox.StandardButton.Cancel,
        )
    ]
    assert splitter.sizes() == dragged
    window.close()


def test_reset_restores_the_opening_sizes_and_keeps_the_window(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh, splitter = _laid_out()
    opening = splitter.sizes()
    triage_opening = fresh._triage.split.sizes()
    evidence_opening = fresh._evidence.split.sizes()
    fresh.close()
    app._settings().remove("window")
    app._settings().setValue("window/geometry", QByteArray(b"kept"))

    window, splitter = _laid_out()
    splitter.setSizes(DRAGGED)
    window._triage.split.setSizes([100, 400])
    window._evidence.split.setSizes([300, 90])
    qt_app.processEvents()
    app._settings().setValue("window/panels", splitter.saveState())
    size = window.size()
    asked(monkeypatch, reset=True)

    assert window.reset_panel_sizes() is True
    qt_app.processEvents()

    assert splitter.sizes() == opening
    # Shares rather than pixels for these two: Triage is on a tab not shown,
    # so its height is not the fresh window's, and halves are what it opens as.
    queue, reasons = window._triage.split.sizes()
    assert abs(queue - reasons) <= 1
    assert abs(triage_opening[0] - triage_opening[1]) <= 1, "premise: it opens at halves"
    table, details = window._evidence.split.sizes()
    assert table / (table + details) == pytest.approx(
        evidence_opening[0] / sum(evidence_opening), abs=0.01
    )
    assert window.size() == size
    stored = app._settings()
    assert stored.value("window/panels") is None
    assert stored.value("window/geometry") == QByteArray(b"kept"), "the window's own shape stays"
    window.close()


def test_the_view_menu_offers_it_above_full_screen(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    view = next(
        required(action.menu(), "menu")
        for action in required(window.menuBar(), "menu bar").actions()
        if action.text() == "&View"
    )
    entries = view.actions()
    reset = entries.index(window._reset_panels_action)
    assert window._reset_panels_action.text() == "Reset &panel sizes"
    assert entries[reset - 1].isSeparator()
    assert entries[reset + 1].isSeparator()
    assert entries[reset + 2] is window._fullscreen_action
    said = asked(monkeypatch, reset=False)
    window._reset_panels_action.trigger()
    assert len(said) == 1, "the menu entry asks"
    window.close()
