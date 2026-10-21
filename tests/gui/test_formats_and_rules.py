"""Formats and rules in one dialog, two tabs."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QDialogButtonBox

from logarc.gui.format_editor import FormatEditor
from logarc.gui.formats_and_rules import FORMATS_TAB, RULES_TAB, FormatsAndRules
from logarc.gui.rules_editor import RulesEditor


def test_the_two_tabs_say_what_each_half_decides(qt_app: QApplication) -> None:
    dialog = FormatsAndRules()

    assert [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())] == [
        "Log formats",
        "Detection rules",
    ]
    assert "can a line be read" in dialog.tabs.tabToolTip(0)
    assert "what does a line mean" in dialog.tabs.tabToolTip(1)
    assert (dialog.tabs.tabText(0), dialog.tabs.tabText(1)) == (FORMATS_TAB, RULES_TAB)
    assert isinstance(dialog.formats, FormatEditor)
    assert isinstance(dialog.rules, RulesEditor)


def test_it_opens_on_formats_unless_asked_for_rules(qt_app: QApplication) -> None:
    assert FormatsAndRules().tabs.currentIndex() == 0
    assert FormatsAndRules(on_rules=True).tabs.currentIndex() == 1


@pytest.mark.parametrize("tab", ["formats", "rules"])
def test_either_tab_s_close_button_closes_the_dialog(qt_app: QApplication, tab: str) -> None:
    dialog = FormatsAndRules(on_rules=tab == "rules")
    dialog.show()
    page = dialog.formats if tab == "formats" else dialog.rules
    close = next(
        button
        for box in page.findChildren(QDialogButtonBox)
        if box.isVisibleTo(dialog)
        for button in box.buttons()
        if box.standardButton(button) == QDialogButtonBox.StandardButton.Close
    )

    close.click()

    assert not dialog.isVisible()


def test_closing_stops_the_rules_tab_s_count(qt_app: QApplication) -> None:
    dialog = FormatsAndRules()
    stopped: list[bool] = []
    dialog.rules.shutdown = lambda: stopped.append(True)  # type: ignore[method-assign]

    dialog.reject()

    assert stopped == [True]
