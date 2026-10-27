"""Formats and rules in one dialog, two tabs."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from itertools import pairwise

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QDialogButtonBox, QMessageBox

from logarc.gui import theme
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


def test_the_pack_list_rows_do_not_overlap_when_the_dialog_opens_on_formats(
    qt_app: QApplication,
) -> None:
    """The pack list is filled while its tab is hidden. Measured before the
    stylesheet's item padding reached it, its rows were placed closer than they
    are drawn, and the highlight on one spilled onto the rows either side."""
    from logarc.gui import theme

    sheet = qt_app.styleSheet()
    qt_app.setStyleSheet(theme.controls_sheet(11))
    try:
        dialog = FormatsAndRules(None, case_path=None, on_rules=False)
        dialog.show()
        QApplication.processEvents()
        dialog.tabs.setCurrentIndex(1)
        QApplication.processEvents()

        packs = dialog.rules._packs
        rects = [packs.visualItemRect(packs.item(row)) for row in range(packs.count())]
        assert all(above.bottom() < below.top() for above, below in pairwise(rects))
        dialog.close()
    finally:
        qt_app.setStyleSheet(sheet)


@contextmanager
def opened_at(qt_app: QApplication, points: float) -> Iterator[FormatsAndRules]:
    """The dialog shown with the theme's stylesheet and text at `points`, as the
    window opens it, and the application put back afterwards."""
    sheet, font = qt_app.styleSheet(), qt_app.font()
    qt_app.setStyleSheet(theme.controls_sheet(points))
    chosen = theme.ui_font(font)
    chosen.setPointSizeF(points)
    qt_app.setFont(chosen)
    dialog = FormatsAndRules()
    try:
        dialog.show()
        QApplication.processEvents()
        yield dialog
    finally:
        dialog.close()
        qt_app.setStyleSheet(sheet)
        qt_app.setFont(font)


def test_every_built_in_format_name_is_shown_whole(qt_app: QApplication) -> None:
    """At the size the window opens at, `nginx-combined-forwarded` included."""
    with opened_at(qt_app, 12) as dialog:
        formats = dialog.formats._formats
        viewport = formats.viewport()
        assert viewport is not None
        assert formats.sizeHintForColumn(0) <= viewport.width()


def test_both_tabs_lists_are_one_width(qt_app: QApplication) -> None:
    """So the column down the left does not move when the tab changes."""
    with opened_at(qt_app, 12) as dialog:
        widths = {}
        for index, page_list in ((0, dialog.formats._formats), (1, dialog.rules._packs)):
            dialog.tabs.setCurrentIndex(index)
            QApplication.processEvents()
            widths[index] = page_list.width()
        assert widths[0] == widths[1]


def test_a_format_name_wider_than_the_list_never_scrolls_it_sideways(
    qt_app: QApplication,
) -> None:
    """Larger text can make a name wider than the list. It is shortened in the
    middle rather than scrolled to, and the whole name is on hover."""
    with opened_at(qt_app, 16) as dialog:
        formats = dialog.formats._formats
        viewport = formats.viewport()
        scroll = formats.horizontalScrollBar()
        assert viewport is not None
        assert scroll is not None
        assert formats.sizeHintForColumn(0) > viewport.width(), "premise: a name overflows"
        assert scroll.maximum() == 0
        (item,) = formats.findItems("nginx-combined-forwarded", Qt.MatchFlag.MatchExactly)
        assert item.toolTip() == "nginx-combined-forwarded"


def _answer_both(monkeypatch: pytest.MonkeyPatch, button: QMessageBox.StandardButton) -> list[str]:
    """Answer either tab's unsaved-changes question with `button`, noting which asked."""
    from logarc.gui import format_editor, rules_editor

    asked: list[str] = []
    for module, tab in ((format_editor, "formats"), (rules_editor, "rules")):

        def answer(_parent: object, tab: str = tab) -> QMessageBox.StandardButton:
            asked.append(tab)
            return button

        monkeypatch.setattr(module, "_ask_unsaved", answer)
    return asked


def _half_written(dialog: FormatsAndRules) -> None:
    dialog.formats.start_new()
    dialog.formats._name.setText("log-cabang")


def test_closing_with_a_half_written_format_asks_and_cancel_stays_open(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog = FormatsAndRules()
    dialog.show()
    _half_written(dialog)
    asked = _answer_both(monkeypatch, QMessageBox.StandardButton.Cancel)

    dialog.reject()

    assert asked == ["formats"]
    assert dialog.isVisible()
    assert dialog.formats._name.text() == "log-cabang"
    dialog.formats._name.clear()
    dialog.close()


def test_the_formats_tab_s_close_button_asks_and_cancel_leaves_the_tab_drawn(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog = FormatsAndRules()
    dialog.show()
    _half_written(dialog)
    _answer_both(monkeypatch, QMessageBox.StandardButton.Cancel)
    close = next(
        button
        for box in dialog.formats.findChildren(QDialogButtonBox)
        for button in box.buttons()
        if box.standardButton(button) == QDialogButtonBox.StandardButton.Close
    )

    close.click()

    assert dialog.isVisible()
    assert dialog.formats.isVisible()
    dialog.formats._name.clear()
    dialog.close()


def test_escape_in_a_format_field_asks_and_cancel_leaves_the_tab_drawn(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    from PyQt6.QtTest import QTest

    dialog = FormatsAndRules()
    dialog.show()
    _half_written(dialog)
    asked = _answer_both(monkeypatch, QMessageBox.StandardButton.Cancel)

    QTest.keyClick(dialog.formats._name, Qt.Key.Key_Escape)

    assert asked == ["formats"]
    assert dialog.isVisible()
    assert dialog.formats.isVisible()
    dialog.formats._name.clear()
    dialog.close()


def test_closing_with_an_edited_pack_asks_and_discard_closes(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog = FormatsAndRules(on_rules=True)
    dialog.show()
    dialog.rules.start_new()
    dialog.rules._name.setText("my-site")
    asked = _answer_both(monkeypatch, QMessageBox.StandardButton.Discard)

    dialog.reject()

    assert asked == ["rules"]
    assert not dialog.isVisible()
