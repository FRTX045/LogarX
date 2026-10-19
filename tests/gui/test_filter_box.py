"""The chip box both search boxes are made of, and the list under it.

Run without a display. What is checked is behaviour and geometry: which tokens
become chips, what the keys do, what the list offers, and that a narrow box
keeps everything inside it.
"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtGui import QFocusEvent, QFontMetrics
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QHBoxLayout, QVBoxLayout, QWidget

from logarc.gui.filter_box import FilterBox
from logarc.search import Scope

VALUES = {"status": [("404", "3,555 lines"), ("200", "9 lines"), ("500", "1 line")]}


@pytest.fixture
def window(qt_app: QApplication) -> QWidget:
    host = QWidget()
    host.resize(520, 360)
    return host


def boxed(host: QWidget, width: int = 480) -> FilterBox:
    box = FilterBox(
        scope=Scope.EVIDENCE, placeholder="Filter these lines…", accessible_name="Filter"
    )
    box.set_values(VALUES, "VALUES IN THIS ACTIVITY")
    layout = QVBoxLayout(host)
    layout.addWidget(box)
    layout.addStretch(1)
    host.resize(width, 360)
    host.show()
    QApplication.processEvents()
    return box


def focus(box: FilterBox) -> None:
    QApplication.sendEvent(
        box.edit, QFocusEvent(QEvent.Type.FocusIn, Qt.FocusReason.OtherFocusReason)
    )
    QApplication.processEvents()


def typed(box: FilterBox, text: str) -> None:
    QTest.keyClicks(box.edit, text)
    QApplication.processEvents()


def press(box: FilterBox, key: Qt.Key) -> None:
    QTest.keyClick(box.edit, key)
    QApplication.processEvents()


# -- chips ----------------------------------------------------------------------------


def test_understood_tokens_become_chips_and_the_rest_stays_typed(window: QWidget) -> None:
    box = boxed(window)

    box.setText("status:404 union path:/a stat:500")

    assert box.chips() == ("status:404", "path:/a")
    assert box.typed() == "union stat:500"
    assert box.text() == "status:404 path:/a union stat:500"


def test_a_filter_becomes_a_chip_when_the_reader_moves_past_it(window: QWidget) -> None:
    box = boxed(window)

    typed(box, "status:404 ")

    assert box.chips() == ("status:404",)
    assert box.typed() == ""


def test_a_typo_stays_text(window: QWidget) -> None:
    box = boxed(window)

    typed(box, "stat:404 ")

    assert box.chips() == ()
    assert box.typed().strip() == "stat:404"


def test_enter_makes_a_chip_of_a_finished_filter(window: QWidget) -> None:
    box = boxed(window)
    typed(box, "status:404")

    press(box, Qt.Key.Key_Return)

    assert box.chips() == ("status:404",)


def test_backspace_in_an_empty_box_takes_the_last_chip(window: QWidget) -> None:
    box = boxed(window)
    box.setText("status:404 path:/a")

    press(box, Qt.Key.Key_Backspace)

    assert box.chips() == ("status:404",)


def test_a_chip_goes_when_its_cross_is_pressed(window: QWidget) -> None:
    box = boxed(window)
    box.setText("status:404 path:/a")
    heard: list[str] = []
    box.textChanged.connect(heard.append)

    box.chip_buttons()[0].click()

    assert box.chips() == ("path:/a",)
    assert heard == ["path:/a"]


def test_every_change_is_heard_once(window: QWidget) -> None:
    box = boxed(window)
    heard: list[str] = []
    box.textChanged.connect(heard.append)

    box.setText("status:404")
    typed(box, "x")
    box.setText("status:404 x")

    assert heard == ["status:404", "status:404 x"]


def test_finishing_a_filter_is_heard_though_the_text_reads_the_same(window: QWidget) -> None:
    """`status:404` typed and `status:404` made a chip read alike, but only one is
    finished, and the client box acts on a finished time and not a half-typed one."""
    box = boxed(window)
    heard: list[str] = []
    finished: list[tuple[str, ...]] = []
    box.textChanged.connect(heard.append)
    box.committed.connect(lambda: finished.append(box.chips()))

    typed(box, "status:404")
    assert finished == []
    before = len(heard)
    typed(box, " ")

    assert len(heard) == before, "the text did not change"
    assert finished == [("status:404",)]


def test_the_placeholder_shows_only_while_there_are_no_chips(window: QWidget) -> None:
    box = boxed(window)
    assert box.edit.placeholderText() == "Filter these lines…"

    box.setText("status:404")

    assert box.edit.placeholderText() != "Filter these lines…"


def test_clear_empties_chips_and_text(window: QWidget) -> None:
    box = boxed(window)
    box.setText("status:404 union")

    box.clear()

    assert box.text() == ""


# -- the list -------------------------------------------------------------------------


def test_focus_opens_the_list_of_filters(window: QWidget) -> None:
    box = boxed(window)

    focus(box)

    assert box.suggestion_list.isVisible()
    assert box.suggestion_list.title() == "FILTER BY"
    assert box.suggestion_list.completions()[:2] == ["status:", "path:"]


def test_after_a_key_the_list_offers_its_values(window: QWidget) -> None:
    box = boxed(window)
    focus(box)

    typed(box, "status:")

    assert box.suggestion_list.title() == "VALUES IN THIS ACTIVITY"
    assert box.suggestion_list.completions() == ["status:404", "status:200", "status:500"]


def test_down_and_tab_complete_the_chosen_value_into_a_chip(window: QWidget) -> None:
    box = boxed(window)
    focus(box)
    typed(box, "status:")

    press(box, Qt.Key.Key_Down)
    press(box, Qt.Key.Key_Tab)

    assert box.chips() == ("status:200",)
    assert box.edit.hasFocus() or QApplication.focusWidget() in (None, box.edit)


def test_choosing_a_key_leaves_it_open_for_its_value(window: QWidget) -> None:
    box = boxed(window)
    focus(box)

    press(box, Qt.Key.Key_Tab)

    assert box.typed() == "status:"
    assert box.suggestion_list.title() == "VALUES IN THIS ACTIVITY"


def test_the_explanation_row_cannot_be_chosen(window: QWidget) -> None:
    box = boxed(window)
    focus(box)
    for _ in range(10):
        press(box, Qt.Key.Key_Down)

    assert box.suggestion_list.current() is not None
    assert box.suggestion_list.current().selectable


def test_escape_closes_the_list(window: QWidget) -> None:
    box = boxed(window)
    focus(box)

    press(box, Qt.Key.Key_Escape)

    assert not box.suggestion_list.isVisible()


def test_a_click_on_a_row_completes_it(window: QWidget) -> None:
    box = boxed(window)
    focus(box)
    typed(box, "status:")

    box.suggestion_list.choose(2)

    assert box.chips() == ("status:500",)


def test_a_word_no_filter_begins_closes_the_list(window: QWidget) -> None:
    box = boxed(window)
    focus(box)

    typed(box, "union")

    assert not box.suggestion_list.isVisible()


def test_the_list_sits_under_the_box_and_inside_the_window(window: QWidget) -> None:
    box = boxed(window)
    focus(box)

    under = box.suggestion_list.geometry()
    top = box.mapTo(window, box.rect().bottomLeft())

    assert under.top() >= top.y()
    assert window.rect().contains(under.topLeft())
    assert under.right() <= window.width()


def test_an_event_after_the_box_lets_go_of_its_field_is_ignored(
    window: QWidget, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Python can clear a box's attributes while Qt is still delivering its
    field's last events: at exit, or when a failed test is torn down. The filter
    assumed `edit` was there and raised inside Qt, which PyQt answers by ending
    the process; found when two failing tests took the whole run down with them."""
    raised: list[object] = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: raised.append(exc))
    box = boxed(window)
    edit = box.edit
    del box.edit
    try:
        QApplication.sendEvent(
            edit, QFocusEvent(QEvent.Type.FocusOut, Qt.FocusReason.OtherFocusReason)
        )
    finally:
        box.edit = edit

    assert raised == []


def at_the_right_edge(host: QWidget, *, box_width: int, host_width: int) -> FilterBox:
    """A narrow box against the right edge of a wide window: the evidence panel's place."""
    box = FilterBox(scope=Scope.EVIDENCE, placeholder="Filter", accessible_name="Filter")
    box.setFixedWidth(box_width)
    row = QHBoxLayout(host)
    row.addStretch(1)
    row.addWidget(box, 0, Qt.AlignmentFlag.AlignTop)
    host.resize(host_width, 360)
    host.show()
    QApplication.processEvents()
    return box


def test_the_list_is_as_wide_as_its_longest_row(window: QWidget) -> None:
    """Its notes are longer than a narrow box. Held to the box's width it scrolled
    sideways, and the scroll bar pushed its last row out of sight."""
    box = at_the_right_edge(window, box_width=300, host_width=1000)
    focus(box)
    shown = box.suggestion_list
    rows = shown._list
    # A window with room for the rows, whatever the font. A fixed width failed
    # once text grew a point: offscreen Qt on Windows measures the rows far wider
    # than a screen does (1,021 pixels), and a list may not outgrow its window.
    window.resize(300 + rows.sizeHintForColumn(0) * 2, 360)
    QApplication.processEvents()
    focus(box)

    # With a character to spare: at 125% a row that fitted to the pixel was drawn
    # a pixel wider and lost its last characters to an ellipsis.
    spare = QFontMetrics(rows.item(0).font()).averageCharWidth()
    assert rows.sizeHintForColumn(0) + spare <= rows.viewport().width(), "every row fits across"
    assert not rows.horizontalScrollBar().isVisible()
    last = rows.item(rows.count() - 1)
    assert rows.visualItemRect(last).bottom() <= rows.viewport().height(), "every row in sight"
    assert shown.geometry().right() <= window.width(), "grown leftwards, inside the window"


def test_a_window_too_narrow_for_the_rows_still_never_scrolls_sideways(window: QWidget) -> None:
    box = at_the_right_edge(window, box_width=240, host_width=260)
    focus(box)
    shown = box.suggestion_list

    assert shown.geometry().width() <= window.width()
    assert not shown._list.horizontalScrollBar().isVisible()


# -- in a narrow panel ----------------------------------------------------------------


def test_chips_wrap_and_the_typing_space_stays_usable(window: QWidget) -> None:
    box = boxed(window, width=260)

    box.setText("status:404 status:403 path:/admin/users method:POST")
    QApplication.processEvents()

    inside = box.contentsRect()
    for chip in box.chip_widgets():
        assert inside.contains(chip.geometry()), chip.token
    assert box.edit.width() >= FilterBox.MIN_TYPING
    assert box.height() > box.edit.height() * 2, "premise: it wrapped onto more lines"
    assert box.geometry().right() < window.width(), "a minimum width is a demand on the window"


def test_a_chip_is_as_wide_as_its_words(window: QWidget) -> None:
    box = boxed(window)
    box.setText("status:404")
    QApplication.processEvents()

    (chip,) = box.chip_widgets()
    key = chip.key.fontMetrics().horizontalAdvance("status")
    value = chip.value.fontMetrics().horizontalAdvance("404")

    assert chip.width() <= key + value + chip.cross.sizeHint().width() + 24
    assert chip.value.text() == "404"


def test_a_chip_longer_than_the_box_gives_way_and_keeps_its_cross(window: QWidget) -> None:
    box = boxed(window, width=240)

    box.setText("path:/a/very/long/path/that/no/narrow/panel/could/hold/in/one/line")
    QApplication.processEvents()

    (chip,) = box.chip_widgets()
    assert box.contentsRect().contains(chip.geometry())
    assert chip.rect().contains(chip.cross.geometry()), "the cross is still there to press"
    assert chip.value.text().endswith("\N{HORIZONTAL ELLIPSIS}")
    assert box.geometry().right() < window.width()
