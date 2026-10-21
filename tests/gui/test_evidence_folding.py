"""The evidence panel folds repeated lines into one row, and opens them again.

Run without a display. The lines are the brute force from the bundled log that
decided the default rule: thirty-nine sign-in attempts, a 302 among the 401s.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QPoint, QRect, Qt
from PyQt6.QtGui import QFont, QTextLayout, QTextOption
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QStyle, QStyleOptionViewItem, QTableWidget
from tables import column_of
from test_folding import brute_force, line
from test_narrow_columns import node

from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.evidence_view import ARROW_CLOSED
from logarc.gui.folding import FoldRule


@pytest.fixture
def panel(qt_app: QApplication) -> EvidencePanel:
    shown = EvidencePanel()
    shown.resize(560, 700)
    shown.set_fold_rule(FoldRule.REQUEST_STATUS_SIZE)
    shown.show()
    qt_app.processEvents()
    return shown


def texts(panel: EvidencePanel, heading: str) -> list[str]:
    table = panel._table
    column = column_of(table, heading)
    return [table.item(row, column).text() for row in range(table.rowCount())]


def test_a_new_panel_folds_nothing(qt_app: QApplication) -> None:
    """The window applies the reader's rule; a panel on its own stays neutral."""
    fresh = EvidencePanel()

    fresh.show_evidence(node(39), brute_force())

    assert fresh._table.rowCount() == 39


def test_an_activity_opens_folded(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    assert panel._table.rowCount() == 7
    assert texts(panel, "Request")[0] == "5x  POST /login"
    assert texts(panel, "Status")[5] == "302"


def test_the_line_count_still_counts_lines_and_the_note_counts_rows(
    panel: EvidencePanel,
) -> None:
    panel.show_evidence(node(39), brute_force())

    assert "Showing 39 of 39 lines" in panel._heading.text()
    assert panel.fold_note.isVisibleTo(panel)
    assert panel.fold_note.text().startswith("39 lines in 7 rows")
    assert "request, status and size" in panel.fold_note.text()


def last_lines(text: str, font: QFont) -> set[str]:
    """The last line `text` wraps to, at every width from 150 to 1,200 pixels."""
    found = set()
    option = QTextOption()
    option.setWrapMode(QTextOption.WrapMode.WordWrap)
    for width in range(150, 1201):
        layout = QTextLayout(text, font)
        layout.setTextOption(option)
        layout.beginLayout()
        last = ""
        while (line := layout.createLine()).isValid():
            line.setLineWidth(width)
            last = text[line.textStart() : line.textStart() + line.textLength()]
        layout.endLayout()
        found.add(last.strip())
    return found


@pytest.mark.parametrize("sort_by", [None, "Status"])
def test_the_note_never_leaves_one_word_on_its_last_line(
    panel: EvidencePanel, sort_by: str | None
) -> None:
    """It once wrapped to a second line holding only `row`."""
    panel.show_evidence(node(39), brute_force())
    if sort_by:
        panel._table.sortItems(column_of(panel._table, sort_by), Qt.SortOrder.AscendingOrder)

    alone = {
        last
        for last in last_lines(panel.fold_note.text(), panel.fold_note.font())
        if len(last.replace("\u00a0", " ").split()) < 2
    }

    assert alone == set()


def test_nothing_to_fold_says_nothing(panel: EvidencePanel) -> None:
    panel.show_evidence(node(3), [line(n, "GET", f"/{n}", 200, 1) for n in (1, 2, 3)])

    assert not panel.fold_note.isVisibleTo(panel)


def test_double_click_opens_and_closes_a_row(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    panel._table.cellDoubleClicked.emit(0, 2)

    assert panel._table.rowCount() == 11
    assert [text.strip() for text in texts(panel, "Line")[1:5]] == [
        "excerpt.log:2015",
        "excerpt.log:2016",
        "excerpt.log:2017",
        "excerpt.log:2018",
    ]
    panel._table.cellDoubleClicked.emit(0, 2)
    assert panel._table.rowCount() == 7


@pytest.mark.parametrize("key", [Qt.Key.Key_Right, Qt.Key.Key_Return])
def test_a_key_opens_the_selected_row(panel: EvidencePanel, key: Qt.Key) -> None:
    panel.show_evidence(node(39), brute_force())
    panel._table.setFocus()

    QTest.keyClick(panel._table, key)

    assert panel._table.rowCount() == 11


def test_left_on_a_line_inside_closes_its_row_and_selects_the_first(
    panel: EvidencePanel,
) -> None:
    panel.show_evidence(node(39), brute_force())
    panel.toggle_row(0)
    panel.select_row(3)
    panel._table.setFocus()

    QTest.keyClick(panel._table, Qt.Key.Key_Left)

    assert panel._table.rowCount() == 7
    assert panel.selected_line().ref.line_no == 2014


def test_selecting_a_line_inside_shows_that_line(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())
    panel.toggle_row(0)

    panel.select_row(2)

    assert panel.selected_line().ref.line_no == 2016
    assert "2016" in panel._detail.sections["source"].content.toPlainText()


def test_the_arrow_click_toggles_and_a_click_elsewhere_only_selects(
    qt_app: QApplication, panel: EvidencePanel
) -> None:
    panel.show_evidence(node(39), brute_force())
    table = panel._table
    arrow = table.visualRect(table.model().index(0, column_of(table, "Line")))

    QTest.mouseClick(
        table.viewport(),
        Qt.MouseButton.LeftButton,
        pos=arrow.topLeft() + QPoint(4, arrow.height() // 2),
    )
    assert table.rowCount() == 11

    request = table.visualRect(table.model().index(0, column_of(table, "Request")))
    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=request.center())
    assert table.rowCount() == 11


def text_rect(table: QTableWidget, row: int) -> QRect:
    """Where Qt draws the Line cell's text: past any ribbon in front of it."""
    index = table.model().index(row, column_of(table, "Line"))
    option = QStyleOptionViewItem()
    table.initViewItemOption(option)
    option.rect = table.visualRect(index)
    table.itemDelegateForIndex(index).initStyleOption(option, index)
    return table.style().subElementRect(QStyle.SubElement.SE_ItemViewItemText, option, table)


def test_the_arrow_still_toggles_beside_a_bookmark(panel: EvidencePanel) -> None:
    lines = brute_force()
    panel.show_evidence(node(39), lines)
    panel.set_marks({lines[2].ref: ("#49a9ff", "third try")})
    table = panel._table
    assert not table.item(0, column_of(table, "Line")).icon().isNull(), "premise: a ribbon"
    text = text_rect(table, 0)
    # Qt's text margin in an item view, then the arrow's own width: its far edge.
    margin = table.style().pixelMetric(QStyle.PixelMetric.PM_FocusFrameHMargin, None, table) + 1
    edge = text.left() + margin + table.fontMetrics().horizontalAdvance(ARROW_CLOSED) - 2

    QTest.mouseClick(
        table.viewport(), Qt.MouseButton.LeftButton, pos=QPoint(edge, text.center().y())
    )

    assert table.rowCount() == 11


def test_a_click_on_the_ribbon_only_selects(panel: EvidencePanel) -> None:
    lines = brute_force()
    panel.show_evidence(node(39), lines)
    panel.set_marks({lines[2].ref: ("#49a9ff", "third try")})
    table = panel._table
    cell = table.visualRect(table.model().index(0, column_of(table, "Line")))
    ribbon = QPoint((cell.left() + text_rect(table, 0).left()) // 2, cell.center().y())

    QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=ribbon)

    assert table.rowCount() == 7


def test_double_clicking_a_line_inside_leaves_its_row_open(panel: EvidencePanel) -> None:
    """Only the folded row opens and closes; a line inside is just a line."""
    panel.show_evidence(node(39), brute_force())
    panel.toggle_row(0)

    panel._table.cellDoubleClicked.emit(2, 2)

    assert panel._table.rowCount() == 11


def test_a_decode_switch_closes_every_row_and_keeps_the_detail_true(
    panel: EvidencePanel,
) -> None:
    panel.show_evidence(node(39), brute_force())
    panel.toggle_row(0)

    panel.set_decode(False)

    assert panel._table.rowCount() == 7
    assert panel.selected_line().ref.line_no == 2014


def fits(panel: EvidencePanel) -> bool:
    """Whether the Line column holds every drawn row's number without cutting it."""
    table = panel._table
    line_column = column_of(table, "Line")
    return table.columnWidth(line_column) >= table.sizeHintForColumn(line_column)


def test_opening_a_row_keeps_its_line_numbers_whole(panel: EvidencePanel) -> None:
    """The lines inside are indented past the arrow the column was fitted to."""
    panel.show_evidence(node(39), brute_force())
    assert fits(panel), "premise: fitted to the closed rows"

    panel.toggle_row(0)

    assert fits(panel)


def test_folding_again_after_another_sort_keeps_the_arrows_whole(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())
    table = panel._table
    table.sortItems(column_of(table, "Status"), Qt.SortOrder.AscendingOrder)
    panel._column_sizes.reset()
    assert fits(panel), "premise: fitted to every line on its own row"

    table.sortItems(column_of(table, "Line"), Qt.SortOrder.AscendingOrder)

    assert fits(panel)


def test_a_width_the_reader_chose_is_kept_when_a_row_opens(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())
    table = panel._table
    line_column = column_of(table, "Line")
    table.horizontalHeader().resizeSection(line_column, 30)
    # Whatever the header allowed: a platform can hold a section to a minimum.
    chosen = table.columnWidth(line_column)
    assert chosen < table.sizeHintForColumn(line_column), "premise: narrower than its rows"

    panel.toggle_row(0)

    assert table.columnWidth(line_column) == chosen


def test_changing_the_rule_refolds_what_is_on_show(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    panel.set_fold_rule(FoldRule.REQUEST)
    assert panel._table.rowCount() == 1
    assert texts(panel, "Status") == ["mixed"]

    panel.set_fold_rule(FoldRule.OFF)
    assert panel._table.rowCount() == 39
    assert not panel.fold_note.isVisibleTo(panel)


def test_a_mixed_value_is_drawn_in_italics(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())
    panel.set_fold_rule(FoldRule.REQUEST)

    assert panel._table.item(0, column_of(panel._table, "Status")).font().italic()


# -- sorting, visits, the filter, bookmarks ----------------------------------------


def test_sorting_by_another_column_shows_every_line_and_says_why(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    panel._table.sortItems(column_of(panel._table, "Status"), Qt.SortOrder.AscendingOrder)
    assert panel._table.rowCount() == 39
    assert panel.fold_note.text().startswith("Sorted by Status")

    panel._table.sortItems(column_of(panel._table, "Line"), Qt.SortOrder.AscendingOrder)
    assert panel._table.rowCount() == 7


def test_line_descending_shows_every_line_too(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    panel._table.sortItems(column_of(panel._table, "Line"), Qt.SortOrder.DescendingOrder)

    assert panel._table.rowCount() == 39


def test_lines_in_two_visits_fold_separately(panel: EvidencePanel) -> None:
    lines = [line(n, "POST", "/login", 401, 7744) for n in (1, 2, 3, 4)]
    visits = {one.ref: ("a" if one.ref.line_no < 3 else "b") for one in lines}

    panel.show_evidence(node(4), lines, visits=visits)

    assert texts(panel, "Request") == ["2x  POST /login", "2x  POST /login"]


def test_a_decode_switch_keeps_the_visits(panel: EvidencePanel) -> None:
    lines = [line(n, "POST", "/login", 401, 7744) for n in (1, 2, 3, 4)]
    visits = {one.ref: ("a" if one.ref.line_no < 3 else "b") for one in lines}
    panel.show_evidence(node(4), lines, visits=visits)

    panel.set_decode(False)

    assert panel._table.rowCount() == 2


def test_a_filter_folds_the_lines_it_keeps(panel: EvidencePanel) -> None:
    """The window hands the panel only what the filter kept; neighbours in that
    list fold even when the log had other lines between them."""
    kept = [line(n, "POST", "/login", 401, 7744) for n in (10, 20, 30)]

    panel.show_evidence(node(3), kept)

    assert panel._table.rowCount() == 1


def test_a_bookmark_inside_a_closed_row_shows_on_the_row_and_then_on_its_line(
    panel: EvidencePanel,
) -> None:
    lines = brute_force()
    panel.show_evidence(node(39), lines)

    panel.set_marks({lines[2].ref: ("#49a9ff", "third try")})
    first = panel._table.item(0, column_of(panel._table, "Line"))
    assert not first.icon().isNull()
    assert "third try" in first.toolTip()

    panel.toggle_row(0)
    marked = [
        row
        for row in range(panel._table.rowCount())
        if not panel._table.item(row, 0).icon().isNull()
    ]
    assert marked == [2]


def test_a_closed_row_without_a_bookmark_names_its_lines(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())

    tip = panel._table.item(0, column_of(panel._table, "Line")).toolTip()

    assert "5 lines: 2014 to 2018" in tip


def test_selecting_a_line_inside_a_closed_row_opens_it(panel: EvidencePanel) -> None:
    lines = brute_force()
    panel.show_evidence(node(39), lines)

    assert panel.select_line(lines[3].ref)

    assert panel._table.rowCount() == 11
    assert panel.selected_line().ref == lines[3].ref


def test_the_menu_on_a_closed_row_names_the_line_it_bookmarks(panel: EvidencePanel) -> None:
    panel.show_evidence(node(39), brute_force())
    rect = panel._table.visualRect(panel._table.model().index(0, 2))

    menu = panel._menu_at(rect.center())

    assert [action.text() for action in menu.actions()] == [
        "Bookmark line 2014\u2026",
        "Make a rule from line 2014\u2026",
    ]
