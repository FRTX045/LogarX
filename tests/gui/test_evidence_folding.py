"""The evidence panel folds repeated lines into one row, and opens them again.

Run without a display. The lines are the brute force from the bundled log that
decided the default rule: thirty-nine sign-in attempts, a 302 among the 401s.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from tables import column_of
from test_folding import brute_force, line
from test_narrow_columns import node

from logarc.gui.evidence_panel import EvidencePanel
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


def test_a_decode_switch_closes_every_row_and_keeps_the_detail_true(
    panel: EvidencePanel,
) -> None:
    panel.show_evidence(node(39), brute_force())
    panel.toggle_row(0)

    panel.set_decode(False)

    assert panel._table.rowCount() == 7
    assert panel.selected_line().ref.line_no == 2014


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
