"""Asking a table for a column by the heading the reader sees.

Written after a column index went stale without anyone noticing. `e9f3b15` put
a pin-mark column in front of the case chooser's five, which moved every other
column one to the right. One test still read column 0 and believed it was
reading the case name; column 0 is now the mark, empty for an unpinned case, so
`assert "\n" not in shown` was asserting about `""` and could not fail. It went
on passing for as long as it took to look.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem
from tables import cell, column_of


def _table() -> QTableWidget:
    table = QTableWidget(1, 3)
    table.setHorizontalHeaderLabels(["Client", "Reqs", "4xx"])
    for column, text in enumerate(("1.2.3.4", "120", "31%")):
        table.setItem(0, column, QTableWidgetItem(text))
    return table


def test_a_column_is_found_under_the_heading_the_reader_sees(qt_app: QApplication) -> None:
    table = _table()

    assert column_of(table, "Client") == 0
    assert column_of(table, "4xx") == 2
    assert cell(table, 0, "4xx").text() == "31%"


def test_a_column_put_in_front_does_not_move_what_the_others_mean(
    qt_app: QApplication,
) -> None:
    """The bug this module exists for, in one test.

    An index says *third from the left*, which is a fact about the layout. A
    heading says *the 4xx ratio*, which is what the test is about, and inserting
    a column cannot change it.
    """
    table = _table()
    was = cell(table, 0, "4xx").text()

    table.insertColumn(0)
    table.setHorizontalHeaderItem(0, QTableWidgetItem(""))

    assert column_of(table, "4xx") == 3, "premise: everything shifted right"
    assert cell(table, 0, "4xx").text() == was, "and still means the same column"


def test_asking_for_a_heading_no_table_carries_says_which(qt_app: QApplication) -> None:
    """A miss has to name the heading and show what was there. `item(0, 9)`
    came back as `None`, and the `# type: ignore` above it turned that into an
    `AttributeError` several lines later."""
    with pytest.raises(AssertionError, match="Bytes"):
        column_of(_table(), "Bytes")


def test_an_empty_cell_says_where_it_was(qt_app: QApplication) -> None:
    table = _table()
    table.setRowCount(2)

    with pytest.raises(AssertionError, match="row 1"):
        cell(table, 1, "Reqs")
