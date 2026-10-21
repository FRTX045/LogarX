"""Column handles work everywhere and refills do not undo manual widths."""

import subprocess
import sys

import pytest
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QMenu, QTableWidget, QTableWidgetItem

from logarc.gui.case_chooser import CaseChooser
from logarc.gui.columns import ColumnWidths
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.format_editor import FormatEditor
from logarc.gui.panels import ClientTable
from logarc.gui.triage import TriagePanel
from logarc.gui.who_else import WhoElseDialog


def drag_edge(table, column, distance=30):
    header = table.horizontalHeader()
    start = QPoint(
        header.sectionViewportPosition(column) + header.sectionSize(column) - 1,
        header.height() // 2,
    )
    end = start + QPoint(distance, 0)
    QTest.mousePress(header.viewport(), Qt.MouseButton.LeftButton, pos=start)
    QTest.mouseMove(header.viewport(), end)
    QTest.mouseRelease(header.viewport(), Qt.MouseButton.LeftButton, pos=end)


@pytest.mark.parametrize(
    "kind", ["clients", "requests", "queues", "cases", "who_else", "mapping", "preview"]
)
def test_every_table_column_can_be_resized_by_dragging(qt_app, kind):
    if kind == "clients":
        view = ClientTable()
        table = view._table
    elif kind == "requests":
        view = EvidencePanel()
        table = view._table
    elif kind == "queues":
        view = TriagePanel()
        table = view.table
    elif kind == "cases":
        view = CaseChooser((), exists=lambda _: True)
        table = view._table
    elif kind == "who_else":
        view = WhoElseDialog()
        table = view.table
    else:
        view = FormatEditor()
        view.start_new_json()
        table = view._mapping if kind == "mapping" else view._fields
        # Built-in mappings must still allow resizing without allowing edits.
        view._set_editable(False)
        assert view._mapping.editTriggers() == QTableWidget.EditTrigger.NoEditTriggers
    view.resize(1600, 800)
    view.show()
    qt_app.processEvents()
    try:
        assert table.isVisible()
        for column in range(table.columnCount()):
            if table.isColumnHidden(column):
                continue
            before = table.columnWidth(column)
            drag_edge(table, column)
            qt_app.processEvents()
            assert table.columnWidth(column) > before, (kind, column)
    finally:
        view.close()


@pytest.mark.parametrize(
    "kind",
    ["clients", "requests", "queues", "cases", "who_else", "mapping", "preview", "finds", "pack"],
)
def test_every_table_cuts_a_long_cell_at_its_edge(qt_app, kind):
    """Rows are one line high, and a table that wraps lays a cell out in lines
    first, so a long cell was cut at its first break rather than at its edge:
    `GET /search?q=' AND 1=(SELECT …` with a fifth of the Request column empty,
    and a case folder read `C:…` at any width. Seen on the real display."""
    from logarc.gui.rules_editor import RulesEditor

    views = {
        "clients": lambda: (ClientTable(), "_table"),
        "requests": lambda: (EvidencePanel(), "_table"),
        "queues": lambda: (TriagePanel(), "table"),
        "cases": lambda: (CaseChooser((), exists=lambda _: True), "_table"),
        "who_else": lambda: (WhoElseDialog(), "table"),
        "mapping": lambda: (FormatEditor(), "_mapping"),
        "preview": lambda: (FormatEditor(), "_fields"),
        "finds": lambda: (RulesEditor(), "_finds"),
        "pack": lambda: (RulesEditor(), "_built_table"),
    }
    view, name = views[kind]()

    assert not getattr(view, name).wordWrap()


def example_table():
    table = QTableWidget(1, 3)
    table.setHorizontalHeaderLabels(["Client", "Requests", "Details"])
    table.setItem(0, 0, QTableWidgetItem("192.0.2.100"))
    table.setItem(0, 1, QTableWidgetItem("200"))
    table.setItem(0, 2, QTableWidgetItem("Example"))
    columns = ColumnWidths(table, fill=2)
    columns.fit_unset()
    table.resize(800, 300)
    table.show()
    return table, columns


def test_manual_widths_survive_new_values_panel_resizing_and_hidden_columns(qt_app):
    table, columns = example_table()
    qt_app.processEvents()
    drag_edge(table, 0)
    drag_edge(table, 2, -70)
    widths = [table.columnWidth(column) for column in (0, 2)]
    table.setItem(0, 0, QTableWidgetItem("2001:db8:1234:5678::1"))
    table.setColumnHidden(0, True)
    columns.fit_unset()
    table.setColumnHidden(0, False)
    columns.fit_unset()
    table.resize(1100, 300)
    qt_app.processEvents()
    assert [table.columnWidth(column) for column in (0, 2)] == widths
    table.close()


def test_default_fill_column_uses_the_room_until_manually_resized(qt_app):
    table, columns = example_table()
    qt_app.processEvents()
    before = table.columnWidth(2)
    table.resize(1000, 300)
    qt_app.processEvents()
    assert table.columnWidth(2) > before
    drag_edge(table, 2, -50)
    manual = table.columnWidth(2)
    table.resize(1200, 300)
    columns.fit_unset()
    qt_app.processEvents()
    assert table.columnWidth(2) == manual
    table.close()


def test_header_menu_can_fit_one_column_and_reset_all_widths(qt_app, monkeypatch):
    table, columns = example_table()
    qt_app.processEvents()
    drag_edge(table, 0, 100)
    wider = table.columnWidth(0)
    header = table.horizontalHeader()
    chosen = "Fit this column to contents"
    monkeypatch.setattr(
        QMenu, "exec", lambda menu, _: next(a for a in menu.actions() if a.text() == chosen)
    )
    header.customContextMenuRequested.emit(QPoint(10, header.height() // 2))
    assert table.columnWidth(0) < wider
    fitted = table.columnWidth(0)
    table.setItem(0, 0, QTableWidgetItem("2001:db8:1234:5678:abcd:ef01:2345:6789"))
    columns.fit_unset()
    assert table.columnWidth(0) == fitted

    chosen = "Reset column widths"
    header.customContextMenuRequested.emit(QPoint(10, header.height() // 2))
    assert table.columnWidth(0) > fitted
    table.close()


def test_double_clicking_an_edge_fits_its_column(qt_app):
    table, _columns = example_table()
    qt_app.processEvents()
    drag_edge(table, 0, 100)
    wider = table.columnWidth(0)
    header = table.horizontalHeader()
    edge = QPoint(header.sectionSize(0) - 1, header.height() // 2)
    QTest.mouseDClick(header.viewport(), Qt.MouseButton.LeftButton, pos=edge)
    qt_app.processEvents()
    assert table.columnWidth(0) < wider
    assert table.columnWidth(0) >= table.fontMetrics().horizontalAdvance("192.0.2.100")
    table.close()


#: A shown table let go of without being closed: the header reports its geometry
#: once more while the table is being destroyed, and is no longer one by then.
_LET_GO = """
import os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem
from logarc.gui.columns import ColumnWidths
app = QApplication(sys.argv)
table = QTableWidget(1, 2)
table.setItem(0, 0, QTableWidgetItem("192.0.2.100"))
ColumnWidths(table, fill=1)
table.show()
app.processEvents()
del table
app.processEvents()
print("still running")
"""


def test_a_table_let_go_while_shown_does_not_end_the_program():
    """In its own process, because what it guards against is the process ending.

    An exception inside a Qt slot is one PyQt answers by aborting everything.
    """
    run = subprocess.run(
        [sys.executable, "-c", _LET_GO], capture_output=True, text=True, timeout=120
    )

    assert run.returncode == 0, run.stderr[-800:]
    assert "still running" in run.stdout
