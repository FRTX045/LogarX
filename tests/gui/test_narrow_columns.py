"""Narrow columns start short and widen back to everything.

At the window's default size the client list cut its Last column to `15 …` and
the evidence table left Request 38 px. The reader chose shorter defaults: dates
without times, line numbers without the file, Size out of the way. Each is a
default only: a column dragged wider shows the full value again, and Size comes
back from the heading's menu.

Run without a display. Widths are compared with what the same text measures in
the same table, never with pixel counts, which differ between platforms.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QPoint
from PyQt6.QtWidgets import (
    QApplication,
    QMenu,
    QStyleOptionViewItem,
    QTableWidget,
    QTableWidgetItem,
)
from tables import column_of

from zodiarc.core.activity import ActivityCategory, Outcome, Severity
from zodiarc.core.event import NormalizedEvent
from zodiarc.core.evidence import EvidenceRef
from zodiarc.core.graph import GraphNode
from zodiarc.evidence import EvidenceLine
from zodiarc.gui.columns import SHORT_TEXT, ColumnWidths, ShortWhenNarrow
from zodiarc.gui.evidence_panel import EvidencePanel
from zodiarc.gui.panels import ClientTable
from zodiarc.storage.base import IpSummary

START = datetime(2026, 3, 10, 19, 12, 18, tzinfo=UTC)


def shown_text(table: QTableWidget, row: int, column: int) -> str:
    """What the cell draws at the column's width now, the way painting asks for it.

    From the view's own option, word wrapping included: an option built by hand
    without it measured differently from a real paint, and passed while the
    window showed `09 M…`.
    """
    index = table.model().index(row, column)
    option = QStyleOptionViewItem()
    table.initViewItemOption(option)
    option.rect = table.visualRect(index)
    delegate = table.itemDelegateForIndex(index)
    delegate.initStyleOption(option, index)
    return option.text


def full_width(table: QTableWidget, column: int) -> int:
    """The width this column takes when every cell shows its full text."""
    delegate = table.itemDelegateForColumn(column)
    table.setItemDelegateForColumn(column, None)
    try:
        return table.sizeHintForColumn(column)
    finally:
        table.setItemDelegateForColumn(column, delegate)


# -- the cell itself -------------------------------------------------------------------


@pytest.fixture
def one_cell(qt_app: QApplication) -> QTableWidget:
    table = QTableWidget(1, 2)
    table.setHorizontalHeaderLabels(["Line", "Rest"])
    item = QTableWidgetItem("excerpt.log:2014")
    item.setData(SHORT_TEXT, "2014")
    table.setItem(0, 0, item)
    table.setItem(0, 1, QTableWidgetItem("POST /login"))
    table.setItemDelegateForColumn(0, ShortWhenNarrow(table))
    ColumnWidths(table, fill=1)
    table.resize(600, 200)
    table.show()
    qt_app.processEvents()
    return table


def test_a_column_starts_as_wide_as_its_short_text(one_cell: QTableWidget) -> None:
    assert one_cell.columnWidth(0) < full_width(one_cell, 0)
    assert shown_text(one_cell, 0, 0) == "2014"


def test_a_column_dragged_wider_shows_the_full_text(one_cell: QTableWidget) -> None:
    header = one_cell.horizontalHeader()
    header.resizeSection(0, full_width(one_cell, 0) + 4)

    assert shown_text(one_cell, 0, 0) == "excerpt.log:2014"
    assert one_cell.item(0, 0).text() == "excerpt.log:2014", "what is copied is whole"


# -- the client list -------------------------------------------------------------------


def summary(ip: str, first: datetime, requests: int = 10) -> IpSummary:
    return IpSummary(
        client_ip=ip,
        request_count=requests,
        first_seen=first,
        last_seen=first + timedelta(hours=1),
        distinct_paths=3,
        client_error_ratio=0.1,
        bytes_total=1024,
        position=0,
    )


@pytest.fixture
def clients(qt_app: QApplication) -> ClientTable:
    table = ClientTable()
    table.resize(440, 500)
    table.show_clients(
        [
            summary("10.0.0.1", datetime(2026, 3, 10, 11, 9, tzinfo=UTC)),
            summary("10.0.0.2", datetime(2026, 2, 15, 8, 40, tzinfo=UTC)),
        ],
        total=2,
    )
    table.show()
    qt_app.processEvents()
    return table


def test_first_and_last_start_as_dates(clients: ClientTable) -> None:
    table = clients._table
    first = column_of(table, "First")

    assert table.columnWidth(first) < full_width(table, first)
    assert shown_text(table, 0, first) in {"10 Mar", "15 Feb"}


def test_first_widened_shows_the_time_and_hovering_gives_it_whole(clients: ClientTable) -> None:
    table = clients._table
    first = column_of(table, "First")
    row = next(r for r in range(table.rowCount()) if table.item(r, 0).text() == "10.0.0.1")

    table.horizontalHeader().resizeSection(first, full_width(table, first) + 4)

    assert shown_text(table, row, first) == "10 Mar 11:09"
    assert table.item(row, first).toolTip() == "10 Mar 2026 11:09:00 UTC"


# -- the evidence table ----------------------------------------------------------------


def node(requests: int) -> GraphNode:
    return GraphNode(
        node_id="192.0.2.23#3/7",
        label="Credential Attack",
        category=ActivityCategory.CREDENTIAL_ATTACK,
        severity=Severity.HIGH,
        outcome=Outcome.BLOCKED,
        request_count=requests,
        distinct_paths=1,
        bytes_total=1,
        start=START,
        end=START + timedelta(minutes=1),
        owasp=None,
        top_targets=("/login",),
        rule_ids=("credential_stuffing",),
        evidence=(),
        evidence_total=requests,
        episode_ids=("192.0.2.23#3/7",),
    )


def lines(files: tuple[str, ...] = ("excerpt.log",), *, size: int | None = 7_782) -> list:
    return [
        EvidenceLine(
            ref=EvidenceRef(files[index % len(files)], 2014 + index),
            source_path=files[index % len(files)],
            text=f"line {index}",
            event=NormalizedEvent(
                timestamp=START + timedelta(seconds=index * 7),
                client_ip="192.0.2.23",
                evidence=EvidenceRef(files[index % len(files)], 2014 + index),
                method="POST",
                path="/login",
                status=401,
                bytes_sent=size,
            ),
            verified=True,
        )
        for index in range(6)
    ]


@pytest.fixture
def panel(qt_app: QApplication) -> EvidencePanel:
    shown = EvidencePanel()
    shown.resize(400, 700)
    shown.show()
    qt_app.processEvents()
    return shown


def test_lines_of_one_file_show_their_number_and_widen_to_the_file(
    qt_app: QApplication, panel: EvidencePanel
) -> None:
    panel.show_evidence(node(6), lines())
    qt_app.processEvents()
    table = panel._table
    first = column_of(table, "Line")

    assert shown_text(table, 0, first) == "2014"
    assert table.columnWidth(first) < full_width(table, first)
    assert table.item(0, first).toolTip().endswith("excerpt.log:2014</span>")

    table.horizontalHeader().resizeSection(first, full_width(table, first) + 4)

    assert shown_text(table, 0, first) == "excerpt.log:2014"


def test_lines_of_several_files_show_the_file_from_the_start(
    qt_app: QApplication, panel: EvidencePanel
) -> None:
    panel.show_evidence(node(6), lines(("access.log", "access.log.1")))
    qt_app.processEvents()
    table = panel._table
    first = column_of(table, "Line")

    assert {shown_text(table, row, first) for row in range(2)} == {
        "access.log:2014",
        "access.log.1:2015",
    }


def choose(monkeypatch: pytest.MonkeyPatch, table: QTableWidget, wording: str) -> None:
    """Right-click a heading and pick `wording` from its menu."""
    monkeypatch.setattr(
        QMenu, "exec", lambda menu, _at: next(a for a in menu.actions() if a.text() == wording)
    )
    header = table.horizontalHeader()
    header.customContextMenuRequested.emit(QPoint(10, header.height() // 2))


def test_size_starts_hidden_and_the_heading_menu_brings_it_back(
    qt_app: QApplication, panel: EvidencePanel, monkeypatch: pytest.MonkeyPatch
) -> None:
    table = panel._table
    size = column_of(table, "Size")
    panel.show_evidence(node(6), lines())
    assert table.isColumnHidden(size)

    choose(monkeypatch, table, "Show Size")

    assert not table.isColumnHidden(size)
    panel.show_evidence(node(6), lines())
    assert not table.isColumnHidden(size), "kept for the next activity"
    panel.show_evidence(node(6), lines(size=None))
    assert table.isColumnHidden(size), "still hidden while there is nothing in it"

    choose(monkeypatch, table, "Show Size")
    panel.show_evidence(node(6), lines())
    assert table.isColumnHidden(size)


def test_only_the_sorted_heading_keeps_room_for_its_arrow(
    qt_app: QApplication, panel: EvidencePanel
) -> None:
    """Qt sizes every heading for the arrow while sorting is on; only one draws it.

    Two activities: the second opens already sorted by Line, so no change of
    sort is reported to give Line its room again.
    """
    panel.show_evidence(node(6), lines())
    panel.show_evidence(node(6), lines())
    qt_app.processEvents()
    table = panel._table
    header = table.horizontalHeader()
    status = column_of(table, "Status")
    with_arrow = header.sectionSizeHint(status)
    header.setSortIndicatorShown(False)
    without = header.sectionSizeHint(status)
    header.setSortIndicatorShown(True)
    assert without < with_arrow

    assert header.sectionSize(status) == max(without, table.sizeHintForColumn(status))
    line = column_of(table, "Line")
    assert header.sortIndicatorSection() == line
    assert header.sectionSize(line) >= header.sectionSizeHint(line), "it opens sorted by Line"

    table.sortItems(status)
    qt_app.processEvents()

    assert header.sectionSize(status) >= with_arrow
