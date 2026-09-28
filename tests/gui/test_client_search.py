"""The client list as a window on the whole case: pages, whole-case search, the open client.

Run without a display. The window's side, which runs the searches, is tested in
`test_window.py`; here the list is driven directly with the pages a search would
return.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from tables import column_of

from logarc.gui.panels import ClientTable
from logarc.storage.base import IpSummary, IpSummaryPage

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
DASH = "\N{EN DASH}"
ELLIPSIS = "\N{HORIZONTAL ELLIPSIS}"


def summary(ip: str, requests: int, position: int = 0) -> IpSummary:
    return IpSummary(
        client_ip=ip,
        request_count=requests,
        first_seen=START,
        last_seen=START + timedelta(minutes=5),
        distinct_paths=3,
        client_error_ratio=0.1,
        bytes_total=1024,
        position=position,
    )


def on_screen(table: ClientTable) -> list[str]:
    column = column_of(table._table, "Client")
    return [
        item.text()
        for row in range(table._table.rowCount())
        if (item := table._table.item(row, column)) is not None
        and not table._table.isRowHidden(row)
    ]


@pytest.fixture
def partial(qt_app: QApplication) -> ClientTable:
    """The busiest three of a case of 900, as a window opens a large case."""
    table = ClientTable()
    table.show_clients(
        [summary("10.0.0.1", 90), summary("10.0.0.2", 80), summary("172.16.0.9", 70)], total=900
    )
    return table


def settle_search() -> None:
    QTest.qWait(ClientTable.SEARCH_DELAY_MS + 50)


def test_rows_open_busiest_first(partial: ClientTable) -> None:
    assert on_screen(partial) == ["10.0.0.1", "10.0.0.2", "172.16.0.9"]


def test_a_partial_list_asks_for_a_whole_case_search(partial: ClientTable) -> None:
    edits, asked = [], []
    partial.filter_edited.connect(lambda: edits.append(True))
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._filter.setText("10.0.9")
    assert edits == [True], "a stale answer must be dropped as soon as the text changes"
    assert asked == []
    assert partial._caption.text() == f"Searching the whole case for 10.0.9{ELLIPSIS}"
    settle_search()
    assert asked == [("10.0.9", 0)]


def test_a_complete_list_filters_itself_and_asks_for_nothing(qt_app: QApplication) -> None:
    table = ClientTable()
    table.show_clients([summary("10.0.0.1", 9), summary("10.0.0.2", 8)], total=2)
    asked = []
    table.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    table._filter.setText("10.0.0.2")
    settle_search()
    assert asked == []
    assert on_screen(table) == ["10.0.0.2"]
    assert table._caption.text() == "1 of 2 clients matches 10.0.0.2"


def test_a_whole_case_answer_replaces_the_rows(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9.9")
    found = IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0)
    assert partial.show_page(found, "10.0.9.9")
    assert on_screen(partial) == ["10.0.9.9"]
    assert partial._caption.text() == "1 of 900 clients matches 10.0.9.9"
    assert not partial._previous.isEnabled()
    assert not partial._next.isEnabled()


def test_an_answer_for_other_text_is_ignored(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9.9")
    partial._filter.setText("10.0.9.8")
    stale = IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0)
    assert not partial.show_page(stale, "10.0.9.9")
    assert "10.0.9.9" not in on_screen(partial)


def test_more_matches_than_a_page_can_be_stepped_through(partial: ClientTable) -> None:
    partial._filter.setText("10.")
    first = IpSummaryPage(tuple(summary(f"10.1.0.{i}", 100 - i) for i in range(3)), 7, 0)
    partial.show_page(first, "10.")
    assert partial._caption.text().startswith(f"Matches 1{DASH}3 of 7 for 10.")
    assert partial._next.isEnabled() and not partial._previous.isEnabled()
    asked = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._next.click()
    assert asked == [("10.", ClientTable.PAGE_SIZE)]


def test_unfiltered_pages_continue_by_request_count(partial: ClientTable) -> None:
    assert partial._next.isEnabled()
    asked = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._next.click()
    assert asked == [("", ClientTable.PAGE_SIZE)]
    later = IpSummaryPage((summary("192.0.2.4", 3, position=501),), 900, ClientTable.PAGE_SIZE)
    partial.show_page(later, "")
    assert partial._caption.text().startswith(
        f"Clients {ClientTable.PAGE_SIZE + 1}{DASH}{ClientTable.PAGE_SIZE + 1} of 900, busiest first"
    )
    assert partial._previous.isEnabled()


def test_clearing_the_search_restores_the_page_without_asking(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9.9")
    partial.show_page(IpSummaryPage((summary("10.0.9.9", 2),), 1, 0), "10.0.9.9")
    asked = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._filter.clear()
    settle_search()
    assert asked == []
    assert on_screen(partial) == ["10.0.0.1", "10.0.0.2", "172.16.0.9"]
    assert partial._caption.text().startswith(f"Clients 1{DASH}3 of 900, busiest first")


def test_an_open_client_outside_the_list_is_named_not_added(partial: ClientTable) -> None:
    chosen = []
    partial.client_chosen.connect(chosen.append)
    partial.set_open_client("10.0.9.9")
    assert "10.0.9.9" not in on_screen(partial)
    assert partial._caption.text().endswith(
        "10.0.9.9, open now, is not in this list; filter by its address to show it."
    )
    partial.set_open_client("10.0.0.2")
    assert partial._table.currentRow() >= 0
    assert "open now" not in partial._caption.text()
    assert chosen == [], "marking the open client must not start a reconstruction"


def test_a_page_sorted_another_way_says_so(partial: ClientTable) -> None:
    partial._table.sortItems(column_of(partial._table, "Client"), Qt.SortOrder.AscendingOrder)
    assert "sorted within this page" in partial._caption.text()
    partial._table.sortItems(column_of(partial._table, "Reqs"), Qt.SortOrder.DescendingOrder)
    assert "sorted within this page" not in partial._caption.text()


def test_a_failed_search_says_so(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9")
    partial.show_failure("10.0.9", "the case could not be read")
    assert partial._caption.text() == (
        "Could not search the whole case for 10.0.9: the case could not be read"
    )
