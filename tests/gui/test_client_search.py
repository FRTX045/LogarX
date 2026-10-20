"""The client list as a window on the whole case: pages, whole-case search, the open client.

Run without a display. The window's side, which runs the searches, is tested in
`test_window.py`; here the list is driven directly with the pages a search would
return.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest
from PyQt6.QtCore import QEvent, Qt
from PyQt6.QtGui import QFocusEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication
from tables import column_of

from logarc.gui.panels import ClientTable
from logarc.storage.base import ClientMatchPage, IpSummary, IpSummaryPage

if TYPE_CHECKING:
    from collections.abc import Iterator

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
    assert partial._caption.text().endswith("Current IP: 10.0.9.9 (outside this list).")
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


def page_two(table: ClientTable) -> None:
    """Step the unfiltered list on to its second page."""
    table.show_page(
        IpSummaryPage(
            (summary("192.0.2.4", 3, position=ClientTable.PAGE_SIZE + 1),),
            900,
            ClientTable.PAGE_SIZE,
        ),
        "",
    )


def test_paging_is_off_until_a_new_searchs_first_page_arrives(partial: ClientTable) -> None:
    page_two(partial)
    assert partial._next.isEnabled() or partial._previous.isEnabled()
    asked = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._filter.setText("10.0.9.9")
    assert not partial._next.isEnabled()
    assert not partial._previous.isEnabled()
    partial._step(1)
    assert asked == [], "a step taken before the search answers used the old page's offset"
    partial.show_page(IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0), "10.0.9.9")
    assert partial._caption.text() == "1 of 900 clients matches 10.0.9.9"


def test_clearing_a_search_returns_to_the_busiest_page(partial: ClientTable) -> None:
    page_two(partial)
    partial._filter.setText("10.0.9.9")
    partial.show_page(IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0), "10.0.9.9")
    partial._filter.clear()
    assert on_screen(partial) == ["10.0.0.1", "10.0.0.2", "172.16.0.9"]
    assert partial._caption.text().startswith(f"Clients 1{DASH}3 of 900, busiest first")


# -- the box searches requests too ---------------------------------------------------


def matched(*rows: tuple[str, int], total: int | None = None, requests: int = 0) -> ClientMatchPage:
    return ClientMatchPage(
        # The client with most matches has the fewest requests, so an order by
        # requests and an order by matches cannot be mistaken for each other.
        tuple(summary(ip, 10 + n, position=n + 1) for n, (ip, _hits) in enumerate(rows)),
        tuple(hits for _ip, hits in rows),
        len(rows) if total is None else total,
        requests or sum(hits for _ip, hits in rows),
        0,
    )


def match_column(table: ClientTable) -> list[str]:
    column = column_of(table._table, "Match")
    return [
        item.text()
        for row in range(table._table.rowCount())
        if (item := table._table.item(row, column)) is not None
        and not table._table.isRowHidden(row)
    ]


def test_the_box_takes_filters_as_chips_and_keeps_addresses_as_typed(partial: ClientTable) -> None:
    partial._filter.setText("status:404 10.0 activity:injection")

    assert partial._filter.chips() == ("status:404", "activity:injection")
    assert partial._filter.typed() == "10.0"
    assert partial.query_text() == "status:404 activity:injection 10.0"


def test_a_request_search_always_asks_the_whole_case(qt_app: QApplication) -> None:
    """A page holds clients, not their requests: even a complete list cannot answer it."""
    table = ClientTable()
    table.show_clients([summary("10.0.0.1", 9), summary("10.0.0.2", 8)], total=2)
    asked = []
    table.page_requested.connect(lambda query, offset: asked.append((query, offset)))

    # Both rows hold the address; neither is known to hold the request yet.
    table._filter.setText("status:200 10.0")

    assert table._caption.text() == f"Searching the whole case for status:200 10.0{ELLIPSIS}"
    assert on_screen(table) == [], "no rows that might be read as the answer"
    settle_search()
    assert asked == [("status:200 10.0", 0)]


def test_matches_are_listed_most_first_with_how_many(partial: ClientTable) -> None:
    partial._filter.setText("status:200 path:/admin")

    assert partial.show_matches(
        matched(("10.0.5.5", 7), ("10.0.0.2", 3), requests=10), "status:200 path:/admin"
    )

    assert on_screen(partial) == ["10.0.5.5", "10.0.0.2"]
    assert match_column(partial) == ["7", "3"]
    assert partial._caption.text() == (
        "2 of 900 clients sent a request matching status:200 path:/admin \N{MIDDLE DOT} 10 requests"
    )


def test_the_match_column_sits_beside_the_address(partial: ClientTable) -> None:
    partial._filter.setText("status:200")
    partial.show_matches(matched(("10.0.5.5", 7)), "status:200")

    header = partial._table.horizontalHeader()
    assert header.visualIndex(column_of(partial._table, "Match")) == 1


def test_more_matches_than_a_page_say_which_these_are(partial: ClientTable) -> None:
    partial._filter.setText("status:4xx")
    partial.show_matches(
        matched(("10.0.5.5", 9), ("10.0.0.2", 4), total=1_234, requests=70_312), "status:4xx"
    )

    assert partial._caption.text() == (
        f"Clients 1{DASH}2 of 1,234 that sent a request matching status:4xx"
        " \N{MIDDLE DOT} 70,312 requests"
    )
    assert partial._next.isEnabled()
    asked = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial._next.click()
    assert asked == [("status:4xx", ClientTable.PAGE_SIZE)]


def test_nothing_matching_says_so_and_how_large_the_case_is(partial: ClientTable) -> None:
    partial._filter.setText("status:418")
    partial.show_matches(matched(), "status:418")

    assert on_screen(partial) == []
    assert (
        partial._caption.text() == "No client sent a request matching status:418. 900 in the case."
    )


def test_an_activity_alone_lists_clients_without_counting_requests(partial: ClientTable) -> None:
    """The scan says which clients an activity reached, not how many of their
    requests: a count summed over its rules could count a request twice."""
    partial._filter.setText("activity:injection")
    partial.show_matches(
        matched(("10.0.5.5", 0), ("10.0.0.2", 0)), "activity:injection", counted=False
    )

    assert on_screen(partial) == ["10.0.0.2", "10.0.5.5"], "busiest first: nothing was counted"
    assert partial._table.isColumnHidden(column_of(partial._table, "Match"))
    assert partial._caption.text() == (
        "2 of 900 clients match activity:injection in the Where to start scan"
    )


def test_an_answer_for_other_text_is_dropped(partial: ClientTable) -> None:
    partial._filter.setText("status:200")
    partial._filter.setText("status:500")

    assert not partial.show_matches(matched(("10.0.5.5", 7)), "status:200")
    assert "10.0.5.5" not in on_screen(partial)


def test_an_address_search_after_a_request_search_has_no_match_column(
    partial: ClientTable,
) -> None:
    partial._filter.setText("status:200")
    partial.show_matches(matched(("10.0.5.5", 7)), "status:200")

    partial._filter.setText("10.0.9.9")
    partial.show_page(IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0), "10.0.9.9")

    assert partial._table.isColumnHidden(column_of(partial._table, "Match"))
    assert partial._caption.text() == "1 of 900 clients matches 10.0.9.9"


def test_clearing_a_request_search_returns_to_the_busiest_page(partial: ClientTable) -> None:
    partial._filter.setText("status:200")
    partial.show_matches(matched(("10.0.5.5", 7)), "status:200")

    partial._filter.clear()

    assert on_screen(partial) == ["10.0.0.1", "10.0.0.2", "172.16.0.9"]
    assert partial._table.isColumnHidden(column_of(partial._table, "Match"))


def test_two_addresses_list_either(qt_app: QApplication) -> None:
    """Several addresses are several clients, as the store answers them."""
    table = ClientTable()
    table.show_clients(
        [summary("10.0.0.1", 9), summary("10.0.0.2", 8), summary("10.9.9.9", 7)], total=3
    )

    table._filter.setText("10.0.0.1 ip:10.9")

    assert on_screen(table) == ["10.0.0.1", "10.9.9.9"]


# -- a time is the range's -----------------------------------------------------------


def test_a_finished_time_asks_for_the_range_and_hands_back_the_rest(
    partial: ClientTable,
) -> None:
    """`after:` and `before:` move the range, so the window is handed them apart."""
    asked: list[tuple[str, int]] = []
    moved: list[str] = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial.range_typed.connect(moved.append)

    partial._filter.setText("after:12:00 status:404 before:2024-05-01T13:00 10.0")
    settle_search()

    assert moved == ["after:12:00 before:2024-05-01T13:00"]
    assert partial.query_without_times() == "status:404 10.0"
    assert asked == []


def test_a_time_still_being_typed_is_searched_and_moves_the_range_once_finished(
    partial: ClientTable,
) -> None:
    """`after:2024-05-01` is whole, and may yet become `after:2024-05-01T12:30`; a
    pause while typing must not move the range to midnight."""
    asked: list[tuple[str, int]] = []
    moved: list[str] = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))
    partial.range_typed.connect(moved.append)

    QTest.keyClicks(partial._filter.edit, "after:12:00")
    assert on_screen(partial) == [], "waiting for the case, as for any filter"
    settle_search()

    assert asked == [("after:12:00", 0)], "a time of day alone is still a filter"
    assert moved == []

    QTest.keyClicks(partial._filter.edit, " ")
    settle_search()

    assert moved == ["after:12:00"]


def test_the_box_can_be_given_a_search(partial: ClientTable) -> None:
    asked: list[tuple[str, int]] = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))

    partial.set_query("status:404 10.0")

    assert partial._filter.chips() == ("status:404",)
    assert asked == [("status:404 10.0", 0)], "at once: it was not typed"


# -- what the caption keeps saying ---------------------------------------------------


def test_a_search_waiting_for_the_scan_says_so_and_keeps_saying_it(
    partial: ClientTable,
) -> None:
    partial._filter.setText("activity:injection")
    partial.show_pending("activity:injection", "Waiting for the scan.")

    assert partial._caption.text() == "Waiting for the scan."
    assert on_screen(partial) == [], "no rows that might be read as the answer"

    partial.set_open_client("10.0.0.1")
    assert partial._caption.text() == "Waiting for the scan.", "not replaced by a count"


def test_a_failed_search_keeps_saying_so(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9")
    partial.show_failure("10.0.9", "the case could not be read")

    partial.set_open_client("10.0.0.1")

    assert partial._caption.text() == (
        "Could not search the whole case for 10.0.9: the case could not be read"
    )


def test_a_message_for_other_text_is_dropped(partial: ClientTable) -> None:
    partial._filter.setText("activity:injection")
    partial.show_pending("activity:sweep", "Waiting for the scan.")

    assert partial._caption.text() != "Waiting for the scan."


def test_new_text_replaces_the_message(partial: ClientTable) -> None:
    partial._filter.setText("activity:injection")
    partial.show_pending("activity:injection", "Waiting for the scan.")

    partial._filter.setText("10.0.0")

    assert partial._caption.text() != "Waiting for the scan."


def test_ties_keep_the_order_the_page_was_cut_in(partial: ClientTable) -> None:
    """However the reader last sorted, ties stay as the case ordered them, so the
    next page visibly continues this one."""
    partial._table.sortItems(column_of(partial._table, "Client"), Qt.SortOrder.DescendingOrder)
    partial._filter.setText("status:200")

    partial.show_matches(matched(("10.0.0.1", 2), ("10.0.0.2", 2), ("10.0.0.3", 2)), "status:200")

    assert on_screen(partial) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_searching_again_asks_at_once(partial: ClientTable) -> None:
    """Nothing was typed, so there is no typing to wait out."""
    partial._filter.setText("activity:injection")
    settle_search()
    asked: list[tuple[str, int]] = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))

    partial.search_again()

    assert asked == [("activity:injection", 0)]


def test_finishing_a_filter_that_is_not_a_time_asks_nothing_more(partial: ClientTable) -> None:
    """The search for `status:404` already ran while it was typed."""
    QTest.keyClicks(partial._filter.edit, "status:404")
    settle_search()
    asked: list[tuple[str, int]] = []
    partial.page_requested.connect(lambda query, offset: asked.append((query, offset)))

    QTest.keyClicks(partial._filter.edit, " ")
    settle_search()

    assert partial._filter.chips() == ("status:404",)
    assert asked == []


def test_an_answer_after_a_failure_replaces_it(partial: ClientTable) -> None:
    """Next failed, then Previous answered: the caption is the answer's."""
    partial._filter.setText("status:200")
    partial.show_failure("status:200", "the case could not be read")

    partial.show_matches(matched(("10.0.5.5", 7)), "status:200")

    assert partial._caption.text() == (
        "1 of 900 clients sent a request matching status:200 \N{MIDDLE DOT} 7 requests"
    )


def test_an_address_answer_after_a_failure_replaces_it(partial: ClientTable) -> None:
    partial._filter.setText("10.0.9.9")
    partial.show_failure("10.0.9.9", "the case could not be read")

    partial.show_page(IpSummaryPage((summary("10.0.9.9", 2, position=701),), 1, 0), "10.0.9.9")

    assert partial._caption.text() == "1 of 900 clients matches 10.0.9.9"


# -- column widths -------------------------------------------------------------------


def visible_widths(table: ClientTable) -> int:
    grid = table._table
    header = grid.horizontalHeader()
    assert header is not None
    return sum(header.sectionSize(c) for c in range(header.count()) if not grid.isColumnHidden(c))


def test_the_spare_width_goes_to_the_last_column_not_the_hidden_match(qt_app: QApplication) -> None:
    """Match is hidden until a search counts requests. Given the spare width while
    hidden, it left a blank band at the right of every list without a search."""
    table = ClientTable()
    table.resize(1400, 400)
    table.show()
    table.show_clients([summary("10.0.0.1", 9)], total=1)
    QApplication.processEvents()

    assert visible_widths(table) == table._table.viewport().width()
    table.close()


def test_an_answer_is_measured_on_its_own_rows(qt_app: QApplication) -> None:
    """Every row is hidden while a search runs; measured then, each column was as
    wide as its heading, and a long address or count was cut short."""
    table = ClientTable()
    table.resize(1400, 400)
    table.show()
    table.show_clients([summary("10.0.0.1", 9)], total=900)
    table._filter.setText("status:200")

    table.show_matches(
        matched(("2001:db8:85a3::8a2e:370:7334", 1_234_567), ("10.0.5.5", 2)), "status:200"
    )
    QApplication.processEvents()

    grid = table._table
    header = grid.horizontalHeader()
    assert header is not None
    client = column_of(grid, "Client")
    assert header.sectionSize(client) == max(
        grid.sizeHintForColumn(client), heading_without_arrow(table, client)
    )
    match = column_of(grid, "Match")  # the sorted one: its heading draws the arrow
    assert header.sectionSize(match) == max(
        grid.sizeHintForColumn(match), header.sectionSizeHint(match)
    )
    assert visible_widths(table) == grid.viewport().width()
    table.close()


# -- the list of filters and the answer ----------------------------------------------


@pytest.fixture
def focused(qt_app: QApplication) -> Iterator[ClientTable]:
    """A list a reader is typing into, in a window, its box focused."""
    table = ClientTable()
    table.resize(900, 600)
    table.show()
    table.show_clients([summary("10.0.0.1", 9), summary("10.0.0.2", 8)], total=900)
    QApplication.sendEvent(
        table._filter.edit, QFocusEvent(QEvent.Type.FocusIn, Qt.FocusReason.OtherFocusReason)
    )
    QApplication.processEvents()
    yield table
    table.close()


def suggesting(table: ClientTable) -> bool:
    shown = table._filter._list
    return shown is not None and shown.isVisible()


def test_an_answer_takes_the_place_of_the_list_of_filters(focused: ClientTable) -> None:
    """Between filters the box offers the next one, over the list: the answer the
    reader stopped typing for was underneath it."""
    QTest.keyClicks(focused._filter.edit, "status:200 ")
    assert suggesting(focused), "premise: the list offers the next filter"

    focused.show_matches(matched(("10.0.5.5", 7)), "status:200")

    assert not suggesting(focused)
    QTest.keyClick(focused._filter.edit, Qt.Key.Key_Down)
    assert suggesting(focused), "and Down brings it back"


def test_a_value_being_chosen_keeps_the_list(focused: ClientTable) -> None:
    focused._filter.set_values({"status": [("404", "3 clients")]}, "VALUES IN THE CASE")
    QTest.keyClicks(focused._filter.edit, "status:4")
    assert suggesting(focused), "premise: the list offers values"

    focused.show_matches(matched(("10.0.5.5", 7)), "status:4")

    assert suggesting(focused)


def test_a_heading_wider_than_its_values_keeps_room_for_its_sort_arrow(
    qt_app: QApplication,
) -> None:
    """Measured while sorting was off, a heading had no room for the arrow sorting
    then drew over it: `Match` above a count of 55 read `atc`."""
    table = ClientTable()
    table.resize(540, 600)
    table.show()
    table.show_clients([summary("10.0.0.1", 9)], total=900)
    table._filter.setText("status:200")

    table.show_matches(matched(("10.0.5.5", 55)), "status:200")
    QApplication.processEvents()

    header = table._table.horizontalHeader()
    assert header is not None
    match = column_of(table._table, "Match")
    assert header.sectionSize(match) >= header.sectionSizeHint(match)
    table.close()


def heading_without_arrow(table: ClientTable, column: int) -> int:
    """What a heading needs with no sort arrow drawn in it."""
    header = table._table.horizontalHeader()
    assert header is not None
    shown = header.isSortIndicatorShown()
    header.setSortIndicatorShown(False)
    try:
        return header.sectionSizeHint(column)
    finally:
        header.setSortIndicatorShown(shown)


def test_only_the_sorted_column_makes_room_for_the_arrow(qt_app: QApplication) -> None:
    """Room for an arrow in every heading pushed the list past its panel, behind a
    scroll bar; only one heading draws it."""
    table = ClientTable()
    table.resize(540, 600)
    table.show()
    table.show_clients([summary("10.0.0.1", 9), summary("10.0.0.2", 8)], total=900)
    QApplication.processEvents()

    grid = table._table
    header = grid.horizontalHeader()
    assert header is not None
    for name in ("Paths", "4xx"):
        column = column_of(grid, name)
        assert header.sectionSize(column) == max(
            grid.sizeHintForColumn(column), heading_without_arrow(table, column)
        ), name
    reqs = column_of(grid, "Reqs")
    assert header.sectionSize(reqs) >= header.sectionSizeHint(reqs), "the sorted one"
    table.close()


def test_a_column_the_reader_sorts_by_makes_room_for_the_arrow(qt_app: QApplication) -> None:
    table = ClientTable()
    table.resize(540, 600)
    table.show()
    table.show_clients([summary("10.0.0.1", 9), summary("10.0.0.2", 8)], total=900)
    grid = table._table

    grid.sortItems(column_of(grid, "Paths"), Qt.SortOrder.DescendingOrder)
    QApplication.processEvents()

    header = grid.horizontalHeader()
    assert header is not None
    paths = column_of(grid, "Paths")
    assert header.sectionSize(paths) >= header.sectionSizeHint(paths)
    table.close()


def test_the_caption_wraps_rather_than_running_off_the_panel(partial: ClientTable) -> None:
    """`8 of 52 clients sent a request matching path:/admin · 123` stopped there,
    at the edge of a panel of the width the window opens with."""
    assert partial._caption.wordWrap()


def test_first_and_last_sort_by_time_not_by_their_words(qt_app: QApplication) -> None:
    """As text, `10 Mar` sorts before `15 Feb`."""
    table = ClientTable()
    table.show_clients(
        [
            IpSummary(
                client_ip=ip,
                request_count=10,
                first_seen=first,
                last_seen=first + timedelta(hours=1),
                distinct_paths=3,
                client_error_ratio=0.1,
                bytes_total=1024,
                position=0,
            )
            for ip, first in (
                ("10.0.0.1", datetime(2026, 3, 10, 11, 9, tzinfo=UTC)),
                ("10.0.0.2", datetime(2026, 2, 15, 8, 40, tzinfo=UTC)),
            )
        ],
        total=2,
    )
    grid = table._table
    address = column_of(grid, "Client")
    for heading in ("First", "Last"):
        grid.sortItems(column_of(grid, heading))
        assert [grid.item(r, address).text() for r in range(grid.rowCount())] == [
            "10.0.0.2",
            "10.0.0.1",
        ], heading
