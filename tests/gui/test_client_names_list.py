"""Names in the client list: shown in place of the address, which every action still uses."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QTableWidgetItem
from tables import column_of

from conftest import fired
from zodiarc.gui.columns import CLIENT_ADDRESS
from zodiarc.gui.panels import ClientTable
from zodiarc.storage.base import ClientMatchPage, IpSummary
from zodiarc.style import display_safe

START = datetime(2026, 3, 10, 19, 12, tzinfo=UTC)
BLUE = "#49a9ff"
NAMES = {"10.0.0.1": "Office VPN"}


def summary(ip: str, requests: int) -> IpSummary:
    return IpSummary(
        client_ip=ip,
        request_count=requests,
        first_seen=START,
        last_seen=START + timedelta(minutes=5),
        distinct_paths=3,
        client_error_ratio=0.1,
        bytes_total=1024,
    )


@pytest.fixture
def table(qt_app: QApplication) -> ClientTable:
    shown = ClientTable()
    shown.resize(520, 500)
    shown.show_clients([summary("10.0.0.1", 90), summary("10.0.0.2", 80)], total=2)
    shown.show()
    QApplication.processEvents()
    return shown


def row_of(table: ClientTable, address: str) -> int:
    for row in range(table._table.rowCount()):
        item = table._table.item(row, 0)
        if item is not None and item.data(CLIENT_ADDRESS) == address:
            return row
    raise AssertionError(f"{address} is not listed")


def cell(table: ClientTable, address: str) -> QTableWidgetItem:
    item = table._table.item(row_of(table, address), 0)
    assert item is not None
    return item


def test_a_named_row_shows_its_name_and_keeps_its_address(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)

    item = cell(table, "10.0.0.1")
    assert item.text() == "Office VPN"
    assert item.toolTip().startswith("10.0.0.1")
    assert cell(table, "10.0.0.2").text() == "10.0.0.2"


def test_shown_false_restores_addresses(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)

    table.set_names(NAMES, shown=False)

    assert cell(table, "10.0.0.1").text() == "10.0.0.1"


def test_names_survive_a_refill(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)

    table.show_clients([summary("10.0.0.1", 90)], total=1)

    assert cell(table, "10.0.0.1").text() == "Office VPN"


def test_choosing_a_named_row_emits_the_address(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)
    chosen: list[str] = []
    table.client_chosen.connect(chosen.append)

    table._table.selectRow(row_of(table, "10.0.0.1"))

    assert chosen == ["10.0.0.1"]
    assert table.selected_client() == "10.0.0.1"


def test_select_quietly_finds_a_named_row(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)

    assert table.select_quietly("10.0.0.1")
    assert table.selected_client() == "10.0.0.1"


def test_the_menu_acts_on_the_address(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)
    asked: list[str] = []
    table.rename_requested.connect(asked.append)
    table.bookmark_requested.connect(asked.append)
    item = cell(table, "10.0.0.1")
    menu = table._menu_at(table._table.visualItemRect(item).center())
    assert menu is not None

    for action in menu.actions():
        action.trigger()

    assert asked == ["10.0.0.1", "10.0.0.1"]


def test_sorting_by_client_orders_by_address_not_name(table: ClientTable) -> None:
    table.set_names({"10.0.0.2": "Alpha", "10.0.0.1": "Zulu"}, shown=True)

    table._table.sortItems(0, Qt.SortOrder.AscendingOrder)

    assert [table._table.item(r, 0).data(CLIENT_ADDRESS) for r in range(2)] == [
        "10.0.0.1",
        "10.0.0.2",
    ]


def test_a_bookmarked_named_row_keeps_both_tips(table: ClientTable) -> None:
    table.set_names(NAMES, shown=True)
    table.set_marks({"10.0.0.1": (BLUE, "Bookmarked: the VPN")})

    tip = cell(table, "10.0.0.1").toolTip()

    assert tip.startswith("10.0.0.1")
    assert "Bookmarked: the VPN" in tip
    assert not cell(table, "10.0.0.1").icon().isNull()


def test_a_name_with_control_characters_is_shown_safely(table: ClientTable) -> None:
    table.set_names({"10.0.0.1": "a‮b"}, shown=True)

    assert cell(table, "10.0.0.1").text() == display_safe("a‮b")


# -- finding clients by name --------------------------------------------------------


def matched(*rows: tuple[str, int], counted: bool = True) -> ClientMatchPage:
    return ClientMatchPage(
        tuple(summary(ip, 10 + n) for n, (ip, _hits) in enumerate(rows)),
        tuple(hits for _ip, hits in rows),
        len(rows),
        sum(hits for _ip, hits in rows),
        0,
    )


def match_texts(table: ClientTable) -> list[tuple[str, str]]:
    column = column_of(table._table, "Match")
    return [
        (table._table.item(row, 0).data(CLIENT_ADDRESS), table._table.item(row, column).text())
        for row in range(table._table.rowCount())
        if not table._table.isRowHidden(row)
    ]


def test_a_client_found_only_by_name_says_so_and_comes_first(table: ClientTable) -> None:
    table.set_names({"10.0.0.3": "Office VPN"}, shown=True)
    table._filter.setText("office")

    table.show_matches(
        matched(("10.0.0.3", 0), ("10.0.0.9", 5)), "office", named=frozenset({"10.0.0.3"})
    )

    assert match_texts(table) == [("10.0.0.3", "by name"), ("10.0.0.9", "5")]
    assert not table._table.isColumnHidden(column_of(table._table, "Match"))


def test_a_client_found_both_ways_shows_both(table: ClientTable) -> None:
    table.set_names({"10.0.0.3": "Office VPN"}, shown=True)
    table._filter.setText("office")

    table.show_matches(
        matched(("10.0.0.3", 2), ("10.0.0.9", 5)), "office", named=frozenset({"10.0.0.3"})
    )

    assert match_texts(table) == [("10.0.0.3", "2, by name"), ("10.0.0.9", "5")]


def test_names_alone_show_the_match_column_without_counts(table: ClientTable) -> None:
    table.set_names({"10.0.0.3": "Office VPN"}, shown=True)
    table._filter.setText("name:office")

    table.show_matches(
        matched(("10.0.0.3", 0)), "name:office", counted=False, named=frozenset({"10.0.0.3"})
    )

    assert match_texts(table) == [("10.0.0.3", "by name")]
    assert table._caption.text().startswith("1 of 2 clients match name:office")
    assert "Triage" not in table._caption.text()


def test_a_named_row_on_the_page_is_not_hidden_while_searching(qt_app: QApplication) -> None:
    partial = ClientTable()
    partial.show_clients([summary("10.0.0.1", 90), summary("10.0.0.2", 80)], total=900)
    partial.set_names({"10.0.0.2": "Office VPN"}, shown=True)

    partial._filter.setText("office")

    visible = [
        partial._table.item(row, 0).data(CLIENT_ADDRESS)
        for row in range(partial._table.rowCount())
        if not partial._table.isRowHidden(row)
    ]
    assert visible == ["10.0.0.2"]


def test_a_name_on_the_page_is_found_with_names_hidden(qt_app: QApplication) -> None:
    partial = ClientTable()
    partial.show_clients([summary("10.0.0.1", 90), summary("10.0.0.2", 80)], total=2)
    partial.set_names({"10.0.0.2": "Office VPN"}, shown=False)

    partial._filter.setText("office")

    visible = [
        partial._table.item(row, 0).text()
        for row in range(partial._table.rowCount())
        if not partial._table.isRowHidden(row)
    ]
    assert visible == ["10.0.0.2"]


def test_a_whole_list_still_asks_the_case_when_a_name_matches(qt_app: QApplication) -> None:
    """An address-like word would be answered on the page; a name it matches needs marking."""
    whole = ClientTable()
    whole.show_clients([summary("10.0.0.1", 90), summary("10.0.0.3", 80)], total=2)
    whole.set_names({"10.0.0.1": "Attacker 2"}, shown=True)
    asked: list[tuple[str, int]] = []
    whole.page_requested.connect(lambda query, offset: asked.append((query, offset)))

    whole._filter.setText("2")
    fired(whole._search_timer)

    assert asked == [("2", 0)]


def test_the_box_says_it_finds_names(table: ClientTable) -> None:
    assert "name:" in table._filter.toolTip()


def test_an_address_after_a_name_search_is_looked_for_in_the_whole_list(
    qt_app: QApplication,
) -> None:
    whole = ClientTable()
    whole.show_clients(
        [summary("10.0.0.1", 90), summary("10.0.0.3", 80), summary("10.0.0.4", 70)], total=3
    )
    whole.set_names({"10.0.0.1": "Attacker 2"}, shown=True)
    whole._filter.setText("2")
    whole.show_matches(matched(("10.0.0.1", 0)), "2", counted=False, named=frozenset({"10.0.0.1"}))

    whole._filter.setText("10.0.0.4")

    visible = [
        whole._table.item(row, 0).data(CLIENT_ADDRESS)
        for row in range(whole._table.rowCount())
        if not whole._table.isRowHidden(row)
    ]
    assert visible == ["10.0.0.4"]
