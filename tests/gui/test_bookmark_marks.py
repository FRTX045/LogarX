"""What is bookmarked shows where it appears, and can be bookmarked from there.

A ribbon in the client list and on the evidence line, in the category's colour,
kept through every refill and re-sort; a right-click on a row bookmarks it; a
button bookmarks the activity on show, and another the search answered.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtWidgets import QApplication

from logarc.core.activity import ActivityCategory, Outcome, Severity
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.core.graph import GraphNode
from logarc.evidence import EvidenceLine
from logarc.gui.evidence_panel import EvidencePanel
from logarc.gui.panels import ClientTable
from logarc.gui.ribbon import ribbon_icon
from logarc.storage.base import ClientMatchPage, IpSummary

START = datetime(2026, 3, 10, 19, 12, tzinfo=UTC)
BLUE = "#49a9ff"


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


@pytest.fixture
def table(qt_app: QApplication) -> ClientTable:
    shown = ClientTable()
    shown.resize(520, 500)
    shown.show_clients(
        [summary("10.0.0.1", 90), summary("2001:db8::77", 80), summary("172.16.0.9", 70)],
        total=900,
    )
    shown.show()
    QApplication.processEvents()
    return shown


def cell(table: ClientTable, ip: str):
    for row in range(table._table.rowCount()):
        item = table._table.item(row, 0)
        if item is not None and item.text() == ip:
            return item
    raise AssertionError(f"{ip} is not listed")


def marked(table: ClientTable) -> set[str]:
    return {
        item.text()
        for row in range(table._table.rowCount())
        if (item := table._table.item(row, 0)) is not None and not item.icon().isNull()
    }


def test_the_ribbon_is_drawn(qt_app: QApplication) -> None:
    assert not ribbon_icon(BLUE).isNull()
    assert not ribbon_icon(BLUE, hollow=True).isNull()


def test_a_marked_client_shows_a_ribbon_that_says_which_bookmark(table: ClientTable) -> None:
    table.set_marks({"2001:db8::77": (BLUE, "Bookmarked: came back after the 404s")})
    assert marked(table) == {"2001:db8::77"}
    assert "came back after the 404s" in cell(table, "2001:db8::77").toolTip()


def test_a_mark_survives_a_refill_and_a_re_sort(table: ClientTable) -> None:
    table.set_marks({"172.16.0.9": (BLUE, "Bookmarked")})
    table.show_clients(
        [summary("172.16.0.9", 5), summary("10.0.0.1", 90), summary("10.9.9.9", 1)], total=900
    )
    table._table.sortItems(1, Qt.SortOrder.AscendingOrder)
    assert marked(table) == {"172.16.0.9"}


def test_clearing_the_marks_takes_the_ribbons_away(table: ClientTable) -> None:
    table.set_marks({"10.0.0.1": (BLUE, "Bookmarked")})
    table.set_marks({})
    assert marked(table) == set()
    assert cell(table, "10.0.0.1").toolTip() == ""


def test_the_ribbon_does_not_cut_the_address(table: ClientTable) -> None:
    before = table._table.columnWidth(0)
    table.set_marks({"2001:db8::77": (BLUE, "Bookmarked")})
    QApplication.processEvents()
    assert table._table.columnWidth(0) > before


def row_point(table, row: int) -> QPoint:
    return table.visualRect(table.model().index(row, 0)).center()


def test_a_right_click_on_a_client_bookmarks_it(table: ClientTable) -> None:
    asked: list[str] = []
    table.bookmark_requested.connect(asked.append)
    row = table._table.row(cell(table, "172.16.0.9"))
    menu = table._menu_at(row_point(table._table, row))
    assert menu is not None
    (action,) = menu.actions()
    assert action.text() == "Bookmark this client\N{HORIZONTAL ELLIPSIS}"
    action.trigger()
    assert asked == ["172.16.0.9"]
    assert table._menu_at(QPoint(5, table._table.viewport().height() - 2)) is None


def test_the_selected_client_is_known(table: ClientTable) -> None:
    assert table.selected_client() is None
    table._table.selectRow(table._table.row(cell(table, "10.0.0.1")))
    assert table.selected_client() == "10.0.0.1"


def test_an_answered_search_can_be_bookmarked_and_only_then(table: ClientTable) -> None:
    asked: list[bool] = []
    table.bookmark_search_requested.connect(lambda: asked.append(True))
    assert not table.search_bookmark.isVisibleTo(table)
    assert table.answered_search() is None

    table._filter.setText("status:200 path:/admin")
    table.show_matches(
        ClientMatchPage((summary("10.0.0.2", 12, 1), summary("10.0.0.3", 10, 2)), (7, 3), 2, 10, 0),
        "status:200 path:/admin",
    )
    assert table.search_bookmark.isVisibleTo(table)
    assert table.answered_search() == ("status:200 path:/admin", 2, 10)
    table.search_bookmark.click()
    assert asked == [True]

    table._filter.setText("status:500")
    assert not table.search_bookmark.isVisibleTo(table)
    assert table.answered_search() is None


# -- the evidence -----------------------------------------------------------------------


def attack() -> GraphNode:
    return GraphNode(
        node_id="s3/1",
        label="Credential Attack",
        category=ActivityCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        outcome=Outcome.BLOCKED,
        request_count=4,
        distinct_paths=1,
        bytes_total=1,
        start=START,
        end=START + timedelta(seconds=40),
        owasp=None,
        top_targets=("/login",),
        rule_ids=("credential",),
        evidence=(),
        evidence_total=4,
        episode_ids=("s3/1",),
    )


def lines(count: int = 4) -> list[EvidenceLine]:
    return [
        EvidenceLine(
            ref=EvidenceRef("C:logs:excerpt.log", 2014 + index),
            source_path="excerpt.log",
            text=f"line {index}",
            event=NormalizedEvent(
                timestamp=START + timedelta(seconds=10 * index),
                client_ip="192.0.2.23",
                evidence=EvidenceRef("C:logs:excerpt.log", 2014 + index),
                method="POST",
                path="/login",
                status=401 + (index == count - 1) * 28,
            ),
            verified=True,
        )
        for index in range(count)
    ]


@pytest.fixture
def panel(qt_app: QApplication) -> EvidencePanel:
    shown = EvidencePanel()
    shown.resize(700, 600)
    shown.show()
    QApplication.processEvents()
    return shown


def marked_lines(panel: EvidencePanel) -> set[EvidenceRef]:
    shown = lines()
    found = set()
    for row in range(panel._table.rowCount()):
        item = panel._table.item(row, 0)
        if item is not None and not item.icon().isNull():
            found.add(shown[item.data(Qt.ItemDataRole.UserRole)].ref)
    return found


def test_a_marked_line_keeps_its_ribbon_through_a_sort(panel: EvidencePanel) -> None:
    saved = lines()[2].ref
    panel.set_marks({saved: (BLUE, "Login attacks: first failed login")})
    panel.show_evidence(attack(), lines())
    panel._table.sortItems(3, Qt.SortOrder.DescendingOrder)
    assert marked_lines(panel) == {saved}


def test_marks_set_after_the_lines_are_shown_apply_at_once(panel: EvidencePanel) -> None:
    panel.show_evidence(attack(), lines())
    panel.set_marks({lines()[0].ref: (BLUE, "Bookmarked")})
    assert marked_lines(panel) == {lines()[0].ref}
    panel.set_marks({})
    assert marked_lines(panel) == set()
    assert all(panel._table.item(row, 0).toolTip() == "" for row in range(4))


def test_the_bookmark_button_is_there_while_an_activity_is(panel: EvidencePanel) -> None:
    asked: list[bool] = []
    panel.bookmark_requested.connect(lambda: asked.append(True))
    assert not panel.bookmark_button.isVisibleTo(panel)
    panel.show_evidence(attack(), lines())
    assert panel.bookmark_button.isVisibleTo(panel)
    panel.bookmark_button.click()
    assert asked == [True]
    panel.clear()
    assert not panel.bookmark_button.isVisibleTo(panel)


def test_a_right_click_on_a_line_bookmarks_that_line(panel: EvidencePanel) -> None:
    asked: list[EvidenceLine] = []
    panel.bookmark_line_requested.connect(asked.append)
    panel.show_evidence(attack(), lines())
    menu = panel._menu_at(row_point(panel._table, 1))
    assert menu is not None
    (action,) = menu.actions()
    assert action.text() == "Bookmark this line\N{HORIZONTAL ELLIPSIS}"
    action.trigger()
    shown_index = panel._table.item(1, 0).data(Qt.ItemDataRole.UserRole)
    assert [line.ref for line in asked] == [lines()[shown_index].ref]


def test_the_line_on_show_can_be_chosen_and_read_back(panel: EvidencePanel) -> None:
    assert panel.selected_line() is None and panel.shown_node() is None
    panel.show_evidence(attack(), lines())
    assert panel.shown_node() == attack()
    assert panel.select_line(lines()[3].ref)
    selected = panel.selected_line()
    assert selected is not None and selected.ref == lines()[3].ref
    assert not panel.select_line(EvidenceRef("other.log", 1))


def test_an_address_typed_after_an_answer_is_not_that_answer(qt_app: QApplication) -> None:
    """A whole case on one page answers an address itself, with no search to run.

    The answer of the search before it is still in hand then, and must not be
    offered as the search the box now holds.
    """
    whole = ClientTable()
    whole.show_clients([summary("10.0.0.1", 90), summary("10.0.0.2", 80)], total=2)
    whole._filter.setText("status:200")
    whole.show_matches(ClientMatchPage((summary("10.0.0.2", 12, 1),), (7,), 1, 7, 0), "status:200")
    assert whole.answered_search() == ("status:200", 1, 7)

    whole._filter.setText("10.0.0.1")

    assert whole.answered_search() is None
    assert not whole.search_bookmark.isVisibleTo(whole)
