"""Names wherever a client is listed outside the client list, and in the evidence record."""

from __future__ import annotations

from datetime import UTC, datetime

from PyQt6.QtWidgets import QApplication
from test_bookmarks_tab import shelf
from test_triage_panel import make_case
from test_who_else import DIRB, GOBUSTER

from conftest import settled
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.evidence import EvidenceLine
from logarx.gui.bookmarks_tab import BookmarksTab
from logarx.gui.evidence_view import detail_for
from logarx.gui.triage import TriagePanel
from logarx.gui.who_else import WhoElseDialog
from logarx.triage.scan import scan_case


def line() -> EvidenceLine:
    ref = EvidenceRef("access.log", 36)
    return EvidenceLine(
        ref=ref,
        source_path="access.log",
        text='127.0.0.1 - - [x] "GET / HTTP/1.1" 200 10',
        event=NormalizedEvent(
            timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            client_ip="127.0.0.1",
            evidence=ref,
            method="GET",
            path="/",
            status=200,
        ),
    )


def test_triage_rows_show_names_and_tip_the_address(qt_app: QApplication, tmp_path) -> None:
    panel = TriagePanel()
    panel.show_result(scan_case(make_case(tmp_path, 2)))
    settled(qt_app)

    panel.set_names({"192.0.2.1": "Office VPN"}, shown=True)

    texts = {panel.table.item(r, 1).toolTip(): panel.table.item(r, 1).text() for r in range(2)}
    assert texts == {"192.0.2.1": "Office VPN", "192.0.2.0": "192.0.2.0"}
    panel.set_names({"192.0.2.1": "Office VPN"}, shown=False)
    assert {panel.table.item(r, 1).text() for r in range(2)} == {"192.0.2.0", "192.0.2.1"}
    panel.close()


def test_who_else_rows_show_names_and_act_on_the_address(qt_app: QApplication) -> None:
    dialog = WhoElseDialog()
    dialog.set_names({"192.0.2.30": "Dirb box"}, shown=True)
    dialog.show_matches("directory_enumeration", [GOBUSTER, DIRB], client_ip="192.0.2.99")
    row = next(r for r in range(2) if dialog.table.item(r, 0).text() == "Dirb box")
    opened: list[str] = []
    dialog.open_client.connect(opened.append)
    asked: list[str] = []
    dialog.bookmark_requested.connect(asked.append)

    dialog._opened(row, 0)
    menu = dialog._menu_at(dialog.table.visualItemRect(dialog.table.item(row, 0)).center())
    assert menu is not None
    menu.actions()[0].trigger()

    assert opened == ["192.0.2.30"]
    assert asked == ["192.0.2.30"]
    dialog.set_names({"192.0.2.30": "Dirb box"}, shown=False)
    assert dialog.table.item(row, 0).text() == "192.0.2.30"
    dialog.close()


def test_evidence_view_adds_a_name_row_above_the_logged_address() -> None:
    fields = detail_for(line(), decode=True, client_name="Office VPN").fields
    labels = [label for label, _value, _colour in fields]

    at = labels.index("Client IP (logged address)")
    assert labels[at - 1] == "Name"
    assert fields[at - 1][1] == "Office VPN"
    assert fields[at][1] == "127.0.0.1"


def test_evidence_view_has_no_name_row_when_unnamed() -> None:
    labels = [label for label, _value, _colour in detail_for(line(), decode=True).fields]

    assert "Name" not in labels


def client_column(tab: BookmarksTab) -> list[str]:
    tree = tab.tree
    return [
        top.child(row).text(2)
        for top in (tree.topLevelItem(i) for i in range(tree.topLevelItemCount()))
        if top is not None
        for row in range(top.childCount())
    ]


def test_bookmarks_tab_shows_the_client_name(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.show_shelf(shelf(), gone=lambda b: False)

    tab.set_names({"10.0.0.9": "Office VPN"}, shown=True)

    assert "Office VPN" in client_column(tab)
    assert "10.0.0.9" not in client_column(tab)
    tab.set_names({"10.0.0.9": "Office VPN"}, shown=False)
    assert "10.0.0.9" in client_column(tab)
