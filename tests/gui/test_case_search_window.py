"""Searching the whole case from the client box, in the window.

Run without a display, on a case built here: a sweeper finds two pages under
/admin among 404s and then fails to sign in; a prober is refused /admin twice;
somebody browses. Times are 11 March 2026, UTC.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtTest import QTest
from tables import column_of

from conftest import fired, settled
from logarx import caseview
from logarx.case import Case
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.core.window import TimeWindow
from logarx.gui.app import MainWindow
from logarx.gui.client_filter import awaiting_scan
from logarx.gui.panels import ClientTable

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

SWEEPER, PROBER, BROWSER = "198.51.100.31", "192.0.2.66", "192.0.2.1"
DAY = datetime(2026, 3, 11, tzinfo=UTC)
START = DAY + timedelta(minutes=50)
DOT = "\N{MIDDLE DOT}"
DASH = "\N{EN DASH}"


def request(
    ip: str, at: datetime, line: int, path: str, status: int, **rest: Any
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=at,
        client_ip=ip,
        evidence=EvidenceRef("access.log", line),
        path=path,
        method=rest.pop("method", "GET"),
        status=status,
        user_agent=rest.pop("user_agent", "Mozilla/5.0"),
        protocol="HTTP/1.1",
    )


def make_case(root: Path, extra: Sequence[NormalizedEvent] = ()) -> Path:
    found = {10: "/admin/panel", 27: "/admin/login"}
    sweep = [
        request(SWEEPER, START + timedelta(seconds=i), 1 + i, found.get(i, f"/guess/{i}"),
                200 if i in found else (500 if i == 21 else 404), user_agent="gobuster/3.5")
        for i in range(33)
    ]  # fmt: skip
    later = START + timedelta(minutes=5)
    sign_in = [
        request(SWEEPER, later + timedelta(seconds=i * 2), 50 + i, "/login", status, method="POST")
        for i, status in enumerate([401, 401, 401, 302])
    ]
    refused = [
        request(PROBER, START + timedelta(minutes=2, seconds=i * 5), 80 + i, "/admin", 403)
        for i in range(2)
    ]
    browsing = [
        request(BROWSER, START + timedelta(minutes=10, seconds=i * 5), 100 + i, "/", 200)
        for i in range(4)
    ]
    with Case.create(root) as case:
        for batch in (sweep, sign_in, refused, browsing, list(extra)):
            case.store.write(batch)
        case.store.finalize()
    return case.root


def opened(qt_app: QApplication, case: Path) -> MainWindow:
    shown = MainWindow()
    shown.report_error = lambda message, detail: (_ for _ in ()).throw(AssertionError(message))
    shown._load_case(case)
    settled(qt_app)
    assert shown._triage.result is not None, "premise: the scan finished"
    return shown


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path) -> Iterator[MainWindow]:
    shown = opened(qt_app, make_case(tmp_path / "case"))
    yield shown
    shown.close()
    settled(qt_app)


@pytest.fixture
def paged(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[MainWindow]:
    """The same case a client to a page, as a case too large to list whole is.

    A list holding every client answers an address itself; only a larger case
    asks the window.
    """
    monkeypatch.setattr(ClientTable, "PAGE_SIZE", 1)
    monkeypatch.setattr(caseview, "CLIENT_LIMIT", 1)
    shown = opened(qt_app, make_case(tmp_path / "case"))
    yield shown
    shown.close()
    settled(qt_app)


def search(qt_app: QApplication, window: MainWindow, text: str) -> None:
    """Typed into the client box, heard once typing rests."""
    window._clients._filter.setText(text)
    fired(window._clients._search_timer)
    settled(qt_app)


def listed(window: MainWindow) -> list[str]:
    table = window._clients._table
    column = column_of(table, "Client")
    return [
        item.text()
        for row in range(table.rowCount())
        if (item := table.item(row, column)) is not None and not table.isRowHidden(row)
    ]


def matches(window: MainWindow) -> list[str]:
    table = window._clients._table
    column = column_of(table, "Match")
    return [
        item.text()
        for row in range(table.rowCount())
        if (item := table.item(row, column)) is not None and not table.isRowHidden(row)
    ]


def caption(window: MainWindow) -> str:
    return window._clients._caption.text()


# -- requests ------------------------------------------------------------------------


def test_the_clients_that_sent_a_matching_request(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, "status:200 path:/admin")

    assert listed(window) == [SWEEPER]
    assert matches(window) == ["2"]
    assert caption(window) == (
        f"1 of 3 clients sent a request matching status:200 path:/admin {DOT} 2 requests"
    )


def test_most_matches_first_then_the_address(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, "path:/admin")

    assert listed(window) == [PROBER, SWEEPER], "two each: the lower address first"
    assert matches(window) == ["2", "2"]


def test_an_address_is_found_as_before(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, BROWSER)

    assert listed(window) == [BROWSER]
    assert caption(window) == f"1 of 3 clients matches {BROWSER}"


def test_several_addresses_are_still_an_address_search(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, f"{PROBER} {BROWSER}")

    assert listed(window) == [BROWSER, PROBER], "busiest first"
    assert window._clients._table.isColumnHidden(column_of(window._clients._table, "Match"))
    assert caption(window) == f"2 of 3 clients match {PROBER} {BROWSER}"


def test_an_ip_filter_finds_part_of_an_address(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, "ip:192.0.2")

    assert listed(window) == [BROWSER, PROBER]


def test_several_addresses_asked_of_a_larger_case_are_an_address_search(
    qt_app: QApplication, paged: MainWindow
) -> None:
    search(qt_app, paged, f"{PROBER} {BROWSER}")

    assert listed(paged) == [BROWSER], "busiest first, a page of one"
    assert paged._clients._table.isColumnHidden(column_of(paged._clients._table, "Match"))
    assert caption(paged).startswith(f"Matches 1{DASH}1 of 2 for {PROBER} {BROWSER}")


def test_an_ip_filter_asked_of_a_larger_case_finds_part_of_an_address(
    qt_app: QApplication, paged: MainWindow
) -> None:
    search(qt_app, paged, "ip:192.0.2")

    assert listed(paged) == [BROWSER]
    assert caption(paged).startswith(f"Matches 1{DASH}1 of 2 for ip:192.0.2")


def test_an_address_and_a_filter_together(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, f"{PROBER} path:/admin")

    assert listed(window) == [PROBER]


# -- time ----------------------------------------------------------------------------


def test_a_time_moves_the_range_and_the_rest_is_searched_in_it(
    qt_app: QApplication, window: MainWindow
) -> None:
    """`after:` and `before:` are the range's, so they move it, and leave the box."""
    search(qt_app, window, "after:00:55 status:401")
    settled(qt_app)

    assert window._window.start == DAY + timedelta(minutes=55), "read on the range's first day"
    assert window._clients.query_text() == "status:401"
    assert listed(window) == [SWEEPER]
    assert matches(window) == ["3"]


def test_typing_while_the_range_moves_is_kept(qt_app: QApplication, window: MainWindow) -> None:
    """On a large case the new range takes seconds to read; what is typed meanwhile
    belongs in the box when it arrives."""
    window._clients._filter.setText("after:00:55")
    window._clients._ask()  # the box at rest: the range starts moving
    QTest.keyClicks(window._clients._filter.edit, "status:401")
    settled(qt_app)
    fired(window._clients._search_timer)
    settled(qt_app)

    assert window._window.start == DAY + timedelta(minutes=55)
    assert window._clients.query_text() == "status:401"
    assert listed(window) == [SWEEPER]


def test_a_range_chosen_on_the_bar_starts_the_box_afresh(
    qt_app: QApplication, window: MainWindow
) -> None:
    """As it always has. Only a time typed in the box carries the rest of the box."""
    search(qt_app, window, "status:401")

    window._time_filter.changed.emit(TimeWindow(DAY + timedelta(minutes=55), None))
    settled(qt_app)

    assert window._clients.query_text() == ""


def test_before_is_kept_out_of_the_range(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, "before:2026-03-11T00:52")
    settled(qt_app)

    assert window._window.end is not None
    assert window._window.end < DAY + timedelta(minutes=52)
    assert PROBER not in listed(window), "its first request is at 00:52 exactly"
    assert window._clients.query_text() == ""


def test_a_time_at_the_case_start_is_the_whole_case(
    qt_app: QApplication, window: MainWindow
) -> None:
    """Nothing to move: the box is searched for the rest, and the range stays open."""
    search(qt_app, window, "after:00:50 status:401")
    settled(qt_app)

    assert window._window.is_open
    assert window._clients.query_text() == "status:401"
    assert listed(window) == [SWEEPER]


def test_a_time_of_day_is_read_on_the_ranges_first_day(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """Not the case's first day: a range already on the 11th stays on the 11th."""
    late = DAY - timedelta(minutes=1)
    shown = opened(qt_app, make_case(tmp_path / "case", [request(BROWSER, late, 200, "/", 200)]))
    try:
        shown._apply_window(TimeWindow(DAY, None))
        settled(qt_app)

        search(qt_app, shown, "after:00:55")
        settled(qt_app)

        assert shown._window.start == DAY + timedelta(minutes=55)
    finally:
        shown.close()
        settled(qt_app)


def test_a_range_that_ends_before_it_starts_is_refused(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "after:01:00 before:00:50")

    assert window._window.is_open, "the range did not move"
    assert caption(window).startswith("Could not search all clients for after:01:00")


# -- activity ------------------------------------------------------------------------


def test_an_activity_lists_the_clients_the_scan_saw_it_on(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "activity:enumeration")

    assert listed(window) == [SWEEPER]
    assert window._clients._table.isColumnHidden(column_of(window._clients._table, "Match"))
    assert caption(window) == "1 of 3 clients match activity:enumeration in the Triage scan"


def test_an_activity_and_a_filter_count_the_requests(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "activity:enumeration status:200")

    assert listed(window) == [SWEEPER]
    assert matches(window) == ["2"]


def test_an_activity_before_the_scan_finishes_says_so_then_answers(
    qt_app: QApplication, window: MainWindow
) -> None:
    window._triage.shutdown()

    search(qt_app, window, "activity:enumeration")

    assert listed(window) == []
    assert caption(window) == awaiting_scan(None, scanning=False)

    window._triage.start(window._case_path)
    settled(qt_app)

    assert listed(window) == [SWEEPER], "asked again once the scan finished"
    assert caption(window) == "1 of 3 clients match activity:enumeration in the Triage scan"


# -- what the box offers -----------------------------------------------------------


def test_the_box_offers_the_values_in_the_range(qt_app: QApplication, window: MainWindow) -> None:
    values = window._clients._filter._values

    assert ("404", f"1 client {DOT} 30 requests") in values["status"]
    assert ("4xx", f"2 clients {DOT} 35 requests") in values["status"]
    assert ("POST", f"1 client {DOT} 4 requests") in values["method"]
    assert ("enumeration", "1 client") in values["activity"]
    assert window._clients._filter._values_title == "VALUES IN THE CASE"


def test_a_narrower_range_offers_its_own_values(qt_app: QApplication, window: MainWindow) -> None:
    search(qt_app, window, "after:00:59")
    settled(qt_app)

    values = window._clients._filter._values
    assert [value for value, _note in values["status"]] == ["200", "2xx"]
    assert window._clients._filter._values_title == "VALUES IN THIS RANGE"


# -- opening a client from a search --------------------------------------------------


def test_a_client_opened_from_a_search_is_filtered_the_same_way(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "status:200 path:/admin")

    window._reconstruct(SWEEPER)
    settled(qt_app)
    settled(qt_app)

    assert window._evidence.filter_text() == "status:200 path:/admin"
    assert window._selected is not None, "the first activity holding a match is opened"
    assert window._selected.request_count == 33
    assert "2 of 33 lines match" in window._evidence.strip.text()


def test_the_first_match_is_the_earliest_activity_holding_one(
    qt_app: QApplication, window: MainWindow
) -> None:
    """The sweep's 404s come before the sign-in's 401s."""
    search(qt_app, window, "status:4xx")

    window._reconstruct(SWEEPER)
    settled(qt_app)
    settled(qt_app)

    assert window._selected is not None
    assert window._selected.request_count == 33


def test_a_choice_made_before_the_matches_are_known_stands(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "status:200")
    window._reconstruct(SWEEPER)
    settled(qt_app)
    settled(qt_app)
    first = window._selected
    assert first is not None
    other = next(n for n in window._result.trace.nodes if n.node_id != first.node_id)
    window._show_evidence(other.node_id)
    settled(qt_app)

    # The matches arriving after the reader chose, as they can on a large case.
    window._open_first_match = window._result
    window._open_first(window._result, frozenset({first.node_id}))
    settled(qt_app)

    assert window._selected.node_id == other.node_id


def test_lines_asked_for_that_are_not_there_open_nothing(
    qt_app: QApplication, window: MainWindow
) -> None:
    """Where to start asked for those lines, not for the first match."""
    search(qt_app, window, "status:200")

    window._reconstruct(SWEEPER, evidence=(EvidenceRef("access.log", 999),))
    settled(qt_app)
    settled(qt_app)

    assert window._evidence.filter_text() == "status:200"
    assert window._selected is None


def test_a_client_found_by_address_opens_unfiltered(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, SWEEPER)

    window._reconstruct(SWEEPER)
    settled(qt_app)

    assert window._evidence.filter_text() == ""
    assert window._selected is None


def test_lines_asked_for_by_name_win_over_the_first_match(
    qt_app: QApplication, window: MainWindow
) -> None:
    """Where to start opens a client at the lines it found; those come first."""
    search(qt_app, window, "status:200")

    window._reconstruct(SWEEPER, evidence=(EvidenceRef("access.log", 50),))
    settled(qt_app)
    settled(qt_app)

    assert window._evidence.filter_text() == "status:200"
    assert window._selected is not None
    assert window._selected.request_count == 4, "the sign-in the lines belong to"
    assert not window._evidence.no_results.isHidden(), "and it holds no 200"


def test_the_first_match_is_opened_only_once(qt_app: QApplication, window: MainWindow) -> None:
    """Moving off it, or changing the filter, is the reader's to do."""
    search(qt_app, window, "status:200")
    window._reconstruct(SWEEPER)
    settled(qt_app)
    settled(qt_app)
    first = window._selected
    other = next(n for n in window._result.trace.nodes if n.node_id != first.node_id)

    window._show_evidence(other.node_id)
    settled(qt_app)
    window._evidence.filter_box.setText("status:401")
    fired(window._evidence._rest)
    settled(qt_app)

    assert window._selected.node_id == other.node_id
