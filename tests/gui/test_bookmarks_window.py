"""Bookmarks in the window: saved from where the reader is, opened in one step, marked.

The story `test_case_search_window` tells, ingested from a real log so that
every line names a file the case knows: a sweeper finds two pages under /admin
among 404s and then fails to sign in; a prober is refused /admin twice;
somebody browses. Times are 11 March 2026, UTC.
"""

from __future__ import annotations

import csv
import io
import os
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QFileDialog, QTableWidget
from test_case_search_window import BROWSER, PROBER, START, SWEEPER, opened, search

from conftest import settled
from logarc import bookmarks
from logarc.bookmarks import Kind, said_for_activity, said_for_request
from logarc.case import Case
from logarc.core.evidence import EvidenceRef
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui.app import MainWindow

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from logarc.core.graph import GraphNode


def _line(
    ip: str,
    at: datetime,
    path: str,
    status: int,
    *,
    method: str = "GET",
    agent: str = "Mozilla/5.0",
) -> str:
    when = at.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{when}] "{method} {path} HTTP/1.1" {status} 512 "-" "{agent}"'


def make_case(root: Path) -> Path:
    """Lines 1-33 the sweep, 34-37 the sign-in, 38-39 the prober, 40-43 the browsing."""
    found = {10: "/admin/panel", 27: "/admin/login"}
    lines = [
        _line(
            SWEEPER,
            START + timedelta(seconds=i),
            found.get(i, f"/guess/{i}"),
            200 if i in found else (500 if i == 21 else 404),
            agent="gobuster/3.5",
        )
        for i in range(33)
    ]
    later = START + timedelta(minutes=5)
    lines += [
        _line(SWEEPER, later + timedelta(seconds=i * 2), "/login", status, method="POST")
        for i, status in enumerate([401, 401, 401, 302])
    ]
    lines += [
        _line(PROBER, START + timedelta(minutes=2, seconds=i * 5), "/admin", 403) for i in range(2)
    ]
    lines += [
        _line(BROWSER, START + timedelta(minutes=10, seconds=i * 5), "/", 200) for i in range(4)
    ]
    log = root.parent / f"{root.name}.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root) as case:
        case.ingest([log])
    return root


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path) -> Iterator[MainWindow]:
    shown = opened(qt_app, make_case(tmp_path / "case"))
    shown.resize(1400, 900)
    shown.show()
    shown.activateWindow()
    settled(qt_app)
    yield shown
    shown.close()
    settled(qt_app)


def reconstruct(qt_app: QApplication, window: MainWindow, ip: str) -> None:
    window._reconstruct(ip)
    settled(qt_app)


def sign_in(window: MainWindow) -> GraphNode:
    """The sweeper's failed sign-in, the activity on /login."""
    assert window._result is not None
    return next(n for n in window._result.trace.nodes if "/login" in n.top_targets)


def show(qt_app: QApplication, window: MainWindow, node: GraphNode) -> None:
    window._show_evidence(node.node_id)
    settled(qt_app)


def save(
    qt_app: QApplication, window: MainWindow, category: str = "Bookmarked", note: str = ""
) -> None:
    box = window._bookmarks.box
    assert box is not None, "the save box opened"
    box.saving.emit(category, note)
    settled(qt_app)


def ctrl_d(qt_app: QApplication, window: MainWindow) -> None:
    window._bookmark_action.trigger()
    settled(qt_app)


def ribboned_rows(table: QTableWidget) -> set[str]:
    return {
        item.text()
        for row in range(table.rowCount())
        if (item := table.item(row, 0)) is not None and not item.icon().isNull()
    }


def ribboned_lines(window: MainWindow) -> set[EvidenceRef]:
    table = window._evidence._table
    return {
        line.ref
        for row in range(table.rowCount())
        if (item := table.item(row, 0)) is not None
        and not item.icon().isNull()
        and (line := window._evidence._line_at(row)) is not None
    }


# -- saving from where the reader is -------------------------------------------------------


def test_ctrl_d_on_the_evidence_bookmarks_the_selected_line(
    qt_app: QApplication, window: MainWindow
) -> None:
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    window._evidence._table.setFocus()
    window._evidence.select_row(1)
    line = window._evidence.selected_line()
    assert line is not None

    ctrl_d(qt_app, window)

    box = window._bookmarks.box
    assert box is not None
    assert box.heading.text() == "Bookmark this line"
    assert box.said.text() == said_for_request(line.ref, line.event)
    save(qt_app, window, note="the one that got through")
    (saved,) = window._bookmarks.shelf.bookmarks
    assert (saved.kind, saved.client, saved.line) == (Kind.REQUEST, SWEEPER, line.ref)
    assert ribboned_lines(window) == {line.ref}
    assert SWEEPER in ribboned_rows(window._clients._table)
    assert window._workspace.tabText(2) == "Bookmarks (1)"


def test_ctrl_d_on_the_canvas_bookmarks_the_activity_from_its_first_line(
    qt_app: QApplication, window: MainWindow
) -> None:
    reconstruct(qt_app, window, SWEEPER)
    node = sign_in(window)
    show(qt_app, window, node)
    window._canvas.setFocus()

    ctrl_d(qt_app, window)

    box = window._bookmarks.box
    assert box is not None
    assert box.heading.text() == "Bookmark this activity"
    assert box.said.text() == said_for_activity(node)
    save(qt_app, window, category="Login attacks")
    (saved,) = window._bookmarks.shelf.bookmarks
    assert saved.kind is Kind.ACTIVITY
    assert saved.line is not None and saved.line.line_no == 34, "the activity's earliest line"
    assert saved.at == START + timedelta(minutes=5)
    ribbons = [
        c for c in window._canvas._nodes[node.node_id].childItems() if c.data(0) == "bookmark"
    ]
    assert len(ribbons) == 1


def test_ctrl_d_on_the_client_list_bookmarks_the_client(
    qt_app: QApplication, window: MainWindow
) -> None:
    table = window._clients._table
    table.setFocus()
    row = next(r for r in range(table.rowCount()) if table.item(r, 0).text() == PROBER)
    blocked = table.blockSignals(True)
    table.selectRow(row)
    table.blockSignals(blocked)

    ctrl_d(qt_app, window)

    box = window._bookmarks.box
    assert box is not None
    assert box.heading.text() == "Bookmark this client"
    assert box.said.text().startswith("2 requests")
    save(qt_app, window)
    assert [b.client for b in window._bookmarks.shelf.bookmarks] == [PROBER]


def test_ctrl_d_in_the_client_box_bookmarks_the_search_and_its_range(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "path:/admin")
    window._clients._filter.edit.setFocus()

    ctrl_d(qt_app, window)

    box = window._bookmarks.box
    assert box is not None
    assert box.heading.text() == "Bookmark this search"
    assert box.said.text().startswith("path:/admin \N{MIDDLE DOT} 2 clients")
    save(qt_app, window)
    (saved,) = window._bookmarks.shelf.bookmarks
    assert (saved.kind, saved.query, saved.range) == (Kind.SEARCH, "path:/admin", None)


def test_ctrl_d_with_nothing_open_says_so(qt_app: QApplication, window: MainWindow) -> None:
    window._canvas.setFocus()
    ctrl_d(qt_app, window)
    assert window._bookmarks.box is None
    assert window._status.text() == "Nothing to bookmark yet."


def test_ctrl_d_on_the_queue_bookmarks_its_current_client(
    qt_app: QApplication, window: MainWindow
) -> None:
    window._workspace.setCurrentIndex(0)
    queue = window._triage.table
    assert queue.rowCount() > 0, "premise: the scan queued somebody"
    queue.setCurrentCell(0, 0)
    queue.setFocus()
    first = window._triage.selected_client()
    assert first is not None

    ctrl_d(qt_app, window)

    box = window._bookmarks.box
    assert box is not None
    assert box.heading.text() == "Bookmark this client"
    save(qt_app, window)
    assert [b.client for b in window._bookmarks.shelf.bookmarks] == [first]


def test_bookmarking_from_the_queue_or_the_evidence_button_opens_the_box(
    qt_app: QApplication, window: MainWindow
) -> None:
    window._triage.bookmark_requested.emit(BROWSER)
    settled(qt_app)
    assert window._bookmarks.box is not None
    assert window._bookmarks.box.heading.text() == "Bookmark this client"
    window._bookmarks.box.reject()
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    window._evidence.bookmark_button.click()
    settled(qt_app)
    assert window._bookmarks.box is not None
    assert window._bookmarks.box.heading.text() == "Bookmark this activity"


# -- opening ---------------------------------------------------------------------------------


def saved_activity(qt_app: QApplication, window: MainWindow) -> str:
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    window._evidence.bookmark_button.click()
    settled(qt_app)
    save(qt_app, window)
    return window._bookmarks.shelf.bookmarks[-1].id


def test_an_activity_opens_on_its_client_and_is_selected(
    qt_app: QApplication, window: MainWindow
) -> None:
    ident = saved_activity(qt_app, window)
    reconstruct(qt_app, window, PROBER)

    window._bookmarks.open(ident)
    settled(qt_app)

    assert window._result is not None and window._result.client_ip == SWEEPER
    assert window._selected is not None and "/login" in window._selected.top_targets
    assert window._workspace.currentIndex() == 1
    assert window._canvas.selected_node_id() == window._selected.node_id
    ribbons = [
        c
        for c in window._canvas._nodes[window._selected.node_id].childItems()
        if c.data(0) == "bookmark"
    ]
    assert len(ribbons) == 1, "the redrawn graph wears its ribbon"


def test_an_opened_activity_is_on_screen_in_a_graph_too_big_to_frame(
    qt_app: QApplication, window: MainWindow
) -> None:
    """A graph too large to frame readably opens on its beginning; the bookmark is later."""
    ident = saved_activity(qt_app, window)
    window._apply_preferences({**window._prefs, "view/wrap_traces": False})
    window.resize(760, 560)
    reconstruct(qt_app, window, PROBER)

    window._bookmarks.open(ident)
    settled(qt_app)

    canvas = window._canvas
    assert window._selected is not None
    item = canvas._nodes[window._selected.node_id]
    drawn = item.sceneBoundingRect().united(item.mapRectToScene(item.childrenBoundingRect()))
    assert canvas.viewport().rect().contains(canvas.mapFromScene(drawn).boundingRect())


def test_a_bookmark_of_the_client_on_screen_opens_without_reading_it_again(
    qt_app: QApplication, window: MainWindow
) -> None:
    ident = saved_activity(qt_app, window)
    window._evidence.clear()
    window._selected = None
    before = window._result

    window._bookmarks.open(ident)
    settled(qt_app)

    assert window._result is before
    assert window._selected is not None and "/login" in window._selected.top_targets


def test_a_case_opened_with_bookmarks_marks_them_and_opens_them(
    qt_app: QApplication, tmp_path: Path
) -> None:
    case = make_case(tmp_path / "kept")
    with Case.open(case) as opened_case:
        source = opened_case.manifest.sources[0].file_id
    ref = EvidenceRef(source, 36)
    bookmarks.apply(
        case,
        lambda shelf: bookmarks.add(
            shelf,
            bookmarks.Bookmark(
                id="r",
                kind=Kind.REQUEST,
                category="Bookmarked",
                said="POST /login",
                note="the third failure",
                saved=START,
                client=SWEEPER,
                line=ref,
                at=START + timedelta(minutes=5, seconds=4),
            ),
        ),
    )
    shown = opened(qt_app, case)
    try:
        settled(qt_app)
        assert shown._workspace.tabText(2) == "Bookmarks (1)"
        assert SWEEPER in ribboned_rows(shown._clients._table)

        shown._bookmarks.open("r")
        settled(qt_app)

        chosen = shown._evidence.selected_line()
        assert chosen is not None and chosen.ref == ref
        assert ribboned_lines(shown) == {ref}
    finally:
        shown.close()
        settled(qt_app)


def test_a_request_opens_on_its_own_line(qt_app: QApplication, window: MainWindow) -> None:
    reconstruct(qt_app, window, SWEEPER)
    show(qt_app, window, sign_in(window))
    window._evidence.select_row(2)
    line = window._evidence.selected_line()
    assert line is not None
    window._bookmark_line(line)
    settled(qt_app)
    save(qt_app, window)
    reconstruct(qt_app, window, BROWSER)

    window._bookmarks.open(window._bookmarks.shelf.bookmarks[-1].id)
    settled(qt_app)

    chosen = window._evidence.selected_line()
    assert chosen is not None and chosen.ref == line.ref


def test_an_activity_outside_a_narrowed_range_widens_it_and_says_so(
    qt_app: QApplication, window: MainWindow
) -> None:
    ident = saved_activity(qt_app, window)
    before_sign_in = TimeWindow(START, START + timedelta(minutes=3))
    window._apply_window(before_sign_in)
    settled(qt_app)
    assert window._window == before_sign_in

    window._bookmarks.open(ident)
    settled(qt_app)

    assert window._window == EVERYTHING
    assert "whole case" in window._status.text()
    assert window._selected is not None and "/login" in window._selected.top_targets


def test_a_client_outside_a_narrowed_range_opens_over_the_whole_case(
    qt_app: QApplication, window: MainWindow
) -> None:
    window._clients.bookmark_requested.emit(BROWSER)
    settled(qt_app)
    save(qt_app, window)
    window._apply_window(TimeWindow(START, START + timedelta(minutes=3)))
    settled(qt_app)

    window._bookmarks.open(window._bookmarks.shelf.bookmarks[-1].id)
    settled(qt_app)

    assert window._window == EVERYTHING
    assert window._result is not None and window._result.client_ip == BROWSER
    assert window._result.request_count == 4
    assert "whole case" in window._status.text()


def test_a_search_opens_in_the_range_it_was_made_in(
    qt_app: QApplication, window: MainWindow
) -> None:
    narrowed = TimeWindow(START, START + timedelta(minutes=3))
    window._apply_window(narrowed)
    settled(qt_app)
    search(qt_app, window, "status:403")
    window._bookmark_search()
    settled(qt_app)
    save(qt_app, window)
    window._apply_window(EVERYTHING)
    settled(qt_app)
    window._clients._filter.setText("")
    settled(qt_app)

    window._bookmarks.open(window._bookmarks.shelf.bookmarks[-1].id)
    settled(qt_app)

    assert window._window == narrowed
    assert window._clients.query_text().strip() == "status:403"
    assert window._clients.answered_search() == ("status:403", 1, 2)


def test_a_search_made_in_the_range_in_force_runs_at_once(
    qt_app: QApplication, window: MainWindow
) -> None:
    search(qt_app, window, "status:403")
    window._bookmark_search()
    settled(qt_app)
    save(qt_app, window)
    window._clients._filter.setText("")
    settled(qt_app)

    window._bookmarks.open(window._bookmarks.shelf.bookmarks[-1].id)
    settled(qt_app)

    assert window._window == EVERYTHING
    assert window._clients.answered_search() == ("status:403", 1, 2)


def test_a_client_that_is_not_in_the_case_cannot_be_opened(
    qt_app: QApplication, tmp_path: Path
) -> None:
    case = make_case(tmp_path / "gone")
    bookmarks.apply(
        case,
        lambda shelf: bookmarks.add(
            shelf,
            bookmarks.Bookmark(
                id="g",
                kind=Kind.CLIENT,
                category="Bookmarked",
                said="",
                note="",
                saved=START,
                client="203.0.113.200",
            ),
        ),
    )
    shown = opened(qt_app, case)
    try:
        settled(qt_app)
        (gone,) = shown._bookmarks.shelf.bookmarks
        assert shown._bookmarks.is_gone(gone)
        shown._bookmarks.open("g")
        settled(qt_app)
        assert shown._result is None
    finally:
        shown.close()
        settled(qt_app)


# -- the case's own ------------------------------------------------------------------------


def test_the_tab_counts_and_another_case_shows_none_of_these(
    qt_app: QApplication, window: MainWindow, tmp_path: Path
) -> None:
    window._clients.bookmark_requested.emit(PROBER)
    settled(qt_app)
    save(qt_app, window)
    window._clients.bookmark_requested.emit(BROWSER)
    settled(qt_app)
    save(qt_app, window)
    assert window._workspace.tabText(2) == "Bookmarks (2)"

    window._load_case(make_case(tmp_path / "other"))
    assert window._bookmarks.shelf.bookmarks == (), "gone while the next case is read"
    assert ribboned_rows(window._clients._table) == set()
    settled(qt_app)

    assert window._workspace.tabText(2) == "Bookmarks"
    assert window._bookmarks.shelf.bookmarks == ()
    assert ribboned_rows(window._clients._table) == set()


def test_the_bookmarks_tab_does_not_widen_the_middle_of_the_window(
    qt_app: QApplication,
) -> None:
    """A tab page's minimum is the whole workspace's, and so the middle column's.

    Measured against a window with no case open, where the other pages are at
    their narrowest, and with the tab holding the longest things it can show.
    """
    fresh = MainWindow()
    try:
        workspace = fresh._workspace
        floor = max(
            page.minimumSizeHint().width()
            for index in range(workspace.count())
            if (page := workspace.widget(index)) is not fresh._bookmarks_tab
        )
        long = bookmarks.Bookmark(
            id="l",
            kind=Kind.ACTIVITY,
            category="Bookmarked",
            said="Credential Attack " * 6,
            note="word " * 60,
            saved=START,
            client=SWEEPER,
        )
        shelf = bookmarks.add(bookmarks.add_category(bookmarks.EMPTY, "A long category name"), long)
        fresh._bookmarks_tab.show_shelf(shelf, gone=lambda _b: False)
        fresh._bookmarks_tab.set_notice("The bookmarks file could not be read. " * 4)

        assert fresh._bookmarks_tab.minimumSizeHint().width() <= floor
    finally:
        fresh.close()


def test_the_report_and_the_csv_carry_the_notes(
    qt_app: QApplication, window: MainWindow, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ident = saved_activity(qt_app, window)
    window._bookmarks.edit(ident)
    save(qt_app, window, note="five failures then in")
    report, table = tmp_path / "report.html", tmp_path / "bookmarks.csv"
    answers = iter([(str(report), ""), (str(table), "")])
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_a, **_k: next(answers))

    window._export("html")
    settled(qt_app)
    window._export_bookmarks()
    settled(qt_app)

    assert "five failures then in" in report.read_text(encoding="utf-8")
    rows = list(csv.reader(io.StringIO(table.read_text(encoding="utf-8-sig"))))
    assert rows[0][0] == "category"
    assert rows[1][2] == SWEEPER and rows[1][4] == "five failures then in"
