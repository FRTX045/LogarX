"""The evidence filter in the window: which lines it keeps, what it fades on the
canvas, and how long it lasts.

Run without a display, on a case built here: one client sweeps 33 paths (30 of
them missing, two found, one error), then signs in and reads its account; a
second client only browses.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")


from conftest import fired, settled
from logarx.case import Case
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.core.graph import GraphKind
from logarx.core.window import TimeWindow
from logarx.gui import app
from logarx.gui.app import MainWindow
from logarx.gui.canvas import FADED

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

    from logarx.core.graph import GraphNode

SWEEPER = "198.51.100.31"
BROWSER = "192.0.2.1"
START = datetime(2026, 3, 11, 0, 50, tzinfo=UTC)
# The two hits and the error fall inside the sweep, the way a wordlist finds them.
SWEEP = [404] * 10 + [200] + [404] * 10 + [500] + [404] * 5 + [200] + [404] * 5


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


def make_case(root: Path) -> Path:
    sweep = [
        request(
            SWEEPER,
            START + timedelta(seconds=i),
            1 + i,
            f"/guess/{i}",
            status,
            user_agent="gobuster/3.5",
        )
        for i, status in enumerate(SWEEP)
    ]
    later = START + timedelta(minutes=5)
    sign_in = [
        request(SWEEPER, later + timedelta(seconds=i * 2), 50 + i, "/login", status, method="POST")
        for i, status in enumerate([401, 401, 401, 302])
    ]
    account = [
        request(SWEEPER, later + timedelta(seconds=20 + i * 3), 60 + i, f"/account/{page}", 200)
        for i, page in enumerate(["home", "orders", "settings"])
    ]
    browsing = [
        request(BROWSER, START + timedelta(minutes=10, seconds=i * 5), 100 + i, "/", 200)
        for i in range(4)
    ]
    with Case.create(root) as case:
        for batch in (sweep, sign_in, account, browsing):
            case.store.write(batch)
        case.store.finalize()
    return case.root


@pytest.fixture
def window(qt_app: QApplication, tmp_path: Path) -> Iterator[MainWindow]:
    shown = MainWindow()
    shown.report_error = lambda message, detail: (_ for _ in ()).throw(AssertionError(message))
    shown._load_case(make_case(tmp_path / "case"))
    settled(qt_app)
    shown._reconstruct(SWEEPER)
    settled(qt_app)
    yield shown
    shown.close()
    settled(qt_app)


def node(window: MainWindow, label: str) -> GraphNode:
    graph = window._result.trace if window._kind is GraphKind.TRACE else window._result.behaviour
    return next(item for item in graph.nodes if item.label == label)


SWEPT, SIGNED_IN, ACCOUNT = "Content Discovery Tool", "Sign In", "Account Area"


def read(qt_app: QApplication, window: MainWindow, label: str) -> None:
    window._show_evidence(node(window, label).node_id)
    settled(qt_app)


def type_filter(qt_app: QApplication, window: MainWindow, text: str) -> None:
    """Typed into the box, heard once typing rests: the reader's own path in."""
    window._evidence.filter_box.setText(text)
    fired(window._evidence._rest)
    settled(qt_app)


def rows(window: MainWindow) -> int:
    return window._evidence._table.rowCount()


def strip(window: MainWindow) -> str:
    return "" if window._evidence.strip.isHidden() else window._evidence.strip.text()


def opacities(window: MainWindow) -> dict[str, float]:
    items = window._canvas._nodes
    return {
        label: items[node(window, label).node_id].opacity() for label in (SWEPT, SIGNED_IN, ACCOUNT)
    }


def test_premise_one_activity_holds_every_status(qt_app: QApplication, window: MainWindow) -> None:
    assert node(window, SWEPT).request_count == 33
    assert node(window, SIGNED_IN).request_count == 4
    assert node(window, ACCOUNT).request_count == 3


# -- the panel ------------------------------------------------------------------------


def test_a_filter_keeps_the_lines_it_matches(qt_app: QApplication, window: MainWindow) -> None:
    read(qt_app, window, SWEPT)

    type_filter(qt_app, window, "status:200")

    assert rows(window) == 2
    assert "2 of 33 lines match status:200" in strip(window)
    assert window._evidence.no_results.isHidden()


def test_clearing_the_filter_shows_the_whole_activity_again(
    qt_app: QApplication, window: MainWindow
) -> None:
    read(qt_app, window, SWEPT)
    type_filter(qt_app, window, "status:200")

    type_filter(qt_app, window, "")

    assert rows(window) == 33
    assert strip(window) == ""


def test_more_matches_than_the_panel_loads(
    qt_app: QApplication, window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The count is of every match; the table holds what the ceiling lets it."""
    monkeypatch.setattr(app, "EVIDENCE_LIMIT", 10)
    read(qt_app, window, SWEPT)

    type_filter(qt_app, window, "status:404")

    assert rows(window) == 10
    assert "30 of 33 lines match status:404" in strip(window)
    assert "showing the first 10" in strip(window)


def test_a_match_past_the_activitys_sample_is_still_found(
    qt_app: QApplication, window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The last hit is request 28 of 33. With a ceiling of 10, the unfiltered panel
    never loads it; the filter searches every request, not the ones loaded."""
    monkeypatch.setattr(app, "EVIDENCE_LIMIT", 10)
    read(qt_app, window, SWEPT)

    type_filter(qt_app, window, "status:200")

    assert rows(window) == 2
    assert "2 of 33 lines match" in strip(window)


def test_nothing_matching_says_no_results_found(qt_app: QApplication, window: MainWindow) -> None:
    read(qt_app, window, SWEPT)

    type_filter(qt_app, window, "status:401")

    assert rows(window) == 0
    assert not window._evidence.no_results.isHidden()


def test_lines_carried_in_still_obey_the_filter(qt_app: QApplication, window: MainWindow) -> None:
    """Where to start opens a client at the lines it found; on the client already
    open, with a filter on, those lines are shown only if the filter keeps them,
    or the table would hold three rows under a strip that says two."""
    read(qt_app, window, SWEPT)
    type_filter(qt_app, window, "status:200")

    window._reconstruct(SWEEPER, evidence=(EvidenceRef("access.log", 1),))
    settled(qt_app)

    assert window._evidence.filter_text() == "status:200"
    assert rows(window) == 2
    assert "2 of 33 lines match status:200" in strip(window)


def test_another_activity_keeps_the_filter(qt_app: QApplication, window: MainWindow) -> None:
    read(qt_app, window, SWEPT)
    type_filter(qt_app, window, "status:401")

    read(qt_app, window, SIGNED_IN)

    assert window._evidence.filter_text() == "status:401"
    assert rows(window) == 3
    assert "3 of 4 lines match status:401" in strip(window)
    assert window._evidence.no_results.isHidden()


def test_the_other_view_keeps_the_filter(qt_app: QApplication, window: MainWindow) -> None:
    read(qt_app, window, SWEPT)
    type_filter(qt_app, window, "status:500")

    window._show_behaviour()
    settled(qt_app)

    assert window._evidence.filter_text() == "status:500"
    assert rows(window) == 1
    assert "1 of 33 lines matches status:500" in strip(window)


def test_the_box_offers_the_values_this_activity_holds(
    qt_app: QApplication, window: MainWindow
) -> None:
    read(qt_app, window, SWEPT)

    box = window._evidence.filter_box
    assert box._values == {
        "status": [
            ("404", "30 lines"),
            ("200", "2 lines"),
            ("500", "1 line"),
            ("2xx", "2 lines"),
            ("4xx", "30 lines"),
            ("5xx", "1 line"),
        ],
        "method": [("GET", "33 lines")],
    }

    read(qt_app, window, SIGNED_IN)

    assert box._values["method"] == [("POST", "4 lines")]


# -- the canvas -----------------------------------------------------------------------


def test_the_canvas_fades_the_activities_no_line_matches(
    qt_app: QApplication, window: MainWindow
) -> None:
    read(qt_app, window, SWEPT)

    type_filter(qt_app, window, "status:500")
    assert opacities(window) == {SWEPT: 1.0, SIGNED_IN: FADED, ACCOUNT: FADED}

    type_filter(qt_app, window, "status:200")
    assert opacities(window) == {SWEPT: 1.0, SIGNED_IN: FADED, ACCOUNT: 1.0}

    type_filter(qt_app, window, "")
    assert opacities(window) == {SWEPT: 1.0, SIGNED_IN: 1.0, ACCOUNT: 1.0}


def test_the_fade_needs_no_activity_selected(qt_app: QApplication, window: MainWindow) -> None:
    """Which activities hold a 500 is a question asked before choosing one."""
    assert window._selected is None

    type_filter(qt_app, window, "method:POST")

    assert opacities(window) == {SWEPT: FADED, SIGNED_IN: 1.0, ACCOUNT: FADED}


def test_the_other_view_is_faded_too(qt_app: QApplication, window: MainWindow) -> None:
    type_filter(qt_app, window, "method:POST")

    window._show_behaviour()
    settled(qt_app)

    assert opacities(window) == {SWEPT: FADED, SIGNED_IN: 1.0, ACCOUNT: FADED}


def test_the_range_moving_keeps_the_filter_and_fades_the_new_graph(
    qt_app: QApplication, window: MainWindow
) -> None:
    """The same client read again: a new reconstruction, the same question."""
    type_filter(qt_app, window, "method:POST")
    before = window._result

    window._reconstruct(SWEEPER)
    settled(qt_app)

    assert window._result is not before, "premise: a new reconstruction"
    assert window._evidence.filter_text() == "method:POST"
    assert opacities(window) == {SWEPT: FADED, SIGNED_IN: 1.0, ACCOUNT: FADED}


def test_a_narrower_range_is_faded_from_its_own_requests(
    qt_app: QApplication, window: MainWindow
) -> None:
    """A new range is a new reconstruction with activities of its own, so the
    answer for the last range is not reused for it. The sweep's only error is
    its 22nd request: a range that keeps it leaves the sweep bright, one that
    cuts it fades the sweep."""
    type_filter(qt_app, window, "status:500")

    def swept() -> float:
        return window._canvas._nodes[node(window, SWEPT).node_id].opacity()

    window._apply_window(TimeWindow(START, START + timedelta(seconds=25)))
    settled(qt_app)
    assert swept() == 1.0, "the error is inside this range"

    window._apply_window(TimeWindow(START, START + timedelta(seconds=15)))
    settled(qt_app)
    assert swept() == FADED, "and outside this one"


# -- how long it lasts ----------------------------------------------------------------


def test_a_new_client_starts_without_a_filter(qt_app: QApplication, window: MainWindow) -> None:
    read(qt_app, window, SWEPT)
    type_filter(qt_app, window, "status:500")

    window._reconstruct(BROWSER)
    settled(qt_app)

    assert window._evidence.filter_text() == ""
    assert {item.opacity() for item in window._canvas._nodes.values()} == {1.0}
    assert window._evidence.filter_box._values == {}, "the last client's values are not offered"


def test_another_case_starts_without_a_filter(
    qt_app: QApplication, window: MainWindow, tmp_path: Path
) -> None:
    type_filter(qt_app, window, "status:500")

    window._load_case(make_case(tmp_path / "other"))
    settled(qt_app)

    assert window._evidence.filter_text() == ""


# -- answers that arrive late ---------------------------------------------------------


def test_an_answer_to_an_older_filter_is_dropped(
    qt_app: QApplication, window: MainWindow, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Jobs finish in whatever order they finish. The one for the text before
    the last must not land on top of the last."""
    read(qt_app, window, SWEPT)
    jobs: list[tuple[Any, dict[str, Any]]] = []
    monkeypatch.setattr(app, "run_job", lambda work, **kw: jobs.append((work, kw)))

    for text in ("status:500", "status:200"):
        window._evidence.set_filter_text(text)
        window._evidence.filter_changed.emit(text)
    for work, kw in reversed(jobs):
        kw["on_done"](work(lambda *_: None))

    assert rows(window) == 2
    assert "status:200" in strip(window)
    assert opacities(window) == {SWEPT: 1.0, SIGNED_IN: FADED, ACCOUNT: 1.0}
