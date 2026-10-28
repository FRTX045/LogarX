"""Letting go of the client being read, from the window's side.

`test_client_release.py` covers the gesture and the signal it produces. This
covers what the window does with it — which is where the feature was broken
while every test of the signal was green.

Run without a display. What is checked is state the window keeps, not how any
of it looks.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from dragging import drag
from on_canvas import node_item
from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarx.case import Case
from logarx.gui.app import MainWindow
from logarx.gui.arrangement_keeper import ArrangementKeeper

START = datetime(2024, 5, 1, 0, 0, tzinfo=UTC)

#: Busy all day, so the case's own span is this client's span.
ALL_DAY = "10.0.0.1"

#: Two minutes in the middle of it. Selecting this one is what makes the band
#: visibly narrow, and letting go of it is what has to widen the band again.
BRIEF = "10.0.0.2"


def _line(client: str, seconds: int, target: str) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    return f'{client} - - [{when}] "GET {target} HTTP/1.1" 200 512 "-" "{agent}"'


@pytest.fixture(scope="module")
def case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Two clients whose lives are different lengths.

    They have to differ, or the band would read the same whether it followed
    the client or the case and this file would prove nothing.
    """
    root = tmp_path_factory.mktemp("letting-go")
    lines = [_line(ALL_DAY, n * 600, f"/page/{n}") for n in range(144)]
    lines += [_line(BRIEF, 43_200 + n, f"/admin/{n}") for n in range(120)]

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _opened(qt_app: QApplication, case: Path) -> MainWindow:
    window = MainWindow()
    window._load_case(case)
    settled(qt_app)
    assert window._clients._table.rowCount() == 2, "premise: both clients are listed"
    return window


def _row_of(window: MainWindow, client_ip: str) -> int:
    table = window._clients._table
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None and cell.text() == client_ip:
            return row
    raise AssertionError(f"{client_ip} is not listed")


def _press(window: MainWindow, client_ip: str) -> None:
    """The whole gesture on that client's row: button down, button up.

    Both halves. `QAbstractItemView` finishes selecting on the release, so a
    test that sends only the press asks the widget a question the reader's hand
    never asks it.
    """
    table = window._clients._table
    at = table.visualItemRect(table.item(_row_of(window, client_ip), 0)).center()
    where = table.viewport().mapToGlobal(at).toPointF()
    for kind, held in (
        (QEvent.Type.MouseButtonPress, Qt.MouseButton.LeftButton),
        (QEvent.Type.MouseButtonRelease, Qt.MouseButton.NoButton),
    ):
        QApplication.sendEvent(
            table.viewport(),
            QMouseEvent(
                kind,
                QPointF(at),
                where,
                Qt.MouseButton.LeftButton,
                held,
                Qt.KeyboardModifier.NoModifier,
            ),
        )


def _band(window: MainWindow) -> tuple[datetime | None, datetime | None]:
    strip = window._time_filter._band
    return strip._first, strip._last


# -- the gesture, end to end ----------------------------------------------


def test_pressing_the_open_client_again_puts_the_case_back(
    qt_app: QApplication, case: Path
) -> None:
    """The reader's way out of a client, and out of the band drawn on its life.

    Driven through the widget rather than by calling the handler, because the
    defect this covers lived between the two: the handler was right, the
    gesture never reached it intact.
    """
    window = _opened(qt_app, case)
    whole = _band(window)

    _press(window, BRIEF)
    settled(qt_app)
    assert window._result is not None, "premise: the press opened the client"
    assert _band(window) != whole, "premise: the band followed the client"

    _press(window, BRIEF)
    settled(qt_app)

    assert window._result is None
    assert _band(window) == whole
    assert not window._clients._table.selectionModel().hasSelection()


def test_a_reconstruction_that_lands_after_letting_go_is_thrown_away(
    qt_app: QApplication, case: Path
) -> None:
    """A job in flight when the reader lets go must not put the client back.

    The window already throws away a reconstruction describing a range no
    longer in force. Nobody being read is the same kind of staleness on the
    other axis, and it arrives the same way: the reader let go a moment before
    the answer came back, and the graph, the heading and the band all returned
    with it.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    assert window._result is not None, "premise: a client is being read"

    window._reconstruct(BRIEF)
    window._let_go_of_client()
    assert window._result is None, "premise: letting go clears it at once"

    settled(qt_app)

    assert window._result is None
    assert window._heading.text() == ""


# -- leaving a client with an arrangement nobody kept ----------------------


def _moved(window: MainWindow) -> str:
    """Drag the first activity on the canvas, and say which one it was."""
    node_id = next(iter(window._canvas.positions))
    drag(window._canvas, node_id, QPoint(70, -40))
    return node_id


#: The dialog is stubbed everywhere below, never shown. A modal `exec()` in a
#: test either blocks the run or has to be dismissed by a timer, and neither of
#: those is a test of the rule that decides whether to ask at all.


def test_moving_to_another_client_with_an_unsaved_arrangement_asks_first(
    qt_app: QApplication, case: Path
) -> None:
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "discard")[1],
        )
        _press(window, ALL_DAY)
        settled(qt_app)

    assert asked == ["asked"]
    window.close()


def test_moving_to_another_client_with_nothing_moved_asks_nothing(
    qt_app: QApplication, case: Path
) -> None:
    """The question would have no subject.

    Asked anyway, the warning becomes something to click through on every
    client, and clicking through is what trains a reader to stop reading it.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "discard")[1],
        )
        _press(window, ALL_DAY)
        settled(qt_app)

    assert asked == []
    assert window._result is not None
    assert window._result.client_ip == ALL_DAY, "and the move went through"
    window.close()


def test_cancelling_leaves_the_reader_on_the_client_they_were_reading(
    qt_app: QApplication, case: Path
) -> None:
    """The selection has already moved by the time the window hears about it,
    so cancelling has to put the row back as well as refusing the move.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    moved = _moved(window)
    placed = (
        node_item(window._canvas, moved).pos().x(),
        node_item(window._canvas, moved).pos().y(),
    )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ArrangementKeeper, "ask", lambda self: "cancel")
        _press(window, ALL_DAY)
        settled(qt_app)

    assert window._result is not None
    assert window._result.client_ip == BRIEF, "the reader was moved anyway"
    assert _row_of(window, BRIEF) in {
        index.row() for index in window._clients._table.selectionModel().selectedRows()
    }, "the row under the reader is not the client being read"
    assert node_item(window._canvas, moved).pos().x() == placed[0], "the graph was redrawn"
    assert node_item(window._canvas, moved).pos().y() == placed[1]
    window.close()


def test_discarding_goes_on_to_the_other_client(qt_app: QApplication, case: Path) -> None:
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ArrangementKeeper, "ask", lambda self: "discard")
        _press(window, ALL_DAY)
        settled(qt_app)

    assert window._result is not None
    assert window._result.client_ip == ALL_DAY
    window.close()


def test_saving_on_the_way_out_keeps_the_arrangement(qt_app: QApplication, case: Path) -> None:
    """And it is there when the reader comes back."""
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    moved = _moved(window)
    placed = (
        node_item(window._canvas, moved).pos().x(),
        node_item(window._canvas, moved).pos().y(),
    )

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ArrangementKeeper, "ask", lambda self: "save")
        _press(window, ALL_DAY)
        settled(qt_app)

    _press(window, BRIEF)
    settled(qt_app)

    assert node_item(window._canvas, moved).pos().x() == placed[0]
    assert node_item(window._canvas, moved).pos().y() == placed[1]
    window.close()


def test_turning_the_warning_off_stops_it_being_asked(qt_app: QApplication, case: Path) -> None:
    """`Don't ask this again` writes the preference, and it is read before the
    dialog is built - or turning it off would only last the session.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)
    window._arrangements_kept.ask_before_leaving = False

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "discard")[1],
        )
        _press(window, ALL_DAY)
        settled(qt_app)

    assert asked == [], "the warning was turned off"
    assert window._result is not None
    assert window._result.client_ip == ALL_DAY
    window.close()


def test_turning_the_warning_back_on_in_preferences_reaches_the_keeper(
    qt_app: QApplication, case: Path
) -> None:
    """The dialog is the only way back after `Don't ask this again`.

    The keeper holds this as a plain attribute rather than reading the store on
    every ask, so something has to carry a change in Preferences across to it.
    Nothing did, and the switch went one way only: off from the dialog, and
    never back on.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)
    window._arrangements_kept.ask_before_leaving = False

    window._apply_preferences({**window._prefs, "view/ask_unsaved_arrangement": True})

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "discard")[1],
        )
        _press(window, ALL_DAY)
        settled(qt_app)

    assert asked == ["asked"], "Preferences turned it on and the keeper never heard"
    window.close()


def test_a_change_of_range_is_not_leaving_the_client(qt_app: QApplication, case: Path) -> None:
    """`_reselect` reconstructs the *same* client whenever the range moves.

    Asked there, the warning would say the reader is leaving a client they are
    still on, and it would fire on every nudge of the date fields - which is
    the fastest way to teach someone to click a warning away without reading it.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "discard")[1],
        )
        window._reselect(BRIEF)
        settled(qt_app)

    assert asked == [], "the same client is not another client"
    assert window._result is not None
    assert window._result.client_ip == BRIEF
    window.close()


def test_letting_go_of_a_moved_client_asks_too(qt_app: QApplication, case: Path) -> None:
    """Pressing the open row again drops the client, and the arrangement with
    it. That is the same loss the warning exists to prevent.
    """
    window = _opened(qt_app, case)
    _press(window, BRIEF)
    settled(qt_app)
    _moved(window)

    asked: list[str] = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            ArrangementKeeper,
            "ask",
            lambda self: (asked.append("asked"), "cancel")[1],
        )
        _press(window, BRIEF)
        settled(qt_app)

    assert asked == ["asked"]
    assert window._result is not None, "cancelling kept the client open"
    assert window._result.client_ip == BRIEF
    window.close()
