"""Narrowing a case to one stretch of time, from the control to the graph.

Run without a display. What is checked here is which numbers reach the screen
and whether the two halves of the window agree about them — none of which the
offscreen platform's missing fonts can hide.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication
from tables import cell

from logarc.case import Case
from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui import app
from logarc.gui.app import MainWindow
from logarc.gui.time_filter import TimeFilterBar

FIRST = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
LAST = datetime(2024, 5, 2, 12, 0, tzinfo=UTC)

BUSY = "203.0.113.9"
BUSIEST = "203.0.113.7"
LATECOMER = "203.0.113.44"
EARLY = datetime(2024, 5, 1, 3, 0, tzinfo=UTC)
LATE = datetime(2024, 5, 1, 4, 0, tzinfo=UTC)


def opened(qt_app: QApplication) -> TimeFilterBar:
    bar = TimeFilterBar()
    bar.set_span((FIRST, LAST))
    return bar


# -- the control on its own ------------------------------------------------


def test_the_control_is_dead_until_a_case_is_open(qt_app: QApplication) -> None:
    """A live control that does nothing reads as a fault in the tool."""
    bar = TimeFilterBar()

    assert not bar._from.isEnabled()
    assert not bar._to.isEnabled()
    assert bar.chosen is EVERYTHING


def test_an_open_case_starts_on_the_whole_of_it(qt_app: QApplication) -> None:
    """Not on a range the reader did not ask for. Opening a case already
    filtered would hide part of it with nothing on screen saying so."""
    bar = opened(qt_app)

    assert bar.chosen.is_open


def test_the_fields_cannot_reach_past_the_case(qt_app: QApplication) -> None:
    """A reader who cannot ask for a stretch the case does not cover cannot get
    an empty reconstruction for a reason that was never on screen."""
    bar = opened(qt_app)

    bar._from.setDateTime(bar._from.dateTime().addYears(-5))

    assert bar.chosen.is_open or bar.chosen.start >= FIRST


def test_narrowing_one_end_is_no_longer_the_whole_case(qt_app: QApplication) -> None:
    bar = opened(qt_app)

    bar._from.setDateTime(bar._from.dateTime().addSecs(3600))

    assert not bar.chosen.is_open
    assert bar.chosen.start == FIRST + timedelta(hours=1)


def test_the_whole_case_reads_as_open_not_as_its_own_two_ends(
    qt_app: QApplication,
) -> None:
    """So nothing downstream has to compare dates to know a filter is off — and
    identifiers stay exactly what they have always been."""
    bar = opened(qt_app)

    bar._from.setDateTime(bar._from.dateTime().addSecs(3600))
    bar.clear()

    assert bar.chosen is EVERYTHING


def test_changing_a_field_reports_the_new_stretch(qt_app: QApplication) -> None:
    bar = opened(qt_app)
    heard: list[TimeWindow] = []
    bar.changed.connect(heard.append)

    bar._from.setDateTime(bar._from.dateTime().addSecs(3600))
    bar._from.editingFinished.emit()

    assert heard and heard[-1].start == FIRST + timedelta(hours=1)


def test_an_end_dragged_before_the_start_is_held_not_swapped(
    qt_app: QApplication,
) -> None:
    """`TimeWindow` refuses a range that ends before it starts. Swapping here
    would turn a mistyped end into a range the reader never asked for; holding
    it shows them what happened."""
    bar = opened(qt_app)
    bar._from.setDateTime(bar._from.dateTime().addSecs(7200))

    bar._to.setDateTime(bar._to.dateTime().addYears(-5))
    bar._to.editingFinished.emit()

    assert bar.chosen.is_open or bar.chosen.end >= bar.chosen.start


def test_showing_a_window_does_not_report_it_back(qt_app: QApplication) -> None:
    """Two controls will point at one range once the band exists. Each has to
    set the other without that counting as the reader asking for something, or
    the two would answer each other forever."""
    bar = opened(qt_app)
    heard: list[TimeWindow] = []
    bar.changed.connect(heard.append)

    bar.set_window(TimeWindow(FIRST + timedelta(hours=2), LAST))

    assert heard == []


# -- the two halves of the window agreeing ---------------------------------


@pytest.fixture(scope="module")
def two_bursts(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Three clients, arranged so a wrong one is visible if it gets picked.

    `BUSIEST` is busier than `BUSY` and is present in both bursts, so it sorts
    above it and takes the first row whatever the range. A reconstruction that
    lands on whatever row the rebuilt table happens to select would therefore
    come back describing `BUSIEST` — which is what makes that fault visible here
    rather than intermittent.
    """
    root = tmp_path_factory.mktemp("windowed")
    lines = []
    for offset in range(12):
        lines.append(_line(EARLY + timedelta(seconds=offset * 5), f"/admin/{offset}", BUSY))
    for offset in range(30):
        lines.append(_line(EARLY + timedelta(seconds=offset * 2), f"/a/{offset}", BUSIEST))
    for offset in range(8):
        lines.append(_line(LATE + timedelta(seconds=offset * 5), f"/wp/{offset}", BUSY))
        lines.append(_line(LATE + timedelta(seconds=offset * 5), f"/x/{offset}", LATECOMER))

    log = root / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def _line(when: datetime, target: str, ip: str) -> str:
    stamp = when.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "GET {target} HTTP/1.1" 404 12 "-" "curl/8.0"'


def settled(qt_app: QApplication, rounds: int = 3) -> None:
    from PyQt6.QtCore import QThreadPool

    for _ in range(rounds):
        pool = QThreadPool.globalInstance()
        assert pool is not None
        assert pool.waitForDone(30_000)
        for _ in range(10):
            qt_app.processEvents()


def reading(qt_app: QApplication, case: Path, client: str) -> MainWindow:
    window = MainWindow()
    window._load_case(case)
    settled(qt_app)
    row = _row_for(window, client)
    assert row is not None, f"{client} is not listed"
    window._clients._table.selectRow(row)
    settled(qt_app)
    return window


def _row_for(window: MainWindow, client: str) -> int | None:
    table = window._clients._table
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None and cell.text() == client:
            return row
    return None


def _requests_in_row(window: MainWindow, client: str) -> int:
    row = _row_for(window, client)
    assert row is not None
    return int(cell(window._clients._table, row, "Reqs").text().replace(",", ""))


EARLY_ONLY = TimeWindow(EARLY, EARLY + timedelta(minutes=5))


def test_a_range_narrows_the_graph(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    assert window._result is not None
    whole = window._result.request_count

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._result is not None
    assert window._result.request_count < whole
    assert window._result.request_count == 12
    window.close()


def test_a_range_narrows_the_client_list_to_who_was_there(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    assert _row_for(window, LATECOMER) is not None, "premise: both are listed"

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert _row_for(window, BUSY) is not None
    assert _row_for(window, LATECOMER) is None
    window.close()


def test_the_row_and_the_graph_agree_about_the_same_client(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """The test this whole feature was shaped around.

    A row saying 20 requests beside a graph saying 12 is two numbers for one
    thing on one screen, and it is what ruled out narrowing the graph alone.
    """
    window = reading(qt_app, two_bursts, BUSY)

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._result is not None
    assert _requests_in_row(window, BUSY) == window._result.request_count
    window.close()


def test_going_back_to_the_whole_case_restores_both_halves(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    assert window._result is not None
    whole = window._result.request_count
    listed = window._clients._table.rowCount()
    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    window._apply_window(EVERYTHING)
    settled(qt_app)

    assert window._clients._table.rowCount() == listed
    assert window._result is not None
    assert window._result.request_count == whole
    window.close()


def test_a_range_holding_nobody_says_so_rather_than_looking_broken(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)

    window._apply_window(
        TimeWindow(datetime(2099, 1, 1, tzinfo=UTC), datetime(2099, 1, 2, tzinfo=UTC))
    )
    settled(qt_app)

    assert window._clients._table.rowCount() == 0
    assert "No client was active" in window._status.text()
    window.close()


def test_the_line_beside_the_control_carries_both_counts(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """One line, both numbers, so a reader can see them agree without looking
    from the list to the heading and back. `gui.timerange` decides the wording;
    this is what proves the window fills it with the right figures."""
    window = reading(qt_app, two_bursts, BUSY)
    assert window._time_filter._summary.text() == "whole case"

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._time_filter._summary.text() == "2 of 3 clients · 12 of 20 requests"
    window.close()


def test_the_line_goes_back_to_saying_whole_case(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    window._apply_window(EVERYTHING)
    settled(qt_app)

    assert window._time_filter._summary.text() == "whole case"
    window.close()


def test_the_line_speaks_before_any_client_has_been_picked(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Setting a range is a reasonable first move — narrow to the hour, then see
    who was there. With no client selected nothing reconstructs, so the line has
    to be filled by the range itself or it goes on claiming the whole case."""
    window = MainWindow()
    window._load_case(two_bursts)
    settled(qt_app)
    assert window._result is None, "premise: nobody has been picked"

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._time_filter._summary.text() == "2 of 3 clients"
    window.close()


def test_the_fields_show_the_range_that_is_actually_in_force(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """A control that does not show its own state is worse than no control.

    Typing in the fields keeps them right by accident. Every other way the range
    can be set — a restored one, the band once it exists — leaves them naming a
    stretch that is not the one being read.
    """
    window = reading(qt_app, two_bursts, BUSY)

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._time_filter.chosen == EARLY_ONLY
    window.close()


# -- the band and the fields as one control --------------------------------


def test_dragging_the_band_moves_the_fields(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """One range, two controls. A band that picked a stretch the fields did not
    show would leave the reader two answers to one question."""
    window = reading(qt_app, two_bursts, BUSY)
    bar = window._time_filter
    picked = TimeWindow(EARLY, EARLY + timedelta(minutes=3))

    bar._band.changed.emit(picked)

    # Asserted before the read, deliberately: the fields have to follow the band
    # at once rather than when the case has been re-read over the new stretch.
    assert bar.chosen == picked
    # And then waited for, because that read was started and this test is not
    # about it. Left running, it outlives the test and the interpreter tears
    # down on top of it.
    settled(qt_app)
    window.close()


def test_dragging_the_band_reads_the_case_over_that_stretch(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)

    window._time_filter._band.changed.emit(EARLY_ONLY)
    settled(qt_app)

    assert window._result is not None
    assert window._result.request_count == 12
    window.close()


def test_typing_in_the_fields_moves_the_band(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._time_filter._band.showing() == EARLY_ONLY
    window.close()


def test_the_band_is_given_the_cases_own_traffic(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Drawn from nothing it is an empty box, and the reason for having it at
    all — seeing where the busy hours are — is gone."""
    window = reading(qt_app, two_bursts, BUSY)

    assert window._time_filter._band._bars
    window.close()


def test_the_reader_stays_on_their_own_client_across_a_range_change(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Rebuilding the client list changes what the table has selected, and that
    is a selection signal like any other — so a reconstruction started for
    whatever row landed selected can finish after the one that was asked for and
    overwrite it. The graph then describes a client the reader never chose.

    Caught only because `BUSIEST` sorts above `BUSY` and survives the range.
    """
    window = reading(qt_app, two_bursts, BUSY)
    assert window._result is not None
    assert window._result.client_ip == BUSY

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._result is not None
    assert window._result.client_ip == BUSY
    assert window._result.request_count == 12
    window.close()


def test_a_reconstruction_of_a_range_no_longer_in_force_is_discarded(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Jobs finish in whatever order they finish, and a second one can be
    started by something as ordinary as refilling the client table. A late
    result describing the wrong range would leave the graph and the list saying
    different things — the failure this whole feature exists to prevent, arrived
    at from the other direction.

    Forced here rather than raced for: the race needs a client table of
    thousands to show up, and a test that only sometimes reproduces guards
    nothing.
    """
    window = reading(qt_app, two_bursts, BUSY)
    window._apply_window(EARLY_ONLY)
    settled(qt_app)
    assert window._result is not None
    kept = window._result

    with patch.object(app, "reconstruct_client", side_effect=_answers_for_the_whole_case):
        window._reconstruct(BUSY)
        settled(qt_app)

    assert window._result is kept, "a result for the wrong range was allowed in"
    window.close()


def _answers_for_the_whole_case(path: Path, client_ip: str, crs: object, **kw: object) -> object:
    """A reconstruction that arrives late, describing the whole case."""
    from logarc.analysis import analyse_ip

    with Case.open(path) as case:
        return analyse_ip(case.store, client_ip, crs=crs.index)  # type: ignore[attr-defined]


# -- turning the bars off --------------------------------------------------


def turn(window: MainWindow, key: str, on: bool) -> None:
    """Change one preference the way the dialog does.

    Through `_apply_preferences`, not by reaching into a widget: that is the
    one path a reader's choice takes now, and a test that took another would
    stop covering the path they use.
    """
    window._apply_preferences({**window._prefs, key: on})


def test_the_bars_are_shown_until_someone_turns_them_off(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    app._settings().clear()
    window = reading(qt_app, two_bursts, BUSY)

    assert window._prefs["view/traffic_band"] is True
    # `isHidden`, not `isVisible`: the second asks whether the widget is on
    # screen, which is false for every child of a window nobody showed. The
    # toggle controls the first.
    assert not window._time_filter._band.isHidden()
    window.close()


def test_turning_the_bars_off_leaves_the_filter_behind(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Only the picture goes. The fields are the precise control and the one a
    reader falls back on for a stretch too narrow to drag onto."""
    window = reading(qt_app, two_bursts, BUSY)

    turn(window, "view/traffic_band", False)

    assert window._time_filter._band.isHidden()
    assert not window._time_filter._from.isHidden()
    assert not window._time_filter._clear.isHidden()
    window.close()


def test_the_filter_still_works_with_the_bars_off(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    turn(window, "view/traffic_band", False)

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._result is not None
    assert window._result.request_count == 12
    window.close()


def test_the_bars_come_back_when_they_are_turned_on(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, BUSY)
    turn(window, "view/traffic_band", False)

    turn(window, "view/traffic_band", True)

    # `isHidden`, not `isVisible`: the second asks whether the widget is on
    # screen, which is false for every child of a window nobody showed. The
    # toggle controls the first.
    assert not window._time_filter._band.isHidden()
    window.close()


def test_the_choice_outlives_the_window(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Checked by opening a second window rather than by reading the setting
    back: a preference stored and never applied is the failure worth catching,
    and reading the file would not catch it."""
    app._settings().clear()
    first = MainWindow()
    turn(first, "view/traffic_band", False)
    first.close()

    second = MainWindow()

    assert second._prefs["view/traffic_band"] is False
    assert second._time_filter._band.isHidden()
    assert "false" in settings_in_a_temp_file.read_text(encoding="utf-8").lower()
    second.close()


# -- the band following the client being read ------------------------------


def band_span(window: MainWindow) -> tuple[datetime, datetime] | None:
    strip = window._time_filter._band
    return None if strip._first is None else (strip._first, strip._last)


def test_the_band_opens_on_the_whole_case(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Before a client is picked the question is still *when was this case
    busy*."""
    window = MainWindow()
    window._load_case(two_bursts)
    settled(qt_app)

    span = band_span(window)
    assert span is not None
    assert span[0] <= EARLY
    assert span[1] >= LATE
    window.close()


def test_picking_a_client_narrows_the_band_to_that_client(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """The whole reason for it: a client alive for an hour fills the band
    instead of being a hairline in the middle of the case."""
    window = MainWindow()
    window._load_case(two_bursts)
    settled(qt_app)
    whole = band_span(window)

    row = _row_for(window, LATECOMER)
    assert row is not None
    window._clients._table.selectRow(row)
    settled(qt_app)

    theirs = band_span(window)
    assert theirs is not None and whole is not None
    assert theirs[0] >= LATE, "the band starts where this client did"
    assert theirs[1] - theirs[0] < whole[1] - whole[0], "and is narrower than the case"
    window.close()


def test_the_bars_are_that_clients_own_requests(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Chosen over counting everyone's: the band becomes that client's history —
    when it worked, when it went quiet."""
    window = reading(qt_app, two_bursts, LATECOMER)

    counted = sum(slot.request_count for slot in window._time_filter._band._bars)

    assert counted == 8, "the eight requests this client made, and nobody else's"
    window.close()


def test_the_band_shows_the_clients_whole_life_not_just_the_range(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """Built from the reconstruction it would only ever cover the range in
    force, so the whole band would be lit and there would be nothing to see
    outside the selection — which is the one thing a reader needs to see."""
    window = reading(qt_app, two_bursts, BUSY)
    whole_life = band_span(window)

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert band_span(window) == whole_life
    window.close()


def test_letting_go_of_a_client_gives_the_case_back(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    window = reading(qt_app, two_bursts, LATECOMER)
    theirs = band_span(window)

    window._load_case(two_bursts)
    settled(qt_app)

    assert band_span(window) != theirs
    window.close()


def test_a_client_dropped_by_the_range_gives_the_band_back_to_the_case(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """The other way to stop reading a client: narrow to a stretch it was not
    there for. Nobody is being read, so the question is the case's again — and a
    band still drawn against a client no longer on screen answers a question
    nobody asked."""
    window = reading(qt_app, two_bursts, LATECOMER)
    theirs = band_span(window)
    assert theirs is not None

    window._apply_window(EARLY_ONLY)
    settled(qt_app)

    assert window._result is None, "premise: this client is not in that stretch"
    assert band_span(window) != theirs
    window.close()


def test_pressing_the_client_again_gives_the_whole_case_back(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """The way out of a client, and out of the band drawn against its life.

    `LATECOMER`, not `BUSY`: `BUSY` is present in both bursts so its life covers
    almost the whole case, and a band that never changed would pass.
    """
    window = reading(qt_app, two_bursts, LATECOMER)
    theirs = band_span(window)
    assert window._result is not None

    window._clients.client_released.emit()
    settled(qt_app)

    assert window._result is None
    assert band_span(window) != theirs
    assert not window._tabs.isVisible()
    assert window._heading.text() == ""
    window.close()


def test_letting_go_takes_the_request_counts_out_of_the_line(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """`12 of 20 requests` names a client nobody is reading any more."""
    window = reading(qt_app, two_bursts, BUSY)
    window._apply_window(EARLY_ONLY)
    settled(qt_app)
    assert "requests" in window._time_filter._summary.text()

    window._clients.client_released.emit()
    settled(qt_app)

    assert "requests" not in window._time_filter._summary.text()
    window.close()


def test_letting_go_stops_the_status_line_naming_that_client(
    qt_app: QApplication, two_bursts: Path, settings_in_a_temp_file: Path
) -> None:
    """`203.0.113.9: 3 activities` left standing is the window reporting on a
    client it is no longer showing — the only line on screen still claiming one
    is open."""
    window = reading(qt_app, two_bursts, BUSY)
    assert BUSY in window._status.text()

    window._clients.client_released.emit()
    settled(qt_app)

    assert BUSY not in window._status.text()
    window.close()
