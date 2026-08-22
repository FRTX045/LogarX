"""The band that shows where a case's traffic sits, and lets a slice be picked.

Run without a display. What is checked is the mapping between a pixel and a
moment, and what a drag produces — not how it looks, which is a question for a
real screen and is asked in the manual plan.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QEvent, QPoint, QPointF, Qt
from PyQt6.QtGui import QMouseEvent
from PyQt6.QtWidgets import QApplication

from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui.timeline import Timeline
from logarc.storage.base import TimeSlot

FIRST = datetime(2024, 5, 1, 0, 0, tzinfo=UTC)
LAST = FIRST + timedelta(hours=24)


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    return QApplication.instance() or QApplication([])


def bars() -> list[TimeSlot]:
    # Twenty-four buckets an hour wide. The last one *starts* at 23:00 and
    # covers the hour after it, so the case ends at 24:00 — which is what the
    # band has to reach, or the busiest minutes of an attack sitting in the
    # final bucket cannot be selected.
    return [TimeSlot(start=FIRST + timedelta(hours=n), request_count=10 + n) for n in range(24)]


def band(qt_app: QApplication) -> Timeline:
    strip = Timeline()
    strip.resize(600, 60)
    strip.set_bars(bars())
    return strip


def press(strip: Timeline, x: int) -> None:
    _send(strip, QEvent.Type.MouseButtonPress, x, Qt.MouseButton.LeftButton)


def move(strip: Timeline, x: int) -> None:
    _send(strip, QEvent.Type.MouseMove, x, Qt.MouseButton.NoButton)


def release(strip: Timeline, x: int) -> None:
    _send(strip, QEvent.Type.MouseButtonRelease, x, Qt.MouseButton.NoButton)


def _send(strip: Timeline, kind: QEvent.Type, x: int, button: Qt.MouseButton) -> None:
    at = QPoint(x, strip.height() // 2)
    QApplication.sendEvent(
        strip,
        QMouseEvent(
            kind,
            QPointF(at),
            strip.mapToGlobal(at).toPointF(),
            button,
            Qt.MouseButton.LeftButton if kind != QEvent.Type.MouseButtonRelease else button,
            Qt.KeyboardModifier.NoModifier,
        ),
    )


# -- a pixel and a moment --------------------------------------------------


def test_the_left_edge_is_the_start_of_the_case(qt_app: QApplication) -> None:
    strip = band(qt_app)

    assert strip.moment_at(strip.track().left()) == FIRST


def test_the_right_edge_is_the_end_of_the_case(qt_app: QApplication) -> None:
    strip = band(qt_app)

    # `right()` is the last pixel *inside* the rectangle, so the moment the
    # case ends at sits one past it.
    assert strip.moment_at(strip.track().right() + 1) == LAST


def test_a_moment_and_its_pixel_agree_with_each_other(qt_app: QApplication) -> None:
    """The band and the fields point at one range. If these two disagreed, a
    drag would show one stretch and read another."""
    strip = band(qt_app)
    noon = FIRST + timedelta(hours=12)

    assert abs((strip.moment_at(strip.pixel_for(noon)) - noon).total_seconds()) < 120


def test_a_pixel_outside_the_track_is_held_at_the_case(qt_app: QApplication) -> None:
    """A drag can leave the widget. Held, the range stays inside the case; free,
    it names a stretch the case does not reach."""
    strip = band(qt_app)

    assert strip.moment_at(-500) == FIRST
    assert strip.moment_at(strip.width() + 500) == LAST


def test_a_band_with_no_traffic_still_answers(qt_app: QApplication) -> None:
    """A case is opened before it is read. Asked about a pixel with no bars, the
    band has to say something rather than divide by a span of zero."""
    strip = Timeline()
    strip.resize(600, 60)

    assert strip.moment_at(10) is None
    assert strip.showing() is EVERYTHING


# -- picking a slice -------------------------------------------------------


def test_dragging_across_the_band_picks_that_stretch(qt_app: QApplication) -> None:
    strip = band(qt_app)
    heard: list[TimeWindow] = []
    strip.changed.connect(heard.append)
    track = strip.track()
    left = track.left() + track.width() // 4
    right = track.left() + track.width() // 2

    press(strip, left)
    move(strip, right)
    release(strip, right)

    assert heard
    picked = heard[-1]
    assert picked.start == strip.moment_at(left)
    assert picked.end == strip.moment_at(right)


def test_dragging_right_to_left_picks_the_same_stretch(qt_app: QApplication) -> None:
    """A hand does not always move the way a range is written."""
    strip = band(qt_app)
    heard: list[TimeWindow] = []
    strip.changed.connect(heard.append)
    track = strip.track()
    left = track.left() + track.width() // 4
    right = track.left() + track.width() // 2

    press(strip, right)
    move(strip, left)
    release(strip, left)

    assert heard[-1].start == strip.moment_at(left)
    assert heard[-1].end == strip.moment_at(right)


def test_a_click_that_selects_nothing_is_not_a_range(qt_app: QApplication) -> None:
    """Otherwise a stray click on the band narrows the case to one instant and
    empties the window."""
    strip = band(qt_app)
    heard: list[TimeWindow] = []
    strip.changed.connect(heard.append)

    press(strip, 200)
    release(strip, 200)

    assert heard == [] or heard[-1].is_open


def test_being_shown_a_range_does_not_report_it_back(qt_app: QApplication) -> None:
    """The fields and the band set each other. Either answering the other would
    leave the two of them talking forever."""
    strip = band(qt_app)
    heard: list[TimeWindow] = []
    strip.changed.connect(heard.append)

    strip.set_window(TimeWindow(FIRST + timedelta(hours=2), FIRST + timedelta(hours=5)))

    assert heard == []
    assert strip.showing().start == FIRST + timedelta(hours=2)


def test_a_band_with_no_case_ignores_a_drag(qt_app: QApplication) -> None:
    strip = Timeline()
    strip.resize(600, 60)
    heard: list[TimeWindow] = []
    strip.changed.connect(heard.append)

    press(strip, 100)
    move(strip, 300)
    release(strip, 300)

    assert heard == []


def test_drawing_an_empty_band_does_not_fall_over(qt_app: QApplication) -> None:
    """A case is opened before it is read, and the widget is painted in between."""
    strip = Timeline()
    strip.resize(600, 60)

    strip.grab()


# -- how wide a bar is drawn ----------------------------------------------


def test_a_bar_is_as_wide_as_the_time_it_stands_for(qt_app: QApplication) -> None:
    """Not as wide as one share of the band.

    The buckets a store returns are only the ones that hold something: a quiet
    hour is absent, not zero. Sized by `1 / len(bars)`, a client with a handful
    of requests draws each one as a sixth of the band — blocks, not a
    histogram. The case-wide histogram is dense enough that this never showed.
    """
    strip = band(qt_app)
    track = strip.track()

    assert strip.bar_width() == pytest.approx(track.width() / 24, abs=2)


def test_bursts_with_quiet_gaps_are_drawn_at_the_burst_width(
    qt_app: QApplication,
) -> None:
    """The shape a real client has: runs of adjacent buckets with nothing
    between them. The step is the narrowest gap, not the first one — read off
    the first pair, a client that started with a pause would draw every bucket
    at the width of that pause.
    """
    full = band(qt_app)
    bursty = Timeline()
    bursty.resize(600, 60)
    # Reaching hour 23, so both bands cover the same day and the comparison is
    # about the step rather than about the span.
    bursty.set_bars(
        [
            TimeSlot(start=FIRST + timedelta(hours=n), request_count=5)
            for n in (0, 1, 2, 14, 15, 16, 23)
        ]
    )

    assert bursty.bar_width() == pytest.approx(full.bar_width(), abs=2)


def test_a_bar_is_never_thinner_than_a_line(qt_app: QApplication) -> None:
    """Hundreds of buckets on a narrow band round to nothing, and the drawing
    disappears rather than getting finer."""
    strip = Timeline()
    strip.resize(120, 60)
    strip.set_bars(
        [TimeSlot(start=FIRST + timedelta(seconds=n), request_count=1) for n in range(400)]
    )

    assert strip.bar_width() >= 1


def test_a_band_of_one_bucket_still_draws_something(qt_app: QApplication) -> None:
    strip = Timeline()
    strip.resize(600, 60)
    strip.set_bars([TimeSlot(start=FIRST, request_count=5)])

    assert strip.bar_width() >= 1


def test_a_client_that_started_with_a_pause_is_still_drawn_at_its_own_step(
    qt_app: QApplication,
) -> None:
    """The step is the narrowest gap, not the first one.

    A client that made one request and then went quiet for hours has a first
    gap of hours. Read off that pair, every bucket it ever filled would be drawn
    hours wide — a row of slabs where the burst is.
    """
    full = band(qt_app)
    late = Timeline()
    late.resize(600, 60)
    late.set_bars(
        [TimeSlot(start=FIRST + timedelta(hours=n), request_count=5) for n in (0, 9, 10, 11, 23)]
    )

    assert late.bar_width() == pytest.approx(full.bar_width(), abs=2)
