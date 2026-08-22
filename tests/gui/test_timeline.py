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
