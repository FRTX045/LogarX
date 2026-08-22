"""The band that shows where a case's traffic sits, and lets a slice be picked.

Draws what `EventStore.activity_over_time` counted and reports what the reader
dragged. It decides nothing about the case: which stretch is in force is the
window's business, and what the words say is `gui.timerange`'s.

Why a picture and not two fields alone. The fields can say *which* stretch but
never *where the traffic is* — and finding the busy hour is most of the reason
anyone reaches for this. On a real log the band shows the day-night rhythm and
the bursts standing out of it, which is a question answered before it is asked.

Its limit is known and was accepted with eyes open: on a case covering days, a
thirty-minute stretch is a hairline here, too narrow to drag onto. That is what
the fields beside it are for, and why the band is drawn to be read rather than
relied on.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QRect, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QWidget

from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui.style import THEME

if TYPE_CHECKING:
    from datetime import datetime

    from PyQt6.QtGui import QMouseEvent, QPaintEvent

    from logarc.storage.base import TimeSlot

__all__ = ["Timeline"]

#: How tall the band stands, and the room kept around the bars for the two
#: dates written beneath them.
_HEIGHT = 58
_INSET = 8
_BELOW = 18

#: How far the mouse must travel before a press counts as picking a stretch. A
#: click that selects nothing would otherwise narrow the case to one instant and
#: empty the window, which reads as the band having broken.
_ENOUGH = 4

_CAPTION_POINTS = 7.5


class Timeline(QWidget):
    """Where the traffic is, and which slice of it is being read."""

    changed = pyqtSignal(object)
    """The reader dragged out a stretch. Carries a `TimeWindow`."""

    def __init__(self) -> None:
        super().__init__()
        self.setMinimumHeight(_HEIGHT)
        self.setCursor(Qt.CursorShape.IBeamCursor)
        self._bars: list[TimeSlot] = []
        self._first: datetime | None = None
        self._last: datetime | None = None
        self._window: TimeWindow = EVERYTHING
        self._from_x: int | None = None
        self._to_x: int | None = None

    # -- what the window tells it ------------------------------------------

    def set_bars(self, bars: list[TimeSlot]) -> None:
        """The case's traffic, counted once when it was opened."""
        self._bars = bars
        self._first = bars[0].start if bars else None
        # The last bucket *starts* at its own moment and covers the step after
        # it. Taking its start as the end of the case would leave the final
        # step unreachable — the busiest minutes of an attack are often there.
        if len(bars) > 1:
            step = bars[1].start - bars[0].start
            self._last = bars[-1].start + step
        elif bars:
            self._last = bars[0].start
        else:
            self._last = None
        self.update()

    def set_window(self, window: TimeWindow) -> None:
        """Show a stretch without reporting it back as a fresh instruction."""
        self._window = window
        self.update()

    def showing(self) -> TimeWindow:
        """The stretch being shown.

        Not `window`: `QWidget.window()` is Qt's own, returning the top-level
        widget this one sits in, and shadowing it would break anything that
        asked the band which window it belongs to.
        """
        return self._window

    # -- pixels and moments ------------------------------------------------

    def track(self) -> QRect:
        """The strip the bars are drawn across."""
        return self.rect().adjusted(_INSET, _INSET, -_INSET, -_BELOW)

    def moment_at(self, x: int) -> datetime | None:
        """The moment a pixel stands for, held inside the case.

        Held rather than free because a drag can leave the widget, and a range
        reaching past the case would name a stretch it does not cover.
        """
        if self._first is None or self._last is None:
            return None
        track = self.track()
        if track.width() <= 0:  # pragma: no cover - a laid-out widget has width
            return self._first
        share = (x - track.left()) / track.width()
        share = min(max(share, 0.0), 1.0)
        return self._first + (self._last - self._first) * share

    def pixel_for(self, when: datetime) -> int:
        """Where a moment falls along the band."""
        track = self.track()
        if self._first is None or self._last is None:  # pragma: no cover - guarded
            return track.left()
        span = (self._last - self._first).total_seconds()
        if span <= 0:  # pragma: no cover - a case of one instant
            return track.left()
        share = (when - self._first).total_seconds() / span
        return track.left() + int(track.width() * min(max(share, 0.0), 1.0))

    # -- picking a stretch -------------------------------------------------

    def mousePressEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None or self._first is None:
            return
        self._from_x = self._to_x = event.pos().x()

    def mouseMoveEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None or self._from_x is None:
            return
        self._to_x = event.pos().x()
        self.update()

    def mouseReleaseEvent(self, event: QMouseEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is None or self._from_x is None:
            return
        self._to_x = event.pos().x()
        first, last = self._from_x, self._to_x
        self._from_x = self._to_x = None
        if abs(last - first) < _ENOUGH:
            self.update()
            return
        # Either way round: a hand does not always move the way a range is
        # written.
        start = self.moment_at(min(first, last))
        end = self.moment_at(max(first, last))
        if start is None or end is None:  # pragma: no cover - guarded by the press
            return
        self._window = TimeWindow(start, end)
        self.update()
        self.changed.emit(self._window)

    # -- drawing -----------------------------------------------------------

    def paintEvent(self, event: QPaintEvent | None) -> None:  # noqa: N802 - Qt's naming, ARG002
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        frame = self.rect().adjusted(0, 0, -1, -1)
        painter.setPen(QPen(QColor(THEME.edge)))
        painter.setBrush(QBrush(QColor(THEME.raised)))
        painter.drawRoundedRect(frame, 3, 3)
        if not self._bars or self._first is None or self._last is None:
            painter.end()
            return

        track = self.track()
        left, right = self._selection_pixels()
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(THEME.tint)))
        painter.drawRect(QRect(left, track.top(), max(right - left, 2), track.height()))

        peak = max(slot.request_count for slot in self._bars) or 1
        width = max(track.width() // max(len(self._bars), 1) - 1, 1)
        for slot in self._bars:
            x = self.pixel_for(slot.start)
            lit = left <= x <= right
            painter.setBrush(QBrush(QColor(THEME.accent if lit else THEME.edge_ink)))
            height = int(track.height() * slot.request_count / peak)
            painter.drawRect(QRect(x, track.bottom() - height, width, height))

        painter.setPen(QPen(QColor(THEME.accent)))
        for edge in (left, right):
            painter.drawLine(edge, track.top() - 2, edge, track.bottom() + 2)

        font = QFont()
        font.setPointSizeF(_CAPTION_POINTS)
        painter.setFont(font)
        painter.setPen(QPen(QColor(THEME.faint)))
        below = QRect(track.left(), track.bottom() + 2, track.width(), _BELOW - 2)
        painter.drawText(below, int(Qt.AlignmentFlag.AlignLeft), _stamp(self._first))
        painter.drawText(below, int(Qt.AlignmentFlag.AlignRight), _stamp(self._last))
        painter.end()

    def _selection_pixels(self) -> tuple[int, int]:
        """Where the highlight sits: the drag in progress, or the range in force."""
        if self._from_x is not None and self._to_x is not None:
            return min(self._from_x, self._to_x), max(self._from_x, self._to_x)
        track = self.track()
        if self._window.is_open or self._window.start is None or self._window.end is None:
            return track.left(), track.right()
        return self.pixel_for(self._window.start), self.pixel_for(self._window.end)


def _stamp(when: datetime) -> str:
    return when.strftime("%d %b %H:%M").lstrip("0")
