"""The control that narrows a case to one stretch of time.

Two fields, a way back to the whole case, and a line saying what is left. It
holds no opinions: what the words say is decided in `zodiarc.timerange`, and what a
window means is decided in `core.window`. This puts them on screen and reports
when the reader changes one.

Deliberately not wired to redraw anything itself. The window owns the range —
one piece of state, changed in one place — because the graph, the client list
and an exported report all have to agree about it, and a control that reached
out to each of them would be three chances for them to disagree.
"""

from __future__ import annotations

from datetime import UTC
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QDateTime, Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QDateTimeEdit,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from zodiarc.core.window import EVERYTHING, TimeWindow
from zodiarc.gui.theme import GAP, TIGHT, on_font_change
from zodiarc.gui.timeline import Timeline
from zodiarc.style import THEME

if TYPE_CHECKING:
    from datetime import datetime

    from zodiarc.storage.base import TimeSlot

__all__ = ["TimeFilterBar"]

#: How a moment is offered for editing. Seconds are not shown: a reader picks a
#: minute, and three spin fields to reach one are three chances to mistype. The
#: window itself keeps seconds, which is what stops two ranges a second apart
#: sharing a name.
_FORMAT = "yyyy-MM-dd  HH:mm"

#: Room for the calendar arrow and the field's own padding, beside the text.
_ARROW = 40

_STYLE = f"""
QWidget#timeFilterBar {{
    background: {THEME.raised};
    border: 1px solid {THEME.edge};
    border-radius: 3px;
}}
QLabel {{ color: {THEME.muted}; }}
QLabel#timeFilterSummary {{ color: {THEME.ink}; }}
QDateTimeEdit {{
    background: {THEME.surface};
    color: {THEME.timestamp};
    border: 1px solid {THEME.edge};
    border-radius: 2px;
    padding: 2px 6px;
}}
QDateTimeEdit:disabled {{ color: {THEME.faint}; border-color: {THEME.edge}; }}
QPushButton {{
    background: transparent;
    color: {THEME.muted};
    border: 1px solid {THEME.edge};
    border-radius: 2px;
    padding: 3px 10px;
}}
QPushButton:hover:enabled {{ color: {THEME.ink}; }}
QPushButton:disabled {{ color: {THEME.faint}; }}
"""


#: What a date field shows while no case is open.
_NO_DATE: Final = "—"


class TimeFilterBar(QWidget):
    """Pick the stretch of time the case is read over."""

    changed = pyqtSignal(object)
    """The reader asked for a different stretch. Carries a `TimeWindow`.

    `object` rather than a typed signal because `TimeWindow` is not a Qt type;
    the window connects a plain callable and reads it as what it is.
    """

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("timeFilterBar")
        self.setStyleSheet(_STYLE)
        self._span: tuple[datetime, datetime] | None = None

        column = QVBoxLayout(self)
        column.setContentsMargins(GAP, TIGHT, GAP, TIGHT)
        column.setSpacing(TIGHT)

        # The band above the fields, because it is read first: it answers
        # *where is the traffic* before the fields are asked *which stretch*.
        self._band = Timeline()
        self._band.changed.connect(self._from_band)
        column.addWidget(self._band)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(GAP)
        column.addLayout(row)

        row.addWidget(QLabel("From"))
        self._from = self._field()
        row.addWidget(self._from)
        row.addWidget(QLabel("to"))
        self._to = self._field()
        row.addWidget(self._to)
        self._fit_fields()
        for field in (self._from, self._to):
            on_font_change(field, self._fit_fields)

        self._clear = QPushButton("All time")
        self._clear.setToolTip("Read the whole case again, from its first request to its last.")
        self._clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear.clicked.connect(self.clear)
        row.addWidget(self._clear)

        row.addStretch(1)
        self._summary = QLabel("")
        self._summary.setObjectName("timeFilterSummary")
        row.addWidget(self._summary)

        self.set_span(None)

    def _from_band(self, window: TimeWindow) -> None:
        """The reader dragged on the band. Show it in the fields and pass it on.

        One range, two controls. The fields are told rather than asked, and told
        with signals blocked, so neither control can answer the other.
        """
        self.set_window(window)
        self.changed.emit(window)

    def _field(self) -> QDateTimeEdit:
        field = QDateTimeEdit()
        field.setDisplayFormat(_FORMAT)
        field.setCalendarPopup(True)
        field.editingFinished.connect(self._announce)
        return field

    def _fit_fields(self) -> None:
        """Room for a whole date and time in each field, at the text size in force.

        Measured, not guessed. Qt sizes one of these to its format string and
        then puts the calendar arrow on top of the result, so the minutes are
        clipped: `2024-05-02 01:2` for a field whose whole job is to say when.
        `_ARROW` is the room that arrow takes.
        """
        for field in (self._from, self._to):
            field.setMinimumWidth(
                QFontMetrics(field.font()).horizontalAdvance("2024-05-02  00:00") + _ARROW
            )

    # -- what the window tells it ------------------------------------------

    def set_bars(self, bars: list[TimeSlot]) -> None:
        """The case's traffic, for the band to draw."""
        self._band.set_bars(bars)

    def set_case_open(self, is_open: bool) -> None:
        """Whether a case is open, so an empty band says the right thing."""
        self._band.set_open(is_open)

    def band_width(self) -> int:
        """How many pixels wide the band's bars are drawn across.

        Asked by the window to decide how finely to count the traffic. Reported
        even while the band is hidden: the reader can turn it back on without
        reopening the case, and a count of zero would draw nothing when they
        did.
        """
        return self._band.track().width()

    def show_band(self, showing: bool) -> None:
        """Whether to draw the traffic at all.

        Only the picture goes. The fields stay, because they are the precise
        control and the one a reader falls back on for a stretch too narrow to
        drag onto — turning the drawing off must not turn the filter off with
        it.
        """
        self._band.setVisible(showing)

    def set_span(self, span: tuple[datetime, datetime] | None) -> None:
        """The stretch the open case covers, or `None` when none is open.

        Both fields are held inside it. A reader cannot ask for a stretch the
        case does not reach, so the reconstruction cannot come back empty for a
        reason that was never on screen.
        """
        self._span = span
        for field in (self._from, self._to):
            field.blockSignals(True)
            field.setEnabled(span is not None)
            if span is None:
                # A dash, not 2000-01-01: Qt shows the special text only at the
                # minimum, so the field is put there while no case is open.
                field.setSpecialValueText(_NO_DATE)
                field.setDateTime(field.minimumDateTime())
            else:
                # Taken away again before the range is set: the case's first
                # moment becomes the minimum, and would read as a dash.
                field.setSpecialValueText("")
                field.setDateTimeRange(_qt(span[0]), _qt(span[1]))
            field.blockSignals(False)
        self._clear.setEnabled(span is not None)
        if span is not None:
            self.set_window(EVERYTHING)

    def set_window(self, window: TimeWindow) -> None:
        """Show `window` without reporting it back as a fresh instruction.

        Two controls will point at one range once the band exists, so each has
        to be able to set the other without that counting as the reader asking
        for something.
        """
        if self._span is None:
            return
        self._band.set_window(window)
        shown = window.clamped_to(*self._span)
        # `clamped_to` fills both ends from the case, so neither is ever absent
        # here — but the type does not say so, and an assert is cheaper than a
        # second type that exists only to carry that promise.
        assert shown.start is not None
        assert shown.end is not None
        for field, when in ((self._from, shown.start), (self._to, shown.end)):
            field.blockSignals(True)
            field.setDateTime(_qt(when))
            field.blockSignals(False)

    @property
    def span(self) -> tuple[datetime, datetime] | None:
        """The stretch the open case covers, or `None` when none is open."""
        return self._span

    def say(self, text: str) -> None:
        """The line on the right: what is left of the case."""
        self._summary.setText(text)

    # -- what the reader tells it ------------------------------------------

    @property
    def chosen(self) -> TimeWindow:
        """The stretch the fields are showing.

        Not `window`: `QWidget.window()` is Qt's own, returning the top-level
        widget this one sits in, and shadowing it would break anything that
        asked this control which window it belongs to.

        The whole case reads as an open window rather than as its own two ends,
        so nothing downstream has to compare dates to know a filter is off — and
        identifiers stay exactly as they always were.
        """
        if self._span is None:
            return EVERYTHING
        chosen = TimeWindow(_py(self._from.dateTime()), _py(self._to.dateTime()))
        return EVERYTHING if chosen == TimeWindow(*self._span) else chosen

    def clear(self) -> None:
        """Back to the whole case."""
        self.set_window(EVERYTHING)
        self._announce()

    def _announce(self) -> None:
        # Held apart rather than swapped: `TimeWindow` refuses a range that ends
        # before it starts, and swapping here would let a mistyped end silently
        # become a range the reader did not ask for.
        if self._from.dateTime() > self._to.dateTime():
            self._to.blockSignals(True)
            self._to.setDateTime(self._from.dateTime())
            self._to.blockSignals(False)
        self.changed.emit(self.chosen)


def _qt(when: datetime) -> QDateTime:
    """A moment Qt can edit. Naive: the fields carry no zone, and the case is
    UTC throughout, so attaching one here would show the reader a shifted clock."""
    return QDateTime(when.replace(tzinfo=None))


def _py(when: QDateTime) -> datetime:
    return when.toPyDateTime().replace(tzinfo=UTC)
