"""The control that narrows a case to one stretch of time.

Two fields, a way back to the whole case, and a line saying what is left. It
holds no opinions: what the words say is decided in `gui.timerange`, and what a
window means is decided in `core.window`. This puts them on screen and reports
when the reader changes one.

Deliberately not wired to redraw anything itself. The window owns the range —
one piece of state, changed in one place — because the graph, the client list
and an exported report all have to agree about it, and a control that reached
out to each of them would be three chances for them to disagree.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QDateTime, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QDateTimeEdit,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QWidget,
)

from logarc.core.window import EVERYTHING, TimeWindow
from logarc.gui.style import THEME
from logarc.gui.theme import GAP, TIGHT

if TYPE_CHECKING:
    from datetime import datetime

__all__ = ["TimeFilterBar"]

#: How a moment is offered for editing. Seconds are not shown: a reader picks a
#: minute, and three spin fields to reach one are three chances to mistype. The
#: window itself keeps seconds, which is what stops two ranges a second apart
#: sharing a name.
_FORMAT = "yyyy-MM-dd  HH:mm"

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
    color: {THEME.ink};
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

        row = QHBoxLayout(self)
        row.setContentsMargins(GAP, TIGHT, GAP, TIGHT)
        row.setSpacing(GAP)

        row.addWidget(QLabel("Between"))
        self._from = self._field()
        row.addWidget(self._from)
        row.addWidget(QLabel("and"))
        self._to = self._field()
        row.addWidget(self._to)

        self._clear = QPushButton("Whole case")
        self._clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clear.clicked.connect(self.clear)
        row.addWidget(self._clear)

        row.addStretch(1)
        self._summary = QLabel("")
        self._summary.setObjectName("timeFilterSummary")
        row.addWidget(self._summary)

        self.set_span(None)

    def _field(self) -> QDateTimeEdit:
        field = QDateTimeEdit()
        field.setDisplayFormat(_FORMAT)
        field.setCalendarPopup(True)
        field.editingFinished.connect(self._announce)
        return field

    # -- what the window tells it ------------------------------------------

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
            if span is not None:
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
    from datetime import UTC

    return when.toPyDateTime().replace(tzinfo=UTC)
