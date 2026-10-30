"""Ctrl and the mouse wheel zoom the interface text, as in most applications."""

from __future__ import annotations

import time
import weakref
from typing import TYPE_CHECKING

from PyQt6.QtCore import QEvent, QObject, Qt, pyqtSignal
from PyQt6.QtGui import QWheelEvent
from PyQt6.QtWidgets import QWidget

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication

__all__ = ["CtrlWheel"]

#: One notch of an ordinary wheel. Touchpads and high-resolution wheels send
#: a fraction of this per event, so steps are counted from the running total.
_NOTCH = 120

#: How long the wheel must rest before a part-turn is dropped, in seconds, so
#: half a gesture now and half a minute later do not add up to a step.
_PAUSE = 0.5

#: The clock the pause is measured on; a test replaces it.
_now = time.monotonic


class CtrlWheel(QObject):
    """Turns Ctrl+wheel over one window into whole zoom steps.

    Installed on the application, so it sees the wheel before the widget under
    the pointer: a text browser would otherwise zoom its own text as well. The
    wheel over `skip`, the graph, is left alone, because the graph zooms with
    the wheel on its own.
    """

    stepped = pyqtSignal(int)
    """+1 to zoom in one step, -1 to zoom out one."""

    def __init__(self, app: QApplication, window: QWidget, *, skip: QWidget) -> None:
        super().__init__(window)
        # The window is this filter's parent, and the graph is held weakly: a
        # Python reference back to either would outlive Qt's destruction of it.
        self._skip = weakref.ref(skip)
        self._pending = 0
        self._last = 0.0
        app.installEventFilter(self)

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802 - Qt's naming
        skip = self._skip()
        if (
            not isinstance(event, QWheelEvent)
            or not event.modifiers() & Qt.KeyboardModifier.ControlModifier
            or not isinstance(watched, QWidget)
            or watched.window() is not self.parent()
            or skip is None
            or watched is skip
            or skip.isAncestorOf(watched)
        ):
            return False
        now = _now()
        if now - self._last > _PAUSE:
            self._pending = 0
        self._last = now
        self._pending += event.angleDelta().y()
        while abs(self._pending) >= _NOTCH:
            step = 1 if self._pending > 0 else -1
            self._pending -= step * _NOTCH
            self.stepped.emit(step)
        return True
