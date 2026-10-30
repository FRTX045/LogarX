"""Giving the graph the screen, and handing the window back afterwards.

The second cut out of `MainWindow`, and the last one the measurement supports.
Four methods that own eight things between them — whether it is on, what was
hidden to make room, and the menu entry that has to agree — and borrow only the
widgets they cover, which is inherent: covering things up is the job.

Preferences was tested as a third candidate and refused. It touches six
attributes and owns none of them: reaching every widget to put one setting in
force is what it is *for*, so a component made of it would hold a reference to
everything and be a fan-out with a name.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QByteArray, Qt, QTimer
from PyQt6.QtGui import QGuiApplication

from zodiarc.gui.display import is_wsl

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtGui import QAction, QKeyEvent
    from PyQt6.QtWidgets import QMainWindow, QWidget

    from zodiarc.gui.canvas import ActivityCanvas

__all__ = ["FullScreen"]


class FullScreen:
    """Whether the graph has the screen, and what it took to give it."""

    def __init__(
        self,
        window: QMainWindow,
        canvas: ActivityCanvas,
        *,
        cover: Callable[[], list[QWidget | None]],
    ) -> None:
        self._window = window
        self._canvas = canvas
        self._cover = cover
        self._action: QAction | None = None
        self._on = False
        self._was_maximised = False
        self.geometry_before: QByteArray | None = None
        """The window's geometry just before it went full screen, while it is.

        What the window saves if it closes in full screen: Qt's own geometry
        would record full screen and open in it next time."""

        # What was hidden on the way in, so only that is shown on the way out.
        # A reader who turned the traffic band off in Preferences must not find
        # it back on because they used full screen.
        self._covered: list[QWidget] = []

    def offer(self, action: QAction) -> None:
        """The menu entry whose tick has to agree with the state."""
        self._action = action

    @property
    def on(self) -> bool:
        return self._on

    def apply(self, on: bool) -> None:
        """Give the graph the screen, or hand the window back."""
        if on == self._on:
            return
        self._on = on
        if self._action is not None:
            # No `blockSignals` around this, though the original had one. The
            # entry is connected to `triggered`, which is user activation, and
            # `setChecked` emits only `toggled` — checked, not assumed. The
            # guard was defending against a signal nobody listens for.
            self._action.setChecked(on)
        self._canvas.set_expanded(on)

        if on:
            self._was_maximised = self._window.isMaximized()
            self.geometry_before = self._window.saveGeometry()
            self._covered = [w for w in self._cover() if w is not None and not w.isHidden()]
            for widget in self._covered:
                widget.hide()
            self._window.showFullScreen()
        else:
            # WSLg may configure fullscreen -> maximized as 0x0 and then
            # terminate the Wayland connection. Unmap first so the maximized
            # window gets a fresh surface. Keep Wayland's correct input and
            # screen coordinates rather than switching to XWayland, whose
            # borderless windows can have a visible/input offset (WSLg #1015).
            if (
                self._was_maximised
                and is_wsl()
                and QGuiApplication.platformName().startswith("wayland")
            ):
                self._window.hide()
            for widget in self._covered:
                widget.show()
            self._covered = []
            self.geometry_before = None
            if self._was_maximised:
                self._window.showMaximized()
            else:
                self._window.showNormal()
        # Refitted once the new geometry exists, not now. `showFullScreen`
        # returns before Qt has laid the window out again, so fitting here
        # frames the graph to the size the canvas has just stopped being —
        # measured, 536px wide while it was already becoming 784.
        QTimer.singleShot(0, self._canvas.fit)

    def from_the_menu(self) -> None:
        """The entry was ticked or unticked; follow it."""
        if self._action is not None:
            self.apply(self._action.isChecked())

    def from_the_canvas(self) -> None:
        """The corner button was pressed. It says nothing about which way."""
        self.apply(not self._on)

    def leaves_on(self, event: QKeyEvent | None) -> bool:
        """Whether this key press was Escape leaving full screen.

        Answered here rather than in the window's `keyPressEvent` so that the
        one condition worth stating — Escape means *leave*, and only when there
        is something to leave — sits with the state it is about. Answering it
        always would make a stray press do something in a window that is not
        full screen, which is how Escape comes to close things nobody asked to
        close.
        """
        if event is None or not self._on or event.key() != Qt.Key.Key_Escape:
            return False
        self.apply(False)
        return True
