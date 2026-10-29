"""Reading, asking for and saving the names a reader gives client addresses.

Like `SessionNameKeeper`, it asks for the case folder instead of being told,
because the folder changes at moments of the window's choosing. It reads the
file each time it is asked for the names, so a name another window saved shows
at the next ask, and `changed` tells the window when what it shows is out of
date: after a save here, or when `refresh` finds the file says something new.

What it owns is the Rename client window while one is open, and the last problem
it reported about the file, so an unreadable file is said once and not on every
read.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

from logarx import client_names
from logarx.bookmarks import utc_now
from logarx.client_names import UNREADABLE_NAME
from logarx.gui.client_rename import ClientRename
from logarx.style import display_safe

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtWidgets import QWidget

__all__ = ["ClientNameKeeper"]

_UNREADABLE: Final = (
    "The client names file in this case could not be read ({problem}), so addresses are"
    " shown. It is kept as it is; the next rename sets it aside as {aside}."
)


class ClientNameKeeper(QObject):
    #: What the window shows for some address may have changed.
    changed = pyqtSignal()

    def __init__(
        self,
        *,
        parent: QWidget | None,
        case_path: Callable[[], Path | None],
        say: Callable[[str], None],
    ) -> None:
        super().__init__(parent)
        self._parent = parent
        self._case_path = case_path
        self._say = say
        self._problem: str | None = None
        self._last: dict[str, str] = {}
        #: The Rename client window, while one is open or was last opened.
        self.dialog: ClientRename | None = None

    def names(self) -> dict[str, str]:
        """Every named address in the open case, and its name; empty with no case.

        A file that cannot be read names nothing, and is said once, when the
        problem first appears or changes.
        """
        case = self._case_path()
        if case is None:
            self._last = {}
            return {}
        loaded = client_names.load(case)
        if loaded.problem != self._problem:
            self._problem = loaded.problem
            if loaded.problem is not None:
                message = _UNREADABLE.format(problem=loaded.problem, aside=UNREADABLE_NAME)
                # Once the window has finished whatever asked: it may say what it
                # did straight afterwards, which would write over this.
                QTimer.singleShot(0, lambda: self._say(message))
        self._last = loaded.names.as_map()
        return dict(self._last)

    def refresh(self) -> None:
        """Read the file again, and say so if another window has changed it."""
        before = self._last
        if self.names() != before:
            self.changed.emit()

    def rename(self, address: str) -> None:
        """Open the Rename client window for `address`.

        `open`, not `exec`: window-modal without a second event loop, so the
        window keeps drawing behind it, and a test can press its buttons.
        """
        case = self._case_path()
        if case is None:
            return
        # Through `names`, so an unreadable file is said before the save sets it aside.
        given = self.names().get(address)

        def save(name: str | None) -> None:
            if name is None:
                client_names.apply(case, lambda names: client_names.forget(names, address))
            else:
                client_names.apply(
                    case, lambda names: client_names.rename(names, address, name, now=utc_now())
                )
            self.names()
            self.changed.emit()

        self.dialog = ClientRename(
            self._parent,
            address=address,
            current=display_safe(given) if given else "",
            named=given is not None,
            save=save,
        )
        self.dialog.open()
