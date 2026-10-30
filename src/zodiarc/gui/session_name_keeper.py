"""Reading, asking for and saving the names a reader gives sessions.

Like `ArrangementKeeper`, it is handed the canvas rather than owning it, and it
asks for what is on screen instead of being told: the case folder and the
reconstruction both change at moments of the window's choosing, and a keeper
told each time would be one more thing that could hold an old value.

What it owns is the Rename session window while one is open, and the last
problem it reported about the file, so an unreadable file is said once and not
on every draw.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QTimer

from zodiarc import session_names
from zodiarc.bookmarks import utc_now
from zodiarc.graphbuild.layout import session_of, sessions_in
from zodiarc.gui.session_rename import SessionRename
from zodiarc.session_names import UNREADABLE_NAME, SessionKey
from zodiarc.style import display_safe, session_name, session_place

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from PyQt6.QtWidgets import QWidget

    from zodiarc.analysis import AnalysisResult
    from zodiarc.core.evidence import EvidenceRef
    from zodiarc.gui.canvas import ActivityCanvas

__all__ = ["SessionNameKeeper"]

_UNREADABLE: Final = (
    "The session names file in this case could not be read ({problem}), so Zodiarc's names"
    " are shown. It is kept as it is; the next rename sets it aside as {aside}."
)


class SessionNameKeeper:
    def __init__(
        self,
        *,
        canvas: ActivityCanvas,
        parent: QWidget,
        case_path: Callable[[], Path | None],
        result: Callable[[], AnalysisResult | None],
        say: Callable[[str], None],
    ) -> None:
        self._canvas = canvas
        self._parent = parent
        self._case_path = case_path
        self._result = result
        self._say = say
        self._problem: str | None = None
        #: The Rename session window, while one is open or was last opened.
        self.dialog: SessionRename | None = None

    def _sessions(
        self, result: AnalysisResult
    ) -> dict[str, tuple[SessionKey, frozenset[EvidenceRef]]]:
        """Each session on screen, by id: the key a new name is kept against, and
        every line it holds, which is what a name already given is found by."""
        return {
            session.session_id: (
                SessionKey(result.client_ip, session.events[0].evidence),
                frozenset(event.evidence for event in session.events),
            )
            for session in result.sessions
            if session.events
        }

    def names_for_drawing(self) -> dict[str, str]:
        """The reader's names for the sessions on screen, by session id.

        Read from the file each time, so a name a second window saved shows at
        the next draw. A file that cannot be read gives Zodiarc's names, and is
        said once, when the problem first appears or changes.
        """
        case, result = self._case_path(), self._result()
        if case is None or result is None:
            return {}
        loaded = session_names.load(case)
        if loaded.problem != self._problem:
            self._problem = loaded.problem
            if loaded.problem is not None:
                message = _UNREADABLE.format(problem=loaded.problem, aside=UNREADABLE_NAME)
                # Once the window has finished: this is read during a draw, and
                # the window says what it read after drawing, which would write
                # straight over it.
                QTimer.singleShot(0, lambda: self._say(message))
        names = {}
        for session_id, (_key, lines) in self._sessions(result).items():
            given = loaded.names.name_in(result.client_ip, lines)
            if given:
                names[session_id] = given
        return names

    def rename(self, session_id: str) -> None:
        """Open the Rename session window for that session.

        `open`, not `exec`: window-modal without a second event loop, so the
        window keeps drawing behind it, and a test can press its buttons.
        """
        case, result = self._case_path(), self._result()
        if case is None or result is None:
            return
        held = self._sessions(result).get(session_id)
        groups = sessions_in(result.trace)
        found = [
            (index, nodes)
            for index, nodes in enumerate(groups, start=1)
            if session_of(nodes[0]) == session_id
        ]
        if held is None or not found:
            return
        key, lines = held
        ((index, nodes),) = found
        zodiarc_name = session_name(nodes)
        given = session_names.load(case).names.name_in(result.client_ip, lines)

        def save(name: str | None) -> None:
            if name is None:
                session_names.apply(
                    case, lambda names: session_names.forget(names, key, within=lines)
                )
            else:
                session_names.apply(
                    case,
                    lambda names: session_names.rename(
                        names, key, name, zodiarc_name=zodiarc_name, now=utc_now(), within=lines
                    ),
                )
            self._canvas.set_session_names(self.names_for_drawing())

        self.dialog = SessionRename(
            self._parent,
            place=session_place(index, len(groups), nodes),
            current=display_safe(given) if given else zodiarc_name,
            zodiarc_name=zodiarc_name,
            renamed=given is not None,
            save=save,
        )
        self.dialog.open()
