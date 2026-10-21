"""Keeping, forgetting and defending how a graph has been arranged.

Ten methods that used to sit on `MainWindow`, and the one part of it that came
out cleanly. Every method there was classified by the window state it reads:
*case*, *client* and *range* turned out to share sixteen, fifteen and fourteen
attributes with each other out of twenty, which is one thing wearing three
names rather than three components. This group shares five, five and four, and
what it shares is only the state everything shares.

It is handed the canvas rather than owning it, because every part of the window
uses that. What it owns is the store of saved arrangements, the key that says
which one belongs to what is on screen, the strip, and the question asked
before an arrangement nobody kept is lost.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from PyQt6.QtWidgets import QCheckBox, QMessageBox

from logarc.gui import arrangement
from logarc.gui.prefs import ASK_UNSAVED_ARRANGEMENT

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtCore import QSettings
    from PyQt6.QtGui import QAction
    from PyQt6.QtWidgets import QWidget

    from logarc.core.graph import GraphKind
    from logarc.gui.arrangement_bar import ArrangementBar
    from logarc.gui.canvas import ActivityCanvas

__all__ = ["LAYOUT_KEY", "ArrangementKeeper"]

#: Where the arrangements the reader saved are kept. One value holding all of
#: them, capped in `gui.arrangement`, so a single read on open answers for every
#: graph rather than one read per case in the settings tree.
#:
#: Like the recent-case list in `gui.app`, this records *what was investigated*:
#: the coordinates are keyed by activity id, and a trace's activity ids are built
#: from the client's address. `Reset layout` removes the arrangement for the
#: graph in front of the reader, which is the control they have over it.
LAYOUT_KEY: Final = "view/arrangements"


@dataclass(frozen=True, slots=True)
class Showing:
    """What the canvas is showing, as far as an arrangement is concerned.

    Asked for rather than handed over. Five things decide which arrangement
    belongs to a graph, and every one of them changes at a different moment:
    the case on open, the client on selection, the kind on a tab, the range on
    the date fields. Told each time, the window has four places that must
    remember; asking has none, and a keeper holding three of the new values and
    two of the old would look up a key that describes nothing — silently, and
    only until somebody noticed their arrangement had stopped coming back.
    """

    case_path: str
    client_ip: str
    kind: GraphKind
    window_tag: str


class ArrangementKeeper:
    """The arrangement half of the window, on its own."""

    def __init__(
        self,
        canvas: ActivityCanvas,
        bar: ArrangementBar,
        *,
        settings: Callable[[], QSettings],
        say: Callable[[str], None],
        parent: QWidget,
        showing: Callable[[], Showing | None],
    ) -> None:
        self._canvas = canvas
        self._bar = bar
        self._settings = settings
        self._say = say
        self._parent = parent
        self._showing = showing
        self._save: QAction | None = None
        self._undo: QAction | None = None
        self._reset: QAction | None = None

        # Whether to warn before an arrangement nobody kept is lost. A plain
        # attribute rather than a settings read, because the window already
        # holds its switches in one dictionary and reads them once at startup:
        # two readers of one stored value disagree the moment one is updated
        # and the other is not.
        self.ask_before_leaving = True

    # -- what it is wired to -----------------------------------------------

    def offer(self, save: QAction, undo: QAction, reset: QAction) -> None:
        """The three menu entries to keep in step with what is on the canvas.

        Kept rather than created here: they belong to the menu bar and to the
        canvas's own context menu, and Qt greys out the same object in both.
        """
        self._save, self._undo, self._reset = save, undo, reset

    # -- the store ---------------------------------------------------------

    def _stored(self) -> arrangement.Store:
        return arrangement.load(str(self._settings().value(LAYOUT_KEY, "")))

    def _key(self, *, wrap: bool | None = None) -> str | None:
        """Which saved arrangement belongs to what is on the canvas now.

        `None` before there is a graph, which is also when the menu entries are
        dead — so nothing downstream has to guess what an arrangement for no
        client would even mean.
        """
        showing = self._showing()
        if showing is None:
            return None
        return arrangement.key(
            showing.case_path,
            showing.client_ip,
            showing.kind,
            wrap=self._canvas.wrap if wrap is None else wrap,
            window=showing.window_tag,
        )

    def saved_positions(self, *, wrap: bool | None = None) -> arrangement.Positions | None:
        """The arrangement kept for this graph, if there is one."""
        name = self._key(wrap=wrap)
        return None if name is None else self._stored().get(name)

    def _baseline(self) -> arrangement.Positions:
        """Where this graph would be drawn if it were opened again right now.

        The layout, with whatever has been saved laid over it — which is exactly
        what `show_graph` does with a saved arrangement. Anything else on the
        canvas is a move the reader has made and not kept.

        Worked out on every ask rather than kept in an attribute, and that is
        what makes saving and resetting take the strip away without either of
        them having to remember to: after a save the store holds the positions
        that are on screen, after a reset it holds nothing and the positions are
        the layout's, and both come out as "nothing has moved" without being
        told. A flag set on the first drag would still be set after an undo had
        put everything back.
        """
        baseline = self._canvas.laid_out
        saved = self.saved_positions()
        if saved:
            baseline.update({node: where for node, where in saved.items() if node in baseline})
        return baseline

    # -- what the reader can do --------------------------------------------

    def undo(self) -> None:
        self._canvas.undo_move()

    def save(self) -> None:
        """Remember where the activities have been put on this graph."""
        name = self._key()
        if name is None:  # pragma: no cover - the entry is dead without a graph
            return
        store = arrangement.remember(self._stored(), name, self._canvas.positions)
        self._settings().setValue(LAYOUT_KEY, arrangement.dump(store))
        self.refresh()
        self._say("Layout saved.")

    def reset(self) -> None:
        """Put every activity back, and forget the arrangement that was saved.

        Both, because otherwise there is no way to be rid of a saved
        arrangement: reset, reopen the case, and it is back — which reads as the
        reset having failed rather than as having done half of what it says.
        """
        self._canvas.reset_layout()
        name = self._key()
        if name is not None:
            self._settings().setValue(
                LAYOUT_KEY, arrangement.dump(arrangement.forget(self._stored(), name))
            )
        self.refresh()
        self._say("Layout reset.")

    def refresh(self) -> None:
        """Grey out what there is nothing to do with, and offer what there is.

        A live control that does nothing reads as a fault in the tool, and
        `Undo` is the one that changes most: it comes alive on the first drag
        and goes back out when the stack empties.

        The strip rides along here because it answers the same question at the
        same moments. This is wired to `arrangement_changed`, which is emitted
        once per drag that moved something — so there is no second thing to
        remember to call, and no second place for the two to fall out of step.
        """
        drawn = self._showing() is not None and bool(self._canvas.positions)
        if self._undo is not None and self._save is not None and self._reset is not None:
            self._undo.setEnabled(drawn and self._canvas.can_undo)
            self._save.setEnabled(drawn)
            self._reset.setEnabled(drawn)
        moved = arrangement.moved_from(self._canvas.positions, self._baseline()) if drawn else ()
        self._bar.show_moved(len(moved))

    # -- and what has to be asked before it is lost ------------------------

    def ask(self) -> str:
        """Put the question, and answer `save`, `discard` or `cancel`.

        Split from `may_leave` so the rule around it can be tested without a
        dialog on screen: a modal `exec()` in a test either blocks the run or
        has to be dismissed by a timer, and neither is a test of the rule.
        """
        showing = self._showing()
        client = showing.client_ip if showing is not None else "this client"
        box = QMessageBox(self._parent)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle("Unsaved layout")
        box.setText(f"Save the layout of {client}?")
        box.setInformativeText(
            "Leaving without saving puts the activities back where they were laid out."
        )
        save = box.addButton("Save and continue", QMessageBox.ButtonRole.AcceptRole)
        discard = box.addButton("Discard", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(save)
        # Held in a name, not passed inline. `setCheckBox` does not keep the
        # Python object alive: an inline `QCheckBox` is collected, the tick
        # disappears from the dialog, and reading `box.checkBox()` afterwards
        # touches freed C++ and takes the process down with no traceback at all.
        ask_again = QCheckBox("Don't ask this again")
        box.setCheckBox(ask_again)

        box.exec()
        if ask_again.isChecked():
            self.ask_before_leaving = False
            self._settings().setValue(ASK_UNSAVED_ARRANGEMENT, False)

        pressed = box.clickedButton()
        if pressed is save:
            return "save"
        return "discard" if pressed is discard else "cancel"

    def may_leave(self) -> bool:
        """Whether the reader is finished with the graph that is on screen.

        `False` only when they said so. A cancelled question is the one answer
        that has to stop whatever asked it, and the caller is the only thing
        that knows how to undo its own half of the gesture.
        """
        if self._showing() is None or not self._canvas.positions:
            return True
        if not self.ask_before_leaving:
            return True
        if not arrangement.moved_from(self._canvas.positions, self._baseline()):
            return True

        answer = self.ask()
        if answer == "save":
            self.save()
        return answer != "cancel"
