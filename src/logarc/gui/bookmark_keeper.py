"""One case's bookmarks, and what the window does with them.

Handed the window, the tab and an `Opener` — the window's own ways of opening a
client, a log line and a search — rather than owning them, the way
`ArrangementKeeper` is handed the canvas. What it owns is the shelf for the open
case, the save box while it is up, and the decisions: what saving the same thing
twice means, what is gone, and what each panel should mark.
"""

from __future__ import annotations

import errno
from dataclasses import dataclass
from dataclasses import replace as changed
from typing import TYPE_CHECKING, Protocol

from PyQt6.QtCore import QObject, QPoint, pyqtSignal
from PyQt6.QtWidgets import QMessageBox, QWidget

from logarc import bookmarks
from logarc.bookmarks import (
    DEFAULT,
    EMPTY,
    UNREADABLE_NAME,
    Bookmark,
    BookmarkWriteError,
    CategoryError,
    Kind,
    Shelf,
    new_id,
    newest_first,
    utc_now,
)
from logarc.caseview import node_for_episodes
from logarc.core.window import EVERYTHING
from logarc.gui.bookmark_box import BookmarkBox
from logarc.gui.bookmarks_tab import BookmarksTab, CategoriesDialog
from logarc.style import plural
from logarc.timerange import spoken

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from pathlib import Path

    from logarc.analysis import AnalysisResult
    from logarc.core.evidence import EvidenceRef
    from logarc.core.graph import ActivityGraph
    from logarc.core.window import TimeWindow
    from logarc.gui.ribbon import Mark

__all__ = ["BookmarkKeeper", "Draft", "Opener"]

_CANNOT_WRITE = "Could not save the bookmark: the case folder cannot be written to."
_UNREADABLE = (
    "The bookmarks file in this case could not be read ({problem}), so none are shown."
    " It is kept as it is; the next bookmark saved sets it aside as {aside}."
)
#: How many bookmarks a client's ribbon lists in its tooltip before counting the rest.
_TIP_LIMIT = 5


@dataclass(frozen=True, slots=True)
class Draft:
    """What is about to be bookmarked, as the window found it."""

    kind: Kind
    #: The save box's heading: "Bookmark this activity", and so on.
    title: str
    said: str
    client: str | None = None
    line: EvidenceRef | None = None
    at: datetime | None = None
    query: str | None = None
    range: TimeWindow | None = None


class Opener(Protocol):
    """The window's side: opening what a bookmark points at, and checking it is there."""

    def open_client(self, ip: str) -> None: ...

    def open_line(
        self, ip: str, ref: EvidenceRef, *, whole_activity: bool, at: datetime | None
    ) -> None: ...

    def open_search(self, query: str, window: TimeWindow) -> None: ...

    def check_targets(
        self,
        clients: frozenset[str],
        done: Callable[[frozenset[str], frozenset[str]], None],
    ) -> None:
        """Find which of `clients` the case holds, and the log files it names; then `done`."""


def _write_failed(error: BookmarkWriteError) -> str:
    refused = isinstance(error.__cause__, PermissionError) or error.errno in (
        errno.EACCES,
        errno.EPERM,
        errno.EROFS,
    )
    if refused:
        return _CANNOT_WRITE
    return f"Could not save the bookmark: {error.strerror or error}."


def _tip(bookmark: Bookmark) -> str:
    return f"{bookmark.category}: {bookmark.note or bookmark.said}"


class BookmarkKeeper(QObject):
    """The open case's bookmarks."""

    changed = pyqtSignal()
    """The shelf changed, or what is gone did: the marks should be drawn again."""

    def __init__(
        self, window: QWidget, tab: BookmarksTab, opener: Opener, *, say: Callable[[str], None]
    ) -> None:
        super().__init__(window)
        self._window = window
        self._tab = tab
        self._opener = opener
        self._say = say
        self._case: Path | None = None
        self._shelf = EMPTY
        self._last = DEFAULT
        # Unknown until the window has looked: nothing is gone before then.
        self._present: frozenset[str] | None = None
        self._sources: frozenset[str] | None = None
        self._generation = 0
        self.box: BookmarkBox | None = None
        self.categories_dialog: CategoriesDialog | None = None
        tab.open_requested.connect(self.open)
        tab.edit_requested.connect(self.edit)
        tab.remove_requested.connect(self.remove)
        tab.categories_requested.connect(self.manage_categories)

    @property
    def shelf(self) -> Shelf:
        return self._shelf

    # -- the case -----------------------------------------------------------------

    def load(self, case_dir: Path | None) -> None:
        """Read the bookmarks of the case at `case_dir`; `None` when no case is open."""
        self._close_box()
        if self.categories_dialog is not None:
            self.categories_dialog.close()
            self.categories_dialog = None
        self._generation += 1
        generation = self._generation
        self._case = case_dir
        self._present = self._sources = None
        if case_dir is None:
            self._shelf = EMPTY
            self._tab.set_notice(None)
        else:
            loaded = bookmarks.load(case_dir)
            self._shelf = loaded.shelf
            self._tab.set_notice(
                None
                if loaded.problem is None
                else _UNREADABLE.format(problem=loaded.problem, aside=UNREADABLE_NAME)
            )

            def checked(present: frozenset[str], sources: frozenset[str]) -> None:
                if generation != self._generation:
                    return
                self._present, self._sources = present, sources
                self._show()

            clients = frozenset(b.client for b in self._shelf.bookmarks if b.client is not None)
            self._opener.check_targets(clients, checked)
        self._last = self._shelf.categories[0].name
        self._show()

    def is_gone(self, bookmark: Bookmark) -> bool:
        """Whether what `bookmark` points at is no longer in the case, as far as is known."""
        if bookmark.kind is Kind.SEARCH:
            return False
        if self._present is not None and bookmark.client not in self._present:
            return True
        return (
            self._sources is not None
            and bookmark.line is not None
            and bookmark.line.source_file_id not in self._sources
        )

    def _show(self) -> None:
        self._tab.show_shelf(self._shelf, gone=self.is_gone)
        self.changed.emit()

    # -- saving and editing ----------------------------------------------------------

    def bookmark(self, draft: Draft, anchor: QPoint | None) -> None:
        """Open the save box for `draft`, or the edit box if it is already bookmarked."""
        if self._case is None:
            self._say("Open a case to bookmark in it.")
            return
        candidate = Bookmark(
            id=new_id(),
            kind=draft.kind,
            category=self._last,
            said=draft.said,
            note="",
            saved=utc_now(),
            client=draft.client,
            line=draft.line,
            at=draft.at,
            query=draft.query,
            range=draft.range,
        )
        existing = self._shelf.same_as(candidate)
        if existing is not None:
            self._say("Already bookmarked: edit it here.")
            self.edit(existing.id, anchor)
            return
        self._open_box(
            title=draft.title,
            bookmark=candidate,
            anchor=anchor,
            change=lambda category, note: (
                lambda shelf: bookmarks.add(
                    shelf, changed(candidate, category=category, note=note, saved=utc_now())
                )
            ),
            done="Bookmarked in {category}.",
        )

    def edit(self, ident: str, anchor: QPoint | None = None) -> None:
        bookmark = self._shelf.by_id(ident)
        if bookmark is None or self._case is None:
            return
        self._open_box(
            title="Edit bookmark",
            bookmark=bookmark,
            anchor=anchor,
            change=lambda category, note: (
                lambda shelf: bookmarks.replace(
                    shelf, changed(bookmark, category=category, note=note)
                )
            ),
            done="Bookmark saved in {category}.",
        )

    def _open_box(
        self,
        *,
        title: str,
        bookmark: Bookmark,
        anchor: QPoint | None,
        change: Callable[[str, str], Callable[[Shelf], Shelf]],
        done: str,
    ) -> None:
        self._close_box()
        box = BookmarkBox(
            self._window,
            title=title,
            said=bookmark.said,
            client=bookmark.client
            if bookmark.client is not None
            else spoken(bookmark.range or EVERYTHING),
            categories=[category.name for category in self._shelf.categories],
            category=bookmark.category,
            note=bookmark.note,
        )
        box.saving.connect(
            lambda category, note: self._save(box, change(category, note), category, done, bookmark)
        )
        box.finished.connect(lambda _result: self._forget_box(box))
        self.box = box
        box.place(anchor if anchor is not None else self._middle())
        box.open()

    def _middle(self) -> QPoint:
        return QPoint(max(12, (self._window.width() - 430) // 2), self._window.height() // 5)

    def _save(
        self,
        box: BookmarkBox,
        change: Callable[[Shelf], Shelf],
        category: str,
        done: str,
        bookmark: Bookmark,
    ) -> None:
        if self._case is None:
            return
        try:
            self._shelf = bookmarks.apply(self._case, change)
        except BookmarkWriteError as error:
            box.show_error(_write_failed(error))
            return
        except CategoryError as error:
            box.show_error(str(error))
            return
        found = self._shelf.category(category)
        self._last = found.name if found is not None else self._shelf.categories[0].name
        # A file that could not be read has just been set aside.
        self._tab.set_notice(None)
        if self._present is not None and bookmark.client is not None:
            self._present = self._present | {bookmark.client}
        self.box = None
        box.accept()
        self._show()
        self._say(done.format(category=self._last))

    def _forget_box(self, box: BookmarkBox) -> None:
        if self.box is box:
            self.box = None

    def _close_box(self) -> None:
        box, self.box = self.box, None
        if box is not None:
            box.reject()

    # -- removing and opening ------------------------------------------------------------

    def remove(self, ident: str) -> None:
        bookmark = self._shelf.by_id(ident)
        if bookmark is None or self._case is None:
            return
        answer = QMessageBox.question(
            self._window,
            "Remove bookmark",
            "Remove this bookmark?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self._shelf = bookmarks.apply(self._case, lambda shelf: bookmarks.remove(shelf, ident))
        except BookmarkWriteError as error:
            self._say(_write_failed(error).replace("save", "remove", 1))
            return
        self._show()
        self._say("Bookmark removed.")

    def open(self, ident: str) -> None:
        bookmark = self._shelf.by_id(ident)
        if bookmark is None or self.is_gone(bookmark):
            return
        if bookmark.kind is Kind.SEARCH:
            self._opener.open_search(bookmark.query or "", bookmark.range or EVERYTHING)
        elif bookmark.client is not None and bookmark.line is not None:
            self._opener.open_line(
                bookmark.client,
                bookmark.line,
                whole_activity=bookmark.kind is Kind.ACTIVITY,
                at=bookmark.at,
            )
        elif bookmark.client is not None:
            self._opener.open_client(bookmark.client)

    # -- categories --------------------------------------------------------------------

    def manage_categories(self) -> None:
        if self._case is None:
            return
        dialog = CategoriesDialog(self._window, self._shelf)
        dialog.rename_requested.connect(self._rename)
        dialog.delete_requested.connect(self._delete_category)
        dialog.finished.connect(lambda _result: self._forget_dialog(dialog))
        self.categories_dialog = dialog
        dialog.open()

    def _forget_dialog(self, dialog: CategoriesDialog) -> None:
        if self.categories_dialog is dialog:
            self.categories_dialog = None

    def _change_categories(self, change: Callable[[Shelf], Shelf]) -> bool:
        dialog = self.categories_dialog
        if self._case is None:
            return False
        try:
            self._shelf = bookmarks.apply(self._case, change)
        except (CategoryError, BookmarkWriteError) as error:
            text = _write_failed(error) if isinstance(error, BookmarkWriteError) else str(error)
            if dialog is not None:
                dialog.show_error(text)
            return False
        if self._shelf.category(self._last) is None:
            self._last = self._shelf.categories[0].name
        if dialog is not None:
            dialog.show_shelf(self._shelf)
        self._show()
        return True

    def _rename(self, old: str, new: str) -> None:
        # Asked before the change: once renamed, the old name is gone, and the
        # change itself falls back to the first category for a name it cannot find.
        was_last = self._last.casefold() == old.casefold()
        if (
            self._change_categories(lambda shelf: bookmarks.rename_category(shelf, old, new))
            and was_last
        ):
            self._last = " ".join(new.split())

    def _delete_category(self, name: str) -> None:
        found = self._shelf.category(name)
        if found is None:
            return
        held = sum(b.category == found.name for b in self._shelf.bookmarks)
        if held:
            first = self._shelf.categories[0].name
            answer = QMessageBox.question(
                self._window,
                "Delete category",
                f"Move its {plural(held, 'bookmark')} to {first}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._change_categories(lambda shelf: bookmarks.delete_category(shelf, name))

    # -- marks --------------------------------------------------------------------------

    def client_marks(self) -> dict[str, Mark]:
        """A ribbon for every client with a bookmark, in its newest bookmark's colour."""
        theirs: dict[str, list[Bookmark]] = {}
        for bookmark in self._shelf.bookmarks:
            if bookmark.client is not None:
                theirs.setdefault(bookmark.client, []).append(bookmark)
        marks: dict[str, Mark] = {}
        for client, unsorted in theirs.items():
            held = newest_first(unsorted)
            lines = [_tip(b) for b in held[:_TIP_LIMIT]]
            if len(held) > _TIP_LIMIT:
                lines.append(f"and {len(held) - _TIP_LIMIT} more")
            marks[client] = (self._shelf.colour_of(held[0].category), "\n".join(lines))
        return marks

    def line_marks(self, client: str) -> dict[EvidenceRef, Mark]:
        """A ribbon for every log line of `client` bookmarked as a request."""
        return {
            b.line: (self._shelf.colour_of(b.category), _tip(b))
            for b in self._shelf.bookmarks
            if b.kind is Kind.REQUEST and b.client == client and b.line is not None
        }

    def node_marks(self, result: AnalysisResult, graph: ActivityGraph) -> dict[str, Mark]:
        """A ribbon for every activity holding a bookmarked activity's line, by node id.

        Found through the line, not an id: the activity it was saved on may since
        have been merged with another, or split, and the one now holding the line
        is the one to mark.
        """
        wanted = {
            b.line: b
            for b in self._shelf.bookmarks
            if b.kind is Kind.ACTIVITY and b.client == result.client_ip and b.line is not None
        }
        if not wanted:
            return {}
        episodes: dict[EvidenceRef, str] = {}
        for assignment in result.assignments:
            if assignment.evidence in wanted:
                episodes[assignment.evidence] = assignment.episode_id
        marks: dict[str, Mark] = {}
        for line, bookmark in wanted.items():
            episode = episodes.get(line)
            node = node_for_episodes(graph, frozenset({episode})) if episode else None
            if node is not None:
                marks[node.node_id] = (self._shelf.colour_of(bookmark.category), _tip(bookmark))
        return marks
