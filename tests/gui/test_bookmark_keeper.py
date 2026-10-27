"""The keeper: one case's bookmarks, saved, edited, removed, opened, and marked.

Driven with a stand-in for the window, which is what opens a client, a line or a
search; the keeper decides which, and what the file and the tab say.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from PyQt6.QtCore import QPoint, Qt
from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget

from logarx import bookmarks
from logarx.bookmarks import DEFAULT, FILE_NAME, UNREADABLE_NAME, Kind
from logarx.core.activity import ActivityCategory, Outcome, Severity
from logarx.core.evidence import EvidenceRef
from logarx.core.graph import ActivityGraph, GraphKind, GraphNode
from logarx.core.window import EVERYTHING, TimeWindow
from logarx.gui import bookmark_keeper
from logarx.gui.bookmark_keeper import BookmarkKeeper, Draft
from logarx.gui.bookmarks_tab import BookmarksTab

AT = datetime(2026, 3, 10, 19, 12, 18, tzinfo=UTC)
LINE = EvidenceRef("excerpt.log", 2014)


class Opener:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []
        self.checks: list[tuple[frozenset[str], Any]] = []

    def open_client(self, ip: str) -> None:
        self.calls.append(("client", ip))

    def open_line(
        self, ip: str, ref: EvidenceRef, *, whole_activity: bool, at: datetime | None
    ) -> None:
        self.calls.append(("line", ip, ref, whole_activity, at))

    def open_search(self, query: str, window: TimeWindow) -> None:
        self.calls.append(("search", query, window))

    def check_targets(self, clients: frozenset[str], done: Any) -> None:
        self.checks.append((clients, done))


@pytest.fixture
def window(qt_app: QApplication) -> QWidget:
    shown = QWidget()
    shown.resize(900, 600)
    shown.show()
    QApplication.processEvents()
    return shown


@pytest.fixture
def parts(
    window: QWidget, tmp_path: Path
) -> tuple[BookmarkKeeper, BookmarksTab, Opener, list[str]]:
    tab = BookmarksTab()
    opener = Opener()
    said: list[str] = []
    keeper = BookmarkKeeper(window, tab, opener, say=said.append)
    keeper.load(tmp_path)
    return keeper, tab, opener, said


def activity(client: str = "192.0.2.23") -> Draft:
    return Draft(
        kind=Kind.ACTIVITY,
        title="Bookmark this activity",
        said="Credential Attack \u00b7 6 requests",
        client=client,
        line=LINE,
        at=AT,
    )


def client(ip: str) -> Draft:
    return Draft(kind=Kind.CLIENT, title="Bookmark this client", said="50 requests", client=ip)


def save(keeper: BookmarkKeeper, draft: Draft, category: str = DEFAULT, note: str = "") -> None:
    keeper.bookmark(draft, QPoint(20, 20))
    box = keeper.box
    assert box is not None
    box.saving.emit(category, note)


def stored(folder: Path) -> bookmarks.Shelf:
    return bookmarks.load(folder).shelf


def test_saving_writes_the_file_lists_it_and_closes_the_box(parts, tmp_path: Path) -> None:
    keeper, tab, _opener, said = parts
    heard: list[bool] = []
    keeper.changed.connect(lambda: heard.append(True))
    keeper.bookmark(activity(), QPoint(20, 20))
    box = keeper.box
    assert box is not None and box.isVisible()
    assert box.heading.text() == "Bookmark this activity"
    assert box.category.currentText() == DEFAULT

    box.saving.emit("Login attacks", "the lockout held")

    (saved,) = stored(tmp_path).bookmarks
    assert (saved.kind, saved.category, saved.note, saved.line, saved.at) == (
        Kind.ACTIVITY,
        "Login attacks",
        "the lockout held",
        LINE,
        AT,
    )
    assert keeper.box is None and not box.isVisible()
    assert tab.count() == 1
    assert heard
    assert said[-1] == "Bookmarked in Login attacks."


def test_the_next_bookmark_starts_in_the_category_last_used(parts) -> None:
    keeper, *_ = parts
    save(keeper, client("10.0.0.1"), category="Scanners")
    keeper.bookmark(client("10.0.0.2"), QPoint(20, 20))
    assert keeper.box is not None and keeper.box.category.currentText() == "Scanners"


def test_saving_what_is_already_bookmarked_edits_that_bookmark(parts, tmp_path: Path) -> None:
    keeper, *_ = parts
    save(keeper, activity(), note="first")
    keeper.bookmark(activity(), QPoint(20, 20))
    box = keeper.box
    assert box is not None
    assert box.heading.text() == "Edit bookmark"
    assert box.note.text() == "first"
    box.saving.emit(DEFAULT, "second")
    assert [b.note for b in stored(tmp_path).bookmarks] == ["second"]


def test_a_folder_that_cannot_be_written_keeps_the_box_open_and_says_why(
    parts, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keeper, tab, *_ = parts

    def refuse(*_: object) -> None:
        raise PermissionError("Access is denied")

    monkeypatch.setattr(Path, "replace", refuse)
    keeper.bookmark(client("10.0.0.1"), QPoint(20, 20))
    box = keeper.box
    assert box is not None
    box.note.setText("keep this")
    box.saving.emit(DEFAULT, "keep this")

    assert keeper.box is box and box.isVisible()
    assert box.error.text() == "Could not save the bookmark: the case folder cannot be written to."
    assert box.note.text() == "keep this"
    assert tab.count() == 0
    assert not (tmp_path / FILE_NAME).exists()


def test_each_kind_opens_through_the_window(parts) -> None:
    keeper, _tab, opener, _said = parts
    narrowed = TimeWindow(AT, AT.replace(hour=20))
    drafts = [
        client("10.0.0.1"),
        activity(),
        Draft(
            kind=Kind.REQUEST, title="t", said="POST /login", client="192.0.2.23", line=LINE, at=AT
        ),
        Draft(kind=Kind.SEARCH, title="t", said="path:/admin", query="path:/admin"),
        Draft(kind=Kind.SEARCH, title="t", said="status:500", query="status:500", range=narrowed),
    ]
    for draft in drafts:
        save(keeper, draft)
    for bookmark in keeper.shelf.bookmarks:
        keeper.open(bookmark.id)
    assert opener.calls == [
        ("client", "10.0.0.1"),
        ("line", "192.0.2.23", LINE, True, AT),
        ("line", "192.0.2.23", LINE, False, AT),
        ("search", "path:/admin", EVERYTHING),
        ("search", "status:500", narrowed),
    ]


def asked_by(
    monkeypatch: pytest.MonkeyPatch, reply: QMessageBox.StandardButton
) -> list[tuple[str, Qt.TextFormat]]:
    """Answer every question the keeper puts with `reply`, keeping what it said and how."""
    asked: list[tuple[str, Qt.TextFormat]] = []

    def answer(box: QMessageBox) -> QMessageBox.StandardButton:
        asked.append((box.text(), box.textFormat()))
        return reply

    monkeypatch.setattr(bookmark_keeper.QMessageBox, "exec", answer)
    return asked


def test_removing_asks_first(parts, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keeper, tab, *_ = parts
    save(keeper, client("10.0.0.1"))
    ident = keeper.shelf.bookmarks[0].id
    answers = iter([QMessageBox.StandardButton.No, QMessageBox.StandardButton.Yes])
    on_enter: list[QMessageBox.StandardButton] = []

    def answer(box: QMessageBox) -> QMessageBox.StandardButton:
        on_enter.append(box.standardButton(box.defaultButton()))
        return next(answers)

    monkeypatch.setattr(bookmark_keeper.QMessageBox, "exec", answer)
    keeper.remove(ident)
    assert on_enter == [QMessageBox.StandardButton.No], "Enter keeps the bookmark"
    assert len(stored(tmp_path).bookmarks) == 1
    keeper.remove(ident)
    assert stored(tmp_path).bookmarks == ()
    assert tab.count() == 0


def test_a_target_the_case_no_longer_holds_is_gone_once_checked(
    parts, window, tmp_path: Path
) -> None:
    keeper, _tab, opener, _said = parts
    save(keeper, client("10.0.0.1"))
    save(keeper, client("10.0.0.2"))
    save(
        keeper,
        Draft(
            kind=Kind.REQUEST,
            title="t",
            said="x",
            client="10.0.0.1",
            line=EvidenceRef("rotated.log", 4),
            at=AT,
        ),
    )
    keeper.load(tmp_path)
    marks = {b.client or "": b for b in keeper.shelf.bookmarks if b.kind is Kind.CLIENT}
    assert not any(keeper.is_gone(b) for b in keeper.shelf.bookmarks), "unknown is not gone"

    clients, done = opener.checks[-1]
    assert clients == frozenset({"10.0.0.1", "10.0.0.2"})
    done(frozenset({"10.0.0.1"}), frozenset({"excerpt.log"}))

    assert not keeper.is_gone(marks["10.0.0.1"])
    assert keeper.is_gone(marks["10.0.0.2"])
    request = next(b for b in keeper.shelf.bookmarks if b.kind is Kind.REQUEST)
    assert keeper.is_gone(request), "its log file is not one the case names"


def test_an_answer_about_another_case_is_ignored(parts, tmp_path: Path) -> None:
    keeper, _tab, opener, _said = parts
    save(keeper, client("10.0.0.2"))
    keeper.load(tmp_path)
    (saved,) = keeper.shelf.bookmarks
    _clients, stale = opener.checks[-1]
    other = tmp_path / "other"
    other.mkdir()
    keeper.load(other)
    stale(frozenset(), frozenset())
    assert not keeper.is_gone(saved), "an answer for the case left behind changed nothing"


def node(node_id: str, episodes: tuple[str, ...], requests: int) -> GraphNode:
    return GraphNode(
        node_id=node_id,
        label="Credential Attack",
        category=ActivityCategory.AUTHENTICATION,
        severity=Severity.HIGH,
        outcome=Outcome.BLOCKED,
        request_count=requests,
        distinct_paths=1,
        bytes_total=0,
        start=AT,
        end=AT,
        owasp=None,
        top_targets=(),
        rule_ids=(),
        evidence=(),
        evidence_total=requests,
        episode_ids=episodes,
    )


def test_an_activity_bookmark_marks_the_activity_now_holding_its_line(parts) -> None:
    keeper, *_ = parts
    save(keeper, activity(), category="Login attacks", note="the lockout held")
    result = SimpleNamespace(
        client_ip="192.0.2.23",
        assignments=[
            SimpleNamespace(evidence=EvidenceRef("excerpt.log", 2000), episode_id="s1/1"),
            SimpleNamespace(evidence=LINE, episode_id="s1/2"),
        ],
    )
    merged = ActivityGraph(
        GraphKind.BEHAVIOUR, "192.0.2.23", nodes=(node("credential", ("s1/1", "s1/2"), 8),)
    )
    marks = keeper.node_marks(result, merged)  # type: ignore[arg-type]
    assert list(marks) == ["credential"]
    colour, tip = marks["credential"]
    assert colour == keeper.shelf.colour_of("Login attacks")
    assert "the lockout held" in tip
    other = SimpleNamespace(client_ip="10.0.0.9", assignments=result.assignments)
    assert keeper.node_marks(other, merged) == {}  # type: ignore[arg-type]


def test_clients_and_lines_are_marked_from_their_bookmarks(parts) -> None:
    keeper, *_ = parts
    save(keeper, client("192.0.2.23"), category="Scanners", note="older")
    save(keeper, activity(), category="Login attacks", note="newer")
    save(
        keeper,
        Draft(
            kind=Kind.REQUEST,
            title="t",
            said="POST /login",
            client="192.0.2.23",
            line=EvidenceRef("excerpt.log", 2015),
            at=AT,
        ),
        note="that one",
    )
    colour, tip = keeper.client_marks()["192.0.2.23"]
    # The last saved: all three can share a second, and then the order added decides.
    newest = keeper.shelf.bookmarks[-1]
    assert colour == keeper.shelf.colour_of(newest.category)
    assert "older" in tip and "newer" in tip
    assert list(keeper.line_marks("192.0.2.23")) == [EvidenceRef("excerpt.log", 2015)]
    assert keeper.line_marks("10.0.0.9") == {}


def test_categories_are_renamed_and_deleted_through_their_dialog(
    parts, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    keeper, *_ = parts
    save(keeper, client("10.0.0.1"), category="Scanners")
    save(keeper, client("10.0.0.2"), category="Login")
    keeper.manage_categories()
    dialog = keeper.categories_dialog
    assert dialog is not None
    dialog.rename_requested.emit("Scanners", "login")
    assert dialog.error.text() == "There is already a category called Login."
    dialog.rename_requested.emit("Scanners", "Probably scanners")
    assert [c.name for c in stored(tmp_path).categories] == [DEFAULT, "Probably scanners", "Login"]
    asked = asked_by(monkeypatch, QMessageBox.StandardButton.Yes)
    dialog.delete_requested.emit("Login")
    assert asked == [("Move its 1 bookmark to Bookmarked?", Qt.TextFormat.PlainText)]
    assert [c.name for c in stored(tmp_path).categories] == [DEFAULT, "Probably scanners"]
    assert [dialog.names.item(i).text() for i in range(dialog.names.count())] == [
        DEFAULT,
        "Probably scanners",
    ]


def test_an_unreadable_file_is_said_and_set_aside_by_the_next_save(
    window: QWidget, tmp_path: Path
) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{not json")
    tab = BookmarksTab()
    keeper = BookmarkKeeper(window, tab, Opener(), say=lambda _text: None)
    keeper.load(tmp_path)
    assert tab.notice.isVisibleTo(tab)
    assert UNREADABLE_NAME in tab.notice.text()
    save(keeper, client("10.0.0.1"))
    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{not json"
    assert not tab.notice.isVisibleTo(tab)


def test_a_category_change_sets_an_unreadable_file_aside_and_says_so(
    window: QWidget, tmp_path: Path
) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{not json")
    tab = BookmarksTab()
    keeper = BookmarkKeeper(window, tab, Opener(), say=lambda _text: None)
    keeper.load(tmp_path)
    keeper.manage_categories()
    dialog = keeper.categories_dialog
    assert dialog is not None

    dialog.rename_requested.emit(DEFAULT, "Look again")

    assert (tmp_path / UNREADABLE_NAME).read_bytes() == b"{not json"
    assert not tab.notice.isVisibleTo(tab)


def test_no_case_means_an_empty_tab_and_nothing_to_save(window: QWidget) -> None:
    tab = BookmarksTab()
    said: list[str] = []
    keeper = BookmarkKeeper(window, tab, Opener(), say=said.append)
    keeper.load(None)
    keeper.bookmark(client("10.0.0.1"), QPoint(0, 0))
    assert keeper.box is None
    assert tab.count() == 0
    assert said == ["Open a case to bookmark in it."]


def test_renaming_the_category_last_used_keeps_it_last_used(parts) -> None:
    keeper, *_ = parts
    save(keeper, client("10.0.0.1"), category="Scanners")
    keeper.manage_categories()
    dialog = keeper.categories_dialog
    assert dialog is not None
    dialog.rename_requested.emit("Scanners", "Probably scanners")
    keeper.bookmark(client("10.0.0.2"), QPoint(20, 20))
    assert keeper.box is not None
    assert keeper.box.category.currentText() == "Probably scanners"


def test_a_category_name_in_a_question_is_shown_as_typed(
    parts, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A name is the reader's, or came with a case copied from somebody else."""
    keeper, *_ = parts
    save(keeper, client("10.0.0.1"), category="Scanners")
    keeper.manage_categories()
    dialog = keeper.categories_dialog
    assert dialog is not None
    dialog.rename_requested.emit(DEFAULT, "<b>Bold</b> & co")
    asked = asked_by(monkeypatch, QMessageBox.StandardButton.No)

    dialog.delete_requested.emit("Scanners")

    assert asked == [("Move its 1 bookmark to <b>Bold</b> & co?", Qt.TextFormat.PlainText)]


def test_a_change_another_window_made_is_read_when_asked(parts, window, tmp_path: Path) -> None:
    keeper, tab, opener, _said = parts
    other = BookmarkKeeper(window, BookmarksTab(), Opener(), say=lambda _text: None)
    other.load(tmp_path)
    save(other, client("10.0.0.1"), note="from the other window")
    assert keeper.shelf.bookmarks == ()

    keeper.refresh()

    assert [b.note for b in keeper.shelf.bookmarks] == ["from the other window"]
    assert tab.count() == 1
    clients, _done = opener.checks[-1]
    assert clients == frozenset({"10.0.0.1"}), "a client it has not checked is asked about"


def test_a_refresh_keeps_a_box_that_is_open_and_its_save_keeps_both(
    parts, window, tmp_path: Path
) -> None:
    keeper, *_ = parts
    keeper.bookmark(client("10.0.0.2"), QPoint(20, 20))
    other = BookmarkKeeper(window, BookmarksTab(), Opener(), say=lambda _text: None)
    other.load(tmp_path)
    save(other, client("10.0.0.1"))

    keeper.refresh()
    box = keeper.box
    assert box is not None, "the reader's box stays open"
    box.saving.emit(DEFAULT, "")

    assert sorted(b.client for b in stored(tmp_path).bookmarks) == ["10.0.0.1", "10.0.0.2"]


def test_refreshing_a_file_nobody_changed_redraws_nothing(parts) -> None:
    keeper, *_ = parts
    save(keeper, client("10.0.0.1"))
    redrawn: list[bool] = []
    keeper.changed.connect(lambda: redrawn.append(True))

    keeper.refresh()

    assert redrawn == []


def test_a_refresh_drops_the_notice_once_the_unreadable_file_is_gone(
    window: QWidget, tmp_path: Path
) -> None:
    (tmp_path / FILE_NAME).write_bytes(b"{not json")
    tab = BookmarksTab()
    keeper = BookmarkKeeper(window, tab, Opener(), say=lambda _text: None)
    keeper.load(tmp_path)
    (tmp_path / FILE_NAME).unlink()

    keeper.refresh()

    assert not tab.notice.isVisibleTo(tab)
