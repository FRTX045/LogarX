"""The Bookmarks tab: every bookmark in the case, by category, one click from its target.

And the dialog its categories are renamed and deleted in.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime

import pytest
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QTextDocument
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QTreeWidgetItem

from logarc.bookmarks import EMPTY, Bookmark, Kind, Shelf, add, add_category
from logarc.core.evidence import EvidenceRef
from logarc.gui.bookmarks_tab import BookmarksTab, CategoriesDialog

SAVED = datetime(2026, 10, 19, 14, 2, tzinfo=UTC)


def mark(
    ident: str,
    *,
    category: str = "Bookmarked",
    note: str = "",
    hour: int = 14,
    client: str = "192.0.2.23",
    kind: Kind = Kind.CLIENT,
    said: str = "50 requests",
) -> Bookmark:
    line = EvidenceRef("excerpt.log", 2014) if kind in (Kind.ACTIVITY, Kind.REQUEST) else None
    return Bookmark(
        id=ident,
        kind=kind,
        category=category,
        said=said,
        note=note,
        saved=SAVED.replace(hour=hour),
        client=client,
        line=line,
    )


def shelf() -> Shelf:
    marks = [
        mark("old", hour=9, note="first look"),
        mark(
            "login",
            category="Login attacks",
            kind=Kind.ACTIVITY,
            said="Credential Attack \u00b7 6 requests",
            note="the lockout held",
        ),
        mark("new", hour=15, client="10.0.0.9", note="came back"),
    ]
    result = EMPTY
    for item in marks:
        result = add(result, item)
    return result


@pytest.fixture
def tab(qt_app: QApplication) -> BookmarksTab:
    shown = BookmarksTab()
    shown.resize(800, 500)
    shown.show_shelf(shelf(), gone=lambda b: False)
    shown.show()
    QApplication.processEvents()
    return shown


def plain(item: QTreeWidgetItem) -> str:
    document = QTextDocument()
    document.setHtml(item.data(1, Qt.ItemDataRole.UserRole))
    return document.toPlainText()


def layout(tab: BookmarksTab) -> list[tuple[str, list[str]]]:
    tree = tab.tree
    shown = []
    for index in range(tree.topLevelItemCount()):
        top = tree.topLevelItem(index)
        if top is None or top.isHidden():
            continue
        rows = [
            top.child(row).data(0, Qt.ItemDataRole.UserRole)
            for row in range(top.childCount())
            if not top.child(row).isHidden()
        ]
        shown.append((top.text(0), rows))
    return shown


def row(tab: BookmarksTab, ident: str) -> QTreeWidgetItem:
    tree = tab.tree
    for index in range(tree.topLevelItemCount()):
        top = tree.topLevelItem(index)
        for child in range(top.childCount()):
            if top.child(child).data(0, Qt.ItemDataRole.UserRole) == ident:
                return top.child(child)
    raise AssertionError(ident)


def test_bookmarks_are_grouped_by_category_newest_first(tab: BookmarksTab) -> None:
    assert layout(tab) == [("Bookmarked   2", ["new", "old"]), ("Login attacks   1", ["login"])]
    assert tab.count() == 3
    assert tab.caption.text() == "3 bookmarks in 2 categories"


def test_of_two_saved_in_the_same_second_the_later_comes_first(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.show_shelf(
        add(add(EMPTY, mark("first")), mark("second", client="10.0.0.9")), gone=lambda b: False
    )
    assert layout(tab) == [("Bookmarked   2", ["second", "first"])]


def test_a_row_says_what_whose_and_when(tab: BookmarksTab) -> None:
    item = row(tab, "login")
    assert item.text(0) == "Activity"
    assert plain(item) == "Credential Attack \u00b7 6 requests\nthe lockout held"
    assert item.text(2) == "192.0.2.23"
    assert item.text(3) == "19 Oct 14:02"


def test_a_note_with_markup_is_shown_as_text(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.show_shelf(add(EMPTY, mark("x", note="<b>bold</b> & <i>")), gone=lambda b: False)
    assert plain(row(tab, "x")).endswith("<b>bold</b> & <i>")


def test_the_filter_reads_every_field_and_says_how_many_match(tab: BookmarksTab) -> None:
    tab.filter.setText("lockout")
    assert layout(tab) == [("Login attacks   1", ["login"])]
    tab.filter.setText("10.0.0.9")
    assert layout(tab) == [("Bookmarked   1", ["new"])]
    assert tab.caption.text() == "1 of 3 bookmarks match"
    tab.filter.setText("nothing like this")
    assert layout(tab) == []
    assert tab.empty.isVisibleTo(tab)
    assert tab.empty.text() == "No bookmark matches nothing like this."


def test_the_category_choice_narrows_the_list(tab: BookmarksTab) -> None:
    assert [tab.category.itemText(i) for i in range(tab.category.count())] == [
        "All categories",
        "Bookmarked",
        "Login attacks",
    ]
    tab.category.setCurrentText("Login attacks")
    assert layout(tab) == [("Login attacks   1", ["login"])]


def test_a_bookmark_opens_by_double_click_enter_or_the_button(tab: BookmarksTab) -> None:
    opened: list[str] = []
    tab.open_requested.connect(opened.append)
    item = row(tab, "old")
    tab.tree.itemDoubleClicked.emit(item, 1)
    tab.tree.setCurrentItem(item)
    QTest.keyClick(tab.tree, Qt.Key.Key_Return)
    tab.open_button.click()
    assert opened == ["old", "old", "old"]


def test_edit_and_remove_say_which(tab: BookmarksTab) -> None:
    edited: list[str] = []
    removed: list[str] = []
    tab.edit_requested.connect(edited.append)
    tab.remove_requested.connect(removed.append)
    assert not tab.edit_button.isEnabled()
    assert not tab.remove_button.isEnabled()
    tab.tree.setCurrentItem(row(tab, "new"))
    tab.edit_button.click()
    tab.remove_button.click()
    QTest.keyClick(tab.tree, Qt.Key.Key_Delete)
    assert edited == ["new"]
    assert removed == ["new", "new"]


def test_a_heading_cannot_be_opened(tab: BookmarksTab) -> None:
    opened: list[str] = []
    tab.open_requested.connect(opened.append)
    heading = tab.tree.topLevelItem(0)
    tab.tree.itemDoubleClicked.emit(heading, 0)
    assert opened == []
    assert not heading.flags() & Qt.ItemFlag.ItemIsSelectable


def test_a_bookmark_whose_target_is_gone_says_so_and_cannot_open(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.show_shelf(shelf(), gone=lambda b: b.id == "login")
    opened: list[str] = []
    tab.open_requested.connect(opened.append)
    item = row(tab, "login")
    assert "Not found in this case any more." in plain(item)
    tab.tree.setCurrentItem(item)
    assert not tab.open_button.isEnabled()
    assert tab.edit_button.isEnabled()
    assert tab.remove_button.isEnabled()
    tab.tree.itemDoubleClicked.emit(item, 1)
    assert opened == []


def test_an_empty_case_says_how_to_bookmark(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.show_shelf(EMPTY, gone=lambda b: False)
    tab.show()
    assert tab.count() == 0
    assert tab.empty.text() == (
        "No bookmarks yet. Press Ctrl+D on a client, an activity or a log line to save it here."
    )
    assert tab.empty.isVisibleTo(tab)
    assert not tab.tree.isVisibleTo(tab)


def test_a_notice_about_the_file_shows_until_taken_away(tab: BookmarksTab) -> None:
    tab.set_notice("The bookmarks file could not be read.")
    assert tab.notice.isVisibleTo(tab)
    assert tab.notice.text() == "The bookmarks file could not be read."
    tab.set_notice(None)
    assert not tab.notice.isVisibleTo(tab)


def test_rows_grow_to_hold_a_long_note(qt_app: QApplication) -> None:
    tab = BookmarksTab()
    tab.resize(700, 500)
    tab.show_shelf(add(EMPTY, mark("long", note="word " * 80)), gone=lambda b: False)
    tab.show()
    QApplication.processEvents()
    tall = tab.tree.visualItemRect(row(tab, "long")).height()
    tab.show_shelf(add(EMPTY, mark("short", note="")), gone=lambda b: False)
    QApplication.processEvents()
    assert tall > 2 * tab.tree.visualItemRect(row(tab, "short")).height()


# -- categories ----------------------------------------------------------------------------


def test_the_first_category_can_be_renamed_but_not_deleted(qt_app: QApplication) -> None:
    dialog = CategoriesDialog(None, add_category(shelf(), "Empty one"))
    renamed: list[tuple[str, str]] = []
    deleted: list[str] = []
    dialog.rename_requested.connect(lambda old, new: renamed.append((old, new)))
    dialog.delete_requested.connect(deleted.append)
    assert [dialog.names.item(i).text() for i in range(dialog.names.count())] == [
        "Bookmarked",
        "Login attacks",
        "Empty one",
    ]
    dialog.names.setCurrentRow(0)
    assert not dialog.delete_button.isEnabled()
    dialog.new_name.setText("To check")
    dialog.rename_button.click()
    dialog.names.setCurrentRow(2)
    assert dialog.delete_button.isEnabled()
    assert dialog.new_name.text() == "Empty one"
    dialog.delete_button.click()
    assert renamed == [("Bookmarked", "To check")]
    assert deleted == ["Empty one"]
    dialog.show_error("There is already a category called Login attacks.")
    assert dialog.error.text() == "There is already a category called Login attacks."
    dialog.close()


def test_a_narrower_column_makes_a_long_note_take_more_lines(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Measured again when a column changes width, and without raising inside Qt,
    which PyQt answers by ending the process."""
    raised: list[object] = []
    monkeypatch.setattr(sys, "excepthook", lambda *exc: raised.append(exc))
    tab = BookmarksTab()
    tab.resize(900, 500)
    tab.show_shelf(add(EMPTY, mark("long", note="word " * 60)), gone=lambda b: False)
    tab.show()
    QApplication.processEvents()
    wide = tab.tree.visualItemRect(row(tab, "long")).height()

    tab.resize(450, 500)
    QApplication.processEvents()
    QApplication.processEvents()

    assert raised == []
    assert tab.tree.visualItemRect(row(tab, "long")).height() > wide
