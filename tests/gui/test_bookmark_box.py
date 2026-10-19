"""The box a bookmark is saved and edited in.

It says what is being saved, takes a category (an existing one, or a new name
typed in) and a note, and hands them over on Enter. It never closes itself: the
window closes it once the bookmark is written, and says why when it cannot be.
"""

from __future__ import annotations

import pytest
from PyQt6.QtCore import QPoint, QRect, Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QDialog, QWidget

from logarc.bookmarks import NAME_LIMIT, NOTE_LIMIT
from logarc.gui.bookmark_box import BookmarkBox


@pytest.fixture
def window(qt_app: QApplication) -> QWidget:
    shown = QWidget()
    shown.resize(800, 600)
    shown.show()
    QApplication.processEvents()
    return shown


def box_on(window: QWidget, **kwargs: object) -> BookmarkBox:
    fields: dict[str, object] = {
        "title": "Bookmark this activity",
        "said": "Credential Attack \N{MIDDLE DOT} 6 requests",
        "client": "192.0.2.23",
        "categories": ["Bookmarked", "Login attacks"],
        "category": "Login attacks",
    }
    fields.update(kwargs)
    box = BookmarkBox(window, **fields)  # type: ignore[arg-type]
    box.show()
    QApplication.processEvents()
    return box


def saved(box: BookmarkBox) -> list[tuple[str, str]]:
    heard: list[tuple[str, str]] = []
    box.saving.connect(lambda category, note: heard.append((category, note)))
    return heard


def test_it_says_what_is_being_saved_and_where(window: QWidget) -> None:
    box = box_on(window, note="first look")
    assert box.heading.text() == "Bookmark this activity"
    assert box.said.text() == "Credential Attack \N{MIDDLE DOT} 6 requests"
    assert box.client.text() == "192.0.2.23" and box.client.isVisibleTo(box)
    assert box.category.currentText() == "Login attacks"
    assert [box.category.itemText(i) for i in range(box.category.count())] == [
        "Bookmarked",
        "Login attacks",
    ]
    assert box.note.text() == "first look"
    assert box.note.maxLength() == NOTE_LIMIT


def test_a_search_has_no_client_line(window: QWidget) -> None:
    box = box_on(window, client=None)
    assert not box.client.isVisibleTo(box)


def test_what_it_says_is_shown_as_text_never_markup(window: QWidget) -> None:
    box = box_on(window, said="GET /<b>bold</b>")
    assert box.said.textFormat() == Qt.TextFormat.PlainText
    assert box.said.text() == "GET /<b>bold</b>"


def test_enter_hands_over_the_category_and_note_once_and_stays_open(window: QWidget) -> None:
    box = box_on(window)
    heard = saved(box)
    box.note.setText("  the lockout held  ")
    QTest.keyClick(box.note, Qt.Key.Key_Return)
    assert heard == [("Login attacks", "the lockout held")]
    assert box.isVisible()


def test_a_new_name_typed_as_the_category_is_handed_over_tidied(window: QWidget) -> None:
    box = box_on(window)
    heard = saved(box)
    box.category.setEditText("  Check   with the web team ")
    edit = box.category.lineEdit()
    assert edit is not None
    QTest.keyClick(edit, Qt.Key.Key_Return)
    assert heard == [("Check with the web team", "")]
    assert box.category.count() == 2, "typing a name does not add it before it is saved"


@pytest.mark.parametrize(
    ("name", "said"),
    [
        ("   ", "A category needs a name."),
        ("x" * (NAME_LIMIT + 1), f"A category name is at most {NAME_LIMIT} characters."),
    ],
)
def test_a_name_that_cannot_be_used_is_refused_in_the_box(
    window: QWidget, name: str, said: str
) -> None:
    box = box_on(window)
    heard = saved(box)
    box.category.setEditText(name)
    box.save.click()
    assert heard == []
    assert box.error.isVisibleTo(box) and box.error.text() == said


def test_an_error_from_saving_keeps_the_box_open_and_says_why(window: QWidget) -> None:
    box = box_on(window)
    box.show_error("Could not save the bookmark: the case folder cannot be written to.")
    assert box.isVisible()
    assert box.error.isVisibleTo(box)
    assert box.error.textFormat() == Qt.TextFormat.PlainText


def test_escape_cancels(window: QWidget) -> None:
    box = box_on(window)
    heard = saved(box)
    QTest.keyClick(box.note, Qt.Key.Key_Escape)
    assert heard == []
    assert box.result() == QDialog.DialogCode.Rejected


def test_it_opens_inside_the_window_even_at_its_right_edge(window: QWidget) -> None:
    box = box_on(window)
    box.place(QPoint(window.width() - 10, 40))
    QApplication.processEvents()
    inside = QRect(window.mapToGlobal(QPoint(0, 0)), window.size())
    assert inside.contains(box.frameGeometry()), (inside, box.frameGeometry())
