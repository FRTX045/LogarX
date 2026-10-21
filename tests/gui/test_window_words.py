"""What the window calls itself and its parts, before and after a case opens."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.case import Case
from logarc.gui.app import MainWindow
from logarc.storage.case import CaseManifest

LINE = '203.0.113.9 - - [10/Mar/2026:10:00:{second:02d} +0000] "GET /{path} HTTP/1.1" 200 512 "-" "Mozilla/5.0"'


@pytest.fixture(scope="module")
def small_case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("words")
    log = root / "access.log"
    log.write_text(
        "\n".join(LINE.format(second=i, path=f"p{i}") for i in range(5)) + "\n", encoding="utf-8"
    )
    with Case.create(root / "case") as case:
        case.ingest([log])
    return root / "case"


def test_a_window_with_no_case_is_called_logarc(qt_app: QApplication) -> None:
    window = MainWindow()

    assert window.windowTitle() == "logarc"
    assert window._status.text() == "No case open"
    window.close()


def test_the_workspace_tabs_are_short_and_explain_themselves_on_hover(
    qt_app: QApplication,
) -> None:
    window = MainWindow()
    tabs = window._workspace

    assert [tabs.tabText(i) for i in range(tabs.count())] == ["Triage", "Activity", "Bookmarks"]
    assert all(tabs.tabToolTip(i) for i in range(tabs.count()))
    window.close()


def test_the_graph_key_is_called_the_legend(qt_app: QApplication) -> None:
    window = MainWindow()

    assert window._graph_key.button.text() == "Legend"
    window.close()


def test_the_title_names_the_open_case(qt_app: QApplication, small_case: Path) -> None:
    window = MainWindow()
    window._load_case(small_case)
    settled(qt_app)

    name = CaseManifest.load(small_case).case_id
    assert window.windowTitle() == f"{name} — logarc"
    window.close()


def test_a_case_that_fails_to_open_takes_its_name_off_the_title(
    qt_app: QApplication, small_case: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    window._load_case(small_case)
    settled(qt_app)
    monkeypatch.setattr(window, "report_error", lambda *_args, **_kwargs: None)

    window._load_case(tmp_path / "not-a-case")
    settled(qt_app)

    assert window.windowTitle() == "logarc"
    window.close()


def test_trace_and_behaviour_sit_beside_the_client_they_describe(
    qt_app: QApplication, small_case: Path
) -> None:
    """One row, address on the left and the switch on the right, drawn as one
    segmented control rather than a second row of tabs above the heading."""
    window = MainWindow()
    window.resize(1400, 880)
    window.show()
    window._load_case(small_case)
    settled(qt_app)
    window._reconstruct("203.0.113.9")
    settled(qt_app)

    heading = window._heading.mapTo(window, window._heading.rect().center())
    switch = window._tabs.mapTo(window, window._tabs.rect().center())
    assert window._tabs.isVisible()
    assert abs(heading.y() - switch.y()) <= 12
    assert switch.x() > heading.x()
    assert ":first" in window._tabs.styleSheet()
    assert ":last" in window._tabs.styleSheet()
    window.close()


def test_the_activity_metadata_is_called_details(qt_app: QApplication) -> None:
    from logarc.gui.evidence_panel import EvidencePanel

    panel = EvidencePanel()

    assert panel.activity_details.button.text() == "Details"
    panel.close()


def test_the_categories_dialog_says_its_rule_on_the_delete_button(qt_app: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel

    from logarc.bookmarks import EMPTY
    from logarc.gui.bookmarks_tab import CategoriesDialog

    dialog = CategoriesDialog(None, EMPTY)

    assert not [w for w in dialog.findChildren(QLabel) if w.text().startswith("Deleting")]
    assert "first one" in dialog.delete_button.toolTip()
    dialog.close()


def test_the_bookmark_box_explains_new_categories_on_hover(qt_app: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel, QWidget

    from logarc.gui.bookmark_box import BookmarkBox

    host = QWidget()
    box = BookmarkBox(
        host,
        title="Bookmark this client",
        said="",
        client=None,
        categories=["Bookmarked"],
        category="Bookmarked",
    )

    assert not [w for w in box.findChildren(QLabel) if w.text().startswith("Type a new name")]
    assert "new category" in box.category.toolTip()
    assert box.save.property("primary") is True
    assert box.save.styleSheet() == ""
    box.close()


def test_the_canvas_and_the_notice_use_the_new_words() -> None:
    from logarc.gui.canvas import STARTUP_MESSAGE, WAITING_MESSAGE

    assert STARTUP_MESSAGE == "Open a case, or start a new one from log files."
    assert WAITING_MESSAGE == "Select a client."


def test_a_narrow_graph_column_never_cuts_the_view_switch(
    qt_app: QApplication, small_case: Path
) -> None:
    """Dragging the evidence column wider squeezes the graph's. The heading
    gives way, onto a second line, and the switch keeps both its words: it
    once lost "Behaviour" to two scroll arrows."""
    from PyQt6.QtWidgets import QSplitter

    window = MainWindow()
    window.resize(1400, 880)
    window.show()
    window._load_case(small_case)
    settled(qt_app)
    window._reconstruct("203.0.113.9")
    settled(qt_app)
    columns = window._evidence.parentWidget()
    while not (isinstance(columns, QSplitter) and columns.count() == 3):
        columns = columns.parentWidget()
    left, centre, right = columns.sizes()
    columns.setSizes([left, 360, right + centre - 360])
    settled(qt_app)

    assert window._tabs.width() >= window._tabs.sizeHint().width()
    heading = window._heading
    assert heading.geometry().right() < window._tabs.geometry().left()
    assert heading.width() >= heading.minimumSizeHint().width(), "no word is cut off"
    assert heading.height() >= heading.heightForWidth(heading.width()), "every line shows"
    assert columns.sizes()[1] <= 500, "the graph column can be dragged narrow"
    assert len(_wrapped(heading, heading.contentsRect().width())) > 1, "premise: it wrapped"
    # And at any width the column could be dragged to, not only this one.
    for width in range(80, 420, 4):
        for line in _wrapped(heading, width):
            noun = line.lstrip().startswith(("request", "session", "activit"))
            assert not noun, f"a count split from its number at {width}px: {line!r}"
    window.close()


def _wrapped(label, width: int) -> list[str]:
    """The lines `label`'s text breaks into at `width`."""
    from PyQt6.QtGui import QTextDocument

    document = QTextDocument()
    document.setDefaultFont(label.font())
    document.setDocumentMargin(0)
    document.setHtml(label.text())
    document.setTextWidth(width)
    document.size()  # laid out on demand
    block = document.firstBlock()
    layout = block.layout()
    text = block.text()
    return [
        text[line.textStart() : line.textStart() + line.textLength()]
        for line in (layout.lineAt(i) for i in range(layout.lineCount()))
    ]
