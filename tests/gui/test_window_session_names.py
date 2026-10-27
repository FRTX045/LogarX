"""Renaming a session from the window: the menu, the double-click, the file, and reopening.

One client with two visits two hours apart, opened the way a reader opens it.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from on_canvas import box_name, has_pencil, session_boxes
from PyQt6.QtCore import QPointF, Qt
from PyQt6.QtGui import QContextMenuEvent
from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarx.analysis import analyse_ip
from logarx.case import Case
from logarx.core.window import TimeWindow
from logarx.gui.app import MainWindow
from logarx.gui.canvas import ActivityCanvas
from logarx.gui.session_name_keeper import SessionNameKeeper
from logarx.session_names import FILE_NAME, SessionKey, load

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
CLIENT = "10.0.0.9"
FIRST = f"{CLIENT}#1"
SECOND = f"{CLIENT}#2"


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    agent = "Mozilla/5.0 (X11; Linux x86_64)"
    lines = [
        f"{CLIENT} - - [{(START + timedelta(seconds=at)):%d/%b/%Y:%H:%M:%S +0000}]"
        f' "GET /page/{at} HTTP/1.1" 200 512 "-" "{agent}"'
        for at in (0, 20, 40, 7_200, 7_220)
    ]
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return tmp_path / "case"


def opened(qt_app: QApplication, case_dir: Path) -> MainWindow:
    window = MainWindow()
    window.resize(1200, 800)
    window.show()
    window._load_case(case_dir)
    settled(qt_app)
    window._clients._table.selectRow(0)
    settled(qt_app)
    assert window._result is not None, "premise: the client is being read"
    assert len(session_boxes(window._canvas)) == 2, "premise: two visits, two boxes"
    return window


def key_of(window: MainWindow, index: int) -> SessionKey:
    assert window._result is not None
    return SessionKey(CLIENT, window._result.sessions[index].events[0].evidence)


def rename_through_the_window(window: MainWindow, session_id: str, name: str) -> None:
    window._session_names.rename(session_id)
    dialog = window._session_names.dialog
    assert dialog is not None and dialog.isVisible()
    dialog.field.setText(name)
    dialog.rename_button.click()


def open_menu_at(canvas: ActivityCanvas, spot: QPointF) -> None:
    canvas.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
    at = canvas.mapFromScene(spot)
    QApplication.sendEvent(
        canvas.viewport(),
        QContextMenuEvent(QContextMenuEvent.Reason.Mouse, at, canvas.viewport().mapToGlobal(at)),
    )


def test_renaming_writes_the_file_and_heads_the_box(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    rename_through_the_window(window, FIRST, "Mine")

    assert load(case_dir).names.name_for(key_of(window, 0)) == "Mine"
    first, second = session_boxes(window._canvas)
    assert (box_name(first), has_pencil(first)) == ("Mine", True)
    assert has_pencil(second) is False
    assert window._session_names.dialog is not None
    assert not window._session_names.dialog.isVisible()
    window.close()


def test_the_name_comes_back_when_the_case_is_opened_again(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    rename_through_the_window(window, SECOND, "Came back later")
    window.close()

    again = opened(qt_app, case_dir)

    second = session_boxes(again._canvas)[1]
    assert (box_name(second), has_pencil(second)) == ("Came back later", True)
    again.close()


def test_use_logarxs_name_takes_the_name_and_pencil_away(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    logarx_name = box_name(session_boxes(window._canvas)[0])
    rename_through_the_window(window, FIRST, "Mine")

    window._session_names.rename(FIRST)
    dialog = window._session_names.dialog
    assert dialog is not None
    assert dialog.field.text() == "Mine"
    dialog.reset_button.click()

    first = session_boxes(window._canvas)[0]
    assert (box_name(first), has_pencil(first)) == (logarx_name, False)
    assert load(case_dir).names.name_for(key_of(window, 0)) is None
    window.close()


def test_the_menu_entry_is_live_inside_a_box_and_greyed_outside(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    canvas = window._canvas
    entry = window._rename_session_action
    assert canvas.actions()[0] is entry
    assert entry.text() == "Rename session…"
    assert canvas.actions()[1].isSeparator()

    inside = session_boxes(canvas)[1].label.sceneBoundingRect().center()
    canvas.centerOn(inside)
    open_menu_at(canvas, inside)
    assert entry.isEnabled()

    outline = session_boxes(canvas)[0].shape.sceneBoundingRect()
    outside = QPointF(outline.left() - 40, outline.top() - 40)
    canvas.centerOn(outside)
    open_menu_at(canvas, outside)
    assert not entry.isEnabled()
    window.close()


def test_the_menu_entry_renames_the_session_it_was_opened_over(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    canvas = window._canvas
    inside = session_boxes(canvas)[1].label.sceneBoundingRect().center()
    canvas.centerOn(inside)
    open_menu_at(canvas, inside)

    window._rename_session_action.trigger()

    dialog = window._session_names.dialog
    assert dialog is not None and dialog.isVisible()
    assert dialog.place.text().startswith("Session 2 of 2 · ")
    dialog.close()
    window.close()


def test_double_clicking_a_heading_opens_the_window(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)

    window._canvas.rename_requested.emit(FIRST)

    dialog = window._session_names.dialog
    assert dialog is not None and dialog.isVisible()
    assert dialog.place.text().startswith("Session 1 of 2 · ")
    assert dialog.note.text() == f"LogarX's name: {box_name(session_boxes(window._canvas)[0])}"
    dialog.close()
    window.close()


def test_behaviour_and_back_keeps_the_name(qt_app: QApplication, case_dir: Path) -> None:
    window = opened(qt_app, case_dir)
    rename_through_the_window(window, FIRST, "Mine")

    window._show_behaviour()
    assert session_boxes(window._canvas) == []
    window._show_trace()

    first = session_boxes(window._canvas)[0]
    assert (box_name(first), has_pencil(first)) == ("Mine", True)
    window.close()


def test_an_unreadable_file_shows_logarxs_names_and_says_so_once(
    qt_app: QApplication, case_dir: Path
) -> None:
    (case_dir / FILE_NAME).write_bytes(b"{oops")

    window = opened(qt_app, case_dir)
    # Said on the next turn of the event loop, after the window has said what it
    # read: said during the draw, that line wrote straight over it.
    assert window._status.text() == "10.0.0.9: 2 activities", "premise: the window spoke last"
    qt_app.processEvents()

    assert not any(has_pencil(box) for box in session_boxes(window._canvas))
    assert window._status.text().startswith(
        "The session names file in this case could not be read ("
    )
    assert window._status.text().endswith(
        "), so LogarX's names are shown. It is kept as it is; the next rename sets it aside"
        " as session-names.unreadable.json."
    )
    said: list[str] = []
    window._session_names._say = said.append
    window._show_behaviour()
    window._show_trace()
    qt_app.processEvents()
    assert said == []
    window.close()


def test_a_filter_that_cuts_the_first_request_shows_logarxs_name(
    qt_app: QApplication, case_dir: Path
) -> None:
    window = opened(qt_app, case_dir)
    rename_through_the_window(window, FIRST, "Mine")
    window.close()

    with Case.open(case_dir) as case:
        whole = analyse_ip(case.store, CLIENT)
        cut = analyse_ip(case.store, CLIENT, window=TimeWindow(start=START + timedelta(seconds=10)))
    canvas = ActivityCanvas()
    said: list[str] = []

    def names_with(result: object) -> dict[str, str]:
        keeper = SessionNameKeeper(
            canvas=canvas,
            parent=canvas,
            case_path=lambda: case_dir,
            result=lambda: result,  # type: ignore[arg-type,return-value]
            say=said.append,
        )
        return keeper.names_for_drawing()

    assert names_with(cut) == {}
    assert names_with(whole) == {FIRST: "Mine"}
    assert said == []


def test_a_refused_folder_leaves_the_heading_as_it_was(
    qt_app: QApplication, case_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = opened(qt_app, case_dir)
    logarx_name = box_name(session_boxes(window._canvas)[0])

    def refuse(*_: object) -> None:
        raise PermissionError("Access is denied")

    monkeypatch.setattr(Path, "replace", refuse)
    rename_through_the_window(window, FIRST, "Mine")

    dialog = window._session_names.dialog
    assert dialog is not None and dialog.isVisible()
    assert dialog.error.text() == "Could not save the name: the case folder cannot be written to."
    first = session_boxes(window._canvas)[0]
    assert (box_name(first), has_pencil(first)) == (logarx_name, False)
    dialog.close()
    window.close()


def test_a_name_given_under_a_filter_survives_clearing_it(
    qt_app: QApplication, case_dir: Path
) -> None:
    """Named while a filter clips the visit's first request, the name is keyed on
    the clipped session's first line, which the whole visit still holds."""
    with Case.open(case_dir) as case:
        whole = analyse_ip(case.store, CLIENT)
        cut = analyse_ip(case.store, CLIENT, window=TimeWindow(start=START + timedelta(seconds=10)))
    canvas = ActivityCanvas()
    showing = {"result": cut}
    keeper = SessionNameKeeper(
        canvas=canvas,
        parent=canvas,
        case_path=lambda: case_dir,
        result=lambda: showing["result"],
        say=lambda _: None,
    )
    keeper.rename(cut.sessions[0].session_id)
    assert keeper.dialog is not None
    keeper.dialog.field.setText("Named under a filter")
    keeper.dialog.rename_button.click()
    assert keeper.names_for_drawing() == {cut.sessions[0].session_id: "Named under a filter"}

    showing["result"] = whole

    assert keeper.names_for_drawing() == {FIRST: "Named under a filter"}
