"""Where things are in the menu bar, and what the preferences dialog does.

The View menu held four different kinds of thing in eleven entries: two view
switches, four one-off actions, four preferences, and one setting that decided
nothing about the view at all — it decided what happened when the application
opened. This is where that separation is held in place.

Run without a display.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QDialog, QMenu

from logarx.gui import prefs
from logarx.gui.app import MainWindow
from logarx.gui.density import Density
from logarx.gui.preferences import PreferencesDialog


def _menu(window: MainWindow, name: str) -> QMenu:
    bar = window.menuBar()
    assert bar is not None
    for action in bar.actions():
        if action.text().replace("&", "") == name:
            menu = action.menu()
            assert menu is not None, f"{name} is not a menu"
            return menu
    raise AssertionError(f"there is no {name} menu")


def _entries(menu: QMenu) -> list[str]:
    return [
        action.text().replace("&", "")
        for action in menu.actions()
        if not action.isSeparator() and action.text()
    ]


def _everywhere(window: MainWindow) -> list[QAction]:
    bar = window.menuBar()
    assert bar is not None
    found: list[QAction] = []
    for top in bar.actions():
        menu = top.menu()
        if menu is None:
            continue
        for action in menu.actions():
            found.append(action)
            deeper = action.menu()
            if deeper is not None:
                found.extend(deeper.actions())
    return found


# -- where things are ------------------------------------------------------


def test_the_view_menu_holds_only_what_is_shown(qt_app: QApplication) -> None:
    """View controls what is shown, including a quick timeline toggle.

    `Full screen` belongs here on the same test every other entry passes: it
    decides what is on screen and nothing else. It is not a preference — it is
    not remembered, and it describes this moment rather than how the reader
    likes to work. `Reset panel sizes` passes it too: it puts the panels that
    show things back where they started.
    """
    window = MainWindow()

    assert _entries(_menu(window, "View")) == [
        "Trace",
        "Behaviour",
        "Timeline",
        "Fit to window",
        "Zoom in",
        "Zoom out",
        "Reset zoom",
        "Reset panel sizes",
        "Full screen",
    ]
    window.close()


def test_other_preferences_stay_in_the_dialog(qt_app: QApplication) -> None:
    """The timeline has a quick toggle; the remaining preferences live in the dialog."""
    window = MainWindow()
    labels = {action.text().replace("&", "") for action in _everywhere(window)}

    for setting in prefs.EVERY:
        assert setting.label not in labels, f"{setting.label} is still in a menu"
    assert "Band detail" not in labels
    window.close()


def test_timeline_menu_choice_is_remembered_and_leaves_date_fields(qt_app: QApplication) -> None:
    first = MainWindow()
    first.show()
    qt_app.processEvents()
    assert first._timeline_action.isChecked()
    first._timeline_action.trigger()
    assert first._time_filter._band.isHidden()
    assert first._time_filter._from.isVisible()
    assert first._time_filter._to.isVisible()
    assert first._time_filter._clear.isVisible()
    first.close()

    second = MainWindow()
    assert not second._timeline_action.isChecked()
    assert second._time_filter._band.isHidden()
    second._timeline_action.trigger()
    assert not second._time_filter._band.isHidden()
    second.close()

    third = MainWindow()
    assert third._timeline_action.isChecked()
    assert not third._time_filter._band.isHidden()
    third.close()


def test_the_edit_menu_holds_what_is_done_to_the_graph(qt_app: QApplication) -> None:
    window = MainWindow()

    assert _entries(_menu(window, "Edit")) == [
        "Undo move",
        "Save layout",
        "Reset layout",
        "Bookmark…",
        "Preferences…",
    ]
    window.close()


def test_the_case_menu_reads_like_every_other_application(qt_app: QApplication) -> None:
    """New before Open, short names; what each does is on the status tip."""
    window = MainWindow()

    assert _entries(_menu(window, "Case")) == [
        "New from logs…",
        "Open…",
        "Open recent…",
        "Formats and rules…",
        "Run CRS scan",
        "Exit",
    ]
    window.close()


def test_exit_shows_no_shortcut(qt_app: QApplication) -> None:
    """`StandardKey.Quit` has no binding on Windows and renders as the word
    "Exit", so the menu read "Exit    Exit"."""
    window = MainWindow()
    (leave,) = [a for a in _menu(window, "Case").actions() if a.text() == "E&xit"]

    assert leave.shortcut().isEmpty()
    window.close()


def test_export_names_the_file_each_entry_writes(qt_app: QApplication) -> None:
    window = MainWindow()

    assert _entries(_menu(window, "Export")) == [
        "Report (HTML)…",
        "Graph (JSON)…",
        "Image (PNG)…",
        "Bookmarks (CSV)…",
    ]
    window.close()


def test_there_is_a_help_menu(qt_app: QApplication) -> None:
    window = MainWindow()

    assert _entries(_menu(window, "Help")) == ["User guide", "Keyboard shortcuts", "About LogarX"]
    window.close()


def test_trace_and_behaviour_are_one_choice(qt_app: QApplication) -> None:
    """Shown as a pair of radio entries, because exactly one is ever in force."""
    window = MainWindow()
    group = window._trace_action.actionGroup()

    assert group is not None
    assert group is window._behaviour_action.actionGroup()
    assert group.isExclusive()
    window.close()


def test_bookmarking_is_ctrl_d_and_is_offered_where_it_is_used(qt_app: QApplication) -> None:
    """Ctrl+D on the window itself, so it answers in full screen with no menu bar."""
    window = MainWindow()

    assert window._bookmark_action.shortcut().toString() == "Ctrl+D"
    assert window._bookmark_action in window.actions()
    # After Rename session… and its separator.
    assert window._canvas.actions()[2].text() == "Bookmark this activity…"
    assert window._canvas.actions()[2].shortcut().isEmpty(), "Ctrl+D is the Edit menu's"
    assert _entries(_menu(window, "Export"))[-1] == "Bookmarks (CSV)…"
    window.close()


def test_the_startup_setting_is_not_in_the_view_menu(qt_app: QApplication) -> None:
    """It was, and it decided nothing about the view. It decided what happened
    when the application opened."""
    window = MainWindow()

    assert "Reopen the last case on start" not in _entries(_menu(window, "View"))
    window.close()


# -- nothing a reader had learned changes ---------------------------------


def test_every_shortcut_still_reaches_the_same_entry(qt_app: QApplication) -> None:
    """Moving an entry to another menu must not move its shortcut. These are
    what a reader's hands know, and relearning them is the cost of a tidy-up
    nobody asked to pay."""
    window = MainWindow()
    reachable = {
        action.shortcut().toString(): action.text().replace("&", "")
        for action in _everywhere(window)
        if not action.shortcut().isEmpty()
    }

    assert reachable["Ctrl+Z"] == "Undo move"
    assert reachable["Ctrl+S"] == "Save layout"
    assert reachable["Ctrl+Shift+R"] == "Reset layout"
    assert reachable["Ctrl+O"] == "Open…"
    assert reachable["Ctrl+Shift+O"] == "Open recent…"
    assert reachable["Ctrl+N"] == "New from logs…"
    assert reachable["F1"] == "User guide"
    window.close()


def test_preferences_has_the_shortcut_every_application_uses(qt_app: QApplication) -> None:
    window = MainWindow()
    shortcuts = {
        action.text().replace("&", ""): action.shortcut().toString()
        for action in _everywhere(window)
    }

    assert shortcuts["Preferences…"] == "Ctrl+,"
    window.close()


# -- and what the dialog does ---------------------------------------------


def _answer(monkeypatch: pytest.MonkeyPatch, code: QDialog.DialogCode, **changes: object) -> None:
    """Open the dialog, set these, and close it with `code` — without a modal.

    Patched on the dialog rather than on the window, so what is under test is
    still the window asking for it and reading the answer back.
    """

    def opened(dialog: PreferencesDialog) -> int:
        for key, value in changes.items():
            control = dialog._controls[key]
            if hasattr(control, "setCurrentIndex"):
                control.setCurrentIndex(control.findData(value))
            else:
                control.setChecked(bool(value))
        return int(code.value)

    monkeypatch.setattr(PreferencesDialog, "exec", opened)


def test_saying_ok_applies_every_setting_at_once(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    assert window._canvas.wrap, "premise: wrapping starts on"
    assert window._density is Density.FINE, "premise: the band starts fine"
    assert window._canvas.sessions, "premise: session boxes start on"

    _answer(
        monkeypatch,
        QDialog.DialogCode.Accepted,
        **{
            "view/wrap_traces": False,
            "view/session_boxes": False,
            "view/band_density": Density.COARSE,
            "view/traffic_band": False,
            "view/decode_targets": False,
            "cases/reopen_last": True,
        },
    )
    window._show_preferences()

    assert window._canvas.wrap is False
    assert window._canvas.sessions is False
    assert window._density is Density.COARSE
    assert window._time_filter._band.isHidden()
    assert window._evidence._decode is False
    window.close()


def test_saying_ok_writes_them_down(qt_app: QApplication, monkeypatch: pytest.MonkeyPatch) -> None:
    """A preference that does not survive the launch is not a preference."""
    first = MainWindow()
    _answer(monkeypatch, QDialog.DialogCode.Accepted, **{"view/wrap_traces": False})
    first._show_preferences()
    first.close()

    second = MainWindow()

    assert second._canvas.wrap is False
    second.close()


def test_the_session_boxes_choice_is_remembered(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = MainWindow()
    _answer(monkeypatch, QDialog.DialogCode.Accepted, **{"view/session_boxes": False})
    first._show_preferences()
    first.close()

    second = MainWindow()

    assert second._canvas.sessions is False
    second.close()


def test_saying_cancel_changes_nothing_at_all(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole reason the dialog applies nothing while it is open: there is
    then nothing to undo, and Cancel cannot half-work."""
    window = MainWindow()

    _answer(
        monkeypatch,
        QDialog.DialogCode.Rejected,
        **{"view/wrap_traces": False, "view/band_density": Density.COARSE},
    )
    window._show_preferences()

    assert window._canvas.wrap is True
    assert window._density is Density.FINE
    window.close()


def test_the_dialog_opens_showing_what_is_in_force(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opened showing defaults instead, a second visit would offer to undo the
    first without saying so."""
    window = MainWindow()
    _answer(monkeypatch, QDialog.DialogCode.Accepted, **{"view/wrap_traces": False})
    window._show_preferences()

    seen: list[bool] = []

    def look(dialog: PreferencesDialog) -> int:
        seen.append(dialog._controls["view/wrap_traces"].isChecked())
        return int(QDialog.DialogCode.Rejected.value)

    monkeypatch.setattr(PreferencesDialog, "exec", look)
    window._show_preferences()

    assert seen == [False]
    window.close()


def test_timeline_menu_and_preferences_use_the_same_choice(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = MainWindow()
    window._timeline_action.trigger()

    def look(dialog: PreferencesDialog) -> int:
        assert not dialog._controls["view/traffic_band"].isChecked()
        dialog._controls["view/traffic_band"].setChecked(True)
        return int(QDialog.DialogCode.Accepted.value)

    monkeypatch.setattr(PreferencesDialog, "exec", look)
    window._show_preferences()
    assert window._timeline_action.isChecked()
    assert not window._time_filter._band.isHidden()

    _answer(monkeypatch, QDialog.DialogCode.Accepted, **{"view/traffic_band": False})
    window._show_preferences()
    assert not window._timeline_action.isChecked()
    assert window._time_filter._band.isHidden()
    window.close()


# -- the same actions, on the canvas ---------------------------------------


def test_the_canvas_offers_the_arrangement_actions_on_a_right_click(
    qt_app: QApplication,
) -> None:
    """Qt builds the menu from the widget's own actions, so these are the very
    same objects the Edit menu carries - not copies that could drift from it.
    """
    window = MainWindow()

    assert window._canvas.contextMenuPolicy() == Qt.ContextMenuPolicy.ActionsContextMenu
    on_canvas = window._canvas.actions()

    assert window._save_layout_action in on_canvas
    assert window._undo_action in on_canvas
    assert window._reset_layout_action in on_canvas
    assert window._fit_action in on_canvas
    window.close()


def test_a_dead_menu_entry_is_dead_on_the_canvas_too(qt_app: QApplication) -> None:
    """Because it is the same action, not a copy of one.

    A right-click that offered to save an arrangement with no graph on the
    canvas would be offering nothing, and a control that does nothing reads as
    a fault in the tool.
    """
    window = MainWindow()
    window._arrangements_kept.refresh()

    assert not window._save_layout_action.isEnabled(), "premise: no graph, nothing to save"
    assert window._save_layout_action in window._canvas.actions()
    window.close()


def test_the_canvas_menu_keeps_the_shortcuts_the_menu_bar_shows(
    qt_app: QApplication,
) -> None:
    """The right-click is also where the shortcut is learned. Rebuilt by hand
    as plain entries, they would carry no shortcut and teach nothing.
    """
    window = MainWindow()

    for action in (window._save_layout_action, window._undo_action, window._reset_layout_action):
        assert not action.shortcut().isEmpty(), f"{action.text()} lost its shortcut"
    window.close()
