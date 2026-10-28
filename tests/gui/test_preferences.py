"""The preferences dialog: what it shows, and what it hands back.

Run without a display. What is checked is the shape and the answer — that every
setting in the catalogue is drawn, that the reader's changes come back, and
that nothing at all happens until they say OK.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialogButtonBox,
    QLabel,
    QTabWidget,
)

from logarx.core.activity import ActivityCategory
from logarx.gui import prefs
from logarx.gui._qt import required
from logarx.gui.density import Density
from logarx.gui.folding import FoldRule
from logarx.gui.icon_grid import KindIconGrid
from logarx.gui.icon_set import KIND_NAMES
from logarx.gui.icons import first_drawable
from logarx.gui.preferences import PreferencesDialog
from logarx.gui.theme import ui_font
from logarx.style import THEME


def _opened(values: dict[str, bool | Density] | None = None) -> PreferencesDialog:
    return PreferencesDialog(values or prefs.defaults())


# -- what it draws ---------------------------------------------------------


def test_every_setting_in_the_catalogue_gets_a_control(qt_app: QApplication) -> None:
    """A setting the dialog does not draw is reachable only by editing the
    settings file by hand. Built from the catalogue rather than written out,
    so adding one and forgetting it is not possible — this test says so."""
    dialog = _opened()

    assert set(dialog._controls) == {setting.key for setting in prefs.EVERY}


def test_a_switch_is_a_checkbox_and_a_choice_is_a_list(qt_app: QApplication) -> None:
    dialog = _opened()

    assert isinstance(dialog._controls["view/wrap_traces"], QCheckBox)
    assert isinstance(dialog._controls["view/band_density"], QComboBox)


def test_the_groups_are_tabs_in_order(qt_app: QApplication) -> None:
    """The shape the reader picked on 2026-10-21: three tabs, each with
    something on it. (It was one page of five boxes before that.)"""
    dialog = _opened()

    tabs = dialog.findChild(QTabWidget)
    assert tabs is not None
    assert [tabs.tabText(i) for i in range(tabs.count())] == list(prefs.GROUPS)
    assert list(prefs.GROUPS) == ["General", "Graph", "Evidence"]


def test_every_setting_explains_itself_on_hover(qt_app: QApplication) -> None:
    """The notes the menu carried as status tips, now where the pointer rests.
    There is no switch to show them: hover is how every other application does
    it, and a switch for help was one more thing to learn."""
    dialog = _opened()

    assert not hasattr(dialog, "explanations")
    for setting in prefs.EVERY:
        assert dialog._controls[setting.key].toolTip() == setting.note


def test_switching_tabs_still_hands_back_every_setting(qt_app: QApplication) -> None:
    """A tab out of sight is still a tab whose values matter on OK."""
    dialog = _opened({**prefs.defaults(), "view/decode_targets": False})
    tabs = dialog.findChild(QTabWidget)
    assert tabs is not None

    tabs.setCurrentIndex(2)
    tabs.setCurrentIndex(0)

    chosen = dialog.chosen()
    assert set(chosen) == {setting.key for setting in prefs.EVERY}
    assert chosen["view/decode_targets"] is False


def test_ok_is_the_default_and_restore_defaults_never_is(qt_app: QApplication) -> None:
    dialog = _opened()
    buttons = dialog.findChild(QDialogButtonBox)
    assert buttons is not None

    ok = buttons.button(QDialogButtonBox.StandardButton.Ok)
    restore = buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults)
    assert ok is not None and restore is not None
    assert ok.isDefault()
    assert not restore.autoDefault()


def test_larger_text_scrolls_without_clipping_the_confirmation_buttons(
    qt_app: QApplication,
) -> None:
    from PyQt6.QtCore import QPoint, QRect
    from PyQt6.QtWidgets import QScrollArea

    original_font = qt_app.font()
    large = ui_font(original_font)
    large.setPointSizeF(14)
    qt_app.setFont(large)
    dialog = _opened()
    try:
        dialog.resize(560, 360)
        tabs = dialog.findChild(QTabWidget)
        assert tabs is not None
        tabs.setCurrentIndex(1)
        dialog.show()
        qt_app.processEvents()
        buttons = dialog.findChild(QDialogButtonBox)
        assert buttons is not None and buttons.isVisible()
        assert dialog.rect().contains(buttons.geometry())
        scroll = tabs.currentWidget()
        assert isinstance(scroll, QScrollArea)
        bar = scroll.verticalScrollBar()
        assert bar is not None
        bar.setValue(bar.maximum())
        qt_app.processEvents()
        viewport = scroll.viewport()
        assert viewport is not None
        # The last thing on the Graph tab: the icons for kinds sit under its
        # switches, so the bottom of the scroll is their Default icons button.
        last = dialog.icons.default_button
        rect = QRect(last.mapTo(viewport, QPoint()), last.size())
        assert viewport.rect().contains(rect.topLeft())
        assert rect.bottom() <= viewport.rect().bottom()
    finally:
        dialog.close()
        qt_app.setFont(original_font)


# -- what it shows ---------------------------------------------------------


def test_it_opens_showing_what_is_in_force(qt_app: QApplication) -> None:
    dialog = _opened(
        {
            **prefs.defaults(),
            "view/wrap_traces": False,
            "view/band_density": Density.COARSE,
        }
    )

    assert dialog._controls["view/wrap_traces"].isChecked() is False
    assert dialog._controls["view/band_density"].currentText() == "Coarse"


def test_what_the_reader_changes_comes_back(qt_app: QApplication) -> None:
    dialog = _opened()

    dialog._controls["cases/reopen_last"].setChecked(True)
    dialog._controls["view/band_density"].setCurrentIndex(0)

    chosen = dialog.chosen()
    assert chosen["cases/reopen_last"] is True
    assert chosen["view/band_density"] is Density.COARSE


def test_what_the_reader_leaves_alone_comes_back_unchanged(qt_app: QApplication) -> None:
    """Half the answer. A dialog that reported defaults for the controls nobody
    touched would quietly undo every preference on every visit."""
    given = {
        **prefs.defaults(),
        "view/wrap_traces": False,
        "view/decode_targets": False,
        "view/band_density": Density.MEDIUM,
    }
    dialog = _opened(given)

    dialog._controls["cases/reopen_last"].setChecked(True)

    assert dialog.chosen() == {**given, "cases/reopen_last": True}


# -- restoring, and holding off ------------------------------------------


def test_restoring_defaults_fills_the_controls(qt_app: QApplication) -> None:
    dialog = _opened({**prefs.defaults(), "view/wrap_traces": False})

    dialog.restore_defaults()

    assert dialog.chosen() == prefs.defaults()


def test_restoring_defaults_is_not_applying_them(qt_app: QApplication) -> None:
    """It fills the controls. Whether the window ever hears about it is the
    reader's decision, taken with OK — which is what makes Cancel mean nothing
    happened rather than something to be undone."""
    dialog = _opened({**prefs.defaults(), "view/wrap_traces": False})
    heard: list[object] = []
    dialog.accepted.connect(lambda: heard.append(1))

    dialog.restore_defaults()

    assert heard == []


def test_the_dialog_cannot_apply_anything_by_itself(qt_app: QApplication) -> None:
    """Structural, and the reason `Cancel` needs no undo: the dialog is handed
    values and hands values back. It has no way to reach the window at all."""
    dialog = _opened()

    dialog._controls["view/wrap_traces"].setChecked(False)

    assert dialog.chosen()["view/wrap_traces"] is False
    assert not hasattr(dialog, "_window")


# -- folding repeated evidence lines ------------------------------------------


def test_folding_offers_every_rule_by_name_with_the_default_chosen(qt_app: QApplication) -> None:
    dialog = _opened()
    control = dialog._controls[prefs.FOLD]

    assert isinstance(control, QComboBox)
    assert [control.itemText(i) for i in range(control.count())] == [
        "Off",
        "Same path",
        "Same request",
        "Same request and status",
        "Same request, status and size",
    ]
    assert control.currentData() is FoldRule.REQUEST_STATUS_SIZE


def test_a_chosen_rule_comes_back_and_restore_puts_the_default_back(
    qt_app: QApplication,
) -> None:
    dialog = _opened()
    control = dialog._controls[prefs.FOLD]
    assert isinstance(control, QComboBox)

    control.setCurrentIndex(control.findData(FoldRule.PATH))
    assert dialog.chosen()[prefs.FOLD] is FoldRule.PATH

    dialog.restore_defaults()
    assert dialog.chosen()[prefs.FOLD] is FoldRule.REQUEST_STATUS_SIZE


def test_text_size_is_zoomed_rather_than_chosen_here(qt_app: QApplication) -> None:
    dialog = _opened()
    tabs = dialog.findChild(QTabWidget)
    assert tabs is not None
    assert "Appearance" not in [tabs.tabText(i) for i in range(tabs.count())]
    assert not any("Text size" in label.text() for label in dialog.findChildren(QLabel))
    assert not any("Text size" in box.text() for box in dialog.findChildren(QCheckBox))
    dialog.close()


def test_the_band_choices_keep_their_names(qt_app: QApplication) -> None:
    dialog = _opened()
    control = dialog._controls["view/band_density"]

    assert isinstance(control, QComboBox)
    assert [control.itemText(i) for i in range(control.count())] == ["Coarse", "Medium", "Fine"]


# -- icons for kinds -------------------------------------------------------


def _icons_dialog(
    icons: dict[ActivityCategory, str] | None = None,
) -> tuple[PreferencesDialog, KindIconGrid]:
    dialog = PreferencesDialog(prefs.defaults(), icons=icons or {})
    return dialog, dialog.icons


def _answers(monkeypatch: pytest.MonkeyPatch, grid: KindIconGrid, answer: object) -> None:
    monkeypatch.setattr(grid, "_pick", lambda kind: answer)


def test_the_graph_tab_offers_an_icon_for_every_kind(qt_app: QApplication) -> None:
    dialog, grid = _icons_dialog()
    assert [button.text() for button in grid.buttons.values()] == list(KIND_NAMES.values())
    graph = [dialog.tabs.tabText(i) for i in range(dialog.tabs.count())].index("Graph")
    assert required(dialog.tabs.widget(graph), "page").isAncestorOf(grid)
    words = [label.text() for label in grid.findChildren(QLabel)]
    assert "Icons" in words
    assert "One for each kind of activity, drawn on the graph. Click one to change it." in words
    assert grid.default_button.text() == "Default icons"


def test_picking_an_icon_for_a_kind_is_handed_back(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog, grid = _icons_dialog()
    _answers(monkeypatch, grid, "bug")
    grid.buttons[ActivityCategory.INJECTION].click()
    assert dialog.chosen_icons() == {ActivityCategory.INJECTION: "bug"}


def test_cancelling_the_picker_changes_nothing(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog, grid = _icons_dialog({ActivityCategory.INJECTION: "bug"})
    _answers(monkeypatch, grid, ...)
    grid.buttons[ActivityCategory.INJECTION].click()
    assert dialog.chosen_icons() == {ActivityCategory.INJECTION: "bug"}


def test_picking_the_default_forgets_the_choice(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog, grid = _icons_dialog({ActivityCategory.INJECTION: "bug"})
    _answers(monkeypatch, grid, None)
    grid.buttons[ActivityCategory.INJECTION].click()
    assert dialog.chosen_icons() == {}


def test_default_icons_puts_every_kind_back(qt_app: QApplication) -> None:
    dialog, grid = _icons_dialog({ActivityCategory.INJECTION: "bug", ActivityCategory.SSRF: "zap"})
    grid.default_button.click()
    assert dialog.chosen_icons() == {}


def test_restore_defaults_puts_the_icons_back_too(qt_app: QApplication) -> None:
    dialog, _grid = _icons_dialog({ActivityCategory.INJECTION: "bug"})
    dialog.restore_defaults()
    assert dialog.chosen_icons() == {}


def test_a_kinds_button_shows_its_icon(qt_app: QApplication) -> None:
    _dialog, grid = _icons_dialog({ActivityCategory.INJECTION: "bug"})
    button = grid.buttons[ActivityCategory.INJECTION]
    size = button.iconSize()
    shown = button.icon().pixmap(size).toImage()
    assert shown == first_drawable(["bug"], THEME.ink, size.width()).toImage()


def test_a_missing_file_choice_shows_the_kinds_default(qt_app: QApplication) -> None:
    _dialog, grid = _icons_dialog({ActivityCategory.INJECTION: "file:gone.svg"})
    button = grid.buttons[ActivityCategory.INJECTION]
    size = button.iconSize()
    shown = button.icon().pixmap(size).toImage()
    assert shown == first_drawable(["syringe"], THEME.ink, size.width()).toImage()
