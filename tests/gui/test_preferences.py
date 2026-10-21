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

from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QDialogButtonBox, QTabWidget

from logarc.gui import prefs
from logarc.gui.density import Density
from logarc.gui.folding import FoldRule
from logarc.gui.preferences import PreferencesDialog
from logarc.gui.text_size import TextSize
from logarc.gui.theme import ui_font


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
        last = dialog._controls["view/ask_unsaved_arrangement"]
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


def test_text_size_is_selectable_and_restore_returns_to_automatic(qt_app: QApplication) -> None:
    dialog = _opened({**prefs.defaults(), prefs.TEXT_SIZE: TextSize.COMPACT})
    control = dialog._controls[prefs.TEXT_SIZE]
    assert isinstance(control, QComboBox)
    assert [control.itemData(index) for index in range(control.count())] == list(TextSize)
    assert control.currentData() is TextSize.COMPACT
    control.setCurrentIndex(control.findData(TextSize.LARGE))
    assert dialog.chosen()[prefs.TEXT_SIZE] is TextSize.LARGE
    dialog.restore_defaults()
    assert dialog.chosen()[prefs.TEXT_SIZE] is TextSize.AUTOMATIC
    dialog.close()


def test_the_band_choices_keep_their_names(qt_app: QApplication) -> None:
    dialog = _opened()
    control = dialog._controls["view/band_density"]

    assert isinstance(control, QComboBox)
    assert [control.itemText(i) for i in range(control.count())] == ["Coarse", "Medium", "Fine"]
