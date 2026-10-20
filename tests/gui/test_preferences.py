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

from PyQt6.QtWidgets import QApplication, QCheckBox, QComboBox, QGroupBox, QLabel

from logarc.gui import prefs
from logarc.gui.density import Density
from logarc.gui.folding import FoldRule
from logarc.gui.preferences import PreferencesDialog
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


def test_the_groups_are_drawn_as_groups_in_order(qt_app: QApplication) -> None:
    """The shape the reader picked: one page, three boxes, nothing hidden
    behind a tab or a category list."""
    dialog = _opened()

    boxes = [box.title() for box in dialog.findChildren(QGroupBox)]

    assert boxes == list(prefs.GROUPS)


def test_explanations_can_be_hidden_without_changing_preferences(qt_app: QApplication) -> None:
    dialog = _opened()
    before = dialog.chosen()
    assert all(note.isHidden() for note in dialog._notes)
    dialog.explanations.click()
    assert all(not note.isHidden() for note in dialog._notes)
    assert dialog.chosen() == before
    dialog.explanations.click()
    assert all(note.isHidden() for note in dialog._notes)
    assert dialog.chosen() == before
    for setting in prefs.EVERY:
        assert dialog._controls[setting.key].toolTip() == setting.note
    dialog.close()


def test_larger_text_scrolls_without_clipping_notes_or_confirmation_buttons(
    qt_app: QApplication,
) -> None:
    from PyQt6.QtCore import QPoint, QRect
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QDialogButtonBox, QLabel, QScrollArea

    original_font = qt_app.font()
    qt_app.setFont(ui_font(original_font))
    dialog = _opened()
    try:
        dialog.resize(560, 420)
        dialog.explanations.setChecked(True)
        dialog.show()
        qt_app.processEvents()
        # Revealing wrapped notes queues another height-for-width layout pass.
        QTest.qWait(20)
        scroll = dialog.findChild(QScrollArea)
        assert scroll is not None
        body = scroll.widget()
        bar = scroll.verticalScrollBar()
        assert body is not None and bar is not None
        assert bar.maximum() > 0
        for note in body.findChildren(QLabel):
            assert note.height() >= note.heightForWidth(note.width())
        buttons = dialog.findChild(QDialogButtonBox)
        assert buttons is not None and buttons.isVisible()
        assert dialog.rect().contains(buttons.geometry())
        bar.setValue(bar.maximum())
        qt_app.processEvents()
        viewport = scroll.viewport()
        assert viewport is not None
        last_control = dialog._controls["cases/reopen_last"]
        rect = QRect(last_control.mapTo(viewport, QPoint()), last_control.size())
        # Scrolled to the bottom, the last control is in view from its left edge
        # and over its whole height. Its width is left alone: offscreen Qt on
        # Windows lays this checkbox out 803 pixels wide, where a real window of
        # the same size gives it 488 of 516, so a sideways check here would be
        # testing the stand-in font rather than the dialog.
        assert viewport.rect().contains(rect.topLeft())
        assert rect.bottom() <= viewport.rect().bottom()
    finally:
        dialog.close()
        qt_app.setFont(original_font)


def test_each_setting_says_what_it_is_for_on_screen(qt_app: QApplication) -> None:
    """Not only in the catalogue. The menu carried these as status tips; a
    dialog that dropped them would make the move a step backwards."""
    dialog = _opened()
    dialog.explanations.setChecked(True)
    written = dialog.grab().size()  # forces a layout, so nothing is unbuilt
    assert written.isValid()

    on_screen = _all_text(dialog)
    for setting in prefs.EVERY:
        assert setting.note in on_screen, f"{setting.key} explains nothing on screen"


def _all_text(dialog: PreferencesDialog) -> str:
    from PyQt6.QtWidgets import QLabel

    return "\n".join(label.text() for label in dialog.findChildren(QLabel))


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
    assert "Appearance" not in [box.title() for box in dialog.findChildren(QGroupBox)]
    assert not any("Text size" in label.text() for label in dialog.findChildren(QLabel))
    assert not any("Text size" in box.text() for box in dialog.findChildren(QCheckBox))
    dialog.close()


def test_the_band_choices_keep_their_names(qt_app: QApplication) -> None:
    dialog = _opened()
    control = dialog._controls["view/band_density"]

    assert isinstance(control, QComboBox)
    assert [control.itemText(i) for i in range(control.count())] == ["Coarse", "Medium", "Fine"]
