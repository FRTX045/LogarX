"""The icon picker: search the shipped set, or take an image of the reader's own."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QDialog, QDialogButtonBox

from logarx.gui._qt import required
from logarx.gui.icon_picker import IconPicker
from logarx.gui.icon_set import icons_dir, lucide

SQUARE = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">'
    '<rect x="1" y="1" width="8" height="8" fill="#00ff00"/></svg>'
)


def picker(current: str | Path | None = "zap", default: str = "syringe") -> IconPicker:
    return IconPicker(title="Icon for Injection", current=current, default=default)


def names(dialog: IconPicker) -> list[object]:
    grid = dialog.grid
    return [
        required(grid.item(row), "item").data(Qt.ItemDataRole.UserRole)
        for row in range(grid.count())
    ]


def current_name(dialog: IconPicker) -> object:
    return required(dialog.grid.currentItem(), "item").data(Qt.ItemDataRole.UserRole)


def test_it_is_titled_for_what_it_picks_for(qt_app: QApplication) -> None:
    assert picker().windowTitle() == "Icon for Injection"


def test_every_icon_is_offered(qt_app: QApplication) -> None:
    assert names(picker()) == sorted(lucide())


def test_search_narrows_the_grid(qt_app: QApplication) -> None:
    dialog = picker()
    dialog.search.setText("syringe")
    assert names(dialog) == ["syringe"]
    assert dialog.search.placeholderText() == "Search icons"


def test_search_keeps_names_before_tags(qt_app: QApplication) -> None:
    dialog = picker()
    dialog.search.setText("lock")
    found = names(dialog)
    assert found[0] == "lock"
    assert found.index("lock") < found.index("key-round")


def test_the_current_icon_is_selected(qt_app: QApplication) -> None:
    dialog = picker(current="zap")
    assert dialog.choice == "zap"
    assert current_name(dialog) == "zap"


def test_no_current_icon_selects_the_default(qt_app: QApplication) -> None:
    dialog = picker(current=None)
    assert dialog.choice is None
    assert current_name(dialog) == "syringe"


def test_picking_an_icon_is_the_choice(qt_app: QApplication) -> None:
    dialog = picker()
    dialog.search.setText("bug")
    (item,) = dialog.grid.findItems("bug", Qt.MatchFlag.MatchExactly)
    dialog.grid.setCurrentItem(item)
    assert dialog.choice == "bug"


def test_a_choice_survives_a_search_that_hides_it(qt_app: QApplication) -> None:
    dialog = picker(current="zap")
    dialog.search.setText("syringe")
    assert dialog.choice == "zap", "searching is looking, not choosing"
    dialog.search.setText("")
    assert current_name(dialog) == "zap"


def test_default_clears_the_choice_and_shows_what_it_means(qt_app: QApplication) -> None:
    dialog = picker(current="zap")
    dialog.default_button.click()
    assert dialog.choice is None
    assert current_name(dialog) == "syringe"
    assert "syringe" in dialog.default_button.toolTip()


def test_a_refused_file_says_why_and_changes_nothing(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    big = tmp_path / "big.svg"
    big.write_text(SQUARE + " " * 1_048_576, encoding="utf-8")
    dialog = picker(current="zap")
    monkeypatch.setattr(dialog, "_ask_for_file", lambda: big)

    dialog.file_button.click()

    assert dialog.note.text() == "big.svg is over 1 MB. Pick a smaller image."
    assert not dialog.note.isHidden()
    assert dialog.choice == "zap"


def test_an_accepted_file_is_the_choice_and_not_copied_yet(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    logo = tmp_path / "logo.svg"
    logo.write_text(SQUARE, encoding="utf-8")
    dialog = picker(current="zap")
    monkeypatch.setattr(dialog, "_ask_for_file", lambda: logo)

    dialog.file_button.click()

    assert dialog.choice == logo
    assert required(dialog.grid.item(0), "item").text() == "Your image"
    assert dialog.note.isHidden()
    assert not icons_dir().exists(), "copied only when the choice is applied"


def test_cancelling_the_file_dialog_changes_nothing(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    dialog = picker(current="zap")
    monkeypatch.setattr(dialog, "_ask_for_file", lambda: None)
    dialog.file_button.click()
    assert dialog.choice == "zap"


def test_a_current_image_of_the_readers_leads_the_grid(qt_app: QApplication) -> None:
    icons_dir().mkdir(parents=True)
    (icons_dir() / "logo.svg").write_text(SQUARE, encoding="utf-8")
    dialog = picker(current="file:logo.svg")
    assert required(dialog.grid.item(0), "item").text() == "Your image"
    assert dialog.choice == "file:logo.svg"


def test_ok_is_the_default_button(qt_app: QApplication) -> None:
    box = required(picker().findChild(QDialogButtonBox), "buttons")
    ok = required(box.button(QDialogButtonBox.StandardButton.Ok), "OK")
    assert ok.isDefault()
    assert not picker().default_button.isDefault()


def test_double_clicking_an_icon_takes_it(qt_app: QApplication) -> None:
    dialog = picker()
    dialog.search.setText("bug")
    (item,) = dialog.grid.findItems("bug", Qt.MatchFlag.MatchExactly)
    dialog.grid.itemActivated.emit(item)
    assert dialog.result() == QDialog.DialogCode.Accepted
    assert dialog.choice == "bug"


def test_the_chosen_icon_is_in_view_once_shown(qt_app: QApplication) -> None:
    dialog = picker(current="syringe")
    dialog.show()
    qt_app.processEvents()
    item = required(dialog.grid.currentItem(), "item")
    shown = dialog.grid.visualItemRect(item)
    viewport = required(dialog.grid.viewport(), "viewport").rect()
    dialog.close()
    assert viewport.contains(shown)
    assert abs(shown.center().y() - viewport.center().y()) < shown.height()


def test_it_opens_quickly(qt_app: QApplication) -> None:
    """1,533 icons, drawn only as they come into view: opening measured 0.02 to
    0.04 s here on 2026-10-24, drawing the 21 in view. The bound is loose so a
    slow runner does not fail it."""
    started = time.perf_counter()
    dialog = picker()
    dialog.show()
    qt_app.processEvents()
    took = time.perf_counter() - started
    dialog.close()
    assert took < 1.5, f"{took:.2f} s"
