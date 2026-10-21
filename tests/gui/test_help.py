"""The Help menu: where the guide is, which keys do what, and what this is."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarc.gui.app import MainWindow
from logarc.gui.help import USER_GUIDE, about_text, shortcut_rows


def test_the_shortcut_list_names_every_menu_entry_that_has_a_key(qt_app: QApplication) -> None:
    window = MainWindow()
    rows = shortcut_rows(window.menuBar())

    assert ("Undo move", "Ctrl+Z") in rows
    assert ("Full screen", "F11") in rows
    assert ("New from logs…", "Ctrl+N") in rows
    assert all(name and keys for name, keys in rows)
    assert not any("&" in name for name, _ in rows), "mnemonic markers are not names"
    window.close()


def test_a_menu_entry_without_a_key_is_not_listed(qt_app: QApplication) -> None:
    window = MainWindow()
    names = [name for name, _ in shortcut_rows(window.menuBar())]

    assert "Formats and rules…" not in names
    assert "Exit" not in names
    window.close()


def test_about_names_the_version_and_the_licence() -> None:
    text = about_text("9.9.9")

    assert "9.9.9" in text
    assert "MIT" in text


def test_the_user_guide_is_the_published_desktop_guide() -> None:
    assert USER_GUIDE == "https://github.com/FRTX045/logarc/blob/main/docs/desktop-app.md"
