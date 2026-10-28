"""Preferences kept under the tool's old name, logarc, before 2026-10-28.

`QSettings` files them under the organisation and application names, so a
rename would otherwise start every reader over: their text size, their icons,
the cases they had open.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSettings

from logarx.gui.app import move_old_settings

if TYPE_CHECKING:
    from pathlib import Path


def _ini(path: Path) -> QSettings:
    return QSettings(str(path), QSettings.Format.IniFormat)


def test_the_old_preferences_are_copied_to_the_new_name(tmp_path: Path) -> None:
    old = _ini(tmp_path / "old.ini")
    old.setValue("view/text_points", 12)
    old.setValue("cases/recent", ["C:/cases/one"])
    old.sync()
    new = _ini(tmp_path / "new.ini")

    assert move_old_settings(new, old) == 2

    assert int(new.value("view/text_points")) == 12
    assert new.value("cases/recent") == ["C:/cases/one"]
    assert old.value("view/text_points") is not None, "the old ones are kept"


def test_preferences_already_kept_under_the_new_name_win(tmp_path: Path) -> None:
    old = _ini(tmp_path / "old.ini")
    old.setValue("view/text_points", 12)
    new = _ini(tmp_path / "new.ini")
    new.setValue("view/text_points", 14)

    assert move_old_settings(new, old) == 0

    assert int(new.value("view/text_points")) == 14
