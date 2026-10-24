"""The window a session is renamed in: what it says, what it saves, and when it stays open."""

from __future__ import annotations

import errno
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QDialog

from logarc.gui.session_rename import SessionRename
from logarc.session_names import SessionNameWriteError

PLACE = "Session 1 of 7 · 09 Mar 09:06\u201309:08"
LOGARC = "Configuration File Probe"


def opened(
    *, current: str = LOGARC, renamed: bool = False, failing: OSError | None = None
) -> tuple[SessionRename, list[str | None]]:
    saved: list[str | None] = []

    def save(name: str | None) -> None:
        if failing is not None:
            raise failing
        saved.append(name)

    window = SessionRename(
        None, place=PLACE, current=current, logarc_name=LOGARC, renamed=renamed, save=save
    )
    window.show()
    return window, saved


def test_it_says_which_session_and_logarcs_name(qt_app: QApplication) -> None:
    window, _ = opened()

    assert window.windowTitle() == "Rename session"
    assert window.place.text() == PLACE
    assert window.note.text() == f"logarc's name: {LOGARC}"
    assert window.error.isHidden()
    window.close()


def test_the_field_holds_the_current_name_all_selected(qt_app: QApplication) -> None:
    window, _ = opened(current="Scanner", renamed=True)

    assert window.field.text() == "Scanner"
    assert window.field.selectedText() == "Scanner"
    window.close()


def test_rename_is_the_default_and_needs_a_name(qt_app: QApplication) -> None:
    window, _ = opened()

    assert window.rename_button.isDefault()
    assert not window.reset_button.autoDefault()
    assert not window.cancel_button.autoDefault()
    window.field.setText("   ")
    assert not window.rename_button.isEnabled()
    window.field.setText("x")
    assert window.rename_button.isEnabled()
    window.close()


def test_the_field_takes_sixty_characters(qt_app: QApplication) -> None:
    window, _ = opened()

    assert window.field.maxLength() == 60
    window.close()


def test_use_logarcs_name_is_live_only_for_a_renamed_session(qt_app: QApplication) -> None:
    plain, _ = opened()
    renamed, _ = opened(current="Scanner", renamed=True)

    assert not plain.reset_button.isEnabled()
    assert renamed.reset_button.isEnabled()
    assert renamed.reset_button.text() == "Use logarc's name"
    plain.close()
    renamed.close()


def test_rename_saves_what_was_typed_and_closes(qt_app: QApplication) -> None:
    window, saved = opened()
    window.field.setText("Mine")

    window.rename_button.click()

    assert saved == ["Mine"]
    assert window.result() == QDialog.DialogCode.Accepted
    assert not window.isVisible()


def test_use_logarcs_name_saves_none_and_closes(qt_app: QApplication) -> None:
    window, saved = opened(current="Scanner", renamed=True)

    window.reset_button.click()

    assert saved == [None]
    assert not window.isVisible()


def test_cancel_saves_nothing(qt_app: QApplication) -> None:
    window, saved = opened()
    window.field.setText("Mine")

    window.cancel_button.click()

    assert saved == []
    assert window.result() == QDialog.DialogCode.Rejected


def test_a_refused_folder_keeps_the_window_open_and_says_so(qt_app: QApplication) -> None:
    window, _ = opened(failing=SessionNameWriteError(errno.EACCES, "Access is denied"))
    window.field.setText("Mine")

    window.rename_button.click()

    assert window.isVisible()
    assert not window.error.isHidden()
    assert window.error.text() == "Could not save the name: the case folder cannot be written to."
    window.close()


def test_another_failure_gives_the_systems_reason(qt_app: QApplication) -> None:
    window, _ = opened(failing=SessionNameWriteError(errno.ENOSPC, "No space left on device"))
    window.field.setText("Mine")

    window.rename_button.click()

    assert window.isVisible()
    assert window.error.text() == "Could not save the name: No space left on device."
    window.close()
