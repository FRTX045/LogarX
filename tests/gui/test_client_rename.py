"""The window a client is named in: what it says, what it saves, and when it stays open."""

from __future__ import annotations

import errno
import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from logarx.client_names import ClientNameWriteError
from logarx.gui.client_rename import ClientRename

ADDRESS = "203.0.113.47"


def opened(
    *, current: str = "", named: bool = False, failing: OSError | None = None
) -> tuple[ClientRename, list[str | None]]:
    saved: list[str | None] = []

    def save(name: str | None) -> None:
        if failing is not None:
            raise failing
        saved.append(name)

    window = ClientRename(None, address=ADDRESS, current=current, named=named, save=save)
    window.show()
    return window, saved


def test_it_says_which_address(qt_app: QApplication) -> None:
    window, _ = opened()

    assert window.windowTitle() == "Rename client"
    assert window.address.text() == ADDRESS
    assert window.error.isHidden()
    window.close()


def test_rename_saves_the_typed_name_and_closes(qt_app: QApplication) -> None:
    window, saved = opened()

    window.field.setText("Office VPN")
    window.rename_button.click()

    assert saved == ["Office VPN"]
    assert not window.isVisible()


def test_rename_is_the_default_and_needs_a_name(qt_app: QApplication) -> None:
    window, _ = opened()

    assert window.rename_button.isDefault()
    assert window.field.maxLength() == 60
    window.field.setText("   ")
    assert not window.rename_button.isEnabled()
    window.field.setText("x")
    assert window.rename_button.isEnabled()
    window.close()


def test_remove_name_saves_none(qt_app: QApplication) -> None:
    window, saved = opened(current="Office VPN", named=True)

    assert window.field.text() == "Office VPN"
    window.remove_button.click()

    assert saved == [None]
    assert not window.isVisible()


def test_remove_is_disabled_when_unnamed(qt_app: QApplication) -> None:
    window, _ = opened()

    assert not window.remove_button.isEnabled()
    window.close()


def test_a_refused_folder_keeps_the_window_open_and_says_why(qt_app: QApplication) -> None:
    window, _ = opened(failing=ClientNameWriteError(errno.EACCES, "denied"))

    window.field.setText("Office VPN")
    window.rename_button.click()

    assert window.isVisible()
    assert window.error.isVisibleTo(window)
    assert window.error.text().startswith("Could not save the name")
    window.close()
