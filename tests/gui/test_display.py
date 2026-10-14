"""WSL display defaults stay local to the app and respect user choices."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from logarc.gui import display


@pytest.fixture(autouse=True)
def clean_display_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in ("XCURSOR_SIZE", "QT_WAYLAND_DECORATION", "WSL_DISTRO_NAME"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(display, "sys", SimpleNamespace(platform="linux"))


def test_wsl_enlarges_cursor_without_replacing_window_buttons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    display.configure_display()

    assert os.environ["XCURSOR_SIZE"] == "32"
    assert "QT_WAYLAND_DECORATION" not in os.environ


def test_explicit_display_choices_are_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")
    monkeypatch.setenv("XCURSOR_SIZE", "48")
    monkeypatch.setenv("QT_WAYLAND_DECORATION", "bradient")

    display.configure_display()

    assert os.environ["XCURSOR_SIZE"] == "48"
    assert os.environ["QT_WAYLAND_DECORATION"] == "bradient"


@pytest.mark.parametrize("platform,wsl", [("linux", False), ("win32", True), ("darwin", True)])
def test_other_desktops_keep_their_defaults(
    monkeypatch: pytest.MonkeyPatch, platform: str, wsl: bool
) -> None:
    monkeypatch.setattr(display, "sys", SimpleNamespace(platform=platform))
    if wsl:
        monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    display.configure_display()

    assert "XCURSOR_SIZE" not in os.environ
    assert "QT_WAYLAND_DECORATION" not in os.environ
