"""WSL display defaults stay local to the app and respect user choices."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from zodiarc.gui import display


@pytest.fixture(autouse=True)
def clean_display_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "XCURSOR_SIZE",
        "QT_WAYLAND_DECORATION",
        "WSL_DISTRO_NAME",
        "QT_QPA_PLATFORM",
        "DISPLAY",
    ):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(display, "sys", SimpleNamespace(platform="linux"))


def test_wsl_enlarges_cursor_without_replacing_window_buttons(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")
    monkeypatch.setenv("DISPLAY", ":0")

    display.configure_display()

    assert os.environ["XCURSOR_SIZE"] == "32"
    assert "QT_WAYLAND_DECORATION" not in os.environ
    assert "QT_QPA_PLATFORM" not in os.environ


@pytest.mark.parametrize("backend", ["wayland", "offscreen", "xcb", "xcb;wayland"])
def test_explicit_display_choices_are_kept(monkeypatch: pytest.MonkeyPatch, backend: str) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")
    monkeypatch.setenv("DISPLAY", ":0")
    monkeypatch.setenv("QT_QPA_PLATFORM", backend)
    monkeypatch.setenv("XCURSOR_SIZE", "48")
    monkeypatch.setenv("QT_WAYLAND_DECORATION", "bradient")

    display.configure_display()

    assert os.environ["XCURSOR_SIZE"] == "48"
    assert os.environ["QT_WAYLAND_DECORATION"] == "bradient"
    assert os.environ["QT_QPA_PLATFORM"] == backend


def test_wsl_without_an_x_server_keeps_qts_backend_choice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    display.configure_display()

    assert "QT_QPA_PLATFORM" not in os.environ
    assert os.environ["XCURSOR_SIZE"] == "32"


@pytest.mark.parametrize("platform,wsl", [("linux", False), ("win32", True), ("darwin", True)])
def test_other_desktops_keep_their_defaults(
    monkeypatch: pytest.MonkeyPatch, platform: str, wsl: bool
) -> None:
    monkeypatch.setattr(display, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setenv("DISPLAY", ":0")
    if wsl:
        monkeypatch.setenv("WSL_DISTRO_NAME", "kali-linux")

    display.configure_display()

    assert "XCURSOR_SIZE" not in os.environ
    assert "QT_WAYLAND_DECORATION" not in os.environ
    assert "QT_QPA_PLATFORM" not in os.environ
