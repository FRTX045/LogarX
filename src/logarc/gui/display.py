"""Local display defaults, set before Qt connects to the desktop."""

from __future__ import annotations

import os
import sys


def is_wsl() -> bool:
    """Whether the GUI is running through WSL's Linux desktop integration."""
    return sys.platform == "linux" and bool(os.environ.get("WSL_DISTRO_NAME"))


def configure_display() -> None:
    """Use stable WSL window transitions and a readable cursor.

    Window buttons are drawn by `window_controls`; no decoration plugin is
    forced, since plugins can hide buttons according to desktop settings.
    WSLg's native Wayland path can terminate the process when fullscreen returns
    to maximized with a zero-size configure. Prefer its X11 server when offered,
    before QApplication connects; explicit Qt backend choices still win.
    """
    if not is_wsl():
        return
    if os.environ.get("DISPLAY"):
        os.environ.setdefault("QT_QPA_PLATFORM", "xcb")
    os.environ.setdefault("XCURSOR_SIZE", "32")
