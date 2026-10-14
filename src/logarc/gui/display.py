"""Local display defaults, set before Qt connects to the desktop."""

from __future__ import annotations

import os
import sys


def is_wsl() -> bool:
    """Whether the GUI is running through WSL's Linux desktop integration."""
    return sys.platform == "linux" and bool(os.environ.get("WSL_DISTRO_NAME"))


def configure_display() -> None:
    """Use a larger WSL cursor, keeping explicit overrides."""
    if not is_wsl():
        return
    os.environ.setdefault("XCURSOR_SIZE", "32")
