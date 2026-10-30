"""The application's own icon, for the title bar and the taskbar.

The executable carries the same mark inside it (`packaging/icon/zodiarc.ico`),
which is what Explorer and a shortcut show. A running window draws what Qt is
told to, and without this it shows Qt's blank one.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

#: Beside this module, and shipped there by the packaging spec, like `lucide.json`.
_PICTURE: Final = Path(__file__).with_name("zodiarc.png")


def application_icon() -> QIcon:
    """The Zodiarc mark: white on a dark tile, 256 px, scaled down by Qt."""
    return QIcon(str(_PICTURE))


def install_application_icon(app: QApplication) -> None:
    """Make every window of `app` wear it, so no dialog has to be told."""
    app.setWindowIcon(application_icon())
