"""The Help menu: where the guide is, which keys do what, and what this is.

The shortcut list is read off the menu bar rather than written out, so a key
added to a menu entry is listed the moment it exists and a key taken away stops
being promised.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QDialog,
    QDialogButtonBox,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
)

from logarc import __version__
from logarc.gui._qt import required
from logarc.gui.columns import ColumnWidths
from logarc.gui.theme import ROOM

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QMenuBar, QWidget

__all__ = [
    "USER_GUIDE",
    "about_text",
    "open_user_guide",
    "shortcut_rows",
    "show_about",
    "show_shortcuts",
]

#: The desktop guide as published. Opened in the reader's browser: the packaged
#: application carries no copy of the docs, and a stale one would be worse.
USER_GUIDE: Final = "https://github.com/FRTX045/logarc/blob/main/docs/desktop-app.md"


def shortcut_rows(bar: QMenuBar) -> list[tuple[str, str]]:
    """`(entry, keys)` for every menu entry that has a key, in menu order."""
    rows: list[tuple[str, str]] = []
    for top in bar.actions():
        menu = top.menu()
        if menu is None:
            continue
        for action in menu.actions():
            if action.isSeparator() or action.shortcut().isEmpty():
                continue
            rows.append((action.text().replace("&", ""), action.shortcut().toString()))
    return rows


def about_text(version: str) -> str:
    """What the About box says."""
    return (
        f"logarc {version}\n\n"
        "Forensic reconstruction of web activity from server access logs.\n\n"
        "MIT License · github.com/FRTX045/logarc"
    )


def open_user_guide() -> None:
    QDesktopServices.openUrl(QUrl(USER_GUIDE))


def show_about(parent: QWidget) -> None:
    QMessageBox.about(parent, "About logarc", about_text(__version__))


def show_shortcuts(parent: QWidget, bar: QMenuBar) -> None:
    """A small table of every key the menus answer to."""
    rows = shortcut_rows(bar)
    dialog = QDialog(parent)
    dialog.setWindowTitle("Keyboard shortcuts")
    table = QTableWidget(len(rows), 2)
    table.setHorizontalHeaderLabels(["Command", "Keys"])
    required(table.verticalHeader()).setVisible(False)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
    for row, (name, keys) in enumerate(rows):
        table.setItem(row, 0, QTableWidgetItem(name))
        table.setItem(row, 1, QTableWidgetItem(keys))
    widths = ColumnWidths(table, fill=0)
    widths.fit_unset()
    buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
    buttons.rejected.connect(dialog.reject)
    column = QVBoxLayout(dialog)
    column.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
    column.addWidget(table)
    column.addWidget(buttons)
    dialog.resize(420, 460)
    dialog.exec()
