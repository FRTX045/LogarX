"""The window a session is renamed in.

Small on purpose: which session, the name, logarc's own name beside it, and
three buttons. It saves before it closes, so a case folder that will not take
the name says so here, while the name the reader typed is still in front of
them, rather than in a status line after the window has gone.
"""

from __future__ import annotations

import errno
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QLineEdit, QVBoxLayout

from logarc.bookmarks import NAME_LIMIT
from logarc.gui.theme import colour_text
from logarc.session_names import SessionNameWriteError
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QWidget

__all__ = ["SessionRename", "write_failed"]

_CANNOT_WRITE: Final = "Could not save the name: the case folder cannot be written to."
#: Wide enough to show a name of the length most readers type without scrolling.
_FIELD_CHARACTERS: Final = 40


def write_failed(error: SessionNameWriteError) -> str:
    """What to say when the case folder would not take the name.

    The same test `bookmark_keeper` uses for a bookmark: a folder that refuses
    is named as such, anything else gives the system's own reason.
    """
    refused = isinstance(error.__cause__, PermissionError) or error.errno in (
        errno.EACCES,
        errno.EPERM,
        errno.EROFS,
    )
    if refused:
        return _CANNOT_WRITE
    return f"Could not save the name: {error.strerror or error}."


class SessionRename(QDialog):
    """Rename one session, or give it logarc's name back.

    `save` is handed the name as typed, or `None` for logarc's own; it raises
    `SessionNameWriteError` when the case folder refuses, and the window then
    stays open and says why.
    """

    def __init__(
        self,
        parent: QWidget | None,
        *,
        place: str,
        current: str,
        logarc_name: str,
        renamed: bool,
        save: Callable[[str | None], None],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rename session")
        self._save = save

        self.place = QLabel(place)
        self.place.setTextFormat(Qt.TextFormat.PlainText)
        colour_text(self.place, THEME.muted)

        self.field = QLineEdit(current)
        self.field.setMaxLength(NAME_LIMIT)
        self.field.setMinimumWidth(self.field.fontMetrics().averageCharWidth() * _FIELD_CHARACTERS)

        self.note = QLabel(f"logarc's name: {logarc_name}")
        self.note.setTextFormat(Qt.TextFormat.PlainText)
        colour_text(self.note, THEME.muted)

        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        colour_text(self.error, THEME.alert)
        self.error.hide()

        buttons = QDialogButtonBox()
        self.reset_button = buttons.addButton(
            "Use logarc's name", QDialogButtonBox.ButtonRole.ResetRole
        )
        self.cancel_button = buttons.addButton(QDialogButtonBox.StandardButton.Cancel)
        self.rename_button = buttons.addButton("Rename", QDialogButtonBox.ButtonRole.AcceptRole)
        # Enter renames; neither other button may take it over when it has focus.
        for other in (self.reset_button, self.cancel_button):
            other.setAutoDefault(False)
        self.rename_button.setDefault(True)
        self.reset_button.setEnabled(renamed)

        self.field.textChanged.connect(self._typed)
        self.rename_button.clicked.connect(lambda: self._try(self.field.text()))
        self.reset_button.clicked.connect(lambda: self._try(None))
        self.cancel_button.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.place)
        layout.addWidget(self.field)
        layout.addWidget(self.note)
        layout.addWidget(self.error)
        layout.addSpacing(self.fontMetrics().height() // 2)
        layout.addWidget(buttons)

        self._typed(current)
        self.field.selectAll()
        self.field.setFocus()

    def _typed(self, text: str) -> None:
        self.rename_button.setEnabled(bool(text.strip()))

    def _try(self, name: str | None) -> None:
        try:
            self._save(name)
        except SessionNameWriteError as error:
            self.error.setText(write_failed(error))
            self.error.show()
            self.adjustSize()
            return
        self.accept()
