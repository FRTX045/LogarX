"""The window a client address is named in.

Small on purpose, like the Rename session window: which address, the name, and
three buttons. It saves before it closes, so a case folder that will not take
the name says so here, while the name the reader typed is still in front of
them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QLineEdit, QVBoxLayout

from logarx.bookmarks import NAME_LIMIT
from logarx.client_names import ClientNameWriteError
from logarx.gui._qt import required
from logarx.gui.session_rename import write_failed
from logarx.gui.theme import colour_text
from logarx.style import THEME, display_safe

if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtWidgets import QWidget

__all__ = ["ClientRename"]

#: Wide enough to show a name of the length most readers type without scrolling.
_FIELD_CHARACTERS: Final = 40


class ClientRename(QDialog):
    """Name one client address, or take its name away.

    `save` is handed the name as typed, or `None` to remove it; it raises
    `ClientNameWriteError` when the case folder refuses, and the window then
    stays open and says why.
    """

    def __init__(
        self,
        parent: QWidget | None,
        *,
        address: str,
        current: str,
        named: bool,
        save: Callable[[str | None], None],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Rename client")
        self._save = save

        # Shown safely: a format reading the client from a forwarded-for header
        # takes it from the request, and the client wrote that.
        self.address = QLabel(display_safe(address))
        self.address.setTextFormat(Qt.TextFormat.PlainText)
        colour_text(self.address, THEME.muted)

        self.field = QLineEdit(current)
        self.field.setMaxLength(NAME_LIMIT)
        self.field.setPlaceholderText("A name for this address")
        self.field.setMinimumWidth(self.field.fontMetrics().averageCharWidth() * _FIELD_CHARACTERS)

        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        colour_text(self.error, THEME.alert)
        self.error.hide()

        buttons = QDialogButtonBox()
        self.remove_button = required(
            buttons.addButton("Remove name", QDialogButtonBox.ButtonRole.ResetRole)
        )
        self.cancel_button = required(buttons.addButton(QDialogButtonBox.StandardButton.Cancel))
        self.rename_button = required(
            buttons.addButton("Rename", QDialogButtonBox.ButtonRole.AcceptRole)
        )
        # Enter renames; neither other button may take it over when it has focus.
        for other in (self.remove_button, self.cancel_button):
            other.setAutoDefault(False)
        self.rename_button.setDefault(True)
        self.remove_button.setEnabled(named)

        self.field.textChanged.connect(self._typed)
        self.rename_button.clicked.connect(lambda: self._try(self.field.text()))
        self.remove_button.clicked.connect(lambda: self._try(None))
        self.cancel_button.clicked.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.address)
        layout.addWidget(self.field)
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
        except ClientNameWriteError as error:
            self.error.setText(write_failed(error))
            self.error.show()
            self.adjustSize()
            return
        self.accept()
