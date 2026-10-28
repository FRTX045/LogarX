"""The box a bookmark is saved and edited in.

Small and quick on purpose: opened from Ctrl+D, a right-click or a Bookmark
button, it says what is being saved, takes a category and an optional note, and
Enter saves. Two keys for the quick path, and room for a note when there is one.

It never closes itself on Save. It hands the category and note over, and the
window closes it once the bookmark is written — so a folder that cannot be
written to leaves the reader's note in front of them with the reason, rather
than a box that vanished as though it had worked.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import QPoint, Qt, pyqtSignal
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from logarx.bookmarks import NAME_LIMIT, NOTE_LIMIT
from logarx.gui.theme import PAD, caption_font, colour_text, heading_font, mono_font
from logarx.style import THEME

if TYPE_CHECKING:
    from collections.abc import Sequence

    from PyQt6.QtGui import QKeyEvent, QShowEvent

__all__ = ["BookmarkBox"]

#: How far the box keeps from the window's edges.
_MARGIN = 12


class BookmarkBox(QDialog):
    """What is being saved, its category, and a note."""

    saving = pyqtSignal(str, str)
    """The category (tidied) and the note (stripped), once both are usable."""

    def __init__(
        self,
        parent: QWidget,
        *,
        title: str,
        said: str,
        client: str | None,
        categories: Sequence[str],
        category: str,
        note: str = "",
    ) -> None:
        # Frameless and modal rather than a click-away popup: Qt closes a popup
        # whenever focus moves, which on some desktops is the moment it opens,
        # and the category's own drop-down list is a popup inside it.
        super().__init__(parent, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setModal(True)
        self.setObjectName("bookmarkBox")
        self.setStyleSheet(
            f"#bookmarkBox {{ background:{THEME.raised}; border:1px solid {THEME.edge};"
            " border-radius:6px; }"
        )
        self.setFixedWidth(430)

        self.heading = QLabel(title)
        self.heading.setFont(heading_font(self.heading.font()))
        # Text, never markup: it came out of a request or a reader's typing.
        self.said = QLabel(said)
        self.said.setTextFormat(Qt.TextFormat.PlainText)
        self.said.setWordWrap(True)
        self.client = QLabel(client or "")
        self.client.setTextFormat(Qt.TextFormat.PlainText)
        self.client.setFont(mono_font(self.client.font().pointSizeF()))
        colour_text(self.client, THEME.identity)
        self.client.setVisible(client is not None)

        self.category = QComboBox()
        self.category.setEditable(True)
        self.category.addItems(list(categories))
        # A typed name becomes a category when the bookmark is saved, not when
        # Enter is pressed in the box: a box closed with Esc must leave nothing.
        self.category.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.category.setCurrentText(category)
        self.category.setAccessibleName("Category")
        self.category.setToolTip("Pick a category, or type a new name to make a new category.")

        self.note = QLineEdit(note)
        self.note.setMaxLength(NOTE_LIMIT)
        self.note.setPlaceholderText("Why it matters (optional)")
        self.note.setAccessibleName("Note")

        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        colour_text(self.error, THEME.alert)
        self.error.hide()

        keys = QLabel("Enter saves \N{MIDDLE DOT} Esc cancels")
        keys.setFont(caption_font(keys.font()))
        colour_text(keys, THEME.faint)
        cancel = QPushButton("Cancel")
        self.save = QPushButton("Save")
        self.save.setProperty("primary", True)
        # Enter is heard once, here in the box (`keyPressEvent`), not from the
        # fields: an editable combo hands Enter back to its own field, which
        # then announces it a second time, and a default button would be a third.
        for button in (cancel, self.save):
            button.setAutoDefault(False)
            button.setDefault(False)
        cancel.clicked.connect(self.reject)
        self.save.clicked.connect(self._save)

        buttons = QHBoxLayout()
        buttons.addWidget(keys)
        buttons.addStretch(1)
        buttons.addWidget(cancel)
        buttons.addWidget(self.save)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)
        layout.addWidget(self.heading)
        layout.addWidget(self.said)
        layout.addWidget(self.client)
        layout.addSpacing(PAD // 2)
        layout.addWidget(QLabel("Category"))
        layout.addWidget(self.category)
        layout.addSpacing(PAD // 2)
        layout.addWidget(QLabel("Note"))
        layout.addWidget(self.note)
        layout.addWidget(self.error)
        layout.addSpacing(PAD // 2)
        layout.addLayout(buttons)

    def showEvent(self, event: QShowEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().showEvent(event)
        # Straight into the note: the category is already the last one used, so
        # the quick path is to type why, or nothing, and press Enter.
        self.note.setFocus()

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is not None and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            event.accept()
            self._save()
            return
        super().keyPressEvent(event)

    def chosen(self) -> tuple[str, str]:
        """The category, its spaces tidied, and the note, stripped."""
        return " ".join(self.category.currentText().split()), self.note.text().strip()

    def show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.show()
        self.adjustSize()

    def place(self, anchor: QPoint) -> None:
        """Open at `anchor`, in the parent's coordinates, kept inside the parent."""
        parent = self.parentWidget()
        self.adjustSize()
        if parent is None:
            return
        size = self.sizeHint().expandedTo(self.size())
        x = max(_MARGIN, min(anchor.x(), parent.width() - size.width() - _MARGIN))
        y = anchor.y()
        if y + size.height() > parent.height() - _MARGIN:
            y = max(_MARGIN, parent.height() - size.height() - _MARGIN)
        self.move(parent.mapToGlobal(QPoint(x, y)))

    def _save(self) -> None:
        category, note = self.chosen()
        if not category:
            self.show_error("A category needs a name.")
            return
        if len(category) > NAME_LIMIT:
            self.show_error(f"A category name is at most {NAME_LIMIT} characters.")
            return
        self.error.hide()
        self.saving.emit(category, note)
