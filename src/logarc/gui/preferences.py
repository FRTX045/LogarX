"""Where the reader changes how the window behaves.

One page, the settings grouped without categories or tabs to switch between.
The page scrolls when larger text or a shorter screen needs more room; the
confirmation buttons stay visible below it.

Drawn from `gui.prefs` rather than written out, so a setting cannot be added to
the catalogue and left undrawn — it would then be reachable only by editing the
settings file by hand.

It applies nothing. The dialog is handed the values in force and hands values
back; the window decides what to do with them, and only if the reader says OK.
That is what makes Cancel mean *nothing happened* rather than *something to be
undone*, and it is why there is no undo here to get wrong.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from logarc.gui import prefs
from logarc.gui.density import Density
from logarc.gui.theme import GAP, ROOM, caption_font
from logarc.style import THEME

if TYPE_CHECKING:
    from logarc.gui.prefs import Setting

__all__ = ["PreferencesDialog"]

#: Wide enough for the longest explaining sentence to take two lines rather
#: than four, measured against the notes in the catalogue.
_WIDTH = 560


class PreferencesDialog(QDialog):
    """The settings the window keeps between launches."""

    def __init__(
        self,
        values: dict[str, bool | Density],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(_WIDTH)
        self._controls: dict[str, QCheckBox | QComboBox] = {}

        column = QVBoxLayout(self)
        column.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        column.setSpacing(ROOM)

        body = QWidget()
        settings = QVBoxLayout(body)
        settings.setContentsMargins(0, 0, 0, 0)
        settings.setSpacing(ROOM)
        for group in prefs.GROUPS:
            settings.addWidget(self._box(group, values))
        settings.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(body)
        column.addWidget(scroll, 1)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.RestoreDefaults
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        restore = buttons.button(QDialogButtonBox.StandardButton.RestoreDefaults)
        if restore is not None:  # pragma: no branch - Qt always builds the ones asked for
            restore.clicked.connect(self.restore_defaults)
        column.addWidget(buttons)

    # -- building ----------------------------------------------------------

    def _box(self, group: str, values: dict[str, bool | Density]) -> QGroupBox:
        box = QGroupBox(group)
        # Wrapped explanations must keep their requested height. The page can
        # scroll instead of compressing the first group until its notes clip.
        box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        inner = QVBoxLayout(box)
        inner.setContentsMargins(GAP, GAP, GAP, GAP)
        inner.setSpacing(GAP)
        for setting in prefs.in_group(group):
            inner.addWidget(self._explained(setting, values[setting.key]))
        return box

    def _explained(self, setting: Setting, value: bool | Density) -> QWidget:
        """One setting: the control, and beneath it the sentence saying why.

        The sentence is not decoration. `Wrap long traces` does not say what a
        trace is or what wrapping does to it, and the menu these replace
        carried exactly this text as a status tip — dropping it in the move
        would make the move a step backwards.
        """
        holder = QWidget()
        column = QVBoxLayout(holder)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(2)
        column.addWidget(self._control(setting, value))

        note = QLabel(setting.note)
        note.setWordWrap(True)
        note.setFont(caption_font(note.font()))
        note.setStyleSheet(f"color:{THEME.faint};")
        column.addWidget(note)
        return holder

    def _control(self, setting: Setting, value: bool | Density) -> QWidget:
        if setting.choices is None:
            switch = QCheckBox(setting.label)
            switch.setChecked(bool(value))
            self._controls[setting.key] = switch
            return switch

        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        line.setSpacing(GAP)
        line.addWidget(QLabel(setting.label))
        choice = QComboBox()
        for option in setting.choices:
            choice.addItem(option.name.title(), option)
        choice.setCurrentIndex(setting.choices.index(value) if isinstance(value, Density) else 0)
        choice.setMinimumWidth(140)
        line.addWidget(choice)
        line.addStretch(1)
        self._controls[setting.key] = choice
        return row

    # -- answering ---------------------------------------------------------

    def chosen(self) -> dict[str, bool | Density]:
        """What the controls are showing now.

        Every setting, not only the ones touched. Reporting the rest as their
        defaults would quietly undo every preference on every visit to this
        dialog.
        """
        values: dict[str, bool | Density] = {}
        for setting in prefs.EVERY:
            control = self._controls[setting.key]
            if isinstance(control, QComboBox):
                values[setting.key] = control.currentData()
            else:
                values[setting.key] = control.isChecked()
        return values

    def restore_defaults(self) -> None:
        """Fill the controls with what the settings start as.

        Filled, not applied. Whether the window ever hears about it is still
        the reader's decision, taken with OK.
        """
        for setting, value in ((s, s.default) for s in prefs.EVERY):
            control = self._controls[setting.key]
            if isinstance(control, QComboBox):
                control.setCurrentIndex(control.findData(value))
            else:
                control.setChecked(bool(value))
