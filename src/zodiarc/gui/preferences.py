"""Where the reader changes how the window behaves.

Three tabs since 2026-10-21, General, Graph and Evidence, each with something
on it; the reader picked them from pictures over five tabs (three holding one
setting) and a sidebar. Each tab scrolls when larger text or a shorter screen
needs more room, and the confirmation buttons stay below all of them.

Drawn from `gui.prefs` rather than written out, so a setting cannot be added to
the catalogue and left undrawn — it would then be reachable only by editing the
settings file by hand.

Every setting explains itself on hover. Its note was once a line under it that
a check box at the top showed and hid; hover is where every other application
keeps that, and a switch for help was one more thing to learn.

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
    QFormLayout,
    QFrame,
    QLabel,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from zodiarc.gui import prefs
from zodiarc.gui.icon_grid import KindIconGrid
from zodiarc.gui.theme import GAP, ROOM, settle_buttons

if TYPE_CHECKING:
    from collections.abc import Mapping

    from zodiarc.core.activity import ActivityCategory
    from zodiarc.gui.icons import Picked
    from zodiarc.gui.prefs import Setting, Value

__all__ = ["PreferencesDialog"]

_WIDTH = 560

#: Every choice box the same width, so the column of them reads as a column.
_CHOICE_WIDTH = 240

#: The tab the icons for kinds sit on.
_ICONS_UNDER = "Graph"


class PreferencesDialog(QDialog):
    """The settings the window keeps between launches."""

    def __init__(
        self,
        values: dict[str, Value],
        parent: QWidget | None = None,
        *,
        icons: Mapping[ActivityCategory, str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Preferences")
        self.setMinimumWidth(_WIDTH)
        self._controls: dict[str, QCheckBox | QComboBox] = {}
        # An icon for each kind, under the Graph settings: what the graph draws.
        self.icons = KindIconGrid(icons or {})

        column = QVBoxLayout(self)
        column.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        column.setSpacing(ROOM)

        self.tabs = QTabWidget()
        for group in prefs.GROUPS:
            self.tabs.addTab(self._page(group, values), group)
        column.addWidget(self.tabs, 1)

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
        settle_buttons(buttons)
        column.addWidget(buttons)

    # -- building ----------------------------------------------------------

    def _page(self, group: str, values: dict[str, Value]) -> QScrollArea:
        """One tab: the choices as a form, then the switches under them."""
        body = QWidget()
        page = QVBoxLayout(body)
        page.setContentsMargins(GAP, ROOM, GAP, GAP)
        page.setSpacing(GAP)
        form = QFormLayout()
        form.setHorizontalSpacing(GAP)
        form.setVerticalSpacing(GAP)
        switches: list[QCheckBox] = []
        for setting in prefs.in_group(group):
            control = self._control(setting, values[setting.key])
            control.setToolTip(setting.note)
            control.setAccessibleDescription(setting.note)
            if isinstance(control, QComboBox):
                name = QLabel(setting.label)
                name.setToolTip(setting.note)
                name.setBuddy(control)
                form.addRow(name, control)
            else:
                switches.append(control)
        if form.rowCount():
            page.addLayout(form)
        for switch in switches:
            page.addWidget(switch)
        if group == _ICONS_UNDER:
            page.addWidget(self.icons)
        page.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(body)
        return scroll

    def _control(self, setting: Setting, value: Value) -> QCheckBox | QComboBox:
        if setting.choices is None:
            switch = QCheckBox(setting.label)
            switch.setChecked(bool(value))
            self._controls[setting.key] = switch
            return switch

        choice = QComboBox()
        for option in setting.choices:
            choice.addItem(option.label, option)
        choice.setCurrentIndex(max(choice.findData(value), 0))
        choice.setFixedWidth(_CHOICE_WIDTH)
        self._controls[setting.key] = choice
        return choice

    # -- answering ---------------------------------------------------------

    def chosen(self) -> dict[str, Value]:
        """What the controls are showing now.

        Every setting, not only the ones touched. Reporting the rest as their
        defaults would quietly undo every preference on every visit to this
        dialog.
        """
        values: dict[str, Value] = {}
        for setting in prefs.EVERY:
            control = self._controls[setting.key]
            if isinstance(control, QComboBox):
                values[setting.key] = control.currentData()
            else:
                values[setting.key] = control.isChecked()
        return values

    def chosen_icons(self) -> dict[ActivityCategory, Picked]:
        """The kinds whose icon the reader changed, and to what: as the grid shows them."""
        return self.icons.values()

    def restore_defaults(self) -> None:
        """Fill the controls with what the settings start as, the icons included.

        Filled, not applied. Whether the window ever hears about it is still
        the reader's decision, taken with OK.
        """
        self.icons.restore_defaults()
        for setting, value in ((s, s.default) for s in prefs.EVERY):
            control = self._controls[setting.key]
            if isinstance(control, QComboBox):
                control.setCurrentIndex(control.findData(value))
            else:
                control.setChecked(bool(value))
