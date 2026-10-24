"""Preferences → Graph → Icons: one button per kind of activity, each its icon.

Like everything else in Preferences it decides nothing by itself: it holds the
reader's picks until the dialog is accepted, and hands them back. A file picked
from disk stays a path until then, so Cancel leaves nothing copied.
"""

from __future__ import annotations

from pathlib import Path
from types import EllipsisType
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from logarc.core.activity import ActivityCategory
from logarc.gui.icon_picker import IconPicker
from logarc.gui.icon_set import DEFAULT_ICONS, KIND_NAMES
from logarc.gui.icons import Picked, first_drawable, path_pixmap
from logarc.gui.theme import GAP, caption_font
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Mapping

    from PyQt6.QtGui import QPixmap

__all__ = ["KindIconGrid"]

_SHOWN: Final = 20
_EXPLAINED: Final = "One for each kind of activity, drawn on the graph. Click one to change it."


class KindIconGrid(QWidget):
    """Fourteen buttons, two columns, and Default icons under them."""

    def __init__(self, chosen: Mapping[ActivityCategory, str]) -> None:
        super().__init__()
        self._chosen: dict[ActivityCategory, Picked] = {
            kind: value for kind, value in chosen.items() if value != DEFAULT_ICONS[kind]
        }
        self.buttons: dict[ActivityCategory, QPushButton] = {}

        heading = QLabel("Icons")
        heading.setStyleSheet("font-weight: 600;")
        explained = QLabel(_EXPLAINED)
        explained.setWordWrap(True)
        explained.setFont(caption_font(explained.font()))
        explained.setStyleSheet(f"color: {THEME.muted};")

        grid = QGridLayout()
        grid.setHorizontalSpacing(GAP)
        grid.setVerticalSpacing(GAP // 2)
        for number, kind in enumerate(KIND_NAMES):
            # A push button, as everywhere else in the window: the house style
            # pads and rounds it, where a tool button drew its icon on the edge.
            button = QPushButton(KIND_NAMES[kind])
            button.setIconSize(QSize(_SHOWN, _SHOWN))
            button.setAutoDefault(False)
            button.setStyleSheet("text-align: left; padding-left: 10px;")
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.setToolTip(f"Change the icon for {KIND_NAMES[kind]}.")
            button.clicked.connect(lambda _checked=False, kind=kind: self._change(kind))
            self.buttons[kind] = button
            grid.addWidget(button, number // 2, number % 2)
            self._draw(kind)

        self.default_button = QPushButton("Default icons")
        self.default_button.setAutoDefault(False)
        self.default_button.setToolTip("Put every kind back to the icon it started with.")
        self.default_button.clicked.connect(self.restore_defaults)
        under = QHBoxLayout()
        under.addWidget(self.default_button)
        under.addStretch(1)

        column = QVBoxLayout(self)
        column.setContentsMargins(0, GAP, 0, 0)
        column.setSpacing(GAP // 2)
        column.addWidget(heading)
        column.addWidget(explained)
        column.addLayout(grid)
        column.addLayout(under)

    def values(self) -> dict[ActivityCategory, Picked]:
        """The kinds whose icon is not their own, and what each was given."""
        return dict(self._chosen)

    def restore_defaults(self) -> None:
        """Every kind back to its own icon. Shown, not applied: OK decides."""
        self._chosen.clear()
        for kind in KIND_NAMES:
            self._draw(kind)

    def _pick(self, kind: ActivityCategory) -> Picked | EllipsisType:
        """Ask the picker; `...` when the reader cancelled it."""
        picker = IconPicker(
            title=f"Icon for {KIND_NAMES[kind]}",
            current=self._chosen.get(kind),
            default=DEFAULT_ICONS[kind],
            parent=self,
        )
        if picker.exec() != int(IconPicker.DialogCode.Accepted.value):
            return ...
        return picker.choice

    def _change(self, kind: ActivityCategory) -> None:
        picked = self._pick(kind)
        if isinstance(picked, EllipsisType):
            return
        if picked is None or picked == DEFAULT_ICONS[kind]:
            self._chosen.pop(kind, None)
        else:
            self._chosen[kind] = picked
        self._draw(kind)

    def _draw(self, kind: ActivityCategory) -> None:
        button = self.buttons[kind]
        size = button.iconSize().width()
        button.setIcon(QIcon(self._pixmap(kind, size)))

    def _pixmap(self, kind: ActivityCategory, size: int) -> QPixmap:
        """The kind's icon as it would be drawn: a file not yet copied is drawn
        from where it is, and anything that does not draw shows the default."""
        picked = self._chosen.get(kind)
        if isinstance(picked, Path) and (drawn := path_pixmap(picked, size)) is not None:
            return drawn
        candidates = [picked] if isinstance(picked, str) else []
        return first_drawable([*candidates, DEFAULT_ICONS[kind]], THEME.ink, size)
