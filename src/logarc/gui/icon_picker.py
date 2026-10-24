"""Pick an icon: search the shipped set, or take an image of the reader's own.

Shared by Preferences, for a whole kind, and Add rule, for one rule. It applies
nothing itself: it hands back what was picked, and a file of the reader's is
copied in only when whoever opened it applies the choice, so Cancel anywhere
leaves nothing behind.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QModelIndex, QSize, Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import required
from logarc.gui.icon_set import FILE_PREFIX, search
from logarc.gui.icons import Picked, icon_file_problem, icon_pixmap, path_pixmap
from logarc.gui.theme import GAP, ROOM, settle_buttons
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Iterable

    from PyQt6.QtGui import QShowEvent

__all__ = ["IconPicker"]

#: How big an icon is shown in the grid, and the cell each one sits in with its
#: name under it.
_SHOWN: Final = 32
_CELL: Final = QSize(104, 76)

_YOUR_IMAGE: Final = "Your image"


class _Drawn(QStyledItemDelegate):
    """Draws an icon as its cell comes into view, not all 1,533 on opening."""

    def initStyleOption(  # noqa: N802 - Qt's naming
        self, option: QStyleOptionViewItem | None, index: QModelIndex
    ) -> None:
        super().initStyleOption(option, index)
        if option is None:  # pragma: no cover - Qt always passes one
            return
        ratio = option.widget.devicePixelRatioF() if option.widget is not None else 1.0
        value = index.data(Qt.ItemDataRole.UserRole)
        size = round(_SHOWN * ratio)
        pixmap = (
            path_pixmap(value, size)
            if isinstance(value, Path)
            else icon_pixmap(str(value), THEME.ink, size)
        )
        if pixmap is None:
            return
        pixmap.setDevicePixelRatio(ratio)
        option.icon = QIcon(pixmap)
        option.features |= QStyleOptionViewItem.ViewItemFeature.HasDecoration
        option.decorationSize = QSize(_SHOWN, _SHOWN)


class IconPicker(QDialog):
    """The icons there are, searchable, with Default and From file… beside OK."""

    def __init__(
        self,
        *,
        title: str,
        current: Picked,
        default: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 480)
        self._default = default
        self._choice: Picked = current
        # A file of the reader's on offer: the current one, or one just taken.
        self._own: str | Path | None = current if _is_own(current) else None

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search icons")
        self.search.setClearButtonEnabled(True)
        self.grid = QListWidget()
        self.grid.setViewMode(QListView.ViewMode.IconMode)
        self.grid.setMovement(QListView.Movement.Static)
        self.grid.setResizeMode(QListView.ResizeMode.Adjust)
        self.grid.setUniformItemSizes(True)
        self.grid.setGridSize(_CELL)
        self.grid.setIconSize(QSize(_SHOWN, _SHOWN))
        self.grid.setWordWrap(True)
        self.grid.setItemDelegate(_Drawn(self.grid))
        self.note = QLabel()
        self.note.setWordWrap(True)
        self.note.setStyleSheet(f"color: {THEME.alert};")
        self.note.hide()

        self.default_button = QPushButton("Default")
        self.default_button.setToolTip(f"Go back to {default}, the icon this starts with.")
        self.default_button.setAutoDefault(False)
        self.file_button = QPushButton("From file…")
        self.file_button.setToolTip("Use an SVG or PNG image of your own, up to 1 MB.")
        self.file_button.setAutoDefault(False)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        settle_buttons(buttons)

        column = QVBoxLayout(self)
        column.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        column.setSpacing(GAP)
        column.addWidget(self.search)
        column.addWidget(self.grid, 1)
        column.addWidget(self.note)
        row = QHBoxLayout()
        row.addWidget(self.default_button)
        row.addWidget(self.file_button)
        row.addStretch(1)
        row.addWidget(buttons)
        column.addLayout(row)

        self._fill(search(""))
        self.grid.currentItemChanged.connect(self._picked)
        self.grid.itemActivated.connect(self._taken)
        self.search.textChanged.connect(lambda text: self._fill(search(text)))
        self.default_button.clicked.connect(self._to_default)
        self.file_button.clicked.connect(self._from_file)

    def showEvent(self, event: QShowEvent | None) -> None:  # noqa: N802 - Qt's naming
        """Bring the chosen icon into view now the grid has its size.

        Scrolled to before, it lands wherever a grid not yet laid out thinks the
        middle is, which was the bottom row.
        """
        super().showEvent(event)
        if (item := self.grid.currentItem()) is not None:
            self.grid.scrollToItem(item, QListView.ScrollHint.PositionAtCenter)

    @property
    def choice(self) -> Picked:
        """A Lucide name, an image of the reader's, or None for the default."""
        return self._choice

    # -- the grid -------------------------------------------------------------

    def _fill(self, names: Iterable[str]) -> None:
        """Offer `names`, in the order given, after the reader's own image if any."""
        self.grid.blockSignals(True)
        self.grid.clear()
        if self._own is not None:
            self._add(_YOUR_IMAGE, self._own)
        for name in names:
            self._add(name, name)
        self.grid.blockSignals(False)
        self._show_choice()

    def _add(self, text: str, value: str | Path) -> None:
        item = QListWidgetItem(text)
        item.setData(Qt.ItemDataRole.UserRole, value)
        item.setToolTip(text if isinstance(value, Path) else str(value))
        self.grid.addItem(item)

    def _show_choice(self) -> None:
        """Select what is chosen, or what Default stands for, if it is on offer."""
        wanted = self._default if self._choice is None else self._choice
        for row in range(self.grid.count()):
            item = required(self.grid.item(row), "item")
            if item.data(Qt.ItemDataRole.UserRole) == wanted:
                self.grid.blockSignals(True)
                self.grid.setCurrentItem(item)
                self.grid.blockSignals(False)
                self.grid.scrollToItem(item, QListView.ScrollHint.PositionAtCenter)
                return

    def _picked(self, item: QListWidgetItem | None) -> None:
        if item is not None:
            self._choice = item.data(Qt.ItemDataRole.UserRole)

    def _taken(self, item: QListWidgetItem) -> None:
        self._picked(item)
        self.accept()

    # -- the buttons ----------------------------------------------------------

    def _to_default(self) -> None:
        self._choice = None
        self.note.hide()
        self._show_choice()

    def _ask_for_file(self) -> Path | None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Use an image", "", "Images (*.svg *.png)")
        return Path(chosen) if chosen else None

    def _from_file(self) -> None:
        path = self._ask_for_file()
        if path is None:
            return
        if problem := icon_file_problem(path):
            self.note.setText(problem)
            self.note.show()
            return
        self.note.hide()
        self._own = path
        self._choice = path
        self._fill(search(self.search.text()))


def _is_own(value: Picked) -> bool:
    """Whether `value` is an image of the reader's rather than a shipped icon."""
    return isinstance(value, Path) or (isinstance(value, str) and value.startswith(FILE_PREFIX))
