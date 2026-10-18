"""A search box whose understood filters become chips, and the list under it.

Both search boxes are this widget: the evidence panel's over one activity, and the
client list's over the whole case. What a token means is `logarc.search`'s; this
file only draws the query and takes it in.

A filter the box understood becomes a chip with its own ✕. That is the whole
point of drawing them: a reader can see at a glance which words were read as
filters, and a typo, which stays plain text, is visibly not one.

The list under the box is a child of the window rather than a popup window. A
popup takes the keyboard, and the reader is typing; and as a child it is in every
grab of the window, so it can be tested and photographed like anything else.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QEvent, QObject, QPoint, QRect, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QFontMetrics
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QLayout,
    QLayoutItem,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
    QWidgetItem,
)

from logarc.gui._qt import required
from logarc.gui.theme import mono_font
from logarc.search import Scope, Suggestion, suggestions, tokens, understood
from logarc.style import THEME

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from PyQt6.QtGui import QKeyEvent, QMoveEvent, QResizeEvent

__all__ = ["FilterBox", "SuggestionList"]

#: The words under the list, so the keys are discoverable from the list itself.
_KEYS_HINT: Final = "↑↓ to choose · Tab to complete · Esc to close"

#: Rows before the list scrolls rather than growing past the window.
_ROWS_SHOWN: Final = 10


class _Chip(QFrame):
    """One understood filter, with the button that takes it away.

    Laid out by hand: the key, the value, and the ✕ at the right. Squeezed, the
    value gives way with an ellipsis and the ✕ stays — a chip that could only be
    as wide as its words would make one long `path:` a minimum width the whole
    window had to pay, and a chip clipped at the right would lose its ✕.
    """

    removed = pyqtSignal(object)

    _LEFT: Final = 8
    _GAP: Final = 5
    _RIGHT: Final = 3

    def __init__(self, token: str) -> None:
        super().__init__()
        self.token = token
        self.setObjectName("chip")
        key, _, value = token.partition(":")
        self._value = value[1:-1] if len(value) > 1 and value[0] == value[-1] == '"' else value
        font = mono_font(8.5)
        self.key = QLabel(key, self)
        self.key.setFont(font)
        self.key.setStyleSheet(f"color:{THEME.muted}; background:transparent;")
        bold = mono_font(8.5)
        bold.setBold(True)
        self.value = QLabel(self._value, self)
        self.value.setFont(bold)
        self.value.setStyleSheet(f"color:{THEME.ink}; background:transparent;")
        self.value.setToolTip(html.escape(token))
        self.cross = QToolButton(self)
        self.cross.setText("✕")
        self.cross.setAutoRaise(True)
        self.cross.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cross.setAccessibleName(f"Remove {token}")
        self.cross.setToolTip(f"Remove {html.escape(token)}")
        self.cross.clicked.connect(lambda: self.removed.emit(self))
        self.setStyleSheet(
            f"#chip {{ background:{THEME.tint}; border:1px solid {THEME.accent};"
            " border-radius:9px; }"
            f" #chip QToolButton {{ color:{THEME.muted}; border:none; padding:0 2px; }}"
            f" #chip QToolButton:hover {{ color:{THEME.ink}; }}"
        )

    def _value_width(self) -> int:
        return self.value.fontMetrics().horizontalAdvance(self._value) + 2

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt's naming
        cross = self.cross.sizeHint()
        width = (
            self._LEFT
            + self.key.sizeHint().width()
            + self._GAP
            + self._value_width()
            + self._GAP
            + cross.width()
            + self._RIGHT
        )
        height = max(self.key.sizeHint().height(), cross.height()) + 2
        return QSize(width, height)

    def minimumSizeHint(self) -> QSize:  # noqa: N802 - Qt's naming
        """The key, an ellipsis, and the ✕."""
        hint = self.sizeHint()
        squeezed = self.value.fontMetrics().horizontalAdvance("…") + 2
        return QSize(hint.width() - self._value_width() + squeezed, hint.height())

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().resizeEvent(event)
        height = self.height()
        key = self.key.sizeHint()
        cross = self.cross.sizeHint()
        self.key.setGeometry(self._LEFT, (height - key.height()) // 2, key.width(), key.height())
        right = self.width() - self._RIGHT - cross.width()
        self.cross.setGeometry(right, (height - cross.height()) // 2, cross.width(), cross.height())
        left = self._LEFT + key.width() + self._GAP
        room = max(right - self._GAP - left, 0)
        metrics = self.value.fontMetrics()
        self.value.setText(metrics.elidedText(self._value, Qt.TextElideMode.ElideRight, room))
        self.value.setGeometry(left, (height - key.height()) // 2, room, key.height())


class _ChipFlow(QLayout):
    """Chips left to right, wrapping; the typing space takes the rest of the last line.

    The typing space is the last item. It is given whatever is left of the line
    the chips end on, and moves to a line of its own when that is less than
    `FilterBox.MIN_TYPING` — a box full of chips must still have room to type.
    """

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._items: list[QLayoutItem] = []
        self.setContentsMargins(4, 3, 4, 3)
        self.setSpacing(5)

    def addItem(self, item: QLayoutItem | None) -> None:  # noqa: N802 - Qt's naming
        if item is not None:
            self._items.append(item)

    def insert(self, index: int, widget: QWidget) -> None:
        """Put `widget` at `index`, ahead of the typing space.

        `addWidget` would append it after the typing space, and `addChildWidget`
        only adopts it: neither gives it a place in the line, so it is given one
        here, as an item of its own.
        """
        self.addChildWidget(widget)
        self._items.insert(index, QWidgetItem(widget))
        self.invalidate()

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int) -> QLayoutItem | None:  # noqa: N802 - Qt's naming
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int) -> QLayoutItem | None:  # noqa: N802 - Qt's naming
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self) -> Qt.Orientation:  # noqa: N802 - Qt's naming
        return Qt.Orientation.Horizontal

    def hasHeightForWidth(self) -> bool:  # noqa: N802 - Qt's naming
        return True

    def heightForWidth(self, width: int) -> int:  # noqa: N802 - Qt's naming
        return self._lay_out(QRect(0, 0, width, 0), place=False)

    def setGeometry(self, rect: QRect) -> None:  # noqa: N802 - Qt's naming
        super().setGeometry(rect)
        self._lay_out(rect, place=True)

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt's naming
        return self.minimumSize()

    def minimumSize(self) -> QSize:  # noqa: N802 - Qt's naming
        """The typing space, or one squeezed chip, on one line: never more.

        A chip's full width is not asked for. A minimum is a demand on the whole
        window, and one long `path:` would otherwise be one.
        """
        size = QSize(FilterBox.MIN_TYPING, 0)
        for item in self._items:
            size = size.expandedTo(QSize(item.minimumSize().width(), item.sizeHint().height()))
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _lay_out(self, rect: QRect, *, place: bool) -> int:
        margins = self.contentsMargins()
        left = rect.x() + margins.left()
        right = rect.x() + rect.width() - margins.right()
        x, y, line = left, rect.y() + margins.top(), 0
        if not self._items:
            return margins.top() + margins.bottom()
        *chips, typing = self._items
        for item in chips:
            hint = item.sizeHint()
            width = min(hint.width(), right - left)
            if x > left and x + width > right:
                x, y, line = left, y + line + self.spacing(), 0
            if place:
                item.setGeometry(QRect(x, y, width, hint.height()))
            x += width + self.spacing()
            line = max(line, hint.height())
        hint = typing.sizeHint()
        if x > left and right - x < FilterBox.MIN_TYPING:
            x, y, line = left, y + line + self.spacing(), 0
        height = max(line, hint.height())
        if place:
            typing.setGeometry(QRect(x, y, right - x, height))
        line = height
        return y + line + margins.bottom() - rect.y()


class SuggestionList(QFrame):
    """The list under a box: a title, the rows, and how to use them.

    `NoFocus` throughout, so a click on a row leaves the keyboard in the box.
    """

    chosen = pyqtSignal(object)
    """A row was clicked. Carries its `Suggestion`."""

    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("suggestions")
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setStyleSheet(
            f"#suggestions {{ background:{THEME.raised}; border:1px solid {THEME.edge};"
            " border-radius:4px; }"
        )
        self._rows: tuple[Suggestion, ...] = ()
        self._title = QLabel()
        self._title.setStyleSheet(f"color:{THEME.faint}; padding:2px 10px 4px 10px;")
        self._list = QListWidget()
        self._list.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._list.setFrameShape(QFrame.Shape.NoFrame)
        # A note is read whole or not at all: the list is made wide enough for
        # its rows (`_place`), and a scroll bar across would only take the room
        # the last row needs.
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setStyleSheet(
            "QListWidget { background:transparent; }"
            f" QListWidget::item {{ padding:3px 6px; color:{THEME.ink}; }}"
            f" QListWidget::item:selected {{ background:{THEME.tint}; }}"
        )
        self._list.itemClicked.connect(self._clicked)
        hint = QLabel(_KEYS_HINT)
        hint.setStyleSheet(f"color:{THEME.faint}; padding:4px 10px 2px 10px;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 6, 0, 6)
        layout.setSpacing(0)
        layout.addWidget(self._title)
        layout.addWidget(self._list)
        layout.addWidget(hint)
        self.hide()

    def show_rows(self, title: str, rows: Sequence[Suggestion], under: QWidget) -> None:
        """Fill the list and place it just below `under`, inside the window."""
        self._rows = tuple(rows)
        self._title.setText(title)
        self._list.clear()
        mono = mono_font(9)
        for row in self._rows:
            item = QListWidgetItem(f"{row.completion}   {row.note}")
            item.setFont(mono)
            if not row.selectable:
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)
                item.setForeground(required(self.palette(), "palette").placeholderText())
            self._list.addItem(item)
        first = next((index for index, row in enumerate(self._rows) if row.selectable), -1)
        self._list.setCurrentRow(first)
        row_height = max(self._list.sizeHintForRow(0), 1) if self._rows else 0
        self._list.setFixedHeight(row_height * min(len(self._rows), _ROWS_SHOWN) + 4)
        self._place(under)
        self.show()
        self.raise_()

    def _place(self, under: QWidget) -> None:
        host = required(self.parentWidget(), "window")
        corner = under.mapTo(host, QPoint(0, under.height() + 2))
        # As wide as its longest row, which in a narrow panel is wider than the
        # box: it then grows leftwards, over the canvas, rather than past the
        # window's edge. Never narrower than the box, never wider than the window.
        rows = self._list
        across = rows.sizeHintForColumn(0) + 2 * (self.frameWidth() + rows.frameWidth())
        # A character to spare. Fitted to the pixel, a row drawn at 125% came out
        # a pixel wider and lost its last characters to an ellipsis.
        if rows.count():
            across += QFontMetrics(required(rows.item(0), "row").font()).averageCharWidth()
        if rows.count() > _ROWS_SHOWN:
            across += required(rows.verticalScrollBar(), "scroll bar").sizeHint().width()
        width = max(under.width(), 320, across)
        width = min(width, host.width() - 4)
        self.setFixedWidth(width)
        self.adjustSize()
        x = min(corner.x(), host.width() - width - 2)
        self.move(max(x, 2), corner.y())

    def title(self) -> str:
        return self._title.text()

    def completions(self) -> list[str]:
        return [row.completion for row in self._rows]

    def current(self) -> Suggestion | None:
        index = self._list.currentRow()
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def step(self, direction: int) -> None:
        """Move to the next row that can be chosen, stopping at either end."""
        index = self._list.currentRow()
        while 0 <= index + direction < len(self._rows):
            index += direction
            if self._rows[index].selectable:
                self._list.setCurrentRow(index)
                return

    def choose(self, index: int) -> None:
        """Choose row `index`, as a click on it would."""
        if 0 <= index < len(self._rows) and self._rows[index].selectable:
            self.chosen.emit(self._rows[index])

    def _clicked(self, item: QListWidgetItem) -> None:
        self.choose(self._list.row(item))


class FilterBox(QFrame):
    """A query as chips and typed text, with suggestions under it."""

    #: The least room left to type in, however many chips there are.
    MIN_TYPING: Final = 120

    textChanged = pyqtSignal(str)  # noqa: N815 - named as QLineEdit's, which it replaces
    """The whole query, once per change."""

    def __init__(self, *, scope: Scope, placeholder: str, accessible_name: str) -> None:
        super().__init__()
        self._scope = scope
        self._placeholder = placeholder
        self._chips: list[_Chip] = []
        self._values: Mapping[str, Sequence[tuple[str, str]]] = {}
        self._values_title = "VALUES"
        self._last = ""
        self._list: SuggestionList | None = None
        self.setObjectName("filterBox")
        self.setProperty("focused", False)
        self.setStyleSheet(
            f"#filterBox {{ background:{THEME.surface}; border:1px solid {THEME.edge};"
            " border-radius:3px; }"
            f' #filterBox[focused="true"] {{ border:1px solid {THEME.accent}; }}'
        )
        policy = QSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

        self.edit = QLineEdit()
        self.edit.setFrame(False)
        self.edit.setFont(mono_font(self.edit.font().pointSizeF()))
        self.edit.setAccessibleName(accessible_name)
        self.edit.setStyleSheet("background:transparent;")
        self.edit.setPlaceholderText(placeholder)
        self.edit.textEdited.connect(self._edited)
        self.edit.installEventFilter(self)
        self._flow = _ChipFlow(self)
        self._flow.addWidget(self.edit)

    # -- what it holds -----------------------------------------------------------

    def text(self) -> str:
        parts = [chip.token for chip in self._chips]
        if self.edit.text().strip():
            parts.append(self.edit.text().strip())
        return " ".join(parts)

    def setText(self, text: str) -> None:  # noqa: N802 - named as QLineEdit's
        """Show `text`: every understood filter as a chip, the rest as typed."""
        for chip in list(self._chips):
            self._drop(chip)
        rest: list[str] = []
        for token in tokens(text):
            if understood(token, self._scope):
                self._add(token)
            else:
                rest.append(token)
        self.edit.setText(" ".join(rest))
        self._changed()

    def clear(self) -> None:
        self.setText("")

    def chips(self) -> tuple[str, ...]:
        return tuple(chip.token for chip in self._chips)

    def chip_widgets(self) -> tuple[QFrame, ...]:
        return tuple(self._chips)

    def chip_buttons(self) -> tuple[QToolButton, ...]:
        return tuple(chip.cross for chip in self._chips)

    def typed(self) -> str:
        return self.edit.text()

    def set_values(self, values: Mapping[str, Sequence[tuple[str, str]]], title: str) -> None:
        """What the list offers after `key:`, and what it calls them."""
        self._values = values
        self._values_title = title
        if self._list is not None and self._list.isVisible():
            self._suggest()

    @property
    def suggestion_list(self) -> SuggestionList:
        if self._list is None:
            self._list = SuggestionList(required(self.window(), "window"))
            self._list.chosen.connect(self._complete)
        return self._list

    # -- chips -------------------------------------------------------------------

    def _add(self, token: str) -> None:
        chip = _Chip(token)
        chip.removed.connect(self._remove)
        self._flow.insert(len(self._chips), chip)
        chip.show()
        self._chips.append(chip)

    def _drop(self, chip: _Chip) -> None:
        self._chips.remove(chip)
        self._flow.removeWidget(chip)
        chip.hide()
        chip.deleteLater()

    def _remove(self, chip: _Chip) -> None:
        self._drop(chip)
        self._changed()
        self.edit.setFocus()

    def _changed(self) -> None:
        self.edit.setPlaceholderText(
            self._placeholder if not self._chips else "add a filter, or type any text…"
        )
        self._flow.invalidate()
        self.updateGeometry()
        now = self.text()
        if now != self._last:
            self._last = now
            self.textChanged.emit(now)

    # -- typing ------------------------------------------------------------------

    def _edited(self, text: str) -> None:
        """Make chips of the filters the reader has moved past."""
        found = tokens(text)
        finished = found if text[-1:].isspace() and text.count('"') % 2 == 0 else found[:-1]
        kept = [token for token in finished if not understood(token, self._scope)]
        made = [token for token in finished if understood(token, self._scope)]
        if made:
            for token in made:
                self._add(token)
            tail = found[len(finished) :]
            self.edit.setText(" ".join(kept + tail) + (" " if kept and not tail else ""))
        self._changed()
        self._suggest()

    def _fragment(self) -> str:
        """The token the reader is in the middle of, or nothing after a space."""
        before = self.edit.text()[: self.edit.cursorPosition()]
        if not before or before[-1].isspace():
            return ""
        found = tokens(before)
        return found[-1] if found else ""

    def _suggest(self) -> None:
        if not self.edit.hasFocus() and self._list is None:
            return
        title, rows = suggestions(
            self._fragment(), self._scope, self._values, values_title=self._values_title
        )
        if rows:
            self.suggestion_list.show_rows(title, rows, self)
        elif self._list is not None:
            self._list.hide()

    def _complete(self, row: Suggestion) -> None:
        """Put `row` in place of the token being typed; a whole filter becomes a chip."""
        text = self.edit.text()
        cursor = self.edit.cursorPosition()
        fragment = self._fragment()
        head = text[: cursor - len(fragment)]
        tail = text[cursor:]
        if row.completion.endswith(":"):
            self.edit.setText(head + row.completion + tail)
            self.edit.setCursorPosition(len(head) + len(row.completion))
            self._changed()
        else:
            self.edit.setText((head + tail).strip())
            self._add(row.completion)
            self._changed()
        self.edit.setFocus()
        self._suggest()

    def _commit(self) -> None:
        """Enter: make a chip of the token being typed, if it is a whole filter."""
        fragment = self._fragment()
        if fragment and understood(fragment, self._scope):
            text = self.edit.text()
            cursor = self.edit.cursorPosition()
            self.edit.setText((text[: cursor - len(fragment)] + text[cursor:]).strip())
            self._add(fragment)
            self._changed()

    # -- keys and focus ----------------------------------------------------------

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        # Looked up, not assumed: at exit Python can let go of `edit` while Qt is
        # still delivering its last events, and an exception raised in here is
        # one PyQt answers by ending the process.
        if event is None or watched is not getattr(self, "edit", None):
            return False
        kind = event.type()
        if kind == QEvent.Type.FocusIn:
            self._focus(True)
            self._suggest()
        elif kind == QEvent.Type.FocusOut:
            self._focus(False)
            if self._list is not None:
                self._list.hide()
        elif kind == QEvent.Type.KeyPress:
            return self._key(event)  # type: ignore[arg-type]
        return False

    def _focus(self, focused: bool) -> None:
        self.setProperty("focused", focused)
        style = self.style()
        if style is not None:
            style.unpolish(self)
            style.polish(self)

    def _key(self, event: QKeyEvent) -> bool:
        key = event.key()
        showing = self._list is not None and self._list.isVisible()
        if showing and self._list is not None:
            if key == Qt.Key.Key_Down:
                self._list.step(1)
                return True
            if key == Qt.Key.Key_Up:
                self._list.step(-1)
                return True
            if key in (Qt.Key.Key_Tab, Qt.Key.Key_Return, Qt.Key.Key_Enter):
                current = self._list.current()
                if current is not None:
                    self._complete(current)
                    return True
            if key == Qt.Key.Key_Escape:
                self._list.hide()
                return True
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._commit()
            return True
        if key == Qt.Key.Key_Down:
            self._suggest()
            return True
        if (
            key == Qt.Key.Key_Backspace
            and self._chips
            and self.edit.cursorPosition() == 0
            and not self.edit.hasSelectedText()
        ):
            self._remove(self._chips[-1])
            return True
        return False

    # -- staying with the box ----------------------------------------------------

    def resizeEvent(self, event: QResizeEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().resizeEvent(event)
        if self._list is not None and self._list.isVisible():
            self._list._place(self)

    def moveEvent(self, event: QMoveEvent | None) -> None:  # noqa: N802 - Qt's naming
        super().moveEvent(event)
        if self._list is not None and self._list.isVisible():
            self._list._place(self)
