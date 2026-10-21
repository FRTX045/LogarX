"""The Bookmarks tab, and the dialog its categories are renamed and deleted in.

Every bookmark in the case, grouped by category in the order the categories were
made, newest first inside each, and one double-click from what it points at. The
tab only shows and asks: what a bookmark is, and what opening one does, belong to
`BookmarkKeeper` and the window.
"""

from __future__ import annotations

import html
from typing import TYPE_CHECKING

from PyQt6.QtCore import QModelIndex, QSize, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QKeyEvent, QPainter, QTextDocument
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from logarc.bookmarks import matches, newest_first
from logarc.core.window import EVERYTHING
from logarc.gui._qt import required
from logarc.gui.flow import FlowLayout
from logarc.gui.ribbon import ribbon_icon
from logarc.gui.theme import PAD, caption_font, colour_text, mono_font, on_font_change
from logarc.style import THEME, plural
from logarc.timerange import spoken

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.bookmarks import Bookmark, Shelf

__all__ = ["BookmarksTab", "CategoriesDialog"]

_ID = Qt.ItemDataRole.UserRole
#: The What cell's text, as rich text the delegate draws wrapped to the column.
_HTML = Qt.ItemDataRole.UserRole
_KIND, _WHAT, _CLIENT, _SAVED = range(4)
_ALL = "All categories"
_EMPTY_CASE = (
    "No bookmarks yet. Press Ctrl+D on a client, an activity or a log line to save it here."
)


def _what(bookmark: Bookmark, *, gone: bool) -> str:
    """What the bookmark says, then why it was saved; escaped, for it is all typed text."""
    said = bookmark.said or bookmark.client or bookmark.query or ""
    blocks = [f'<div style="color:{THEME.faint if gone else THEME.ink}">{html.escape(said)}</div>']
    if gone:
        blocks.append(f'<div style="color:{THEME.warning}">Not found in this case any more.</div>')
    if bookmark.note:
        blocks.append(f'<div style="color:{THEME.muted}"><i>{html.escape(bookmark.note)}</i></div>')
    return "".join(blocks)


class _WrappedText(QStyledItemDelegate):
    """Draws the What column wrapped to its width, and says how tall that makes a row.

    Measured at the column's own width, so a long note takes the lines it needs
    and a short one stays one line; the tree is told to measure again whenever a
    column changes width.
    """

    def __init__(self, tree: QTreeWidget) -> None:
        super().__init__(tree)
        self._tree = tree

    def _document(self, font: QFont, index: QModelIndex, width: int) -> QTextDocument:
        document = QTextDocument()
        document.setDefaultFont(font)
        document.setDocumentMargin(3)
        document.setHtml(index.data(_HTML) or "")
        document.setTextWidth(max(40, width))
        return document

    def paint(
        self, painter: QPainter | None, option: QStyleOptionViewItem, index: QModelIndex
    ) -> None:
        if painter is None or index.data(_HTML) is None:
            super().paint(painter, option, index)
            return
        styled = QStyleOptionViewItem(option)
        self.initStyleOption(styled, index)
        styled.text = ""
        style = styled.widget.style() if styled.widget is not None else QApplication.style()
        required(style, "style").drawControl(
            QStyle.ControlElement.CE_ItemViewItem, styled, painter, styled.widget
        )
        document = self._document(styled.font, index, styled.rect.width())
        painter.save()
        painter.translate(styled.rect.topLeft())
        document.drawContents(painter)
        painter.restore()

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:  # noqa: N802
        if index.data(_HTML) is None:
            return super().sizeHint(option, index)
        document = self._document(option.font, index, self._tree.columnWidth(index.column()))
        return QSize(int(document.idealWidth()), int(document.size().height()) + 2)


class _Tree(QTreeWidget):
    """The list, with Enter to open and Delete to remove."""

    open_key = pyqtSignal()
    delete_key = pyqtSignal()

    def measure_again(self) -> None:
        """Ask every row its height again, as a column's new width changes it.

        `doItemsLayout` is protected in Qt and absent from PyQt's stubs, but it is
        there on an instance of a Python subclass, which this is.
        """
        self.doItemsLayout()  # type: ignore[attr-defined]

    def keyPressEvent(self, event: QKeyEvent | None) -> None:  # noqa: N802 - Qt's naming
        if event is not None and event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.open_key.emit()
            return
        if event is not None and event.key() == Qt.Key.Key_Delete:
            self.delete_key.emit()
            return
        super().keyPressEvent(event)


class BookmarksTab(QWidget):
    """Every bookmark in the case, by category."""

    open_requested = pyqtSignal(str)
    edit_requested = pyqtSignal(str)
    remove_requested = pyqtSignal(str)
    categories_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self._shelf: Shelf | None = None
        # Which bookmarks point at nothing now, by id: kept as data rather
        # than as the caller's function, which would tie this tab to it.
        self._gone: frozenset[str] = frozenset()

        self.notice = QLabel()
        self.notice.setTextFormat(Qt.TextFormat.PlainText)
        self.notice.setWordWrap(True)
        self.notice.setStyleSheet(
            f"background:{THEME.raised}; color:{THEME.warning};"
            f" border-left:3px solid {THEME.warning}; padding:4px 8px;"
        )
        self.notice.hide()

        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter bookmarks\N{HORIZONTAL ELLIPSIS}")
        self.filter.setAccessibleName("Filter bookmarks")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(lambda _text: self._fill())
        self.category = QComboBox()
        self.category.setAccessibleName("Category")
        self.category.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.category.setMinimumContentsLength(14)
        # Fourteen characters when there is room, about eight when the column
        # is dragged narrow: the tab's minimum is the whole workspace's.
        self._fit_category()
        on_font_change(self.category, self._fit_category)
        self.category.currentTextChanged.connect(lambda _text: self._fill())
        categories = QPushButton("Categories\N{HORIZONTAL ELLIPSIS}")
        categories.clicked.connect(self.categories_requested.emit)

        self.caption = QLabel()
        # Wrapped, as the client list's is: unwrapped, a caption sets the
        # narrowest the middle of the window can be.
        self.caption.setWordWrap(True)
        self.caption.setFont(caption_font(self.caption.font()))
        colour_text(self.caption, THEME.muted)
        self.empty = QLabel()
        self.empty.setTextFormat(Qt.TextFormat.PlainText)
        self.empty.setWordWrap(True)
        self.empty.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        colour_text(self.empty, THEME.muted)
        self.empty.hide()

        self.tree = _Tree()
        self.tree.setColumnCount(4)
        self.tree.setHeaderLabels(["Kind", "What", "Client", "Saved"])
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        self.tree.setUniformRowHeights(False)
        self.tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.tree.setItemDelegateForColumn(_WHAT, _WrappedText(self.tree))
        header = required(self.tree.header(), "bookmark list header")
        header.setFont(caption_font(self.tree.font()))
        header.setStretchLastSection(False)
        for column, mode in (
            (_KIND, QHeaderView.ResizeMode.ResizeToContents),
            (_WHAT, QHeaderView.ResizeMode.Stretch),
            (_CLIENT, QHeaderView.ResizeMode.ResizeToContents),
            (_SAVED, QHeaderView.ResizeMode.ResizeToContents),
        ):
            header.setSectionResizeMode(column, mode)
        # A wrapped row's height depends on its column's width. A bound method:
        # Qt made this header, and a lambda on it would keep the tab for good.
        header.sectionResized.connect(self._column_resized)
        self.tree.itemDoubleClicked.connect(lambda item, _column: self._open(item))
        self.tree.currentItemChanged.connect(lambda *_: self._update_buttons())
        self.tree.open_key.connect(lambda: self._open(self.tree.currentItem()))
        self.tree.delete_key.connect(self._remove)

        self.open_button = QPushButton("Open")
        self.edit_button = QPushButton("Edit\N{HORIZONTAL ELLIPSIS}")
        self.remove_button = QPushButton("Remove")
        self.open_button.clicked.connect(lambda: self._open(self.tree.currentItem()))
        self.edit_button.clicked.connect(self._edit)
        self.remove_button.clicked.connect(self._remove)
        hint = QLabel("Double-click to open \N{MIDDLE DOT} Delete removes")
        hint.setFont(caption_font(hint.font()))
        # Given only the room the buttons leave, so in a narrow column the hint
        # gives way rather than setting the width of the whole middle of the
        # window: a tab page's minimum is every page's minimum. Not wrapped: a
        # hint squeezed to a few pixels and wrapped stands a word to a line.
        hint.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        colour_text(hint, THEME.faint)

        top = QHBoxLayout()
        top.addWidget(self.filter, 1)
        top.addWidget(self.category)
        top.addWidget(categories)
        # In one row on the right while there is room, wrapping when there is
        # not: three buttons side by side were wider than the narrowest middle
        # column on Linux, measured 264 against 252.
        buttons = QWidget()
        row = FlowLayout(buttons, spacing=PAD, right=True, one_row=True)
        row.setContentsMargins(0, 0, 0, 0)
        for button in (self.open_button, self.edit_button, self.remove_button):
            row.addWidget(button)
        bottom = QHBoxLayout()
        bottom.addWidget(hint, 1)
        bottom.addWidget(buttons)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(PAD, PAD, PAD, PAD)
        layout.setSpacing(PAD)
        layout.addWidget(self.notice)
        layout.addLayout(top)
        layout.addWidget(self.caption)
        layout.addWidget(self.tree, 1)
        layout.addWidget(self.empty, 1)
        layout.addLayout(bottom)
        self._update_buttons()

    def _fit_category(self) -> None:
        self.category.setMinimumWidth(self.category.fontMetrics().averageCharWidth() * 8)

    def _column_resized(self, _index: int, _old: int, _new: int) -> None:
        self.tree.measure_again()

    # -- what is shown -----------------------------------------------------------

    def show_shelf(self, shelf: Shelf, *, gone: Callable[[Bookmark], bool]) -> None:
        """Show `shelf`; `gone` says which bookmarks point at nothing in the case now."""
        self._shelf = shelf
        self._gone = frozenset(b.id for b in shelf.bookmarks if gone(b))
        chosen = self.category.currentText()
        blocked = self.category.blockSignals(True)
        self.category.clear()
        self.category.addItems([_ALL, *(c.name for c in shelf.categories)])
        self.category.setCurrentText(chosen if self.category.findText(chosen) >= 0 else _ALL)
        self.category.blockSignals(blocked)
        self._fill()

    def count(self) -> int:
        return len(self._shelf.bookmarks) if self._shelf is not None else 0

    def set_notice(self, text: str | None) -> None:
        """Say something about the bookmarks file itself, or take it away."""
        self.notice.setText(text or "")
        self.notice.setVisible(bool(text))

    def _fill(self) -> None:
        shelf = self._shelf
        kept = self._selected()
        self.tree.clear()
        if shelf is None:
            return
        words = self.filter.text().strip()
        only = self.category.currentText()
        bold = QFont(self.tree.font())
        bold.setBold(True)
        mono = mono_font(self.tree.font().pointSizeF())
        shown = 0
        for category in shelf.categories:
            if only not in (_ALL, "") and category.name != only:
                continue
            members = newest_first(
                b for b in shelf.bookmarks if b.category == category.name and matches(b, words)
            )
            if not members:
                continue
            heading = QTreeWidgetItem([f"{category.name}   {len(members)}"])
            heading.setIcon(_KIND, ribbon_icon(shelf.colour_of(category.name)))
            heading.setFont(_KIND, bold)
            heading.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.tree.addTopLevelItem(heading)
            heading.setFirstColumnSpanned(True)
            heading.setExpanded(True)
            for bookmark in members:
                gone = bookmark.id in self._gone
                window = bookmark.range if bookmark.range is not None else EVERYTHING
                item = QTreeWidgetItem(
                    heading,
                    [
                        bookmark.kind.value.title(),
                        "",
                        bookmark.client if bookmark.client is not None else spoken(window),
                        bookmark.saved.strftime("%d %b %H:%M"),
                    ],
                )
                item.setData(_KIND, _ID, bookmark.id)
                item.setData(_WHAT, _HTML, _what(bookmark, gone=gone))
                item.setFont(_CLIENT, mono)
                for column, colour in (
                    (_KIND, THEME.muted),
                    (_CLIENT, THEME.identity),
                    (_SAVED, THEME.muted),
                ):
                    item.setForeground(column, QBrush(QColor(THEME.faint if gone else colour)))
                    item.setTextAlignment(
                        column, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
                    )
                if bookmark.id == kept:
                    self.tree.setCurrentItem(item)
                shown += 1
        total = len(shelf.bookmarks)
        self._say(shown=shown, total=total, words=words, only=only)
        self._update_buttons()

    def _say(self, *, shown: int, total: int, words: str, only: str) -> None:
        narrowed = bool(words) or only not in (_ALL, "")
        if total == 0:
            self.caption.setText("")
            self.empty.setText(_EMPTY_CASE)
        elif shown == 0:
            self.caption.setText(f"0 of {plural(total, 'bookmark')} match")
            self.empty.setText(
                f"No bookmark matches {words}." if words else f"No bookmark in {only}."
            )
        elif narrowed:
            self.caption.setText(f"{shown} of {plural(total, 'bookmark')} match")
        else:
            used = len({b.category for b in self._shelf.bookmarks}) if self._shelf else 0
            self.caption.setText(
                f"{plural(total, 'bookmark')} in {plural(used, 'category', 'categories')}"
            )
        self.tree.setVisible(shown > 0)
        self.empty.setVisible(shown == 0)

    # -- acting on one ----------------------------------------------------------------

    def _selected(self) -> str | None:
        item = self.tree.currentItem()
        ident = item.data(_KIND, _ID) if item is not None else None
        return ident if isinstance(ident, str) else None

    def _bookmark(self, ident: str | None) -> Bookmark | None:
        if ident is None or self._shelf is None:
            return None
        return self._shelf.by_id(ident)

    def _update_buttons(self) -> None:
        bookmark = self._bookmark(self._selected())
        self.open_button.setEnabled(bookmark is not None and bookmark.id not in self._gone)
        self.edit_button.setEnabled(bookmark is not None)
        self.remove_button.setEnabled(bookmark is not None)

    def _open(self, item: QTreeWidgetItem | None) -> None:
        ident = item.data(_KIND, _ID) if item is not None else None
        bookmark = self._bookmark(ident if isinstance(ident, str) else None)
        if bookmark is not None and bookmark.id not in self._gone:
            self.open_requested.emit(bookmark.id)

    def _edit(self) -> None:
        ident = self._selected()
        if ident is not None:
            self.edit_requested.emit(ident)

    def _remove(self) -> None:
        ident = self._selected()
        if ident is not None:
            self.remove_requested.emit(ident)


class CategoriesDialog(QDialog):
    """Rename and delete categories. The first can be renamed, never deleted."""

    rename_requested = pyqtSignal(str, str)
    delete_requested = pyqtSignal(str)

    def __init__(self, parent: QWidget | None, shelf: Shelf) -> None:
        super().__init__(parent)
        self.setWindowTitle("Bookmark categories")
        self.names = QListWidget()
        self.names.currentRowChanged.connect(self._chosen)
        self.new_name = QLineEdit()
        self.new_name.setAccessibleName("New name")
        self.rename_button = QPushButton("Rename")
        self.delete_button = QPushButton("Delete")
        self.rename_button.clicked.connect(self._rename)
        self.delete_button.clicked.connect(self._delete)
        self.error = QLabel()
        self.error.setTextFormat(Qt.TextFormat.PlainText)
        self.error.setWordWrap(True)
        colour_text(self.error, THEME.alert)
        self.error.hide()
        self.delete_button.setToolTip(
            "Deleting a category moves its bookmarks to the first one, which cannot be deleted."
        )
        close = QPushButton("Close")
        close.clicked.connect(self.accept)

        rename = QHBoxLayout()
        rename.addWidget(self.new_name, 1)
        rename.addWidget(self.rename_button)
        rename.addWidget(self.delete_button)
        layout = QVBoxLayout(self)
        layout.addWidget(self.names, 1)
        layout.addLayout(rename)
        layout.addWidget(self.error)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)
        self.resize(380, 340)
        self.show_shelf(shelf)

    def show_shelf(self, shelf: Shelf) -> None:
        row = max(0, self.names.currentRow())
        blocked = self.names.blockSignals(True)
        self.names.clear()
        for category in shelf.categories:
            item = QListWidgetItem(ribbon_icon(shelf.colour_of(category.name)), category.name)
            self.names.addItem(item)
        self.names.blockSignals(blocked)
        self.names.setCurrentRow(min(row, self.names.count() - 1))
        self._chosen(self.names.currentRow())

    def show_error(self, text: str) -> None:
        self.error.setText(text)
        self.error.show()

    def _name(self) -> str | None:
        item = self.names.currentItem()
        return item.text() if item is not None else None

    def _chosen(self, row: int) -> None:
        self.error.hide()
        name = self._name()
        self.new_name.setText(name or "")
        self.rename_button.setEnabled(name is not None)
        self.delete_button.setEnabled(name is not None and row > 0)

    def _rename(self) -> None:
        name = self._name()
        if name is not None:
            self.rename_requested.emit(name, self.new_name.text())

    def _delete(self) -> None:
        name = self._name()
        if name is not None and self.names.currentRow() > 0:
            self.delete_requested.emit(name)
