"""Where a reader writes a log format, and tries it before saving it.

Two screens, one file, because they are two views of the same list: the editor
writes into the library and the chooser reads from it, and a saved format has
to be offerable the instant it is written or the reader has to restart the
application to use what they just made.

The shape is a list on the left and one format on the right, with a pasted log
line under it and the fields that came out of it beneath that. It was chosen
over the alternative of pointing at parts of a pasted line and naming them:
that guesses, and a guess that is nearly right is worse here than no guess at
all — the reader accepts it, and finds out at ingest. Seeing the rule and its
result side by side never claims more than it can show.

**Built-ins are shown and cannot be edited.** Registration order is preference
order, so an edited copy of `apache-combined` would never be reached, and a
case recording that name would quietly begin to mean something else. They stay
selectable because trying a preset against your own log is the first thing
worth doing and the cheapest.

The judgement lives in `gui.format_preview`, which is free of Qt and tested
without a display. What is here is the arranging of it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import required
from logarc.gui.format_preview import preview
from logarc.gui.style import THEME
from logarc.gui.theme import GAP, ROOM, caption_font
from logarc.parsers.library import FormatLibraryError, load_library, save_library
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.registry import (
    available_formats,
    get_spec,
    is_built_in,
    register_saved_formats,
)
from logarc.parsers.spec import LogFormatSpec

if TYPE_CHECKING:
    from logarc.gui.format_preview import Preview
    from logarc.parsers.spec import FormatSpec

__all__ = ["FormatChoice", "FormatEditor"]

#: Room for a combined directive on one line without wrapping, measured against
#: `apache-vhost-combined`, which is the longest thing this has to show.
_WIDTH = 820

#: Tall enough to open with every field of the preview in sight, measured
#: rather than guessed: eleven rows at `_ROW` plus the fields above them.
_HEIGHT = 700

_ROW = 26

_DETECT = "Detect automatically"

#: The first row of the list, and the reason there is no "nothing is selected"
#: state to get wrong. `QListWidget` makes row 0 current the first time it is
#: shown if nothing is — measured, by watching it overwrite a half-written
#: format — so a list whose row 0 is a real format silently discards what the
#: reader has typed. A list whose row 0 *is* the blank form cannot.
_NEW = "New format…"

_BUILT_IN_HEADING = "Built in"
_SAVED_HEADING = "Saved by you"

#: The rows of the list that are not formats. A format named after one of them
#: would be picked up by the wrong branch of `_on_selected` and edited as
#: something it is not, so the names are refused on the way in.
_RESERVED = frozenset({_NEW, _BUILT_IN_HEADING, _SAVED_HEADING})

_SAMPLE_HINT = (
    "Paste one line from your log here.\nCopy it exactly, including the quotes and brackets."
)


def _saved() -> list[FormatSpec]:
    """The library, or an empty one when it cannot be read.

    A damaged file is a thing to report where it can be acted on — the CLI says
    so on every command — not a reason for this screen to refuse to open. A
    reader who has broken their library needs somewhere to write a new format,
    and this is that somewhere.
    """
    try:
        return load_library()
    except FormatLibraryError:
        return []


class FormatEditor(QDialog):
    """The library of log formats: read a built-in, write your own, try both."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Log formats")
        self.setMinimumWidth(_WIDTH)
        self.resize(_WIDTH, _HEIGHT)

        self._editing: str | None = None
        self._trouble = ""

        self._formats = QListWidget()
        self._formats.setMaximumWidth(220)
        self._formats.currentTextChanged.connect(self._on_selected)
        self._headings: set[int] = set()

        self._name = QLineEdit()
        self._name.setPlaceholderText("A name you will recognise later")

        self._directive = QLineEdit()
        self._directive.setPlaceholderText('%h %l %u %t "%r" %>s %b')
        self._directive.textChanged.connect(self._refresh_preview)

        self._note = QLineEdit()
        self._note.setPlaceholderText("What this format is for (optional)")

        self._sample = QPlainTextEdit()
        self._sample.setPlaceholderText(_SAMPLE_HINT)
        self._sample.setFixedHeight(64)
        self._sample.textChanged.connect(self._refresh_preview)

        self._fields = QTableWidget(0, 2)
        self._fields.setHorizontalHeaderLabels(["Field", "Read from the line"])
        required(self._fields.verticalHeader()).setVisible(False)
        self._fields.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        # The value column takes the rest of the width. Left at its content
        # width it stopped after the longest short value, leaving half the
        # table empty and a long user agent clipped in the same picture.
        heads = required(self._fields.horizontalHeader())
        heads.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        heads.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # Tight rows so all eleven fields are in sight at the opening size.
        # At Qt's default only seven were, and the four out of view are the
        # ones a custom format most often gets wrong — referer, user agent,
        # host, and the byte count.
        required(self._fields.verticalHeader()).setDefaultSectionSize(_ROW)

        self._status = QLabel("")
        self._status.setWordWrap(True)
        self._status.setFont(caption_font(self._status.font()))

        self._delete = QPushButton("Delete")
        self._delete.clicked.connect(self.delete)
        self._save = QPushButton("Save")
        self._save.clicked.connect(self.save)

        self._build(parent_layout=QHBoxLayout(self))
        self._reload()

    # -- assembling --------------------------------------------------------

    def _build(self, parent_layout: QHBoxLayout) -> None:
        parent_layout.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        parent_layout.setSpacing(GAP)

        left = QVBoxLayout()
        left.setSpacing(GAP // 2)
        left.addWidget(self._labelled("Formats"))
        left.addWidget(self._formats, 1)

        right = QVBoxLayout()
        right.setSpacing(GAP // 2)
        for caption, field in (
            ("Name", self._name),
            ("LogFormat directive", self._directive),
            ("Note", self._note),
        ):
            right.addWidget(self._labelled(caption))
            right.addWidget(field)
        right.addWidget(self._labelled("A line from your log"))
        right.addWidget(self._sample)
        right.addWidget(self._status)
        right.addWidget(self._fields, 1)

        buttons = QDialogButtonBox()
        buttons.addButton(self._delete, QDialogButtonBox.ButtonRole.DestructiveRole)
        buttons.addButton(self._save, QDialogButtonBox.ButtonRole.AcceptRole)
        close = buttons.addButton(QDialogButtonBox.StandardButton.Close)
        if close is not None:
            close.clicked.connect(self.reject)
        right.addWidget(buttons)

        parent_layout.addLayout(left)
        parent_layout.addLayout(right, 1)

    def _labelled(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setFont(caption_font(label.font()))
        label.setStyleSheet(f"color: {THEME.muted};")
        return label

    # -- what the tests and the window ask -------------------------------

    def listed(self) -> list[str]:
        """Every format on the left, in the order they are offered.

        Without the blank-form row and the two group headings, which are
        entries in the widget and not formats.
        """
        items = [
            self._formats.item(row)
            for row in range(self._formats.count())
            if row not in self._headings
        ]
        return [item.text() for item in items if item is not None and item.text() != _NEW]

    def editing(self) -> str | None:
        """The saved format being edited, or `None` for a new or built-in one."""
        return self._editing

    def trouble(self) -> str:
        """Why the last save was refused. Empty when nothing was refused."""
        return self._trouble

    def preview(self) -> Preview:
        """What the directive currently reads out of the pasted line."""
        return preview(self._directive.text(), self._sample.toPlainText())

    # -- moving around the list ------------------------------------------

    def select(self, name: str) -> None:
        """Load `name` into the fields on the right."""
        matches = self._formats.findItems(name, Qt.MatchFlag.MatchExactly)
        if matches:
            self._formats.setCurrentItem(matches[0])
        else:  # pragma: no cover - only reachable if the list went stale
            self._on_selected(name)

    def start_new(self) -> None:
        """Clear the right-hand side for a format that does not exist yet."""
        self._formats.setCurrentRow(0)
        self._blank()

    def _blank(self) -> None:
        self._editing = None
        self._trouble = ""
        self._name.clear()
        self._directive.clear()
        self._note.clear()
        self._set_editable(True)
        self._refresh_preview()

    def _on_selected(self, name: str) -> None:
        if not name:
            return
        if name == _NEW:
            self._blank()
            return
        try:
            spec = get_spec(name)
        except LookupError:  # pragma: no cover - the list is built from the registry
            return
        if spec is None:
            # Registered from a factory: there is code behind the name and no
            # definition to show, let alone edit.
            self._editing = None
            self._name.setText(name)
            self._directive.clear()
            self._note.clear()
            self._set_editable(False)
            self._refresh_preview()
            return

        self._editing = name if self._is_saved(name) else None
        self._name.setText(spec.name)
        self._directive.setText(spec.summary)
        self._note.setText(spec.description)
        self._set_editable(self._is_saved(name))
        self._refresh_preview()

    def _is_saved(self, name: str) -> bool:
        return name in available_formats() and not is_built_in(name)

    def _set_editable(self, editable: bool) -> None:
        for field in (self._name, self._directive, self._note):
            field.setEnabled(editable)
        self._save.setEnabled(editable)
        self._delete.setEnabled(editable and self._editing is not None)
        # Never disabled. Trying a built-in against your own log is reading,
        # not editing, and it is the first useful thing a reader can do here.
        self._sample.setEnabled(True)

    # -- writing ----------------------------------------------------------

    def save(self) -> bool:
        """Write what is on the right into the library. False if refused."""
        self._trouble = ""
        name = self._name.text().strip()
        if not name:
            return self._refuse("Give this format a name.")
        if name in _RESERVED:
            return self._refuse(f"{name!r} is what the list beside this calls one of its own rows.")

        saved = _saved()
        if is_built_in(name):
            return self._refuse(
                f"{name!r} is a built-in format. Built-ins are matched first, so a "
                "saved format of the same name would never be reached."
            )

        spec = LogFormatSpec(
            name=name, directive=self._directive.text(), description=self._note.text().strip()
        )
        try:
            spec.build()
        except LogFormatError as exc:
            return self._refuse(str(exc))

        # Replace by name rather than by position, so renaming a format while
        # editing it adds the new one and leaves the old, which is what the
        # reader asked for by changing the name rather than pressing Delete.
        kept = [item for item in saved if item.name not in {name, self._editing}]
        try:
            save_library([*kept, spec])
        except FormatLibraryError as exc:
            return self._refuse(str(exc))

        # Registered here, not at the next launch: a format that is in the file
        # and absent from every list offering it is one the reader cannot use.
        register_saved_formats()
        self._reload()
        self.select(name)
        return True

    def delete(self) -> None:
        """Forget the saved format on the right.

        Cases already ingested with it are unaffected — each carries its own
        copy of the definition — so this needs no confirmation about evidence.
        """
        if self._editing is None:
            return
        save_library([spec for spec in _saved() if spec.name != self._editing])
        register_saved_formats()
        self._editing = None
        self._reload()
        self.start_new()

    def _refuse(self, why: str) -> bool:
        self._trouble = why
        self._status.setText(why)
        return False

    # -- keeping the screen current --------------------------------------

    def _reload(self) -> None:
        """Rebuild the list, grouped, and land on something sensible.

        Reconciles the registry with the library file first, so the list agrees
        with what is on disk however it got there — `logarc formats add`, a
        second window, or an editor. `register_saved_formats` removes what a
        previous call installed as well as adding, so a format deleted
        elsewhere stops being offered rather than lingering under a live name.

        Grouped because the two halves are not the same kind of thing: one
        ships with logarc and cannot be edited, the other is the reader's and
        can. Told apart only by what happens when you click them, the reader
        finds that out by being refused.
        """
        register_saved_formats()
        current = self._name.text()
        built_in = [name for name in available_formats() if is_built_in(name)]
        saved = [name for name in available_formats() if not is_built_in(name)]

        self._formats.blockSignals(True)
        self._formats.clear()
        self._headings.clear()
        self._formats.addItem(_NEW)
        for heading, names in ((_BUILT_IN_HEADING, built_in), (_SAVED_HEADING, saved)):
            if not names:
                continue
            self._headings.add(self._formats.count())
            self._formats.addItem(self._heading_item(heading))
            self._formats.addItems(names)
        self._formats.blockSignals(False)

        if current in available_formats():
            self.select(current)
        else:
            # Deliberately, rather than leaving it to the widget: see `_NEW`.
            self._formats.setCurrentRow(0)
            self._blank()

    def _heading_item(self, text: str) -> QListWidgetItem:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        item.setFont(caption_font(item.font()))
        item.setForeground(QColor(THEME.faint))
        return item

    def _refresh_preview(self) -> None:
        result = self.preview()
        self._status.setText(self._trouble or result.status)
        self._fields.setRowCount(len(result.fields))
        for row, (field, value) in enumerate(result.fields):
            self._fields.setItem(row, 0, QTableWidgetItem(field))
            self._fields.setItem(row, 1, QTableWidgetItem(value))


class FormatChoice(QDialog):
    """Which format to read a log with, asked once before an ingest."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("How should these logs be read?")

        self._choice = QComboBox()
        self._fill()

        explain = QLabel(
            "Detecting works for Apache and nginx logs and anything shaped like "
            "them. Choose a format when the logs are in one of your own."
        )
        explain.setWordWrap(True)
        explain.setFont(caption_font(explain.font()))
        explain.setStyleSheet(f"color: {THEME.muted};")

        manage = QPushButton("Log formats…")
        manage.clicked.connect(self._manage)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.addButton(manage, QDialogButtonBox.ButtonRole.ResetRole)

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        stack.addWidget(self._choice)
        stack.addWidget(explain)
        stack.addWidget(buttons)

    def _fill(self) -> None:
        # Same reconciliation as the editor's list, and needed for the same
        # reason: a format written on the command line has to be offerable here
        # without the reader restarting the application.
        register_saved_formats()
        chosen = self.chosen() if self._choice.count() else None
        self._choice.clear()
        # First and therefore the default. It is what every ingest did before
        # there was a choice, and it is right far more often than not; a
        # default of "pick one" would make the common case worse to serve the
        # rare one.
        self._choice.addItem(_DETECT, userData=None)
        for name in available_formats():
            self._choice.addItem(name, userData=name)
        if chosen is not None:
            self.choose(chosen)

    def offered(self) -> list[str]:
        """Every format on the list, without the detect entry."""
        return [self._choice.itemText(row) for row in range(1, self._choice.count())]

    def chosen(self) -> str | None:
        """The chosen format's name, or `None` for detect-it-yourself."""
        data = self._choice.currentData()
        return str(data) if data is not None else None

    def choose(self, name: str) -> None:
        found = self._choice.findData(name)
        if found >= 0:
            self._choice.setCurrentIndex(found)

    def _manage(self) -> None:
        FormatEditor(self).exec()
        self._fill()
