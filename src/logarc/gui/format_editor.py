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

import json
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
from logarc.gui.format_preview import preview, preview_mapping
from logarc.gui.style import THEME
from logarc.gui.theme import GAP, ROOM, caption_font
from logarc.parsers.json_format import MAPPABLE, JsonFormatError, guess_mapping
from logarc.parsers.library import FormatLibraryError, load_library, save_library
from logarc.parsers.logformat import LogFormatError
from logarc.parsers.registry import (
    available_formats,
    get_spec,
    is_built_in,
    register_saved_formats,
)
from logarc.parsers.spec import JsonFormatSpec, LogFormatSpec

if TYPE_CHECKING:
    from collections.abc import Sequence

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

#: The first rows of the list, and the reason there is no "nothing is
#: selected" state to get wrong. `QListWidget` makes row 0 current the first
#: time it is shown if nothing is — measured, by watching it overwrite a
#: half-written format — so a list whose row 0 is a real format silently
#: discards what the reader has typed. A list whose row 0 *is* a blank form
#: cannot.
#:
#: Two of them rather than one, because a single row could not say which kind
#: is being started, and asking afterwards means the reader types a directive
#: into a screen that wanted a mapping.
_NEW_TEXT = "New text format…"
_NEW_JSON = "New JSON format…"

_BUILT_IN_HEADING = "Built in"
_SAVED_HEADING = "Saved by you"

#: The rows of the list that are not formats. A format named after one of them
#: would be picked up by the wrong branch of `_on_selected` and edited as
#: something it is not, so the names are refused on the way in.
_RESERVED = frozenset({_NEW_TEXT, _NEW_JSON, _BUILT_IN_HEADING, _SAVED_HEADING})

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


def _install_saved() -> str:
    """Reconcile the registry with the library file. Returns what went wrong.

    Empty when nothing did. Guarded for the same reason `_saved` is, and it has
    to be guarded separately: `register_saved_formats` reads the file itself,
    so a damaged one raised straight out of the constructor and took the window
    down with it — on the one screen that could have fixed the file.
    """
    try:
        register_saved_formats()
    except FormatLibraryError as exc:
        return str(exc)
    return ""


class FormatEditor(QDialog):
    """The library of log formats: read a built-in, write your own, try both."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Log formats")
        self.setMinimumWidth(_WIDTH)
        self.resize(_WIDTH, _HEIGHT)

        self._editing: str | None = None
        self._trouble = ""
        self._library_trouble = ""
        self._kind = "logformat"

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

        # The JSON half. Fixed rows, one per field logarc records, rather than
        # a list the reader adds to: which fields *can* be mapped is the
        # decision they are making, and a list they have to populate hides the
        # ones they have not thought of.
        self._mapping = QTableWidget(len(MAPPABLE), 2)
        self._mapping.setHorizontalHeaderLabels(["logarc calls it", "your log calls it"])
        required(self._mapping.verticalHeader()).setVisible(False)
        required(self._mapping.verticalHeader()).setDefaultSectionSize(_ROW)
        heads = required(self._mapping.horizontalHeader())
        heads.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        heads.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for row, ours in enumerate(MAPPABLE):
            label = QTableWidgetItem(ours)
            label.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self._mapping.setItem(row, 0, label)
            self._mapping.setItem(row, 1, QTableWidgetItem(""))
        self._mapping.itemChanged.connect(self._refresh_preview)

        self._time_format = QLineEdit()
        self._time_format.setPlaceholderText(
            "Leave empty unless the time is neither ISO nor a number"
        )
        self._time_format.textChanged.connect(self._refresh_preview)

        self._guess = QPushButton("Guess from the line above")
        self._guess.clicked.connect(self.guess)

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
        right.addWidget(self._labelled("Name"))
        right.addWidget(self._name)

        self._directive_label = self._labelled("LogFormat directive")
        right.addWidget(self._directive_label)
        right.addWidget(self._directive)

        right.addWidget(self._labelled("Note"))
        right.addWidget(self._note)

        right.addWidget(self._labelled("A line from your log"))
        right.addWidget(self._sample)

        # Under the sample, because guessing reads it and mapping is checked
        # against it. Above the mapping, because that is the order the reader
        # works in: paste, guess, correct.
        self._guess_row = QWidget()
        guessing = QHBoxLayout(self._guess_row)
        guessing.setContentsMargins(0, 0, 0, 0)
        guessing.addWidget(self._guess)
        guessing.addWidget(self._labelled("Time format"))
        guessing.addWidget(self._time_format, 1)
        right.addWidget(self._guess_row)

        right.addWidget(self._status)

        # The rule on the left, what it read on the right. Stacked, neither
        # table could show even half its rows at the opening size and the
        # reader scrolled one to check the other. Side by side they are the
        # comparison they exist to be — and in text mode the mapping is hidden,
        # so the result takes the whole width on its own.
        tables = QWidget()
        beside = QHBoxLayout(tables)
        beside.setContentsMargins(0, 0, 0, 0)
        beside.setSpacing(GAP // 2)
        beside.addWidget(self._mapping, 1)
        beside.addWidget(self._fields, 1)
        right.addWidget(tables, 1)

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
        return [
            item.text()
            for item in items
            if item is not None and item.text() not in (_NEW_TEXT, _NEW_JSON)
        ]

    def kind(self) -> str:
        """Which shape the right-hand side is in: `logformat` or `json`."""
        return self._kind

    def mapping(self) -> tuple[tuple[str, str], ...]:
        """The rows of the mapping table that have been filled in."""
        rows = []
        for row, ours in enumerate(MAPPABLE):
            cell = self._mapping.item(row, 1)
            theirs = cell.text().strip() if cell is not None else ""
            if theirs:
                rows.append((ours, theirs))
        return tuple(rows)

    def set_mapping(self, fields: Sequence[tuple[str, str]]) -> None:
        """Put `fields` into the table, clearing whatever was there."""
        by_ours = dict(fields)
        self._mapping.blockSignals(True)
        for row, ours in enumerate(MAPPABLE):
            self._mapping.setItem(row, 1, QTableWidgetItem(by_ours.get(ours, "")))
        self._mapping.blockSignals(False)
        self._refresh_preview()

    def guess(self) -> None:
        """Propose a mapping from the pasted line, for the reader to correct."""
        try:
            payload = json.loads(self._sample.toPlainText().strip())
        except (json.JSONDecodeError, ValueError):
            self._refuse("That line is not JSON, so there are no keys to guess from.")
            return
        if not isinstance(payload, dict):
            self._refuse("That line is JSON but not an object, so it has no keys to map.")
            return
        self._trouble = ""
        self.set_mapping(guess_mapping(payload))

    def editing(self) -> str | None:
        """The saved format being edited, or `None` for a new or built-in one."""
        return self._editing

    def trouble(self) -> str:
        """Why the last save was refused. Empty when nothing was refused."""
        return self._trouble

    def preview(self) -> Preview:
        """What the format on screen currently reads out of the pasted line."""
        sample = self._sample.toPlainText()
        if self._kind == "json":
            return preview_mapping(self.mapping(), self._time_format.text().strip(), sample)
        return preview(self._directive.text(), sample)

    # -- moving around the list ------------------------------------------

    def select(self, name: str) -> None:
        """Load `name` into the fields on the right."""
        matches = self._formats.findItems(name, Qt.MatchFlag.MatchExactly)
        if matches:
            self._formats.setCurrentItem(matches[0])
        else:  # pragma: no cover - only reachable if the list went stale
            self._on_selected(name)

    def start_new(self) -> None:
        """Clear the right-hand side for a text format that does not exist yet."""
        self.select(_NEW_TEXT)

    def start_new_json(self) -> None:
        """Clear the right-hand side for a JSON format that does not exist yet."""
        self.select(_NEW_JSON)

    def _blank(self, kind: str) -> None:
        self._editing = None
        self._trouble = ""
        self._name.clear()
        self._directive.clear()
        self._note.clear()
        self._time_format.clear()
        self.set_mapping(())
        self._show_kind(kind)
        self._set_editable(True)
        self._refresh_preview()

    def _show_kind(self, kind: str) -> None:
        """Put the right half of the screen in front of the reader.

        Hidden rather than disabled: a greyed-out mapping table beside a live
        directive line invites the reader to wonder which one this format uses,
        and the answer is never both.
        """
        self._kind = kind
        text = kind == "logformat"
        self._directive_label.setVisible(text)
        self._directive.setVisible(text)
        self._mapping.setVisible(not text)
        self._guess_row.setVisible(not text)

    def _on_selected(self, name: str) -> None:
        if not name:
            return
        if name in (_NEW_TEXT, _NEW_JSON):
            self._blank("logformat" if name == _NEW_TEXT else "json")
            return
        try:
            spec = get_spec(name)
        except LookupError:  # pragma: no cover - the list is built from the registry
            return
        if spec is None:
            # Registered from a factory: there is code behind the name and no
            # definition to show, let alone edit.
            self._editing = None
            self._show_kind("logformat")
            self._name.setText(name)
            self._directive.clear()
            self._note.clear()
            self._set_editable(False)
            self._refresh_preview()
            return

        self._editing = name if self._is_saved(name) else None
        self._show_kind(spec.kind)
        self._name.setText(spec.name)
        self._note.setText(spec.description)
        if isinstance(spec, JsonFormatSpec):
            self._directive.clear()
            self._time_format.setText(spec.time_format)
            self.set_mapping(spec.fields)
        else:
            self._directive.setText(spec.directive)
            self._time_format.clear()
            self.set_mapping(())
        self._set_editable(self._is_saved(name))
        self._refresh_preview()

    def _is_saved(self, name: str) -> bool:
        return name in available_formats() and not is_built_in(name)

    def _set_editable(self, editable: bool) -> None:
        for field in (self._name, self._directive, self._note, self._time_format):
            field.setEnabled(editable)
        self._mapping.setEnabled(editable)
        self._guess.setEnabled(editable)
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

        spec: FormatSpec = (
            JsonFormatSpec(
                name=name,
                fields=self.mapping(),
                time_format=self._time_format.text().strip(),
                description=self._note.text().strip(),
            )
            if self._kind == "json"
            else LogFormatSpec(
                name=name, directive=self._directive.text(), description=self._note.text().strip()
            )
        )
        try:
            spec.build()
        except (LogFormatError, JsonFormatError) as exc:
            return self._refuse(str(exc))

        # Both the new name and the one being edited are dropped, so changing
        # the name of a format is a rename rather than a copy. That is the
        # reading that matches the gesture — a reader wanting two formats would
        # have started a new one — and no case is affected either way, since
        # each carries its own copy of the definition it was read with.
        kept = [item for item in saved if item.name not in {name, self._editing}]
        try:
            save_library([*kept, spec])
        except FormatLibraryError as exc:
            return self._refuse(str(exc))

        # `_reload` re-registers from the file, so the format is usable now
        # rather than at the next launch: one that is in the file and absent
        # from every list offering it is one the reader cannot use.
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
        self._editing = None
        # `_reload` reconciles the registry with the file, which is what takes
        # the deleted format out of every list that was offering it.
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
        self._library_trouble = _install_saved()
        current = self._name.text()
        built_in = [name for name in available_formats() if is_built_in(name)]
        saved = [name for name in available_formats() if not is_built_in(name)]

        self._formats.blockSignals(True)
        self._formats.clear()
        self._headings.clear()
        self._formats.addItem(_NEW_TEXT)
        self._formats.addItem(_NEW_JSON)
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
            # Deliberately, rather than leaving it to the widget: see the
            # `_NEW_TEXT` note above.
            self._formats.setCurrentRow(0)
            self._blank("logformat")

    def _heading_item(self, text: str) -> QListWidgetItem:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        item.setFont(caption_font(item.font()))
        item.setForeground(QColor(THEME.faint))
        return item

    def _refresh_preview(self) -> None:
        result = self.preview()
        # The library's own trouble comes first. It is about the whole screen,
        # where the other two are about the directive in front of the reader,
        # and it is the one they cannot work out from what they can see.
        self._status.setText(self._library_trouble or self._trouble or result.status)
        # The extra fields last, under the canonical ones and named as the log
        # names them rather than as the schema would: they are not schema
        # fields, and dressing them up as though they were would suggest the
        # rest of logarc reads them the same way.
        rows = [*result.fields, *result.extra]
        self._fields.setRowCount(len(rows))
        for row, (field, value) in enumerate(rows):
            self._fields.setItem(row, 0, QTableWidgetItem(field))
            self._fields.setItem(row, 1, QTableWidgetItem(value))


class FormatChoice(QDialog):
    """Which format to read a log with, asked once before an ingest."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("How should these logs be read?")

        self._library_trouble = ""
        self._choice = QComboBox()
        self._fill()

        explain = QLabel(
            self._library_trouble
            or "Detecting works for Apache and nginx logs and anything shaped like "
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
        self._library_trouble = _install_saved()
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
