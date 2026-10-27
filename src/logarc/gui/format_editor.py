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
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from logarc.gui._qt import required
from logarc.gui.columns import ColumnWidths
from logarc.gui.format_preview import (
    preview,
    preview_columns,
    preview_mapping,
    preview_pattern,
)
from logarc.gui.theme import (
    GAP,
    LIST_WIDTH,
    ROOM,
    caption_font,
    colour_text,
    on_font_change,
    settle_buttons,
)
from logarc.parsers.columns import FIELDS_DIRECTIVE, declared_columns
from logarc.parsers.fieldnames import MAPPABLE
from logarc.parsers.fieldnames import guess_mapping as guess_from_names
from logarc.parsers.json_format import guess_mapping
from logarc.parsers.library import FormatLibraryError, load_library, save_library
from logarc.parsers.registry import (
    available_formats,
    get_spec,
    is_built_in,
    register_saved_formats,
)
from logarc.parsers.spec import (
    ColumnsFormatSpec,
    JsonFormatSpec,
    LogFormatSpec,
    PatternFormatSpec,
)
from logarc.style import THEME

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

#: The blank form's row, and the reason there is no "nothing is selected"
#: state to get wrong. `QListWidget` makes a row current the first time it is
#: shown if nothing is — measured, by watching it overwrite a half-written
#: format — so a list that lands on a real format silently discards what the
#: reader has typed. A list that lands on a blank form cannot.
#:
#: One row, whose kind New's menu sets; it was four rows, one per kind, which
#: made the list half commands. Known by a data role rather than by its text,
#: so a format saved under the same name (the command line allows any) still
#: opens as itself.
_DRAFT = "Untitled"
_DRAFT_ROLE: Final = Qt.ItemDataRole.UserRole

_CUSTOM_HEADING = "CUSTOM"
_BUILT_IN_HEADING = "BUILT-IN"

#: Names the list keeps for its own rows. A format called one of them would be
#: hard to tell from the row on screen, so the editor refuses them.
_RESERVED = frozenset({_DRAFT, _CUSTOM_HEADING, _BUILT_IN_HEADING})

#: What New offers, and the kind each starts. A menu on one button rather than
#: four rows in the list: rows are things, and these are commands.
_NEW_KINDS: Final = (
    ("Text (LogFormat)", "logformat"),
    ("JSON", "json"),
    ("Table (CSV, TSV, W3C)", "columns"),
    ("Pattern (regular expression)", "pattern"),
)

#: What the separator box offers, in the spelling a reader recognises. A tab is
#: not something anyone can type into a text box and see.
_SEPARATORS: Final[dict[str, str]] = {"Space": " ", "Comma": ",", "Tab": "\t"}

#: Room for one pasted line, and for the header-and-a-row a table needs.
_SAMPLE_SHORT: Final = 64
_SAMPLE_TALL: Final = 108

_SAMPLE_HINT = (
    "Paste one line from your log here.\nCopy it exactly, including the quotes and brackets."
)

#: What to ask for in the sample box, per kind. A table wants several lines,
#: because for that kind the header is half the definition.
_SAMPLE_HINTS: Final[dict[str, str]] = {
    "logformat": _SAMPLE_HINT,
    "json": _SAMPLE_HINT,
    "columns": (
        "Paste a few lines from your log, header and all.\n"
        "The #Fields: line is where the column names come from."
    ),
    "pattern": _SAMPLE_HINT,
}

#: What the one-line rule box is called, per kind. The box holds a directive
#: for one kind and a regular expression for another, and naming it for either
#: would be wrong half the time.
_RULE_LABELS: Final[dict[str, str]] = {
    # Either: an nginx `log_format` is read as the directive it means.
    "logformat": "LogFormat or log_format",
    "pattern": "Regular expression",
}

#: The placeholder in that box, per kind.
_RULE_HINTS: Final[dict[str, str]] = {
    "logformat": '%h %l %u %t "%r" %>s %b',
    "pattern": r"^(?P<timestamp>\S+) (?P<client_ip>\S+) ...",
}


def _is_draft(item: QListWidgetItem) -> bool:
    return bool(item.data(_DRAFT_ROLE))


def _named_item(name: str) -> QListWidgetItem:
    """A format's row in the list, carrying its whole name for when the row cuts it short."""
    item = QListWidgetItem(name)
    item.setToolTip(name)
    return item


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
        # A pattern's `escapes`, which has no control of its own: only a
        # built-in or a format written on the command line carries one. Kept
        # from the format on screen so its preview reads what ingest will, and
        # so saving it again does not drop what nothing here shows.
        self._escapes = ""

        self._formats = QListWidget()
        self._formats.setMaximumWidth(LIST_WIDTH)
        # A name wider than the list is shortened in the middle, where two
        # formats of one family differ least, rather than scrolled to; the
        # whole name is each item's tooltip.
        self._formats.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._formats.setTextElideMode(Qt.TextElideMode.ElideMiddle)
        self._formats.currentItemChanged.connect(self._on_item)
        self._headings: set[int] = set()
        self._draft_kind = "logformat"
        self.new_button = QPushButton("New")
        self.new_button.setToolTip("Start a new log format.")
        kinds = QMenu(self.new_button)
        for offered, kind in _NEW_KINDS:
            entry = required(kinds.addAction(offered))
            entry.triggered.connect(lambda _checked=False, k=kind: self._start(k))
        self.new_button.setMenu(kinds)
        # In a dialog every push button wants to be the default. Only Save is.
        self.new_button.setAutoDefault(False)

        self._name = QLineEdit()
        self._name.setPlaceholderText("A name you will recognise later")

        self._rule = QLineEdit()
        self._rule.setPlaceholderText('%h %l %u %t "%r" %>s %b')
        self._rule.textChanged.connect(self._refresh_preview)

        self._note = QLineEdit()
        self._note.setPlaceholderText("What this format is for (optional)")

        # The JSON half. Fixed rows, one per field logarc records, rather than
        # a list the reader adds to: which fields *can* be mapped is the
        # decision they are making, and a list they have to populate hides the
        # ones they have not thought of.
        self._mapping = QTableWidget(len(MAPPABLE), 2)
        self._mapping_edit_triggers = self._mapping.editTriggers()
        self._mapping.setHorizontalHeaderLabels(["Field", "Your log's key"])
        required(self._mapping.verticalHeader()).setVisible(False)
        self._mapping_columns = ColumnWidths(self._mapping, fill=1)
        for row, ours in enumerate(MAPPABLE):
            label = QTableWidgetItem(ours)
            label.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self._mapping.setItem(row, 0, label)
            self._mapping.setItem(row, 1, QTableWidgetItem(""))
        self._mapping.itemChanged.connect(self._refresh_preview)
        self._mapping_columns.fit_unset()

        self._time_format = QLineEdit()
        self._time_format.setPlaceholderText(
            "Leave empty unless the time is neither ISO nor a number"
        )
        self._time_format.textChanged.connect(self._refresh_preview)

        self._guess = QPushButton("Guess fields")
        self._guess.setAutoDefault(False)
        self._guess.setToolTip("Fill the mapping in from the sample line.")
        self._guess.clicked.connect(self.guess)

        # The table half. Only these two are new: a table is a mapping like a
        # JSON log, and shares that screen.
        self._separator = QComboBox()
        self._separator.addItems(list(_SEPARATORS))
        self._separator.currentTextChanged.connect(self._refresh_preview)

        self._columns = QLineEdit()
        self._columns.setPlaceholderText("Leave empty when the log names its own columns")
        self._columns.textChanged.connect(self._refresh_preview)

        self._separator_label = self._labelled("Separator")
        self._columns_label = self._labelled("Columns")

        self._sample = QPlainTextEdit()
        self._sample.setPlaceholderText(_SAMPLE_HINT)
        self._sample.setFixedHeight(_SAMPLE_SHORT)
        self._sample.textChanged.connect(self._refresh_preview)

        self._fields = QTableWidget(0, 2)
        self._fields.setHorizontalHeaderLabels(["Field", "Value"])
        required(self._fields.verticalHeader()).setVisible(False)
        self._fields.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        # The value column takes the rest of the width. Left at its content
        # width it stopped after the longest short value, leaving half the
        # table empty and a long user agent clipped in the same picture.
        self._field_columns = ColumnWidths(self._fields, fill=1)
        self._fit_rows()
        for table in (self._mapping, self._fields):
            on_font_change(table, self._fit_rows)

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

    def _fit_rows(self) -> None:
        """Tight rows, so all eleven fields are in sight at the opening size.

        At Qt's default only seven were, and the four out of view are the ones
        a custom format most often gets wrong: referer, user agent, host, and
        the byte count. Taller only when zoomed text would not fit `_ROW`.
        """
        for table in (self._mapping, self._fields):
            height = max(_ROW, table.fontMetrics().height() + 8)
            required(table.verticalHeader()).setDefaultSectionSize(height)

    def _build(self, parent_layout: QHBoxLayout) -> None:
        parent_layout.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        parent_layout.setSpacing(GAP)

        left = QVBoxLayout()
        left.setSpacing(GAP // 2)
        left.addWidget(self._labelled("Formats"))
        left.addWidget(self._formats, 1)
        tools = QHBoxLayout()
        tools.setContentsMargins(0, 0, 0, 0)
        tools.addWidget(self.new_button)
        tools.addStretch(1)
        left.addLayout(tools)

        right = QVBoxLayout()
        right.setSpacing(GAP // 2)
        right.addWidget(self._labelled("Name"))
        right.addWidget(self._name)

        self._rule_label = self._labelled(_RULE_LABELS["logformat"])
        right.addWidget(self._rule_label)
        right.addWidget(self._rule)

        right.addWidget(self._labelled("Note"))
        right.addWidget(self._note)

        right.addWidget(self._labelled("Sample line"))
        right.addWidget(self._sample)

        # Under the sample, because guessing reads it and mapping is checked
        # against it. Above the mapping, because that is the order the reader
        # works in: paste, guess, correct.
        # The guess button belongs to the kinds that map names; the time
        # format belongs to those *and* to a pattern, whose syslog stamp needs
        # telling apart from an ISO one. So they are separate rows.
        self._guess_row = QWidget()
        guessing = QHBoxLayout(self._guess_row)
        guessing.setContentsMargins(0, 0, 0, 0)
        guessing.addWidget(self._guess)
        guessing.addStretch(1)
        right.addWidget(self._guess_row)

        self._time_row = QWidget()
        timing = QHBoxLayout(self._time_row)
        timing.setContentsMargins(0, 0, 0, 0)
        timing.addWidget(self._labelled("Time format"))
        timing.addWidget(self._time_format, 1)
        right.addWidget(self._time_row)

        self._table_row = QWidget()
        tabular = QHBoxLayout(self._table_row)
        tabular.setContentsMargins(0, 0, 0, 0)
        tabular.addWidget(self._separator_label)
        tabular.addWidget(self._separator)
        tabular.addWidget(self._columns_label)
        tabular.addWidget(self._columns, 1)
        right.addWidget(self._table_row)

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
        settle_buttons(buttons)
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
        return [item.text() for item in items if item is not None and not _is_draft(item)]

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
        self._mapping_columns.fit_unset()
        self._refresh_preview()

    def guess(self) -> None:
        """Propose a mapping from the pasted lines, for the reader to correct.

        Where the names come from is all that differs between the kinds: keys
        in a JSON object, headings in a table. What the names mean is one
        answer, in `parsers.fieldnames`.
        """
        if self._kind == "columns":
            self._guess_columns()
            return
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

    def _guess_columns(self) -> None:
        lines = [line for line in self._sample.toPlainText().splitlines() if line.strip()]
        given = self.columns()
        if given:
            self._trouble = ""
            self.set_mapping(guess_from_names(given))
            return

        found, _header = declared_columns(lines, self.separator())
        if not found or not any(line.strip().startswith(FIELDS_DIRECTIVE) for line in lines):
            self._refuse(
                "These lines have no #Fields: header to take the column names from. "
                "Write them into Columns yourself."
            )
            return
        self._trouble = ""
        self.set_mapping(guess_from_names(found))

    def columns(self) -> tuple[str, ...]:
        """The column names typed in, if any. Empty means the log names them."""
        return tuple(part.strip() for part in self._columns.text().split(",") if part.strip())

    def separator(self) -> str:
        """The character between cells, from the box's own wording."""
        return _SEPARATORS[self._separator.currentText()]

    def editing(self) -> str | None:
        """The saved format being edited, or `None` for a new or built-in one."""
        return self._editing

    def trouble(self) -> str:
        """Why the last save was refused. Empty when nothing was refused."""
        return self._trouble

    def preview(self) -> Preview:
        """What the format on screen currently reads out of the pasted line."""
        sample = self._sample.toPlainText()
        if self._kind == "columns":
            return preview_columns(
                self.mapping(),
                self.columns(),
                self.separator(),
                self._time_format.text().strip(),
                sample,
                self._escapes,
            )
        if self._kind == "json":
            return preview_mapping(self.mapping(), self._time_format.text().strip(), sample)
        if self._kind == "pattern":
            return preview_pattern(
                self._rule.text(), self._time_format.text().strip(), sample, self._escapes
            )
        return preview(self._rule.text(), sample)

    # -- moving around the list ------------------------------------------

    def select(self, name: str) -> None:
        """Load `name` into the fields on the right."""
        matches = [
            item
            for item in self._formats.findItems(name, Qt.MatchFlag.MatchExactly)
            if not _is_draft(item)
        ]
        if matches:
            self._formats.setCurrentItem(matches[0])
        else:  # pragma: no cover - only reachable if the list went stale
            self._on_selected(name)

    def start_new(self) -> None:
        """Clear the right-hand side for a text format that does not exist yet."""
        self._start("logformat")

    def start_new_json(self) -> None:
        """Clear the right-hand side for a JSON format that does not exist yet."""
        self._start("json")

    def start_new_columns(self) -> None:
        """Clear the right-hand side for a table format that does not exist yet."""
        self._start("columns")

    def start_new_pattern(self) -> None:
        """Clear the right-hand side for a pattern that does not exist yet."""
        self._start("pattern")

    def _start(self, kind: str) -> None:
        """Put the Untitled row in front, as a blank `kind`.

        Blanked here as well as by the selection, which does not fire when
        the row is already current. Not when it is current as `kind` already:
        that is the new format, being written, and blanking it lost the work.
        """
        current = self._formats.currentItem()
        if current is not None and _is_draft(current) and kind == self._draft_kind:
            return
        self._draft_kind = kind
        self._formats.blockSignals(True)
        self._formats.setCurrentRow(self._draft_row())
        self._formats.blockSignals(False)
        self._blank(kind)

    def _draft_row(self) -> int:
        return next(
            row
            for row in range(self._formats.count())
            if _is_draft(required(self._formats.item(row)))
        )

    def _blank(self, kind: str) -> None:
        self._editing = None
        self._escapes = ""
        self._trouble = ""
        self._name.clear()
        self._rule.clear()
        self._note.clear()
        self._time_format.clear()
        self._columns.clear()
        self._separator.setCurrentIndex(0)
        self.set_mapping(())
        self._show_kind(kind)
        self._set_editable(True)
        self._refresh_preview()

    def _show_kind(self, kind: str) -> None:
        """Put the right half of the screen in front of the reader.

        Hidden rather than disabled: a greyed-out mapping table beside a live
        directive line invites the reader to wonder which one this format uses,
        and the answer is never both. A control that means nothing here is a
        question they have to answer before realising it was not being asked.
        """
        self._kind = kind
        one_line = kind in _RULE_LABELS
        self._rule_label.setVisible(one_line)
        self._rule.setVisible(one_line)
        if one_line:
            self._rule_label.setText(_RULE_LABELS[kind])
            self._rule.setPlaceholderText(_RULE_HINTS[kind])
        self._mapping.setVisible(not one_line)
        self._guess_row.setVisible(not one_line)
        self._time_row.setVisible(kind != "logformat")
        self._table_row.setVisible(kind == "columns")
        self._sample.setPlaceholderText(_SAMPLE_HINTS[kind])
        # A table wants a header and a row, so it wants room for both. One line
        # of a four-line paste, with the rest behind a scrollbar, hides the
        # half the reader is being asked to check.
        self._sample.setFixedHeight(_SAMPLE_TALL if kind == "columns" else _SAMPLE_SHORT)
        required(self._mapping.horizontalHeader()).setVisible(True)
        self._mapping.setHorizontalHeaderLabels(
            ["Field", "Your log's column" if kind == "columns" else "Your log's key"]
        )

    def _on_item(self, item: QListWidgetItem | None, _previous: QListWidgetItem | None) -> None:
        if item is None:
            return
        if _is_draft(item):
            self._blank(self._draft_kind)
            return
        self._on_selected(item.text())

    def _on_selected(self, name: str) -> None:
        if not name:
            return
        try:
            spec = get_spec(name)
        except LookupError:  # pragma: no cover - the list is built from the registry
            return
        if spec is None:
            # Registered from a factory: there is code behind the name and no
            # definition to show, let alone edit.
            self._editing = None
            self._escapes = ""
            self._show_kind("logformat")
            self._name.setText(name)
            self._rule.clear()
            self._note.clear()
            self._set_editable(False)
            self._refresh_preview()
            return

        self._editing = name if self._is_saved(name) else None
        self._escapes = (
            spec.escapes if isinstance(spec, (PatternFormatSpec, ColumnsFormatSpec)) else ""
        )
        self._show_kind(spec.kind)
        self._name.setText(spec.name)
        self._note.setText(spec.description)
        if isinstance(spec, LogFormatSpec):
            self._rule.setText(spec.directive)
            self._time_format.clear()
            self.set_mapping(())
        elif isinstance(spec, PatternFormatSpec):
            self._rule.setText(spec.pattern)
            self._time_format.setText(spec.time_format)
            self.set_mapping(())
        else:
            self._rule.clear()
            self._time_format.setText(spec.time_format)
            self.set_mapping(spec.fields)
        if isinstance(spec, ColumnsFormatSpec):
            self._columns.setText(", ".join(spec.columns))
            self._separator.setCurrentText(
                next(shown for shown, char in _SEPARATORS.items() if char == spec.separator)
            )
        self._set_editable(self._is_saved(name))
        self._refresh_preview()

    def _is_saved(self, name: str) -> bool:
        return name in available_formats() and not is_built_in(name)

    def _set_editable(self, editable: bool) -> None:
        for field in (self._name, self._rule, self._note, self._time_format, self._columns):
            field.setEnabled(editable)
        # Keep its header usable for resizing while built-in mappings remain
        # read-only, rather than disabling the entire table.
        self._mapping.setEditTriggers(
            self._mapping_edit_triggers if editable else QTableWidget.EditTrigger.NoEditTriggers
        )
        self._guess.setEnabled(editable)
        self._separator.setEnabled(editable)
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
            return self._refuse(f"{name!r} is reserved: the list uses it for its own rows.")

        saved = _saved()
        if is_built_in(name):
            return self._refuse(
                f"{name!r} is a built-in format. Built-ins are matched first, so a "
                "saved format of the same name would never be reached."
            )

        spec = self._spec_on_screen(name)
        try:
            # `check`, not `build`: a table format may not know its columns
            # until a log is in hand, and the reader is saving a definition
            # rather than reading a file.
            spec.check()
        except ValueError as exc:
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

    def _spec_on_screen(self, name: str) -> FormatSpec:
        """The definition the right-hand side currently describes."""
        note = self._note.text().strip()
        when = self._time_format.text().strip()
        if self._kind == "columns":
            return ColumnsFormatSpec(
                name=name,
                fields=self.mapping(),
                columns=self.columns(),
                separator=self.separator(),
                time_format=when,
                description=note,
                escapes=self._escapes,
            )
        if self._kind == "json":
            return JsonFormatSpec(
                name=name, fields=self.mapping(), time_format=when, description=note
            )
        if self._kind == "pattern":
            return PatternFormatSpec(
                name=name,
                pattern=self._rule.text(),
                time_format=when,
                description=note,
                escapes=self._escapes,
            )
        return LogFormatSpec(name=name, directive=self._rule.text(), description=note)

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
        colour_text(self._status, THEME.alert)
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
        # The reader's own first, headed by the blank form: a rebuilt list then
        # always has a blank to land on, never a real format to overwrite.
        self._headings.add(self._formats.count())
        self._formats.addItem(self._heading_item(_CUSTOM_HEADING))
        draft = QListWidgetItem(_DRAFT)
        draft.setData(_DRAFT_ROLE, True)
        italic = draft.font()
        italic.setItalic(True)
        draft.setFont(italic)
        self._formats.addItem(draft)
        for name in saved:
            self._formats.addItem(_named_item(name))
        self._headings.add(self._formats.count())
        self._formats.addItem(self._heading_item(_BUILT_IN_HEADING))
        for name in built_in:
            self._formats.addItem(_named_item(name))
        self._formats.blockSignals(False)

        if current in available_formats():
            self.select(current)
        else:
            # Deliberately, rather than leaving it to the widget: a list landing
            # on a real format would discard what the reader had typed.
            self._start("logformat")

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
        failed = (
            self._library_trouble
            or self._trouble
            or (not result.ok and self._sample.toPlainText().strip())
        )
        colour_text(self._status, THEME.alert if failed else THEME.muted)
        # The extra fields last, under the canonical ones and named as the log
        # names them rather than as the schema would: they are not schema
        # fields, and dressing them up as though they were would suggest the
        # rest of logarc reads them the same way.
        rows = [*result.fields, *result.extra]
        self._fields.setRowCount(len(rows))
        for row, (field, value) in enumerate(rows):
            label = QTableWidgetItem(field)
            label.setForeground(QColor(THEME.muted))
            item = QTableWidgetItem(value)
            if row < len(result.fields) and field in ("Client", "Host"):
                item.setForeground(QColor(THEME.identity))
            elif row < len(result.fields) and field == "When":
                item.setForeground(QColor(THEME.timestamp))
            self._fields.setItem(row, 0, label)
            self._fields.setItem(row, 1, item)
        self._field_columns.fit_unset()


class FormatChoice(QDialog):
    """Which format to read a log with, asked once before an ingest."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Log format")

        self._library_trouble = ""
        self._choice = QComboBox()
        self._fill()

        self._choice.setToolTip(
            "Detecting works for Apache and nginx logs and anything shaped like "
            "them. Choose a format when the logs are in one of your own."
        )
        # Said on screen only when something is wrong with the library; the
        # usual advice is the list's tooltip.
        explain = QLabel(self._library_trouble)
        explain.setWordWrap(True)
        explain.setFont(caption_font(explain.font()))
        explain.setStyleSheet(f"color: {THEME.alert};")
        explain.setVisible(bool(self._library_trouble))

        manage = QPushButton("Manage…")
        manage.setToolTip("See and write the log formats logarc can read.")
        manage.clicked.connect(self._manage)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.addButton(manage, QDialogButtonBox.ButtonRole.ResetRole)
        settle_buttons(buttons)

        stack = QVBoxLayout(self)
        stack.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        stack.setSpacing(GAP)
        row = QHBoxLayout()
        row.setSpacing(GAP)
        row.addWidget(QLabel("Format"))
        row.addWidget(self._choice, 1)
        stack.addLayout(row)
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
        # Imported here: that dialog holds a FormatEditor, so importing it at the
        # top would have each module import the other.
        from logarc.gui.formats_and_rules import FormatsAndRules

        FormatsAndRules(self).exec()
        self._fill()
