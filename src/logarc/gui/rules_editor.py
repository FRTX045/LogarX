"""The Detection rules tab: the built-in packs, the reader's own, and what each finds.

Holds no wording that can be tested without a display (`gui.rules_view` has it)
and no knowledge of where packs live (`rules_library` has that). What is here is
the screen: which pack is on show, the YAML being edited, the switches, and the
counts.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor, QTextFormat
from PyQt6.QtWidgets import (
    QApplication,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from logarc import rules_library
from logarc.detect.rules import RulePackError, load_pack_text
from logarc.detect.ruleset import PackText, RuleSet, build_rules, built_in_packs
from logarc.gui._qt import required
from logarc.gui.columns import ColumnWidths
from logarc.gui.rules_view import (
    NEW_PACK_TEXT,
    ask_text,
    delete_question,
    error_line,
    in_words,
    read_summary,
)
from logarc.gui.theme import GAP, ROOM, caption_font, mono_font
from logarc.gui.workers import run_job
from logarc.rule_finds import FindsCancelled, FindsProgress, count_finds
from logarc.style import THEME, plural, severity_text_colour

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from logarc.detect.rules import Rule
    from logarc.detect.ruleset import BuiltInPack
    from logarc.rule_finds import Find

__all__ = ["RulesEditor"]

#: The list's own rows: two section headings and the blank pack being written.
#: Commands are buttons under the list, not rows in it; a row that sometimes
#: opens a pack and sometimes runs a command made every click a guess.
_CUSTOM: Final = "CUSTOM"
_BUILT_IN: Final = "BUILT-IN"
_DRAFT: Final = "Untitled"

#: What a row of the list is, `(kind, name)`, held on the row rather than read
#: off its text, so a pack named like a heading cannot be taken for one.
_ROLE: Final = Qt.ItemDataRole.UserRole

#: How long typing must pause before the pack is read again. Reading is cheap;
#: the count it restarts is not.
_PAUSE_MS: Final = 500
_ROW: Final = 26
_COLUMNS: Final = ("Rule", "Category", "Severity", "Lines", "Clients")


def _caption(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setFont(caption_font(label.font()))
    return label


def _heading(text: str) -> QLabel:
    label = _caption(text)
    label.setStyleSheet(f"color: {THEME.muted};")
    return label


class RulesEditor(QWidget):
    """The rules tab. Writes the reader's library as they act; nothing is pending."""

    changed = pyqtSignal()
    """The library changed: a pack saved, deleted or loaded, or a rule switched."""
    read_again = pyqtSignal()
    """The reader asked for the open case to be read with the rules in force now."""
    close_requested = pyqtSignal()

    def __init__(self, case_path: Path | None = None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._case_path = case_path
        # Loaded once: about 170 ms, and the pack is checked against them every
        # time typing pauses.
        self._built_in: tuple[BuiltInPack, ...] = built_in_packs()
        self._library = rules_library.in_force(built_in=self._built_in)
        self._editing: str | None = None
        self.stale = False
        self._finds_stop: threading.Event | None = None
        self._finds_generation = 0

        self._packs = QListWidget()
        self._packs.setMaximumWidth(220)
        self._packs.currentRowChanged.connect(self._on_row)

        # -- your pack
        self._name = QLineEdit()
        self._name.setPlaceholderText("my-site")
        self._name.setToolTip("Letters, digits, - and _")
        self._name.textChanged.connect(self._schedule_check)
        self._yaml = QPlainTextEdit()
        self._yaml.setFont(mono_font(QApplication.font().pointSizeF()))
        self._yaml.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._yaml.textChanged.connect(self._schedule_check)
        self._status = _caption()
        self._finds = self._table(switches=False)
        self._finds_widths = ColumnWidths(self._finds, fill=0)
        self._finds_note = _caption()
        self._delete = QPushButton("Delete")
        self._delete.clicked.connect(self.confirm_delete)
        self._save = QPushButton("Save")
        self._save.clicked.connect(self.save)
        self._confirm, self._confirm_text = self._bar(
            ("Delete", self.delete, "confirmDelete"), ("Keep", self._keep, "keep")
        )
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(_PAUSE_MS)
        self._timer.timeout.connect(self._check)

        # -- a built-in pack
        self._built_name = QLineEdit()
        self._built_name.setEnabled(False)
        self._built_note = _caption()
        self._built_table = self._table(switches=True)
        self._built_widths = ColumnWidths(self._built_table, fill=1)
        self._built_table.itemChanged.connect(self._switched)
        self._built_count = _caption()
        self._built_yaml = QPlainTextEdit()
        self._built_yaml.setFont(mono_font(QApplication.font().pointSizeF()))
        self._built_yaml.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._built_yaml.setReadOnly(True)
        self._built_views = QStackedWidget()
        self._built_views.addWidget(self._built_table)
        self._built_views.addWidget(self._built_yaml)
        self._as_yaml = QPushButton("View YAML")
        self._as_yaml.clicked.connect(self._swap_view)

        # -- ask first
        self._ask, self._ask_text = self._bar(
            ("Re-read now", self._read_again, "readAgain"), ("Later", self._later, "later")
        )

        self._pages = QStackedWidget()
        self._pages.addWidget(self._yours_page())
        self._pages.addWidget(self._built_in_page())
        self._build()
        self._fill_list()
        self._packs.setCurrentRow(self._draft_row())

    # -- assembling ----------------------------------------------------------

    def _table(self, *, switches: bool) -> QTableWidget:
        headers = (["On"] if switches else []) + list(_COLUMNS)
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        if switches:
            required(table.horizontalHeaderItem(0)).setToolTip(
                "Untick a rule that is wrong for your site. It stays listed and can be "
                "ticked again."
            )
        required(table.verticalHeader()).setVisible(False)
        required(table.verticalHeader()).setDefaultSectionSize(_ROW)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        return table

    def _bar(self, *buttons: tuple[str, Callable[[], None], str]) -> tuple[QFrame, QLabel]:
        frame = QFrame()
        row = QHBoxLayout(frame)
        row.setContentsMargins(0, 0, 0, 0)
        text = _caption()
        row.addWidget(text, 1)
        for label, slot, name in buttons:
            button = QPushButton(label)
            button.setObjectName(name)
            button.clicked.connect(slot)
            row.addWidget(button)
        frame.hide()
        return frame, text

    def _yours_page(self) -> QWidget:
        page = QWidget()
        column = QVBoxLayout(page)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(GAP // 2)
        column.addWidget(_heading("Name"))
        column.addWidget(self._name)
        column.addWidget(_heading("Rules (YAML)"))
        column.addWidget(self._yaml, 4)
        column.addWidget(self._status)
        column.addWidget(_heading("Matches in this case"))
        column.addWidget(self._finds, 2)
        column.addWidget(self._finds_note)
        column.addWidget(self._confirm)
        buttons = QDialogButtonBox()
        buttons.addButton(self._delete, QDialogButtonBox.ButtonRole.DestructiveRole)
        buttons.addButton(self._save, QDialogButtonBox.ButtonRole.AcceptRole)
        close = required(buttons.addButton(QDialogButtonBox.StandardButton.Close))
        close.clicked.connect(self.close_requested.emit)
        column.addWidget(buttons)
        return page

    def _built_in_page(self) -> QWidget:
        page = QWidget()
        column = QVBoxLayout(page)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(GAP // 2)
        column.addWidget(_heading("Name"))
        column.addWidget(self._built_name)
        column.addWidget(self._built_note)
        column.addWidget(self._built_views, 1)
        column.addWidget(self._built_count)
        buttons = QDialogButtonBox()
        buttons.addButton(self._as_yaml, QDialogButtonBox.ButtonRole.ActionRole)
        close = required(buttons.addButton(QDialogButtonBox.StandardButton.Close))
        close.clicked.connect(self.close_requested.emit)
        column.addWidget(buttons)
        return page

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        outer.setSpacing(GAP)
        row = QHBoxLayout()
        row.setSpacing(GAP)
        left = QVBoxLayout()
        left.setSpacing(GAP // 2)
        left.addWidget(_heading("Rule packs"))
        left.addWidget(self._packs, 1)
        self.new_button = QPushButton("New")
        self.new_button.setToolTip("Start a new rule pack.")
        self.new_button.clicked.connect(self.start_new)
        self.import_button = QPushButton("Import\u2026")
        self.import_button.setToolTip("Add a rule pack from a YAML file.")
        self.import_button.clicked.connect(self._ask_for_file)
        tools = QHBoxLayout()
        tools.setContentsMargins(0, 0, 0, 0)
        tools.addWidget(self.new_button)
        tools.addWidget(self.import_button)
        tools.addStretch(1)
        left.addLayout(tools)
        row.addLayout(left)
        row.addWidget(self._pages, 1)
        outer.addLayout(row, 1)
        outer.addWidget(self._ask)

    # -- the list ------------------------------------------------------------

    def listed(self) -> list[str]:
        return [required(self._packs.item(row)).text() for row in range(self._packs.count())]

    def select(self, name: str) -> None:
        for row in range(self._packs.count()):
            data = required(self._packs.item(row)).data(_ROLE)
            if data is not None and data[1] == name:
                self._packs.setCurrentRow(row)
                return
        raise LookupError(name)

    def _fill_list(self) -> None:
        self._packs.blockSignals(True)
        self._packs.clear()
        # The reader's own first: those are the ones worked on. The blank pack
        # heads them, so a rebuilt list always has somewhere safe to land.
        self._packs.addItem(self._heading_row(_CUSTOM))
        draft = self._row(_DRAFT, "new")
        italic = draft.font()
        italic.setItalic(True)
        draft.setFont(italic)
        for saved in self._library.packs:
            item = self._row(
                f"{saved.name} (does not load)" if saved.problem else saved.name,
                "yours",
                saved.name,
            )
            item.setToolTip(saved.problem or saved.note)
            if saved.problem:
                item.setForeground(QColor(THEME.alert))
        self._packs.addItem(self._heading_row(_BUILT_IN))
        for pack in self._built_in:
            self._row(pack.name, "built-in", pack.name)
        self._packs.blockSignals(False)

    def _row(self, text: str, kind: str, name: str | None = None) -> QListWidgetItem:
        item = QListWidgetItem(text)
        item.setData(_ROLE, (kind, name))
        self._packs.addItem(item)
        return item

    def _draft_row(self) -> int:
        """Where the blank pack is: under the CUSTOM heading."""
        return next(
            row
            for row in range(self._packs.count())
            if required(self._packs.item(row)).data(_ROLE) == ("new", None)
        )

    def start_new(self) -> None:
        """Open a blank pack, from wherever the list is."""
        self._packs.setCurrentRow(self._draft_row())
        self._open_new()

    def _heading_row(self, text: str) -> QListWidgetItem:
        item = QListWidgetItem(text)
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        item.setFont(caption_font(item.font()))
        item.setForeground(QColor(THEME.faint))
        return item

    def _on_row(self, row: int) -> None:
        item = self._packs.item(row)
        if item is None or item.data(_ROLE) is None:
            return
        kind, name = item.data(_ROLE)
        self._confirm.hide()
        if kind == "new":
            self._open_new()
        elif kind == "built-in":
            self._open_built_in(name)
        elif kind == "yours":
            self._open_yours(name)

    def _reload(self, select: str | None) -> None:
        self._library = rules_library.in_force(built_in=self._built_in)
        self._fill_list()
        if select is None:
            self._packs.setCurrentRow(self._draft_row())
            self._open_new()
        else:
            self.select(select)

    # -- your pack -----------------------------------------------------------

    def _open_new(self) -> None:
        self._editing = None
        self._pages.setCurrentIndex(0)
        self._show_pack("", NEW_PACK_TEXT)
        self._delete.setEnabled(False)

    def _open_yours(self, name: str) -> None:
        (saved,) = [pack for pack in self._library.packs if pack.name == name]
        self._editing = name
        self._pages.setCurrentIndex(0)
        self._show_pack(name, saved.text)
        self._delete.setEnabled(True)

    def _show_pack(self, name: str, text: str) -> None:
        for widget in (self._name, self._yaml):
            widget.blockSignals(True)
        self._name.setText(name)
        self._yaml.setPlainText(text)
        for widget in (self._name, self._yaml):
            widget.blockSignals(False)
        self._check()

    def _schedule_check(self) -> None:
        self._save.setEnabled(False)
        self._timer.start()

    def _check(self) -> bool:
        """Read the pack on show. True when it would save.

        The YAML first, then the name: a new pack opens with no name, and that
        is a step still to take, not a mistake to colour red.
        """
        self._timer.stop()
        name, text = self._name.text().strip(), self._yaml.toPlainText()
        label = name or "new"
        others = tuple(pack for pack in self._library.ruleset.packs if pack.name != self._editing)
        try:
            build_rules(
                RuleSet((*others, PackText(label, text)), self._library.ruleset.switched_off),
                built_in=self._built_in,
            )
            rules = tuple(load_pack_text(f"{label}.yaml", text))
        except RulePackError as exc:
            self._refuse(in_words(exc), error_line(text, exc))
            return False
        if name and (problem := rules_library.name_problem(name, replacing=self._editing)):
            self._refuse(problem, None)
            return False
        self._mark(None)
        self._status.setStyleSheet("")
        said = read_summary(rules)
        self._status.setText(said if name else f"{said} Name the pack to save it.")
        self._save.setEnabled(bool(name))
        self._count(self._finds, rules)
        return bool(name)

    def _refuse(self, message: str, line: int | None) -> None:
        self._stop_count()
        self._save.setEnabled(False)
        self._status.setStyleSheet(f"color: {THEME.alert};")
        self._status.setText(message)
        self._mark(line)
        self._finds.setRowCount(0)
        self._finds_note.setText(
            "Nothing to show until the pack reads."
            + (" The last saved version stays in use." if self._editing else "")
        )

    def _mark(self, line: int | None) -> None:
        if line is None:
            self._yaml.setExtraSelections([])
            return
        block = required(self._yaml.document()).findBlockByLineNumber(line - 1)
        cursor = QTextCursor(block)
        marked = QTextEdit.ExtraSelection()
        shade = QColor(THEME.alert)
        shade.setAlpha(70)
        look = QTextCharFormat()
        look.setBackground(shade)
        look.setProperty(QTextFormat.Property.FullWidthSelection, True)
        marked.format = look
        marked.cursor = cursor
        self._yaml.setExtraSelections([marked])
        # Moving the reader's cursor while they type would fight them; only
        # scroll the mistake into sight.
        if not self._yaml.hasFocus():
            self._yaml.setTextCursor(cursor)
            self._yaml.centerCursor()

    def save(self) -> bool:
        if not self._check():
            return False
        name = self._name.text().strip()
        try:
            rules_library.save_pack(
                name, self._yaml.toPlainText(), replacing=self._editing, built_in=self._built_in
            )
        except (RulePackError, rules_library.RulesLibraryError) as exc:
            self._refuse(in_words(exc) if isinstance(exc, RulePackError) else str(exc), None)
            return False
        self._reload(name)
        self._changed("Saved.")
        return True

    def confirm_delete(self) -> None:
        if self._editing is None:
            return
        (saved,) = [pack for pack in self._library.packs if pack.name == self._editing]
        rules = None if saved.problem else len(load_pack_text(f"{saved.name}.yaml", saved.text))
        self._confirm_text.setText(delete_question(saved.name, rules))
        self._confirm.show()

    def delete(self) -> None:
        if self._editing is None:
            return
        rules_library.delete_pack(self._editing)
        self._confirm.hide()
        self._reload(None)
        self._changed("Deleted.")

    def _keep(self) -> None:
        self._confirm.hide()

    def load_file(self, path: Path) -> str:
        """Copy a pack file into the library. "" when it worked, else why not."""
        try:
            name = rules_library.import_pack(path, built_in=self._built_in)
        except RulePackError as exc:
            return in_words(exc)
        except rules_library.RulesLibraryError as exc:
            return str(exc)
        self._reload(name)
        self._changed("Imported.")
        return ""

    def _ask_for_file(self) -> None:
        chosen, _ = QFileDialog.getOpenFileName(self, "Import rule pack", "", "Rule packs (*.yaml)")
        if chosen and (reason := self.load_file(Path(chosen))):
            QMessageBox.warning(self, "Pack not imported", reason)

    # -- a built-in pack -----------------------------------------------------

    def _open_built_in(self, name: str) -> None:
        (pack,) = [pack for pack in self._built_in if pack.name == name]
        self._pages.setCurrentIndex(1)
        self._built_name.setText(pack.name)
        self._built_note.setText(
            f"Built-in \u00b7 {plural(len(pack.rules), 'rule')}"
            + (f". {self._library.trouble}" if self._library.trouble else "")
        )
        self._built_yaml.setPlainText(pack.path.read_text(encoding="utf-8"))
        self._fill(self._built_table, pack.rules, switches=True)
        self._count(self._built_table, pack.rules)

    def _swap_view(self) -> None:
        showing_yaml = self._built_views.currentIndex() == 0
        self._built_views.setCurrentIndex(1 if showing_yaml else 0)
        self._as_yaml.setText("View table" if showing_yaml else "View YAML")

    def _switched(self, item: QTableWidgetItem) -> None:
        if item.column() != 0:
            return
        rule_id = required(self._built_table.item(item.row(), 1)).data(Qt.ItemDataRole.UserRole)
        on = item.checkState() == Qt.CheckState.Checked
        rules_library.switch_rule(rule_id, on=on)
        self._library = rules_library.in_force(built_in=self._built_in)
        self._colour_row(self._built_table, item.row())
        # A built-in switched back on can take its id back from one of the
        # reader's packs, which then stops loading: the list has to say so.
        current = self._packs.currentRow()
        self._fill_list()
        self._packs.blockSignals(True)
        self._packs.setCurrentRow(current)
        self._packs.blockSignals(False)
        self._changed("Switched on." if on else "Switched off.")

    # -- the tables and the count ---------------------------------------------

    def _fill(self, table: QTableWidget, rules: Sequence[Rule], *, switches: bool) -> None:
        table.blockSignals(True)
        table.setRowCount(len(rules))
        first = 1 if switches else 0
        for row, rule in enumerate(rules):
            if switches:
                box = QTableWidgetItem("")
                box.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                off = rule.id in self._library.ruleset.switched_off
                box.setCheckState(Qt.CheckState.Unchecked if off else Qt.CheckState.Checked)
                table.setItem(row, 0, box)
            name = QTableWidgetItem(rule.name)
            name.setToolTip(rule.id)
            name.setData(Qt.ItemDataRole.UserRole, rule.id)
            table.setItem(row, first, name)
            table.setItem(row, first + 1, QTableWidgetItem(rule.category.value.replace("_", " ")))
            severity = QTableWidgetItem(rule.severity.name.lower())
            # Kept on the cell, so a row painted faint and back keeps its colour.
            severity.setData(Qt.ItemDataRole.UserRole, severity_text_colour(rule.severity))
            table.setItem(row, first + 2, severity)
            for column in (3, 4):
                cell = QTableWidgetItem("")
                cell.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
                table.setItem(row, first + column, cell)
            self._colour_row(table, row)
        table.blockSignals(False)
        (self._built_widths if switches else self._finds_widths).fit_unset()

    def _colour_row(self, table: QTableWidget, row: int) -> None:
        """Every cell of a row from what it says now: faint when the rule is
        switched off or found nothing, the severity in its own colour, the rest
        in the text colour. Worked out whole each time, because a count changes
        under a row and a switch flips it, and either alone left it half right."""
        first = 1 if table is self._built_table else 0
        rule_id = required(table.item(row, first)).data(Qt.ItemDataRole.UserRole)
        off = table is self._built_table and rule_id in self._library.ruleset.switched_off
        # Put back what was in force, not "unblocked": called in the middle of
        # filling the table, unblocking let the next row's tick box report a
        # switch before that row had a rule in it.
        was_blocked = table.blockSignals(True)
        for column in range(first, table.columnCount()):
            cell = required(table.item(row, column))
            if off:
                colour = THEME.faint
            elif column == first + 2:
                colour = cell.data(Qt.ItemDataRole.UserRole)
            elif column >= first + 3 and cell.text() in ("", "—"):
                colour = THEME.faint
            else:
                colour = THEME.ink
            cell.setForeground(QColor(colour))
        table.blockSignals(was_blocked)

    def _show_counts(self, table: QTableWidget, finds: dict[str, Find]) -> None:
        first = 1 if table is self._built_table else 0
        table.blockSignals(True)
        for row in range(table.rowCount()):
            rule_id = required(table.item(row, first)).data(Qt.ItemDataRole.UserRole)
            found = finds.get(rule_id)
            if found is None:
                continue
            for column, value in ((3, found.lines), (4, found.clients)):
                required(table.item(row, first + column)).setText(
                    f"{value:,}" if found.lines else "—"
                )
            self._colour_row(table, row)
        table.blockSignals(False)

    def _count(self, table: QTableWidget, rules: Sequence[Rule]) -> None:
        """Count what `rules` find in the open case, into `table`, as clients are read.

        A new count replaces any running one: the old one is told to stop, and
        anything it still delivers is recognised by its generation and dropped.
        """
        self._stop_count()
        note = self._finds_note if table is self._finds else self._built_count
        if table is self._finds:
            self._fill(table, rules, switches=False)
        if not rules:
            note.setText("")
            return
        if self._case_path is None:
            note.setText("Open a case to see what it finds.")
            return
        generation = self._finds_generation
        self._finds_stop = stop = threading.Event()
        path = self._case_path

        def work(report: Callable[[object], None]) -> dict[str, Find] | None:
            try:
                return count_finds(path, rules, cancelled=stop.is_set, report=report)
            except FindsCancelled:
                return None

        def advanced(progress: object) -> None:
            if generation == self._finds_generation and isinstance(progress, FindsProgress):
                self._show_counts(table, progress.finds)
                note.setText(f"Read {progress.done:,} of {plural(progress.total, 'client')}…")

        def done(finds: dict[str, Find] | None) -> None:
            if generation != self._finds_generation or finds is None:
                return
            self._finds_stop = None
            self._show_counts(table, finds)
            note.setText("All clients counted.")

        def failed(message: str, _detail: str) -> None:
            if generation == self._finds_generation:
                self._finds_stop = None
                note.setText(f"Could not count: {message}")

        note.setText("Counting…")
        run_job(work, on_done=done, on_error=failed, on_advance=advanced)

    def _stop_count(self) -> None:
        self._finds_generation += 1
        if self._finds_stop is not None:
            self._finds_stop.set()
            self._finds_stop = None

    # -- ask first -----------------------------------------------------------

    def _changed(self, what: str) -> None:
        self.stale = True
        self.changed.emit()
        if self._case_path is not None:
            self._ask_text.setText(ask_text(what))
            self._ask.show()

    def _read_again(self) -> None:
        self.stale = False
        self._ask.hide()
        self.read_again.emit()

    def _later(self) -> None:
        self._ask.hide()

    def shutdown(self) -> None:
        """Stop what is running. The dialog calls it on its way out."""
        self._timer.stop()
        self._stop_count()
