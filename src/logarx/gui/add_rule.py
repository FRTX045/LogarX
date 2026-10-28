"""The Add a rule window: one signature rule from a form, into one of the reader's packs.

Opened from the Detection rules tab and from a line in the evidence panel. What
the form holds, its checks and its YAML are `rule_draft`'s; adding the text to a
pack safely is `rules_library.add_rule`'s; the wording is `gui.rule_form_view`'s.
What is here is the screen: the fields, the check line, what the rule matches in
the open case, and the question after saving.

The window does not re-read the case itself. Saving emits `saved`, and the
answer to the question emits `read_again` or `later`, for whoever opened it to
act on, so the rules tab and the main window each keep one owner of "the rules
changed".
"""

from __future__ import annotations

import html
import threading
from datetime import UTC
from pathlib import Path
from textwrap import indent
from types import EllipsisType
from typing import TYPE_CHECKING, Final

from PyQt6.QtCore import QSize, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from logarx import rules_library
from logarx.core.activity import ActivityCategory, Severity
from logarx.detect.rules import RulePackError, load_pack_text
from logarx.detect.ruleset import PackText, RuleSet, build_rules
from logarx.gui._qt import required
from logarx.gui.icon_picker import IconPicker
from logarx.gui.icon_set import DEFAULT_ICONS, FILE_PREFIX, KIND_NAMES, file_name_of
from logarx.gui.icons import Picked, adopt_icon_file, first_drawable, path_pixmap
from logarx.gui.rule_form_view import (
    CASE_NOTE,
    CATEGORY_LABELS,
    DECODED_TIP,
    EXACT_NOTE,
    FIELD_LABELS,
    TEST_LABELS,
    finds_caption,
    id_caption,
    parts_heading,
)
from logarx.gui.rules_view import ask_text, in_words
from logarx.gui.theme import GAP, ROOM, caption_font, mono_font, on_font_change
from logarx.gui.workers import run_job
from logarx.pack_append import CannotAppend, appended
from logarx.rule_draft import (
    FORM_FIELDS,
    Condition,
    Draft,
    LinePart,
    Test,
    conditions_from,
    line_parts,
    problems,
    rule_block,
    rule_id_for,
    tests_for,
)
from logarx.rule_finds import FindsCancelled, FindsProgress, count_finds
from logarx.style import THEME, display_safe

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence
    from pathlib import Path

    from logarx.detect.rules import Rule
    from logarx.detect.ruleset import BuiltInPack
    from logarx.evidence import EvidenceLine
    from logarx.rule_finds import Find

__all__ = ["AddRuleDialog"]

_PAUSE_MS: Final = 500
_ROW: Final = 26
_EXAMPLES: Final = 5
_EXAMPLE_COLUMNS: Final = ("Line", "Client", "When", "Request", "Status")
_CHOOSE: Final = "Choose…"

#: How big the rule's icon is drawn beside what it is.
_ICON_SHOWN: Final = 20

#: The longest value a request part's checkbox spells out. A checkbox label
#: never wraps, so a longer one is shortened in the middle, where it keeps the
#: start and the end of a payload, and the whole of it is on hover.
_PART_CHARS: Final = 80

#: Room kept between the window and the edges of the screen's work area.
_SCREEN_MARGIN: Final = 40


class _Natural(QScrollArea):
    """A scroll area that asks for as much room as its contents would take.

    `QScrollArea` asks for a fixed modest size whatever it holds. This one asks
    for its contents' own, so a window opens exactly as large as before, and
    only scrolls when that is more than the screen gives it.
    """

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt's naming
        inner = self.widget()
        if inner is None:
            return super().sizeHint()
        frame = self.frameWidth() * 2
        return inner.sizeHint() + QSize(frame, frame)


def _scrolled(content: QWidget) -> QScrollArea:
    area = _Natural()
    area.setWidget(content)
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    return area


def _part_label(label: str, value: str) -> str:
    """A request part as its checkbox says it: the value shortened past `_PART_CHARS`."""
    if len(value) > _PART_CHARS:
        keep = _PART_CHARS - 1
        value = value[: keep - keep // 3] + "\u2026" + value[len(value) - keep // 3 :]
    return f"{label}: {value}"


def _caption(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setWordWrap(True)
    label.setFont(caption_font(label.font()))
    return label


def _heading(text: str) -> QLabel:
    label = _caption(text)
    label.setStyleSheet(f"color: {THEME.muted};")
    return label


class _ConditionRow(QWidget):
    """One condition: field, test, value, and a button to take it away."""

    changed = pyqtSignal()
    removed = pyqtSignal(object)

    def __init__(self, condition: Condition) -> None:
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.field_box = QComboBox()
        self.field_box.setToolTip(DECODED_TIP)
        for field in FORM_FIELDS:
            self.field_box.addItem(FIELD_LABELS[field], field)
        self.test_box = QComboBox()
        self.value_box = QLineEdit()
        self.value_box.setFont(mono_font(QApplication.font().pointSizeF()))
        self.value_box.setAccessibleName("Value")
        self.remove_button = QToolButton()
        self.remove_button.setText("\N{MULTIPLICATION SIGN}")
        self.remove_button.setAccessibleName("Remove this condition")
        self.remove_button.setToolTip("Remove this condition")
        row.addWidget(self.field_box, 2)
        row.addWidget(self.test_box, 1)
        row.addWidget(self.value_box, 3)
        row.addWidget(self.remove_button)
        self.set(condition.field, condition.test, condition.value)
        self.field_box.currentIndexChanged.connect(self._field_changed)
        self.test_box.currentIndexChanged.connect(self.changed.emit)
        self.value_box.textChanged.connect(self.changed.emit)
        self.remove_button.clicked.connect(lambda: self.removed.emit(self))

    def set(self, field: str, test: Test, value: str) -> None:
        self.field_box.blockSignals(True)
        self.field_box.setCurrentIndex(self.field_box.findData(field))
        self.field_box.blockSignals(False)
        self._fill_tests(test)
        self.value_box.setText(value)
        self.changed.emit()

    def condition(self) -> Condition:
        return Condition(
            self.field_box.currentData(), Test(self.test_box.currentData()), self.value_box.text()
        )

    def _field_changed(self) -> None:
        self._fill_tests(Test(self.test_box.currentData()))
        self.changed.emit()

    def _fill_tests(self, keep: Test) -> None:
        offered = tests_for(self.field_box.currentData())
        self.test_box.blockSignals(True)
        self.test_box.clear()
        for test in offered:
            self.test_box.addItem(TEST_LABELS[test], test.value)
        self.test_box.setCurrentIndex(
            self.test_box.findData((keep if keep in offered else offered[0]).value)
        )
        self.test_box.blockSignals(False)


class AddRuleDialog(QDialog):
    """One rule, built from fields and added to one of the reader's packs."""

    saved = pyqtSignal(str)
    """A rule was written into this pack."""

    read_again = pyqtSignal()
    later = pyqtSignal()

    def __init__(
        self,
        parent: QWidget | None,
        *,
        case_path: Path | None,
        library: rules_library.Library,
        built_in: Sequence[BuiltInPack],
        into: str | None = None,
        line: EvidenceLine | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add a rule")
        self._case_path = case_path
        self._library = library
        self._built_in = built_in
        self._line = line
        self._taken = {rule.id for rule in build_rules(library.ruleset, built_in=built_in).rules}
        self._rows: list[_ConditionRow] = []
        self._block = ""
        self._answered = False
        self._finds_stop: threading.Event | None = None
        self._finds_generation = 0
        self._shown_generation = 0

        self._name = QLineEdit()
        self._name.setPlaceholderText("What it catches, in a few words")
        self._id_line = _caption()
        self._category = QComboBox()
        self._category.addItem(_CHOOSE, None)
        for category, label in CATEGORY_LABELS.items():
            self._category.addItem(label, category.value)
        self._severity = QComboBox()
        self._severity.addItem(_CHOOSE, None)
        for severity in Severity:
            self._severity.addItem(severity.name.lower(), severity.name)
        # The rule's own icon, if the reader gives it one. A file of theirs
        # stays a path until the rule is added, so nothing is copied for a
        # rule that never is.
        self._icon: Picked = None
        self.icon_chip = QPushButton()
        self.icon_chip.setObjectName("iconChip")
        self.icon_chip.setFlat(True)
        self.icon_chip.setAutoDefault(False)
        self.icon_chip.setIconSize(QSize(_ICON_SHOWN, _ICON_SHOWN))
        self.icon_chip.setToolTip("What the graph draws inside an activity this rule names.")
        self.icon_chip.clicked.connect(self._change_icon)
        self.icon_button = QPushButton("Change…")
        self.icon_button.setObjectName("changeIcon")
        self.icon_button.setAutoDefault(False)
        self.icon_button.clicked.connect(self._change_icon)
        self._category.currentIndexChanged.connect(self._show_icon)
        self._mode = QComboBox()
        self._mode.addItem("all", "all")
        self._mode.addItem("any", "any")
        self._rows_box = QVBoxLayout()
        self._rows_box.setContentsMargins(0, 0, 0, 0)
        self._add_row_button = QPushButton("+ Add condition")
        self._add_row_button.clicked.connect(lambda: self.add_condition())

        self._more_toggle = QToolButton()
        self._more_toggle.setText("More (optional)")
        self._more_toggle.setCheckable(True)
        self._confidence = QLineEdit()
        self._confidence.setPlaceholderText("1.0")
        self._owasp = QLineEdit()
        self._owasp.setPlaceholderText("A05:2025")
        self._references = QLineEdit()
        self._references.setPlaceholderText("CAPEC-66, a ticket, a link")
        self._more = self._more_fields()
        self._more_toggle.toggled.connect(self._more.setVisible)

        self._into = QComboBox()
        self._fill_into(into)
        self._check_line = _caption()
        self._yaml_view = QPlainTextEdit()
        self._yaml_view.setReadOnly(True)
        self._yaml_view.setFont(mono_font(QApplication.font().pointSizeF()))
        self._yaml_view.hide()
        self._finds_line = _caption()
        self._examples = QTableWidget(0, len(_EXAMPLE_COLUMNS))
        self._examples.setHorizontalHeaderLabels(list(_EXAMPLE_COLUMNS))
        required(self._examples.verticalHeader()).setVisible(False)
        self._examples.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._fit_rows()
        on_font_change(self._examples, self._fit_rows)

        self._view_yaml = QPushButton("View YAML")
        self._view_yaml.setObjectName("viewYaml")
        self._view_yaml.clicked.connect(self._toggle_yaml)
        self._add = QPushButton("Add rule")
        self._add.setObjectName("addRule")
        self._add.setDefault(True)
        self._add.clicked.connect(self.add)
        self._buttons = QDialogButtonBox()
        self._buttons.addButton(self._view_yaml, QDialogButtonBox.ButtonRole.ActionRole)
        cancel = required(self._buttons.addButton(QDialogButtonBox.StandardButton.Cancel))
        cancel.setObjectName("cancel")
        cancel.clicked.connect(self.reject)
        self._buttons.addButton(self._add, QDialogButtonBox.ButtonRole.AcceptRole)
        self._back = QPushButton("Back")
        self._back.setObjectName("back")
        self._back.clicked.connect(lambda: self._pages.setCurrentIndex(0))
        self._buttons.addButton(self._back, QDialogButtonBox.ButtonRole.ResetRole)
        self._exact_note = _caption(EXACT_NOTE)

        # -- the first step when started from a line
        self._parts_heading = _caption()
        self._parts_note = _caption()
        self._parts_note.setStyleSheet(f"color: {THEME.alert};")
        self._part_boxes: list[tuple[LinePart, QCheckBox]] = []
        self._pages = QStackedWidget()
        self._ask, self._ask_text = self._bar(
            ("Re-read now", self._re_read, "readAgain"), ("Later", self._put_off, "later")
        )

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(_PAUSE_MS)
        self._timer.timeout.connect(self._check)
        for box in (self._category, self._severity, self._mode, self._into):
            box.currentIndexChanged.connect(self._schedule)
        for edit in (self._name, self._confidence, self._owasp, self._references):
            edit.textChanged.connect(self._schedule)

        self._build()
        if line is not None and line.event is not None:
            self._parts_heading.setText(parts_heading(line.ref.line_no))
            self._parts_note.setText(line.note or "")
            self._parts_note.setVisible(bool(line.note))
            for part in line_parts(line.event):
                shown = display_safe(part.value)
                tick = QCheckBox(_part_label(FIELD_LABELS[part.field], shown))
                # Escaped and marked up, or Qt reads a payload that looks like
                # HTML as HTML and the hover loses the very part that matters.
                tick.setToolTip(f"<span style='white-space:pre-wrap'>{html.escape(shown)}</span>")
                tick.setChecked(part.ticked)
                self._part_boxes.append((part, tick))
            self._pages.setCurrentIndex(0)
        else:
            self._back.hide()
            self._exact_note.hide()
            self.add_condition()
            self._pages.setCurrentIndex(1)
        self._fill_parts_page()
        self._fit_to_screen()
        self._schedule()

    # -- assembling ----------------------------------------------------------

    def _more_fields(self) -> QWidget:
        more = QWidget()
        row = QHBoxLayout(more)
        row.setContentsMargins(0, 0, 0, 0)
        for label, edit, stretch in (
            ("Confidence", self._confidence, 1),
            ("OWASP", self._owasp, 1),
            ("References", self._references, 3),
        ):
            column = QVBoxLayout()
            column.addWidget(_heading(label))
            column.addWidget(edit)
            row.addLayout(column, stretch)
        more.hide()
        return more

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

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(ROOM, ROOM, ROOM, ROOM)
        self._parts_page = QWidget()
        form = QWidget()
        self._pages.addWidget(self._parts_page)
        self._pages.addWidget(form)
        outer.addWidget(self._pages)
        # The fields scroll and the buttons under them do not, so however many
        # conditions there are, Add rule is never below the bottom of the screen.
        page = QVBoxLayout(form)
        page.setContentsMargins(0, 0, 0, 0)
        page.setSpacing(GAP // 2)
        fields = QWidget()
        page.addWidget(_scrolled(fields), 1)
        page.addWidget(self._ask)
        page.addWidget(self._buttons)
        column = QVBoxLayout(fields)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(GAP // 2)
        column.addWidget(_heading("Name"))
        column.addWidget(self._name)
        column.addWidget(self._id_line)
        kinds = QHBoxLayout()
        for label, box, stretch in (
            ("What kind of activity", self._category, 2),
            ("Severity", self._severity, 1),
        ):
            part = QVBoxLayout()
            part.addWidget(_heading(label))
            part.addWidget(box)
            kinds.addLayout(part, stretch)
        column.addLayout(kinds)
        icon_row = QHBoxLayout()
        icon_row.addWidget(_heading("Icon"))
        icon_row.addWidget(self.icon_chip)
        icon_row.addWidget(self.icon_button)
        icon_row.addStretch(1)
        column.addLayout(icon_row)
        self._show_icon()
        mode = QHBoxLayout()
        mode.addWidget(QLabel("A request matches when"))
        mode.addWidget(self._mode)
        mode.addWidget(QLabel("of these are true:"))
        mode.addStretch(1)
        column.addLayout(mode)
        column.addLayout(self._rows_box)
        adding = QHBoxLayout()
        adding.addWidget(self._add_row_button)
        adding.addStretch(1)
        column.addLayout(adding)
        column.addWidget(_caption(CASE_NOTE))
        column.addWidget(self._exact_note)
        column.addWidget(self._more_toggle)
        column.addWidget(self._more)
        into = QHBoxLayout()
        into.addWidget(_heading("Save into"))
        into.addWidget(self._into, 1)
        column.addLayout(into)
        column.addWidget(self._check_line)
        column.addWidget(self._yaml_view, 2)
        column.addWidget(_heading("Matches in this case"))
        column.addWidget(self._finds_line)
        column.addWidget(self._examples, 2)

    def _fill_parts_page(self) -> None:
        page = QVBoxLayout(self._parts_page)
        page.setContentsMargins(0, 0, 0, 0)
        page.setSpacing(GAP // 2)
        parts = QWidget()
        page.addWidget(_scrolled(parts), 1)
        column = QVBoxLayout(parts)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(GAP // 2)
        column.addWidget(self._parts_heading)
        column.addWidget(self._parts_note)
        for _part, box in self._part_boxes:
            box.setFont(mono_font(QApplication.font().pointSizeF()))
            column.addWidget(box)
        column.addStretch(1)
        buttons = QDialogButtonBox()
        go_on = QPushButton("Continue")
        go_on.setObjectName("continue")
        go_on.setDefault(True)
        go_on.clicked.connect(self._continue)
        buttons.addButton(go_on, QDialogButtonBox.ButtonRole.AcceptRole)
        cancel = required(buttons.addButton(QDialogButtonBox.StandardButton.Cancel))
        cancel.clicked.connect(self.reject)
        page.addWidget(buttons)

    def _fit_to_screen(self) -> None:
        """Open as large as the contents ask, but never past the screen's work area."""
        screen = self.screen() or QApplication.primaryScreen()
        if screen is None:
            return
        area = screen.availableGeometry()
        wanted = self.sizeHint()
        self.resize(
            min(wanted.width(), area.width() - _SCREEN_MARGIN),
            min(wanted.height(), area.height() - _SCREEN_MARGIN),
        )

    def _continue(self) -> None:
        """Conditions from the ticked parts, in place of any there; the rest is kept."""
        for row in list(self._rows):
            self._remove(row)
        ticked = [part for part, box in self._part_boxes if box.isChecked()]
        for condition in conditions_from(LinePart(p.field, p.value, True) for p in ticked):
            self.add_condition(condition.field, condition.test, condition.value)
        self._mode.setCurrentIndex(self._mode.findData("all"))
        self._pages.setCurrentIndex(1)

    def _fit_rows(self) -> None:
        """Rows of `_ROW`, taller only when zoomed text would not fit it."""
        height = max(_ROW, self._examples.fontMetrics().height() + 8)
        required(self._examples.verticalHeader()).setDefaultSectionSize(height)

    def _fill_into(self, preferred: str | None) -> None:
        loading = [pack.name for pack in self._library.packs if not pack.problem]
        names = list(loading)
        default = rules_library.DEFAULT_PACK.casefold()
        if not any(name.casefold() == default for name in loading):
            names.append(rules_library.DEFAULT_PACK)
        self._into.addItems(names)
        chosen = rules_library.target_for(self._library, preferred).name
        self._into.setCurrentIndex(max(self._into.findText(chosen), 0))

    # -- the form ------------------------------------------------------------

    def add_condition(
        self, field: str = "path_decoded", test: Test = Test.CONTAINS, value: str = ""
    ) -> _ConditionRow:
        row = _ConditionRow(Condition(field, test, value))
        row.changed.connect(self._schedule)
        row.removed.connect(self._remove)
        self._rows.append(row)
        self._rows_box.addWidget(row)
        self._schedule()
        return row

    def _remove(self, row: _ConditionRow) -> None:
        self._rows.remove(row)
        row.setParent(None)
        row.deleteLater()
        self._schedule()

    def draft(self) -> Draft:
        category = self._category.currentData()
        severity = self._severity.currentData()
        return Draft(
            name=self._name.text(),
            category=None if category is None else ActivityCategory(category),
            severity=None if severity is None else Severity[severity],
            mode="any" if self._mode.currentData() == "any" else "all",
            conditions=tuple(row.condition() for row in self._rows),
            confidence=self._confidence.text(),
            owasp=self._owasp.text(),
            references=self._references.text(),
            icon=_value_of(self._icon),
        )

    # -- the icon --------------------------------------------------------------

    def _kind(self) -> ActivityCategory | None:
        chosen = self._category.currentData()
        return None if chosen is None else ActivityCategory(chosen)

    def _pick_icon(self) -> Picked | EllipsisType:
        """Ask the picker; `...` when the reader cancelled it."""
        kind = self._kind()
        picker = IconPicker(
            title=f"Icon for {self._name.text().strip() or 'this rule'}",
            current=self._icon,
            default=DEFAULT_ICONS[kind or ActivityCategory.UNKNOWN],
            parent=self,
        )
        if picker.exec() != int(IconPicker.DialogCode.Accepted.value):
            return ...
        return picker.choice

    def _change_icon(self) -> None:
        picked = self._pick_icon()
        if isinstance(picked, EllipsisType):
            return
        self._icon = picked
        self._show_icon()
        self._schedule()

    def _show_icon(self) -> None:
        """The chip: the rule's own icon and its name, or its kind's and "Same as"."""
        kind = self._kind()
        own = DEFAULT_ICONS[kind or ActivityCategory.UNKNOWN]
        picked = self._icon
        if picked is None:
            text = f"Same as {KIND_NAMES[kind]}" if kind is not None else "Same as the kind"
            drawn = first_drawable([own], THEME.ink, _ICON_SHOWN)
        elif isinstance(picked, Path):
            text = picked.name
            drawn = path_pixmap(picked, _ICON_SHOWN) or first_drawable(
                [own], THEME.ink, _ICON_SHOWN
            )
        else:
            text = file_name_of(picked) or picked
            drawn = first_drawable([picked, own], THEME.ink, _ICON_SHOWN)
        self.icon_chip.setText(text)
        self.icon_chip.setIcon(QIcon(drawn))

    def _target(self) -> rules_library.Target:
        name = self._into.currentText()
        if any(pack.name == name and not pack.problem for pack in self._library.packs):
            return rules_library.Target(name, True)
        return rules_library.target_for(self._library, None)

    def _started_from(self, target: rules_library.Target) -> str:
        if not target.exists:
            return rules_library.NEW_PACK_HEAD
        return next(pack.text for pack in self._library.packs if pack.name == target.name)

    def _schedule(self) -> None:
        self._add.setEnabled(False)
        self._timer.start()

    def _check(self) -> bool:
        """Check the form as it stands. True when the rule can be added."""
        self._timer.stop()
        draft = self.draft()
        rule_id = rule_id_for(draft.name, self._taken)
        self._id_line.setText(id_caption(rule_id) if rule_id else "")
        found = problems(draft)
        target = self._target()
        if found or target.problem:
            return self._refuse(found[0] if found else target.problem)
        block = rule_block(draft, rule_id)
        others = tuple(pack for pack in self._library.ruleset.packs if pack.name != target.name)
        try:
            text = appended(self._started_from(target), block)
            build_rules(
                RuleSet((*others, PackText(target.name, text)), self._library.ruleset.switched_off),
                built_in=self._built_in,
            )
        except CannotAppend as exc:
            return self._refuse(
                f"{exc} Add the rule in the YAML editor: View YAML gives its text.", block
            )
        except RulePackError as exc:
            return self._refuse(in_words(exc))
        self._block = block
        self._yaml_view.setPlainText(block)
        self._check_line.setStyleSheet("")
        self._check_line.setText("Ready to add.")
        self._add.setEnabled(True)
        self._count(load_pack_text("new.yaml", "version: 1\nrules:\n" + indent(block, "  ")))
        return True

    def _refuse(self, message: str, block: str = "") -> bool:
        """Say why the rule cannot be added. `block` stays in View YAML when the
        reader is told to paste it into the YAML editor instead."""
        self._stop_count()
        self._block = ""
        self._add.setEnabled(False)
        self._check_line.setStyleSheet(f"color: {THEME.alert};")
        self._check_line.setText(message)
        self._yaml_view.setPlainText(block)
        self._examples.setRowCount(0)
        self._finds_line.setText("")
        return False

    def _toggle_yaml(self) -> None:
        showing = self._yaml_view.isHidden()
        self._yaml_view.setVisible(showing)
        self._view_yaml.setText("Hide YAML" if showing else "View YAML")

    # -- saving --------------------------------------------------------------

    def add(self) -> bool:
        """Write the rule into the chosen pack. True when it was written."""
        if isinstance(source := self._icon, Path):
            # Copied now, as the rule goes in, and under the name the copy
            # really got: a clash is numbered, and the rule must say which.
            try:
                self._icon = adopt_icon_file(source)
            except OSError as exc:
                return self._refuse(f"{source.name} could not be copied: {exc.strerror}.")
            self._show_icon()
        if not self._check():
            return False
        target = self._target()
        block = self._block
        try:
            rules_library.add_rule(
                target,
                block,
                started_from=self._started_from(target) if target.exists else "",
                built_in=self._built_in,
            )
        except CannotAppend as exc:
            return self._refuse(
                f"{exc} Add the rule in the YAML editor: View YAML gives its text.", block
            )
        except RulePackError as exc:
            return self._refuse(in_words(exc))
        except rules_library.RulesLibraryError as exc:
            return self._refuse(str(exc), block)
        self.saved.emit(target.name)
        if self._case_path is None:
            self._answered = True
            self.accept()
            return True
        self._ask_text.setText(ask_text("Saved."))
        self._buttons.hide()
        self._ask.show()
        return True

    def _re_read(self) -> None:
        self._answered = True
        self.read_again.emit()
        self.accept()

    def _put_off(self) -> None:
        self._answered = True
        self.later.emit()
        self.accept()

    def done(self, result: int) -> None:
        """Every way out: the question still open counts as Later."""
        if not self._answered and not self._ask.isHidden():
            self._answered = True
            self.later.emit()
        self.shutdown()
        super().done(result)

    def shutdown(self) -> None:
        self._timer.stop()
        self._stop_count()

    # -- what it matches -----------------------------------------------------

    def _count(self, rules: Sequence[Rule]) -> None:
        self._stop_count()
        self._examples.setRowCount(0)
        if self._case_path is None:
            self._finds_line.setText(finds_caption(None, running=False))
            return
        generation = self._finds_generation
        self._finds_stop = stop = threading.Event()
        path = self._case_path
        rule_id = rules[0].id

        def work(report: Callable[[object], None]) -> dict[str, Find] | None:
            try:
                return count_finds(
                    path, rules, cancelled=stop.is_set, report=report, examples=_EXAMPLES
                )
            except FindsCancelled:
                return None

        def advanced(progress: object) -> None:
            if generation == self._finds_generation and isinstance(progress, FindsProgress):
                self._show(generation, progress.finds.get(rule_id), running=True)

        def done(finds: dict[str, Find] | None) -> None:
            if generation != self._finds_generation or finds is None:
                return
            self._finds_stop = None
            self._show(generation, finds.get(rule_id), running=False)

        def failed(message: str, _detail: str) -> None:
            if generation == self._finds_generation:
                self._finds_stop = None
                self._finds_line.setText(f"Could not count: {message}")

        self._finds_line.setText("Counting…")
        run_job(work, on_done=done, on_error=failed, on_advance=advanced)

    def _show(self, generation: int, find: Find | None, *, running: bool) -> None:
        if find is None:
            return
        self._shown_generation = generation
        self._finds_line.setText(finds_caption(find, running=running))
        self._examples.setRowCount(len(find.examples))
        for row, example in enumerate(find.examples):
            cells = (
                str(example.ref.line_no),
                example.client,
                example.when.astimezone(UTC).strftime("%d %b %H:%M:%S"),
                example.request,
                "" if example.status is None else str(example.status),
            )
            for column, text in enumerate(cells):
                self._examples.setItem(row, column, QTableWidgetItem(text))

    def _stop_count(self) -> None:
        self._finds_generation += 1
        if self._finds_stop is not None:
            self._finds_stop.set()
            self._finds_stop = None


def _value_of(picked: Picked) -> str:
    """What a rule's `icon:` says for `picked`: a file not copied yet by the
    name it will be copied under, nothing at all for "same as the kind"."""
    if picked is None:
        return ""
    if isinstance(picked, Path):
        return FILE_PREFIX + picked.name
    return picked
