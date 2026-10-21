"""The Detection rules tab: the built-in packs, the reader's own, and what each finds."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QPushButton

from conftest import fired, settled
from logarc import rules_library
from logarc.case import Case
from logarc.gui import rules_editor as rules_editor_module
from logarc.gui.rules_editor import RulesEditor
from logarc.rule_finds import Find, FindsCancelled

SHOPFRONT_LOG = Path(__file__).parents[1] / "data" / "apache-shopfront" / "excerpt.log"

#: One rule that finds nothing on the shopfront log.
CART_NEVER = """\
version: 1
rules:
  - id: shop_cart_emptied_by_api
    name: Cart emptied through the API
    category: api_call
    severity: info
    match:
      all:
        - {field: method, equals: DELETE}
        - {field: path, regex: "^/never$"}
"""

SHOPFRONT = """\
version: 1
note: What misuse of our own shop's API looks like
rules:
  - id: shop_stock_polling
    name: Stock levels polled by a script
    category: crawling
    severity: low
    confidence: 0.7
    member:
      all:
        - {field: path, regex: "^/api/stock$"}
    window:
      span_seconds: 300
      min_requests: 3
      conditions:
        - {metric: request_count, op: ">=", value: 3}

  - id: shop_cart_emptied_by_api
    name: Cart emptied through the API
    category: api_call
    severity: info
    match:
      all:
        - {field: method, equals: DELETE}
        - {field: path, regex: "^/api/cart$"}
"""


@pytest.fixture(scope="module")
def shopfront_case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("rules-tab") / "case"
    with Case.create(root) as case:
        case.ingest([SHOPFRONT_LOG])
    return root


def _typed(editor: RulesEditor, text: str) -> None:
    editor._yaml.setPlainText(text)
    fired(editor._timer)


def _until(condition, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "the condition never held"
        QTest.qWait(10)


def _counts(editor: RulesEditor, table_name: str = "_finds") -> dict[str, tuple[str, str]]:
    table = getattr(editor, table_name)
    first = 1 if table_name == "_built_table" else 0
    return {
        table.item(row, first).data(Qt.ItemDataRole.UserRole): (
            table.item(row, first + 3).text(),
            table.item(row, first + 4).text(),
        )
        for row in range(table.rowCount())
    }


def test_the_list_holds_packs_yours_first(qt_app: QApplication) -> None:
    """Only packs: the commands that were rows in it are buttons under it."""
    rules_library.save_pack("shopfront", SHOPFRONT)

    editor = RulesEditor()

    assert editor.listed() == [
        "CUSTOM", "Untitled", "shopfront",
        "BUILT-IN", "actions", "access", "files", "injection", "recon", "ssrf",
        "java", "nodejs", "perl", "php", "python", "shell", "windows",
    ]  # fmt: skip
    assert not [row for row in editor.listed() if row.endswith("\u2026")]


def test_new_and_import_are_buttons_under_the_list(qt_app: QApplication) -> None:
    editor = RulesEditor()

    assert editor.new_button.text() == "New"
    assert editor.import_button.text() == "Import\u2026"
    assert editor.new_button.toolTip()
    assert editor.import_button.toolTip()


def test_new_starts_an_untitled_pack_from_wherever_you_are(qt_app: QApplication) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)
    editor = RulesEditor()
    editor.select("shopfront")

    editor.new_button.click()

    assert editor._packs.currentItem().text() == "Untitled"
    assert editor._name.text() == ""
    assert "rules:" in editor._yaml.toPlainText()
    assert not editor._delete.isEnabled()


def test_import_copies_the_file_in_and_opens_it(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "house.yaml"
    source.write_text(SHOPFRONT, encoding="utf-8")
    monkeypatch.setattr(
        rules_editor_module.QFileDialog,
        "getOpenFileName",
        lambda *_args, **_kwargs: (str(source), ""),
    )
    editor = RulesEditor()

    editor.import_button.click()

    assert editor._packs.currentItem().text() == "house"
    assert "house" in editor.listed()


def test_a_pack_s_note_is_its_tooltip_in_the_list(qt_app: QApplication) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)

    editor = RulesEditor()
    (row,) = [
        r for r in range(editor._packs.count()) if editor._packs.item(r).text() == "shopfront"
    ]

    assert editor._packs.item(row).toolTip() == "What misuse of our own shop's API looks like"


def test_a_pack_broken_on_disk_is_listed_as_not_loading(qt_app: QApplication) -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "broken.yaml").write_text("version: 1\nrules:\n  - id: x\n", encoding="utf-8")

    editor = RulesEditor()

    assert "broken (does not load)" in editor.listed()


def test_a_mistake_turns_save_off_and_marks_its_line(qt_app: QApplication) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)
    editor = RulesEditor()
    editor.select("shopfront")

    broken = SHOPFRONT.replace(
        "{field: method, equals: DELETE}", "{field: method, equals: DELETE, contains: X}"
    )
    _typed(editor, broken)

    assert not editor._save.isEnabled()
    assert editor._status.text().startswith(
        "Rule shop_cart_emptied_by_api, first condition under match"
    )
    (marked,) = editor._yaml.extraSelections()
    assert marked.cursor.blockNumber() + 1 == next(
        n for n, line in enumerate(broken.splitlines(), 1) if "contains: X" in line
    )


def test_the_last_saved_version_keeps_applying_while_the_edit_is_wrong(
    qt_app: QApplication,
) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)
    editor = RulesEditor()
    editor.select("shopfront")

    _typed(editor, "version: 1\nrules:\n  - id: x\n")

    assert not editor.save()
    assert rules_library.in_force().ruleset.packs[0].text == SHOPFRONT


def test_a_pack_that_reads_says_what_it_holds_and_can_be_saved(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor._name.setText("shopfront")

    _typed(editor, SHOPFRONT)

    assert (
        editor._status.text()
        == "2 rules read: 1 about a single request, 1 about a run of requests."
    )
    assert editor._save.isEnabled()
    assert editor.save()
    assert "shopfront" in editor.listed()


def test_saving_a_pack_that_clashes_with_another_is_refused(qt_app: QApplication) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)
    editor = RulesEditor()
    editor._name.setText("again")

    _typed(editor, SHOPFRONT)

    assert not editor._save.isEnabled()
    assert "shopfront" in editor._status.text()


def test_a_name_that_is_not_a_file_name_is_refused(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor._name.setText("my rules")

    _typed(editor, SHOPFRONT)

    assert not editor._save.isEnabled()
    assert editor._status.text() == "A name can hold letters, digits, - and _ only."


def test_deleting_asks_inside_the_panel_first(qt_app: QApplication) -> None:
    rules_library.save_pack("shopfront", SHOPFRONT)
    editor = RulesEditor()
    editor.show()
    editor.select("shopfront")

    editor.confirm_delete()

    assert editor._confirm.isVisible()
    assert editor._confirm_text.text() == "Delete shopfront? Its 2 rules stop applying."
    assert rules_library.in_force().ruleset.packs  # nothing deleted yet

    editor.delete()

    assert rules_library.in_force().ruleset.packs == ()
    assert "shopfront" not in editor.listed()


def test_unticking_a_built_in_rule_writes_the_file_at_once(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor.select("recon")
    table = editor._built_table
    (row,) = [
        r for r in range(table.rowCount())
        if table.item(r, 1).data(Qt.ItemDataRole.UserRole) == "http_library_user_agent"
    ]  # fmt: skip

    table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)

    stored = json.loads((rules_library.rules_dir() / "switched-off.json").read_text("utf-8"))
    assert stored == ["http_library_user_agent"]
    assert editor.stale


def test_show_as_yaml_swaps_the_table_for_the_source(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor.select("recon")

    editor._as_yaml.click()

    assert editor._built_views.currentIndex() == 1
    assert editor._as_yaml.text() == "View table"
    editor._as_yaml.click()
    assert editor._built_views.currentIndex() == 0


def test_with_no_case_open_the_count_says_so(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor._name.setText("shopfront")

    _typed(editor, SHOPFRONT)

    assert editor._finds_note.text() == "Open a case to see what it finds."


def test_the_example_pack_s_counts_on_the_shopfront_case(
    qt_app: QApplication, shopfront_case: Path
) -> None:
    editor = RulesEditor(shopfront_case)
    editor._name.setText("shopfront")

    _typed(editor, SHOPFRONT)
    settled(qt_app)

    assert _counts(editor) == {
        "shop_stock_polling": ("29", "7"),
        "shop_cart_emptied_by_api": ("1", "1"),
    }
    editor.shutdown()


def test_a_count_that_finishes_after_an_edit_is_not_shown(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Held open by hand, so the order is the one that goes wrong: the count for
    the edited pack lands first, the one for the pack before it lands after."""
    gates: list[threading.Event] = []

    def held(path, rules, *, cancelled, report):
        gate = threading.Event()
        gates.append(gate)
        gate.wait(10)
        # Ignores `cancelled` on purpose: a count past its last check still returns.
        return {rule.id: Find(99, 9) if len(rules) == 2 else Find(0, 0) for rule in rules}

    monkeypatch.setattr(rules_editor_module, "count_finds", held)
    editor = RulesEditor(shopfront_case)
    editor._name.setText("shopfront")
    _typed(editor, SHOPFRONT)
    _typed(editor, CART_NEVER)
    _until(lambda: len(gates) == 2)

    gates[1].set()
    _until(lambda: _counts(editor) == {"shop_cart_emptied_by_api": ("—", "—")})
    gates[0].set()
    settled(qt_app)

    assert _counts(editor) == {"shop_cart_emptied_by_api": ("—", "—")}


def test_closing_the_dialog_stops_the_count(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    told: list[bool] = []

    def waits(path, rules, *, cancelled, report):
        deadline = time.monotonic() + 10
        while not cancelled():
            if time.monotonic() > deadline:
                told.append(False)
                return {}
            time.sleep(0.01)
        told.append(True)
        raise FindsCancelled

    monkeypatch.setattr(rules_editor_module, "count_finds", waits)
    editor = RulesEditor(shopfront_case)
    editor._name.setText("shopfront")
    _typed(editor, SHOPFRONT)

    editor.shutdown()
    settled(qt_app)

    assert told == [True]


def test_a_built_in_pack_s_counts_fill_in(qt_app: QApplication, shopfront_case: Path) -> None:
    """The preview's figure for Scripted Client on this log: 117 lines from 4 clients."""
    editor = RulesEditor(shopfront_case)
    editor.select("recon")
    settled(qt_app)

    assert _counts(editor, "_built_table")["http_library_user_agent"] == ("117", "4")
    assert editor._built_count.text() == "All clients counted."


def test_a_damaged_switch_file_is_said_on_a_built_in_pack(qt_app: QApplication) -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "switched-off.json").write_text("{not json")

    editor = RulesEditor()
    editor.select("recon")

    assert "Every built-in rule is on" in editor._built_note.text()


def test_a_new_pack_asks_for_a_name_without_calling_it_a_mistake(qt_app: QApplication) -> None:
    editor = RulesEditor()

    assert editor._status.text() == (
        "No rules yet. Add them under rules:, as in the example. Name the pack to save it."
    )
    assert editor._status.styleSheet() == ""
    assert not editor._save.isEnabled()


def test_saving_with_a_case_open_asks_whether_to_read_it_again(
    qt_app: QApplication, shopfront_case: Path
) -> None:
    editor = RulesEditor(shopfront_case)
    editor.show()
    editor._name.setText("shopfront")
    _typed(editor, SHOPFRONT)
    asked: list[bool] = []
    editor.read_again.connect(lambda: asked.append(True))

    editor.save()

    assert editor._ask.isVisible()
    assert editor._ask_text.text() == "Saved. The open case was read with the old rules."
    editor._ask.findChild(QPushButton, "readAgain").click()
    assert asked == [True]
    assert not editor.stale
    editor.shutdown()
    settled(qt_app)


def test_with_no_case_open_nothing_is_asked(qt_app: QApplication) -> None:
    editor = RulesEditor()
    editor.show()
    editor._name.setText("shopfront")
    _typed(editor, SHOPFRONT)

    editor.save()

    assert not editor._ask.isVisible()


def test_loading_a_file_copies_it_and_selects_it(qt_app: QApplication, tmp_path: Path) -> None:
    source = tmp_path / "My Rules.yaml"
    source.write_text(SHOPFRONT, encoding="utf-8")
    editor = RulesEditor()

    assert editor.load_file(source) == ""
    assert editor._packs.currentItem().text() == "My-Rules"


def test_loading_a_file_that_does_not_load_says_why(qt_app: QApplication, tmp_path: Path) -> None:
    source = tmp_path / "bad.yaml"
    source.write_text("version: 1\nrules:\n  - id: x\n", encoding="utf-8")

    reason = RulesEditor().load_file(source)

    assert reason.startswith("Rule x")


def test_a_count_that_climbs_from_nothing_is_not_left_faint(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Seen in the first real screenshot: a cell drawn faint while its rule had
    found nothing yet stayed faint once its lines arrived, so a rule that was on
    and finding things looked switched off."""
    from logarc.rule_finds import FindsProgress
    from logarc.style import THEME

    def climbing(path, rules, *, cancelled, report):
        report(FindsProgress(1, 2, {rule.id: Find(0, 0) for rule in rules}))
        return {rule.id: Find(5, 1) for rule in rules}

    monkeypatch.setattr(rules_editor_module, "count_finds", climbing)
    editor = RulesEditor(shopfront_case)
    editor._name.setText("shopfront")
    _typed(editor, SHOPFRONT)
    settled(qt_app)

    table = editor._finds
    assert {table.item(row, 3).text() for row in range(table.rowCount())} == {"5"}
    assert {
        table.item(row, column).foreground().color().name()
        for row in range(table.rowCount())
        for column in (3, 4)
    } == {QColor(THEME.ink).name()}


def test_switching_a_rule_back_on_gives_it_its_colours_back(qt_app: QApplication) -> None:
    """Ticking a rule again repainted its whole row in the plain text colour,
    and its severity lost the colour every other row's keeps."""
    from logarc.core.activity import Severity
    from logarc.style import severity_text_colour

    editor = RulesEditor()
    editor.select("recon")
    table = editor._built_table
    (row,) = [
        r for r in range(table.rowCount())
        if table.item(r, 1).data(Qt.ItemDataRole.UserRole) == "http_library_user_agent"
    ]  # fmt: skip

    table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
    table.item(row, 0).setCheckState(Qt.CheckState.Checked)

    assert (
        table.item(row, 3).foreground().color().name()
        == QColor(severity_text_colour(Severity.INFO)).name()
    )


def test_a_built_in_pack_is_introduced_by_its_count(qt_app: QApplication) -> None:
    """The advice about unticking moved to the On column, where it is acted on."""
    editor = RulesEditor()
    editor.select("recon")

    assert editor._built_note.text() == "Built-in \u00b7 15 rules"
    assert "Untick" in editor._built_table.horizontalHeaderItem(0).toolTip()


def test_the_rules_tab_labels_are_short(qt_app: QApplication) -> None:
    from PyQt6.QtWidgets import QLabel

    editor = RulesEditor()
    words = {label.text() for label in editor.findChildren(QLabel)}

    assert {"Rule packs", "Name", "Rules (YAML)", "Matches in this case"} <= words
    assert editor._as_yaml.text() == "View YAML"
    assert editor._name.placeholderText() == "my-site"
    assert editor._name.toolTip() == "Letters, digits, - and _"
    assert editor._ask.findChild(QPushButton, "readAgain").text() == "Re-read now"
