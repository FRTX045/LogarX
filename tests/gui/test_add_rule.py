"""The Add a rule window: one signature rule from a form, into one of the reader's packs."""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QCoreApplication, QEvent
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QPushButton

from conftest import fired, settled
from logarc import rules_library
from logarc.case import Case
from logarc.core.activity import ActivityCategory, Severity
from logarc.detect.rules import load_pack_text
from logarc.detect.ruleset import built_in_packs
from logarc.gui import add_rule as add_rule_module
from logarc.gui.add_rule import AddRuleDialog
from logarc.rule_draft import Test, rule_block
from logarc.rule_finds import Find, FindsProgress

SHOPFRONT_LOG = Path(__file__).parents[1] / "data" / "apache-shopfront" / "excerpt.log"
BUILT_IN = built_in_packs()

SHOP = """\
version: 1
rules:
  - id: shop_probe
    name: Shop probe
    category: injection
    severity: high
    match:
      all:
        - {field: path, equals: /shop-probe}
"""


@pytest.fixture(scope="module")
def shopfront_case(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("add-rule") / "case"
    with Case.create(root) as case:
        case.ingest([SHOPFRONT_LOG])
    return root


def _dialog(case_path: Path | None = None, *, into: str | None = None) -> AddRuleDialog:
    library = rules_library.in_force(built_in=BUILT_IN)
    return AddRuleDialog(None, case_path=case_path, library=library, built_in=BUILT_IN, into=into)


def _fill(
    dialog: AddRuleDialog,
    *,
    name: str = "Cart emptied",
    category: ActivityCategory = ActivityCategory.API_CALL,
    severity: Severity = Severity.INFO,
    conditions: tuple[tuple[str, Test, str], ...] = (("method", Test.EQUALS, "DELETE"),),
) -> None:
    dialog._name.setText(name)
    dialog._category.setCurrentIndex(dialog._category.findData(category.value))
    dialog._severity.setCurrentIndex(dialog._severity.findData(severity.name))
    for index, (field, test, value) in enumerate(conditions):
        row = dialog._rows[index] if index < len(dialog._rows) else dialog.add_condition()
        row.set(field, test, value)
    fired(dialog._timer)


def _until(condition, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "the condition never held"
        QTest.qWait(10)


def _button(dialog: AddRuleDialog, name: str) -> QPushButton:
    found = dialog.findChild(QPushButton, name)
    assert found is not None, name
    return found


def _ids(name: str) -> list[str]:
    text = (rules_library.rules_dir() / f"{name}.yaml").read_text(encoding="utf-8")
    return [rule.id for rule in load_pack_text("t.yaml", text)]


def test_a_blank_form_cannot_be_added(qt_app: QApplication) -> None:
    dialog = _dialog()
    fired(dialog._timer)

    assert not _button(dialog, "addRule").isEnabled()
    assert dialog._check_line.text() == "Give the rule a name."
    dialog.shutdown()


def test_category_and_severity_start_unchosen(qt_app: QApplication) -> None:
    dialog = _dialog()
    dialog._name.setText("Cart emptied")
    dialog._rows[0].set("method", Test.EQUALS, "DELETE")
    fired(dialog._timer)

    draft = dialog.draft()
    assert draft.category is None
    assert draft.severity is None
    assert dialog._check_line.text() == "Choose what kind of activity it is."
    dialog.shutdown()


def test_a_complete_rule_is_written_to_my_rules(qt_app: QApplication) -> None:
    dialog = _dialog()
    saved: list[str] = []
    dialog.saved.connect(saved.append)
    _fill(dialog)

    assert _button(dialog, "addRule").isEnabled()
    assert dialog.add()
    assert _ids("My-rules") == ["cart_emptied"]
    assert saved == ["My-rules"]


def test_the_id_caption_follows_the_name(qt_app: QApplication) -> None:
    dialog = _dialog()
    _fill(dialog, name="Script in uploads")

    assert dialog._id_line.text() == "Saved with the id script_in_uploads"
    dialog.shutdown()


def test_a_taken_id_is_numbered(qt_app: QApplication) -> None:
    rules_library.save_pack("shop", SHOP)
    dialog = _dialog()
    _fill(dialog, name="Shop probe")

    assert dialog._id_line.text() == "Saved with the id shop_probe_2"
    dialog.shutdown()


def test_save_into_offers_packs_that_load_and_my_rules(qt_app: QApplication) -> None:
    rules_library.save_pack("shop", SHOP)
    (rules_library.rules_dir() / "broken.yaml").write_text("rules: [oops", encoding="utf-8")

    dialog = _dialog()
    offered = [dialog._into.itemText(i) for i in range(dialog._into.count())]

    assert offered == ["shop", "My-rules"]
    assert dialog._into.currentText() == "My-rules"
    assert _dialog(into="shop")._into.currentText() == "shop"
    dialog.shutdown()


def test_a_rule_goes_into_the_chosen_pack(qt_app: QApplication) -> None:
    rules_library.save_pack("shop", SHOP)
    dialog = _dialog(into="shop")
    _fill(dialog)

    assert dialog.add()
    assert _ids("shop") == ["shop_probe", "cart_emptied"]


def test_view_yaml_shows_the_block(qt_app: QApplication) -> None:
    dialog = _dialog()
    _fill(dialog)

    _button(dialog, "viewYaml").click()

    assert not dialog._yaml_view.isHidden()
    assert dialog._yaml_view.toPlainText() == rule_block(dialog.draft(), "cart_emptied")
    assert _button(dialog, "viewYaml").text() == "Hide YAML"
    dialog.shutdown()


def test_counts_and_examples_fill_in(qt_app: QApplication, shopfront_case: Path) -> None:
    dialog = _dialog(shopfront_case)
    _fill(
        dialog,
        conditions=(("method", Test.EQUALS, "DELETE"), ("path", Test.REGEX, "^/api/cart$")),
    )

    _until(lambda: dialog._finds_line.text() == "1 match from 1 client.")

    assert dialog._examples.rowCount() == 1
    cart = next(
        number
        for number, text in enumerate(SHOPFRONT_LOG.read_text(encoding="utf-8").splitlines(), 1)
        if "DELETE /api/cart" in text
    )
    assert dialog._examples.item(0, 0).text() == str(cart)
    dialog.shutdown()
    settled(qt_app)


def test_with_no_case_open_the_count_says_so(qt_app: QApplication) -> None:
    dialog = _dialog()
    _fill(dialog)

    assert dialog._finds_line.text() == "Open a case to see what it matches."
    dialog.shutdown()


def test_with_a_case_open_saving_asks_to_re_read(
    qt_app: QApplication, shopfront_case: Path
) -> None:
    dialog = _dialog(shopfront_case)
    asked: list[bool] = []
    dialog.read_again.connect(lambda: asked.append(True))
    dialog.show()
    _fill(dialog)

    assert dialog.add()

    assert dialog._ask.isVisible()
    assert dialog._ask_text.text() == "Saved. The open case was read with the old rules."
    assert _button(dialog, "readAgain").text() == "Re-read now"
    _button(dialog, "readAgain").click()
    assert asked == [True]
    assert dialog.result() == AddRuleDialog.DialogCode.Accepted
    settled(qt_app)


def test_closing_with_the_question_open_means_later(
    qt_app: QApplication, shopfront_case: Path
) -> None:
    dialog = _dialog(shopfront_case)
    later: list[bool] = []
    dialog.later.connect(lambda: later.append(True))
    dialog.show()
    _fill(dialog)
    assert dialog.add()

    dialog.reject()

    assert later == [True]
    settled(qt_app)


def test_with_no_case_open_saving_just_closes(qt_app: QApplication) -> None:
    dialog = _dialog()
    dialog.show()
    _fill(dialog)

    assert dialog.add()

    assert not dialog._ask.isVisible()
    assert dialog.result() == AddRuleDialog.DialogCode.Accepted


def test_a_pack_changed_elsewhere_is_said_and_not_written(qt_app: QApplication) -> None:
    rules_library.save_pack("shop", SHOP)
    dialog = _dialog(into="shop")
    changed = SHOP.replace("Shop probe", "Edited elsewhere")
    (rules_library.rules_dir() / "shop.yaml").write_text(changed, encoding="utf-8")
    _fill(dialog)

    assert not dialog.add()

    assert dialog._check_line.text() == (
        "shop was changed outside this window. Close it and try again."
    )
    assert (rules_library.rules_dir() / "shop.yaml").read_text(encoding="utf-8") == changed
    dialog.shutdown()


def _held_count(monkeypatch: pytest.MonkeyPatch) -> tuple[threading.Event, list[bool]]:
    """`count_finds` that reports once, then waits to be released, ignoring `cancelled`."""
    release = threading.Event()
    stopped: list[bool] = []

    def held(path, rules, *, cancelled, report, examples):
        finds = {rule.id: Find(1, 1) for rule in rules}
        report(FindsProgress(1, 2, finds))
        release.wait(10)
        stopped.append(cancelled())
        return finds

    monkeypatch.setattr(add_rule_module, "count_finds", held)
    return release, stopped


def test_closing_mid_count_stops_it(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, stopped = _held_count(monkeypatch)
    dialog = _dialog(shopfront_case)
    _fill(dialog)

    dialog.reject()
    release.set()
    settled(qt_app)

    assert stopped == [True]


def test_a_late_count_after_the_window_is_gone_touches_nothing(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, _ = _held_count(monkeypatch)
    raised: list[object] = []
    monkeypatch.setattr(sys, "excepthook", lambda *args: raised.append(args))
    dialog = _dialog(shopfront_case)
    _fill(dialog)

    dialog.reject()
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    release.set()
    settled(qt_app)

    assert raised == []


def test_a_late_count_after_an_edit_is_dropped(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, _ = _held_count(monkeypatch)
    dialog = _dialog(shopfront_case)
    _fill(dialog)
    first = dialog._finds_generation

    _fill(dialog, name="Cart emptied again")
    release.set()
    settled(qt_app)

    assert dialog._finds_generation > first
    assert dialog._shown_generation == dialog._finds_generation
    dialog.shutdown()


def test_a_rule_can_be_added_while_the_count_runs(
    qt_app: QApplication, shopfront_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, _ = _held_count(monkeypatch)
    dialog = _dialog(shopfront_case)
    _fill(dialog)
    _until(lambda: "so far" in dialog._finds_line.text())

    assert _button(dialog, "addRule").isEnabled()
    assert dialog.add()
    assert _ids("My-rules") == ["cart_emptied"]
    release.set()
    settled(qt_app)
