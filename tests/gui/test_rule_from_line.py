"""Make a rule from a line in the evidence panel, and what the window does after."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QPushButton
from test_bookmark_marks import attack, lines, row_point
from test_rules_window import IP, LINES, _on_screen, _opened

from conftest import fired, settled
from logarx import rules_library
from logarx.case import Case
from logarx.core.activity import ActivityCategory, Severity
from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.evidence import EvidenceLine
from logarx.gui import app as app_module
from logarx.gui.add_rule import AddRuleDialog
from logarx.gui.evidence_panel import EvidencePanel

MAKE = "Make a rule from this line\N{HORIZONTAL ELLIPSIS}"


@pytest.fixture
def panel(qt_app: QApplication) -> EvidencePanel:
    shown = EvidencePanel()
    shown.resize(700, 600)
    shown.show()
    QApplication.processEvents()
    return shown


@pytest.fixture
def root(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return tmp_path / "case"


def _texts(panel: EvidencePanel, row: int) -> list[str]:
    menu = panel._menu_at(row_point(panel._table, row))
    assert menu is not None
    return [action.text() for action in menu.actions()]


def test_the_menu_offers_a_rule_for_a_parsed_line(panel: EvidencePanel) -> None:
    asked: list[EvidenceLine] = []
    panel.make_rule_requested.connect(asked.append)
    panel.show_evidence(attack(), lines())
    panel.select_row(0)

    menu = panel._menu_at(row_point(panel._table, 1))
    assert menu is not None
    (make,) = [action for action in menu.actions() if action.text() == MAKE]
    make.trigger()

    shown_index = panel._table.item(1, 0).data(0x0100)
    assert [line.ref for line in asked] == [lines()[shown_index].ref]


def test_an_unparsed_line_offers_no_rule(panel: EvidencePanel) -> None:
    unread = [
        EvidenceLine(ref=line.ref, source_path=line.source_path, text=line.text, verified=True)
        for line in lines()
    ]
    panel.show_evidence(attack(), unread)

    assert MAKE not in _texts(panel, 1)


def _cgi_line() -> EvidenceLine:
    ref = EvidenceRef("access.log", 2)
    event = NormalizedEvent(
        timestamp=datetime(2020, 10, 10, 13, 55, 4, tzinfo=UTC),
        client_ip=IP,
        evidence=ref,
        method="GET",
        path="/cgi-bin/quux.pl",
        status=200,
        bytes_sent=12,
        user_agent="curl/8.0",
    )
    return EvidenceLine(ref, "access.log", text="...", event=event, verified=True)


def _complete(dialog: AddRuleDialog) -> None:
    (go_on,) = [b for b in dialog.findChildren(QPushButton) if b.objectName() == "continue"]
    go_on.click()
    dialog._name.setText("Quux probe")
    dialog._category.setCurrentIndex(dialog._category.findData(ActivityCategory.INJECTION.value))
    dialog._severity.setCurrentIndex(dialog._severity.findData(Severity.HIGH.name))
    fired(dialog._timer)


def _click(dialog: AddRuleDialog, name: str) -> None:
    (button,) = [b for b in dialog.findChildren(QPushButton) if b.objectName() == name]
    button.click()


def test_choosing_it_opens_the_window_on_that_line(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[AddRuleDialog] = []
    monkeypatch.setattr(app_module, "_open_add_rule", opened.append)
    window = _opened(qt_app, root)

    window._evidence.make_rule_requested.emit(_cgi_line())

    (dialog,) = opened
    assert dialog._parts_heading.text() == "Line 2: tick what makes it suspicious."
    assert any("/cgi-bin/quux.pl" in box.text() for _part, box in dialog._part_boxes)
    dialog.shutdown()


def test_re_read_from_the_window_reads_the_case_with_the_new_rule(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def add(dialog: AddRuleDialog) -> None:
        _complete(dialog)
        dialog.show()
        assert dialog.add()
        _click(dialog, "readAgain")

    monkeypatch.setattr(app_module, "_open_add_rule", add)
    window = _opened(qt_app, root)

    window._make_rule(_cgi_line())
    settled(qt_app)

    assert "Quux probe" in _on_screen(window)
    assert not window._rules_notice.isVisible()


def test_later_leaves_the_strip(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def add(dialog: AddRuleDialog) -> None:
        _complete(dialog)
        dialog.show()
        assert dialog.add()
        _click(dialog, "later")

    monkeypatch.setattr(app_module, "_open_add_rule", add)
    window = _opened(qt_app, root)

    window._make_rule(_cgi_line())
    settled(qt_app)

    assert window._rules_notice.isVisible()
    assert "Rules changed since this case was read." in window._rules_notice.text()
    assert "Quux probe" not in _on_screen(window)


def test_a_library_that_fails_to_load_leaves_the_strip(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reported: list[str] = []

    def add(dialog: AddRuleDialog) -> None:
        _complete(dialog)
        dialog.show()
        assert dialog.add()

        def broken(**_kwargs: object) -> rules_library.Library:
            raise OSError("the rules folder went away")

        monkeypatch.setattr(rules_library, "in_force", broken)
        _click(dialog, "readAgain")

    monkeypatch.setattr(app_module, "_open_add_rule", add)
    window = _opened(qt_app, root)
    monkeypatch.setattr(window, "report_error", lambda message, *_a, **_k: reported.append(message))

    window._make_rule(_cgi_line())
    settled(qt_app)

    assert len(reported) == 1
    assert window._rules_notice.isVisible()
    assert "Rules changed since this case was read." in window._rules_notice.text()


def test_a_broken_my_rules_is_refused_from_the_evidence_panel_too(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "my-rules.yaml").write_bytes(b"rules: [oops")
    seen: list[tuple[bool, str, list[str]]] = []

    def add(dialog: AddRuleDialog) -> None:
        _complete(dialog)
        (adding,) = [b for b in dialog.findChildren(QPushButton) if b.objectName() == "addRule"]
        offered = [dialog._into.itemText(i) for i in range(dialog._into.count())]
        seen.append((adding.isEnabled(), dialog._check_line.text(), offered))
        dialog.shutdown()

    monkeypatch.setattr(app_module, "_open_add_rule", add)
    window = _opened(qt_app, root)

    window._make_rule(_cgi_line())

    ((enabled, said, offered),) = seen
    assert not enabled
    assert said.startswith("A pack called my-rules exists but does not load.")
    assert "my-rules" not in offered
    assert (folder / "my-rules.yaml").read_bytes() == b"rules: [oops"
