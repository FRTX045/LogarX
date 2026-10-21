"""The window reads a case with the reader's rules, and asks before reading it again."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import QApplication, QFileDialog, QPushButton

from conftest import settled
from logarc import rules_library
from logarc.case import Case
from logarc.gui.app import MainWindow

IP = "203.0.113.5"
LINES = [
    f'{IP} - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    f'{IP} - - [10/Oct/2020:13:55:04 +0000] "GET /cgi-bin/quux.pl HTTP/1.1" 200 12 "-" "curl/8.0"',
]
HOUSE = """\
version: 1
rules:
  - id: house_cgi_probe
    name: House rule CGI probe
    category: injection
    severity: high
    match:
      any:
        - {field: path_decoded, regex: "/cgi-bin/quux"}
"""


@pytest.fixture
def root(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return tmp_path / "case"


def _opened(qt_app: QApplication, root: Path) -> MainWindow:
    window = MainWindow()
    window.show()
    window._load_case(root)
    settled(qt_app)
    window._reconstruct(IP)
    settled(qt_app)
    return window


def _on_screen(window: MainWindow) -> str:
    assert window._result is not None
    return json.dumps(window._result.to_dict())


def _button(window: MainWindow, text: str) -> QPushButton:
    (button,) = [b for b in window._rules_notice.findChildren(QPushButton) if b.text() == text]
    return button


def test_a_case_is_read_with_the_packs_in_the_reader_s_settings(
    qt_app: QApplication, root: Path
) -> None:
    rules_library.save_pack("house", HOUSE)

    window = _opened(qt_app, root)

    assert "House rule CGI probe" in _on_screen(window)
    assert not window._rules_notice.isVisible()


def test_a_change_with_a_case_open_puts_up_the_strip(qt_app: QApplication, root: Path) -> None:
    window = _opened(qt_app, root)
    rules_library.save_pack("house", HOUSE)

    window._rules_changed()

    assert window._rules_notice.isVisible()
    assert "Rules changed since this case was read." in window._rules_notice.text()
    assert "House rule CGI probe" not in _on_screen(window)


def test_read_it_again_reads_the_client_on_screen_with_the_new_rules(
    qt_app: QApplication, root: Path
) -> None:
    window = _opened(qt_app, root)
    rules_library.save_pack("house", HOUSE)
    window._rules_changed()

    _button(window, "Re-read").click()
    settled(qt_app)

    assert "House rule CGI probe" in _on_screen(window)
    assert not window._rules_notice.isVisible()


def test_where_to_start_is_scanned_again_with_the_new_rules(
    qt_app: QApplication, root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    window = _opened(qt_app, root)
    started: list[object] = []
    monkeypatch.setattr(window._triage, "start", lambda path, window_, rules: started.append(rules))
    rules_library.switch_rule("http_library_user_agent", on=False)

    window._read_again()
    settled(qt_app)

    assert [r.switched_off for r in started] == [frozenset({"http_library_user_agent"})]


def test_a_pack_that_does_not_load_is_said_once_the_case_is_read(
    qt_app: QApplication, root: Path
) -> None:
    folder = rules_library.rules_dir()
    folder.mkdir(parents=True)
    (folder / "broken.yaml").write_text("version: 1\nrules:\n  - id: x\n", encoding="utf-8")

    window = _opened(qt_app, root)

    assert window._rules_notice.isVisible()
    assert "did not load" in window._rules_notice.text()
    assert "broken" in window._rules_notice.text()


def test_opening_another_case_clears_the_strip(qt_app: QApplication, root: Path) -> None:
    window = _opened(qt_app, root)
    window._rules_changed()

    window._load_case(root)
    settled(qt_app)

    assert not window._rules_notice.isVisible()


def test_with_no_case_open_a_change_asks_nothing(qt_app: QApplication) -> None:
    window = MainWindow()

    window._rules_changed()

    assert not window._rules_notice.isVisible()


def test_the_menu_entry_names_both_halves(qt_app: QApplication) -> None:
    """Every menu action is made as `QAction(text, window)`, so it is the window's child."""
    texts = [action.text() for action in MainWindow().findChildren(QAction)]

    assert "Formats and &rules…" in texts
    assert "Log &formats…" not in texts


def test_the_report_the_window_writes_names_the_reader_s_pack(
    qt_app: QApplication, root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rules_library.save_pack("house", HOUSE)
    window = _opened(qt_app, root)
    target = tmp_path / "report.html"
    monkeypatch.setattr(QFileDialog, "getSaveFileName", lambda *_a, **_k: (str(target), ""))

    window._export("html")
    settled(qt_app)

    page = target.read_text(encoding="utf-8")
    assert "House rule CGI probe" in page
    assert "added: house (1 rule)" in page
