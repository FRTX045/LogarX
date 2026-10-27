"""Ingesting from the window with a format the reader wrote.

Before this, `MainWindow._ingest_new_case` passed no format at all — every
ingest from the window was auto-detected, and a log in a format of the user's
own could not be read from the interface by any means.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarx.gui import app as app_module
from logarx.gui.app import MainWindow
from logarx.parsers.library import save_library
from logarx.parsers.registry import register_saved_formats
from logarx.parsers.spec import LogFormatSpec

#: Pipe-separated: detection cannot read it, so a case with events in it is
#: proof the chosen format was the one used.
PIPED = '%h|%t|"%r"|%>s|%b'

LINES = [
    '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET / HTTP/1.1"|200|2326',
    '203.0.113.5|[10/Oct/2020:13:55:40 +0000]|"GET /.env HTTP/1.1"|404|0',
    '198.51.100.9|[10/Oct/2020:13:56:00 +0000]|"POST /login HTTP/1.1"|302|0',
]


@pytest.fixture
def piped_log(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return log


def _answer_the_dialogs(
    monkeypatch: pytest.MonkeyPatch, log: Path, case_dir: Path, *, format_name: str | None
) -> None:
    monkeypatch.setattr(
        app_module.QFileDialog, "getOpenFileNames", lambda *_a, **_k: ([str(log)], "")
    )
    monkeypatch.setattr(
        app_module.QFileDialog, "getExistingDirectory", lambda *_a, **_k: str(case_dir)
    )
    monkeypatch.setattr(app_module.FormatChoice, "exec", lambda _self: 1)
    monkeypatch.setattr(app_module.FormatChoice, "chosen", lambda _self: format_name)


def test_a_chosen_format_is_the_one_the_ingest_uses(
    qt_app: QApplication, tmp_path: Path, piped_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])
    register_saved_formats()
    case_dir = tmp_path / "case"
    _answer_the_dialogs(monkeypatch, piped_log, case_dir, format_name="log-kantor")

    window = MainWindow()
    window._ingest_new_case()
    settled(qt_app)

    manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    assert manifest["sources"][0]["events_parsed"] == 3
    assert manifest["sources"][0]["log_format"] == "log-kantor"
    window.close()


def test_the_case_records_the_definition_so_it_outlives_the_format(
    qt_app: QApplication, tmp_path: Path, piped_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    save_library([LogFormatSpec(name="log-kantor", directive=PIPED)])
    register_saved_formats()
    case_dir = tmp_path / "case"
    _answer_the_dialogs(monkeypatch, piped_log, case_dir, format_name="log-kantor")

    window = MainWindow()
    window._ingest_new_case()
    settled(qt_app)

    manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    assert manifest["sources"][0]["format_spec"]["directive"] == PIPED
    window.close()


def test_leaving_it_on_detect_reads_an_ordinary_log(
    qt_app: QApplication, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default, and what every ingest from the window did before there was
    a choice. It has to keep working without the reader touching anything."""
    plain = '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 26 "-" "curl/8"'
    log = tmp_path / "plain.log"
    log.write_text("\n".join([plain] * 5) + "\n", encoding="utf-8")
    case_dir = tmp_path / "case"
    _answer_the_dialogs(monkeypatch, log, case_dir, format_name=None)

    window = MainWindow()
    window._ingest_new_case()
    settled(qt_app)

    manifest = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    assert manifest["sources"][0]["log_format"] == "apache-combined"
    window.close()


def test_cancelling_the_format_question_abandons_the_ingest(
    qt_app: QApplication, tmp_path: Path, piped_log: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not a fall back to detection. A reader who opened that screen has a
    format in mind, and quietly doing the other thing would build a case that
    looks right and was read by something they did not choose."""
    case_dir = tmp_path / "case"
    _answer_the_dialogs(monkeypatch, piped_log, case_dir, format_name=None)
    monkeypatch.setattr(app_module.FormatChoice, "exec", lambda _self: 0)

    window = MainWindow()
    window._ingest_new_case()
    settled(qt_app)

    assert not case_dir.exists()
    window.close()
