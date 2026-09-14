"""The window saying a case holds part of a log rather than all of it.

A case narrowed at ingest answers "who else was there" with silence, and
silence reads exactly like nobody. Everything the window draws — the client
list, the traffic band, every count in the panels — is true of the clients that
were kept and says nothing about the ones that were not. That is only safe if
the reader knows, so the strip is not optional decoration: it is the difference
between a partial case and a misleading one.

Run without a display.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.case import Case
from logarc.gui.app import MainWindow

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /a HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
]


def _log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


def _case(tmp_path: Path, *, only: set[str] | None = None) -> Path:
    root = tmp_path / ("narrowed" if only else "whole")
    with Case.create(root) as case:
        case.ingest([_log(tmp_path)], only_clients=only)
        case.finalize()
    return root


def test_a_narrowed_case_says_so_on_screen(qt_app: QApplication, tmp_path: Path) -> None:
    window = MainWindow()
    window.show()
    window._load_case(_case(tmp_path, only={"203.0.113.5"}))
    settled(qt_app)

    assert window._filter_notice.isVisible()
    assert "203.0.113.5" in window._filter_notice.text()
    window.close()


def test_a_whole_case_says_nothing(qt_app: QApplication, tmp_path: Path) -> None:
    """A strip that is always there is a strip nobody reads."""
    window = MainWindow()
    window.show()
    window._load_case(_case(tmp_path))
    settled(qt_app)

    assert not window._filter_notice.isVisible()
    window.close()


def test_the_strip_comes_down_when_a_whole_case_is_opened_after_a_narrowed_one(
    qt_app: QApplication, tmp_path: Path
) -> None:
    """The failure worth guarding: a warning left up from the previous case is
    worse than none, because it is attached to the wrong evidence."""
    window = MainWindow()
    window.show()
    window._load_case(_case(tmp_path, only={"203.0.113.5"}))
    settled(qt_app)
    assert window._filter_notice.isVisible(), "premise: this case is narrowed"

    window._load_case(_case(tmp_path))
    settled(qt_app)

    assert not window._filter_notice.isVisible()
    window.close()
