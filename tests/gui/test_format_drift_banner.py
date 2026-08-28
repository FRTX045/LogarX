"""The window telling a reader that a case's format has been edited since.

The wording is tested next door, without a display. This is the other half:
that the strip actually goes up on a drifted case, stays down on an untouched
one, and is separate from the quarantine strip — so dismissing one does not
take the other with it.
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
from logarc.parsers.apache import COMBINED
from logarc.parsers.library import save_library
from logarc.parsers.registry import register_saved_formats, unregister_format
from logarc.parsers.spec import LogFormatSpec

#: Pipe-separated, so nothing built in reads it and the case genuinely depends
#: on the saved definition it was ingested with.
JANUARY = '%h|%t|"%r"|%>s|%b'
JUNE = '%h|%t|"%r"|%>s|%b|%{Referer}i'

LINES = [
    '203.0.113.5|[10/Oct/2020:13:55:36 +0000]|"GET / HTTP/1.1"|200|2326',
    '203.0.113.5|[10/Oct/2020:13:55:40 +0000]|"GET /.env HTTP/1.1"|404|0',
    '198.51.100.9|[10/Oct/2020:13:56:00 +0000]|"POST /login HTTP/1.1"|302|0',
]


@pytest.fixture
def case_read_with_a_saved_format(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")

    save_library([LogFormatSpec(name="log-kantor", directive=JANUARY)])
    register_saved_formats()
    try:
        root = tmp_path / "case"
        with Case.create(root) as case:
            case.ingest([log], log_format="log-kantor")
    finally:
        unregister_format("log-kantor")
    return root


def test_an_untouched_format_leaves_the_strip_down(
    qt_app: QApplication, case_read_with_a_saved_format: Path
) -> None:
    """The premise for everything below: opening a case whose format nobody
    has touched must say nothing at all."""
    window = MainWindow()
    window.show()

    window._load_case(case_read_with_a_saved_format)
    settled(qt_app)

    assert not window._format_notice.isVisible()


def test_an_edited_format_puts_the_strip_up(
    qt_app: QApplication, case_read_with_a_saved_format: Path
) -> None:
    save_library([LogFormatSpec(name="log-kantor", directive=JUNE)])

    window = MainWindow()
    window.show()
    window._load_case(case_read_with_a_saved_format)
    settled(qt_app)

    assert window._format_notice.isVisible()
    assert "log-kantor" in window._format_notice.text()


def test_a_deleted_format_leaves_the_strip_down(
    qt_app: QApplication, case_read_with_a_saved_format: Path
) -> None:
    """Nothing to compare against, and the case reads correctly from its own
    copy. A warning here would only teach the reader to dismiss warnings."""
    save_library([])

    window = MainWindow()
    window.show()
    window._load_case(case_read_with_a_saved_format)
    settled(qt_app)

    assert not window._format_notice.isVisible()


def test_the_case_still_reads_its_events_after_the_format_is_edited(
    qt_app: QApplication, case_read_with_a_saved_format: Path
) -> None:
    """The point the notice is careful to make in words, checked as behaviour:
    the strip goes up and the case behind it is whole."""
    save_library([LogFormatSpec(name="log-kantor", directive=JUNE)])

    window = MainWindow()
    window.show()
    window._load_case(case_read_with_a_saved_format)
    settled(qt_app)

    assert window._format_notice.isVisible(), "premise: this case drifted"
    assert set(window._whole_counts) == {"203.0.113.5", "198.51.100.9"}
    assert window._whole_counts["203.0.113.5"] == 2


def test_the_two_strips_are_dismissed_separately(
    qt_app: QApplication, case_read_with_a_saved_format: Path
) -> None:
    """They report different things. A reader who has taken in one of them must
    not lose the other by closing it."""
    save_library([LogFormatSpec(name="log-kantor", directive=COMBINED)])

    window = MainWindow()
    window.show()
    window._load_case(case_read_with_a_saved_format)
    settled(qt_app)

    assert window._format_notice.isVisible(), "premise: this case drifted"
    window._format_notice.dismiss()

    assert not window._format_notice.isVisible()
