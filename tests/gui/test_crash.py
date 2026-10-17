"""The net under the interface.

A mistake in a slot used to end the process. Qt calls its own handler for an
exception that reaches it, and that handler aborts — no traceback, no dialog,
no exit status a person could read. Measured: exit code -1073740791, zero bytes
of output. The window simply vanished.

Proven here against real Qt signals rather than by calling the hook by hand,
because what is being checked is precisely that Qt never gets the chance.
"""

from __future__ import annotations

import io
import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QObject, pyqtSignal
from PyQt6.QtWidgets import QApplication, QMessageBox

from logarc.gui import app as app_module
from logarc.gui import crash


@pytest.fixture(autouse=True)
def hook_restored() -> object:
    """Put `sys.excepthook` back. Left installed, one test's net catches the
    next test's failures and the suite reports nothing wrong at all."""
    before = sys.excepthook
    yield before
    sys.excepthook = before


class Talker(QObject):
    said = pyqtSignal()


def _reporter() -> tuple[list[tuple[str, str]], object]:
    seen: list[tuple[str, str]] = []

    def report(message: str, detail: str) -> None:
        seen.append((message, detail))

    return seen, report


# -- the thing itself ------------------------------------------------------


def test_a_slot_that_raises_no_longer_ends_the_process(qt_app: QApplication) -> None:
    """The whole point. Without the net this test does not fail — the process
    running it stops, and pytest reports nothing at all."""
    seen, report = _reporter()
    crash.install(report)
    talker = Talker()
    talker.said.connect(lambda: 1 // 0)

    talker.said.emit()

    # Reaching this line is most of the assertion. Without the net the process
    # is gone by now and pytest reports nothing — not a failure, an absence.
    assert seen, "the problem went unreported"


def test_the_reader_is_told_what_went_wrong(qt_app: QApplication) -> None:
    seen, report = _reporter()
    crash.install(report)
    talker = Talker()

    def listener() -> None:
        raise ValueError("the case is not open")

    talker.said.connect(listener)

    talker.said.emit()

    message, _detail = seen[0]
    assert message == "ValueError: the case is not open"


def test_the_traceback_is_kept_not_only_the_sentence(qt_app: QApplication) -> None:
    """A sentence says a tool broke. Only the traceback says where."""
    seen, report = _reporter()
    crash.install(report)
    talker = Talker()

    def listener() -> None:
        raise ValueError("boom")

    talker.said.connect(listener)

    talker.said.emit()

    _message, detail = seen[0]
    assert "Traceback" in detail
    assert "listener" in detail
    assert "ValueError: boom" in detail


def test_the_wording_matches_the_one_a_failed_job_already_uses() -> None:
    """`Job` reports `f"{type(exc).__name__}: {exc}"`. Two wordings for one kind
    of trouble would read as two different kinds."""
    seen, report = _reporter()
    crash.install(report)

    sys.excepthook(RuntimeError, RuntimeError("no case open"), None)

    assert seen[0][0] == "RuntimeError: no case open"


# -- what it must not swallow ---------------------------------------------


def test_ctrl_c_still_quits(hook_restored: object) -> None:
    """The net catches mistakes, not the reader asking to leave. Swallowed,
    Ctrl-C would print a message and carry on."""
    passed_on: list[type[BaseException]] = []
    sys.excepthook = lambda kind, value, tb: passed_on.append(kind)
    seen, report = _reporter()

    crash.install(report)
    sys.excepthook(KeyboardInterrupt, KeyboardInterrupt(), None)

    assert passed_on == [KeyboardInterrupt]
    assert seen == []


def test_an_exit_is_still_an_exit() -> None:
    passed_on: list[type[BaseException]] = []
    sys.excepthook = lambda kind, value, tb: passed_on.append(kind)
    seen, report = _reporter()

    crash.install(report)
    sys.excepthook(SystemExit, SystemExit(0), None)

    assert passed_on == [SystemExit]
    assert seen == []


# -- when it goes wrong over and over -------------------------------------


def test_a_storm_is_written_down_rather_than_shown_again(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A slot that raises on every repaint raises hundreds of times.

    Reported each time, the reader gets a modal they cannot dismiss faster than
    it reappears — a net that makes the window less usable than the crash did.
    The log keeps every one of them.
    """
    seen, report = _reporter()
    crash.install(report, limit=3)

    for n in range(10):
        sys.excepthook(ValueError, ValueError(f"again {n}"), None)

    assert len(seen) == 3, "the reader should be told, then left alone"
    written = capsys.readouterr().err
    assert "again 9" in written, "the ones past the limit are still recorded"


# -- where the terminal cannot take it ------------------------------------

#: A traceback through a Windows user folder named in Chinese.
THROUGH_A_CHINESE_FOLDER = 'File "C:\\Users\\王伟\\logarc\\src\\app.py", line 1\nValueError: x'


def _narrow() -> io.TextIOWrapper:
    """stderr as a redirected Windows console has it: the code page, strictly."""
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")


def test_writing_down_never_fails_on_what_the_stream_cannot_encode() -> None:
    """The window writes a failure's details to stderr before it shows them, and
    redirected on Windows stderr is the code page. A character it has no byte for
    raised there, and the dialog after it never came up."""
    stream = _narrow()

    crash.write_down(THROUGH_A_CHINESE_FOLDER, stream)

    stream.seek(0)
    written = stream.read()
    assert "ValueError: x" in written
    assert "\\u738b" in written, "kept as an escape, not dropped"


def test_writing_down_to_no_stream_at_all_is_nothing() -> None:
    """The packaged application has no console, and no stderr."""
    crash.write_down(THROUGH_A_CHINESE_FOLDER, None)


def test_the_dialog_still_comes_up_where_the_terminal_cannot_print_its_details(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    shown: list[str] = []
    monkeypatch.setattr(QMessageBox, "exec", lambda box: shown.append(box.text()) or 0)
    monkeypatch.setattr(sys, "stderr", _narrow())
    window = app_module.MainWindow()

    window.report_error("CRS did not finish.", THROUGH_A_CHINESE_FOLDER)

    assert shown == ["CRS did not finish."]


def test_installing_hands_back_the_hook_it_replaced() -> None:
    """So a caller can put it back, which is what the fixture above does and
    what any test of a hook has to be able to do."""
    before = sys.excepthook
    _seen, report = _reporter()

    assert crash.install(report) is before


# -- and that it is actually put up ---------------------------------------


def test_the_entry_point_puts_the_net_up(
    qt_app: QApplication, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A net nobody installs is a module with tests and no effect.

    Driven through `main` rather than by reading it: this one line is the whole
    difference between a window that says what went wrong and a window that
    disappears.

    The theme and the display defaults are left out because they are applied
    to the whole application, which every later test shares: themed here, two
    layout tests in `test_window.py` measured Fusion's widths instead of the
    ones they were written against.
    """
    installed: list[object] = []
    monkeypatch.setattr(app_module.crash, "install", lambda report, **kw: installed.append(report))
    monkeypatch.setattr(app_module, "apply_theme", lambda app: None)
    monkeypatch.setattr(app_module, "configure_display", lambda: None)
    monkeypatch.setattr(app_module.MainWindow, "show", lambda self: None)
    monkeypatch.setattr(app_module.MainWindow, "offer_start", lambda self: None)
    monkeypatch.setattr(app_module.QApplication, "exec", lambda self: 0)

    assert app_module.main() == 0

    assert installed, "main ran with no net under it"
