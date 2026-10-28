"""What the window says when CRS fails on a reader's computer.

A sidecar that crashes prints a Go panic, a stack of forty lines that says
nothing to the person reading the window, and the dialog showed all of it as
its message: on 2026-10-15, on a newer Intel CPU, it ran off the bottom of the
screen and never said whether the case was still good. The dialog now says
that CRS did not finish, why in a line, that nothing in the case was changed,
and how to try again; the output itself is behind Show Details, for whoever
reports it. "Nothing changed" rather than "no CRS results": a run from the
older-CRS strip that fails leaves the results the case already had.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox

from conftest import settled
from logarx.case import Case
from logarx.detect.crs import CrsUnavailableError
from logarx.gui import app as app_module
from logarx.gui.app import MainWindow

PANIC = (
    "panic: wasm error: invalid table access\n"
    "\twasm stack trace:\n"
    "\t\t.$24(i32,i32,i32,i32)\n"
    "\n"
    "goroutine 1 [running]:\n"
    "main.main()\n"
    "\tcrs/main.go:275 +0x24d"
)


@pytest.fixture
def shown(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str, str]]:
    """Each dialog the window shows: its text, the line under it, its details."""
    seen: list[tuple[str, str, str]] = []

    def capture(box: QMessageBox) -> int:
        seen.append((box.text(), box.informativeText(), box.detailedText()))
        return 0

    monkeypatch.setattr(QMessageBox, "exec", capture)
    return seen


def _opened(qt_app: QApplication, tmp_path: Path) -> MainWindow:
    log = tmp_path / "access.log"
    log.write_text(
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"\n',
        encoding="utf-8",
    )
    root = tmp_path / "case"
    with Case.create(root) as case:
        case.ingest([log])
    window = MainWindow()
    window.show()
    window._load_case(root)
    settled(qt_app)
    return window


def _failing_with(monkeypatch: pytest.MonkeyPatch, error: Exception) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise error

    monkeypatch.setattr(app_module.SidecarConfig, "check", lambda self: None)
    monkeypatch.setattr(app_module, "enrich_case", fail)


def test_a_crashed_sidecar_is_told_in_a_sentence_with_its_output_behind_details(
    qt_app: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shown: list[tuple[str, str, str]],
) -> None:
    window = _opened(qt_app, tmp_path)
    _failing_with(
        monkeypatch,
        CrsUnavailableError(
            "CRS stopped unexpectedly (crs-sidecar exited 2: panic: wasm error: invalid "
            "table access)",
            detail=PANIC,
        ),
    )

    window._run_crs_now()
    settled(qt_app)

    ((text, under, details),) = shown
    assert text == "CRS did not finish."
    assert "CRS stopped unexpectedly" in under
    assert "Nothing in the case was changed" in under
    assert "Case → Run CRS scan" in under
    assert "goroutine 1 [running]:" not in text + under
    assert "goroutine 1 [running]:" in details


def test_the_reason_is_given_without_the_name_of_the_error_class(
    qt_app: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shown: list[tuple[str, str, str]],
) -> None:
    """`CrsUnavailableError:` is the program talking to itself."""
    window = _opened(qt_app, tmp_path)
    _failing_with(monkeypatch, CrsUnavailableError("crs-sidecar: cannot open lfi-os-files.data"))

    window._run_crs_now()
    settled(qt_app)

    ((_text, under, _details),) = shown
    assert under.startswith("crs-sidecar: cannot open lfi-os-files.data")
    assert "CrsUnavailableError" not in under


def test_the_status_line_says_it_too(
    qt_app: QApplication,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    shown: list[tuple[str, str, str]],
) -> None:
    window = _opened(qt_app, tmp_path)
    _failing_with(monkeypatch, CrsUnavailableError("crs-sidecar exited 2", detail=PANIC))

    window._run_crs_now()
    settled(qt_app)

    assert window._status.text() == "CRS did not finish."
