"""The cyclic collector runs between the window's tests, never inside one.

A window kept alive only by a reference cycle can be the focus window. When
focus moves, Qt saves it as the previous window, sends it a FocusOut, and then
reads it again to say which window is now active. Python runs during that
FocusOut, in an event filter or a handler, and if the collector chose that
moment to free the window, Qt read freed memory: CI's segfault in
`QApplicationPrivate::notifyActiveWindowChange`, on Python 3.11 in the first
fixture of `test_evidence_search.py`, twice running, and once in 5 runs under
gdb in WSL. A window freed at the end of the test that left it is never anybody's
previous window.
"""

from __future__ import annotations

import gc
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

FIRST = """
import weakref

from PyQt6.QtWidgets import QLineEdit, QVBoxLayout, QWidget

LEFT = []


def test_leaves_a_focused_window_in_a_cycle(qt_app):
    window = QWidget()
    window.cycle = window
    edit = QLineEdit()
    QVBoxLayout(window).addWidget(edit)
    window.show()
    window.activateWindow()
    edit.setFocus()
    qt_app.processEvents()
    LEFT.append(weakref.ref(window))
"""

SECOND = """
from test_first import LEFT


def test_finds_it_gone_before_it_starts(qt_app):
    assert LEFT[0]() is None, "a window one test left in a cycle outlived it"
"""


def test_the_collector_waits_for_the_test_to_end() -> None:
    assert not gc.isenabled()


def test_a_window_left_in_a_cycle_is_gone_before_the_next_test(tmp_path: Path) -> None:
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_first.py").write_text(FIRST, encoding="utf-8")
    (tmp_path / "test_second.py").write_text(SECOND, encoding="utf-8")

    run = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:randomly",
         "--no-cov", str(tmp_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=tmp_path,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"}, timeout=120, check=False,
    )  # fmt: skip

    assert run.returncode == 0, run.stdout[-2000:] + run.stderr[-2000:]
