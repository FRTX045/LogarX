"""One `QApplication` for the whole run, as Qt requires.

The `qt_app` fixture was scoped to a module and held the only reference to the
application, so pytest let go of it at the end of every test file and PyQt
deleted it: 31 applications in one run of this suite, measured 2026-10-17.
Windows still alive at that moment, held by reference cycles the collector had
not reached, lost their C++ objects with it, and the collector finished them
off later, inside a new window's `__init__`, touching freed memory. That was
the Linux segfault CI retried on exit 139.

Checked across a real module boundary, in a pytest of its own run with this
directory's conftest. A Qt property marks the application in the first file and
is read back in the second: an application built again would not carry it, even
at the same address.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

FIRST = """
def test_marks_the_application(qt_app):
    qt_app.setProperty("zodiarc-probe", "first file")
"""

SECOND = """
def test_finds_the_same_application(qt_app):
    assert qt_app.property("zodiarc-probe") == "first file"
"""


def test_the_application_outlives_every_test_module(tmp_path: Path) -> None:
    shutil.copy(Path(__file__).with_name("conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_first.py").write_text(FIRST, encoding="utf-8")
    (tmp_path / "test_second.py").write_text(SECOND, encoding="utf-8")

    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--no-cov", str(tmp_path)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )

    assert done.returncode == 0, done.stdout + done.stderr
    assert "2 passed" in done.stdout
