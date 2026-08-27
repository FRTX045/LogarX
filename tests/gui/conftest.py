"""What every test of the interface needs before it can ask anything.

Fifteen files were each carrying their own copy of `qt_app`, byte for byte the
same, and four their own copy of `settled`. One copy each, here.

The `QT_QPA_PLATFORM` default is set at import, before any test module can
build a `QApplication`: Qt reads it once, when the application is constructed,
so a module that set it after would be setting it for nobody.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QThreadPool
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="module")
def qt_app() -> QApplication:
    """The one application object, reused across a module.

    Qt permits exactly one `QApplication` per process, so this hands back
    whichever already exists. Module scope rather than session because that is
    what every copy of this fixture used, and a widget left over from another
    file is a state a test did not ask for.
    """
    return QApplication.instance() or QApplication([])


def settled(qt_app: QApplication, timeout: float = 30.0) -> None:
    """Wait for the window's background work, then let its results land.

    Everything the window does off the interface thread comes back as a queued
    signal, so waiting for the pool is only half of it: without pumping the
    event loop afterwards the job has finished and nothing has been told.

    A plain function rather than a fixture because callers ask for it in the
    middle of a test, between a gesture and the assertion about it, which is
    not something a fixture can be asked for.
    """
    pool = QThreadPool.globalInstance()
    assert pool is not None
    assert pool.waitForDone(int(timeout * 1000)), "background work did not finish"
    qt_app.processEvents()
