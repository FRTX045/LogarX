"""What every test of the interface needs before it can ask anything.

Fifteen files were each carrying their own copy of `qt_app`, byte for byte the
same, five their own copy of `settled`, and seven their own settings seam in
four different shapes. One copy each, here.

The `QT_QPA_PLATFORM` default is set at import, before any test module can
build a `QApplication`: Qt reads it once, when the application is constructed,
so a module that set it after would be setting it for nobody.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSettings, QThreadPool
from PyQt6.QtWidgets import QApplication

from logarc.gui import app


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


@pytest.fixture(autouse=True)
def settings_in_a_temp_file(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Point the window's preferences at a file nobody has to live with.

    `QSettings` resolves to `HKCU\\Software` on Windows, so without this the
    suite writes real preferences onto whichever machine ran it and reads its
    own leftovers back on the next run - which would make these tests pass or
    fail according to what a previous run happened to leave behind.

    Substituting the factory, not `QSettings.setDefaultFormat` and `setPath`:
    those were tried first and do not redirect the `QSettings(org, app)`
    constructor at all. It goes on resolving to the registry, and the isolation
    is imaginary while looking completely convincing.

    Autouse across every test of the interface, not only the seven modules that
    carried a copy of this. The other eight were safe because none of them
    happens to reach a settings read today, which is a fact about what those
    tests do rather than a rule holding them to it.

    One file per module rather than per test, which is the wider of the two
    scopes the copies used. `test_window` needs it that way: several of its
    tests clear the store by hand, which only means anything if what an earlier
    test wrote is still there.
    """
    ini = tmp_path_factory.mktemp("settings") / "logarc.ini"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(app, "_settings", lambda: QSettings(str(ini), QSettings.Format.IniFormat))
        yield ini
