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
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtCore import QSettings, QThreadPool
from PyQt6.QtWidgets import QApplication

from logarc.gui import app, workers


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

    **Round and round until a pump starts nothing**, rather than waiting once.
    A result landing is exactly when the window starts the next thing - an
    ingest that finishes loads the case, and loading a case is another job - so
    that job begins during the pump, which is after the wait the caller made.
    Waiting once left it running, and a test that returned there carried a live
    thread into the interpreter's own teardown: on this machine the process then
    ended with 0xC0000409 *after* the test had passed. Twice over, and gone as
    soon as the second round was waited for.

    `waitForDone(0)` is the loop's condition because it answers for a job the
    instant it is started, checked rather than assumed - 40 starts, 40 times not
    empty. Were it racy, a round could see an empty pool and return into the
    same live thread this exists to wait for.

    A plain function rather than a fixture because callers ask for it in the
    middle of a test, between a gesture and the assertion about it, which is
    not something a fixture can be asked for.
    """
    pool = QThreadPool.globalInstance()
    assert pool is not None
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        assert left > 0, "background work did not finish"
        assert pool.waitForDone(int(left * 1000)), "background work did not finish"
        qt_app.processEvents()
        # An idle pool is not the whole condition. `run_job` retires a job when
        # its `finished` signal is *delivered*, not when the work returns, so a
        # job started from inside another job's slot can run to completion
        # during this pump and still be holding its callbacks (and through them
        # the window) with its own signal queued behind us.
        if pool.waitForDone(0) and not workers._in_flight:
            return


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


@pytest.fixture(autouse=True)
def nothing_left_running(request: pytest.FixtureRequest) -> Iterator[None]:
    """Fail a test that walks away from work it started.

    Three tests here did. Each passed, and each ended the process with
    0xC0000409 when it was the last thing to run - one of them only sometimes,
    which is the worse kind: it had been arriving as a segfault on CI, on a
    different machine, days apart, with nothing to point at.

    Nothing in the assertion is about crashing. A test that returns while the
    window is still reading has stopped watching before the thing it asked for
    happened, so what it checked was the state on the way there. `settled` is
    how a test says it wants the end of that.

    Quiet where there is no application - 207 tests here are of Qt-free seams
    and never build one, and `globalInstance()` is None for them. An assertion
    that demanded a display from those would be asking them to stop being what
    they are.
    """
    yield
    if QApplication.instance() is None:
        return
    pool = QThreadPool.globalInstance()
    if pool is None:
        return
    left = pool.activeThreadCount()
    assert left == 0, (
        f"{request.node.name} ended with {left} job(s) still running. "
        "Call settled(qt_app) before the test returns."
    )
