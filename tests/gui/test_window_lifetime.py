"""A window that nobody holds any more should be collectable.

The GUI suite builds 81 `MainWindow`s and leaks roughly one per test: at the
worst moment 41 were alive at once, the oldest built 35 tests earlier. The Linux
runners then segfault inside `MainWindow.__init__` building a `QAction` — three
times so far, most recently on a commit that changed nothing but Markdown.

**Found and fixed 2026-09-21.** The cause was ownership of the background job,
not anything about windows. `run_job` handed its `Job` to `QThreadPool` with
auto-delete on, so the pool destroyed the C++ runnable — and the `JobSignals`
object it owned — as soon as `run()` returned, before the queued signals had
been delivered. PyQt's bookkeeping for those connections was orphaned rather
than released, and went on holding the Python slots for good.

The evidence that settled it: the `done()` closure from `_load_case` was still
alive afterwards with **no Python referrer at all**. A live function nothing in
Python holds is held from C. It closed over the window, so the window could
never be collected.

Two earlier readings were wrong and are worth recording. The project had
concluded this was "a C++-side reference rather than a Python cycle" — the
holders are ordinary Python objects, which is a different fix. And the first
attempt at that fix, disconnecting from inside the slot, is worse than the leak:
by then the C++ `JobSignals` is gone and `disconnect()` on it is an access
violation.
"""

from __future__ import annotations

import gc
import weakref
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from logarc.case import Case
from logarc.gui.app import MainWindow

if TYPE_CHECKING:
    from pathlib import Path

    from PyQt6.QtWidgets import QApplication

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /a HTTP/1.1" 200 1 "-" "curl/8.0"',
    '203.0.113.6 - - [10/Oct/2020:13:55:37 +0000] "GET /b HTTP/1.1" 404 1 "-" "curl/8.0"',
]


def a_case(root: Path) -> Path:
    log = root / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    with Case.create(root / "case") as case:
        case.ingest([log])
        case.finalize()
    return root / "case"


def test_a_window_is_collectable_once_nothing_holds_it(qt_app: QApplication) -> None:
    """A window that was only built lets go when dropped.

    This passes today and is kept because it is the half that works: whatever
    roots a window after a case is loaded, construction alone does not do it.
    A regression here would mean the menu, the canvas or the panels had started
    holding the window strongly, which is a different bug from the one below.
    """
    window = MainWindow()
    watch = weakref.ref(window)

    del window
    gc.collect()

    assert watch() is None, "a freshly built MainWindow is being held by something"


def test_ten_built_windows_do_not_pile_up(qt_app: QApplication) -> None:
    window_refs = []
    for _ in range(10):
        window = MainWindow()
        window_refs.append(weakref.ref(window))
        del window

    gc.collect()

    alive = [ref for ref in window_refs if ref() is not None]
    assert not alive, f"{len(alive)} of 10 windows survived being dropped"


def test_a_window_that_loaded_a_case_is_collectable(qt_app: QApplication, tmp_path: Path) -> None:
    """The regression itself: running a background job must not root the window.

    This was the leak. `run_job` handed its `Job` to `QThreadPool` with
    auto-delete on, so the pool destroyed the C++ runnable — and the
    `JobSignals` it owned — the moment `run()` returned, before the queued
    signals had been delivered. PyQt's bookkeeping for those connections was
    orphaned rather than cleaned up, and went on holding the Python slots. The
    `done()` closure from `_load_case` survived with no Python referrer at all,
    held only from C, and held the window through its closure.

    The fix is ownership: Python keeps the job until it reports back. If that
    regresses, this test fails here rather than as a segfault on a Linux runner
    forty tests later.
    """
    from tests.gui.conftest import settled

    window = MainWindow()
    window.show()
    window._load_case(a_case(tmp_path))
    settled(qt_app)

    watch = weakref.ref(window)
    del window
    gc.collect()

    assert watch() is None, "a window that loaded a case is still alive"
