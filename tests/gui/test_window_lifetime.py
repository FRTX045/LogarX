"""A window that nobody holds any more should be collectable.

The GUI suite builds 81 `MainWindow`s and leaks roughly one per test: at the
worst moment 41 were alive at once, the oldest built 35 tests earlier. The Linux
runners then segfault inside `MainWindow.__init__` building a `QAction` — three
times so far, most recently on a commit that changed nothing but Markdown.

**Measured 2026-09-21, and it corrects what this project previously believed.**
The earlier note concluded the survivors were "held by something a full
`gc.collect()` cannot break, which points at a C++-side reference". The first
half is true and the second is wrong: every holder is an ordinary Python object.
Tracing a leaked window names them — an `ArrangementKeeper`, a `FullScreen`, the
`done()` closure from `_load_case`, and three bound methods held by the first
two. `Job` and `JobSignals` are fully collected and are not involved.

What triggers it is narrow and reproducible: **a window that has loaded a case
leaks; one that has not is collected immediately.** The leak is permanent within
the process, surviving repeated `gc.collect()`, an event-loop turn, and further
allocation.

The last test here reproduces that and is `xfail(strict=True)` rather than
deleted or commented out. Strict, so the day somebody fixes it the suite fails
and says so — an xfail that quietly starts passing is how a fix goes unnoticed
and a regression later goes unexplained.
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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Known leak: a window that has loaded a case is never collected. Traced "
        "2026-09-21 to Python holders — ArrangementKeeper, FullScreen, the "
        "done() closure in _load_case — not to a C++ reference as previously "
        "thought. Root not yet found. See TODO.md."
    ),
)
def test_a_window_that_loaded_a_case_is_collectable(qt_app: QApplication, tmp_path: Path) -> None:
    """The leak itself, pinned so it cannot be lost or misremembered.

    One window, one case, and the question the suite's 41 survivors are made of.
    Everything else about the reproduction — that it is permanent, that
    `gc.collect()` does not touch it, that `Job` and `JobSignals` are innocent —
    is in the module docstring and in TODO.md, because a test should state the
    property rather than the investigation.
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
