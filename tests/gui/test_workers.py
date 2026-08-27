"""How engine work reports back to the window.

The window runs nothing on the thread that paints it, so everything a long job
has to say arrives as a signal. What it is *able* to say is the subject here.
"""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6", reason="the GUI extra is not installed")

from PyQt6.QtWidgets import QApplication

from conftest import settled
from logarc.gui.workers import run_job


def test_a_job_can_report_figures_as_well_as_a_sentence(qt_app: QApplication) -> None:
    """`progress` carried `str`, so a count could only ever arrive as a
    sentence — which is why the window's progress bar has always been the
    indeterminate kind, with no number able to reach it.

    Sentences still go where they always went. Anything else goes to `advanced`,
    so a reader that wants the figures gets them without parsing prose back into
    numbers.
    """
    said: list[str] = []
    advanced: list[object] = []
    done: list[object] = []

    def work(report: Callable[[object], None]) -> str:
        report("opening")
        report({"lines": 5})
        report("still going")
        return "finished"

    run_job(
        work,
        on_done=done.append,
        on_error=lambda _message, _detail: None,
        on_progress=said.append,
        on_advance=advanced.append,
    )
    settled(qt_app, timeout=10.0)

    assert said == ["opening", "still going"]
    assert advanced == [{"lines": 5}]
    assert done == ["finished"]


def test_a_job_that_reports_nothing_structured_still_works(qt_app: QApplication) -> None:
    """Every existing caller reports only sentences and passes no `on_advance`.
    They must go on working untouched."""
    said: list[str] = []
    done: list[object] = []

    def work(report: Callable[[object], None]) -> int:
        report("working")
        return 7

    run_job(work, on_done=done.append, on_error=lambda _m, _d: None, on_progress=said.append)
    settled(qt_app, timeout=10.0)

    assert said == ["working"]
    assert done == [7]
