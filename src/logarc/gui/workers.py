"""Running engine work off the interface thread.

Ingesting a gigabyte takes minutes. Doing that on the thread that paints the
window means the window stops painting, and an investigator cannot tell a busy
tool from a hung one. So nothing here calls the engine directly: every call goes
through a `Job` on a thread pool and comes back as a signal.

The engine knows nothing about any of this. A job is a plain callable that
happens to be run elsewhere, which is what keeps the rule that anything the
window can do is also scriptable.
"""

from __future__ import annotations

import traceback
from typing import TYPE_CHECKING, Any

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal

from logarc.gui._qt import required

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["Job", "JobSignals", "run_job"]


class JobSignals(QObject):
    """How a job reports back. Signals are the only way it touches the GUI."""

    finished = pyqtSignal(object)
    failed = pyqtSignal(str, str)
    """Message for the user, and the traceback for the log."""

    progress = pyqtSignal(str)


class Job(QRunnable):
    """One unit of engine work, run on the pool.

    The callable is handed a `report` function it may call to describe what it
    is doing; anything it returns is delivered to `finished`.
    """

    def __init__(self, work: Callable[[Callable[[str], None]], Any]) -> None:
        super().__init__()
        self._work = work
        self.signals = JobSignals()

    def run(self) -> None:
        try:
            result = self._work(self.signals.progress.emit)
        except Exception as exc:
            # Both halves matter: the window needs a sentence a person can act
            # on, and the terminal needs the traceback. Swallowing either is how
            # a forensic tool ends up failing quietly.
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}", traceback.format_exc())
        else:
            self.signals.finished.emit(result)


def run_job(
    work: Callable[[Callable[[str], None]], Any],
    *,
    on_done: Callable[[Any], None],
    on_error: Callable[[str, str], None],
    on_progress: Callable[[str], None] | None = None,
    pool: QThreadPool | None = None,
) -> Job:
    """Start `work` on the thread pool and wire its results up."""
    job = Job(work)
    job.signals.finished.connect(on_done)
    job.signals.failed.connect(on_error)
    if on_progress is not None:
        job.signals.progress.connect(on_progress)
    target = pool or required(QThreadPool.globalInstance(), "thread pool")
    target.start(job)
    return job
