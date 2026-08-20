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
    """A sentence about what is being done."""

    advanced = pyqtSignal(object)
    """A structured snapshot — figures a reader can draw rather than read.

    Separate from `progress` rather than widening it, because the two have
    different readers: a sentence belongs in the status bar, a snapshot in
    whatever is showing the numbers. Widening `progress` to `object` would send
    both to both and leave every reader testing the type."""


class Job(QRunnable):
    """One unit of engine work, run on the pool.

    The callable is handed a `report` function it may call to describe what it
    is doing; anything it returns is delivered to `finished`.
    """

    def __init__(self, work: Callable[[Callable[[object], None]], Any]) -> None:
        super().__init__()
        self._work = work
        self.signals = JobSignals()

    def _report(self, payload: object) -> None:
        """Send a sentence one way and anything else the other."""
        if isinstance(payload, str):
            self.signals.progress.emit(payload)
        else:
            self.signals.advanced.emit(payload)

    def run(self) -> None:
        try:
            result = self._work(self._report)
        except Exception as exc:
            # Both halves matter: the window needs a sentence a person can act
            # on, and the terminal needs the traceback. Swallowing either is how
            # a forensic tool ends up failing quietly.
            self.signals.failed.emit(f"{type(exc).__name__}: {exc}", traceback.format_exc())
        else:
            self.signals.finished.emit(result)


def run_job(
    work: Callable[[Callable[[object], None]], Any],
    *,
    on_done: Callable[[Any], None],
    on_error: Callable[[str, str], None],
    on_progress: Callable[[str], None] | None = None,
    on_advance: Callable[[Any], None] | None = None,
    pool: QThreadPool | None = None,
) -> Job:
    """Start `work` on the thread pool and wire its results up."""
    job = Job(work)
    job.signals.finished.connect(on_done)
    job.signals.failed.connect(on_error)
    if on_progress is not None:
        job.signals.progress.connect(on_progress)
    if on_advance is not None:
        job.signals.advanced.connect(on_advance)
    target = pool or required(QThreadPool.globalInstance(), "thread pool")
    target.start(job)
    return job
