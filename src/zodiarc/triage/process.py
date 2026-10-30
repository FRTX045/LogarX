"""Own a spawned scan process from a GUI worker thread, including its cleanup."""

from __future__ import annotations

import multiprocessing
import tempfile
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, cast

from zodiarc.core.window import EVERYTHING, TimeWindow
from zodiarc.detect.ruleset import NO_EXTRA_RULES, RuleSet
from zodiarc.triage.scan import ScanCancelled, TriageResult, scan_case

if TYPE_CHECKING:
    from collections.abc import Callable
    from multiprocessing.connection import Connection
    from multiprocessing.synchronize import Event
    from threading import Event as ThreadEvent

    from zodiarc.triage.scan import TriageProgress


def _scan_worker(
    root: Path,
    window: TimeWindow,
    rules: RuleSet,
    scratch: Path,
    output: Connection,
    stop: Event,
) -> None:
    try:
        result = scan_case(
            root,
            window=window,
            rules=rules,
            scratch_root=scratch,
            report=lambda progress: output.send(("progress", progress)),
            cancelled=stop.is_set,
        )
        output.send(("done", result))
    except ScanCancelled:
        output.send(("cancelled", None))
    except Exception as exc:
        output.send(("error", f"{type(exc).__name__}: {exc}"))
    finally:
        output.close()


def run_scan(
    root: Path,
    *,
    window: TimeWindow = EVERYTHING,
    rules: RuleSet = NO_EXTRA_RULES,
    report: Callable[[TriageProgress], None],
    stop: ThreadEvent,
) -> TriageResult:
    """Run off the UI thread; cancellation also bounds a very large client scan.

    The live parent removes its child's scratch files after cancellation or exit.
    Abrupt termination of the parent can bypass cleanup and leave scratch files;
    completed caches are published separately and atomically.

    `rules` crosses into the child as data, as `window` does: the child must
    label with what the window holds, not read the reader's library for itself.
    """
    if stop.is_set():
        raise ScanCancelled()
    directory = root / "triage"
    directory.mkdir(parents=True, exist_ok=True)
    context = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="worker-", dir=directory) as temporary:
        incoming, outgoing = context.Pipe(duplex=False)
        cancel = context.Event()
        process = context.Process(
            target=_scan_worker, args=(root, window, rules, Path(temporary), outgoing, cancel)
        )
        try:
            process.start()
            outgoing.close()
            stopping: float | None = None
            while True:
                if stop.is_set():
                    cancel.set()
                    stopping = stopping or monotonic()
                    if monotonic() - stopping >= 1:
                        raise ScanCancelled()
                if incoming.poll(0.05):
                    try:
                        kind, payload = incoming.recv()
                    except EOFError:
                        raise RuntimeError(
                            "The prioritization worker exited without a result."
                        ) from None
                    if stop.is_set() or kind == "cancelled":
                        raise ScanCancelled()
                    if kind == "done":
                        return cast(TriageResult, payload)
                    if kind == "error":
                        raise RuntimeError(payload)
                    report(payload)
                elif not process.is_alive():
                    raise RuntimeError(f"The prioritization worker exited ({process.exitcode}).")
        finally:
            cancel.set()
            if process.pid is not None:
                process.join(timeout=1)
                if process.is_alive():
                    process.terminate()
                    process.join()
                process.close()
            incoming.close()
            outgoing.close()
