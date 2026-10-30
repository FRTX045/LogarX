"""How late a 20 ms Qt timer fires while the sidecars replay a case in a thread.

    python tools/measure/ui_latency.py CASE [--binary EXE]
    python tools/measure/ui_latency.py --idle 20

The window replays CRS in a worker thread, so what a user feels is the main
thread's event loop falling behind while that thread works. A timer that should
fire every 20 ms is the measure: how late each tick came. `--idle` takes the
same measure with nothing running, which is the floor to compare against.
Nothing is written into the case.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from zodiarc.case import Case
from zodiarc.detect.crs.sidecar import SidecarConfig, run_sidecar

INTERVAL_MS = 20


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("case", type=Path, nargs="?", help="a case directory")
    target.add_argument(
        "--idle", type=float, metavar="SECONDS", help="measure with nothing running"
    )
    parser.add_argument("--binary", type=Path, help="a sidecar build (default: the checkout's)")
    args = parser.parse_args(argv)

    config = (
        SidecarConfig() if args.binary is None else replace(SidecarConfig(), binary=args.binary)
    )
    events = []
    if args.case is not None:
        with Case.open(args.case) as case:
            events = list(case.store.all_events())

    app = QApplication([])
    late: list[float] = []
    last = [time.perf_counter()]

    def tick() -> None:
        now = time.perf_counter()
        late.append((now - last[0]) * 1000 - INTERVAL_MS)
        last[0] = now

    timer = QTimer()
    timer.setInterval(INTERVAL_MS)
    timer.timeout.connect(tick)
    timer.start()

    done = threading.Event()
    took = [0.0]

    def work() -> None:
        started = time.perf_counter()
        try:
            if args.idle is not None:
                time.sleep(args.idle)
            else:
                run_sidecar(events, config=config)
        finally:
            took[0] = time.perf_counter() - started
            done.set()

    threading.Thread(target=work, daemon=True).start()
    poll = QTimer()
    poll.setInterval(100)
    poll.timeout.connect(lambda: app.quit() if done.is_set() else None)
    poll.start()
    app.exec()
    late.sort()

    def at(share: float) -> float:
        return late[min(len(late) - 1, int(share * len(late)))]

    print(
        f"{len(late)} ticks in {took[0]:.1f} s: median late {statistics.median(late):.1f} ms, "
        f"p95 {at(0.95):.1f} ms, p99 {at(0.99):.1f} ms, worst {late[-1]:.1f} ms, "
        f"over 100 ms late {sum(1 for x in late if x > 100)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
