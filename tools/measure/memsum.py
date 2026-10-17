"""Summarise what memsample.ps1 recorded: the peak total, and the peak per process.

python tools/measure/memsum.py SAMPLES
"""

from __future__ import annotations

import sys
from pathlib import Path

MB = 1024 * 1024


def summarise(samples: Path) -> str:
    """One line: most processes at once, the peak totals, the per-process range."""
    most = total_working = total_private = 0
    peak: dict[str, int] = {}
    for line in samples.read_text(encoding="ascii").splitlines():
        processes = [field.split(":") for field in line.split()]
        if not processes:
            continue
        most = max(most, len(processes))
        total_working = max(total_working, sum(int(p[1]) for p in processes))
        total_private = max(total_private, sum(int(p[2]) for p in processes))
        for pid, _, _, peak_working in processes:
            peak[pid] = max(peak.get(pid, 0), int(peak_working))
    if not peak:
        return "no samples: the process was never seen running"
    return (
        f"{most} processes at most; peak total working set {total_working / MB:.0f} MB, "
        f"peak total private {total_private / MB:.0f} MB; per-process peak working set "
        f"{min(peak.values()) / MB:.0f}-{max(peak.values()) / MB:.0f} MB"
    )


if __name__ == "__main__":
    print(summarise(Path(sys.argv[1])))
