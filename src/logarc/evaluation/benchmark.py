"""Measuring what the tool costs at each size.

Three claims are being checked, and each needs its own number:

* ingest is linear and streaming — lines/s and MB/s should hold as the input
  grows, and peak memory should not follow it;
* the store is an archive, not a copy — Parquet with compression should be
  several times smaller than the log it came from;
* analysis is O(k) in one client's requests, not O(n) in the corpus — the time
  to reconstruct a client should stay flat while the corpus grows around it.

The third is the one that justifies the two-pass architecture, so it is
measured rather than argued.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Iterator, Sequence
    from pathlib import Path

__all__ = ["BenchmarkError", "BenchmarkResult", "run_benchmark"]

_WORKER = "logarc.evaluation.bench_worker"


class BenchmarkError(RuntimeError):
    """Raised when a benchmark run could not be completed."""


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """What one size cost."""

    lines: int
    source: str
    bytes_read: int
    ingest_seconds: float
    peak_rss_bytes: int
    store_bytes: int
    clients: int
    quarantined: int
    analysed_ip: str
    analysed_requests: int
    analysed_episodes: int
    analyse_seconds: float

    @property
    def lines_per_second(self) -> float:
        return self.lines / self.ingest_seconds if self.ingest_seconds else 0.0

    @property
    def megabytes_per_second(self) -> float:
        megabytes = self.bytes_read / 1_048_576
        return megabytes / self.ingest_seconds if self.ingest_seconds else 0.0

    @property
    def peak_rss_mb(self) -> float:
        return self.peak_rss_bytes / 1_048_576

    @property
    def compression_ratio(self) -> float:
        """How many times smaller the store is than the log."""
        return self.bytes_read / self.store_bytes if self.store_bytes else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "lines": self.lines,
            "source": self.source,
            "bytes_read": self.bytes_read,
            "ingest_seconds": self.ingest_seconds,
            "lines_per_second": self.lines_per_second,
            "megabytes_per_second": self.megabytes_per_second,
            "peak_rss_mb": self.peak_rss_mb,
            "store_bytes": self.store_bytes,
            "compression_ratio": self.compression_ratio,
            "clients": self.clients,
            "quarantined": self.quarantined,
            "analysed_ip": self.analysed_ip,
            "analysed_requests": self.analysed_requests,
            "analysed_episodes": self.analysed_episodes,
            "analyse_seconds": self.analyse_seconds,
        }


def run_benchmark(
    sizes: Iterable[int],
    *,
    log: Path,
    workdir: Path,
    on_start: Callable[[int], None] | None = None,
) -> Iterator[BenchmarkResult]:
    """Measure each prefix size of `log` in a fresh process, smallest first.

    Yields as each run finishes so a long benchmark prints its rows as it goes
    rather than after the last one. A size below one line, or one the log
    cannot supply, is an error rather than a shorter run: a row labelled with a
    size it did not measure is the kind of number this module exists to avoid.
    """
    wanted = sorted(sizes)
    # Checked before the first run rather than inside the loop, so a bad size
    # cannot be reported after earlier rows have already been printed.
    for lines in wanted:
        if lines < 1:
            raise BenchmarkError(f"{lines:,} is not a corpus size; ask for at least one line")
    for lines in wanted:
        if on_start is not None:
            on_start(lines)
        yield _run_one(lines, log=log, workdir=workdir)


def _run_one(lines: int, *, log: Path, workdir: Path) -> BenchmarkResult:
    command: Sequence[str] = (
        sys.executable,
        "-m",
        _WORKER,
        "--log",
        str(log),
        "--lines",
        str(lines),
        "--workdir",
        str(workdir),
    )
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise BenchmarkError(
            f"benchmark run of {lines:,} lines failed:\n{completed.stderr.strip()}"
        )

    try:
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise BenchmarkError(
            f"benchmark run of {lines:,} lines produced no result: {completed.stdout!r}"
        ) from exc

    return BenchmarkResult(
        lines=payload["lines"],
        source=payload["source"],
        bytes_read=payload["bytes_read"],
        ingest_seconds=payload["ingest_seconds"],
        peak_rss_bytes=payload["peak_rss_bytes"],
        store_bytes=payload["store_bytes"],
        clients=payload["clients"],
        quarantined=payload["quarantined"],
        analysed_ip=payload["analysed_ip"],
        analysed_requests=payload["analysed_requests"],
        analysed_episodes=payload["analysed_episodes"],
        analyse_seconds=payload["analyse_seconds"],
    )
