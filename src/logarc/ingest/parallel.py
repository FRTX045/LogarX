"""Ingesting one log with several worker processes.

Parsing is 96% of what ingest costs — measured, not assumed — and within that
the regex match is only a quarter. The rest is CPython moving fields about, so
a faster pattern engine cannot buy much and the work is instead spread across
processes. It parallelises cleanly because parsing a line depends on nothing but
that line.

Each worker takes a byte range from `scan`, parses it, and writes its own
Parquet shard and its own quarantine file into the shared case. Nothing is sent
back but three counts: handing events across a process boundary would pickle
millions of objects and give back the time the parallelism just saved.

**Threads would not do.** The parse holds the GIL throughout — it is Python
bytecode, not a library call that releases it — so threads would take turns
rather than run at once.

Two limits, stated rather than worked around:

* **Compressed logs cannot be split.** gzip and bzip2 have no random access, so
  a range cannot be read without decompressing everything before it. Callers
  fall back to the sequential path.
* **Memory rises with the worker count.** Each holds its own batch, so four
  workers cost roughly four times one. That is the trade, and it is why the
  count is the caller's to choose rather than something picked here.
"""

from __future__ import annotations

import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.ingest.quarantine import Quarantine
from logarc.ingest.reader import Compression, open_log
from logarc.ingest.scan import Chunk, read_range, scan_chunks
from logarc.parsers.registry import DEFAULT_SAMPLE_SIZE, detect_format, get_parser
from logarc.storage.event_store import ParquetEventStore

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["MIN_PARALLEL_BYTES", "can_split", "ingest_file_parallel"]

#: Below this, a sequential ingest finishes before the workers have started.
#: Spawning a process costs tens of milliseconds on Linux and rather more on
#: Windows, and a small log is parsed in less than that.
MIN_PARALLEL_BYTES: Final = 32 << 20  # 32 MB

_UNPARSEABLE: Final = "line does not match the log format"


def can_split(path: Path) -> bool:
    """Whether `path` can be read in ranges at all.

    Compression is the only thing that rules it out, and it is detected from the
    leading bytes rather than the name — evidence arrives named however it was
    seized, and a gzipped file called `access.log` is common.
    """
    with open_log(Path(path)) as stream:
        return stream.compression is Compression.NONE


def worth_splitting(path: Path, *, workers: int) -> bool:
    """Whether splitting `path` across `workers` would pay for itself."""
    if workers <= 1 or not can_split(path):
        return False
    return Path(path).stat().st_size >= MIN_PARALLEL_BYTES


@dataclass(frozen=True, slots=True)
class _Task:
    """One worker's instructions.

    Only paths, a chunk and strings: everything here is pickled to reach a
    process started by spawn, which is how Windows starts one.
    """

    path: Path
    chunk: Chunk
    case_root: Path
    file_id: str
    log_format: str
    shard: str
    batch_size: int


@dataclass(frozen=True, slots=True)
class _Counts:
    lines_read: int
    events_parsed: int
    lines_quarantined: int


def _parse_chunk(task: _Task) -> _Counts:
    """Parse one range in this process, writing straight into the case.

    Module level and taking a single picklable argument because a worker started
    by spawn re-imports this module and looks the function up by name. A closure
    or a bound method cannot be found that way — and the failure is quiet: the
    pool raises nothing an ordinary run surfaces, and the ingest completes
    having stored nothing.
    """
    parser = get_parser(task.log_format)
    lines_read = events_parsed = lines_quarantined = 0

    store = ParquetEventStore(task.case_root, shard=task.shard)
    try:
        with Quarantine(task.case_root, shard=task.shard) as quarantine:
            batch = []
            for line_no, text in read_range(task.path, task.chunk):
                lines_read += 1
                if not text.strip():
                    continue
                event = parser.parse_line(text, EvidenceRef(task.file_id, line_no))
                if event is None:
                    quarantine.record(task.file_id, line_no, text, reason=_UNPARSEABLE)
                    lines_quarantined += 1
                    continue
                batch.append(event)
                events_parsed += 1
                if len(batch) >= task.batch_size:
                    store.write(batch)
                    batch = []
            if batch:
                store.write(batch)
            lines_quarantined = quarantine.count
    finally:
        store.close()

    return _Counts(lines_read, events_parsed, lines_quarantined)


def ingest_file_parallel(
    path: Path,
    case_root: Path,
    *,
    file_id: str,
    log_format: str | None = None,
    workers: int,
    batch_size: int,
    on_progress: Callable[[int, int], None] | None = None,
) -> tuple[_Counts, str, int, str, float]:
    """Parse `path` into the case at `case_root` using `workers` processes.

    Returns the counts, the digest, the size, the format used and the elapsed
    time — everything the caller needs to build an `IngestResult`, without this
    module having to know what one is.
    """
    path = Path(path)
    started = time.perf_counter()

    # The format is resolved once, here, and its *name* is what workers receive.
    # Detecting per worker would let two ranges of one file disagree.
    resolved = _resolve_format(path, log_format)

    scan = scan_chunks(path, parts=workers)
    tasks = [
        _Task(
            path=path,
            chunk=chunk,
            case_root=Path(case_root),
            file_id=file_id,
            log_format=resolved,
            shard=f"{index:02d}",
            batch_size=batch_size,
        )
        for index, chunk in enumerate(scan.chunks)
    ]

    lines = events = quarantined = 0
    if tasks:
        with ProcessPoolExecutor(max_workers=min(workers, len(tasks))) as pool:
            for counts in pool.map(_parse_chunk, tasks):
                lines += counts.lines_read
                events += counts.events_parsed
                quarantined += counts.lines_quarantined
                if on_progress:
                    on_progress(lines, scan.size_bytes)

    # The parts exist only for the duration of the run; a case is read from one
    # quarantine file, and two records of the same lines would double its count.
    Quarantine.merge(Path(case_root))

    return (
        _Counts(lines, events, quarantined),
        scan.sha256,
        scan.size_bytes,
        resolved,
        time.perf_counter() - started,
    )


def _resolve_format(path: Path, log_format: str | None) -> str:
    if log_format is not None:
        get_parser(log_format)  # fail here rather than inside a worker
        return log_format

    with open_log(path) as stream:
        sample = [text for _, text in _head(stream, DEFAULT_SAMPLE_SIZE)]
    detection = detect_format(sample)
    if detection is None:
        from logarc.ingest.pipeline import FormatDetectionError

        raise FormatDetectionError(
            f"could not identify the log format of {path}; pass one explicitly with --format"
        )
    return detection.parser.name


def _head(stream: object, count: int) -> list[tuple[int, str]]:
    from itertools import islice

    return list(islice(iter(stream), count))  # type: ignore[call-overload]
