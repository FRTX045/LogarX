"""Reads a log file end to end and writes the events it contains into a store.

This is the O(n) half of the two-pass design: one streaming walk over the log,
with memory bounded by the batch size. Everything after ingest works from the
store and never touches the original file again.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from itertools import chain, islice
from typing import TYPE_CHECKING, Final

from logarc.core.evidence import EvidenceRef
from logarc.ingest.reader import open_log
from logarc.parsers.registry import DEFAULT_SAMPLE_SIZE, detect_format, get_parser

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from logarc.core.event import NormalizedEvent
    from logarc.ingest.quarantine import Quarantine
    from logarc.parsers.base import LogParser
    from logarc.storage.base import EventStore

__all__ = ["FormatDetectionError", "IngestCancelled", "IngestResult", "ingest_file"]

#: Events buffered before a write. Large enough that Parquet row groups are
#: worth having, small enough that memory stays flat on a huge log.
DEFAULT_BATCH_SIZE: Final = 100_000

_UNPARSEABLE: Final = "line does not match the log format"


class FormatDetectionError(RuntimeError):
    """Raised when a log's format cannot be identified."""


# No `Error` suffix: this is not a failure. It reports that someone asked the
# ingest to stop, and calling it an error would push callers towards handling a
# deliberate cancel the same way they handle a corrupt file.
class IngestCancelled(RuntimeError):  # noqa: N818
    """Raised when the caller stopped an ingest before it reached the end.

    Deliberately an exception rather than a quiet early return. A short read
    that looks like a finished one is the worst outcome available here: the
    case would go on to be finalised, and a truncated log would present as a
    complete one. Raising forces every caller to decide what to do about it.
    """

    def __init__(self, path: Path, lines_read: int) -> None:
        super().__init__(f"ingest of {path} cancelled after {lines_read:,} lines")
        self.path = path
        self.lines_read = lines_read


@dataclass(frozen=True, slots=True)
class IngestResult:
    """What one ingested file contributed to the case."""

    file_id: str
    original_path: str
    sha256: str
    size_bytes: int
    compression: str
    log_format: str
    lines_read: int
    events_parsed: int
    lines_quarantined: int
    duration_seconds: float

    @property
    def lines_per_second(self) -> float:
        return self.lines_read / self.duration_seconds if self.duration_seconds else 0.0


def ingest_file(
    path: Path,
    store: EventStore,
    quarantine: Quarantine,
    *,
    file_id: str | None = None,
    log_format: str | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    on_progress: Callable[[int, int], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
) -> IngestResult:
    """Parse `path` into `store`, quarantining whatever does not parse.

    `log_format` names a registered format; when omitted it is detected from the
    first lines of the file. Detection failing is an error rather than a guess:
    choosing the wrong parser would quarantine the entire log and present as an
    empty result.

    `on_progress` is called with `(lines_read, bytes_read)` once per batch, for
    progress reporting in long-running ingests.

    `should_cancel` is polled at the same batch boundaries and raises
    `IngestCancelled` when it answers true. A plain predicate rather than a
    threading primitive: the engine has no opinion on what makes a caller want
    to stop, and taking one would drag the interface layer's concerns in here.
    Asking once per batch rather than once per line keeps a ten-million-line
    ingest from paying for the question; the cost is that a stop lands at the
    next boundary rather than instantly.
    """
    file_id = file_id or path.name
    started = time.perf_counter()

    with open_log(path) as stream:
        lines = iter(stream)
        sample = list(islice(lines, DEFAULT_SAMPLE_SIZE))
        parser = _resolve_parser(path, log_format, [text for _, text in sample])

        batch: list[NormalizedEvent] = []
        lines_read = 0
        events_parsed = 0
        lines_quarantined = 0

        for line_no, text in chain(sample, lines):
            lines_read += 1
            # Blank lines are padding, not damage: they are neither parsed nor
            # quarantined, so the two counts plus blanks account for every line.
            if not text.strip():
                continue

            event = parser.parse_line(text, EvidenceRef(file_id, line_no))
            if event is None:
                quarantine.record(file_id, line_no, text, reason=_UNPARSEABLE)
                lines_quarantined += 1
                continue

            batch.append(event)
            events_parsed += 1
            if len(batch) >= batch_size:
                store.write(batch)
                batch = []
                if on_progress:
                    on_progress(lines_read, stream.bytes_read)
                # After the write, never before: whatever has been read is real
                # evidence, and a cancel should shorten the ingest rather than
                # throw away the part that already succeeded.
                if should_cancel and should_cancel():
                    raise IngestCancelled(path, lines_read)

        if batch:
            store.write(batch)
            if on_progress:
                on_progress(lines_read, stream.bytes_read)

        return IngestResult(
            file_id=file_id,
            original_path=str(path),
            sha256=stream.sha256,
            size_bytes=stream.size_bytes,
            compression=stream.compression.value,
            log_format=parser.name,
            lines_read=lines_read,
            events_parsed=events_parsed,
            lines_quarantined=lines_quarantined,
            duration_seconds=time.perf_counter() - started,
        )


def _resolve_parser(path: Path, log_format: str | None, sample: list[str]) -> LogParser:
    if log_format is not None:
        return get_parser(log_format)

    detection = detect_format(sample)
    if detection is None:
        raise FormatDetectionError(
            f"could not identify the log format of {path}; pass one explicitly with --format"
        )
    return detection.parser
