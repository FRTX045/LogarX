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
from logarc.parsers.base import skips
from logarc.parsers.registry import (
    DEFAULT_SAMPLE_SIZE,
    detect_format,
    get_parser,
    get_spec,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from logarc.core.event import NormalizedEvent
    from logarc.ingest.quarantine import Quarantine
    from logarc.parsers.base import LogParser
    from logarc.parsers.spec import FormatSpec
    from logarc.storage.base import EventStore

__all__ = [
    "FormatDetectionError",
    "IngestCancelled",
    "IngestResult",
    "ResolvedFormat",
    "ingest_file",
    "resolve_format",
    "resolve_parser",
]

#: Events buffered before a write. Large enough that Parquet row groups are
#: worth having, small enough that memory stays flat on a huge log.
DEFAULT_BATCH_SIZE: Final = 100_000

#: How often progress is reported, in lines.
#:
#: Reporting was tied to the batch write, which meant once per hundred thousand
#: lines — measured at one update every 2.7 seconds on a real ingest, which is
#: what made a working window look like a stuck one. A batch is sized for how
#: much is worth holding in memory before a write; how often somebody watching
#: wants to hear is a different question and now has its own answer.
#:
#: A line count rather than a clock, so the cadence is the same on every machine
#: and can be asserted exactly rather than waited for. At the forty thousand
#: lines a second this parses at, it is about twenty reports a second.
PROGRESS_STRIDE: Final = 2_000

#: Longest line handed to a parser, in characters.
#:
#: Parsing costs about 327 times the line's own length in memory — measured
#: 2026-09-14 while auditing the tool as a target, at 5.5 GB for a 16 MB line
#: and 20.9 GB for a 64 MB one. The parse is linear; the multiplier is simply
#: very large. Nothing bounded the line, and nothing bounds the compression
#: ratio that can deliver it either: 31.9 KB of gzip expanded to a 32 MB line
#: in the same audit, so a small archive could ask for more memory than the
#: machine has.
#:
#: A megabyte is about 120 times the longest line Apache will write — its
#: `LimitRequestLine` default is 8,190 bytes — so no real log reaches it, while
#: the worst case falls from 21 GB to about 327 MB. `--max-line-bytes` raises
#: it for a log that genuinely needs more.
DEFAULT_MAX_LINE_BYTES: Final = 1_048_576

_UNPARSEABLE: Final = "line does not match the log format"

_TOO_LONG: Final = "line is longer than the limit and was not parsed"


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

    format_spec: FormatSpec | None
    """The definition this file was read with, when there is one to record.

    `None` for a format registered by handing over a factory — see
    `registry.get_spec`. The case then falls back to looking the name up, which
    is what every case did before definitions were carried at all."""

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
    max_line_bytes: int = DEFAULT_MAX_LINE_BYTES,
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
        # Detection runs before the loop below and scores every registered
        # parser against this sample, so an over-long line left in it would be
        # parsed by all of them — on the path that runs first, and the one a
        # `RecursionError` already came out of once. Excluded here rather than
        # only in the loop.
        resolved = resolve_format(
            path, log_format, [text for _, text in sample if len(text) <= max_line_bytes]
        )
        parser = resolved.parser

        batch: list[NormalizedEvent] = []
        lines_read = 0
        events_parsed = 0
        lines_quarantined = 0

        reported_at = 0

        def report() -> None:
            nonlocal reported_at
            # Guarded against reporting the same line twice: a stride boundary
            # and a batch boundary can land together, and a rate worked out
            # from two reports an instant apart divides by nearly nothing.
            if on_progress and lines_read != reported_at:
                reported_at = lines_read
                on_progress(lines_read, stream.bytes_read)

        for line_no, text in chain(sample, lines):
            lines_read += 1
            if lines_read % PROGRESS_STRIDE == 0:
                report()
            # Blank lines are padding, not damage: they are neither parsed nor
            # quarantined, so the two counts plus blanks account for every line.
            # A line the format calls its own bookkeeping — a W3C `#Fields:`
            # directive, a CSV header row — is padding of the same kind. Four
            # of those open every IIS file, and quarantining them would put a
            # "lines could not be parsed" strip over every such case.
            if not text.strip() or skips(parser, text):
                continue

            # Recorded rather than dropped, and only the head of it is kept:
            # what matters as evidence is that something wrote a line no server
            # would write, not the megabytes it used to say so.
            if len(text) > max_line_bytes:
                quarantine.record(
                    file_id, line_no, text[:1024], reason=f"{_TOO_LONG} ({len(text)} characters)"
                )
                lines_quarantined += 1
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
                report()
                # After the write, never before: whatever has been read is real
                # evidence, and a cancel should shorten the ingest rather than
                # throw away the part that already succeeded.
                if should_cancel and should_cancel():
                    raise IngestCancelled(path, lines_read)

        if batch:
            store.write(batch)
        # Always, batch or no batch: the last stride boundary is almost never
        # the last line, and a read that stopped short of its own total would
        # leave the window at 99%.
        report()

        return IngestResult(
            file_id=file_id,
            original_path=str(path),
            sha256=stream.sha256,
            size_bytes=stream.size_bytes,
            compression=stream.compression.value,
            log_format=resolved.name,
            format_spec=resolved.spec,
            lines_read=lines_read,
            events_parsed=events_parsed,
            lines_quarantined=lines_quarantined,
            duration_seconds=time.perf_counter() - started,
        )


@dataclass(frozen=True, slots=True)
class ResolvedFormat:
    """Which format reads a file, in all three forms the callers need.

    The parser does the reading, the name is what a person sees, and the
    definition is what survives leaving this process — into a worker, and into
    the case. Resolving returns all three together because deriving one from
    another later is exactly where the two ingest paths could drift apart.
    """

    name: str
    parser: LogParser
    spec: FormatSpec | None


def resolve_format(path: Path, log_format: str | None, sample: list[str]) -> ResolvedFormat:
    """Decide which format reads `path`, or refuse and say how to fix it.

    Shared with the parallel path rather than copied into it. Both must refuse
    in the same words: the sentence names the flag that resolves the problem,
    and two copies of it are one edit away from an investigator being given
    advice that only one of them still offers.
    """
    if log_format is not None:
        spec = get_spec(log_format)
        if spec is None:
            return ResolvedFormat(name=log_format, parser=get_parser(log_format), spec=None)
        # Resolved against the file, because part of a table format's
        # definition is in the file: a W3C log names its columns in a header.
        # What comes back is what travels to the workers and into the case.
        resolved = spec.resolved(sample)
        return ResolvedFormat(name=log_format, parser=resolved.build(), spec=resolved)

    detection = detect_format(sample)
    if detection is None:
        raise FormatDetectionError(
            f"could not identify the log format of {path}; pass one explicitly with --format"
        )
    return ResolvedFormat(name=detection.name, parser=detection.parser, spec=detection.spec)


def resolve_parser(path: Path, log_format: str | None, sample: list[str]) -> LogParser:
    """Just the parser, for a caller with nothing to carry across a boundary."""
    return resolve_format(path, log_format, sample).parser
