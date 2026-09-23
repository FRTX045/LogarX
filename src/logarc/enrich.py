"""Adding CRS detections to a case, watchably and stoppably.

The command line did this inline behind a spinner, which is all a terminal can
draw. The window needs two things a spinner never had to provide — a figure to
size a bar from, and a way to stop that keeps what has been found — so the work
lives here and both callers share it. That is the standing rule in this project:
anything the window can do is also scriptable.

**Stopping does not raise, and the difference from ingest is deliberate.** A
cancelled ingest raises `IngestCancelled`, because a truncated case that presents
as a complete one is the worst outcome available there. Enrichment only ever
*adds* to a case: a partial result is a smaller true answer, not a false one. So
this stops by letting the event stream end, which is exactly what allows
`run_sidecar` to return the detections it has already collected. Raising would
throw them away, and the dialog promises otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from time import perf_counter
from typing import TYPE_CHECKING

from logarc.case import Case
from logarc.detect.crs.sidecar import SidecarConfig, primary_site_host, run_sidecar
from logarc.detect.crs.store import write_detections

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

    from logarc.core.event import NormalizedEvent
    from logarc.detect.crs.sidecar import CrsDetection

__all__ = ["EnrichOutcome", "EnrichProgress", "enrich_case"]

#: How often to report, in requests. Small enough that a bar moves visibly on a
#: case of any size, large enough that the reporting is not the expensive part —
#: the sidecar replays a few hundred requests a second, so this is a few updates
#: a second rather than hundreds.
_EVERY = 500


@dataclass(frozen=True, slots=True)
class EnrichProgress:
    """How far in, out of how many.

    `total` comes from the manifest rather than from counting the store first.
    Counting first would read the whole case to find out how long reading the
    whole case will take, on the one path that streams specifically to avoid
    holding a corpus in memory.
    """

    replayed: int
    total: int


@dataclass(frozen=True, slots=True)
class EnrichOutcome:
    """What a run did, whether it finished or was stopped."""

    replayed: int
    covered: int
    """Requests with at least one detection, counted by `(file, line)`."""

    detections: tuple[CrsDetection, ...]
    path: Path
    stopped: bool
    seconds: float
    config: SidecarConfig
    """The configuration that ran, which is not always the one passed in: the
    case's own host replaces the caller's. Report this one."""

    @property
    def rate(self) -> float:
        return self.replayed / self.seconds if self.seconds else 0.0


def enrich_case(
    root: Path,
    *,
    config: SidecarConfig | None = None,
    report: Callable[[EnrichProgress], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
    every: int = _EVERY,
) -> EnrichOutcome:
    """Replay a case's requests through CRS and keep what comes back.

    Raises `ValueError` if the case holds no events, `CrsUnavailableError` if the
    sidecar or the ruleset is missing. Both are the caller's to word: this layer
    does not know whether it is talking to a terminal or a dialog.
    """
    config = config or SidecarConfig()
    replayed = 0
    stopped = False

    with Case.open(root) as opened:
        # The host CRS compares every URL in a parameter against comes from the
        # case, whatever config the caller built. It is a fact about the site,
        # not a preference: the command line builds its own config for the
        # paranoia level and has no way to set a host, and if the answer only
        # applied when no config was passed, `logarc enrich` would go on telling
        # CRS that every site is `localhost`.
        site_host = primary_site_host(opened.site_hosts)
        if site_host is not None:
            config = replace(config, host=site_host)

        total = opened.manifest.total_events_parsed
        stream = opened.store.all_events()

        # One event is pulled to tell an empty case from a full one, then put
        # back by chaining it in front. Asking afterwards would report a missing
        # sidecar to somebody whose real problem is that they have not ingested.
        first = next(stream, None)
        if first is None:
            raise ValueError(f"no events in {root}; ingest a log first")

        def watched(source: Iterator[NormalizedEvent]) -> Iterator[NormalizedEvent]:
            nonlocal replayed, stopped
            for stored in source:
                if should_stop is not None and should_stop():
                    stopped = True
                    return
                replayed += 1
                yield stored
                if report is not None and replayed % every == 0:
                    report(EnrichProgress(replayed=replayed, total=total))

        started = perf_counter()
        detections = run_sidecar(watched(_from(first, stream)), config=config)
        seconds = perf_counter() - started

        path = write_detections(opened.root, detections)
        opened.manifest.config.update(config.as_config())
        opened.manifest.save(opened.root)

    if report is not None and replayed % every != 0:
        # The last partial block, so a bar finishes where the work did rather
        # than stopping at the last round number.
        report(EnrichProgress(replayed=replayed, total=total))

    return EnrichOutcome(
        replayed=replayed,
        covered=len({(one.source_file_id, one.line_no) for one in detections}),
        detections=tuple(detections),
        path=path,
        stopped=stopped,
        seconds=seconds,
        config=config,
    )


def _from(first: NormalizedEvent, rest: Iterator[NormalizedEvent]) -> Iterator[NormalizedEvent]:
    yield first
    yield from rest
