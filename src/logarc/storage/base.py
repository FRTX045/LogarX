"""The storage contract, so the backend can be replaced without touching analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

    from logarc.core.event import NormalizedEvent
    from logarc.core.window import TimeWindow


@dataclass(frozen=True, slots=True)
class IpSummary:
    """What is known about one client without loading any of its events.

    This is what makes choosing an IP instant on a large case: the summary is
    computed once during ingest, so the selection screen never scans the store.
    """

    client_ip: str
    request_count: int
    first_seen: datetime
    last_seen: datetime
    distinct_paths: int
    client_error_ratio: float
    """Share of responses in the 4xx range. High values suggest probing for
    resources that are not there."""
    bytes_total: int


@dataclass(frozen=True, slots=True)
class TimeSlot:
    """How much traffic the case carried over one stretch of it.

    What the band above the graph is drawn from: enough to show where the busy
    hours are, and nothing more. Whose requests they were is a different
    question, answered by `ip_summaries`.
    """

    start: datetime
    request_count: int


class EventStore(Protocol):
    """Writes events during ingest, reads them back one client at a time.

    The asymmetry is deliberate and is what the two-pass design rests on:
    writing is a single streaming pass over the whole log, reading is a narrow
    lookup that analysis performs repeatedly. See ADR-0002.
    """

    def write(self, events: Iterable[NormalizedEvent]) -> None:
        """Append a batch. Only valid before `finalize`."""
        ...

    def finalize(self) -> None:
        """Close out ingest and build the structures reads depend on."""
        ...

    def events_for_ip(
        self, client_ip: str, *, window: TimeWindow | None = None
    ) -> list[NormalizedEvent]:
        """All events for one client, in time order.

        `window` narrows the read to one stretch of time, counting both ends.
        Applied here rather than by the caller so the backend can skip the rows
        instead of handing them over to be discarded.
        """
        ...

    def all_events(self) -> Iterator[NormalizedEvent]:
        """Every event in the case, streamed.

        The one whole-case read, and it exists for enrichment: sending each
        client's requests to the CRS sidecar separately would pay process
        startup per client and re-read the same partitions. Streamed rather
        than returned as a list, because a case can hold millions of events and
        the caller batches them anyway.
        """
        ...

    def ip_summaries(
        self,
        *,
        limit: int | None = None,
        order_by: str = "requests",
        window: TimeWindow | None = None,
    ) -> list[IpSummary]:
        """Per-client summaries, busiest first unless `order_by` says otherwise.

        `window` narrows every figure to one stretch of time — the counts, the
        first and last sighting, the error share. Not a filter over whole-case
        summaries: a client half inside the window would then be listed with
        numbers describing the half that is not shown.
        """
        ...

    def activity_over_time(
        self, *, buckets: int = 200, client_ip: str | None = None
    ) -> list[TimeSlot]:
        """Request volume across the case, in roughly `buckets` steps.

        Roughly, because the step is the span divided by `buckets` and stretches
        of it may carry nothing at all. A case covering minutes and one covering
        a month both come back filled, which is what lets one band serve either.

        `client_ip` asks about one client instead, over *its* own span rather
        than the case's. That is the point of asking: a client alive for ninety
        minutes fills the band, instead of being a hairline in the middle of two
        days.
        """
        ...

    def close(self) -> None:
        """Release any held resources."""
        ...
