"""The storage contract, so the backend can be replaced without touching analysis."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable, Iterator

    from zodiarc.core.event import NormalizedEvent
    from zodiarc.core.window import TimeWindow
    from zodiarc.search import Query


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
    position: int = 0
    """One-based population position when returned by a paginated query."""


@dataclass(frozen=True, slots=True)
class IpSummaryPage:
    rows: tuple[IpSummary, ...]
    total: int
    offset: int


@dataclass(frozen=True, slots=True)
class ClientMatchPage:
    """One page of the clients that sent at least one request matching a search.

    Each row describes its client over the range, as the unfiltered list does;
    `hits` says how many of that client's requests matched. The totals are of
    the whole search, not the page, so a caption can say how much it found.
    """

    rows: tuple[IpSummary, ...]
    hits: tuple[int, ...]
    """Matching requests per row, in the same order."""
    total: int
    """Clients that sent at least one matching request."""
    requests: int
    """Matching requests, across all of those clients."""
    offset: int


@dataclass(frozen=True, slots=True)
class TimeSlot:
    """How much traffic the case carried over one stretch of it.

    What the band above the graph is drawn from: enough to show where the busy
    hours are, and nothing more. Whose requests they were is a different
    question, answered by `ip_summaries`.
    """

    start: datetime
    request_count: int


@dataclass(frozen=True, slots=True)
class CaseOverview:
    """How large the case is, before any of it is listed.

    Its own question, because `ip_summaries` is capped — a window has to draw a
    table from it, and a case of a hundred thousand clients cannot be a hundred
    thousand rows. Everything a window says *about the case* has to come from
    here instead: derived from that capped list, a case of 119,880 clients
    reported itself as a case of 500, and its date fields covered the eight days
    the busiest five hundred happened to span rather than the twenty-seven the
    case does.
    """

    clients: int
    first_seen: datetime | None
    last_seen: datetime | None
    """Both absent when the case holds nothing. A case is opened before it is
    read, and the window asks then."""


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

    def iter_clients(self, *, window: TimeWindow | None = None) -> Iterator[list[NormalizedEvent]]:
        """Visit all clients once, yielding one chronological event list at a time."""
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

    def ip_summary_page(
        self,
        *,
        query: str = "",
        offset: int = 0,
        limit: int = 100,
        window: TimeWindow | None = None,
        exact: bool = False,
    ) -> IpSummaryPage:
        """Filter and page all clients, retaining their unfiltered volume positions.

        `exact` matches the whole address; otherwise any address containing `query`.
        """
        ...

    def search_clients(
        self,
        query: Query,
        *,
        offset: int = 0,
        limit: int = 100,
        window: TimeWindow | None = None,
        clients: frozenset[str] | None = None,
        also: frozenset[str] = frozenset(),
    ) -> ClientMatchPage:
        """The clients that sent at least one request `query` matches, most first.

        A request matches exactly when `query.matches` says it does: the evidence
        box asks that in Python of one client's lines, and a reader who opens a
        client found here must find there the lines that were counted. Its
        addresses narrow the clients; `clients`, when given, holds the search to
        those (what `activity:` hands over). Ties go to the lower address.

        `also` are clients found another way, by a name a reader gave them: each
        one in the range is listed, ahead of the rest, whether or not it sent a
        matching request and whatever the addresses say, with its hits (0 when
        none). The totals count it once.
        """
        ...

    def clients_present(self, clients: Collection[str]) -> frozenset[str]:
        """Which of `clients`, as whole addresses, the case holds."""
        ...

    def value_counts(
        self, *, window: TimeWindow | None = None
    ) -> dict[str, list[tuple[str, int, int]]]:
        """The statuses and methods in the range: `(value, clients, requests)` each.

        Status codes most common first, then their classes; methods most common
        first. Only values the search box can take as a filter are offered.
        """
        ...

    def overview(self, *, window: TimeWindow | None = None) -> CaseOverview:
        """How many clients the case holds, and the stretch it covers.

        Counted, not read off `ip_summaries`: that list is capped, and a figure
        taken from it describes the cap rather than the case.

        `window` asks the same about one stretch — how much of the case a range
        left, which is the other half of the same sentence.
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
