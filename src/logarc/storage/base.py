"""The storage contract, so the backend can be replaced without touching analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable
    from datetime import datetime

    from logarc.core.event import NormalizedEvent


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

    def events_for_ip(self, client_ip: str) -> list[NormalizedEvent]:
        """All events for one client, in time order."""
        ...

    def ip_summaries(self, *, limit: int | None = None) -> list[IpSummary]:
        """Per-client summaries, busiest first."""
        ...

    def close(self) -> None:
        """Release any held resources."""
        ...
