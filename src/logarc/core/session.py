"""A session: one client's activity, bounded in time."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from logarc.core.event import NormalizedEvent


@dataclass(frozen=True, slots=True)
class Session:
    """A contiguous run of requests attributed to one client.

    A session is the outermost unit of segmentation. It exists because "an IP"
    is not the same as "a visitor": addresses are shared behind NAT, reassigned,
    and revisited days apart. Bounding by inactivity and by client software
    gives a unit that can reasonably be read as one person doing one thing.
    """

    session_id: str
    client_ip: str
    user_agent: str | None
    events: tuple[NormalizedEvent, ...]

    @property
    def start(self) -> datetime:
        return self.events[0].timestamp

    @property
    def end(self) -> datetime:
        return self.events[-1].timestamp

    @property
    def duration(self) -> timedelta:
        return self.end - self.start

    @property
    def request_count(self) -> int:
        return len(self.events)
