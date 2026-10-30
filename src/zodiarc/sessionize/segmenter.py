"""Level 1 segmentation: splitting a client's events into sessions.

Three boundary conditions, all deterministic, with the thresholds recorded in
each analysis export so a result can be reproduced. See ADR-0003 for why this
is not done statistically.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from zodiarc.core.session import Session

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from zodiarc.core.event import NormalizedEvent
    from zodiarc.core.window import TimeWindow

__all__ = ["SessionPolicy", "sessionize"]

#: Thirty minutes is the long-standing convention in web analytics for "the
#: visitor has gone away". Adopted rather than invented so results can be
#: compared against other work.
DEFAULT_IDLE_TIMEOUT: Final = timedelta(minutes=30)

#: An upper bound on a single session, so a scanner deliberately pacing itself
#: under the idle timeout does not produce one session lasting days.
DEFAULT_MAX_DURATION: Final = timedelta(hours=8)


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    """The thresholds a segmentation was run with."""

    idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT
    max_duration: timedelta = DEFAULT_MAX_DURATION
    split_on_user_agent_change: bool = True

    def as_config(self) -> dict[str, object]:
        """The form recorded in each analysis export."""
        return {
            "idle_timeout_seconds": int(self.idle_timeout.total_seconds()),
            "max_duration_seconds": int(self.max_duration.total_seconds()),
            "split_on_user_agent_change": self.split_on_user_agent_change,
        }


def sessionize(
    events: Iterable[NormalizedEvent],
    policy: SessionPolicy | None = None,
    *,
    window: TimeWindow | None = None,
) -> list[Session]:
    """Group `events` into sessions, one client at a time.

    A new session starts when the gap since the previous request exceeds the
    idle timeout, when the User-Agent changes, or when the session has run for
    longer than the maximum duration.

    Events may arrive in any order; they are sorted per client first. The store
    already returns them sorted, but relying on that would make this quietly
    wrong for any other caller.

    `window` does not filter — whoever read these events has already done that.
    It puts its name on the sessions, and through them on the episodes and every
    identifier printed in a report. Two reconstructions of one client over two
    windows describe different things, and sharing a name they would say so
    using the same identifiers.

    An open window, or none, names sessions exactly as they have always been
    named. That is what keeps every case and report already on disk valid.
    """
    policy = policy or SessionPolicy()
    tag = f"@{window.tag}" if window is not None and not window.is_open else ""

    by_client: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        by_client[event.client_ip].append(event)

    sessions: list[Session] = []
    for client_ip, client_events in by_client.items():
        client_events.sort(key=lambda e: (e.timestamp, e.evidence.line_no))
        sessions.extend(_split_one_client(client_ip, client_events, policy, tag))
    return sessions


def _split_one_client(
    client_ip: str,
    events: Sequence[NormalizedEvent],
    policy: SessionPolicy,
    tag: str,
) -> list[Session]:
    sessions: list[Session] = []
    current: list[NormalizedEvent] = []

    for event in events:
        if current and _starts_new_session(current, event, policy):
            sessions.append(_build(client_ip, len(sessions) + 1, current, tag))
            current = []
        current.append(event)

    if current:
        sessions.append(_build(client_ip, len(sessions) + 1, current, tag))
    return sessions


def _starts_new_session(
    current: Sequence[NormalizedEvent],
    event: NormalizedEvent,
    policy: SessionPolicy,
) -> bool:
    previous = current[-1]

    # Strictly greater, so a threshold quoted in a report means what it says:
    # a gap of exactly thirty minutes is still the same session.
    if event.timestamp - previous.timestamp > policy.idle_timeout:
        return True
    if policy.split_on_user_agent_change and event.user_agent != previous.user_agent:
        return True
    return event.timestamp - current[0].timestamp > policy.max_duration


def _build(client_ip: str, index: int, events: Sequence[NormalizedEvent], tag: str) -> Session:
    return Session(
        session_id=f"{client_ip}{tag}#{index}",
        client_ip=client_ip,
        user_agent=events[0].user_agent,
        events=tuple(events),
    )
