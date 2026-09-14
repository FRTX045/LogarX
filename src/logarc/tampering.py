"""Reading a log for signs it was edited after the fact.

An attacker who gets in often tidies up behind themselves, and a log that looks
clean may simply be a log that was cleaned. The SHA-256 taken at ingest proves
the file has not changed since logarc read it and says nothing whatever about
what happened before that — this module is pointed at exactly that gap.

**Nothing here is proof, and the wording is part of the design.** A log cannot
establish that it was edited. Every signal below has an innocent explanation
that is usually the right one: a reordering is a corrected clock far more often
than a forgery, a missing stretch is log rotation, a quiet week is a server
nobody found. So each observation carries what was seen, what it is consistent
with — the innocent readings first, because they are the likely ones — and what
would actually settle the question, which is always something outside the log.

A forensic tool that cries wolf is worse than one that stays quiet, because
somebody may be accused on the strength of it. The tests hold this module to
that: an observation with no innocent reading is treated as a defect.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.event import NormalizedEvent

__all__ = ["Observation", "inspect"]

#: Below this many requests a log has no rhythm to depart from, and the absence
#: of anything is unremarkable. Reporting "no 404s" across nine requests would
#: be arithmetic dressed as a finding.
MIN_REQUESTS: Final = 50

#: Marks a client that announced itself as automated. Deliberately short and
#: conservative: this is used to decide whether *any* automated traffic is
#: present, so a miss costs a false observation and breadth is worth more than
#: precision here.
_AUTOMATED: Final = (
    "bot",
    "crawl",
    "spider",
    "slurp",
    "curl",
    "wget",
    "python-requests",
    "go-http-client",
    "scan",
    "http-client",
    "libwww",
    "okhttp",
)

#: Seconds that count as "a round time" for the last request in a log. An hour
#: and a day; a minute is far too common to mean anything.
_ROUND_SECONDS: Final = (3_600, 86_400)


@dataclass(frozen=True, slots=True)
class Observation:
    """One thing about a log that an untouched log does not usually show."""

    signal: str
    """Short stable id, for a report or a test to name it by."""

    headline: str
    """What was seen, in one line."""

    detail: str
    """The numbers behind it, so a reader can weigh it rather than trust it."""

    consistent_with: tuple[str, ...]
    """What else produces this, innocent readings first.

    Never empty. An observation with nothing in here is an accusation, and this
    module does not make accusations.
    """

    would_settle_it: tuple[str, ...]
    """What would actually answer the question — always outside the log."""


def _out_of_order(events: Sequence[NormalizedEvent]) -> Observation | None:
    """Entries whose timestamp goes backwards against the order they are stored in."""
    backwards = 0
    worst = 0.0
    previous = events[0].timestamp
    for item in events[1:]:
        if item.timestamp < previous:
            backwards += 1
            worst = max(worst, (previous - item.timestamp).total_seconds())
        previous = max(previous, item.timestamp)

    if not backwards:
        return None

    return Observation(
        signal="out_of_order",
        headline=f"{backwards:,} entries are older than a line above them.",
        detail=(
            f"{backwards:,} of {len(events):,} requests carry a timestamp earlier "
            f"than one already seen further up the file; the largest step back is "
            f"{worst:,.0f} seconds. A log is normally written in the order things "
            f"happened, so the file's order and the clock's order agree.\n\n"
            f"Read the count as a size, not as a number of edits. One line moved "
            f"from further down makes every entry it was moved past read as out of "
            f"order, so a single change can produce hundreds — measured on this "
            f"project's own test log, transposing two entries 400 apart reported "
            f"400."
        ),
        consistent_with=(
            "a clock that was corrected, by NTP or by hand, while the server ran",
            "two or more servers' logs merged into one file",
            "a load balancer writing entries as requests finish rather than start",
            "lines inserted, removed or re-ordered after the fact",
        ),
        would_settle_it=(
            "the server's own NTP or clock-adjustment record for that period",
            "whether the file is one server's log or a merge of several",
            "the original file's hash, if anyone took one before it was handled",
        ),
    )


def _no_client_errors(events: Sequence[NormalizedEvent]) -> Observation | None:
    """A public server refuses something. A log where nothing was ever missing."""
    statuses = Counter(item.status for item in events if item.status is not None)
    client_errors = sum(count for status, count in statuses.items() if 400 <= status < 500)
    if client_errors:
        return None

    return Observation(
        signal="no_client_errors",
        headline="Not one request in this log was refused or missing.",
        detail=(
            f"All {len(events):,} requests answered 2xx or 3xx. Anything reachable "
            f"from the internet collects 404s within hours — mistyped paths, stale "
            f"links, and every scanner that has ever found it."
        ),
        consistent_with=(
            "a log already filtered to successful requests, by the server or by a tool",
            "an internal service nothing outside can reach",
            "a very short window, or a site that is not public",
            "a stretch of refusals removed from the file",
        ),
        would_settle_it=(
            "the server's log configuration — whether it writes every response or some",
            "whether this file is the whole log or an extract someone prepared",
            "another log from the same period, from the same host",
        ),
    )


def _no_automated_traffic(events: Sequence[NormalizedEvent]) -> Observation | None:
    """Anything reachable is crawled. A log with no bot in it at all."""
    for item in events:
        agent = (item.user_agent or "").lower()
        if not agent or any(mark in agent for mark in _AUTOMATED):
            return None

    return Observation(
        signal="no_automated_traffic",
        headline="Every request here came from something calling itself a browser.",
        detail=(
            f"None of {len(events):,} requests carries a User-Agent naming a crawler, "
            f"a scanner or an HTTP library, and none is missing one. Anything "
            f"reachable is found by crawlers within days, and they say who they are."
        ),
        consistent_with=(
            "a site not reachable from the internet, or new enough not to be indexed",
            "a log already filtered to human traffic",
            "a proxy or CDN absorbing automated requests before this server sees them",
            "automated entries removed from the file",
        ),
        would_settle_it=(
            "whether anything sits in front of this server",
            "whether the host appears in DNS or has ever been linked to",
            "the same server's log from a neighbouring period",
        ),
    )


def _ends_on_a_round_time(events: Sequence[NormalizedEvent]) -> Observation | None:
    """Traffic does not stop on the hour. A truncation does."""
    last = max(item.timestamp for item in events)
    for unit in _ROUND_SECONDS:
        seconds = (
            last.hour * 3_600 + last.minute * 60 + last.second
            if unit == 86_400
            else last.minute * 60 + last.second
        )
        if seconds % unit == 0:
            name = "the hour" if unit == 3_600 else "midnight"
            return Observation(
                signal="ends_on_a_round_time",
                headline=f"The last request lands exactly on {name}.",
                detail=(
                    f"The final entry is timestamped {last.isoformat()}, to the second. "
                    f"Requests arrive when they arrive; a file that stops on a round "
                    f"number more often stopped because something cut it there."
                ),
                consistent_with=(
                    "log rotation, which cuts on exactly such a boundary by design",
                    "an extract someone took for a fixed period",
                    "coincidence — one log in 3,600 ends on the hour honestly",
                    "a file truncated at a chosen time",
                ),
                would_settle_it=(
                    "the server's rotation schedule, and whether the next file continues",
                    "whether a following log exists and picks up where this stops",
                    "the file's own modification time against its last entry",
                ),
            )
    return None


#: Every check, in the order a report should read them.
_CHECKS: Final = (
    _out_of_order,
    _no_client_errors,
    _no_automated_traffic,
    _ends_on_a_round_time,
)


def inspect(events: Sequence[NormalizedEvent]) -> list[Observation]:
    """Everything about `events` that an untouched log does not usually show.

    An empty list is the ordinary answer and the one most logs should get.
    `events` is expected in the order the file stored them, which is what
    `EventStore.all_events` yields: the whole point of the first check is that
    the file's order and the clock's order should agree.
    """
    if len(events) < MIN_REQUESTS:
        return []

    found = [check(events) for check in _CHECKS]
    return [item for item in found if item is not None]
