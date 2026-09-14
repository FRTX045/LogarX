"""Reading a log for signs it was edited after the fact.

The hard part of this is not finding the signals. It is refusing to overclaim
them: none of these establishes tampering, every one has an innocent
explanation that is usually the right one, and a forensic tool that cries wolf
is worse than one that stays quiet. So the tests below are as much about what
the report *does not* say as about what it finds.

The SHA-256 taken at ingest proves the file has not changed since logarc read
it. It says nothing whatever about what happened before, which is the gap this
module is pointed at.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.tampering import inspect

START = datetime(2026, 3, 9, 9, 0, tzinfo=UTC)


def event(
    n: int,
    *,
    seconds: float | None = None,
    status: int = 200,
    path: str = "/",
    agent: str = "Mozilla/5.0 (X11; Linux x86_64) Chrome/120",
) -> NormalizedEvent:
    when = START + timedelta(seconds=n * 30 if seconds is None else seconds)
    return NormalizedEvent(
        timestamp=when,
        client_ip=f"203.0.113.{n % 50}",
        evidence=EvidenceRef("access.log", n + 1),
        method="GET",
        path=path,
        query=None,
        status=status,
        bytes_sent=512,
        referer=None,
        user_agent=agent,
    )


def ordinary(count: int = 400) -> list[NormalizedEvent]:
    """A log with the background noise every real one carries."""
    events = []
    for n in range(count):
        if n % 17 == 0:
            events.append(event(n, status=404, path=f"/missing-{n}"))
        elif n % 23 == 0:
            events.append(event(n, agent="Googlebot/2.1 (+http://www.google.com/bot.html)"))
        else:
            events.append(event(n))
    return events


def signals(events: list[NormalizedEvent]) -> set[str]:
    return {observation.signal for observation in inspect(events)}


# -- the quiet case -------------------------------------------------------


def test_an_ordinary_log_raises_nothing() -> None:
    """The first requirement. A tool that flags every log flags none of them."""
    assert inspect(ordinary()) == []


def test_a_log_too_short_to_judge_says_nothing() -> None:
    """Six requests have no rhythm to depart from, and no background noise is
    expected in them. Reporting an absence of 404s here would be arithmetic
    dressed as a finding."""
    assert inspect([event(n) for n in range(6)]) == []


# -- out of order ---------------------------------------------------------


def test_entries_out_of_order_are_reported() -> None:
    events = ordinary()
    events[200], events[201] = events[201], events[200]

    assert "out_of_order" in signals(events)


def test_out_of_order_names_a_clock_change_before_it_names_tampering() -> None:
    """The innocent reading comes first because it is usually the right one:
    a merged log, an NTP step, a server whose clock was corrected."""
    events = ordinary()
    events[200], events[201] = events[201], events[200]

    (found,) = [o for o in inspect(events) if o.signal == "out_of_order"]

    assert found.consistent_with, "an observation with no innocent reading is an accusation"
    assert "clock" in " ".join(found.consistent_with).lower()
    assert found.would_settle_it


# -- the absence of noise -------------------------------------------------


def test_a_log_with_no_client_errors_at_all_is_worth_remarking_on() -> None:
    """Every public server refuses something. A log where nothing was ever
    missing has either been filtered or is not a public server's."""
    clean = [event(n) for n in range(400)]

    assert "no_client_errors" in signals(clean)


def test_a_log_with_no_automated_traffic_at_all_is_worth_remarking_on() -> None:
    """Anything reachable is crawled within days. A week with no bot at all is
    not what the internet does."""
    events = [event(n, status=404 if n % 17 == 0 else 200, path=f"/p-{n}") for n in range(400)]

    assert "no_automated_traffic" in signals(events)


# -- a cut that lands too neatly -----------------------------------------


def test_a_log_ending_exactly_on_the_hour_is_remarked_on() -> None:
    """Traffic does not stop on the hour. A truncation does."""
    events = ordinary(300)
    # Re-time so the last request lands precisely at 12:00:00.
    last = datetime(2026, 3, 9, 12, 0, 0, tzinfo=UTC)
    events = [
        event(n, seconds=(last - START).total_seconds() - (len(events) - 1 - n) * 7)
        if n % 17
        else event(
            n,
            seconds=(last - START).total_seconds() - (len(events) - 1 - n) * 7,
            status=404,
        )
        for n in range(len(events))
    ]

    assert "ends_on_a_round_time" in signals(events)


def test_an_ordinary_ending_is_not_remarked_on() -> None:
    assert "ends_on_a_round_time" not in signals(ordinary())


# -- how it reports -------------------------------------------------------


def test_nothing_is_ever_called_proof() -> None:
    """The whole discipline of this module in one assertion.

    A log cannot establish that it was edited. It can only be inconsistent with
    what an untouched log usually looks like, and the difference matters when
    somebody is going to be accused of something.
    """
    events = ordinary()
    events[200], events[201] = events[201], events[200]
    events = [e for e in events if e.status != 404]

    for observation in inspect(events):
        wording = f"{observation.headline} {observation.detail}".lower()
        for forbidden in ("proves", "proof", "confirms", "definitely", "certainly"):
            assert forbidden not in wording, f"{observation.signal} overclaims: {wording}"
        assert observation.consistent_with, f"{observation.signal} offers no innocent reading"
        assert observation.would_settle_it, (
            f"{observation.signal} does not say what would settle it"
        )
