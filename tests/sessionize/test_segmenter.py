"""Tests for splitting one client's event stream into sessions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logarx.core.event import NormalizedEvent
from logarx.core.evidence import EvidenceRef
from logarx.core.window import EVERYTHING, TimeWindow
from logarx.sessionize.segmenter import SessionPolicy, sessionize

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)


def event(
    minutes: float = 0,
    *,
    ip: str = "203.0.113.5",
    user_agent: str | None = "curl/8.0",
    path: str = "/",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=START + timedelta(minutes=minutes),
        client_ip=ip,
        evidence=EvidenceRef("access.log", int(minutes * 60) + 1),
        method="GET",
        path=path,
        status=200,
        user_agent=user_agent,
    )


def test_no_events_produce_no_sessions() -> None:
    assert sessionize([]) == []


def test_a_single_event_is_a_session() -> None:
    sessions = sessionize([event()])

    assert len(sessions) == 1
    assert sessions[0].start == START
    assert sessions[0].end == START


def test_events_close_together_stay_in_one_session() -> None:
    sessions = sessionize([event(0), event(5), event(10)])

    assert len(sessions) == 1
    assert len(sessions[0].events) == 3


def test_a_gap_longer_than_the_idle_timeout_starts_a_new_session() -> None:
    sessions = sessionize([event(0), event(45)])

    assert len(sessions) == 2


def test_a_gap_exactly_at_the_timeout_does_not_split() -> None:
    """The boundary is defined as strictly greater, so a threshold written in a
    report means what it says."""
    sessions = sessionize([event(0), event(30)])

    assert len(sessions) == 1


def test_a_change_of_user_agent_starts_a_new_session() -> None:
    """One IP with two clients is usually a NAT or proxy. Treating them as one
    visitor would splice two people's behaviour into a single story."""
    sessions = sessionize([event(0, user_agent="curl/8.0"), event(1, user_agent="sqlmap/1.7")])

    assert len(sessions) == 2
    assert sessions[0].user_agent == "curl/8.0"
    assert sessions[1].user_agent == "sqlmap/1.7"


def test_splitting_on_user_agent_can_be_turned_off() -> None:
    policy = SessionPolicy(split_on_user_agent_change=False)

    sessions = sessionize(
        [event(0, user_agent="curl/8.0"), event(1, user_agent="sqlmap/1.7")], policy
    )

    assert len(sessions) == 1


def test_a_session_is_capped_at_the_maximum_duration() -> None:
    """A slow scanner pacing itself under the idle timeout would otherwise
    produce one session lasting days."""
    policy = SessionPolicy(idle_timeout=timedelta(minutes=30), max_duration=timedelta(hours=1))
    events = [event(minutes=step * 20) for step in range(7)]

    sessions = sessionize(events, policy)

    assert len(sessions) > 1
    assert all(s.duration <= timedelta(hours=1) for s in sessions)


def test_events_arriving_out_of_order_are_sorted_first() -> None:
    sessions = sessionize([event(10), event(0), event(5)])

    assert len(sessions) == 1
    assert [e.timestamp for e in sessions[0].events] == [
        START,
        START + timedelta(minutes=5),
        START + timedelta(minutes=10),
    ]


def test_session_ids_are_stable_and_identify_the_client() -> None:
    sessions = sessionize([event(0), event(45)])

    assert [s.session_id for s in sessions] == ["203.0.113.5#1", "203.0.113.5#2"]
    assert sessionize([event(0), event(45)])[0].session_id == sessions[0].session_id


def test_a_session_reports_its_span_and_size() -> None:
    (session,) = sessionize([event(0), event(4)])

    assert session.start == START
    assert session.end == START + timedelta(minutes=4)
    assert session.duration == timedelta(minutes=4)
    assert session.request_count == 2


def test_a_missing_user_agent_does_not_split_against_a_present_one_repeatedly() -> None:
    """Absent user agents are common; each absence must not look like a change."""
    sessions = sessionize([event(0, user_agent=None), event(1, user_agent=None)])

    assert len(sessions) == 1


def test_events_from_several_clients_are_grouped_per_client() -> None:
    sessions = sessionize([event(0, ip="1.1.1.1"), event(1, ip="2.2.2.2"), event(2, ip="1.1.1.1")])

    by_ip = {s.client_ip: s for s in sessions}
    assert set(by_ip) == {"1.1.1.1", "2.2.2.2"}
    assert by_ip["1.1.1.1"].request_count == 2


# -- naming what was reconstructed inside a window -------------------------


def test_without_a_window_a_session_is_named_exactly_as_it_always_was() -> None:
    """The contract that keeps every case and report already on disk valid.

    Written as a literal rather than derived, so a change to how names are built
    has to come here and be argued for, instead of quietly agreeing with itself.
    """
    sessions = sessionize([event(0), event(10)])

    assert [s.session_id for s in sessions] == ["203.0.113.5#1"]


def test_a_window_puts_its_own_name_on_the_session() -> None:
    """Two reconstructions of one client over two windows describe different
    things. Sharing a name, the reports would say so using the same identifiers
    and a folder holding both would have nothing in it to tell them apart."""
    window = TimeWindow(START, START + timedelta(minutes=30))

    sessions = sessionize([event(0), event(10)], window=window)

    assert [s.session_id for s in sessions] == [f"203.0.113.5@{window.tag}#1"]


def test_an_open_window_names_a_session_as_if_there_were_none() -> None:
    plain = sessionize([event(0), event(10)])
    open_window = sessionize([event(0), event(10)], window=EVERYTHING)

    assert [s.session_id for s in open_window] == [s.session_id for s in plain]


def test_the_window_in_a_name_reads_back_as_the_window_that_made_it() -> None:
    """An identifier that carries a range has to give it up again, or it says
    which report it belongs to without saying what that report covers."""
    window = TimeWindow(START, START + timedelta(minutes=30))

    session_id = sessionize([event(0)], window=window)[0].session_id

    _, _, tail = session_id.partition("@")
    assert TimeWindow.from_tag(tail.partition("#")[0]) == window
