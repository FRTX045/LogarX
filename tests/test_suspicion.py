"""Ordering the client list by where an investigator should start.

Two things constrain this more than the formula does.

It has to be cheap. `IpSummary` is computed once at ingest precisely so that
choosing a client never scans the store, and a ranking that ran detection over
a hundred thousand clients to sort them would undo the whole two-pass design.
So the score is built only from what the summary already carries.

And it has to explain itself. A reader must be able to see why this client is
third and that one is tenth; a ranking nobody can account for is one nobody
should act on, and in a forensic tool it is worse than no ranking at all. Every
score here carries the reasons that made it.

It orders a worklist. It does not decide guilt.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from logarc.storage.base import IpSummary
from logarc.suspicion import explain

START = datetime(2026, 3, 9, 9, 0, tzinfo=UTC)


def summary(
    ip: str = "203.0.113.5",
    *,
    requests: int = 100,
    paths: int = 80,
    errors: float = 0.0,
    minutes: int = 60,
) -> IpSummary:
    return IpSummary(
        client_ip=ip,
        request_count=requests,
        first_seen=START,
        last_seen=START + timedelta(minutes=minutes),
        distinct_paths=paths,
        client_error_ratio=errors,
        bytes_total=requests * 512,
    )


def names(item: IpSummary) -> set[str]:
    return {reason.name for reason in explain(item).reasons}


# -- what scores ----------------------------------------------------------


def test_an_ordinary_visitor_scores_nothing() -> None:
    """Most clients in most cases. A ranking where everyone scores is a
    ranking that orders nothing."""
    ranked = explain(summary(requests=100, paths=80, errors=0.0))

    assert ranked.points == 0
    assert ranked.reasons == ()


def test_refused_requests_are_the_strongest_signal() -> None:
    """Measured on the committed excerpt: every client with any 4xx at all was
    hostile in the truth, bar one at 2%."""
    ranked = explain(summary(requests=100, paths=90, errors=1.0))

    assert "refusals" in names(ranked.summary)
    assert ranked.points >= 2.0


def test_asking_for_the_same_few_pages_over_and_over_scores() -> None:
    """The signal that catches a client with no 4xx at all.

    On the excerpt this is the one that finds `192.0.2.31` — an sqlmap run
    against a single search endpoint, answered 200 every time, which the
    refusal signal cannot see.
    """
    ranked = explain(summary(requests=100, paths=2, errors=0.0))

    assert "repetition" in names(ranked.summary)


def test_a_browser_revisiting_pages_does_not_score_for_repetition() -> None:
    """The threshold's whole job. Real visitors on the excerpt sit between 0.37
    and 1.00 distinct paths per request — they revisit, and that is shopping."""
    ranked = explain(summary(requests=100, paths=45, errors=0.0))

    assert "repetition" not in names(ranked.summary)


def test_a_client_with_too_few_requests_is_not_judged_on_repetition() -> None:
    """One request for one page is a ratio of 1.0 and means nothing; three
    requests for one page is not yet a pattern."""
    ranked = explain(summary(requests=3, paths=1, errors=0.0))

    assert "repetition" not in names(ranked.summary)


# -- what it must not become ---------------------------------------------


def test_every_score_carries_its_reasons() -> None:
    """A ranking nobody can account for is one nobody should act on."""
    ranked = explain(summary(requests=200, paths=4, errors=0.8))

    assert ranked.points > 0
    assert ranked.reasons
    assert sum(reason.points for reason in ranked.reasons) == ranked.points
    for reason in ranked.reasons:
        assert reason.because, f"{reason.name} scores without saying why"


def test_the_reasons_are_written_for_a_reader_not_a_formula() -> None:
    """The sentence beside the number is the part that gets acted on."""
    ranked = explain(summary(requests=100, paths=90, errors=0.75))

    (refusals,) = [r for r in ranked.reasons if r.name == "refusals"]
    assert "75%" in refusals.because
    assert "refused" in refusals.because or "missing" in refusals.because


def test_nothing_here_calls_a_client_an_attacker() -> None:
    """It orders a worklist. Whatever the score, the wording stays a
    description of what was counted."""
    ranked = explain(summary(requests=500, paths=2, errors=1.0))

    wording = " ".join(reason.because for reason in ranked.reasons).lower()
    for verdict in ("attacker", "malicious", "hostile", "intruder", "guilty"):
        assert verdict not in wording, f"the reasons pass judgement: {wording}"
