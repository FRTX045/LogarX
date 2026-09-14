"""Where an investigator should start, and why.

The client list is ordered by request count by default, and the busiest client
is very often not the one worth looking at first. This orders it by how far a
client departs from what ordinary traffic does — and, more importantly, says
what the departure was.

**Built only from `IpSummary`.** That summary is computed once at ingest so
that choosing a client never scans the store; a ranking that ran the detection
engine over a hundred thousand clients in order to sort them would undo the
two-pass design it sits inside. Everything here is arithmetic over columns that
already exist, which is also why the same score can be expressed in SQL and
done by the store.

**It orders a worklist. It does not decide guilt.** The wording of every reason
is held to that by a test: these sentences say what was counted, never what the
client is.

## Why these two signals, and not the ones that seemed obvious

Measured 2026-09-15 against the committed excerpt, whose truth says which of
its 52 clients were hostile (11 of them):

- **Refusals carry almost all of it.** Every client with any 4xx at all was
  hostile in the truth, bar one at 2%. Ordering on refusals alone puts 9 of the
  top 10 right.
- **Repetition finds the one refusals cannot.** `192.0.2.31` is an sqlmap run
  against a single search endpoint, answered 200 every time — invisible to the
  first signal, and obvious in the second at 0.02 distinct paths per request.
- **Request rate was measured and dropped.** It is anti-correlated here: the
  three fastest clients in the excerpt (120, 100 and 76 requests a minute) are
  all ordinary visitors, while the most prolific attacker in it managed 0.1 a
  minute over six days. Speed is a property of the network, not of intent.
- **"Many distinct paths" was measured and dropped**, and it is worth saying
  why, because it is the intuitive one: a wordlist walk *sounds* like it should
  touch many paths. In this corpus the opposite holds. Attackers hammered a few
  endpoints (0.02 to 0.43 distinct paths per request) and shoppers browsed widely
  (0.37 to 1.00). The intuition was backwards and the data said so.

Ordering by request count puts 2 of the top 5 right. This puts 5 of 5, and 10
of the top 10.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from logarc.storage.base import IpSummary

__all__ = ["MIN_REQUESTS_FOR_REPETITION", "REPETITION_FLOOR", "Ranked", "Reason", "explain", "rank"]

#: Weight on the share of refused requests. Twice the repetition weight because
#: it is measurably the stronger signal, not because two is a round number.
_REFUSAL_WEIGHT: Final = 2.0

#: How repetitive a client has to be before it counts: two thirds, which reads
#: as "asked for the same page three times over on average".
#:
#: Chosen for having a plain meaning rather than by fitting. It is also not on a
#: knife edge — 0.75 scores identically on the excerpt (P@10 of 10/10 either
#: way), while dropping to 0.5 admits ordinary shoppers and costs two of them.
REPETITION_FLOOR: Final = 2 / 3

#: Below this, the ratio is noise. One request for one page is a ratio of 1.0
#: and means nothing at all.
MIN_REQUESTS_FOR_REPETITION: Final = 20


@dataclass(frozen=True, slots=True)
class Reason:
    """One thing that put a client up the list."""

    name: str
    points: float
    because: str
    """The sentence a reader acts on. Says what was counted, never what the
    client is — a ranking that passes judgement is one that has stopped being
    a worklist."""


@dataclass(frozen=True, slots=True)
class Ranked:
    """A client, its place in the order, and what put it there."""

    summary: IpSummary
    points: float
    reasons: tuple[Reason, ...]


def explain(summary: IpSummary) -> Ranked:
    """Score one client and say what the score is made of."""
    reasons: list[Reason] = []

    if summary.client_error_ratio > 0:
        share = summary.client_error_ratio
        reasons.append(
            Reason(
                name="refusals",
                points=_REFUSAL_WEIGHT * share,
                because=(
                    f"{share:.0%} of its requests were refused or missing — "
                    f"it asked for things that were not there."
                ),
            )
        )

    if summary.request_count >= MIN_REQUESTS_FOR_REPETITION:
        repetition = 1.0 - (summary.distinct_paths / summary.request_count)
        if repetition > REPETITION_FLOOR:
            per_path = summary.request_count / max(summary.distinct_paths, 1)
            reasons.append(
                Reason(
                    name="repetition",
                    points=repetition,
                    because=(
                        f"{summary.request_count:,} requests across only "
                        f"{summary.distinct_paths:,} "
                        f"{'page' if summary.distinct_paths == 1 else 'pages'} — "
                        f"{per_path:.0f} times each on average."
                    ),
                )
            )

    return Ranked(
        summary=summary,
        points=sum(reason.points for reason in reasons),
        reasons=tuple(reasons),
    )


def rank(summaries: Iterable[IpSummary]) -> list[Ranked]:
    """Every client, most worth looking at first.

    Ties keep the order they arrived in, which is the store's — so a case read
    twice lists the same way.
    """
    scored = [explain(item) for item in summaries]
    return sorted(scored, key=lambda item: -item.points)


def ordering_sql() -> str:
    """The same score, for the store to sort by without loading every client.

    Kept beside the Python so the two cannot drift apart unnoticed: a case of a
    hundred thousand clients is ordered by this expression, and the reasons
    shown beside the rows that come back are computed by `explain` from the same
    fields. If these ever disagreed, the list would be sorted by one rule and
    annotated by another.
    """
    repetition = "(1.0 - CAST(distinct_paths AS DOUBLE) / request_count)"
    return (
        f"({_REFUSAL_WEIGHT} * client_error_ratio + "
        f"CASE WHEN request_count >= {MIN_REQUESTS_FOR_REPETITION} "
        f"AND {repetition} > {REPETITION_FLOOR} THEN {repetition} ELSE 0 END) DESC, "
        f"request_count DESC"
    )


def as_sentences(ranked: Ranked) -> Sequence[str]:
    """The reasons as lines, for a report or a tooltip."""
    return [reason.because for reason in ranked.reasons]
