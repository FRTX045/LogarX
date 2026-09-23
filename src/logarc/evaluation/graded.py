"""Grade Suspicious activity orderings by what an investigator should open first.

Grades come from the truth file alone, never from this tool's rules, so the
evaluation cannot agree with the tool merely because it shares its definitions:
2 for a client whose truth holds a targeted attack category, 1 for a client whose
hostile truth is only reconnaissance or enumeration, 0 for a client with none.

These measures sit beside the binary ones in `evaluation.triage`, which stay as
they are.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from math import log2
from statistics import mean
from typing import TYPE_CHECKING, Final

from logarc.triage.profile import TARGETED

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from logarc.evaluation.truth import TruthRecord

LOW_SUPPORT_MAX: Final = 5
"""Hostile truth requests at or below which a targeted client is low-support.

Frozen from the gap observed in the dataset builds (2 to 5 against 18 or more);
a cohort for these builds, not a universal threshold."""

TIERS: Final = (10, 25, 50)
"""Investigation budgets; a client's tier is the first one it falls within."""


@dataclass(frozen=True)
class ClientTruth:
    grade: int
    hostile: int
    """Requests whose truth category is hostile."""
    requests: int


def client_truth(
    records: Iterable[TruthRecord], exclusions: Mapping[str, str]
) -> dict[str, ClientTruth]:
    """One grade per judged client; excluded clients are left out, not called benign."""
    hostile: dict[str, int] = defaultdict(int)
    requests: dict[str, int] = defaultdict(int)
    targeted: set[str] = set()
    for record in records:
        if record.client_ip in exclusions:
            continue
        requests[record.client_ip] += 1
        if record.category.is_hostile:
            hostile[record.client_ip] += 1
        if record.category in TARGETED:
            targeted.add(record.client_ip)
    return {
        ip: ClientTruth(2 if ip in targeted else 1 if hostile[ip] else 0, hostile[ip], requests[ip])
        for ip in requests
    }


def low_support(truth: Mapping[str, ClientTruth]) -> frozenset[str]:
    return frozenset(
        ip for ip, item in truth.items() if item.grade == 2 and item.hostile <= LOW_SUPPORT_MAX
    )


def tier(rank: int | None) -> int:
    """0 within 10, 1 within 25, 2 within 50, 3 beyond or unranked."""
    if rank is None:
        return len(TIERS)
    return next((index for index, budget in enumerate(TIERS) if rank <= budget), len(TIERS))


@dataclass(frozen=True)
class GradedScores:
    judged: int
    targeted: int
    ranks: dict[str, int | None]
    """Every judged client's rank, None for a client the ordering does not contain."""
    yield_at: dict[int, float | None]
    """Targeted clients in the first k, per available slot: min(k, judged)."""
    recall_at: dict[int, float | None]
    benign_at: dict[int, int]
    mean_targeted_rank: float | None
    """An unranked targeted client counts as judged + 1: a penalty, not a position."""
    ndcg_at: dict[int, float | None]
    unranked_targeted: tuple[str, ...]


def graded_scores(order: Sequence[str], truth: Mapping[str, ClientTruth]) -> GradedScores:
    """Score one ordering of judged clients; undefined quantities are None."""
    if len(set(order)) != len(order):
        raise ValueError("a ranking must not repeat an IP")
    if any(ip not in truth for ip in order):
        raise ValueError("every ranked client needs an explicit relevance judgment")
    judged = len(truth)
    targeted = [ip for ip, item in truth.items() if item.grade == 2]
    position = {ip: index for index, ip in enumerate(order, 1)}
    ranks = {ip: position.get(ip) for ip in truth}
    ideal = sorted((item.grade for item in truth.values()), reverse=True)

    def found(k: int) -> int:
        return sum(truth[ip].grade == 2 for ip in order[:k])

    def ndcg(k: int) -> float | None:
        best = sum(grade / log2(index + 2) for index, grade in enumerate(ideal[:k]))
        if not best:
            return None
        gained = sum(truth[ip].grade / log2(index + 2) for index, ip in enumerate(order[:k]))
        return gained / best

    return GradedScores(
        judged=judged,
        targeted=len(targeted),
        ranks=ranks,
        yield_at={k: found(k) / min(k, judged) if judged else None for k in TIERS},
        recall_at={k: found(k) / len(targeted) if targeted else None for k in TIERS},
        benign_at={k: sum(truth[ip].grade == 0 for ip in order[:k]) for k in TIERS},
        mean_targeted_rank=(mean(ranks[ip] or judged + 1 for ip in targeted) if targeted else None),
        ndcg_at={k: ndcg(k) for k in TIERS},
        unranked_targeted=tuple(sorted(ip for ip in targeted if ranks[ip] is None)),
    )


_EPSILON: Final = 1e-12


def _mean(values: Iterable[float | None]) -> float:
    known = list(values)
    if any(value is None for value in known):
        raise ValueError("a measure the selection needs is undefined")
    return mean(value for value in known if value is not None)


def choose_graded(development: Mapping[str, Mapping[str, GradedScores]]) -> str:
    """C1 or C2, by the frozen order: higher mean targeted yield at 10 wins, then higher
    at 25, then lower mean of mean targeted rank, then C1."""
    if not development:
        raise ValueError("selection needs development builds")

    def measure(method: str) -> tuple[float, float, float]:
        builds = [scores[method] for scores in development.values()]
        return (
            round(_mean(s.yield_at[10] for s in builds), 12),
            round(_mean(s.yield_at[25] for s in builds), 12),
            -round(_mean(s.mean_targeted_rank for s in builds), 12),
        )

    c1, c2 = measure("c1"), measure("c2")
    return "c2" if c2 > c1 else "c1"


def graded_gate(
    baseline: Mapping[str, GradedScores],
    challenger: Mapping[str, GradedScores],
    low_support: Mapping[str, frozenset[str]],
) -> dict[str, object]:
    """The frozen held-out gate. All three must hold for the challenger to be promoted:
    mean targeted yield at 10 and 25 each no lower and one higher; no low-support targeted
    client in a worse tier in any build; benign clients at 10, 25 and 50 not more in any build.
    Every per-client rank change is returned whatever the result."""
    if (
        not baseline
        or baseline.keys() != challenger.keys()
        or baseline.keys() != low_support.keys()
    ):
        raise ValueError("the gate needs the same nonempty set of held-out builds")

    def yield_mean(side: Mapping[str, GradedScores], k: int) -> float:
        return _mean(scores.yield_at[k] for scores in side.values())

    deltas = {k: yield_mean(challenger, k) - yield_mean(baseline, k) for k in (10, 25)}
    head_yield = all(d >= -_EPSILON for d in deltas.values()) and any(
        d > _EPSILON for d in deltas.values()
    )
    tier_drops = {
        build: sorted(
            ip
            for ip in low_support[build]
            if tier(challenger[build].ranks[ip]) > tier(baseline[build].ranks[ip])
        )
        for build in baseline
    }
    benign_rises = {
        build: [k for k in TIERS if challenger[build].benign_at[k] > baseline[build].benign_at[k]]
        for build in baseline
    }
    checks = {
        "head_yield": head_yield,
        "low_support_tiers": not any(tier_drops.values()),
        "benign_head": not any(benign_rises.values()),
    }
    return {
        "promote": all(checks.values()),
        "checks": checks,
        "yield_deltas": deltas,
        "tier_drops": tier_drops,
        "benign_rises": benign_rises,
        "rank_changes": {
            build: {
                ip: (rank, challenger[build].ranks[ip])
                for ip, rank in baseline[build].ranks.items()
                if rank != challenger[build].ranks[ip]
            }
            for build in baseline
        },
    }
