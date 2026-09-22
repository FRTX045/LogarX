"""Fixed ranking experiments and predeclared promotion checks, never GUI controls."""

from __future__ import annotations

from collections import Counter
from math import log2
from statistics import mean
from typing import TYPE_CHECKING, Any

from logarc.triage.profile import (
    DEFAULT_POLICY,
    FEATURES,
    comparable,
    priority_score,
    rank_profiles,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from logarc.triage.profile import ClientProfile, RankedClient

CANDIDATES = ("support", "weighted", "share")
GROUPS = (
    ("requests", "bytes_total"),
    ("peak_per_minute",),
    ("distinct_path_share", "target_concentration"),
    ("4xx_share", "5xx_share", "bytes_mean"),
)


def suspicious_candidates(profiles: Sequence[ClientProfile]) -> dict[str, list[str]]:
    """Compare the agreed formulas without changing detection or eligibility."""
    selected = [p for p in profiles if p.hostile_requests]

    def key(p: ClientProfile, method: str) -> tuple[float, int, int, int, str]:
        if method == "support":
            return (
                -p.hostile_requests,
                -len(p.categories),
                -p.severity,
                -p.hostile_targets,
                p.client_ip,
            )
        score = (
            priority_score(p)
            if method == "share"
            else log2(1 + p.hostile_requests) * (1 + p.severity / 4)
        )
        return (-score, -len(p.categories), -p.hostile_targets, -p.hostile_requests, p.client_ip)

    return {
        "suspicious": [
            p.client_ip
            for p in sorted(
                selected,
                key=lambda p: (
                    -p.severity,
                    -len(p.categories),
                    -p.hostile_targets,
                    -p.hostile_requests,
                    p.client_ip,
                ),
            )
        ],
        **{
            name: [p.client_ip for p in sorted(selected, key=lambda p: key(p, name))]
            for name in CANDIDATES
        },
    }


def _vector(row: RankedClient) -> tuple[float, ...]:
    return tuple(r.percentile or 0 for r in row.reasons) + (0.0,) * (
        len(FEATURES) - len(row.reasons)
    )


def unusual_candidates(profiles: Sequence[ClientProfile]) -> dict[str, list[str]]:
    """Aggregate measured deviations; an unavailable field supplies no deviation."""
    rows = rank_profiles(profiles, "unusual")

    def key(row: RankedClient, strongest: int) -> tuple[float, tuple[float, ...], str]:
        deviations = {r.metric: max(0, 2 * (r.percentile or 0) - 1) for r in row.reasons}
        groups = sorted(
            (max((deviations[m] for m in group if m in deviations), default=0) for group in GROUPS),
            reverse=True,
        )
        return (-sum(groups[:strongest]), tuple(-v for v in groups), row.profile.client_ip)

    return {
        "statistics": [r.profile.client_ip for r in rows],
        "group_sum": [r.profile.client_ip for r in sorted(rows, key=lambda r: key(r, 4))],
        "group_top2": [r.profile.client_ip for r in sorted(rows, key=lambda r: key(r, 2))],
    }


def audit_unusual(profiles: Sequence[ClientProfile]) -> dict[str, Any]:
    """Count exact ranking ties separately from ties on individual bounded fields."""
    rows = rank_profiles(profiles, "unusual")
    counts = Counter(_vector(row) for row in rows)
    positions: dict[tuple[float, ...], list[int]] = {}
    for position, row in enumerate(rows, 1):
        positions.setdefault(_vector(row), []).append(position)
    budgets = (10, 25, 50, 100, 250)
    return {
        "ranked": len(rows),
        "complete_vector_tie_groups": sum(count > 1 for count in counts.values()),
        "largest_vector_tie": max(counts.values(), default=0),
        "ip_dependent_positions": {
            str(k): sum(counts[_vector(row)] > 1 for row in rows[:k]) for k in budgets
        },
        "boundary_ties": {
            str(k): sum(group[0] <= k < group[-1] for group in positions.values()) for k in budgets
        },
        "ceiling_ties": {
            metric: sum(
                comparable(p, metric, DEFAULT_POLICY) and p.features[metric] == 1 for p in profiles
            )
            for metric in ("distinct_path_share", "target_concentration", "4xx_share", "5xx_share")
        },
        "comparable_by_feature": {
            metric: sum(comparable(p, metric, DEFAULT_POLICY) for p in profiles)
            for metric in FEATURES
        },
    }


def promotion_gate(
    baseline: Mapping[str, Mapping[str, float | None]],
    challenger: Mapping[str, Mapping[str, float | None]],
) -> dict[str, Any]:
    """Apply the agreed held-out gate once; absent quiet truth cannot prove safety."""
    if not baseline or baseline.keys() != challenger.keys():
        raise ValueError("promotion needs the same nonempty set of held-out cases")

    def delta(metric: str) -> float | None:
        pairs = [(baseline[case][metric], challenger[case][metric]) for case in baseline]
        if any(a is None or b is None for a, b in pairs):
            return None
        return mean(float(b) - float(a) for a, b in pairs if a is not None and b is not None)

    deltas = {metric: delta(metric) for metric in ("yield10", "yield25", "yield50", "quiet50")}
    checks = {
        "head_gain_10": deltas["yield10"] is not None and deltas["yield10"] >= 0.10 - 1e-12,
        "yield_25": deltas["yield25"] is not None and deltas["yield25"] >= -1e-12,
        "yield_50": deltas["yield50"] is not None and deltas["yield50"] >= -1e-12,
        "quiet_recall_50": deltas["quiet50"] is not None and deltas["quiet50"] >= -1e-12,
        "per_case_head_loss": all(
            a is not None and b is not None and b >= a - 1
            for a, b in (
                (baseline[case]["hits10"], challenger[case]["hits10"]) for case in baseline
            )
        ),
    }
    return {"promote": all(checks.values()), "checks": checks, "mean_deltas": deltas}


def choose_challenger(cases: Mapping[str, Mapping[str, Mapping[str, float | None]]]) -> str:
    """Choose from development cases only, using the declared metric and tie order."""
    if not cases:
        raise ValueError("candidate selection needs development cases")

    def value(name: str, metric: str) -> float:
        values = [case[name][metric] for case in cases.values()]
        if metric != "quiet50" and any(v is None for v in values):
            raise ValueError("development yield is unavailable")
        known = [v for v in values if v is not None]
        return mean(known) if known else -1

    return max(
        CANDIDATES,
        key=lambda name: (
            (value(name, "yield10") + value(name, "yield25")) / 2,
            value(name, "yield50"),
            value(name, "quiet50"),
            -CANDIDATES.index(name),
        ),
    )
