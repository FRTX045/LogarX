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
    from collections.abc import Callable, Mapping, Sequence

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


GRADED_METHODS = ("policy3", "c1", "c2")
"""Today's shipped ordering and the two frozen challengers of the graded evaluation."""


def bonus_parts(profile: ClientProfile) -> tuple[int, int, float]:
    """The frozen bonuses: distinct high-confidence pairs (at most 3), a probe-then-attack
    session (at most 1), and recurrence (0.5 per hostile session after the first, at most 2).
    """
    return (
        min(3, profile.distinct_rule_pairs),
        1 if profile.sequence_sessions else 0,
        min(2.0, 0.5 * max(0, profile.hostile_sessions - 1)),
    )


def c1_score(profile: ClientProfile) -> float:
    return priority_score(profile) + sum(bonus_parts(profile))


def c2_score(profile: ClientProfile) -> float:
    """C1 with only the logarithmic support term capped at 31 hostile requests."""
    h, n = profile.hostile_requests, profile.requests
    return log2(1 + min(h, 31)) * (1 + profile.severity / 4) * (0.5 + 0.5 * h / n) + sum(
        bonus_parts(profile)
    )


def graded_orderings(profiles: Sequence[ClientProfile]) -> dict[str, list[str]]:
    """Today's order and both challengers over the same clients, with today's tie keys."""
    selected = [p for p in profiles if p.hostile_requests]
    scores = {"policy3": priority_score, "c1": c1_score, "c2": c2_score}

    def order(score: Callable[[ClientProfile], float]) -> list[str]:
        return [
            p.client_ip
            for p in sorted(
                selected,
                key=lambda p: (
                    -score(p),
                    -len(p.categories),
                    -p.hostile_targets,
                    -p.hostile_requests,
                    p.client_ip,
                ),
            )
        ]

    return {name: order(scores[name]) for name in GRADED_METHODS}


def assert_same_ranked(orders: Mapping[str, Sequence[str]]) -> None:
    """Orderings compared by the gate must differ in order only, never in who is ranked."""
    sets = {name: frozenset(order) for name, order in orders.items()}
    if len(set(sets.values())) > 1:
        raise ValueError(f"orderings do not rank the same clients: {sorted(sets)}")


def crs_placed(profile: ClientProfile) -> bool:
    """Whether the application put this client first on CRS paranoia level 1 evidence alone.

    Read from `exploit_rules`, because `hostile_rules` cannot tell a level 1
    detection from any other CRS label. `exploit_rules` names a `crs:` rule
    only when the client has no native exploit evidence.
    """
    return any(rule.startswith("crs:") for rule in profile.exploit_rules)


def exploit_orderings(
    profiles: Sequence[ClientProfile],
    *,
    category_rules: frozenset[str],
    eligible_rules: frozenset[str],
) -> dict[str, list[str]]:
    """Policy 3, the exploit-evidence-first order and the category-only comparator over the
    same clients, plus the order the application itself produces.

    `exploit_first` and `category_only` read each client's `hostile_rules`, the rule ids of
    every hostile label on its requests, rather than `exploit_examples`, so the
    application's native ordering is checked against a separate computation. `crs:` ids
    appear in `hostile_rules` but in neither rule set. `exploit_first` also puts first a
    client the application placed by CRS level 1 evidence (`crs_placed`), which only the
    profile records, so that part is not computed separately. `category_only` stays native.
    `category_rules` are the ids of the engine's attack-category rules and `eligible_rules`
    the same without the exclusions; both are required so neither can be defaulted.
    """
    selected = [p for p in profiles if p.hostile_requests]

    def order(group: Callable[[ClientProfile], int]) -> list[str]:
        return [
            p.client_ip
            for p in sorted(
                selected,
                key=lambda p: (
                    group(p),
                    -priority_score(p),
                    -len(p.categories),
                    -p.hostile_targets,
                    -p.hostile_requests,
                    p.client_ip,
                ),
            )
        ]

    return {
        "policy3": order(lambda p: 0),
        "exploit_first": order(
            lambda p: 0 if crs_placed(p) or any(r in eligible_rules for r in p.hostile_rules) else 1
        ),
        "category_only": order(
            lambda p: 0 if any(r in category_rules for r in p.hostile_rules) else 1
        ),
        "app": [row.profile.client_ip for row in rank_profiles(selected, "suspicious")],
    }
