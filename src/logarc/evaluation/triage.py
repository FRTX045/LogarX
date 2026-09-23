"""Compare investigation queues against explicit, separate relevance judgments.

Isolation Forest is an optional local experiment. Nothing in the GUI imports
this module or uses the model's scores as probabilities of malicious activity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import log1p
from statistics import median
from typing import TYPE_CHECKING, Any

from logarc.triage.profile import DEFAULT_POLICY, FEATURES, comparable, rank_profiles

BUDGETS = (10, 25, 50, 100, 250)
MODEL_SEEDS = (7, 19, 42, 73, 101)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from logarc.triage.profile import ClientProfile, TriagePolicy


@dataclass(frozen=True)
class BudgetScore:
    budget: int
    reviewed: int
    relevant: int
    precision: float | None
    recall: float | None
    yield_per_slot: float | None


def budget_scores(
    order: Sequence[str],
    judgments: Mapping[str, bool],
    *,
    budgets: tuple[int, ...] = BUDGETS,
) -> tuple[BudgetScore, ...]:
    """Measure observed prefixes; absence of positive truth makes recall unknown."""
    if len(set(order)) != len(order):
        raise ValueError("a ranking must not repeat an IP")
    if any(ip not in judgments for ip in order):
        raise ValueError("every ranked client needs an explicit relevance judgment")
    if any(budget < 1 for budget in budgets):
        raise ValueError("investigation budgets must be positive")
    positives = sum(judgments.values())
    scores = []
    for budget in budgets:
        prefix = order[:budget]
        found = sum(judgments[ip] for ip in prefix)
        scores.append(
            BudgetScore(
                budget,
                len(prefix),
                found,
                found / len(prefix) if prefix else None,
                found / positives if positives else None,
                found / min(budget, len(judgments)) if judgments else None,
            )
        )
    return tuple(scores)


@dataclass(frozen=True)
class ModelRanking:
    status: str
    order: tuple[str, ...] = ()
    scores: tuple[float, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


def isolation_order(
    profiles: Sequence[ClientProfile],
    policy: TriagePolicy = DEFAULT_POLICY,
    *,
    random_state: int = 42,
) -> ModelRanking:
    """Fit this case's eligible clients; lower raw scores mean more unusual."""
    eligible = [p for p in profiles if p.requests >= policy.minimum_requests]
    if len(eligible) < policy.minimum_model_population:
        return ModelRanking("insufficient population")
    try:
        import sklearn
        from sklearn.ensemble import IsolationForest
    except ImportError:
        return ModelRanking("dependency unavailable: install the evaluation extra")

    columns: list[list[float]] = []
    names: list[str] = []
    medians: dict[str, float] = {}
    count_features = {"requests", "peak_per_minute", "bytes_total", "bytes_mean"}
    for metric in FEATURES:
        values = [p.features[metric] if comparable(p, metric, policy) else None for p in eligible]
        known = [v for v in values if v is not None]
        if len(known) < policy.minimum_population:
            continue
        fill = medians[metric] = median(known)
        filled = [fill if value is None else value for value in values]
        if metric in count_features:
            filled = [log1p(max(value, 0)) for value in filled]
        if len(set(filled)) > 1:
            names.append(metric)
            columns.append(filled)
        missing = [float(value is None) for value in values]
        if len(set(missing)) > 1:
            names.append(f"{metric}:missing")
            columns.append(missing)
    metadata: dict[str, Any] = {
        "sklearn_version": sklearn.__version__,
        "features": names,
        "log1p_features": sorted(count_features.intersection(names)),
        "median_imputation": medians,
        "random_state": random_state,
        "n_estimators": 200,
        "max_samples": min(256, len(eligible)),
        "contamination": "auto",
        "population": len(eligible),
        "score_direction": "lower is more unusual",
        "baseline": "current case; not assumed benign",
    }
    if not columns:
        return ModelRanking("no varying features", metadata=metadata)
    matrix = list(zip(*columns, strict=True))
    model = IsolationForest(
        n_estimators=200,
        max_samples=min(256, len(eligible)),
        contamination="auto",
        random_state=random_state,
        n_jobs=1,
    )
    model.fit(matrix)
    scores = tuple(float(score) for score in model.score_samples(matrix))
    indices = sorted(range(len(eligible)), key=lambda i: (scores[i], eligible[i].client_ip))
    return ModelRanking(
        "complete",
        tuple(eligible[i].client_ip for i in indices),
        tuple(scores[i] for i in indices),
        metadata,
    )


@dataclass(frozen=True)
class RankingEvaluation:
    population: int
    positives: int
    base_rate: float | None
    eligible: int
    eligible_positives: int
    excluded: int
    excluded_positives: int
    maximum_recall: float | None
    returned: int
    quiet_positives: int
    quiet_recall_at_50: float | None
    budgets: tuple[BudgetScore, ...]
    recall_curve: tuple[float | None, ...]
    head: tuple[str, ...]
    false_recommendations: tuple[str, ...]
    status: str = "complete"


@dataclass(frozen=True)
class EvaluationReport:
    provenance: dict[str, str]
    comparisons: dict[str, dict[str, dict[str, RankingEvaluation]]]
    models: dict[str, dict[str, dict[str, Any]]]


def evaluate_order(
    order: Sequence[str],
    judgments: Mapping[str, bool],
    *,
    eligible: set[str],
    quiet: set[str],
    status: str = "complete",
) -> RankingEvaluation:
    """Keep eligibility ceilings distinct from actual returned-client recall."""
    if not set(order) <= eligible <= judgments.keys():
        raise ValueError("ranked and eligible clients must belong to the judged population")
    budgets = budget_scores(order, judgments) if status == "complete" else ()
    positives = sum(judgments.values())
    eligible_positives = sum(judgments[ip] for ip in eligible)
    quiet_positive = {ip for ip in quiet if judgments[ip]}
    found = 0
    curve = []
    for ip in order:
        found += judgments[ip]
        curve.append(found / positives if positives else None)
    return RankingEvaluation(
        len(judgments),
        positives,
        positives / len(judgments) if judgments else None,
        len(eligible),
        eligible_positives,
        len(judgments) - len(eligible),
        positives - eligible_positives,
        eligible_positives / positives if positives else None,
        len(order),
        len(quiet_positive),
        len(quiet_positive.intersection(order[:50])) / len(quiet_positive)
        if quiet_positive and status == "complete"
        else None,
        budgets,
        tuple(curve),
        tuple(order[: max(BUDGETS)]),
        tuple(ip for ip in order[: max(BUDGETS)] if not judgments[ip]),
        status,
    )


def compare_rankings(
    profiles: Sequence[ClientProfile],
    *,
    suspicious: Mapping[str, bool],
    unusual: Mapping[str, bool] | None = None,
    provenance: Mapping[str, str],
    include_model: bool = True,
    model_seeds: tuple[int, ...] = MODEL_SEEDS,
) -> EvaluationReport:
    """Keep security truth separate from judgments of useful unusual activity.

    Missing unusual judgments omit that evaluation rather than reusing attack
    labels. A partial judgment set is rejected rather than treating unreviewed
    clients as negatives. Model metadata is available from `isolation_order`.
    """
    from logarc.evaluation.priorities import suspicious_candidates, unusual_candidates

    clients = {p.client_ip for p in profiles}
    if len(clients) != len(profiles):
        raise ValueError("profiles must contain unique client IPs")
    goals = {"suspicious": suspicious}
    if unusual is not None:
        goals["unusual"] = unusual
    if any(set(judgments) != clients for judgments in goals.values()):
        raise ValueError("each goal needs an explicit judgment for every client")
    if set(provenance) != set(goals) or not all(value.strip() for value in provenance.values()):
        raise ValueError("each judgment goal needs explicit provenance")
    populations = {
        "operational": list(profiles),
        "matched": [p for p in profiles if comparable(p, "4xx_share", DEFAULT_POLICY)],
    }
    comparisons = {}
    models: dict[str, dict[str, dict[str, Any]]] = {}
    for population_name, population in populations.items():
        population_ips = {p.client_ip for p in population}
        quiet = {p.client_ip for p in population if p.requests < DEFAULT_POLICY.minimum_requests}
        statistical = population_ips - quiet
        hostile = {p.client_ip for p in population if p.hostile_requests}
        orders = {
            "requests": [r.profile.client_ip for r in rank_profiles(population, "all")],
            "errors": [
                p.client_ip
                for p in sorted(
                    (
                        p
                        for p in population
                        if p.coverage.get("status", 0) and "4xx_share" in p.features
                    ),
                    key=lambda p: (-p.features["4xx_share"], p.client_ip),
                )
            ],
            **suspicious_candidates(population),
            **unusual_candidates(population),
        }
        eligible = {
            name: (
                hostile
                if name in ("suspicious", "support", "weighted", "share")
                else statistical
                if name in ("statistics", "group_sum", "group_top2")
                else set(order)
            )
            for name, order in orders.items()
        }
        statuses = {
            name: "complete"
            if len(statistical) >= DEFAULT_POLICY.minimum_population
            else "insufficient population"
            for name in ("statistics", "group_sum", "group_top2")
        }
        models[population_name] = {}
        if include_model:
            for seed in model_seeds:
                model = isolation_order(population, random_state=seed)
                name = "isolation_forest" if seed == 42 else f"isolation_forest_{seed}"
                orders[name] = list(model.order)
                eligible[name] = statistical
                statuses[name] = model.status
                models[population_name][name] = {"status": model.status, **model.metadata}
        comparisons[population_name] = {
            goal: {
                name: evaluate_order(
                    order,
                    {ip: judgments[ip] for ip in population_ips},
                    eligible=eligible[name],
                    quiet=quiet,
                    status=statuses.get(name, "complete"),
                )
                for name, order in orders.items()
            }
            for goal, judgments in goals.items()
        }
    return EvaluationReport(dict(provenance), comparisons, models)
