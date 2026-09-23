"""Compact client measurements and deterministic investigation queues."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from itertools import islice
from math import log2
from typing import TYPE_CHECKING, Literal

from logarc.analysis import label_sessions
from logarc.core.activity import Severity
from logarc.core.evidence import EvidenceRef

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.event import NormalizedEvent
    from logarc.detect.crs import DetectionIndex
    from logarc.detect.engine import RuleEngine
    from logarc.sessionize.segmenter import SessionPolicy

QueueName = Literal["suspicious", "unusual", "all"]
FEATURES = {
    "requests": "Requests",
    "peak_per_minute": "Peak requests in 60 seconds",
    "distinct_path_share": "Distinct paths per recorded path",
    "target_concentration": "Share at the most requested path",
    "4xx_share": "4xx share of recorded statuses",
    "5xx_share": "5xx share of recorded statuses",
    "bytes_total": "Recorded response bytes",
    "bytes_mean": "Mean recorded response bytes",
}
SAMPLE_SIZE = 5


@dataclass(frozen=True)
class TriagePolicy:
    minimum_requests: int = 20
    minimum_population: int = 30
    minimum_model_population: int = 100
    version: int = 3


DEFAULT_POLICY = TriagePolicy()


@dataclass(frozen=True)
class PriorityReason:
    text: str
    evidence: tuple[EvidenceRef, ...]
    metric: str = ""
    value: float | None = None
    percentile: float | None = None
    population: int = 0


@dataclass(frozen=True)
class ClientProfile:
    client_ip: str
    requests: int
    severity: int
    categories: tuple[str, ...]
    hostile_targets: int
    hostile_requests: int
    features: dict[str, float]
    coverage: dict[str, int]
    evidence: dict[str, tuple[EvidenceRef, ...]]
    reasons: tuple[PriorityReason, ...] = ()
    statuses: dict[str, int] = field(default_factory=dict)
    rules_matched: dict[str, int] = field(default_factory=dict)
    """Requests each rule matched, whether or not its label was the one kept.

    A scanner's enumeration is labelled `scanner_user_agent`, which outranks
    `directory_enumeration` on confidence. Asked who else enumerated, counting
    only the labels kept would leave that scanner out of the answer.
    """
    rules_won: dict[str, int] = field(default_factory=dict)
    """Requests each rule named: the label a reconstruction shows for them."""


@dataclass(frozen=True)
class RankedClient:
    profile: ClientProfile
    reasons: tuple[PriorityReason, ...]
    rank: int = 0


def profile_client(
    events: Sequence[NormalizedEvent],
    engine: RuleEngine,
    *,
    crs: DetectionIndex | None = None,
    session_policy: SessionPolicy | None = None,
) -> ClientProfile:
    """Measure one client; preserve sampled witnesses, never infer compromise."""
    if not events:
        raise ValueError("a client profile needs events")
    ordered = sorted(events, key=lambda e: (e.timestamp, e.evidence.line_no))
    if any(e.client_ip != ordered[0].client_ip for e in ordered):
        raise ValueError("a client profile must contain one IP")
    categories: dict[str, list[EvidenceRef]] = {}
    category_counts: Counter[str] = Counter()
    category_severity: dict[str, int] = {}
    hostile_targets: set[str] = set()
    rules_matched: Counter[str] = Counter()
    rules_won: Counter[str] = Counter()
    severity = hostile_requests = 0
    for _, labelled in label_sessions(ordered, engine, policy=session_policy, crs=crs):
        for item in labelled:
            rules_won[item.label.rule_id] += 1
            # The label is added because it is not always in `all_labels`: a
            # request nothing matched is named by the fallback alone. A set,
            # because a rule listed twice is still one match on one request.
            rules_matched.update(
                {label.rule_id for label in item.all_labels} | {item.label.rule_id}
            )
            hostile = [label for label in item.all_labels if label.category.is_hostile]
            if not hostile:
                continue
            hostile_requests += 1
            severity = max(severity, *(int(label.severity) for label in hostile))
            if item.event.path is not None:
                hostile_targets.add(item.event.path)
            for category in {label.category.value for label in hostile}:
                category_counts[category] += 1
                strongest = max(
                    int(label.severity) for label in hostile if label.category.value == category
                )
                if strongest > category_severity.get(category, -1):
                    category_severity[category] = strongest
                    categories[category] = []
                refs = categories.setdefault(category, [])
                if strongest == category_severity[category] and len(refs) < SAMPLE_SIZE:
                    refs.append(item.event.evidence)

    paths = [e for e in ordered if e.path is not None]
    statuses = [e for e in ordered if e.status is not None]
    sizes = [e for e in ordered if e.bytes_sent is not None]
    coverage = {"path": len(paths), "status": len(statuses), "bytes_sent": len(sizes)}
    features: dict[str, float] = {"requests": float(len(ordered))}
    evidence = {"requests": tuple(e.evidence for e in ordered[:SAMPLE_SIZE])}
    left = peak = peak_start = 0
    for right, event in enumerate(ordered):
        while event.timestamp - ordered[left].timestamp >= timedelta(seconds=60):
            left += 1
        if right - left + 1 > peak:
            peak, peak_start = right - left + 1, left
    features["peak_per_minute"] = float(peak)
    evidence["peak_per_minute"] = tuple(
        e.evidence for e in ordered[peak_start : peak_start + min(peak, SAMPLE_SIZE)]
    )
    if paths:
        counts = Counter(e.path for e in paths)
        target, count = counts.most_common(1)[0]
        features["distinct_path_share"] = len(counts) / len(paths)
        features["target_concentration"] = count / len(paths)
        witnesses: dict[str | None, EvidenceRef] = {}
        for event in paths:
            witnesses.setdefault(event.path, event.evidence)
            if len(witnesses) == SAMPLE_SIZE:
                break
        evidence["distinct_path_share"] = tuple(witnesses.values())
        evidence["target_concentration"] = tuple(
            islice(
                (e.evidence for e in paths if e.path == target),
                SAMPLE_SIZE,
            )
        )
    if statuses:
        for name, lower in (("4xx_share", 400), ("5xx_share", 500)):
            matching = [
                e for e in statuses if e.status is not None and lower <= e.status < lower + 100
            ]
            features[name] = len(matching) / len(statuses)
            evidence[name] = tuple(e.evidence for e in matching[:SAMPLE_SIZE])
    if sizes:
        total = sum(e.bytes_sent for e in sizes if e.bytes_sent is not None)
        features["bytes_total"] = float(total)
        features["bytes_mean"] = total / len(sizes)
        largest = sorted(sizes, key=lambda e: e.bytes_sent or 0, reverse=True)[:SAMPLE_SIZE]
        evidence["bytes_total"] = evidence["bytes_mean"] = tuple(e.evidence for e in largest)
    return ClientProfile(
        ordered[0].client_ip,
        len(ordered),
        severity,
        tuple(sorted(categories)),
        len(hostile_targets),
        hostile_requests,
        features,
        coverage,
        evidence,
        tuple(
            PriorityReason(
                f"{category.replace('_', ' ').capitalize()} indicators on {category_counts[category]:,} "
                f"{'request' if category_counts[category] == 1 else 'requests'}; "
                f"strongest {Severity(category_severity[category]).name.lower()}",
                tuple(categories[category]),
            )
            for category in sorted(
                categories, key=lambda c: (-category_severity[c], -category_counts[c], c)
            )
        ),
        dict(sorted(Counter(str(e.status) for e in statuses).items())),
        dict(sorted(rules_matched.items())),
        dict(sorted(rules_won.items())),
    )


def comparable(profile: ClientProfile, metric: str, policy: TriagePolicy) -> bool:
    """Require enough observed values for each compared feature, including ratios."""
    field_name = {
        "distinct_path_share": "path",
        "target_concentration": "path",
        "4xx_share": "status",
        "5xx_share": "status",
        "bytes_total": "bytes_sent",
        "bytes_mean": "bytes_sent",
    }.get(metric)
    return (
        profile.requests >= policy.minimum_requests
        and metric in profile.features
        and (field_name is None or profile.coverage.get(field_name, 0) >= policy.minimum_requests)
    )


def priority_score(profile: ClientProfile) -> float:
    """Balance hostile support, severity and share for a nonempty client profile."""
    return (
        log2(1 + profile.hostile_requests)
        * (1 + profile.severity / 4)
        * (0.5 + 0.5 * profile.hostile_requests / profile.requests)
    )


def rank_profiles(
    profiles: Sequence[ClientProfile],
    queue: QueueName,
    policy: TriagePolicy = DEFAULT_POLICY,
) -> list[RankedClient]:
    """Rank the complete population before the interface applies a page limit."""
    if queue == "all":
        return [
            RankedClient(p, p.reasons)
            for p in sorted(profiles, key=lambda p: (-p.requests, p.client_ip))
        ]
    if queue == "suspicious":
        selected = sorted(
            (p for p in profiles if p.hostile_requests),
            key=lambda p: (
                -priority_score(p),
                -len(p.categories),
                -p.hostile_targets,
                -p.hostile_requests,
                p.client_ip,
            ),
        )
        ranked = []
        for profile in selected:
            evidence = tuple(
                dict.fromkeys(ref for reason in profile.reasons for ref in reason.evidence)
            )[:SAMPLE_SIZE]
            support = PriorityReason(
                f"{profile.hostile_requests:,} of {profile.requests:,} requests have hostile detections "
                f"({profile.hostile_requests / profile.requests:.0%}); strongest severity "
                f"{Severity(profile.severity).name.lower()}. Priority balances support, severity and share.",
                evidence,
            )
            ranked.append(RankedClient(profile, (support, *profile.reasons)))
        return ranked
    if queue != "unusual":
        raise ValueError(f"unknown investigation queue: {queue}")
    populations = {
        metric: sorted(p.features[metric] for p in profiles if comparable(p, metric, policy))
        for metric in FEATURES
    }
    ranked = []
    for profile in profiles:
        reasons = []
        for metric, population in populations.items():
            if len(population) < policy.minimum_population or not comparable(
                profile, metric, policy
            ):
                continue
            value = profile.features[metric]
            percentile = bisect_left(population, value) / len(population)
            if percentile <= 0.5:
                continue
            reasons.append(
                PriorityReason(
                    f"{FEATURES[metric]}: {value:,.3g}; above {percentile:.0%} of {len(population):,} comparable clients",
                    profile.evidence.get(metric, ()),
                    metric,
                    value,
                    percentile,
                    len(population),
                )
            )
        if reasons:
            reasons.sort(key=lambda r: (-(r.percentile or 0), r.metric))
            ranked.append(RankedClient(profile, tuple(reasons)))
    return sorted(
        ranked,
        key=lambda row: (
            tuple(-(r.percentile or 0) for r in row.reasons)
            + (0.0,) * (len(FEATURES) - len(row.reasons)),
            row.profile.client_ip,
        ),
    )
