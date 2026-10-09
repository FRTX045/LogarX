"""Compact client measurements and deterministic investigation queues."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from itertools import islice
from math import log2
from typing import TYPE_CHECKING, Final, Literal

from logarc.analysis import label_sessions
from logarc.core.activity import ActivityCategory, Severity
from logarc.core.evidence import EvidenceRef
from logarc.detect.crs.mapping import category_for, severity_for
from logarc.detect.engine import names_activity

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.activity import ActivityLabel
    from logarc.core.event import NormalizedEvent
    from logarc.detect.crs import CrsDetection, DetectionIndex
    from logarc.detect.engine import LabelledEvent, RuleEngine
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

#: Author-assigned rule confidence at which a native detection counts as a
#: high-confidence rule match. An engineering threshold until the evaluation's
#: audit of the qualifying rules supports it; it is not an attack probability.
HIGH_CONFIDENCE: Final = 0.85

#: Categories that open a probe-then-attack ordering, and those that close it.
PROBE: Final = frozenset({ActivityCategory.RECONNAISSANCE, ActivityCategory.ENUMERATION})
TARGETED: Final = frozenset(
    {
        ActivityCategory.INJECTION,
        ActivityCategory.PATH_TRAVERSAL,
        ActivityCategory.ACCESS_CONTROL,
        ActivityCategory.CREDENTIAL_ATTACK,
        ActivityCategory.SSRF,
        ActivityCategory.EXPLOITATION,
    }
)

#: Attack-category rules whose evidence also fits ordinary activity: each records
#: where a client went or what the server answered, not a payload it sent. Their
#: matches stay in the queue and its reasons; they cannot place a client first.
NOT_EXPLOIT_EVIDENCE: Final = frozenset(
    {
        "admin_area_probe",
        "forced_browsing",
        "forced_browsing_succeeded",
        "admin_reached_without_signing_in",
        "server_errors_provoked",
    }
)


def is_exploit_evidence(label: ActivityLabel) -> bool:
    """Whether a match places its client first in the Suspicious queue.

    A native rule in an attack category, other than the five above. CRS-derived
    labels never do, wherever they are stored; CRS reaches the first group only
    through detections, judged by `crs_exploit_category`.
    """
    return (
        label.category in TARGETED
        and not label.rule_id.startswith("crs:")
        and label.rule_id not in NOT_EXPLOIT_EVIDENCE
    )


def crs_exploit_category(
    detection: CrsDetection, *, site_host_known: bool
) -> ActivityCategory | None:
    """The targeted category a CRS detection gives as exploit evidence, or None.

    Paranoia level 1 only, only a match the request itself carries
    (`names_activity`), and only a rule this project maps into `TARGETED`.
    `site_host_known` is the engine's `crs_host_trusted`. This judges
    detections, never labels: a `crs:` label is not exploit evidence.
    """
    if detection.paranoia_level != 1 or not names_activity(detection):
        return None
    category = category_for(
        detection.rule_id, detection.attack_family, site_host_known=site_host_known
    )
    return category if category in TARGETED else None


@dataclass(frozen=True)
class TriagePolicy:
    minimum_requests: int = 20
    minimum_population: int = 30
    minimum_model_population: int = 100
    version: int = 4


DEFAULT_POLICY = TriagePolicy()


@dataclass(frozen=True)
class RequestExample:
    """One request shown as an example behind a reason, named the way a reader finds it."""

    evidence: EvidenceRef
    method: str | None
    path: str | None
    timestamp: str
    """As recorded, in ISO 8601."""
    note: str = ""
    """What the request stands for in its reason: a rule name, or the probe's category."""
    query: str | None = None
    """The query string as recorded, which is where most payloads are."""


@dataclass(frozen=True)
class PriorityReason:
    text: str
    """What was observed."""
    evidence: tuple[EvidenceRef, ...]
    metric: str = ""
    value: float | None = None
    percentile: float | None = None
    population: int = 0
    kind: str = ""
    why: str = ""
    """Why the observation deserves attention, or empty where the text says it all."""
    summary: str = ""
    """The compact, client-specific observation the queue's table shows."""
    examples: tuple[RequestExample, ...] = ()


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

    A tool's sweep is labelled `content_discovery_user_agent`, which outranks
    `directory_enumeration` on confidence. Asked who else enumerated, counting
    only the labels kept would leave that tool out of the answer.
    """
    rules_won: dict[str, int] = field(default_factory=dict)
    """Requests each rule named: the label a reconstruction shows for them."""
    sessions: int = 0
    hostile_sessions: int = 0
    """Sessions with at least one hostile request, each counted once."""
    first_hostile: str | None = None
    last_hostile: str | None = None
    distinct_rule_pairs: int = 0
    """The largest set of (high-confidence rule, request) pairs using each rule and each
    request once. Several rules on one request support it once; one rule repeated is one."""
    distinct_examples: tuple[RequestExample, ...] = ()
    sequence_sessions: int = 0
    """Sessions where a probe is followed, at a strictly later time, by a targeted attempt."""
    sequence_examples: tuple[RequestExample, ...] = ()
    recurrence_examples: tuple[RequestExample, ...] = ()
    category_counts: dict[str, int] = field(default_factory=dict)
    """Flagged requests per hostile category; a request in two categories counts in both."""
    hostile_rules: dict[str, int] = field(default_factory=dict)
    """Flagged requests per rule with a hostile label, so one noisy rule can be named."""
    hostile_rule_names: dict[str, str] = field(default_factory=dict)
    exploit_examples: tuple[RequestExample, ...] = ()
    """Empty, or one request. The first in time with an eligible native match, its `note`
    the strongest eligible rule's name (severity, then confidence, then rule id); failing
    that, the first with CRS level 1 evidence (`crs_exploit_category`), its `note` that
    detection's message.

    A non-empty value places the client in the first group of the Suspicious queue.
    """
    exploit_rules: tuple[str, ...] = ()
    """The rule id behind each exploit example, in the same order; `crs:<id>` for CRS."""


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
    severity = hostile_requests = sessions = hostile_sessions = sequence_sessions = 0
    specific: dict[str, list[LabelledEvent]] = {}
    sequence_examples: tuple[RequestExample, ...] = ()
    recurrence_examples: list[RequestExample] = []
    hostile_times = []
    hostile_rules: Counter[str] = Counter()
    hostile_rule_names: dict[str, str] = {}
    exploit: list[tuple[LabelledEvent, ActivityLabel]] = []
    crs_exploit: tuple[LabelledEvent, CrsDetection] | None = None
    site_host_known = engine.crs_host_trusted
    for _, labelled in label_sessions(ordered, engine, policy=session_policy, crs=crs):
        sessions += 1
        pair = _probe_then_attack(labelled)
        if pair:
            sequence_sessions += 1
            sequence_examples = sequence_examples or pair
        first_hostile = next(
            (
                item
                for item in labelled
                if any(label.category.is_hostile for label in item.all_labels)
            ),
            None,
        )
        if first_hostile is not None:
            hostile_sessions += 1
            if len(recurrence_examples) < SAMPLE_SIZE:
                recurrence_examples.append(_example(first_hostile))
        for item in labelled:
            rules_won[item.label.rule_id] += 1
            # The label is added because it is not always in `all_labels`: a
            # request nothing matched is named by the fallback alone. A set,
            # because a rule listed twice is still one match on one request.
            rules_matched.update(
                {label.rule_id for label in item.all_labels} | {item.label.rule_id}
            )
            if not exploit:
                eligible = [
                    label
                    for label in {
                        lab.rule_id: lab for lab in (*item.all_labels, item.label)
                    }.values()
                    if is_exploit_evidence(label)
                ]
                found = _strongest(eligible) if eligible else None
                if found is not None:
                    exploit = [(item, found)]
            if not exploit and crs_exploit is None:
                qualifying = [
                    detection
                    for detection in item.crs
                    if crs_exploit_category(detection, site_host_known=site_host_known)
                ]
                if qualifying:
                    # Rescue's tie-break among level 1 detections: severity, then rule id.
                    crs_exploit = (
                        item,
                        max(qualifying, key=lambda d: (severity_for(d.severity), d.rule_id)),
                    )
            hostile = [label for label in item.all_labels if label.category.is_hostile]
            if not hostile:
                continue
            hostile_requests += 1
            hostile_times.append(item.event.timestamp)
            severity = max(severity, *(int(label.severity) for label in hostile))
            for rule_id in {label.rule_id for label in hostile if high_confidence_match(label)}:
                specific.setdefault(rule_id, []).append(item)
            for label in {label.rule_id: label for label in hostile}.values():
                hostile_rules[label.rule_id] += 1
                hostile_rule_names[label.rule_id] = label.name
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

    pairs = _matching(specific)
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
    if exploit:
        exploit_examples = tuple(_example(item, label.name) for item, label in exploit)
        exploit_rules = tuple(label.rule_id for _, label in exploit)
    elif crs_exploit is not None:
        item, detection = crs_exploit
        exploit_examples = (_example(item, detection.msg or f"CRS rule {detection.rule_id}"),)
        exploit_rules = (detection.label_id,)
    else:
        exploit_examples, exploit_rules = (), ()
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
        sessions,
        hostile_sessions,
        min(hostile_times).isoformat() if hostile_times else None,
        max(hostile_times).isoformat() if hostile_times else None,
        len(pairs),
        tuple(
            _example(
                item, next(label.name for label in item.all_labels if label.rule_id == rule_id)
            )
            for rule_id, item in pairs[:SAMPLE_SIZE]
        ),
        sequence_sessions,
        sequence_examples,
        tuple(recurrence_examples),
        dict(sorted(category_counts.items())),
        dict(sorted(hostile_rules.items())),
        dict(sorted(hostile_rule_names.items())),
        exploit_examples,
        exploit_rules,
    )


def _example(item: LabelledEvent, note: str = "") -> RequestExample:
    event = item.event
    return RequestExample(
        event.evidence, event.method, event.path, event.timestamp.isoformat(), note, event.query
    )


def high_confidence_match(label: ActivityLabel) -> bool:
    """A high-confidence rule match: native, hostile, at or above `HIGH_CONFIDENCE`.

    CRS labels never qualify: neither their severity nor their fixed confidence
    says how narrowly a detection is defined.
    """
    return (
        label.category.is_hostile
        and not label.rule_id.startswith("crs:")
        and label.confidence >= HIGH_CONFIDENCE
    )


def _strongest(labels: Sequence[ActivityLabel]) -> ActivityLabel:
    return max(labels, key=lambda label: (int(label.severity), label.confidence, label.rule_id))


def _probe_then_attack(labelled: Sequence[LabelledEvent]) -> tuple[RequestExample, ...]:
    """The first targeted attempt in one session that has a probe strictly earlier,
    paired with the latest such probe.

    Position in the sorted session is not enough: requests logged at the same
    time, possibly in different files, have no order the log can vouch for, so
    a probe only becomes usable once the clock has moved past it.
    """
    usable = latest = None
    current = None
    for item in labelled:
        if item.event.timestamp != current:
            usable = latest or usable
            latest, current = None, item.event.timestamp
        targeted = [label for label in item.all_labels if label.category in TARGETED]
        if targeted and usable is not None:
            probe = _strongest([label for label in usable.all_labels if label.category in PROBE])
            return (
                _example(usable, probe.category.value.replace("_", " ").capitalize()),
                _example(item, _strongest(targeted).name),
            )
        if any(label.category in PROBE for label in item.all_labels):
            latest = item
    return ()


def _matching(edges: dict[str, list[LabelledEvent]]) -> list[tuple[str, LabelledEvent]]:
    """The largest set of (rule, request) pairs using each rule and each request once.

    Augmenting paths over rules in id order, so the same client always yields
    the same pairs. Each rule keeps at most as many requests as there are
    rules, which is enough for an exact maximum.
    """
    owner: dict[EvidenceRef, str] = {}
    chosen: dict[str, LabelledEvent] = {}
    limit = len(edges)

    def augment(rule: str, seen: set[EvidenceRef]) -> bool:
        for item in edges[rule][:limit]:
            ref = item.event.evidence
            if ref in seen:
                continue
            seen.add(ref)
            if ref not in owner or augment(owner[ref], seen):
                owner[ref], chosen[rule] = rule, item
                return True
        return False

    for rule in sorted(edges):
        augment(rule, set())
    return sorted(
        chosen.items(),
        key=lambda pair: (pair[1].event.timestamp, pair[1].event.evidence.line_no, pair[0]),
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
    """Rank the complete population before the interface applies a page limit.

    The Suspicious queue puts clients with exploit evidence before all others;
    each group is ordered by the priority score and its tie keys.
    """
    if queue == "all":
        return [
            RankedClient(p, p.reasons)
            for p in sorted(profiles, key=lambda p: (-p.requests, p.client_ip))
        ]
    if queue == "suspicious":
        selected = sorted(
            (p for p in profiles if p.hostile_requests),
            key=lambda p: (
                0 if p.exploit_examples else 1,
                -priority_score(p),
                -len(p.categories),
                -p.hostile_targets,
                -p.hostile_requests,
                p.client_ip,
            ),
        )
        # Imported here because the reasons module reads this one's types.
        from logarc.triage.reasons import suspicious_reasons

        return [RankedClient(profile, suspicious_reasons(profile)) for profile in selected]
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
