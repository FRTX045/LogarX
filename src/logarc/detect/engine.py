"""Level 2 segmentation: attaching an activity label to every request.

Two rule families run here. Signature rules test one request against a pattern.
Window rules test a run of requests against aggregate thresholds, catching what
no single request reveals — twenty 404s in a minute is enumeration, while any
one of them is a missing page.

Requests matching nothing are not left blank. They fall through to benign
classification, because a graph of attacks alone loses the thread between them
and cannot tell a scanner that only probed from an attacker who probed,
succeeded, and then used what they opened.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory, ActivityLabel, Severity
from logarc.detect.crs import RESCUE_CONFIDENCE, category_for_family, severity_for
from logarc.detect.rules import Condition, SignatureRule, WindowRule
from logarc.normalize.decode import NormalizedText, canonical_path, normalize

if TYPE_CHECKING:
    from collections.abc import Sequence

    from logarc.core.event import NormalizedEvent
    from logarc.detect.crs import CrsDetection, DetectionIndex
    from logarc.detect.rules import Rule, WindowCondition

__all__ = ["LabelledEvent", "RuleEngine"]

_STATIC_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        "css", "js", "mjs", "map", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
        "woff", "woff2", "ttf", "eot", "mp4", "webm", "mp3", "pdf", "txt", "xml",
    }
)  # fmt: skip

_AUTH_HINTS: Final[tuple[str, ...]] = ("/login", "/signin", "/auth", "/oauth", "/session")
_API_HINTS: Final[tuple[str, ...]] = ("/api/", "/graphql", "/v1/", "/v2/", "/rest/")
_CRAWLER_HINTS: Final[tuple[str, ...]] = ("bot", "crawler", "spider", "slurp")

_BENIGN_CONFIDENCE: Final = 0.5


def _benign(category: ActivityCategory, name: str) -> ActivityLabel:
    return ActivityLabel(
        rule_id=f"benign:{category.value}",
        name=name,
        category=category,
        severity=Severity.INFO,
        confidence=_BENIGN_CONFIDENCE,
    )


class RequestView:
    """One request, with its normalised forms computed once and reused.

    Normalisation is the expensive part of matching, and a request is tested
    against every rule, so it is cached per request rather than per rule.
    """

    __slots__ = ("__dict__", "event")

    def __init__(self, event: NormalizedEvent) -> None:
        self.event = event

    @cached_property
    def _path(self) -> NormalizedText:
        return normalize(self.event.path)

    @cached_property
    def _query(self) -> NormalizedText:
        # Form encoding: a `+` here is a space, and reading it literally is how
        # `1'+or+'1'='1` slips past every rule that expects whitespace.
        return normalize(self.event.query, plus_is_space=True)

    @cached_property
    def _target(self) -> NormalizedText:
        return normalize(self.event.target, plus_is_space=True)

    @cached_property
    def _referer(self) -> NormalizedText:
        return normalize(self.event.referer)

    @cached_property
    def _user_agent(self) -> NormalizedText:
        return normalize(self.event.user_agent)

    @cached_property
    def extension(self) -> str:
        path = self.event.path or ""
        _, _, tail = path.rpartition("/")
        stem, dot, extension = tail.rpartition(".")
        return extension.lower() if dot and stem else ""

    def value(self, field_name: str) -> str:
        """The text of one matchable field, as a string."""
        event = self.event
        match field_name:
            case "method":
                return event.method or ""
            case "path":
                return event.path or ""
            case "query":
                return event.query or ""
            case "target":
                return event.target
            case "referer":
                return event.referer or ""
            case "user_agent":
                return event.user_agent or ""
            case "protocol":
                return event.protocol or ""
            case "host":
                return event.host or ""
            case "extension":
                return self.extension
            case "path_decoded":
                return self._path.text
            case "query_decoded":
                return self._query.text
            case "target_decoded":
                return self._target.text
            case "referer_decoded":
                return self._referer.text
            case "user_agent_decoded":
                return self._user_agent.text
            case "status":
                return str(event.status) if event.status is not None else ""
            case "bytes_sent":
                return str(event.bytes_sent) if event.bytes_sent is not None else ""
            case "decode_depth":
                return str(self._target.decode_depth)
            case "had_null":
                # Numeric so a rule can write `min: 1`, matching how
                # `decode_depth` is tested rather than inventing a boolean form.
                return "1" if self._target.had_null else "0"
        return ""  # pragma: no cover - field names are validated at load time


@dataclass
class LabelledEvent:
    """A request together with what the rules concluded about it."""

    event: NormalizedEvent
    label: ActivityLabel
    all_labels: list[ActivityLabel] = field(default_factory=list)
    crs: tuple[CrsDetection, ...] = ()
    """What OWASP CRS made of the same request, when the case was enriched.

    Deliberately not folded into `all_labels`. That list feeds `_most_severe`,
    so a CRS detection placed there could outrank a rule that actually examined
    the request and asserted a category — and CRS asserts no category at all.
    Held apart, it is corroborating evidence everywhere, and names the activity
    only where nothing else did.
    """


class RuleEngine:
    """Applies a ruleset to requests."""

    def __init__(self, rules: Sequence[Rule]) -> None:
        self.rules = list(rules)
        self._signatures = [rule for rule in self.rules if isinstance(rule, SignatureRule)]
        self._windows = [rule for rule in self.rules if isinstance(rule, WindowRule)]

    @cached_property
    def fingerprint(self) -> str:
        """A digest of the ruleset, recorded so a report can name what produced it."""
        digest = hashlib.sha256()
        for rule in sorted(self.rules, key=lambda item: item.id):
            digest.update(rule.model_dump_json(exclude={"source_pack"}).encode())
        return digest.hexdigest()

    def label_events(
        self,
        events: Sequence[NormalizedEvent],
        *,
        crs: DetectionIndex | None = None,
    ) -> list[LabelledEvent]:
        """Label each request, then let window rules upgrade what they cover.

        Events are assumed to be in time order, as a session's are.

        `crs` is the detection set a case was enriched with, keyed the way
        `EvidenceRef` identifies a line. Omitted, every request is labelled
        exactly as it was before CRS existed.
        """
        labelled = [self._label_one(event, crs) for event in events]
        self._apply_windows(labelled)
        return labelled

    def _label_one(self, event: NormalizedEvent, crs: DetectionIndex | None) -> LabelledEvent:
        view = RequestView(event)
        matches = [rule for rule in self._signatures if _matches(rule, view)]
        detections = _detections_for(crs, event)

        labels = [_to_label(rule) for rule in matches]
        label = _most_severe(labels) if labels else _classify_benign(view)

        # INFO is this ruleset saying "I noticed something and I am not calling
        # it an attack" — every benign classification, and `Scripted Client` on
        # a curl user-agent. Such a request is still effectively unclassified,
        # so CRS gets asked before it is reported as ordinary traffic.
        #
        # The first cut of this only asked when *nothing* matched, which read
        # well and was wrong: a `curl` user-agent alone was enough to suppress a
        # critical CRS detection on the same request, because a rule had
        # technically fired. Anything LOW or above is a real claim about the
        # request and still wins outright.
        if label.severity is Severity.INFO and (rescued := _rescue(detections)) is not None:
            return LabelledEvent(
                event=event,
                label=rescued,
                all_labels=[*labels, rescued],
                crs=detections,
            )

        return LabelledEvent(event=event, label=label, all_labels=labels, crs=detections)

    def _apply_windows(self, labelled: list[LabelledEvent]) -> None:
        """Fire window rules, then settle each request's primary label.

        The primary label is recomputed from the complete set of matches rather
        than replaced as each rule fires. Sequential replacement made the winner
        depend on the order rules happened to be loaded in, which is not a
        property a forensic result may have — the same evidence and the same
        ruleset must always produce the same answer.
        """
        for rule in self._windows:
            members = [index for index, item in enumerate(labelled) if _is_member(rule, item)]
            label = _to_label(rule)
            for covered in _windows_meeting(rule, labelled, members):
                for index in covered:
                    labelled[index].all_labels.append(label)

        for item in labelled:
            if item.all_labels:
                item.label = _most_severe(item.all_labels)


def _is_member(rule: WindowRule, item: LabelledEvent) -> bool:
    if rule.member is None:
        return True
    conditions = rule.member.conditions
    view = RequestView(item.event)
    if rule.member.requires_all:
        return all(_condition_holds(condition, view) for condition in conditions)
    return any(_condition_holds(condition, view) for condition in conditions)


def _windows_meeting(
    rule: WindowRule, labelled: Sequence[LabelledEvent], members: Sequence[int]
) -> list[list[int]]:
    """Index groups where `rule`'s thresholds hold.

    The scan runs over the rule's *members* rather than over every request, so a
    burst is measured against the requests it consists of. Neighbouring
    unrelated traffic neither dilutes the metrics nor gets labelled by
    association.
    """
    span = rule.window.span_seconds
    hits: list[list[int]] = []

    end = 0
    for start in range(len(members)):
        if end < start:
            end = start
        limit = labelled[members[start]].event.timestamp.timestamp() + span
        while end < len(members) and labelled[members[end]].event.timestamp.timestamp() <= limit:
            end += 1

        if end - start < rule.window.min_requests:
            continue
        events = [labelled[index].event for index in members[start:end]]
        if all(_metric_holds(condition, events, span) for condition in rule.window.conditions):
            hits.append(list(members[start:end]))
    return hits


def _metric_holds(condition: WindowCondition, events: Sequence[NormalizedEvent], span: int) -> bool:
    actual = _metric(condition.metric, events, span)
    target = condition.value
    match condition.op:
        case ">=":
            return actual >= target
        case ">":
            return actual > target
        case "<=":
            return actual <= target
        case "<":
            return actual < target
        case "==":
            return actual == target
        case "!=":
            return actual != target
    return False  # pragma: no cover - operators are validated at load time


def _metric(name: str, events: Sequence[NormalizedEvent], span: int) -> float:
    total = len(events)
    if total == 0:  # pragma: no cover - windows always hold at least one event
        return 0.0

    match name:
        case "request_count":
            return float(total)
        case "distinct_paths":
            # Counted canonically: `/a/b`, `/a//b` and `/a/./b` are one path,
            # and counting them as three moves this metric across its threshold
            # without the client having touched a new resource.
            return float(len({canonical_path(event.path) for event in events}))
        case "distinct_statuses":
            return float(len({event.status for event in events}))
        case "not_found_ratio":
            return sum(event.status == 404 for event in events) / total
        case "client_error_ratio":
            return sum(_in_range(event.status, 400, 499) for event in events) / total
        case "server_error_ratio":
            return sum(_in_range(event.status, 500, 599) for event in events) / total
        case "success_ratio":
            return sum(_in_range(event.status, 200, 299) for event in events) / total
        case "requests_per_second":
            return total / span if span else 0.0
    return 0.0  # pragma: no cover - metrics are validated at load time


def _in_range(status: int | None, low: int, high: int) -> bool:
    return status is not None and low <= status <= high


def _matches(rule: SignatureRule, view: RequestView) -> bool:
    conditions = rule.match.conditions
    if rule.match.requires_all:
        return all(_condition_holds(condition, view) for condition in conditions)
    return any(_condition_holds(condition, view) for condition in conditions)


def _condition_holds(condition: Condition, view: RequestView) -> bool:
    value = view.value(condition.field_name)

    if (pattern := condition.compiled) is not None:
        return pattern.search(value) is not None
    if condition.contains is not None:
        return condition.contains.lower() in value.lower()
    if condition.equals is not None:
        return value.lower() == condition.equals.lower()
    if condition.any_of is not None:
        return value.lower() in {option.lower() for option in condition.any_of}

    try:
        numeric = float(value)
    except ValueError:
        return False
    if condition.min is not None:
        return numeric >= condition.min
    return condition.max is not None and numeric <= condition.max


def _detections_for(crs: DetectionIndex | None, event: NormalizedEvent) -> tuple[CrsDetection, ...]:
    if not crs:
        return ()
    key = (event.evidence.source_file_id, event.evidence.line_no)
    return tuple(crs.get(key, ()))


#: `matched_var` prefixes whose content came from a *different* request.
#:
#: A referer is where the client came from. When CRS matches a payload there,
#: the request that carried it is the previous one, and naming *this* request
#: for it puts the finding on the wrong line — which in a tool whose whole claim
#: is that every finding resolves to a source line is the worst way to be wrong.
#: `GET /contact` returning 200 is navigation away from an attack, not an attack.
#:
#: Coraza reports the header as it was written, so the comparison is folded.
_HEARSAY_VARS: Final[tuple[str, ...]] = ("request_headers:referer",)


def _names_activity(detection: CrsDetection) -> bool:
    """Whether this detection may be the answer, as opposed to corroboration.

    Attachment is not in question — a detection is kept as evidence either way,
    because "this client had just been somewhere hostile" is worth an
    investigator's attention. This governs only whether it can name the
    activity.
    """
    return not detection.matched_var.strip().lower().startswith(_HEARSAY_VARS)


def _rescue(detections: Sequence[CrsDetection]) -> ActivityLabel | None:
    """Name an activity from CRS, for a request no rule packed here recognised.

    Only detections whose family this project has an opinion about can do this;
    see `detect/crs/mapping.py` for which, and why the rest are withheld. When
    several qualify the most severe wins, matching how competing rule matches
    are already resolved.

    Detections read out of a referer are skipped: see `_HEARSAY_VARS`. The test
    is per detection rather than per request, so a request carrying both a
    referer-borne match and one in its own query is still named by the second.

    Returns None when nothing qualifies, which is the ordinary case and means
    the caller should fall through to benign classification as before.
    """
    candidates = [
        (detection, category)
        for detection in detections
        if _names_activity(detection)
        and (category := category_for_family(detection.attack_family)) is not None
    ]
    if not candidates:
        return None

    # Severity first, then the *lowest* paranoia level, then rule id.
    #
    # The middle term is what stops an arbitrary number deciding what an analyst
    # reads. Ranking on rule id alone means 942 (SQLi) always outranks 932 (RCE),
    # which always outranks 930 (LFI), and at PL2 that showed: two SQLi rules
    # fire alongside 932140 on `for %variable in (set) do command`, all three
    # critical, and the episode came out named "SQL Injection Attack" for a
    # Windows command payload. CRS's paranoia levels encode how readily a rule
    # fires, so the lowest one present is the most confident account of the
    # request. Rule id remains only as a tie-break with no meaning of its own,
    # so that equally severe and equally confident detections still resolve the
    # same way every run rather than by dictionary order.
    detection, category = max(
        candidates,
        key=lambda pair: (
            severity_for(pair[0].severity),
            -(pair[0].paranoia_level or 0),
            pair[0].rule_id,
        ),
    )
    return ActivityLabel(
        rule_id=detection.label_id,
        name=detection.msg or f"CRS rule {detection.rule_id}",
        category=category,
        severity=severity_for(detection.severity),
        confidence=RESCUE_CONFIDENCE,
        references=detection.capec,
    )


def _to_label(rule: Rule) -> ActivityLabel:
    return ActivityLabel(
        rule_id=rule.id,
        name=rule.name,
        category=rule.category,
        severity=rule.severity,
        confidence=rule.confidence,
        owasp=rule.owasp,
        references=rule.references,
    )


def _most_severe(labels: Sequence[ActivityLabel]) -> ActivityLabel:
    """Pick the label a report should lead with.

    Severity first, then confidence, then rule id. The last is a tie-break with
    no meaning of its own; it exists so that two equally severe, equally
    confident rules always resolve the same way rather than by load order.
    """
    return max(labels, key=lambda label: (label.severity, label.confidence, label.rule_id))


def _classify_benign(view: RequestView) -> ActivityLabel:
    """Describe a request no rule claimed.

    Deliberately coarse. These categories exist to give the graph continuity,
    not to make fine distinctions about ordinary traffic.
    """
    event = view.event
    agent = (event.user_agent or "").lower()
    path = view.value("path_decoded")

    if any(hint in agent for hint in _CRAWLER_HINTS):
        return _benign(ActivityCategory.CRAWLING, "Crawler Traffic")
    if view.extension in _STATIC_EXTENSIONS:
        return _benign(ActivityCategory.STATIC_ASSET, "Static Asset")
    if any(hint in path for hint in _AUTH_HINTS):
        return _benign(ActivityCategory.AUTHENTICATION, "Authentication")
    if any(hint in path for hint in _API_HINTS):
        return _benign(ActivityCategory.API_CALL, "API Call")
    if event.method and event.method.upper() not in {"GET", "HEAD"}:
        return _benign(ActivityCategory.API_CALL, "Non-idempotent Request")
    return _benign(ActivityCategory.BROWSING, "Page View")
