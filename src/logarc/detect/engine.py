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
import re
from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction
from functools import cached_property
from typing import TYPE_CHECKING, Final

from logarc.core.activity import ActivityCategory, ActivityLabel, Severity
from logarc.detect.crs import RESCUE_CONFIDENCE, category_for, severity_for
from logarc.detect.rules import Condition, SignatureRule, WindowRule
from logarc.normalize.decode import NormalizedText, canonical_path, normalize

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from logarc.core.event import NormalizedEvent
    from logarc.detect.crs import CrsDetection, DetectionIndex
    from logarc.detect.rules import MatchBlock, Rule, WindowCondition

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


def _bare_host(value: str | None) -> str:
    """A host with its scheme, port, userinfo and trailing dot removed.

    Both sides of the off-domain comparison go through this, so `example.com`,
    `EXAMPLE.com:443` and `http://user@example.com./` all reduce to the same
    string and only a genuine difference of host survives.
    """
    if not value:
        return ""
    host = value.strip().lower()
    _, _, host = host.rpartition("//")  # drop any scheme
    host = host.partition("/")[0]  # and anything after the authority
    host = host.rpartition("@")[2]  # and any userinfo
    if host.startswith("["):  # an IPv6 literal keeps its brackets
        head, sep, _ = host.partition("]")
        return head + sep if sep else host
    return host.partition(":")[0].rstrip(".")


def _referer_host(referer: str) -> str:
    """The host a Referer points at, or empty when it does not name one.

    A relative Referer — some proxies rewrite them — names no host and cannot
    be off-domain, so it reads as empty and the comparison declines to fire.
    """
    value = referer.strip()
    if "//" not in value:
        return ""
    return _bare_host(value)


#: A URL sitting in a query parameter's *value*, with the parameter name left
#: out of the match so no allow-list of names is implied — an attacker uses
#: whatever the application happens to call its parameter.
#:
#: Bounded throughout. `[^\s&]{1,200}` rather than `.*` is what keeps a long
#: query linear, and the schemes are the ones that fetch something.
_URL_IN_PARAM: Final = re.compile(
    r"[?&][^=&]{1,64}=\s*((?:https?|ftps?|ldaps?|gophers?|dict)://[^\s&]{1,200})",
    re.IGNORECASE,
)


def _url_host(target: str) -> str:
    """The host a URL found in a parameter points at.

    Parsed by hand rather than with `urlsplit`, which raises on some of the
    shapes this has to survive — a bracket that never closes, a port that is
    not a number — and which would turn a malformed payload into an exception
    in the middle of labelling a case.
    """
    _, _, rest = target.partition("://")
    authority = rest.split("/")[0].split("?")[0].split("#")[0]
    return _bare_host(authority.rpartition("@")[2])


def _benign(category: ActivityCategory, name: str) -> ActivityLabel:
    return ActivityLabel(
        rule_id=f"benign:{category.value}",
        name=name,
        category=category,
        severity=Severity.INFO,
        confidence=_BENIGN_CONFIDENCE,
    )


#: What a request is called when its line could not be read.
#:
#: Not a `benign:` label, because it is not a claim that the request was
#: harmless — it is the absence of a claim. Confidence is zero for the same
#: reason: nothing here was classified, and a reader comparing labels should see
#: that this one rests on nothing.
_UNREADABLE: Final = ActivityLabel(
    rule_id="unreadable",
    name="Unreadable Request",
    category=ActivityCategory.UNKNOWN,
    severity=Severity.INFO,
    confidence=0.0,
)


class RequestView:
    """One request, with its normalised forms computed once and reused.

    Normalisation is the expensive part of matching, and a request is tested
    against every rule, so it is cached per request rather than per rule.
    """

    __slots__ = ("__dict__", "event", "site_hosts")

    def __init__(self, event: NormalizedEvent, *, site_hosts: frozenset[str] = frozenset()) -> None:
        self.event = event
        self.site_hosts = site_hosts
        """The hosts the reader said are their own, already reduced.

        Empty means unanswered, and unanswered is not a guess in either
        direction — see `query_url_offsite`.
        """

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

    @property
    def is_static_asset(self) -> bool:
        return self.extension in _STATIC_EXTENSIONS

    @cached_property
    def referer_offsite(self) -> bool:
        """Whether the Referer names a different host than the request itself.

        The one comparison the rule language could not make, and two whole CRS
        families turn on it. Session fixation and remote file inclusion are both
        *identical requests* apart from where the link came from:

            /login?sessionid=abc123   Referer: https://myapp.com/previous  harmless
            /login?sessionid=abc123   Referer: https://attacker.com/       attack

        Computed here rather than exposed as a general field-to-field operator
        because the comparison has three decisions in it, and each is easier to
        get right once in Python than to re-derive in every rule that needs it:

        **Hosts, not domains.** `app.example.com` and `attacker.example.com`
        share a registrable domain and are not the same site. The corpus is
        explicit — one case is described as "subdomain should not match" and
        expects a detection.

        **Scheme and port are not part of it.** `http://example.com/x` is the
        same site as an HTTPS request to `example.com:443`, and the corpus has
        that pair as a harmless case.

        **Absence is not evidence.** No Referer is a separate and weaker signal
        that CRS scores with its own rule; conflating it with an off-domain one
        would make every bookmarked visit a fixation attempt. And a log that
        records no Host — `apache-combined`, which is most of them — cannot
        answer at all, so it answers `False` and the rules that read this stay
        silent rather than guess.
        """
        host = _bare_host(self.event.host)
        if not host or not self.event.referer:
            return False
        origin = _referer_host(self.event.referer)
        return bool(origin) and origin != host

    @cached_property
    def query_url_offsite(self) -> bool:
        """Whether a query parameter carries a URL to a host this site does not own.

        Remote file inclusion is this and nothing else. The server is asked to
        fetch a file and go on trusting it, and the request that does it is
        `GET /page?url=…` — character for character what a share link, an OAuth
        callback and a login redirect look like. Passing a URL in a query string
        is one of the most ordinary things on the web, so the destination is the
        only thing that separates them.

        **Unanswered, this says nothing, and that was the decision.** It does
        *not* fall back to the request's own Host header. Measured against the
        OWASP CRS corpus, both routes find the same eleven attacks that nothing
        else in this tree catches; guessing from the Host header also accuses
        two of the 134 requests the corpus certifies as harmless, and being told
        accuses none. The two it gets wrong are an ad server's `loc=` and a
        plain `?url=https://example.com` behind `Host: localhost` — which is
        what a reverse proxy writes, not what the site is called.

        So the cost of leaving the question unanswered is findings, never false
        ones, which is the safe direction for a tool whose credibility is the
        product.

        Whole hosts, never suffixes: `example.com.evil.com` is a domain bought
        to be misread as `example.com`. That is also why a reader with a `www.`
        has to name both — `_bare_host` reduces scheme, port, userinfo and a
        trailing dot, and stops there.
        """
        if not self.site_hosts:
            return False
        query = self.event.query
        if not query:
            return False
        # Matched against the decoded form, so one rule covers every encoding —
        # but with a leading separator restored, because `_URL_IN_PARAM` looks
        # for `?` or `&` before the parameter name and `query_decoded` has
        # neither at the front.
        haystack = "?" + self._query.text
        return any(
            host and host not in self.site_hosts
            for host in (_url_host(found.group(1)) for found in _URL_IN_PARAM.finditer(haystack))
        )

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
            case "referer_offsite":
                # Numeric like `had_null` and `decode_depth`, so a rule writes
                # `min: 1` rather than the schema growing a boolean form.
                return "1" if self.referer_offsite else "0"
            case "query_url_offsite":
                return "1" if self.query_url_offsite else "0"
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

    def __init__(self, rules: Sequence[Rule], *, site_hosts: Iterable[str] = ()) -> None:
        self.rules = list(rules)
        self._signatures = [rule for rule in self.rules if isinstance(rule, SignatureRule)]
        self._windows = [rule for rule in self.rules if isinstance(rule, WindowRule)]
        self.site_hosts = frozenset(
            reduced for reduced in (_bare_host(name) for name in site_hosts) if reduced
        )
        """The hosts the reader said are their own, for `query_url_offsite`.

        Reduced on the way in rather than at every comparison, so a reader who
        types a whole URL into a box that asked for a domain is understood, and
        so the set can be compared against a URL's host directly.

        **Deliberately not part of `fingerprint`.** That digest answers "which
        ruleset produced this", and folding a per-case answer into it would make
        the same rules fingerprint differently for every case. `AnalysisResult`
        carries the hosts separately, beside `crs_fingerprint`, for the same
        reason CRS is carried there: it is provenance, not rules.
        """

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
        view = RequestView(event, site_hosts=self.site_hosts)
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
        # One view per request for the whole pass. Every window rule tests the
        # same requests, and a view built per rule would normalise each one
        # again for every rule that looks at it.
        views = [RequestView(item.event, site_hosts=self.site_hosts) for item in labelled]
        for rule in self._windows:
            members = [index for index, view in enumerate(views) if _is_member(rule, view)]
            label = _to_label(rule)
            for index in _members_of_matching_windows(rule, labelled, members):
                labelled[index].all_labels.append(label)

        for item in labelled:
            if item.all_labels:
                item.label = _most_severe(item.all_labels)


def _is_member(rule: WindowRule, view: RequestView) -> bool:
    return rule.member is None or _block_holds(rule.member, view)


def _covered(members: Sequence[int], coverage: Sequence[int]) -> list[int]:
    """Resolve a difference array of window starts and ends into request indices.

    `coverage[p]` is +1 where a matching window begins at member position `p`
    and -1 one past where it ends, so the running total is how many windows
    cover a position and any positive count means the member is labelled.
    """
    active = 0
    covered: list[int] = []
    for position, index in enumerate(members):
        active += coverage[position]
        if active:
            covered.append(index)
    return covered


def _members_of_matching_windows(
    rule: WindowRule, labelled: Sequence[LabelledEvent], members: Sequence[int]
) -> list[int]:
    """Request indices covered by at least one matching window.

    The scan runs over the rule's *members* rather than over every request, so a
    burst is measured against the requests it consists of. Neighbouring
    unrelated traffic neither dilutes the metrics nor gets labelled by
    association.
    """
    if not members:
        return []
    if thresholds := _static_guard_thresholds(rule):
        return _members_of_static_guarded_windows(rule, labelled, members, *thresholds)

    coverage = [0] * (len(members) + 1)

    _cover_maximal_windows(rule, labelled, members, coverage, reverse=False)
    _cover_maximal_windows(rule, labelled, members, coverage, reverse=True)
    return _covered(members, coverage)


def _static_guard_thresholds(rule: WindowRule) -> tuple[int, Fraction] | None:
    """Return the optimisable distinct-path and static-ratio thresholds."""
    conditions = {condition.metric: condition for condition in rule.window.conditions}
    if len(rule.window.conditions) != 2 or set(conditions) != {
        "distinct_paths",
        "static_asset_ratio",
    }:
        return None
    distinct = conditions["distinct_paths"]
    static = conditions["static_asset_ratio"]
    if (
        distinct.op != ">="
        or static.op != "<="
        or static.value != 0.2
        or not distinct.value.is_integer()
    ):
        return None
    return int(distinct.value), Fraction(1, 5)


def _members_of_static_guarded_windows(
    rule: WindowRule,
    labelled: Sequence[LabelledEvent],
    members: Sequence[int],
    distinct_threshold: int,
    static_threshold: Fraction,
) -> list[int]:
    """Find every guarded window in O(n log n), including interior runs."""
    total = len(members)
    if not total:
        return []

    events = [labelled[index].event for index in members]
    timestamps = [event.timestamp.timestamp() for event in events]
    paths = [canonical_path(event.path) for event in events]
    numerator, denominator = static_threshold.numerator, static_threshold.denominator
    balance = [0]
    for event in events:
        balance.append(
            balance[-1] + (denominator if RequestView(event).is_static_asset else 0) - numerator
        )
    tree, tree_size = _range_min_tree(balance)

    coverage = [0] * (total + 1)
    time_end = 0
    distinct_end = 0
    distinct_paths: Counter[str] = Counter()
    for start in range(total):
        while (
            time_end < total
            and timestamps[time_end] <= timestamps[start] + rule.window.span_seconds
        ):
            time_end += 1
        if distinct_end < start:
            distinct_end = start
        while distinct_end < total and len(distinct_paths) < distinct_threshold:
            distinct_paths[paths[distinct_end]] += 1
            distinct_end += 1

        if len(distinct_paths) >= distinct_threshold:
            first_end = max(start + rule.window.min_requests, distinct_end)
            matching_end = _rightmost_at_most(
                tree, tree_size, first_end, time_end + 1, balance[start]
            )
            if matching_end is not None:
                coverage[start] += 1
                coverage[matching_end] -= 1

        if start < distinct_end:
            distinct_paths[paths[start]] -= 1
            if not distinct_paths[paths[start]]:
                del distinct_paths[paths[start]]

    return _covered(members, coverage)


def _range_min_tree(values: Sequence[int]) -> tuple[list[float], int]:
    size = 1 << (len(values) - 1).bit_length()
    tree = [float("inf")] * (size * 2)
    tree[size : size + len(values)] = values
    for node in range(size - 1, 0, -1):
        tree[node] = min(tree[node * 2], tree[node * 2 + 1])
    return tree, size


def _rightmost_at_most(
    tree: Sequence[float], size: int, left: int, right: int, target: float
) -> int | None:
    """Rightmost index in ``[left, right)`` whose value is at most target."""

    def search(node: int, node_left: int, node_right: int) -> int | None:
        if node_right <= left or right <= node_left or tree[node] > target:
            return None
        if node_right - node_left == 1:
            return node_left
        middle = (node_left + node_right) // 2
        found = search(node * 2 + 1, middle, node_right)
        return found if found is not None else search(node * 2, node_left, middle)

    return search(1, 0, size)


def _cover_maximal_windows(
    rule: WindowRule,
    labelled: Sequence[LabelledEvent],
    members: Sequence[int],
    coverage: list[int],
    *,
    reverse: bool,
) -> None:
    """Mark maximal matching windows from one temporal direction."""
    span = rule.window.span_seconds
    measurements = _WindowMeasurements()
    edge = len(members) if reverse else 0
    anchors = range(len(members) - 1, -1, -1) if reverse else range(len(members))

    for anchor in anchors:
        timestamp = labelled[members[anchor]].event.timestamp.timestamp()
        if reverse:
            limit = timestamp - span
            while edge > 0 and labelled[members[edge - 1]].event.timestamp.timestamp() >= limit:
                edge -= 1
                measurements.add(labelled[members[edge]].event)
            start, end = edge, anchor + 1
        else:
            limit = timestamp + span
            while (
                edge < len(members) and labelled[members[edge]].event.timestamp.timestamp() <= limit
            ):
                measurements.add(labelled[members[edge]].event)
                edge += 1
            start, end = anchor, edge

        if measurements.total >= rule.window.min_requests and all(
            _measurement_holds(condition, measurements, span)
            for condition in rule.window.conditions
        ):
            coverage[start] += 1
            coverage[end] -= 1
        measurements.remove(labelled[members[anchor]].event)


@dataclass
class _WindowMeasurements:
    total: int = 0
    paths: Counter[str] = field(default_factory=Counter)
    statuses: Counter[int | None] = field(default_factory=Counter)
    not_found: int = 0
    client_errors: int = 0
    server_errors: int = 0
    successes: int = 0
    static_assets: int = 0

    def add(self, event: NormalizedEvent) -> None:
        self.total += 1
        self.paths[canonical_path(event.path)] += 1
        self.statuses[event.status] += 1
        self.not_found += event.status == 404
        self.client_errors += _in_range(event.status, 400, 499)
        self.server_errors += _in_range(event.status, 500, 599)
        self.successes += _in_range(event.status, 200, 299)
        self.static_assets += RequestView(event).is_static_asset

    def remove(self, event: NormalizedEvent) -> None:
        self.total -= 1
        path = canonical_path(event.path)
        self.paths[path] -= 1
        if not self.paths[path]:
            del self.paths[path]
        self.statuses[event.status] -= 1
        if not self.statuses[event.status]:
            del self.statuses[event.status]
        self.not_found -= event.status == 404
        self.client_errors -= _in_range(event.status, 400, 499)
        self.server_errors -= _in_range(event.status, 500, 599)
        self.successes -= _in_range(event.status, 200, 299)
        self.static_assets -= RequestView(event).is_static_asset

    def value(self, name: str, span: int) -> float:
        if not self.total:  # pragma: no cover - matching windows are never empty
            return 0.0
        match name:
            case "request_count":
                return float(self.total)
            case "distinct_paths":
                return float(len(self.paths))
            case "distinct_statuses":
                return float(len(self.statuses))
            case "not_found_ratio":
                return self.not_found / self.total
            case "client_error_ratio":
                return self.client_errors / self.total
            case "server_error_ratio":
                return self.server_errors / self.total
            case "success_ratio":
                return self.successes / self.total
            case "requests_per_second":
                return self.total / span if span else 0.0
            case "static_asset_ratio":
                return self.static_assets / self.total
        return 0.0  # pragma: no cover - metrics are validated at load time


def _measure(events: Iterable[NormalizedEvent]) -> _WindowMeasurements:
    measurements = _WindowMeasurements()
    for event in events:
        measurements.add(event)
    return measurements


def _metric_holds(condition: WindowCondition, events: Sequence[NormalizedEvent], span: int) -> bool:
    return _measurement_holds(condition, _measure(events), span)


def _measurement_holds(
    condition: WindowCondition, measurements: _WindowMeasurements, span: int
) -> bool:
    actual = measurements.value(condition.metric, span)
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
    return _measure(events).value(name, span)


def _in_range(status: int | None, low: int, high: int) -> bool:
    return status is not None and low <= status <= high


def _matches(rule: SignatureRule, view: RequestView) -> bool:
    return _block_holds(rule.match, view)


def _block_holds(block: MatchBlock, view: RequestView) -> bool:
    """Whether a rule's `any`/`all` block of conditions holds for one request."""
    conditions = block.conditions
    if block.requires_all:
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

    Only detections whose family this project has an opinion about can do this,
    and a few rule ids correct the category their family implies; see
    `detect/crs/mapping.py` for which, and why the rest are withheld. When
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
        and (category := category_for(detection.rule_id, detection.attack_family)) is not None
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

    Severity first, then whether the label describes an attack at all, then
    confidence, then rule id. The last is a tie-break with no meaning of its
    own; it exists so that two equally severe, equally confident rules always
    resolve the same way rather than by load order.

    Hostility sits above confidence because the packs now describe ordinary use
    as well as attacks, and the two meet at INFO. `Scripted Client` is INFO at
    0.4 — deliberately unsure, because a user-agent is a claim — while
    `View Cart` on `/cart` is INFO at 0.85 and nearly certain. Ranking by
    confidence alone leads a report on a `curl` request to `/cart` with
    "View Cart", which is true and useless: it buries the only part worth
    reading under the part nobody needed telling.
    """
    return max(
        labels,
        key=lambda label: (
            label.severity,
            label.category.is_hostile,
            label.confidence,
            label.rule_id,
        ),
    )


def _classify_benign(view: RequestView) -> ActivityLabel:
    """Describe a request no rule claimed.

    Deliberately coarse. These categories exist to give the graph continuity,
    not to make fine distinctions about ordinary traffic.
    """
    event = view.event
    agent = (event.user_agent or "").lower()
    path = view.value("path_decoded")

    # Before anything else, because every branch below reads the path and would
    # otherwise fall through to `Page View` — telling the reader the client
    # browsed a page when nothing here knows what it asked for. Malformed
    # request lines are routine in attack traffic, which is exactly why they are
    # kept rather than discarded, and exactly why they must not be described as
    # ordinary use.
    #
    # Ahead of the crawler check too: that branch answers *who*, and a
    # user-agent is the cheapest thing in a request to forge. Knowing who
    # claimed to send an unreadable line is not knowing what was sent.
    if not event.path:
        return _UNREADABLE

    if any(hint in agent for hint in _CRAWLER_HINTS):
        return _benign(ActivityCategory.CRAWLING, "Crawler Traffic")
    if view.is_static_asset:
        return _benign(ActivityCategory.STATIC_ASSET, "Static Asset")
    if any(hint in path for hint in _AUTH_HINTS):
        return _benign(ActivityCategory.AUTHENTICATION, "Authentication")
    if any(hint in path for hint in _API_HINTS):
        return _benign(ActivityCategory.API_CALL, "API Call")
    if event.method and event.method.upper() not in {"GET", "HEAD"}:
        return _benign(ActivityCategory.API_CALL, "Non-idempotent Request")
    return _benign(ActivityCategory.BROWSING, "Page View")
