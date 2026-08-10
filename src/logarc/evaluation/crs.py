"""Scoring the rules against a corpus this project did not write.

Every other number in `docs/evaluation.md` comes from traffic `logarc generate`
produced, graded against rules from the same hands. That is a real weakness and
it is not hypothetical: the `+`-as-space defect recorded in ADR-0005 survived
every generated scenario and surfaced only when somebody else's dataset was
converted. A corpus written elsewhere finds what a corpus written here cannot.

The OWASP Core Rule Set ships a regression suite — thousands of cases, each a
concrete payload with an assertion about which of *their* rules must fire. It is
adversarial, it is maintained against real bypasses, and it owes nothing to this
project's assumptions. Four things have to be said plainly about using it:

**Most of it is invisible to an access log.** Roughly three cases in five put
their payload in a request body. A web server records the request line and
nothing after it, so no access-log tool can ever see those. They are counted and
reported rather than dropped, because a rate quoted without its ceiling invites
the reader to mistake a structural limit for a failure.

**Visible means the combined format, not the common one.** The request line, and
also `Referer` and `User-Agent`, which combined logs record and this tool parses
and has rules for. Judging against the common format would delete the two
families these rules are strongest at while the tool ships for combined. Every
other header — `Cookie`, `Content-Type`, a custom one — is genuinely out of
reach and is excluded and counted.

**Some cases assert that nothing should match.** They are CRS's own
false-positive regression tests. Counting them as payloads to be caught would
score correct restraint as failure, so they are held out of the rate and
reported separately as an advisory.

**No mapping between the two taxonomies is claimed.** CRS families name
vulnerability classes; this tool's categories name observed behaviour. A payload
CRS files under SQL injection that a path-traversal rule catches is caught. The
categories that fired are printed because the shape is worth seeing, and are not
scored, because scoring them would turn an opinion about taxonomy into a metric.

What remains is a detection rate per family: of the payloads an access log could
carry, how many did any hostile rule fire on. It measures breadth of signature
coverage, which is a different question from whether a session is reconstructed
correctly, and one the generated corpus was never able to ask.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final

import yaml

from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping, Sequence
    from pathlib import Path

    from logarc.core.activity import ActivityCategory

__all__ = [
    "CORPUS_SUBPATH",
    "FAMILY_TITLES",
    "SCORED_FAMILIES",
    "CrsCorpus",
    "CrsDetection",
    "CrsError",
    "CrsExclusion",
    "CrsFamilyScore",
    "CrsReport",
    "CrsTest",
    "ExclusionReason",
    "load_crs_corpus",
    "score_crs",
]

#: Where a coreruleset clone keeps its regression cases. Joined onto the path the
#: caller gives, so the argument is "the clone" rather than a path into its
#: internals that would break when the project rearranges itself.
CORPUS_SUBPATH: Final = ("tests", "regression", "tests")

#: The families whose cases are payloads an access-log tool could conceivably
#: see. 911, 920, 921 and 922 test method, protocol and multipart enforcement —
#: a proxy's job, at a layer below anything a log line records. 949 and 999 are
#: the blocking engine's own plumbing rather than attacks. 943 (session
#: fixation) is a real family this tool has no rule for; it is left out of the
#: default so the headline is not padded with a guaranteed zero, and `--family
#: 943` will add it back for anyone who wants the gap shown. The omission is a
#: choice, not an oversight.
SCORED_FAMILIES: Final[tuple[str, ...]] = (
    "913",
    "930",
    "931",
    "932",
    "933",
    "934",
    "941",
    "942",
    "944",
)

#: Short names, for a table column. Not a claim about this tool's own taxonomy.
FAMILY_TITLES: Final[Mapping[str, str]] = {
    "911": "method",
    "913": "scanner",
    "920": "protocol",
    "921": "protocol attack",
    "922": "multipart",
    "930": "LFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP",
    "934": "generic",
    "941": "XSS",
    "942": "SQLi",
    "943": "session fixation",
    "944": "Java",
}

#: URIs the corpus uses when the payload lives somewhere other than the request
#: line. Derived rather than guessed: every case that carries a body uses one of
#: these, so a URI outside the set is itself the payload. A length threshold was
#: tried first and was wrong in both directions — it dropped `/.env` and
#: `/.n8n/config`, which are exactly what the reconnaissance rules exist for.
NEUTRAL_URIS: Final[frozenset[str]] = frozenset({"", "/", "/get", "/post"})

#: The agent string the corpus sends when it is not testing the agent string.
#: Anything else in `User-Agent` is the payload.
CRS_TEST_AGENT: Final = "OWASP CRS test agent"

#: Synthesised, because the corpus has no responses at all. Conservative rather
#: than neutral: exactly one bundled rule is status-conditioned, and a 200 can
#: only stop it firing. The rate this module reports is therefore a floor.
SYNTHETIC_STATUS: Final = 200

#: Any address will do — no rule matches on it, and reconstruction never runs.
CORPUS_CLIENT: Final = "203.0.113.5"

#: Payloads are labelled one at a time, so the only thing the timestamp has to
#: be is real and tz-aware: window rules read it even though they cannot fire.
CORPUS_EPOCH: Final = datetime(2024, 1, 1, tzinfo=UTC)

_HEX: Final = "0123456789abcdef"
_REVISION_LENGTH: Final = 12
_PROGRESS_INTERVAL: Final = 200


class CrsError(ValueError):
    """Raised when a path is not a coreruleset clone, or a case file cannot be read."""


class ExclusionReason(StrEnum):
    """Why a case was not scored. Every case that is not scoreable gets exactly one."""

    BODY_PAYLOAD = "body_payload"
    """The payload is in a request body.

    An access log records the request line and nothing after it. This is a limit
    on what any tool reading one can see, not a failure of these rules.
    """

    UNLOGGED_HEADER = "unlogged_header"
    """The payload is in a header the combined format does not write — a cookie,
    a content type, one of the corpus's own custom headers."""

    NEGATIVE_ASSERTION = "negative_assertion"
    """CRS asserts that no rule should fire.

    These are its false-positive regression tests. Scoring them as attacks to be
    caught would record correct restraint as a miss, so they are held out of the
    rate and reported separately.
    """

    NO_ASSERTION = "no_assertion"
    """The case asserts on log text only, naming no rule id either way."""

    ENCODED_REQUEST = "encoded_request"
    """The case supplies a pre-encoded request rather than fields to build one from."""

    MALFORMED = "malformed"
    """Well-formed YAML whose case does not have the shape this reader expects."""


@dataclass(frozen=True, slots=True)
class CrsTest:
    """One CRS case, reduced to what a request line and a combined log can carry."""

    family: str
    rule_id: int
    test_id: int
    desc: str
    source: str
    index: int
    """Position in the corpus, used as the evidence line number so a prediction
    can be traced back to the case that produced it."""

    method: str
    uri: str
    user_agent: str | None
    referer: str | None
    in_request_line: bool
    """True when the URI is the payload, false when it rides in a logged header.
    Reported apart because the two are visible for different reasons, and a
    reader may want to judge against the common format instead."""


@dataclass(frozen=True, slots=True)
class CrsExclusion:
    """One case that was read and deliberately not scored."""

    family: str
    source: str
    test_id: int
    reason: ExclusionReason


@dataclass(frozen=True, slots=True)
class CrsCorpus:
    """Every case that was read, sorted by what an access log can carry.

    `scoreable` and `excluded` partition the corpus: each case read appears in
    exactly one of them. `negatives` is a view onto the subset of `excluded`
    whose reason is `NEGATIVE_ASSERTION`, kept in full because those cases are
    still worth running — as an advisory, not as part of the rate.
    """

    root: Path
    revision: str | None
    scoreable: tuple[CrsTest, ...]
    negatives: tuple[CrsTest, ...]
    excluded: tuple[CrsExclusion, ...]
    files_read: int

    @property
    def total(self) -> int:
        return len(self.scoreable) + len(self.excluded)

    def by_reason(self) -> dict[ExclusionReason, int]:
        """How many cases each exclusion reason accounts for."""
        return dict(Counter(item.reason for item in self.excluded))


@dataclass(frozen=True, slots=True)
class CrsDetection:
    """What the rules made of one payload."""

    test: CrsTest
    categories: tuple[ActivityCategory, ...]
    """The hostile categories that fired, in match order. Empty is a miss."""

    rule_ids: tuple[str, ...]

    @property
    def detected(self) -> bool:
        return bool(self.categories)


@dataclass(frozen=True, slots=True)
class CrsFamilyScore:
    """How many of one family's visible payloads any hostile rule caught."""

    family: str
    title: str
    scoreable: int
    detected: int
    in_request_line: int
    in_logged_header: int
    categories: Mapping[ActivityCategory, int]
    """Which categories fired, descriptively.

    Not scored. No mapping from a CRS family to one of this tool's categories is
    asserted anywhere, because there is no agreed one and inventing it would
    make every future taxonomy change look like an accuracy regression.
    """

    excluded: Mapping[ExclusionReason, int]

    @property
    def missed(self) -> int:
        return self.scoreable - self.detected

    @property
    def total(self) -> int:
        return self.scoreable + sum(self.excluded.values())

    @property
    def hidden_in_bodies(self) -> int:
        return self.excluded.get(ExclusionReason.BODY_PAYLOAD, 0)

    @property
    def negatives(self) -> int:
        return self.excluded.get(ExclusionReason.NEGATIVE_ASSERTION, 0)

    @property
    def detection_rate(self) -> float:
        if not self.scoreable:
            return 0.0
        return self.detected / self.scoreable

    @property
    def visible_ratio(self) -> float:
        """The share of this family a tool reading an access log could ever see."""
        if not self.total:
            return 0.0
        return self.scoreable / self.total


@dataclass(frozen=True, slots=True)
class CrsReport:
    """What these rules caught on a corpus their authors did not write."""

    corpus_root: Path
    corpus_revision: str | None
    ruleset_fingerprint: str
    rule_count: int
    families: tuple[CrsFamilyScore, ...]
    detections: tuple[CrsDetection, ...]
    excluded: tuple[CrsExclusion, ...]
    negatives_scored: int
    negatives_fired: int
    """Cases CRS says should not match that a rule fired on anyway.

    Advisory only. `no_expect_ids` says one particular CRS rule must not match,
    not that the request is benign, so this is not a false-positive rate.
    """

    files_read: int

    @property
    def scoreable(self) -> int:
        return sum(family.scoreable for family in self.families)

    @property
    def detected(self) -> int:
        return sum(family.detected for family in self.families)

    @property
    def missed(self) -> int:
        return self.scoreable - self.detected

    @property
    def total(self) -> int:
        return self.scoreable + len(self.excluded)

    @property
    def detection_rate(self) -> float:
        if not self.scoreable:
            return 0.0
        return self.detected / self.scoreable

    @property
    def visible_ratio(self) -> float:
        if not self.total:
            return 0.0
        return self.scoreable / self.total

    @property
    def hidden_in_bodies(self) -> int:
        return sum(family.hidden_in_bodies for family in self.families)

    def by_reason(self) -> dict[ExclusionReason, int]:
        return dict(Counter(item.reason for item in self.excluded))

    def misses(self) -> tuple[CrsDetection, ...]:
        """Every payload no rule fired on. The part of the result that is actionable."""
        return tuple(item for item in self.detections if not item.detected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus_root": str(self.corpus_root),
            "corpus_revision": self.corpus_revision,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "rule_count": self.rule_count,
            "files_read": self.files_read,
            "totals": {
                "cases_read": self.total,
                "scoreable": self.scoreable,
                "detected": self.detected,
                "missed": self.missed,
                "detection_rate": round(self.detection_rate, 4),
                "visible_ratio": round(self.visible_ratio, 4),
            },
            "negatives": {
                "scored": self.negatives_scored,
                "fired": self.negatives_fired,
            },
            "excluded": {reason.value: count for reason, count in sorted(self.by_reason().items())},
            "families": [
                {
                    "family": family.family,
                    "title": family.title,
                    "scoreable": family.scoreable,
                    "detected": family.detected,
                    "missed": family.missed,
                    "detection_rate": round(family.detection_rate, 4),
                    "in_request_line": family.in_request_line,
                    "in_logged_header": family.in_logged_header,
                    "categories": {
                        category.value: count for category, count in family.categories.items()
                    },
                    "excluded": {
                        reason.value: count for reason, count in sorted(family.excluded.items())
                    },
                }
                for family in self.families
            ],
            "misses": [
                {
                    "family": item.test.family,
                    "source": item.test.source,
                    "test_id": item.test.test_id,
                    "rule_id": item.test.rule_id,
                    "desc": item.test.desc,
                    "uri": item.test.uri,
                    "in_request_line": item.test.in_request_line,
                }
                for item in self.misses()
            ],
        }


def load_crs_corpus(
    *,
    clone: Path,
    families: Sequence[str] = SCORED_FAMILIES,
    on_file: Callable[[Path], None] | None = None,
) -> CrsCorpus:
    """Read a coreruleset clone's regression cases and sort them by visibility."""
    root = clone.joinpath(*CORPUS_SUBPATH)
    if not root.is_dir():
        raise CrsError(
            f"{clone} is not a coreruleset clone: expected a directory at "
            f"{'/'.join(CORPUS_SUBPATH)}"
        )

    wanted = set(families)
    scoreable: list[CrsTest] = []
    negatives: list[CrsTest] = []
    excluded: list[CrsExclusion] = []
    files_read = 0
    index = 0

    # rglob rather than the flat glob `logarc.detect.rules._expand` uses: CRS
    # keeps its cases one directory deep, under REQUEST-<family>-<name>/.
    for path in sorted(root.rglob("*.yaml")):
        family = _family_of(path)
        if family is None or family not in wanted:
            continue
        files_read += 1
        if on_file is not None:
            on_file(path)
        for test, exclusion in _cases(path, family, start=index):
            index += 1
            if exclusion is not None:
                excluded.append(exclusion)
                if test is not None and exclusion.reason is ExclusionReason.NEGATIVE_ASSERTION:
                    negatives.append(test)
            elif test is not None:
                scoreable.append(test)

    return CrsCorpus(
        root=root,
        revision=_git_revision(clone),
        scoreable=tuple(scoreable),
        negatives=tuple(negatives),
        excluded=tuple(excluded),
        files_read=files_read,
    )


def score_crs(
    *,
    clone: Path,
    engine: RuleEngine | None = None,
    families: Sequence[str] = SCORED_FAMILIES,
    score_negatives: bool = True,
    on_progress: Callable[[int, int], None] | None = None,
) -> CrsReport:
    """Label every access-log-visible CRS payload and report the rate per family."""
    corpus = load_crs_corpus(clone=clone, families=families)
    engine = engine if engine is not None else RuleEngine(default_rules())

    detections = tuple(
        _judge(engine, test) for test in _tracked(corpus.scoreable, on_progress=on_progress)
    )
    negatives_fired = 0
    if score_negatives:
        negatives_fired = sum(_judge(engine, test).detected for test in corpus.negatives)

    return CrsReport(
        corpus_root=corpus.root,
        corpus_revision=corpus.revision,
        ruleset_fingerprint=engine.fingerprint,
        rule_count=len(engine.rules),
        families=_family_scores(corpus, detections, families),
        detections=detections,
        excluded=corpus.excluded,
        negatives_scored=len(corpus.negatives) if score_negatives else 0,
        negatives_fired=negatives_fired,
        files_read=corpus.files_read,
    )


def _tracked(
    tests: Sequence[CrsTest], *, on_progress: Callable[[int, int], None] | None
) -> Iterator[CrsTest]:
    total = len(tests)
    for done, test in enumerate(tests, start=1):
        if on_progress is not None and (done % _PROGRESS_INTERVAL == 0 or done == total):
            on_progress(done, total)
        yield test


def _family_scores(
    corpus: CrsCorpus, detections: Sequence[CrsDetection], families: Sequence[str]
) -> tuple[CrsFamilyScore, ...]:
    caught: dict[str, list[CrsDetection]] = {}
    for item in detections:
        caught.setdefault(item.test.family, []).append(item)

    dropped: dict[str, Counter[ExclusionReason]] = {}
    for exclusion in corpus.excluded:
        dropped.setdefault(exclusion.family, Counter())[exclusion.reason] += 1

    scores: list[CrsFamilyScore] = []
    for family in families:
        items = caught.get(family, [])
        excluded = dict(dropped.get(family, Counter()))
        if not items and not excluded:
            continue
        categories: Counter[ActivityCategory] = Counter()
        for item in items:
            categories.update(item.categories)
        scores.append(
            CrsFamilyScore(
                family=family,
                title=FAMILY_TITLES.get(family, family),
                scoreable=len(items),
                detected=sum(item.detected for item in items),
                in_request_line=sum(item.test.in_request_line for item in items),
                in_logged_header=sum(not item.test.in_request_line for item in items),
                categories=dict(categories.most_common()),
                excluded=excluded,
            )
        )
    return tuple(scores)


def _judge(engine: RuleEngine, test: CrsTest) -> CrsDetection:
    """Run one payload past the rules, alone.

    One event per call is what keeps window rules out of the number: every
    bundled one needs several requests before it can fire, and a corpus of
    unrelated payloads is not a session. The full engine is used rather than a
    signatures-only subset so that the fingerprint recorded in the report names
    the ruleset that actually ships.
    """
    (labelled,) = engine.label_events([_as_event(test)])
    hostile = [label for label in labelled.all_labels if label.category.is_hostile]
    return CrsDetection(
        test=test,
        categories=tuple(label.category for label in hostile),
        rule_ids=tuple(label.rule_id for label in hostile),
    )


def _as_event(test: CrsTest) -> NormalizedEvent:
    # Split on `?` rather than handing the whole URI over as a path: the engine
    # normalises a query with `plus_is_space=True` and a path without it, so a
    # form-encoded payload in the wrong field is invisible. That is the defect
    # ADR-0005 records finding in CSIC, reintroduced here for free otherwise.
    path, _, query = test.uri.partition("?")
    return NormalizedEvent(
        timestamp=CORPUS_EPOCH + timedelta(seconds=test.index),
        client_ip=CORPUS_CLIENT,
        evidence=EvidenceRef("crs", test.index),
        method=test.method,
        path=path or "/",
        query=query or None,
        protocol="HTTP/1.1",
        status=SYNTHETIC_STATUS,
        user_agent=test.user_agent,
        referer=test.referer,
    )


def _family_of(path: Path) -> str | None:
    """The family a case file belongs to, from the directory holding it."""
    name = path.parent.name
    if not name.startswith("REQUEST-"):
        # Everything else is RESPONSE-*, which tests response bodies.
        return None
    parts = name.split("-")
    return parts[1] if len(parts) > 1 and parts[1].isdigit() else None


def _cases(
    path: Path, family: str, *, start: int
) -> Iterator[tuple[CrsTest | None, CrsExclusion | None]]:
    """Read one case file, yielding each stage already judged.

    A file that cannot be read, or is not a mapping, raises: the caller pointed
    at the wrong thing. A well-formed file holding one case of an unexpected
    shape is counted as MALFORMED instead, because the corpus gains fields
    between releases and one of them must not stop the measurement.
    """
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise CrsError(f"{path.name} could not be read: {exc}") from exc
    if not isinstance(payload, dict):
        raise CrsError(f"{path.name} is not a CRS test file: expected a mapping with 'tests'")

    document = _mapping(payload)
    rule_id = document.get("rule_id")
    rule_id = rule_id if isinstance(rule_id, int) else 0
    index = start

    for entry in _sequence(document.get("tests")):
        case = _mapping(entry)
        test_id = case.get("test_id")
        test_id = test_id if isinstance(test_id, int) else 0
        desc = _text(case.get("desc"))
        for stage in _sequence(case.get("stages")):
            # Older FTW files wrap each stage in a `stage:` key; newer ones do not.
            unwrapped = _mapping(stage)
            unwrapped = _mapping(unwrapped.get("stage")) or unwrapped
            yield _classify(
                unwrapped,
                family=family,
                rule_id=rule_id,
                test_id=test_id,
                desc=desc,
                source=path.name,
                index=index,
            )
            index += 1


def _classify(
    stage: Mapping[str, object],
    *,
    family: str,
    rule_id: int,
    test_id: int,
    desc: str,
    source: str,
    index: int,
) -> tuple[CrsTest | None, CrsExclusion | None]:
    """Decide whether one stage is a payload an access log could carry."""

    def drop(reason: ExclusionReason) -> tuple[None, CrsExclusion]:
        return None, CrsExclusion(family=family, source=source, test_id=test_id, reason=reason)

    request = _mapping(stage.get("input"))
    if not request:
        return drop(ExclusionReason.MALFORMED)
    if request.get("encoded_request"):
        return drop(ExclusionReason.ENCODED_REQUEST)
    if request.get("data"):
        return drop(ExclusionReason.BODY_PAYLOAD)

    uri = _text(request.get("uri"))
    headers = {key.lower(): _text(value) for key, value in _mapping(request.get("headers")).items()}
    agent = headers.get("user-agent") or None
    referer = headers.get("referer") or None

    in_request_line = uri not in NEUTRAL_URIS
    if not in_request_line:
        # The combined format writes Referer and User-Agent, and this tool has
        # rules that match only there. Judging against the common format would
        # discard the families these rules are strongest at.
        carries_payload = (agent is not None and agent != CRS_TEST_AGENT) or referer is not None
        if not carries_payload:
            return drop(ExclusionReason.UNLOGGED_HEADER)

    log = _mapping(_mapping(stage.get("output")).get("log"))
    positive = "expect_ids" in log
    negative = "no_expect_ids" in log
    if not positive and not negative:
        return drop(ExclusionReason.NO_ASSERTION)

    test = CrsTest(
        family=family,
        rule_id=rule_id,
        test_id=test_id,
        desc=desc,
        source=source,
        index=index,
        method=_text(request.get("method")).upper() or "GET",
        uri=uri or "/",
        user_agent=agent,
        referer=referer,
        in_request_line=in_request_line,
    )
    if negative and not positive:
        return test, CrsExclusion(
            family=family,
            source=source,
            test_id=test_id,
            reason=ExclusionReason.NEGATIVE_ASSERTION,
        )
    return test, None


def _git_revision(clone: Path) -> str | None:
    """The clone's checked-out commit, so a rate can be re-derived later.

    CRS gains cases with every release, so both the denominator and the rate
    drift. Without this there is no way to tell a rule change from a corpus one.
    """
    git = clone / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref:"):
            head = (git / head.removeprefix("ref:").strip()).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    head = head.lower()
    if len(head) < _REVISION_LENGTH or any(char not in _HEX for char in head):
        return None
    return head[:_REVISION_LENGTH]


def _mapping(value: object) -> Mapping[str, object]:
    """A YAML value as a string-keyed mapping, or empty if it is anything else."""
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _sequence(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return list(value)


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""
