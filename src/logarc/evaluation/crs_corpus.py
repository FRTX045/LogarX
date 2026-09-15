"""Scoring this project's own rules against the OWASP CRS regression corpus.

**This is not the `score-crs` ADR-0008 retired, and the difference is the whole
point.** That one ran CRS's rules against CRS's corpus — a project marking its
own homework, which is why retiring it was right. This runs the other way:
logarc's rule packs against a question paper written by somebody else, for
somebody else's tool, years before this project existed. That is the only kind
of score worth quoting.

## The corpus asks three questions, not one

Reading every case as an attack scores a quarter of the corpus backwards, so
each case is sorted into one of three buckets by what the corpus itself says.

**`expect_ids` — an attack.** Something should fire. This is the recall
denominator.

**`no_expect_ids` described as a false positive — benign traffic.** CRS added
these after one of its rules fired on something harmless and a user complained:
`firstname.dockery@host.tld`, `history.history=test`, `a timeless cinematic
icon`. Silence is the right answer and a match is the defect, so these are the
false-alarm denominator — the more valuable of the two, because a pack can
reach any recall at all by matching everything and only this number stops that
being a good score.

**`no_expect_ids` otherwise — not a question this tool can answer.** This is the
trap, and it is easy to score wrongly in the other direction. `no_expect_ids`
names *specific CRS rule IDs*: it says rule 932230 must not fire, not that the
traffic is harmless. One such case is
`/get?foo=system('echo cd /tmp;wget …;perl p.txt;rm -rf')` — an unmistakable
RCE that a *different* CRS rule is expected to catch. logarc's rules do not
correspond to CRS rule IDs at all, so it has no way to be right or wrong here.
These are counted, named, and left out of both figures.

Sorting the second from the third leans on CRS's own wording (`False positive`,
`FP with word performance`, `benign`, `legitimate`), which is a convention and
not a schema. Cases whose wording does not say go to the third bucket, so the
error runs toward measuring less rather than claiming more.

## What it can and cannot reach

A combined access log is one line per request holding the request line, the
Referer and the User-Agent. Nothing else. A great many corpus cases put their
payload in a POST body or in a header no log writes down, and **those are
counted apart rather than as misses** — scoring them as failures would measure
the log format and then report the number as a score for the rules. The same
filter applies to the negative cases: a request whose payload the log never
recorded cannot raise a false alarm either, and leaving it in that denominator
would buy a clean precision figure with cases nothing was ever asked about.

## How generous the counting is

A case counts as caught when *any* hostile rule fires, without asking whether
the category was right. That is deliberately generous, and it is stated here so
nobody reads the figure as stricter than it is: the number is a ceiling on how
well the pack does, not a floor.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Literal, TypeAlias

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

    from logarc.core.event import NormalizedEvent
    from logarc.detect.engine import RuleEngine

#: One `input` block from the corpus, as PyYAML hands it over.
Case: TypeAlias = "dict[str, Any]"

#: What the corpus asks of a request-level tool for one case. See the module
#: docstring — `"unscored"` is a real answer here, not a failure to classify.
Expectation: TypeAlias = 'Literal["attack", "benign", "unscored"]'

__all__ = ["FAMILIES", "CorpusError", "FamilyScore", "score_corpus"]


class CorpusError(RuntimeError):
    """The corpus is missing, unreadable, or was asked for a family it lacks."""


#: The CRS families worth scoring, and what to call them in a report. Response
#: families (950+) describe what the server sent back and have no bearing on
#: what a request looked like, so they are left out.
FAMILIES: Final[dict[str, str]] = {
    "930": "LFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP",
    "934": "generic",
    "941": "XSS",
    "942": "SQLi",
    "943": "session",
    "944": "Java",
}

#: The corpus writes this into every case it does not otherwise care about, so
#: a request carrying it is not carrying a payload there.
_FILLER_AGENT: Final = "OWASP CRS test agent"

#: How CRS says, in prose, that a case is harmless traffic rather than an attack
#: one of its rules happens to over-match. There is no field for it, so this is
#: the only thing there is to read. `FP with word performance` and `Negative
#: test: benign request to root` are both real descriptions from the corpus.
_BENIGN_DESC: Final = re.compile(
    r"false[\s_-]?positive|\bfps?\b|\bbenign\b|\blegitimate\b|allow[\s_-]?list|not an attack",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class FamilyScore:
    """What one CRS family costs this rule pack.

    The counts partition the family exactly once each, so they can be added up
    and checked: `cases == in_reach + negatives + out_of_reach + unscored`.
    """

    family: str
    name: str
    cases: int
    in_reach: int
    """Cases that should match, and whose payload an access log records."""

    caught: int
    negatives: int
    """Cases that should *not* match, and whose payload an access log records."""

    false_alarms: int
    """Negatives that matched anyway. Every one is a rule that is too broad."""

    out_of_reach: int = 0
    """Cases, of either kind, whose payload no access log records. Not misses."""

    unscored: int = 0
    """Cases the corpus does not put a request-level question to.

    Mostly `no_expect_ids` constraining one CRS rule by number over traffic
    that may well be hostile — see the module docstring — plus a handful
    checked by a regex on the log instead. Counted rather than guessed at."""

    missed: tuple[str, ...] = ()
    """A few of the requests that got through, so the number leads somewhere.

    A bare percentage says a pack is weak; these say how it is weak, which is
    what someone writing the next rule actually needs.
    """

    fired_wrongly: tuple[str, ...] = ()
    """A few negatives that matched, each with the rule that matched it.

    These are the more useful of the two lists: a miss costs a rule nobody has
    written yet, but a false alarm names one already here and says it is wrong.
    """

    by_rule: dict[str, int] = field(default_factory=dict)
    """Which rules did the catching, most first."""

    @property
    def recall(self) -> float:
        """Caught, over what should match and could be seen."""
        return self.caught / self.in_reach if self.in_reach else 0.0

    @property
    def false_alarm_rate(self) -> float:
        """Fired, over what should *not* match and could be seen."""
        return self.false_alarms / self.negatives if self.negatives else 0.0


def _expectation(stage: dict[str, Any], desc: str) -> Expectation:
    """What this stage asks of a tool that reads access logs.

    `expect_ids` is unambiguous. `no_expect_ids` is not: it constrains one CRS
    rule by number, and the traffic underneath may be anything from an email
    address to a live RCE that a neighbouring rule is meant to catch. Only the
    description separates them, so only the description is trusted to.
    """
    log = ((stage.get("output") or {}).get("log")) or {}
    if "expect_ids" in log:
        return "attack"
    if "no_expect_ids" in log and _BENIGN_DESC.search(desc):
        return "benign"
    return "unscored"


def _cases(root: Path, family: str) -> Iterator[tuple[Case, Expectation]]:
    """Every `input` block the corpus holds for one family, with what it asks."""
    for folder in sorted(root.iterdir()):
        if not folder.is_dir() or f"-{family}-" not in folder.name:
            continue
        for path in sorted(folder.glob("*.yaml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as exc:
                raise CorpusError(f"{path} could not be read: {exc}") from exc
            if not isinstance(doc, dict):
                continue
            for test in doc.get("tests") or []:
                desc = str(test.get("desc") or "")
                for stage in test.get("stages") or []:
                    inner = stage.get("stage", stage) or {}
                    payload = inner.get("input")
                    if payload:
                        yield payload, _expectation(inner, desc)


def _within_reach(payload: Case) -> bool:
    """Whether an access log would have recorded this case's payload at all.

    A path on its own is not enough, and that is the subtle part: the corpus
    posts to a bare `/get` or `/post` with everything in the body, and counting
    those as reachable would put cases in the denominator that no access-log
    tool could ever answer.
    """
    headers = {str(k).lower(): str(v) for k, v in (payload.get("headers") or {}).items()}
    agent = headers.get("user-agent", "")
    _, _, query = str(payload.get("uri") or "/").partition("?")
    return bool(query) or bool(headers.get("referer")) or (bool(agent) and agent != _FILLER_AGENT)


def _as_event(payload: Case, line_no: int) -> NormalizedEvent:
    from datetime import UTC, datetime

    from logarc.core.event import NormalizedEvent
    from logarc.core.evidence import EvidenceRef

    headers = {str(k).lower(): str(v) for k, v in (payload.get("headers") or {}).items()}
    path, _, query = str(payload.get("uri") or "/").partition("?")
    return NormalizedEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        client_ip="203.0.113.9",
        evidence=EvidenceRef("crs-corpus", line_no),
        method=str(payload.get("method") or "GET"),
        path=path or "/",
        query=query or None,
        status=200,
        bytes_sent=512,
        referer=headers.get("referer"),
        # A corpus case that writes no User-Agent is not a request that had
        # none; it is a fixture whose author had no interest in the field. Left
        # as None, `absent_user_agent` fires and the case scores as caught on a
        # rule that never looked at the payload. Twelve cases of 5,051, but a
        # score is not allowed to be right on average.
        user_agent=headers.get("user-agent") or _FILLER_AGENT,
    )


def score_corpus(
    root: Path,
    *,
    engine: RuleEngine,
    families: Sequence[str] | None = None,
    examples: int = 3,
) -> list[FamilyScore]:
    """Score `engine`'s rules against the corpus rooted at `root`."""
    if not root.is_dir():
        raise CorpusError(
            f"No CRS regression corpus at {root}.\n"
            f"It arrives with the ruleset rather than with this package:\n"
            f"  git clone https://github.com/coreruleset/coreruleset.git vendor/coreruleset\n"
            f"The corpus is then at vendor/coreruleset/tests/regression/tests."
        )

    wanted = list(families) if families else list(FAMILIES)
    scores: list[FamilyScore] = []

    for family in wanted:
        cases = in_reach = caught = negatives = false_alarms = out_of_reach = unscored = 0
        missed: list[str] = []
        fired_wrongly: list[str] = []
        by_rule: dict[str, int] = {}

        for payload, expected in _cases(root, family):
            cases += 1
            if expected == "unscored":
                unscored += 1
                continue
            if not _within_reach(payload):
                out_of_reach += 1
                continue

            event = _as_event(payload, cases)
            (labelled,) = engine.label_events([event])
            # Hostile labels only. The packs describe ordinary use too, and
            # every corpus request lands on `/get` or `/post` — which an action
            # rule recognises. Counting any match at all was right while every
            # rule was about an attack; the moment `action/` existed it moved
            # RCE from 9% to 20% and session from 5% to 65% with nothing new
            # detected, and reported a `Form Submission` on a POST as a false
            # alarm eleven times. Both halves of the score were wrong, and both
            # looked like results.
            rules = [item.rule_id for item in labelled.all_labels if item.category.is_hostile]
            target = str(payload.get("uri") or "/")[:96]

            if expected == "attack":
                in_reach += 1
                if rules:
                    caught += 1
                    by_rule[rules[0]] = by_rule.get(rules[0], 0) + 1
                elif len(missed) < examples:
                    missed.append(target)
            else:
                negatives += 1
                if rules:
                    false_alarms += 1
                    if len(fired_wrongly) < examples:
                        fired_wrongly.append(f"{rules[0]} on {target}")

        if not cases:
            known = ", ".join(sorted(FAMILIES))
            raise CorpusError(
                f"No cases for family {family!r} under {root}. "
                f"Zero of zero is not a result. Families here are: {known}."
            )

        scores.append(
            FamilyScore(
                family=family,
                name=FAMILIES.get(family, family),
                cases=cases,
                in_reach=in_reach,
                caught=caught,
                negatives=negatives,
                false_alarms=false_alarms,
                out_of_reach=out_of_reach,
                unscored=unscored,
                missed=tuple(missed),
                fired_wrongly=tuple(fired_wrongly),
                by_rule=dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
            )
        )

    return scores
