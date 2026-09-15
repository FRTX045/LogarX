"""Scoring this project's own rules against the OWASP CRS regression corpus.

**This is not the `score-crs` ADR-0008 retired, and the difference is the whole
point.** That one ran CRS's rules against CRS's corpus — a project marking its
own homework, which is why retiring it was right. This runs the other way:
logarc's rule packs against a question paper written by somebody else, for
somebody else's tool, years before this project existed. That is the only kind
of score worth quoting.

## What it can and cannot reach

A combined access log is one line per request holding the request line, the
Referer and the User-Agent. Nothing else. A great many corpus cases put their
payload in a POST body or in a header no log writes down, and **those are
counted apart rather than as misses** — scoring them as failures would measure
the log format and then report the number as a score for the rules.

Measured 2026-09-15 on the vendored corpus, that split is not small: of 429 PHP
cases, 272 are within reach; of 1,006 RCE cases, 537 are.

## How generous the counting is

A case counts as caught when *any* hostile rule fires, without asking whether
the category was right. That is deliberately generous, and it is stated here so
nobody reads the figure as stricter than it is: the number is a ceiling on how
well the pack does, not a floor.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, TypeAlias

import yaml

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from pathlib import Path

    from logarc.core.event import NormalizedEvent
    from logarc.detect.engine import RuleEngine

#: One `input` block from the corpus, as PyYAML hands it over.
Case: TypeAlias = "dict[str, Any]"

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


@dataclass(frozen=True, slots=True)
class FamilyScore:
    """What one CRS family costs this rule pack."""

    family: str
    name: str
    cases: int
    in_reach: int
    caught: int
    missed: tuple[str, ...] = ()
    """A few of the requests that got through, so the number leads somewhere.

    A bare percentage says a pack is weak; these say how it is weak, which is
    what someone writing the next rule actually needs.
    """

    by_rule: dict[str, int] = field(default_factory=dict)
    """Which rules did the catching, most first."""

    @property
    def out_of_reach(self) -> int:
        """Cases whose payload no access log records. Not misses."""
        return self.cases - self.in_reach

    @property
    def recall(self) -> float:
        """Caught, over what could be seen — never over everything."""
        return self.caught / self.in_reach if self.in_reach else 0.0


def _cases(root: Path, family: str) -> Iterator[Case]:
    """Every `input` block the corpus holds for one family."""
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
                for stage in test.get("stages") or []:
                    payload = (stage.get("stage", stage) or {}).get("input")
                    if payload:
                        yield payload


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
        user_agent=headers.get("user-agent"),
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
        cases = in_reach = caught = 0
        missed: list[str] = []
        by_rule: dict[str, int] = {}

        for payload in _cases(root, family):
            cases += 1
            if not _within_reach(payload):
                continue
            in_reach += 1
            event = _as_event(payload, in_reach)
            (labelled,) = engine.label_events([event])
            rules = [item.rule_id for item in labelled.all_labels]
            if rules:
                caught += 1
                by_rule[rules[0]] = by_rule.get(rules[0], 0) + 1
            elif len(missed) < examples:
                target = str(payload.get("uri") or "/")
                missed.append(target[:96])

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
                missed=tuple(missed),
                by_rule=dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
            )
        )

    return scores
