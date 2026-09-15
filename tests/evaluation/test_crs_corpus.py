"""Scoring this project's rules against a corpus somebody else wrote.

The corpus is OWASP CRS's own regression suite. That makes the direction matter
more than usual, and ADR-0008 is the reason: the `score-crs` it retired scored
*CRS's* rules with *CRS's* corpus, a project grading itself. This runs the other
way — logarc's rules against a question paper logarc had no hand in — which is
the only kind of score worth quoting.

The tests here use a corpus written inline rather than the vendored one. The
real thing is a git clone that a fresh checkout may not have, and a test that
skips when it is absent would be a test nobody notices has stopped running.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.evaluation.crs_corpus import CorpusError, score_corpus

#: One case per shape, so each assertion below has exactly one thing to fail on.
CASES = """\
---
meta:
  author: "test"
rule_id: 933150
tests:
  - test_id: 1
    desc: payload in the query, and logarc catches it
    stages:
      - input:
          uri: "/get?x=system('id')"
          method: GET
          headers:
            User-Agent: "OWASP CRS test agent"
  - test_id: 2
    desc: payload in the query, and logarc does not catch it
    stages:
      - input:
          uri: "/get?x=perfectly-ordinary-value"
          method: GET
          headers:
            User-Agent: "OWASP CRS test agent"
  - test_id: 3
    desc: payload in the body, which no access log records
    stages:
      - input:
          uri: "/post"
          method: POST
          data: "var=system('id')"
          headers:
            User-Agent: "OWASP CRS test agent"
"""


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    root = tmp_path / "tests"
    folder = root / "REQUEST-933-APPLICATION-ATTACK-PHP"
    folder.mkdir(parents=True)
    (folder / "933150.yaml").write_text(CASES, encoding="utf-8")
    return root


@pytest.fixture(scope="module")
def engine() -> RuleEngine:
    return RuleEngine(default_rules())


def test_a_payload_in_the_query_is_within_reach(corpus: Path, engine: RuleEngine) -> None:
    (php,) = score_corpus(corpus, engine=engine, families=["933"])

    assert php.cases == 3
    assert php.in_reach == 2, "the two with a query string; the body case is not"


def test_a_payload_in_the_body_is_not_counted_as_a_miss(corpus: Path, engine: RuleEngine) -> None:
    """The line this whole measurement rests on.

    A combined access log records the request line, the Referer and the
    User-Agent. It does not record the body — not for logarc, not for anything.
    Scoring those cases as failures would measure the log format and report it
    as a score for the rules.
    """
    (php,) = score_corpus(corpus, engine=engine, families=["933"])

    assert php.cases - php.in_reach == 1
    assert php.out_of_reach == 1


def test_recall_is_over_what_could_be_seen_not_over_everything(
    corpus: Path, engine: RuleEngine
) -> None:
    (php,) = score_corpus(corpus, engine=engine, families=["933"])

    assert php.caught == 1, "system('id') fires; the ordinary value does not"
    assert php.recall == pytest.approx(0.5), "1 of the 2 in reach, not 1 of 3"


def test_the_misses_are_reported_so_they_can_be_worked_on(corpus: Path, engine: RuleEngine) -> None:
    """A bare percentage says a rule pack is weak. The misses say how."""
    (php,) = score_corpus(corpus, engine=engine, families=["933"])

    assert php.missed
    assert "perfectly-ordinary-value" in php.missed[0]


def test_a_corpus_that_is_not_there_says_where_it_should_be(
    tmp_path: Path, engine: RuleEngine
) -> None:
    """It is a git clone, not part of the package, so a first-time reader will
    hit this — and a bare "not found" makes a missing checkout look broken."""
    with pytest.raises(CorpusError) as raised:
        score_corpus(tmp_path / "nowhere", engine=engine)

    message = str(raised.value)
    assert "coreruleset" in message
    assert "git clone" in message, "the message has to carry the way out"


def test_an_unknown_family_is_refused_rather_than_scored_as_empty(
    corpus: Path, engine: RuleEngine
) -> None:
    """Zero of zero is not a result, and a typo that scores 0% silently is
    worse than one that stops."""
    with pytest.raises(CorpusError, match="999"):
        score_corpus(corpus, engine=engine, families=["999"])
