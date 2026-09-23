from dataclasses import replace

import pytest
from test_profiles import events

from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.triage.profile import RequestExample, profile_client


def example(line, path="/login", note="", seconds=0):
    return RequestExample(
        EvidenceRef("access.log", line), "GET", path, f"2026-01-01T00:00:{seconds:02d}+00:00", note
    )


@pytest.fixture(scope="module")
def plain():
    """A client with hostile detections and none of the facts the new reasons need."""
    profile = profile_client(
        events(count=4, path="/etc/passwd", user_agent="Mozilla/5.0"), RuleEngine([])
    )
    return replace(
        profile,
        hostile_requests=12,
        requests=48,
        severity=3,
        sessions=1,
        hostile_sessions=1,
    )


def kinds(reasons):
    return [reason.kind for reason in reasons]


def test_a_client_with_no_new_facts_leads_with_its_support(plain):
    from logarc.triage.reasons import suspicious_reasons

    reasons = suspicious_reasons(plain)
    assert kinds(reasons) == ["support"]
    support = reasons[0]
    assert support.text == (
        "12 of 48 requests have hostile detections (25%); strongest severity high."
    )
    assert support.summary == "12 of 48 requests hostile; strongest high"


def test_reasons_come_in_a_fixed_order_and_keep_category_reasons_last(plain):
    from logarc.triage.profile import PriorityReason
    from logarc.triage.reasons import suspicious_reasons

    category = PriorityReason("Injection indicators on 3 requests; strongest high", ())
    profile = replace(
        plain,
        reasons=(category,),
        distinct_rule_pairs=2,
        distinct_examples=(example(3, note="Rule A"), example(4, note="Rule B")),
        sequence_sessions=1,
        sequence_examples=(example(1, "/admin/", "Enumeration"), example(2, note="SQL Injection")),
        sessions=6,
        hostile_sessions=4,
        first_hostile="2026-01-01T00:00:00+00:00",
        last_hostile="2026-01-04T00:00:00+00:00",
        recurrence_examples=(example(1), example(9)),
    )
    reasons = suspicious_reasons(profile)
    assert kinds(reasons) == ["distinct_rules", "sequence", "recurrence", "support", ""]
    assert reasons[-1] == category


def test_distinct_matches_are_described_as_high_confidence_rule_matches(plain):
    from logarc.triage.reasons import suspicious_reasons

    examples = (example(3, note="Rule A"), example(4, note="Rule B"), example(5, note="Rule C"))
    profile = replace(plain, distinct_rule_pairs=3, distinct_examples=examples)
    reason = suspicious_reasons(profile)[0]
    assert reason.text == "3 rules matched on 3 requests."
    assert reason.summary == "3 high-confidence rule matches"
    assert reason.why == (
        "Distinct high-confidence rule matches provide support beyond repetition of one rule."
    )
    assert reason.examples == examples
    assert reason.evidence == tuple(item.evidence for item in examples)


def test_a_single_high_confidence_match_does_not_claim_more_than_one_rule(plain):
    from logarc.triage.reasons import suspicious_reasons

    reason = suspicious_reasons(
        replace(plain, distinct_rule_pairs=1, distinct_examples=(example(3, note="Rule A"),))
    )[0]
    assert reason.text == "1 rule matched on 1 request."
    assert reason.summary == "1 high-confidence rule match"
    assert "beyond repetition" not in reason.why


def test_the_sequence_names_what_was_seen_without_linking_the_two(plain):
    from logarc.triage.reasons import suspicious_reasons

    pair = (example(1, "/admin/", "Enumeration"), example(2, "/login", "SQL Injection"))
    once = suspicious_reasons(replace(plain, sequence_sessions=1, sequence_examples=pair))[0]
    assert once.text == (
        "Enumeration was followed by an attack-pattern match (SQL Injection) "
        "against /login in the same session."
    )
    assert once.summary == "Enumeration then SQL Injection, 1 session"
    assert once.why == "The ordering makes this session worth reviewing as a whole."
    assert once.examples == pair
    thrice = suspicious_reasons(replace(plain, sequence_sessions=3, sequence_examples=pair))[0]
    assert thrice.text.endswith(" The same ordering occurs in 3 sessions.")
    assert thrice.summary == "Enumeration then SQL Injection, 3 sessions"


@pytest.mark.parametrize(
    ("last", "span"),
    [
        ("2026-01-01T00:00:30+00:00", "less than a minute"),
        ("2026-01-01T00:59:59+00:00", "59 minutes"),
        ("2026-01-01T01:00:00+00:00", "1 hour"),
        ("2026-01-02T23:59:59+00:00", "47 hours"),
        ("2026-01-03T00:00:00+00:00", "2 days"),
        ("2026-01-04T12:00:00+00:00", "3 days"),
    ],
)
def test_recurrence_states_sessions_and_the_span_rounded_down(plain, last, span):
    from logarc.triage.reasons import suspicious_reasons

    reason = suspicious_reasons(
        replace(
            plain,
            sessions=6,
            hostile_sessions=4,
            first_hostile="2026-01-01T00:00:00+00:00",
            last_hostile=last,
            recurrence_examples=(example(1), example(9)),
        )
    )[0]
    assert reason.kind == "recurrence"
    assert reason.text == (
        "Hostile detections occurred in 4 of 6 sessions. "
        f"The first and last matching requests were {span} apart."
    )
    assert reason.summary == "Hostile in 4 of 6 sessions"


def test_one_hostile_session_is_not_recurrence(plain):
    from logarc.triage.reasons import suspicious_reasons

    assert "recurrence" not in kinds(suspicious_reasons(replace(plain, sessions=5)))


def test_no_reason_claims_more_than_the_evidence_shows(plain):
    from logarc.triage.reasons import suspicious_reasons

    profile = replace(
        plain,
        distinct_rule_pairs=1,
        distinct_examples=(example(3, note="Rule A"),),
        sequence_sessions=2,
        sequence_examples=(example(1, "/a", "Reconnaissance"), example(2, "/b", "Rule A")),
        sessions=3,
        hostile_sessions=2,
        first_hostile="2026-01-01T00:00:00+00:00",
        last_hostile="2026-01-02T00:00:00+00:00",
    )
    words = " ".join(
        f"{reason.text} {reason.why} {reason.summary}".lower()
        for reason in suspicious_reasons(profile)
    )
    for banned in ("confirmed", "probability", "persist", "caused", "discovered", "succeeded"):
        assert banned not in words
    assert chr(0x2014) not in words


def test_the_order_of_the_queue_is_unchanged():
    from logarc.triage.profile import rank_profiles

    engine = RuleEngine(default_rules())
    quiet = profile_client(events("192.0.2.9", 1, path="/etc/passwd"), engine)
    loud = profile_client(events("192.0.2.1", 30, path="/etc/passwd"), engine)
    ranked = rank_profiles([quiet, loud], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.1", "192.0.2.9"]
    assert all("support" in kinds(row.reasons) for row in ranked)
