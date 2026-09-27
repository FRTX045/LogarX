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
    """A client with flagged requests and none of the facts the context reasons need."""
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
        category_counts={"injection": 8, "enumeration": 4},
        hostile_rules={"sqli_union_select": 8, "directory_enumeration": 4},
        hostile_rule_names={
            "sqli_union_select": "SQL Injection (UNION SELECT)",
            "directory_enumeration": "Directory Enumeration",
        },
    )


def kinds(reasons):
    return [reason.kind for reason in reasons]


def reason(profile, kind):
    from logarc.triage.reasons import suspicious_reasons

    return next(item for item in suspicious_reasons(profile) if item.kind == kind)


def test_a_client_with_no_context_facts_has_only_its_flagged_requests(plain):
    from logarc.triage.reasons import suspicious_reasons

    reasons = suspicious_reasons(plain)
    assert kinds(reasons) == ["support"]
    assert reasons[0].text == "12 of 48 requests flagged (25%); strongest severity high."
    assert reasons[0].summary == "12 of 48 requests flagged; strongest high"


def test_flagged_requests_come_first_then_context_then_categories(plain):
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
    assert kinds(reasons) == ["support", "distinct_rules", "sequence", "recurrence", ""]
    assert reasons[-1] == category


@pytest.mark.parametrize(
    ("flagged", "requests", "counts", "why"),
    [
        (
            40,
            50,
            {"enumeration": 40},
            "Flagged requests, mostly probing, make up most of this client's recorded "
            "activity rather than a few isolated requests.",
        ),
        (
            12,
            48,
            {"injection": 8, "enumeration": 4},
            "Flagged requests, mostly injection patterns, are a substantial part of this "
            "client's recorded activity.",
        ),
        (
            3,
            300,
            {"path_traversal": 2, "enumeration": 1},
            "Flagged requests, mostly path traversal patterns, are a small part of this "
            "client's recorded activity; the rest was not flagged.",
        ),
        (
            20,
            40,
            {"injection": 6, "enumeration": 6, "ssrf": 8},
            "Flagged requests of several kinds make up most of this client's recorded "
            "activity rather than a few isolated requests.",
        ),
    ],
)
def test_the_why_of_flagged_requests_describes_this_clients_share(
    plain, flagged, requests, counts, why
):
    # Two rules per category, so no single rule explains every flagged request.
    rules = {
        f"{name}_{part}": share
        for name, count in counts.items()
        for part, share in (("a", count - count // 2), ("b", count // 2))
    }
    profile = replace(
        plain,
        hostile_requests=flagged,
        requests=requests,
        category_counts=counts,
        hostile_rules=rules,
        hostile_rule_names={rule: rule for rule in rules},
    )
    assert reason(profile, "support").why == why


def test_one_rule_behind_every_flagged_request_is_named(plain):
    profile = replace(
        plain,
        hostile_requests=30,
        requests=31,
        category_counts={"reconnaissance": 30},
        hostile_rules={"scanner_user_agent": 30},
        hostile_rule_names={"scanner_user_agent": "Security Scanner User-Agent"},
    )
    assert reason(profile, "support").why == (
        "Every flagged request matches one rule (Security Scanner User-Agent), so check "
        "that rule's matches before relying on the count."
    )


def test_a_rule_on_every_request_does_not_hide_the_other_rules(plain):
    profile = replace(
        plain,
        hostile_requests=48,
        requests=48,
        category_counts={"reconnaissance": 48, "injection": 3},
        hostile_rules={"scanner_user_agent": 48, "sqli_union_select": 3},
        hostile_rule_names={
            "scanner_user_agent": "Security Scanner User-Agent",
            "sqli_union_select": "SQL Injection (UNION SELECT)",
        },
    )
    assert reason(profile, "support").why == (
        "Every flagged request matches one rule (Security Scanner User-Agent), so the count "
        "mostly reflects that rule; 1 other rule also matched some of them."
    )


def test_a_single_flagged_request_asks_to_be_inspected(plain):
    profile = replace(
        plain,
        hostile_requests=1,
        category_counts={"injection": 1},
        hostile_rules={"sqli_union_select": 1},
    )
    assert reason(profile, "support").why == (
        "A single flagged request: inspect it before relying on it."
    )


def test_distinct_rule_matches_are_named_without_claiming_specificity(plain):
    examples = (example(3, note="Rule A"), example(4, note="Rule B"), example(5, note="Rule C"))
    found = reason(
        replace(plain, distinct_rule_pairs=3, distinct_examples=examples), "distinct_rules"
    )
    assert found.text == "3 rules matched on 3 requests."
    assert found.summary == "3 distinct rule matches"
    assert found.why == "Distinct rule matches provide support beyond repetition of one rule."
    assert found.examples == examples
    assert found.evidence == tuple(item.evidence for item in examples)


def test_one_rule_match_says_its_rating_is_not_about_this_request(plain):
    found = reason(
        replace(plain, distinct_rule_pairs=1, distinct_examples=(example(3, note="Rule A"),)),
        "distinct_rules",
    )
    assert found.text == "1 rule matched on 1 request."
    assert found.summary == "1 distinct rule match"
    assert found.why == (
        "One rule matched here. Its rating describes the rule, not this request, "
        "so inspect the request before relying on it."
    )


def test_the_sequence_names_what_was_seen_without_linking_the_two(plain):
    pair = (example(1, "/admin/", "Enumeration"), example(2, "/login", "SQL Injection"))
    once = reason(replace(plain, sequence_sessions=1, sequence_examples=pair), "sequence")
    assert once.text == (
        "Enumeration was followed by an attack-pattern match (SQL Injection) "
        "against /login in the same session."
    )
    assert once.summary == "Enumeration then SQL Injection, 1 session"
    assert once.why == "The ordering makes this session worth reviewing as a whole."
    assert once.examples == pair
    thrice = reason(replace(plain, sequence_sessions=3, sequence_examples=pair), "sequence")
    assert thrice.text.endswith(" The same ordering occurs in 3 sessions.")
    assert thrice.summary == "Enumeration then SQL Injection, 3 sessions"


def recurring(plain, last):
    return replace(
        plain,
        sessions=6,
        hostile_sessions=4,
        first_hostile="2026-01-01T00:00:00+00:00",
        last_hostile=last,
        recurrence_examples=(example(1), example(9)),
    )


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
    found = reason(recurring(plain, last), "recurrence")
    assert found.text == (
        "Hostile detections occurred in 4 of 6 sessions. "
        f"The first and last matching requests were {span} apart."
    )
    assert found.summary == "Detections in 4 of 6 sessions"


@pytest.mark.parametrize("last", ["2026-01-01T00:00:30+00:00", "2026-01-01T00:59:59+00:00"])
def test_sessions_within_an_hour_may_be_one_burst(plain, last):
    assert reason(recurring(plain, last), "recurrence").why == (
        "The sessions are close together, so they may be one burst split by a session boundary."
    )


def test_sessions_far_apart_are_offered_for_review_not_called_persistent(plain):
    assert reason(recurring(plain, "2026-01-04T12:00:00+00:00"), "recurrence").why == (
        "Review the matching requests across these sessions to see whether their "
        "behaviour is related."
    )


def test_one_hostile_session_is_not_recurrence(plain):
    from logarc.triage.reasons import suspicious_reasons

    assert "recurrence" not in kinds(suspicious_reasons(replace(plain, sessions=5)))


def test_no_reason_claims_more_than_the_evidence_shows(plain):
    from logarc.triage.reasons import suspicious_reasons

    profile = replace(
        recurring(plain, "2026-01-02T00:00:00+00:00"),
        distinct_rule_pairs=1,
        distinct_examples=(example(3, note="Rule A"),),
        sequence_sessions=2,
        sequence_examples=(example(1, "/a", "Reconnaissance"), example(2, "/b", "Rule A")),
    )
    words = " ".join(
        f"{item.text} {item.why} {item.summary}".lower() for item in suspicious_reasons(profile)
    )
    for banned in (
        "confirmed",
        "probability",
        "persist",
        "caused",
        "discovered",
        "succeeded",
        "seen once",
        "hostile;",
        "requests hostile",
    ):
        assert banned not in words
    assert chr(0x2014) not in words


def test_the_order_of_the_queue_is_unchanged():
    from logarc.triage.profile import rank_profiles

    engine = RuleEngine(default_rules())
    quiet = profile_client(events("192.0.2.9", 1, path="/etc/passwd"), engine)
    loud = profile_client(events("192.0.2.1", 30, path="/etc/passwd"), engine)
    ranked = rank_profiles([quiet, loud], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.1", "192.0.2.9"]
    assert all(row.reasons[0].kind == "support" for row in ranked)
