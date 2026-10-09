from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from logarc.analysis import analyse_ip
from logarc.core.event import NormalizedEvent
from logarc.core.evidence import EvidenceRef
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.storage.event_store import ParquetEventStore


def events(ip="192.0.2.1", count=20, **fields):
    return [
        NormalizedEvent(
            timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=i),
            client_ip=ip,
            evidence=EvidenceRef("source", i + 1),
            **(
                {
                    "path": "/",
                    "method": "GET",
                    "status": 200,
                    "bytes_sent": 100,
                    "user_agent": "Mozilla/5.0",
                    "protocol": "HTTP/1.1",
                }
                | fields
            ),
        )
        for i in range(count)
    ]


def test_quiet_attack_precedes_busy_benign_and_matches_reconstruction(tmp_path):
    from logarc.triage.profile import profile_client, rank_profiles

    engine = RuleEngine(default_rules())
    quiet = events("192.0.2.9", 1, path="/etc/passwd", query="file=../../etc/passwd")
    busy = events("192.0.2.1", 1000)
    profile = profile_client(quiet, engine)
    benign = profile_client(busy, engine)
    store = ParquetEventStore(tmp_path / "store")
    try:
        store.write(quiet)
        store.finalize()
        reconstruction = analyse_ip(store, quiet[0].client_ip, engine=engine)
        assert profile.hostile_requests == sum(
            any(label.category.is_hostile for label in item.labelled.all_labels)
            for item in reconstruction.assignments
        )
        assert profile.hostile_requests == 1
        ranked = rank_profiles([benign, profile], "suspicious")
        assert [row.profile.client_ip for row in ranked] == ["192.0.2.9"]
        assert ranked[0].reasons[0].evidence == (quiet[0].evidence,)
        assert "compromise" not in ranked[0].reasons[0].text.lower()
    finally:
        store.close()


def test_promoted_order_bounds_severity_and_explains_support_without_losing_evidence():
    from logarc.triage.profile import DEFAULT_POLICY, profile_client, rank_profiles

    engine = RuleEngine(default_rules())
    base = profile_client(events(count=1, path="/etc/passwd"), engine)
    quiet = replace(base, client_ip="quiet", severity=4)
    sustained = replace(
        base, client_ip="sustained", requests=1000, hostile_requests=1000, severity=3
    )
    noisy = replace(sustained, client_ip="noisy", requests=100000)
    rows = rank_profiles([quiet, noisy, sustained], "suspicious")
    assert [row.profile.client_ip for row in rows] == ["sustained", "noisy", "quiet"]
    support = next(reason for reason in rows[0].reasons if reason.kind == "support")
    assert "1,000 of 1,000" in support.text
    assert support.evidence == base.reasons[0].evidence
    assert rows[0].reasons[-len(base.reasons) :] == base.reasons
    assert DEFAULT_POLICY.version == 4


def test_priority_score_matches_hand_calculated_support_severity_and_share():
    import pytest

    from logarc.triage.profile import priority_score, profile_client

    base = profile_client(events(count=1), RuleEngine(default_rules()))
    for hostile, requests, severity, expected in (
        (0, 10, 4, 0.0),
        (3, 3, 4, 4.0),
        (3, 6, 4, 3.0),
        (3, 6, 0, 1.5),
        (7, 7, 2, 4.5),
    ):
        profile = replace(base, hostile_requests=hostile, requests=requests, severity=severity)
        assert priority_score(profile) == pytest.approx(expected)


def test_duplicate_rule_matches_count_one_request():
    from logarc.triage.profile import profile_client

    rules = default_rules()
    sample = events(count=1, path="/etc/passwd", query="file=../../etc/passwd")
    once = profile_client(sample, RuleEngine(rules))
    twice = profile_client(sample, RuleEngine(rules + rules))
    assert once == twice


def test_shared_ip_native_and_crs_labels_match_reconstruction(tmp_path):
    from logarc.detect.crs import CrsDetection
    from logarc.triage.profile import profile_client

    sample = events(count=24)
    sample[0] = replace(sample[0], query="id=1 UNION SELECT password FROM users")
    sample[1] = replace(sample[1], path="/get", query="foo=for %variable in (set) do command")
    sample[2:] = [replace(event, user_agent="Googlebot/2.1") for event in sample[2:]]
    crs = {}
    for index, family in enumerate(("attack-sqli", "attack-rce"), 1):
        detection = CrsDetection(
            source_file_id="source",
            line_no=index,
            rule_id=942100 + index,
            severity="critical",
            msg="Fixture detection",
            matched_var="ARGS:q",
            transformed_value="fixture",
            attack_family=family,
        )
        crs[("source", index)] = [detection, detection]
    engine = RuleEngine(default_rules())
    profile = profile_client(sample, engine, crs=crs)
    store = ParquetEventStore(tmp_path / "store")
    try:
        store.write(sample)
        store.finalize()
        reconstruction = analyse_ip(store, sample[0].client_ip, engine=engine, crs=crs)
        hostile = [
            assignment
            for assignment in reconstruction.assignments
            if any(label.category.is_hostile for label in assignment.labelled.all_labels)
        ]
        assert profile.hostile_requests == len(hostile) == 2
        assert profile.severity == max(
            int(label.severity)
            for assignment in hostile
            for label in assignment.labelled.all_labels
            if label.category.is_hostile
        )
        assert {ref for reason in profile.reasons for ref in reason.evidence} <= {
            assignment.evidence for assignment in hostile
        }
    finally:
        store.close()


def test_statistics_preserve_missingness_and_real_peak_evidence():
    from logarc.triage.profile import profile_client

    sample = events(count=80, status=None, bytes_sent=None)
    profile = profile_client(sample, RuleEngine([]))
    assert "4xx_share" not in profile.features
    assert "bytes_total" not in profile.features
    assert profile.coverage["status"] == 0
    assert profile.features["peak_per_minute"] == 60
    assert profile.evidence["peak_per_minute"]
    assert all(ref in {e.evidence for e in sample} for ref in profile.evidence["peak_per_minute"])


def test_uniform_traffic_is_not_declared_unusual():
    from logarc.triage.profile import profile_client, rank_profiles

    engine = RuleEngine([])
    profiles = [profile_client(events(f"192.0.2.{i}"), engine) for i in range(30)]
    assert rank_profiles(profiles, "unusual") == []


def test_unusual_order_uses_complete_population_and_measured_reasons():
    from logarc.triage.profile import profile_client, rank_profiles

    engine = RuleEngine([])
    profiles = [profile_client(events(f"192.0.2.{i}"), engine) for i in range(30)]
    outlier = profile_client(events("192.0.2.250", count=100), engine)
    ranked = rank_profiles([*profiles, outlier], "unusual")
    assert ranked[0].profile.client_ip == outlier.client_ip
    reason = next(reason for reason in ranked[0].reasons if reason.metric == "requests")
    assert reason.value == 100
    assert reason.population == 31
    assert reason.percentile == 30 / 31
    assert reason.evidence
    assert rank_profiles(profiles[:29], "unusual") == []


def test_short_clients_and_sparse_fields_cannot_drive_anomaly_comparisons():
    from logarc.triage.profile import profile_client, rank_profiles

    engine = RuleEngine([])
    profiles = [profile_client(events(f"192.0.2.{i}"), engine) for i in range(30)]
    sparse = events("192.0.2.250", status=None)
    sparse[0] = replace(sparse[0], status=500)
    result = rank_profiles([*profiles, profile_client(sparse, engine)], "unusual")
    assert not any(reason.metric == "5xx_share" for row in result for reason in row.reasons)
    assert rank_profiles([profile_client(events(count=19), engine)] * 30, "unusual") == []


def test_leading_reason_explains_the_strongest_evidence():
    from logarc.triage.profile import profile_client

    sample = events(count=2, path="/wp-admin/", status=404)
    sample[1] = replace(
        sample[1], path="/product", query="id=1 UNION SELECT password FROM users", status=200
    )
    profile = profile_client(sample, RuleEngine(default_rules()))
    assert "injection" in profile.reasons[0].text.lower()
    assert profile.reasons[0].evidence == (sample[1].evidence,)


def test_tied_security_ranks_use_ip_order():
    from logarc.triage.profile import profile_client, rank_profiles

    engine = RuleEngine(default_rules())
    profiles = [
        profile_client(events(ip, 1, path="/etc/passwd"), engine)
        for ip in ("192.0.2.9", "192.0.2.1")
    ]
    assert [r.profile.client_ip for r in rank_profiles(profiles, "suspicious")] == [
        "192.0.2.1",
        "192.0.2.9",
    ]


def scanned(ip="192.0.2.33", count=30):
    """Enumeration from a scanner: distinct missing paths, one per second."""
    return [
        replace(event, path=f"/w{i}")
        for i, event in enumerate(events(ip, count, status=404, user_agent="gobuster/3.5"))
    ]


def test_a_rule_that_matches_but_loses_the_label_is_still_counted():
    """Two tools ran one wordlist, and only one of them was named for it.

    With a content-discovery tool's user-agent the same enumeration is labelled
    `content_discovery_user_agent`, which outranks `directory_enumeration` on
    confidence. Counting only the label that won would say nobody else
    enumerated.
    """
    from logarc.triage.profile import profile_client

    profile = profile_client(scanned(), RuleEngine(default_rules()))
    assert profile.rules_matched["directory_enumeration"] == 30
    assert "directory_enumeration" not in profile.rules_won
    assert profile.rules_won["content_discovery_user_agent"] == 30


def test_ordinary_traffic_is_counted_under_the_label_it_was_given():
    """Nothing matched, so the label is the fallback and `all_labels` is empty.

    Asking who else browsed has to find these requests all the same.
    """
    from logarc.triage.profile import profile_client

    profile = profile_client(events(count=3), RuleEngine(default_rules()))
    assert profile.rules_matched == {"benign:browsing": 3}
    assert profile.rules_won == {"benign:browsing": 3}


def test_rule_counts_agree_with_reconstruction(tmp_path):
    """Every rule a reconstruction shows under "Matched by" can be looked up.

    A node's `rule_ids` are the labels its requests won, so the set of those
    across a reconstruction is exactly the set of rules this client won.
    """
    from collections import Counter

    from logarc.triage.profile import profile_client

    engine = RuleEngine(default_rules())
    sample = [
        *scanned(),
        *(
            replace(
                event,
                timestamp=event.timestamp + timedelta(hours=2),
                evidence=EvidenceRef("source", 100 + i),
            )
            for i, event in enumerate(events("192.0.2.33", 3))
        ),
    ]
    profile = profile_client(sample, engine)
    store = ParquetEventStore(tmp_path / "store")
    try:
        store.write(sample)
        store.finalize()
        reconstruction = analyse_ip(store, "192.0.2.33", engine=engine)
    finally:
        store.close()

    matched: Counter[str] = Counter()
    won: Counter[str] = Counter()
    for item in reconstruction.assignments:
        labelled = item.labelled
        won[labelled.label.rule_id] += 1
        for rule_id in {label.rule_id for label in labelled.all_labels} | {labelled.label.rule_id}:
            matched[rule_id] += 1
    assert profile.rules_matched == dict(matched)
    assert profile.rules_won == dict(won)
    assert {rule for node in reconstruction.trace.nodes for rule in node.rule_ids} == set(
        profile.rules_won
    )


def fixture_rules(tmp_path, *rules):
    """Signature rules matching a word in the query: (id, category, severity, confidence, word)."""
    from logarc.detect.rules import load_rules

    body = "version: 1\nrules:\n" + "".join(
        f"  - id: {rule_id}\n"
        f"    name: {rule_id.replace('_', ' ').title()}\n"
        f"    category: {category}\n"
        f"    severity: {severity}\n"
        f"    confidence: {confidence}\n"
        "    match:\n"
        "      any:\n"
        "        - field: query\n"
        f"          contains: {word}\n"
        for rule_id, category, severity, confidence, word in rules
    )
    path = tmp_path / "fixture.yaml"
    path.write_text(body, encoding="utf-8")
    return RuleEngine(load_rules([path]))


def at(event, seconds, line=None):
    """The event moved to `seconds` after the fixture's epoch, optionally renumbered."""
    return replace(
        event,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
        evidence=EvidenceRef(event.evidence.source_file_id, line or event.evidence.line_no),
    )


def test_distinct_rule_pairs_are_a_maximum_matching_not_a_minimum_of_counts(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        ("rule_a", "injection", "high", 0.9, "alpha"),
        ("rule_b", "injection", "high", 0.9, "beta"),
        ("rule_c", "injection", "high", 0.9, "gamma"),
    )
    sample = events(count=3, query="alpha")
    sample[0] = replace(sample[0], query="alpha beta gamma")
    profile = profile_client(sample, engine)
    assert profile.distinct_rule_pairs == 2
    assert len(profile.distinct_examples) == 2
    assert len({example.evidence for example in profile.distinct_examples}) == 2


def test_only_native_rules_at_high_confidence_count_as_specific(tmp_path):
    from logarc.detect.crs import CrsDetection
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        ("unsure", "injection", "critical", 0.8, "maybe"),
        ("sure_but_low", "reconnaissance", "low", 0.85, "sure"),
    )
    sample = events(count=3)
    sample[0] = replace(sample[0], query="maybe")
    sample[1] = replace(sample[1], query="sure")
    detection = CrsDetection(
        source_file_id="source",
        line_no=3,
        rule_id=942100,
        severity="critical",
        msg="Fixture detection",
        matched_var="ARGS:q",
        transformed_value="fixture",
        attack_family="attack-sqli",
    )
    profile = profile_client(sample, engine, crs={("source", 3): [detection]})
    assert profile.hostile_requests == 3
    assert profile.distinct_rule_pairs == 1
    assert profile.distinct_examples[0].evidence == sample[1].evidence
    assert profile.distinct_examples[0].note == "Sure But Low"


def test_many_distinct_matches_keep_the_full_count_and_a_bounded_sample(tmp_path):
    from logarc.triage.profile import SAMPLE_SIZE, profile_client

    words = [f"word{i}" for i in range(12)]
    engine = fixture_rules(
        tmp_path, *((f"rule_{i}", "injection", "high", 0.9, word) for i, word in enumerate(words))
    )
    sample = [
        replace(event, query=word) for event, word in zip(events(count=12), words, strict=True)
    ]
    profile = profile_client(sample, engine)
    assert profile.distinct_rule_pairs == 12
    assert len(profile.distinct_examples) == SAMPLE_SIZE


def probe_attack_engine(tmp_path):
    return fixture_rules(
        tmp_path,
        ("probe", "enumeration", "medium", 0.9, "probe"),
        ("attack", "injection", "critical", 0.9, "attack"),
    )


def test_a_probe_followed_by_an_attack_marks_its_session(tmp_path):
    from logarc.triage.profile import profile_client

    sample = events(count=4)
    sample[1] = replace(sample[1], query="probe", path="/admin/")
    sample[2] = replace(sample[2], query="attack", path="/login")
    profile = profile_client(sample, probe_attack_engine(tmp_path))
    assert profile.sequence_sessions == 1
    probe, attack = profile.sequence_examples
    assert (probe.evidence, attack.evidence) == (sample[1].evidence, sample[2].evidence)
    assert (probe.note, attack.note, attack.path) == ("Enumeration", "Attack", "/login")


def test_an_attack_before_the_probe_is_not_a_sequence(tmp_path):
    from logarc.triage.profile import profile_client

    sample = events(count=4)
    sample[1] = replace(sample[1], query="attack")
    sample[2] = replace(sample[2], query="probe")
    assert profile_client(sample, probe_attack_engine(tmp_path)).sequence_sessions == 0


def test_one_request_with_both_labels_is_not_a_sequence(tmp_path):
    from logarc.triage.profile import profile_client

    sample = events(count=4)
    sample[1] = replace(sample[1], query="probe attack")
    assert profile_client(sample, probe_attack_engine(tmp_path)).sequence_sessions == 0


def test_the_ordering_is_counted_once_per_session(tmp_path):
    from logarc.triage.profile import profile_client

    first = events(count=4)
    first[0] = replace(first[0], query="probe")
    first[1] = replace(first[1], query="attack")
    first[2] = replace(first[2], query="probe")
    first[3] = replace(first[3], query="attack")
    second = [at(event, 86_400 + i, line=10 + i) for i, event in enumerate(first)]
    profile = profile_client(first + second, probe_attack_engine(tmp_path))
    assert profile.sequence_sessions == 2


def test_equal_timestamps_never_establish_an_order(tmp_path):
    from logarc.triage.profile import profile_client

    engine = probe_attack_engine(tmp_path)
    base = events(count=2)
    same_file = [
        at(replace(base[0], query="probe"), 5, line=1),
        at(replace(base[1], query="attack"), 5, line=2),
    ]
    assert profile_client(same_file, engine).sequence_sessions == 0
    two_files = [
        replace(same_file[0], evidence=EvidenceRef("a.log", 1)),
        replace(same_file[1], evidence=EvidenceRef("b.log", 2)),
    ]
    assert profile_client(two_files, engine).sequence_sessions == 0


def test_hostile_sessions_and_the_span_of_matching_requests(tmp_path):
    from logarc.triage.profile import profile_client

    engine = probe_attack_engine(tmp_path)
    day = 86_400
    sample = events(count=3)
    sample = [
        at(replace(sample[0], query="attack"), 0, line=1),
        at(sample[1], day, line=2),
        at(replace(sample[2], query="attack"), 3 * day, line=3),
    ]
    profile = profile_client(sample, engine)
    assert (profile.sessions, profile.hostile_sessions) == (3, 2)
    assert profile.first_hostile == sample[0].timestamp.isoformat()
    assert profile.last_hostile == sample[2].timestamp.isoformat()
    assert [example.evidence for example in profile.recurrence_examples] == [
        sample[0].evidence,
        sample[2].evidence,
    ]


def test_flagged_requests_are_counted_per_category_and_per_rule(tmp_path):
    from logarc.triage.profile import profile_client

    engine = probe_attack_engine(tmp_path)
    sample = events(count=5)
    sample[0] = replace(sample[0], query="probe")
    sample[1] = replace(sample[1], query="probe")
    sample[2] = replace(sample[2], query="probe attack")
    profile = profile_client(sample, engine)
    assert profile.category_counts == {"enumeration": 3, "injection": 1}
    assert profile.hostile_rules == {"attack": 1, "probe": 3}
    assert profile.hostile_rule_names == {"attack": "Attack", "probe": "Probe"}


def test_example_requests_keep_their_query(tmp_path):
    from logarc.triage.profile import profile_client

    sample = events(count=4)
    sample[1] = replace(sample[1], query="probe=1", path="/admin/")
    sample[2] = replace(sample[2], query="id=1&attack=union", path="/login")
    probe, attack = profile_client(sample, probe_attack_engine(tmp_path)).sequence_examples
    assert (probe.query, attack.query) == ("probe=1", "id=1&attack=union")


EXCLUDED_FROM_EXPLOIT_EVIDENCE = (
    ("admin_area_probe", "access_control"),
    ("forced_browsing", "access_control"),
    ("forced_browsing_succeeded", "access_control"),
    ("admin_reached_without_signing_in", "access_control"),
    ("server_errors_provoked", "exploitation"),
)


def test_a_quiet_exploit_attempt_precedes_a_loud_probing_client(tmp_path):
    from logarc.triage.profile import profile_client, rank_profiles

    engine = fixture_rules(
        tmp_path,
        ("sweep", "enumeration", "medium", 0.9, "sweep"),
        ("sqli_fixture", "injection", "high", 0.9, "attack"),
    )
    quiet = profile_client(events("192.0.2.9", 1, query="attack"), engine)
    loud = profile_client(events("192.0.2.1", 500, query="sweep"), engine)
    assert loud.exploit_examples == ()
    assert quiet.exploit_rules == ("sqli_fixture",)
    assert [example.note for example in quiet.exploit_examples] == ["Sqli Fixture"]
    assert quiet.exploit_examples[0].evidence == EvidenceRef("source", 1)
    ranked = rank_profiles([loud, quiet], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.9", "192.0.2.1"]


def test_inside_the_exploit_group_more_flagged_requests_come_first(tmp_path):
    from logarc.triage.profile import profile_client, rank_profiles

    engine = fixture_rules(tmp_path, ("sqli_fixture", "injection", "high", 0.9, "attack"))
    few = profile_client(events("192.0.2.1", 2, query="attack"), engine)
    many = profile_client(events("192.0.2.2", 30, query="attack"), engine)
    ranked = rank_profiles([few, many], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.2", "192.0.2.1"]


@pytest.mark.parametrize(("rule_id", "category"), EXCLUDED_FROM_EXPLOIT_EVIDENCE)
def test_an_excluded_rule_alone_does_not_place_a_client_first(tmp_path, rule_id, category):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        (rule_id, category, "high", 0.9, "excluded"),
        ("sqli_fixture", "injection", "high", 0.9, "attack"),
    )
    alone = profile_client(events(count=3, query="excluded"), engine)
    assert alone.hostile_requests == 3
    assert alone.exploit_examples == ()
    assert alone.exploit_rules == ()
    sample = events(count=3, query="excluded")
    sample[2] = replace(sample[2], query="attack")
    with_eligible = profile_client(sample, engine)
    assert with_eligible.exploit_rules == ("sqli_fixture",)


def test_the_earliest_eligible_request_is_the_exploit_example_across_sessions(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        ("zeta_rule", "injection", "high", 0.9, "zeta"),
        ("alpha_rule", "injection", "high", 0.9, "alpha"),
    )
    first, later = events(count=2)
    sample = [
        replace(first, query="zeta"),
        at(replace(later, query="alpha"), 3 * 3600, line=2),
    ]
    profile = profile_client(sample, engine)
    assert profile.sessions == 2
    assert profile.exploit_rules == ("zeta_rule",)
    assert [example.evidence for example in profile.exploit_examples] == [EvidenceRef("source", 1)]


def test_the_strongest_eligible_rule_on_the_request_is_named(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        ("alpha_rule", "injection", "medium", 0.9, "both"),
        ("zeta_rule", "injection", "critical", 0.9, "both"),
    )
    profile = profile_client(events(count=1, query="both"), engine)
    assert profile.exploit_rules == ("zeta_rule",)
    assert [example.note for example in profile.exploit_examples] == ["Zeta Rule"]


def test_an_eligible_match_that_loses_the_label_still_counts(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(
        tmp_path,
        ("scanner_fixture", "reconnaissance", "critical", 0.95, "both"),
        ("sqli_fixture", "injection", "high", 0.9, "both"),
    )
    sample = events(count=1, query="both")
    (labelled,) = engine.label_events(sample)
    assert labelled.label.rule_id == "scanner_fixture"
    profile = profile_client(sample, engine)
    assert profile.exploit_rules == ("sqli_fixture",)


def test_is_exploit_evidence_by_rule_and_category(tmp_path):
    from logarc.core.activity import ActivityCategory
    from logarc.triage.profile import is_exploit_evidence

    engine = fixture_rules(
        tmp_path,
        ("sqli_fixture", "injection", "high", 0.9, "attack"),
        ("recon_fixture", "reconnaissance", "high", 0.9, "recon"),
    )
    (injection,) = engine.label_events(events(count=1, query="attack"))
    (recon,) = engine.label_events(events(count=1, query="recon"))
    assert is_exploit_evidence(injection.label)
    assert not is_exploit_evidence(recon.label)
    crs_label = replace(injection.label, rule_id="crs:942100", category=ActivityCategory.INJECTION)
    assert not is_exploit_evidence(crs_label)


def test_a_crs_label_alone_never_places_a_client_first(tmp_path):
    from logarc.triage.profile import priority_score, profile_client, rank_profiles

    sample = events(count=3)
    profile = profile_client(
        sample, RuleEngine(default_rules()), crs={("source", 1): [crs_detection(level=2)]}
    )
    assert profile.hostile_requests == 1
    assert "injection" in profile.categories
    assert profile.exploit_examples == ()
    assert [row.profile for row in rank_profiles([profile], "suspicious")] == [profile]

    engine = fixture_rules(tmp_path, ("sqli_fixture", "injection", "high", 0.9, "attack"))
    busy = events("192.0.2.9", 20)
    busy[5] = replace(busy[5], query="attack")
    native = profile_client(busy, engine)
    assert priority_score(native) < priority_score(profile)
    ranked = rank_profiles([profile, native], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.9", "192.0.2.1"]


def test_the_same_detection_at_level_one_places_the_client_first(tmp_path):
    from logarc.triage.profile import priority_score, profile_client, rank_profiles

    sample = events(count=3)
    profile = profile_client(
        sample, RuleEngine(default_rules()), crs={("source", 1): [crs_detection(level=1)]}
    )
    assert profile.exploit_rules == ("crs:942100",)
    engine = fixture_rules(tmp_path, ("sqli_fixture", "injection", "high", 0.9, "attack"))
    busy = events("192.0.2.9", 20)
    busy[5] = replace(busy[5], query="attack")
    native = profile_client(busy, engine)
    assert priority_score(native) < priority_score(profile)
    ranked = rank_profiles([profile, native], "suspicious")
    assert [row.profile.client_ip for row in ranked] == ["192.0.2.1", "192.0.2.9"]


def test_a_window_rule_match_is_exploit_evidence():
    from logarc.triage.profile import profile_client

    sample = events(count=5, path="/login", method="POST", status=401)
    profile = profile_client(sample, RuleEngine(default_rules()))
    assert profile.exploit_rules == ("credential_attack",)


def crs_detection(
    line=1,
    rule_id=942100,
    *,
    level=1,
    family="attack-sqli",
    var="ARGS:q",
    value="1 union select",
    severity="critical",
    msg="Fixture detection",
):
    from logarc.detect.crs import CrsDetection

    return CrsDetection(
        source_file_id="source",
        line_no=line,
        rule_id=rule_id,
        severity=severity,
        msg=msg,
        matched_var=var,
        transformed_value=value,
        attack_family=family,
        paranoia_level=level,
    )


@pytest.mark.parametrize(
    ("changes", "trusted", "expected"),
    [
        ({}, False, "injection"),
        ({"level": 2}, False, None),
        ({"level": None}, False, None),
        ({"var": "REQUEST_HEADERS:Referer"}, False, None),
        ({"var": "MATCHED_VARS:REQUEST_HEADERS:Referer"}, False, None),
        ({"value": "${id}"}, False, None),
        ({"rule_id": 913100, "family": "attack-reputation-scanner"}, False, None),
        ({"rule_id": 920250, "family": "attack-protocol"}, False, None),
        ({"rule_id": 931130, "family": "attack-rfi"}, False, None),
        ({"rule_id": 931130, "family": "attack-rfi"}, True, "ssrf"),
    ],
)
def test_crs_exploit_category(changes, trusted, expected):
    from logarc.triage.profile import crs_exploit_category

    category = crs_exploit_category(crs_detection(**changes), site_host_known=trusted)
    assert (category.value if category else None) == expected


def test_a_level_one_detection_alone_names_the_request_and_message():
    from logarc.triage.profile import profile_client

    engine = RuleEngine(default_rules())
    profile = profile_client(events(count=3), engine, crs={("source", 2): [crs_detection(line=2)]})
    assert profile.exploit_rules == ("crs:942100",)
    assert [e.note for e in profile.exploit_examples] == ["Fixture detection"]
    assert [e.evidence for e in profile.exploit_examples] == [EvidenceRef("source", 2)]
    unnamed = profile_client(
        events(count=3), engine, crs={("source", 2): [crs_detection(line=2, msg="")]}
    )
    assert [e.note for e in unnamed.exploit_examples] == ["CRS rule 942100"]


def test_a_level_one_detection_counts_when_a_native_label_won(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(tmp_path, ("recon_fixture", "reconnaissance", "high", 0.9, "probe"))
    sample = events(count=2, query="probe")
    (first, _) = engine.label_events(sample, crs={("source", 1): [crs_detection()]})
    assert first.label.rule_id == "recon_fixture"
    profile = profile_client(sample, engine, crs={("source", 1): [crs_detection()]})
    assert profile.exploit_rules == ("crs:942100",)


def test_a_level_two_rescue_label_is_not_exploit_evidence():
    from logarc.triage.profile import profile_client

    engine = RuleEngine(default_rules())
    script = crs_detection(
        rule_id=930121,
        family="attack-lfi",
        var="REQUEST_HEADERS:User-Agent",
        value="libwww-perl/6.72",
        level=2,
        msg="OS File Access Attempt in REQUEST_FILENAME",
    )
    sample = events(count=2, user_agent="libwww-perl/6.72")
    (first, _) = engine.label_events(sample, crs={("source", 1): [script]})
    assert first.label.rule_id == "crs:930121"
    profile = profile_client(sample, engine, crs={("source", 1): [script]})
    assert profile.hostile_requests == 1
    assert profile.exploit_examples == ()
    assert profile.exploit_rules == ()


def test_native_evidence_is_named_even_when_crs_evidence_came_first(tmp_path):
    from logarc.triage.profile import profile_client

    engine = fixture_rules(tmp_path, ("sqli_fixture", "injection", "high", 0.9, "attack"))
    sample = events(count=3)
    sample[2] = replace(sample[2], query="attack")
    profile = profile_client(sample, engine, crs={("source", 1): [crs_detection()]})
    assert profile.exploit_rules == ("sqli_fixture",)
    assert [e.evidence for e in profile.exploit_examples] == [EvidenceRef("source", 3)]


@pytest.mark.parametrize(
    ("first", "second", "named"),
    [
        ((941100, "attack-xss", "critical"), (942100, "attack-sqli", "warning"), "crs:941100"),
        ((941100, "attack-xss", "critical"), (942100, "attack-sqli", "critical"), "crs:942100"),
    ],
)
def test_the_crs_tie_break_is_severity_then_rule_id(first, second, named):
    from logarc.triage.profile import profile_client

    detections = [
        crs_detection(rule_id=rule, family=family, severity=severity)
        for rule, family, severity in (first, second)
    ]
    profile = profile_client(
        events(count=1), RuleEngine(default_rules()), crs={("source", 1): detections}
    )
    assert profile.exploit_rules == (named,)


def test_only_the_eligible_detection_on_a_request_is_named():
    from logarc.triage.profile import profile_client

    detections = [
        crs_detection(rule_id=942999, var="REQUEST_HEADERS:Referer"),
        crs_detection(rule_id=942998, level=2),
        crs_detection(rule_id=942100),
    ]
    profile = profile_client(
        events(count=1), RuleEngine(default_rules()), crs={("source", 1): detections}
    )
    assert profile.exploit_rules == ("crs:942100",)


def test_crs_exploit_evidence_changes_nothing_else_about_the_profile():
    from logarc.triage.profile import priority_score, profile_client

    engine = RuleEngine(default_rules())
    sample = events(count=3)
    at_one = profile_client(sample, engine, crs={("source", 2): [crs_detection(line=2, level=1)]})
    at_two = profile_client(sample, engine, crs={("source", 2): [crs_detection(line=2, level=2)]})
    assert at_one.exploit_rules == ("crs:942100",)
    assert at_two.exploit_rules == ()
    assert replace(at_one, exploit_examples=(), exploit_rules=()) == at_two
    assert priority_score(at_one) == priority_score(at_two)
