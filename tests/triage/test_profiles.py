from dataclasses import replace
from datetime import UTC, datetime, timedelta

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
    assert "1,000 of 1,000" in rows[0].reasons[0].text
    assert rows[0].reasons[0].evidence == base.reasons[0].evidence
    assert rows[0].reasons[1:] == base.reasons
    assert DEFAULT_POLICY.version == 3


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
