from dataclasses import replace

from test_triage_evaluation import population


def test_candidates_have_bounded_severity_and_keep_quiet_clients():
    from logarc.evaluation.priorities import suspicious_candidates

    base = population()[0]
    single = replace(base, client_ip="single", severity=4, hostile_requests=1, requests=1)
    sustained = replace(
        base, client_ip="sustained", severity=3, hostile_requests=1000, requests=1000
    )
    orders = suspicious_candidates([single, sustained])
    assert orders["suspicious"] == ["single", "sustained"]
    for name in ("support", "weighted", "share"):
        assert orders[name] == ["sustained", "single"]


def test_shipped_order_and_share_experiment_preserve_support_fraction_and_ties():
    from logarc.evaluation.priorities import suspicious_candidates
    from logarc.triage.profile import rank_profiles

    base = population()[0]
    profiles = [
        replace(base, client_ip="b-tied", hostile_requests=3, requests=6, severity=4),
        replace(base, client_ip="z-concentrated", hostile_requests=3, requests=3, severity=4),
        replace(base, client_ip="a-diluted", hostile_requests=3, requests=6, severity=4),
        replace(base, client_ip="quiet", hostile_requests=1, requests=1, severity=4),
    ]
    expected = ["z-concentrated", "a-diluted", "b-tied", "quiet"]
    assert [row.profile.client_ip for row in rank_profiles(profiles, "suspicious")] == expected
    assert suspicious_candidates(profiles)["share"] == expected


def test_uniform_population_has_no_unusual_findings_or_ip_tiebreak_positions():
    from logarc.evaluation.priorities import audit_unusual, unusual_candidates

    base = population()[0]
    profiles = [replace(base, client_ip=str(i)) for i in range(100)]
    assert all(not order for order in unusual_candidates(profiles).values())
    assert audit_unusual(profiles)["ip_dependent_positions"]["10"] == 0


def test_complete_vector_ties_cross_budgets_but_single_feature_ties_need_not():
    from logarc.evaluation.priorities import audit_unusual

    profiles = population()
    profiles[-1] = replace(profiles[0], client_ip=profiles[-1].client_ip)
    result = audit_unusual(profiles)
    assert result["complete_vector_tie_groups"] > 0
    assert result["ip_dependent_positions"]["10"] == 10
    assert result["boundary_ties"]["10"] > 0


def test_gate_rejects_head_gain_that_loses_quiet_attacks():
    from logarc.evaluation.priorities import promotion_gate

    baseline = {
        str(seed): {"yield10": 0.5, "yield25": 0.6, "yield50": 0.8, "quiet50": 0.2, "hits10": 5}
        for seed in (41, 53, 67, 71)
    }
    winner = {
        seed: {**values, "yield10": 0.7, "hits10": 7, "quiet50": 0.1}
        for seed, values in baseline.items()
    }
    result = promotion_gate(baseline, winner)
    assert not result["promote"]
    assert not result["checks"]["quiet_recall_50"]
    winner = {seed: {**values, "quiet50": 0.2} for seed, values in winner.items()}
    assert promotion_gate(baseline, winner)["promote"]
