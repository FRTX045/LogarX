from dataclasses import replace

import pytest
from test_triage_evaluation import population


def test_candidates_have_bounded_severity_and_keep_quiet_clients():
    from zodiarc.evaluation.priorities import suspicious_candidates

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
    from zodiarc.evaluation.priorities import suspicious_candidates
    from zodiarc.triage.profile import rank_profiles

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
    from zodiarc.evaluation.priorities import audit_unusual, unusual_candidates

    base = population()[0]
    profiles = [replace(base, client_ip=str(i)) for i in range(100)]
    assert all(not order for order in unusual_candidates(profiles).values())
    assert audit_unusual(profiles)["ip_dependent_positions"]["10"] == 0


def test_complete_vector_ties_cross_budgets_but_single_feature_ties_need_not():
    from zodiarc.evaluation.priorities import audit_unusual

    profiles = population()
    profiles[-1] = replace(profiles[0], client_ip=profiles[-1].client_ip)
    result = audit_unusual(profiles)
    assert result["complete_vector_tie_groups"] > 0
    assert result["ip_dependent_positions"]["10"] == 10
    assert result["boundary_ties"]["10"] > 0


def test_gate_rejects_head_gain_that_loses_quiet_attacks():
    from zodiarc.evaluation.priorities import promotion_gate

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


def test_bonus_parts_are_capped_as_frozen():
    from zodiarc.evaluation.priorities import bonus_parts

    base = population()[0]
    assert bonus_parts(replace(base, distinct_rule_pairs=5, sequence_sessions=3))[:2] == (3, 1)
    assert bonus_parts(replace(base, distinct_rule_pairs=0, sequence_sessions=0))[:2] == (0, 0)
    for sessions, expected in ((0, 0.0), (1, 0.0), (2, 0.5), (5, 2.0), (9, 2.0)):
        assert bonus_parts(replace(base, hostile_sessions=sessions))[2] == expected


def test_c2_caps_only_the_logarithmic_support_term():
    import pytest

    from zodiarc.evaluation.priorities import c1_score, c2_score

    base = replace(
        population()[0],
        hostile_requests=40,
        requests=80,
        severity=4,
        distinct_rule_pairs=0,
        sequence_sessions=0,
        hostile_sessions=1,
    )
    assert c2_score(base) == pytest.approx(5 * 2 * 0.75)
    from math import log2

    assert c1_score(base) == pytest.approx(log2(41) * 2 * 0.75)
    diluted = replace(base, requests=160)
    assert c2_score(diluted) == pytest.approx(5 * 2 * (0.5 + 0.5 * 40 / 160))


def test_bonuses_let_a_low_support_client_pass_a_bare_one():
    from zodiarc.evaluation.priorities import graded_orderings
    from zodiarc.triage.profile import rank_profiles

    base = population()[0]
    quiet = replace(
        base,
        client_ip="quiet",
        hostile_requests=3,
        requests=50,
        severity=4,
        distinct_rule_pairs=3,
        sequence_sessions=1,
        hostile_sessions=1,
    )
    bare = replace(
        base,
        client_ip="bare",
        hostile_requests=20,
        requests=20,
        severity=1,
        distinct_rule_pairs=0,
        sequence_sessions=0,
        hostile_sessions=1,
    )
    orders = graded_orderings([quiet, bare])
    assert orders["policy3"] == [
        r.profile.client_ip for r in rank_profiles([quiet, bare], "suspicious")
    ]
    assert orders["policy3"] == ["bare", "quiet"]
    assert orders["c1"] == orders["c2"] == ["quiet", "bare"]


def test_orderings_that_rank_different_clients_are_refused():
    import pytest

    from zodiarc.evaluation.priorities import assert_same_ranked

    assert_same_ranked({"policy3": ["a", "b"], "c1": ["b", "a"]})
    with pytest.raises(ValueError, match="same clients"):
        assert_same_ranked({"policy3": ["a", "b"], "c1": ["a"]})


def graded(order, grades):
    from test_graded import truth_of

    from zodiarc.evaluation.graded import graded_scores

    return graded_scores(order, truth_of(grades))


POPULATION = {f"t{i}": 2 for i in range(4)} | {f"b{i}": 0 for i in range(60)}


def head(*targeted, benign_first=0):
    """An order with `benign_first` benign clients, then the named targeted ones, then the rest."""
    benign = [f"b{i}" for i in range(60)]
    rest = [f"t{i}" for i in range(4) if f"t{i}" not in targeted]
    return benign[:benign_first] + list(targeted) + benign[benign_first:] + rest


def test_development_selection_follows_the_frozen_order():
    from zodiarc.evaluation.graded import choose_graded

    def dev(c1, c2):
        return {"d": {"c1": graded(c1, POPULATION), "c2": graded(c2, POPULATION)}}

    assert choose_graded(dev(head("t0", benign_first=10), head("t0"))) == "c2"
    assert choose_graded(dev(head("t0", benign_first=30), head("t0", benign_first=12))) == "c2"
    assert choose_graded(dev(head("t0", benign_first=55), head("t0", benign_first=52))) == "c2"
    assert choose_graded(dev(head("t0"), head("t0"))) == "c1"


def test_the_gate_promotes_a_challenger_that_passes_all_three_checks():
    from zodiarc.evaluation.graded import graded_gate

    baseline = {"h": graded(head("t0", "t1", benign_first=8), POPULATION)}
    challenger = {"h": graded(head("t0", "t1", "t2", benign_first=5), POPULATION)}
    result = graded_gate(baseline, challenger, {"h": frozenset({"t0"})})
    assert result["promote"] is True
    assert result["rank_changes"]["h"]["t0"] == (9, 6)


def test_the_gate_refuses_a_challenger_whose_head_does_not_improve():
    from zodiarc.evaluation.graded import graded_gate

    same = graded(head("t0", "t1"), POPULATION)
    result = graded_gate({"h": same}, {"h": same}, {"h": frozenset()})
    assert result["promote"] is False
    assert result["checks"]["head_yield"] is False


def test_the_gate_refuses_a_low_support_client_leaving_its_tier():
    from zodiarc.evaluation.graded import graded_gate

    benign = [f"b{i}" for i in range(60)]
    baseline = {"h": graded(head("t0", "t1", benign_first=7), POPULATION)}
    challenger = {"h": graded(["t1", "t2", *benign[:9], "t0", *benign[9:], "t3"], POPULATION)}
    assert (baseline["h"].ranks["t0"], challenger["h"].ranks["t0"]) == (8, 12)
    result = graded_gate(baseline, challenger, {"h": frozenset({"t0"})})
    assert result["checks"]["head_yield"] is True
    assert result["checks"]["benign_head"] is True
    assert result["checks"]["low_support_tiers"] is False
    assert result["promote"] is False


def test_the_gate_refuses_more_benign_clients_at_the_head_of_any_build():
    from zodiarc.evaluation.graded import graded_gate

    baseline = {
        "h1": graded(head("t0", "t1", benign_first=8), POPULATION),
        "h2": graded(head("t0"), POPULATION),
    }
    challenger = {
        "h1": graded(head("t0", "t1", "t2", "t3"), POPULATION),
        "h2": graded(head("t0", benign_first=10), POPULATION),
    }
    assert baseline["h2"].benign_at[10] == 9 and challenger["h2"].benign_at[10] == 10
    result = graded_gate(baseline, challenger, {"h1": frozenset(), "h2": frozenset()})
    assert result["checks"]["head_yield"] is True
    assert result["checks"]["benign_head"] is False
    assert result["promote"] is False


def exploit_fixture(tmp_path):
    """An injection client, a client matching only an excluded-id access-control rule, and a
    loud client that only probes, profiled by one engine."""
    import test_profiles as helpers

    from zodiarc.triage.profile import NOT_EXPLOIT_EVIDENCE, TARGETED, profile_client

    engine = helpers.fixture_rules(
        tmp_path,
        ("sqli_probe", "injection", 3, 0.9, "union"),
        ("admin_area_probe", "access_control", 3, 0.9, "admin"),
        ("noisy_scan", "reconnaissance", 4, 0.9, "scan"),
    )
    fields = {"path": "/"}
    profiles = [
        profile_client(helpers.events("192.0.2.1", 3, query="q=union", **fields), engine),
        profile_client(helpers.events("192.0.2.2", 2, query="q=admin", **fields), engine),
        profile_client(helpers.events("192.0.2.3", 20, query="q=scan", **fields), engine),
    ]
    category_rules = frozenset(r.id for r in engine.rules if r.category in TARGETED)
    return profiles, category_rules, category_rules - NOT_EXPLOIT_EVIDENCE


def test_exploit_orderings_place_each_tier_and_the_application_agrees(tmp_path):
    from zodiarc.evaluation.priorities import assert_same_ranked, exploit_orderings

    profiles, category_rules, eligible = exploit_fixture(tmp_path)
    orders = exploit_orderings(profiles, category_rules=category_rules, eligible_rules=eligible)
    assert set(orders) == {"policy3", "exploit_first", "category_only", "app"}
    assert_same_ranked(orders)
    assert set(orders["category_only"][:2]) == {"192.0.2.1", "192.0.2.2"}
    assert orders["exploit_first"][0] == "192.0.2.1"
    assert orders["policy3"][0] == "192.0.2.3"
    assert orders["exploit_first"] == orders["app"]


def test_exploit_orderings_require_both_rule_sets(tmp_path):
    from zodiarc.evaluation.priorities import exploit_orderings

    profiles, category_rules, eligible = exploit_fixture(tmp_path)
    with pytest.raises(TypeError):
        exploit_orderings(profiles, eligible_rules=eligible)  # type: ignore[call-arg]
    with pytest.raises(TypeError):
        exploit_orderings(profiles, category_rules=category_rules)  # type: ignore[call-arg]


def test_exploit_orderings_place_a_crs_level_one_client_first_as_the_application_does(tmp_path):
    import test_profiles as helpers

    from zodiarc.detect.engine import RuleEngine
    from zodiarc.detect.rulepacks import default_rules
    from zodiarc.evaluation.priorities import exploit_orderings
    from zodiarc.triage.profile import profile_client

    profiles, category_rules, eligible = exploit_fixture(tmp_path)
    detection = helpers.crs_detection(line=1)
    placed = profile_client(
        helpers.events("192.0.2.4", 30, path="/"),
        RuleEngine(default_rules()),
        crs={("source", 1): [detection]},
    )
    assert placed.exploit_rules == ("crs:942100",)
    orders = exploit_orderings(
        [*profiles, placed], category_rules=category_rules, eligible_rules=eligible
    )
    assert set(orders["exploit_first"][:2]) == {"192.0.2.1", "192.0.2.4"}
    assert orders["exploit_first"] == orders["app"]
