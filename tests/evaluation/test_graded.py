from math import log2

import pytest

from logarc.core.activity import ActivityCategory as C
from logarc.evaluation.truth import TruthRecord


def records(*rows):
    """(ip, category) pairs as truth records, one line each."""
    return [
        TruthRecord(line, ip, category, f"{ip}#1") for line, (ip, category) in enumerate(rows, 1)
    ]


def truth_of(grades):
    from logarc.evaluation.graded import ClientTruth

    return {ip: ClientTruth(grade, hostile=grade, requests=10) for ip, grade in grades.items()}


def test_grades_come_from_truth_categories_alone():
    from logarc.evaluation.graded import ClientTruth, client_truth

    truth = client_truth(
        records(
            ("t", C.RECONNAISSANCE),
            ("t", C.INJECTION),
            ("t", C.BROWSING),
            ("p", C.ENUMERATION),
            ("p", C.BROWSING),
            ("b", C.BROWSING),
            ("x", C.UNKNOWN),
        ),
        exclusions={"x": "unknown request ground truth"},
    )
    assert truth == {
        "t": ClientTruth(2, hostile=2, requests=3),
        "p": ClientTruth(1, hostile=1, requests=2),
        "b": ClientTruth(0, hostile=0, requests=1),
    }


def test_low_support_targeted_clients_have_at_most_five_hostile_truth_requests():
    from logarc.evaluation.graded import ClientTruth, low_support

    truth = {
        "quiet": ClientTruth(2, hostile=5, requests=400),
        "loud": ClientTruth(2, hostile=6, requests=20),
        "probe": ClientTruth(1, hostile=1, requests=3),
    }
    assert low_support(truth) == frozenset({"quiet"})


def test_yield_is_per_slot_and_recall_per_targeted_client():
    from logarc.evaluation.graded import graded_scores

    grades = {f"t{i}": 2 for i in range(7)} | {f"b{i}": 0 for i in range(893)}
    order = [f"t{i}" for i in range(7)] + [f"b{i}" for i in range(20)]
    scores = graded_scores(order, truth_of(grades))
    assert scores.judged == 900
    assert scores.yield_at[10] == pytest.approx(0.7)
    assert scores.recall_at[10] == pytest.approx(1.0)
    assert scores.benign_at == {10: 3, 25: 18, 50: 20}
    assert scores.mean_targeted_rank == pytest.approx(4.0)


def test_an_unranked_targeted_client_counts_as_judged_plus_one():
    from logarc.evaluation.graded import graded_scores

    grades = {"t1": 2, "t2": 2, "b": 0, "p": 1}
    scores = graded_scores(["t1", "p"], truth_of(grades))
    assert scores.ranks["t2"] is None
    assert scores.unranked_targeted == ("t2",)
    assert scores.mean_targeted_rank == pytest.approx((1 + 5) / 2)


@pytest.mark.parametrize(
    ("rank", "expected"),
    [(1, 0), (10, 0), (11, 1), (25, 1), (26, 2), (50, 2), (51, 3), (None, 3)],
)
def test_tiers_are_within_10_25_50_or_beyond(rank, expected):
    from logarc.evaluation.graded import tier

    assert tier(rank) == expected


def test_ndcg_uses_the_grade_as_gain():
    from logarc.evaluation.graded import graded_scores

    scores = graded_scores(["c", "a", "b"], truth_of({"a": 2, "b": 1, "c": 0, "d": 0}))
    dcg = 2 / log2(3) + 1 / log2(4)
    ideal = 2 / log2(2) + 1 / log2(3)
    assert scores.ndcg_at[10] == pytest.approx(dcg / ideal)


def test_without_targeted_clients_recall_and_rank_are_undefined():
    from logarc.evaluation.graded import graded_scores

    scores = graded_scores(["b1", "b2"], truth_of({"b1": 0, "b2": 0, "b3": 0}))
    assert scores.recall_at == {10: None, 25: None, 50: None}
    assert scores.mean_targeted_rank is None
    assert scores.benign_at[10] == 2
    assert scores.yield_at[10] == pytest.approx(0.0)


def test_zero_ideal_gain_leaves_ndcg_undefined():
    from logarc.evaluation.graded import graded_scores

    scores = graded_scores(["b1"], truth_of({"b1": 0, "b2": 0}))
    assert scores.ndcg_at == {10: None, 25: None, 50: None}


def test_probe_only_clients_keep_ndcg_defined_without_targeted_clients():
    from logarc.evaluation.graded import graded_scores

    scores = graded_scores(["p", "b"], truth_of({"p": 1, "b": 0}))
    assert scores.mean_targeted_rank is None
    assert scores.ndcg_at[10] == pytest.approx(1.0)


def test_an_empty_judged_population_has_no_yield():
    from logarc.evaluation.graded import graded_scores

    scores = graded_scores([], {})
    assert scores.yield_at == {10: None, 25: None, 50: None}


def test_an_unjudged_ip_is_refused():
    from logarc.evaluation.graded import graded_scores

    with pytest.raises(ValueError, match="judgment"):
        graded_scores(["stranger"], truth_of({"b": 0}))


def test_a_repeated_ip_is_refused():
    from logarc.evaluation.graded import graded_scores

    with pytest.raises(ValueError, match="repeat"):
        graded_scores(["b", "b"], truth_of({"b": 0}))
