"""Scoring arithmetic, checked against cases whose answers are obvious by hand."""

from __future__ import annotations

import pytest

from logarc.core.activity import ActivityCategory as Category
from logarc.evaluation.metrics import (
    Prediction,
    score_binary,
    score_classification,
    score_segmentation,
)


def guess(
    truth: Category, predicted: Category, considered: set[Category] | None = None
) -> Prediction:
    return Prediction(
        truth=truth,
        predicted=predicted,
        considered=frozenset(considered or {predicted}),
    )


# -- classification ----------------------------------------------------------


def test_a_perfect_classifier_scores_one_everywhere() -> None:
    report = score_classification(
        [
            guess(Category.INJECTION, Category.INJECTION),
            guess(Category.BROWSING, Category.BROWSING),
            guess(Category.BROWSING, Category.BROWSING),
        ]
    )

    assert report.accuracy == 1.0
    assert report.macro_f1 == 1.0
    for score in report.scores:
        assert (score.precision, score.recall, score.f1) == (1.0, 1.0, 1.0)


def test_counts_are_split_into_hits_and_both_kinds_of_miss() -> None:
    report = score_classification(
        [
            guess(Category.INJECTION, Category.INJECTION),
            guess(Category.INJECTION, Category.BROWSING),  # missed
            guess(Category.BROWSING, Category.INJECTION),  # false alarm
            guess(Category.BROWSING, Category.BROWSING),
        ]
    )
    injection = report.for_category(Category.INJECTION)

    assert (injection.support, injection.predicted) == (2, 2)
    assert (injection.true_positives, injection.false_positives) == (1, 1)
    assert injection.false_negatives == 1
    assert injection.precision == 0.5
    assert injection.recall == 0.5
    assert injection.f1 == 0.5


def test_a_category_that_is_never_predicted_scores_zero_rather_than_dividing_by_zero() -> None:
    report = score_classification([guess(Category.SSRF, Category.BROWSING)])
    ssrf = report.for_category(Category.SSRF)

    assert ssrf.support == 1
    assert ssrf.predicted == 0
    assert (ssrf.precision, ssrf.recall, ssrf.f1) == (0.0, 0.0, 0.0)


def test_the_confusion_matrix_says_what_a_category_was_mistaken_for() -> None:
    report = score_classification(
        [
            guess(Category.ENUMERATION, Category.RECONNAISSANCE),
            guess(Category.ENUMERATION, Category.RECONNAISSANCE),
            guess(Category.ENUMERATION, Category.ENUMERATION),
        ]
    )

    assert report.confusion[Category.ENUMERATION, Category.RECONNAISSANCE] == 2
    assert report.confusion[Category.ENUMERATION, Category.ENUMERATION] == 1
    assert report.top_confusions()[0] == (
        Category.ENUMERATION,
        Category.RECONNAISSANCE,
        2,
    )


def test_a_secondary_match_counts_towards_lenient_recall_only() -> None:
    """A request can honestly be two things; the graph shows one of them.

    Strict recall scores the label that reached the graph. Lenient recall says
    whether the right answer was found at all, which separates a rule that
    never fires from one that fires and is outranked.
    """
    report = score_classification(
        [
            guess(
                Category.SSRF, Category.INJECTION, considered={Category.INJECTION, Category.SSRF}
            ),
        ]
    )
    ssrf = report.for_category(Category.SSRF)

    assert ssrf.recall == 0.0
    assert ssrf.recall_any == 1.0


def test_macro_averaging_covers_only_the_categories_the_truth_contains() -> None:
    """A category that was never in the log cannot have a meaningful recall.

    It still appears in the table, so its false alarms are visible; it just
    does not drag the average toward zero for a behaviour nobody generated.
    """
    report = score_classification(
        [
            guess(Category.BROWSING, Category.BROWSING),
            guess(Category.BROWSING, Category.SSRF),
        ]
    )

    browsing = report.for_category(Category.BROWSING)
    assert browsing.f1 == pytest.approx(2 / 3)
    assert report.macro_f1 == pytest.approx(2 / 3)
    assert report.for_category(Category.SSRF).support == 0
    assert report.for_category(Category.SSRF).false_positives == 1


def test_weighted_averaging_follows_how_common_each_category_is() -> None:
    report = score_classification(
        [guess(Category.BROWSING, Category.BROWSING)] * 9
        + [guess(Category.INJECTION, Category.BROWSING)]
    )

    # Browsing: precision 9/10, recall 1 -> F1 0.947...; injection: 0.
    assert report.weighted_f1 == pytest.approx(0.9 * (2 * 0.9 / 1.9))
    assert report.macro_f1 == pytest.approx((2 * 0.9 / 1.9) / 2)


def test_scoring_nothing_is_empty_rather_than_an_error() -> None:
    report = score_classification([])

    assert report.total == 0
    assert report.accuracy == 0.0
    assert report.macro_f1 == 0.0
    assert report.scores == ()


# -- segmentation ------------------------------------------------------------


def test_segmentation_that_matches_the_truth_exactly_scores_one() -> None:
    report = score_segmentation([[("a", "1"), ("a", "1"), ("b", "2"), ("b", "2")]])

    assert report.boundary_precision == 1.0
    assert report.boundary_recall == 1.0
    assert report.boundary_f1 == 1.0
    assert report.truth_activities == 2
    assert report.predicted_episodes == 2


def test_merging_two_activities_costs_recall_but_not_precision() -> None:
    """Noise absorption merges on purpose, so this is the shape of that cost."""
    report = score_segmentation([[("a", "1"), ("a", "1"), ("b", "1"), ("b", "1")]])

    assert report.boundaries_expected == 1
    assert report.boundaries_found == 0
    assert report.boundary_recall == 0.0
    assert report.boundary_precision == 0.0  # nothing found, so nothing correct
    assert report.truth_activities == 2
    assert report.predicted_episodes == 1


def test_splitting_one_activity_costs_precision_but_not_recall() -> None:
    report = score_segmentation([[("a", "1"), ("a", "2"), ("a", "2"), ("b", "3")]])

    assert report.boundaries_expected == 1
    assert report.boundaries_found == 2
    assert report.boundaries_agreed == 1
    assert report.boundary_recall == 1.0
    assert report.boundary_precision == 0.5


def test_a_client_with_one_request_offers_no_boundary_to_judge() -> None:
    report = score_segmentation([[("a", "1")]])

    assert report.boundaries_expected == 0
    assert report.boundaries_found == 0
    assert report.boundary_f1 == 0.0
    assert report.truth_activities == 1


def test_clients_are_scored_independently_of_each_other() -> None:
    """The gap between two clients is not a boundary either of them missed."""
    report = score_segmentation([[("a", "1"), ("a", "1")], [("b", "2"), ("b", "2")]])

    assert report.boundaries_expected == 0
    assert report.boundaries_found == 0
    assert report.truth_activities == 2
    assert report.predicted_episodes == 2


def test_the_fragmentation_ratio_says_whether_the_graph_got_coarser() -> None:
    report = score_segmentation([[("a", "1"), ("b", "1"), ("c", "2")]])

    assert report.truth_activities == 3
    assert report.predicted_episodes == 2
    assert report.fragmentation == pytest.approx(2 / 3)


def test_scoring_no_clients_is_empty_rather_than_an_error() -> None:
    report = score_segmentation([])

    assert report.truth_activities == 0
    assert report.fragmentation == 0.0
    assert report.boundary_f1 == 0.0


def test_a_clean_corpus_reports_attack_scores_as_undefined_not_zero() -> None:
    """Precision and recall over a corpus with no attacks in it are 0/0.

    Printing them as 0.000 tells whoever ran the clean-traffic control that
    detection failed completely, when in fact there was nothing to detect and
    nothing was wrongly flagged. A number that looks like a result and is not
    one is the worst thing an evaluation can produce.
    """
    score = score_binary([(False, False)] * 100)

    assert not score.has_attacks
    assert score.false_positive_rate == 0.0
    assert score.accuracy == 1.0


def test_a_corpus_with_attacks_is_scored_normally() -> None:
    score = score_binary([(True, True)] * 8 + [(True, False)] * 2 + [(False, False)] * 90)

    assert score.has_attacks
    assert score.recall == pytest.approx(0.8)
    assert score.precision == pytest.approx(1.0)
