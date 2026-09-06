"""How well the reconstruction did, in numbers.

Two questions are scored separately, because they are the two halves of the
problem and a tool can be good at one and bad at the other:

* **Classification** — was each request understood correctly? Reported per
  category as precision, recall and F1, so a category the tool is bad at cannot
  hide inside an overall average.
* **Segmentation** — were the joins between one activity and the next found in
  the right places? Scored over adjacent pairs of requests: for each pair the
  truth either does or does not put a boundary there, and so does the tool.
  That treats a merge and a split as different mistakes, which they are.

Segmentation recall is expected to be below one. Noise absorption removes
boundaries deliberately — a favicon fetched in the middle of an attack must not
split it into three activities — so some boundaries the truth contains are ones
the tool is right to drop. The number is reported rather than defended.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from logarc.core.activity import ActivityCategory

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "BinaryScore",
    "CategoryScore",
    "ClassificationReport",
    "Prediction",
    "SegmentationReport",
    "score_binary",
    "score_classification",
    "score_segmentation",
]


def _ratio(numerator: float, denominator: float) -> float:
    """Zero rather than an exception when there is nothing to divide."""
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True, slots=True)
class Prediction:
    """What one request really was, and what the tool made of it."""

    truth: ActivityCategory

    predicted: ActivityCategory
    """The label that reached the graph — the most severe match."""

    considered: frozenset[ActivityCategory]
    """Every category that matched, including the ones that were outranked.

    A request can honestly be two things at once. Keeping the full set makes it
    possible to distinguish a rule that never fired from one that fired and lost
    a precedence contest, which are different defects with different fixes.
    """


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """One row of the accuracy table."""

    category: ActivityCategory
    support: int
    predicted: int
    true_positives: int
    false_positives: int
    false_negatives: int
    recovered: int
    """Truth items whose category appeared among the matches, ranked or not."""

    @property
    def precision(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return _ratio(2 * precision * recall, precision + recall)

    @property
    def recall_any(self) -> float:
        return _ratio(self.recovered, self.support)


@dataclass(frozen=True, slots=True)
class ClassificationReport:
    """Per-category accuracy over every request that was scored."""

    scores: tuple[CategoryScore, ...]
    confusion: Mapping[tuple[ActivityCategory, ActivityCategory], int]
    total: int
    correct: int

    def for_category(self, category: ActivityCategory) -> CategoryScore:
        for score in self.scores:
            if score.category is category:
                return score
        raise KeyError(f"{category.value} was neither expected nor predicted")

    @property
    def accuracy(self) -> float:
        return _ratio(self.correct, self.total)

    @property
    def macro_f1(self) -> float:
        """F1 averaged over the categories the log actually contained.

        Categories with no support still appear in the table, so their false
        alarms are visible, but they are left out of the average: a recall of
        zero for a behaviour nobody generated is not a fact about the tool.
        """
        present = [score.f1 for score in self.scores if score.support]
        return sum(present) / len(present) if present else 0.0

    @property
    def weighted_f1(self) -> float:
        """F1 weighted by how common each category was."""
        support = sum(score.support for score in self.scores)
        if not support:
            return 0.0
        return sum(score.f1 * score.support for score in self.scores) / support

    def top_confusions(
        self, limit: int = 10
    ) -> list[tuple[ActivityCategory, ActivityCategory, int]]:
        """The most frequent mistakes, worst first."""
        wrong = [
            (truth, predicted, count)
            for (truth, predicted), count in self.confusion.items()
            if truth is not predicted
        ]
        wrong.sort(key=lambda item: (-item[2], item[0].value, item[1].value))
        return wrong[:limit]


def score_classification(predictions: Iterable[Prediction]) -> ClassificationReport:
    """Score per-request labelling against what the requests really were."""
    truth_counts: Counter[ActivityCategory] = Counter()
    predicted_counts: Counter[ActivityCategory] = Counter()
    hits: Counter[ActivityCategory] = Counter()
    recovered: Counter[ActivityCategory] = Counter()
    confusion: Counter[tuple[ActivityCategory, ActivityCategory]] = Counter()
    total = 0

    for item in predictions:
        total += 1
        truth_counts[item.truth] += 1
        predicted_counts[item.predicted] += 1
        confusion[item.truth, item.predicted] += 1
        if item.truth is item.predicted:
            hits[item.truth] += 1
        if item.truth in item.considered:
            recovered[item.truth] += 1

    seen = set(truth_counts) | set(predicted_counts)
    scores = tuple(
        CategoryScore(
            category=category,
            support=truth_counts[category],
            predicted=predicted_counts[category],
            true_positives=hits[category],
            false_positives=predicted_counts[category] - hits[category],
            false_negatives=truth_counts[category] - hits[category],
            recovered=recovered[category],
        )
        # Ordered by how much of the log the category accounts for, so the rows
        # that carry the most weight are read first.
        for category in sorted(seen, key=lambda item: (-truth_counts[item], item.value))
    )

    return ClassificationReport(
        scores=scores,
        confusion=dict(confusion),
        total=total,
        correct=sum(hits.values()),
    )


@dataclass(frozen=True, slots=True)
class BinaryScore:
    """Attack or not, for sources that cannot say more.

    A labelled public dataset marks a request as anomalous without saying which
    technique it is, so per-category figures cannot be computed from it. This is
    the whole of what such a dataset can honestly support.
    """

    total: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        precision, recall = self.precision, self.recall
        return _ratio(2 * precision * recall, precision + recall)

    @property
    def accuracy(self) -> float:
        return _ratio(self.true_positives + self.true_negatives, self.total)

    @property
    def false_positive_rate(self) -> float:
        """How much ordinary traffic gets flagged — the cost of using the tool."""
        return _ratio(self.false_positives, self.false_positives + self.true_negatives)

    @property
    def has_attacks(self) -> bool:
        """Whether the truth holds a hostile request at all.

        Without one, precision and recall are 0/0 — undefined, not zero — and
        anything that prints them as 0.000 tells whoever ran a clean-traffic
        control that detection failed completely, when nothing was there to
        detect and nothing was wrongly flagged. A figure that looks like a
        result and is not one is the worst thing an evaluation can emit, so
        callers are given the means to say so instead.
        """
        return (self.true_positives + self.false_negatives) > 0

    def to_dict(self) -> dict[str, float | int]:
        return {
            "total": self.total,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "false_positive_rate": self.false_positive_rate,
            "has_attacks": self.has_attacks,
        }


def score_binary(judgements: Iterable[tuple[bool, bool]]) -> BinaryScore:
    """Score `(was hostile, was called hostile)` pairs."""
    counts = Counter(judgements)
    return BinaryScore(
        total=sum(counts.values()),
        true_positives=counts[True, True],
        false_positives=counts[False, True],
        true_negatives=counts[False, False],
        false_negatives=counts[True, False],
    )


@dataclass(frozen=True, slots=True)
class SegmentationReport:
    """Whether activities were separated in the right places."""

    truth_activities: int
    predicted_episodes: int
    boundaries_expected: int
    boundaries_found: int
    boundaries_agreed: int

    @property
    def boundary_precision(self) -> float:
        return _ratio(self.boundaries_agreed, self.boundaries_found)

    @property
    def boundary_recall(self) -> float:
        return _ratio(self.boundaries_agreed, self.boundaries_expected)

    @property
    def boundary_f1(self) -> float:
        precision, recall = self.boundary_precision, self.boundary_recall
        return _ratio(2 * precision * recall, precision + recall)

    @property
    def fragmentation(self) -> float:
        """Episodes produced per activity the log contained.

        Below one means the graph is coarser than the truth, which is what
        absorption is for. Well above one means it is fragmented, which is the
        failure the episode builder exists to prevent.
        """
        return _ratio(self.predicted_episodes, self.truth_activities)


def score_segmentation(clients: Iterable[Sequence[tuple[str, str]]]) -> SegmentationReport:
    """Score activity boundaries, one client at a time.

    Each client is its own sequence of `(true activity, reconstructed episode)`
    in request order. Scoring per client rather than over the whole log matters:
    the gap between two different clients is not a boundary either of them was
    supposed to find.
    """
    truth_activities: set[str] = set()
    predicted_episodes: set[str] = set()
    expected = found = agreed = 0

    for sequence in clients:
        for index, (truth, predicted) in enumerate(sequence):
            truth_activities.add(truth)
            predicted_episodes.add(predicted)
            if index == 0:
                continue
            previous_truth, previous_predicted = sequence[index - 1]
            is_expected = truth != previous_truth
            is_found = predicted != previous_predicted
            expected += is_expected
            found += is_found
            agreed += is_expected and is_found

    return SegmentationReport(
        truth_activities=len(truth_activities),
        predicted_episodes=len(predicted_episodes),
        boundaries_expected=expected,
        boundaries_found=found,
        boundaries_agreed=agreed,
    )
