"""Running the real reconstruction over a known log and scoring the result.

Deliberately no shortcut: this drives `analyse_ip`, the same entry point the
CLI and the GUI use, so what is measured is what ships. A scorer that ran its
own simplified pipeline would report on code nobody else executes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from logarc.analysis import AnalysisPolicy, analyse_ip
from logarc.detect.engine import RuleEngine
from logarc.detect.rulepacks import default_rules
from logarc.evaluation.metrics import (
    Prediction,
    score_binary,
    score_classification,
    score_segmentation,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from logarc.detect.crs import DetectionIndex
    from logarc.evaluation.metrics import (
        BinaryScore,
        ClassificationReport,
        SegmentationReport,
    )
    from logarc.evaluation.truth import GroundTruth
    from logarc.storage.base import EventStore

__all__ = ["EvaluationReport", "evaluate"]


@dataclass(frozen=True, slots=True)
class EvaluationReport:
    """Everything one evaluation run concluded."""

    scenario: str
    source_file_id: str
    granularity: str
    ruleset_fingerprint: str
    policy: dict[str, Any]

    crs_fingerprint: str | None = field(default=None, kw_only=True)
    """Which CRS produced the detections this run used, if any.

    `kw_only` so it can sit beside `ruleset_fingerprint`, where it belongs to a
    reader, rather than being exiled to the end of the class by the rule that a
    defaulted field cannot precede a required one.

    `None` means the case was never enriched, and that is a claim rather than an
    omission — a reader comparing two reports has to be able to see which one
    had a second ruleset behind it.

    Beside `ruleset_fingerprint` rather than folded into it, for the reason
    `AnalysisResult` keeps them apart: one names the rules this project wrote
    and the other names a dependency, and a CRS version bump should move a
    figure that says *CRS* moved.
    """

    crs_coverage: tuple[int, int] | None = field(default=None, kw_only=True)
    """`(replayed, requests)` when that CRS run was stopped part way, else
    `None`. A score built on part of a CRS run is not a measurement of the
    complete tool, and the numbers written for a paper have to say so."""

    classification: ClassificationReport | None
    """Per-activity figures, or None when the truth only knew attack-or-not.

    Absent rather than empty, so a table that cannot be honestly produced from
    the source cannot be produced by accident either.
    """

    binary: BinaryScore
    segmentation: SegmentationReport

    clients: int
    lines_expected: int
    lines_scored: int

    @property
    def lines_missing(self) -> int:
        """Lines the log contains that never reached the store.

        Malformed lines are quarantined rather than dropped, so this is where
        they surface. Left out of the accuracy figures, counted here, because a
        parser that silently discarded the hard lines would otherwise look like
        a classifier that is very accurate on the easy ones.
        """
        return self.lines_expected - self.lines_scored

    def to_dict(self) -> dict[str, Any]:
        """The machine-readable form, for a results table."""
        payload: dict[str, Any] = {
            "scenario": self.scenario,
            "source_file_id": self.source_file_id,
            "granularity": self.granularity,
            "ruleset_fingerprint": self.ruleset_fingerprint,
            "crs_fingerprint": self.crs_fingerprint,
            "crs_coverage": (
                {"replayed": self.crs_coverage[0], "requests": self.crs_coverage[1]}
                if self.crs_coverage is not None
                else None
            ),
            "policy": self.policy,
            "totals": {
                "clients": self.clients,
                "lines_expected": self.lines_expected,
                "lines_scored": self.lines_scored,
                "lines_missing": self.lines_missing,
            },
            "binary": self.binary.to_dict(),
            "segmentation": {
                "truth_activities": self.segmentation.truth_activities,
                "predicted_episodes": self.segmentation.predicted_episodes,
                "fragmentation": self.segmentation.fragmentation,
                "boundaries_expected": self.segmentation.boundaries_expected,
                "boundaries_found": self.segmentation.boundaries_found,
                "boundaries_agreed": self.segmentation.boundaries_agreed,
                "boundary_precision": self.segmentation.boundary_precision,
                "boundary_recall": self.segmentation.boundary_recall,
                "boundary_f1": self.segmentation.boundary_f1,
            },
        }
        if self.classification is not None:
            payload["classification"] = self._classification_dict(self.classification)
        return payload

    @staticmethod
    def _classification_dict(report: ClassificationReport) -> dict[str, Any]:
        return {
            "accuracy": report.accuracy,
            "macro_f1": report.macro_f1,
            "weighted_f1": report.weighted_f1,
            "per_category": [
                {
                    "category": score.category.value,
                    "support": score.support,
                    "predicted": score.predicted,
                    "true_positives": score.true_positives,
                    "false_positives": score.false_positives,
                    "false_negatives": score.false_negatives,
                    "precision": score.precision,
                    "recall": score.recall,
                    "f1": score.f1,
                    "recall_any": score.recall_any,
                }
                for score in report.scores
            ],
            "top_confusions": [
                {"expected": expected.value, "predicted": predicted.value, "count": count}
                for expected, predicted, count in report.top_confusions()
            ],
        }


def evaluate(
    store: EventStore,
    truth: GroundTruth,
    *,
    engine: RuleEngine | None = None,
    policy: AnalysisPolicy | None = None,
    crs: DetectionIndex | None = None,
    crs_fingerprint: str | None = None,
    crs_coverage: tuple[int, int] | None = None,
    on_client: Callable[[str], None] | None = None,
) -> EvaluationReport:
    """Reconstruct every client the truth knows about, and score the result.

    `crs` is passed through so the same corpus can be scored with and without
    enrichment. That comparison is the guard on the whole CRS integration:
    recall may rise, but precision on traffic the rules already read correctly
    must not fall.

    `crs_fingerprint` is what makes that comparison checkable a month later. A
    report holding CRS's findings and not its version is a number nobody can
    reproduce once the dependency moves.
    """
    # Built once. Left to default, `analyse_ip` compiles the whole ruleset from
    # YAML for every client it is given, which on a corpus with two thousand of
    # them is two thousand identical rule compilations.
    engine = engine or RuleEngine(default_rules())
    policy = policy or AnalysisPolicy()

    predictions: list[Prediction] = []
    judgements: list[tuple[bool, bool]] = []
    sequences: list[list[tuple[str, str]]] = []
    scored = 0

    grouped = truth.by_client()
    for client_ip, records in grouped.items():
        result = analyse_ip(store, client_ip, engine=engine, policy=policy, crs=crs)

        found = {
            item.evidence.line_no: item
            for item in result.assignments
            if item.evidence.source_file_id == truth.source_file_id
        }

        sequence: list[tuple[str, str]] = []
        for record in records:
            assignment = found.get(record.line_no)
            if assignment is None:
                continue
            scored += 1
            predictions.append(
                Prediction(
                    truth=record.category,
                    predicted=assignment.category,
                    considered=assignment.categories,
                )
            )
            judgements.append((record.category.is_hostile, assignment.category.is_hostile))
            sequence.append((record.instance_id, assignment.episode_id))

        if sequence:
            sequences.append(sequence)
        if on_client is not None:
            on_client(client_ip)

    return EvaluationReport(
        scenario=truth.scenario,
        source_file_id=truth.source_file_id,
        granularity=truth.granularity,
        ruleset_fingerprint=engine.fingerprint,
        crs_fingerprint=crs_fingerprint,
        crs_coverage=crs_coverage,
        policy=policy.as_config(),
        # A source that only knows attack-or-not carries stand-in categories,
        # and a per-activity table built from those would look like a result
        # while meaning nothing.
        classification=None if truth.is_binary else score_classification(predictions),
        binary=score_binary(judgements),
        segmentation=score_segmentation(sequences),
        clients=len(grouped),
        lines_expected=truth.line_count,
        lines_scored=scored,
    )
