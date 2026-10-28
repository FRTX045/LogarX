"""Scoring a whole case against a real log whose contents are known.

The excerpt under tests/data/apache-shopfront is a slice of the LogarX Dataset
medium build. The floors below come from one native (no CRS) measurement of
it on 2026-09-08, set a little under what came out so a regression shows and
noise does not:

    3,825 lines scored, 0 missing, 52 clients
    accuracy 0.889   macro F1 0.687
    injection: support 57, precision 1.000, recall 0.684
    attack or not: precision 0.982, recall 0.893, false-alarm rate 0.0076
    ordinary lines called hostile: 20 of 2,616
"""

from __future__ import annotations

import json
from pathlib import Path

from logarx.case import Case
from logarx.core.activity import ActivityCategory
from logarx.evaluation.scoring import evaluate
from logarx.evaluation.truth import GroundTruth, read_truth


def test_every_line_of_the_excerpt_is_scored(
    excerpt_case: Case, excerpt_truth: GroundTruth
) -> None:
    report = evaluate(excerpt_case.store, excerpt_truth)

    assert report.lines_expected == excerpt_truth.line_count
    assert report.lines_scored == excerpt_truth.line_count
    assert report.lines_missing == 0
    assert report.classification.total == excerpt_truth.line_count


def test_the_report_names_what_produced_it(excerpt_case: Case, excerpt_truth: GroundTruth) -> None:
    """A number nobody can reproduce is not a result."""
    report = evaluate(excerpt_case.store, excerpt_truth)

    assert report.scenario == "apache-shopfront-medium-excerpt"
    assert len(report.ruleset_fingerprint) == 64
    assert report.policy["idle_timeout_seconds"] == 1800
    assert report.policy["episode_max_gap_seconds"] == 300


def test_each_client_is_scored_separately(excerpt_case: Case, excerpt_truth: GroundTruth) -> None:
    report = evaluate(excerpt_case.store, excerpt_truth)

    assert report.clients == len(excerpt_truth.by_client())
    assert report.clients > 40


def test_lines_that_never_reached_the_store_are_counted_not_ignored(
    excerpt_case: Case, excerpt_truth: GroundTruth
) -> None:
    """Quarantined or dropped lines must show up, not quietly improve the score."""
    ghost = excerpt_truth.records[0].__class__(
        line_no=999_999,
        client_ip="100.99.0.1",
        category=ActivityCategory.INJECTION,
        instance_id="ghost#1",
    )
    padded = excerpt_truth.__class__(
        scenario=excerpt_truth.scenario,
        seed=excerpt_truth.seed,
        source_file_id=excerpt_truth.source_file_id,
        generated_at=excerpt_truth.generated_at,
        records=(*excerpt_truth.records, ghost),
    )

    report = evaluate(excerpt_case.store, padded)

    assert report.lines_expected == excerpt_truth.line_count + 1
    assert report.lines_missing == 1
    assert report.classification.total == excerpt_truth.line_count


def test_ordinary_traffic_is_not_reported_as_an_attack(
    excerpt_case: Case, excerpt_truth: GroundTruth
) -> None:
    """The false-positive half. A tool that cries wolf is not usable."""
    report = evaluate(excerpt_case.store, excerpt_truth)
    confusion = report.classification.confusion
    ordinary = sum(n for (truth, _), n in confusion.items() if not truth.is_hostile)
    hostile = sum(
        n
        for (truth, predicted), n in confusion.items()
        if not truth.is_hostile and predicted.is_hostile
    )

    assert ordinary > 1000
    assert hostile / ordinary < 0.02


def test_an_injection_campaign_is_found(excerpt_case: Case, excerpt_truth: GroundTruth) -> None:
    report = evaluate(excerpt_case.store, excerpt_truth)
    injection = report.classification.for_category(ActivityCategory.INJECTION)

    assert injection.support >= 50
    assert injection.recall > 0.6
    assert injection.precision > 0.95


def test_the_report_serialises_for_a_paper_table(
    excerpt_case: Case, excerpt_truth: GroundTruth
) -> None:
    payload = evaluate(excerpt_case.store, excerpt_truth).to_dict()

    assert json.loads(json.dumps(payload))["scenario"] == "apache-shopfront-medium-excerpt"
    assert payload["classification"]["per_category"][0]["category"]
    assert "boundary_f1" in payload["segmentation"]
    assert payload["totals"]["lines_missing"] == 0


def test_hostile_or_not_is_scored_alongside_the_categories(
    excerpt_case: Case, excerpt_truth: GroundTruth
) -> None:
    """The question a defender actually asks first."""
    report = evaluate(excerpt_case.store, excerpt_truth)

    assert report.granularity == "category"
    assert report.binary.total == report.lines_scored
    assert report.binary.recall > 0.85
    assert report.binary.false_positive_rate < 0.05


def test_a_binary_truth_gets_no_per_category_table(tmp_path: Path) -> None:
    """A dataset that only knows attack-or-not cannot support one.

    The truth file says so in its header, so this is enforced rather than
    written down and hoped for.
    """
    from logarx.evaluation.csic import convert_csic

    normal = tmp_path / "normal.txt"
    anomalous = tmp_path / "anomalous.txt"
    normal.write_text(
        "GET http://localhost:8080/shop/index.jsp HTTP/1.1\n"
        "User-Agent: Mozilla/5.0\n"
        "Cookie: JSESSIONID=AAAA\n\n",
        encoding="utf-8",
    )
    anomalous.write_text(
        "GET http://localhost:8080/shop/item.jsp?id=1%27+OR+%271%27%3D%271 HTTP/1.1\n"
        "User-Agent: Mozilla/5.0\n"
        "Cookie: JSESSIONID=BBBB\n\n",
        encoding="utf-8",
    )
    log = tmp_path / "csic.log"
    convert_csic(
        normal=[normal], anomalous=[anomalous], out=log, truth_path=tmp_path / "csic.truth.jsonl"
    )
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])

    with Case.open(tmp_path / "case") as case:
        report = evaluate(case.store, read_truth(tmp_path / "csic.truth.jsonl"))

    assert report.granularity == "binary"
    assert report.classification is None
    assert report.binary.total == 2
    assert report.binary.true_positives == 1
    assert report.binary.true_negatives == 1
    assert "classification" not in report.to_dict()


def test_progress_is_reported_per_client(excerpt_case: Case, excerpt_truth: GroundTruth) -> None:
    seen: list[str] = []

    evaluate(excerpt_case.store, excerpt_truth, on_client=seen.append)

    assert len(seen) == len(excerpt_truth.by_client())
