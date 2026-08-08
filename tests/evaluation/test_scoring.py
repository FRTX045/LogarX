"""Scoring a whole case against the log it was generated from."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from logarc.case import Case
from logarc.core.activity import ActivityCategory
from logarc.evaluation.generator import write_log
from logarc.evaluation.scoring import evaluate
from logarc.evaluation.truth import read_truth


def build(tmp_path: Path, scenario: str, lines: int = 1500, seed: int = 11) -> tuple[Case, Path]:
    log = tmp_path / "sample.log"
    truth_path = tmp_path / "sample.truth.jsonl"
    write_log(log, scenario=scenario, lines=lines, seed=seed, truth_path=truth_path)

    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return Case.open(tmp_path / "case"), truth_path


@pytest.fixture
def mixed(tmp_path: Path) -> tuple[Case, Path]:
    return build(tmp_path, "mixed")


def test_every_generated_line_is_scored(mixed: tuple[Case, Path]) -> None:
    case, truth_path = mixed
    truth = read_truth(truth_path)

    report = evaluate(case.store, truth)

    assert report.lines_expected == truth.line_count
    assert report.lines_scored == truth.line_count
    assert report.lines_missing == 0
    assert report.classification.total == truth.line_count


def test_the_report_names_what_produced_it(mixed: tuple[Case, Path]) -> None:
    """A number nobody can reproduce is not a result."""
    case, truth_path = mixed

    report = evaluate(case.store, read_truth(truth_path))

    assert report.scenario == "mixed"
    assert len(report.ruleset_fingerprint) == 64
    assert report.policy["idle_timeout_seconds"] == 1800
    assert report.policy["episode_max_gap_seconds"] == 300


def test_each_client_is_scored_separately(mixed: tuple[Case, Path]) -> None:
    case, truth_path = mixed
    truth = read_truth(truth_path)

    report = evaluate(case.store, truth)

    assert report.clients == len(truth.by_client())
    assert report.clients > 5


def test_lines_that_never_reached_the_store_are_counted_not_ignored(
    tmp_path: Path,
) -> None:
    """Quarantined or dropped lines must show up, not quietly improve the score."""
    case, truth_path = build(tmp_path, "normal_browsing", lines=200)
    truth = read_truth(truth_path)
    ghost = truth.records[0].__class__(
        line_no=99_999,
        client_ip="100.99.0.1",
        category=ActivityCategory.INJECTION,
        instance_id="ghost#1",
    )
    padded = truth.__class__(
        scenario=truth.scenario,
        seed=truth.seed,
        source_file_id=truth.source_file_id,
        generated_at=truth.generated_at,
        records=(*truth.records, ghost),
    )

    report = evaluate(case.store, padded)

    assert report.lines_expected == truth.line_count + 1
    assert report.lines_missing == 1
    assert report.classification.total == truth.line_count


def test_ordinary_traffic_is_not_reported_as_an_attack(tmp_path: Path) -> None:
    """The false-positive half. A tool that cries wolf is not usable."""
    case, truth_path = build(tmp_path, "normal_browsing", lines=3000)

    report = evaluate(case.store, read_truth(truth_path))
    hostile = sum(
        count
        for (truth_category, predicted), count in report.classification.confusion.items()
        if not truth_category.is_hostile and predicted.is_hostile
    )

    assert hostile / report.classification.total < 0.01


def test_an_injection_campaign_is_found(tmp_path: Path) -> None:
    case, truth_path = build(tmp_path, "sqli_campaign", lines=4000)

    report = evaluate(case.store, read_truth(truth_path))
    injection = report.classification.for_category(ActivityCategory.INJECTION)

    assert injection.support > 0
    assert injection.recall > 0.9
    assert injection.precision > 0.9


def test_the_report_serialises_for_a_paper_table(mixed: tuple[Case, Path]) -> None:
    case, truth_path = mixed

    payload = evaluate(case.store, read_truth(truth_path)).to_dict()

    assert json.loads(json.dumps(payload))["scenario"] == "mixed"
    assert payload["classification"]["per_category"][0]["category"]
    assert "boundary_f1" in payload["segmentation"]
    assert payload["totals"]["lines_missing"] == 0


def test_hostile_or_not_is_scored_alongside_the_categories(mixed: tuple[Case, Path]) -> None:
    """The question a defender actually asks first."""
    case, truth_path = mixed

    report = evaluate(case.store, read_truth(truth_path))

    assert report.granularity == "category"
    assert report.binary.total == report.lines_scored
    assert report.binary.recall > 0.9
    assert report.binary.false_positive_rate < 0.05


def test_a_binary_truth_gets_no_per_category_table(tmp_path: Path) -> None:
    """A dataset that only knows attack-or-not cannot support one.

    The truth file says so in its header, so this is enforced rather than
    written down and hoped for.
    """
    from logarc.evaluation.csic import convert_csic

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


def test_progress_is_reported_per_client(mixed: tuple[Case, Path]) -> None:
    case, truth_path = mixed
    seen: list[str] = []

    evaluate(case.store, read_truth(truth_path), on_client=seen.append)

    assert len(seen) == len(read_truth(truth_path).by_client())
