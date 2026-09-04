"""The generate and evaluate commands, as a user meets them."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.cli.main import app
from logarc.core.activity import ActivityCategory
from logarc.evaluation.truth import TruthRecord, TruthWriter

runner = CliRunner()


@pytest.fixture
def generated(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "sample.log"
    result = runner.invoke(
        app,
        [
            "generate",
            "--scenario", "sqli_campaign",
            "--lines", "1200",
            "--seed", "4",
            "--out", str(log),
            "--truth", str(tmp_path / "sample.truth.jsonl"),
        ],
    )  # fmt: skip
    assert result.exit_code == 0, result.stdout
    return log, tmp_path / "sample.truth.jsonl"


def test_generate_writes_a_log_and_its_truth(generated: tuple[Path, Path]) -> None:
    log, truth = generated

    assert len(log.read_text(encoding="utf-8").splitlines()) == 1200
    assert truth.exists()


def test_generate_lists_the_scenarios_it_knows() -> None:
    result = runner.invoke(app, ["generate", "--list"])

    assert result.exit_code == 0
    assert "sqli_campaign" in result.stdout
    assert "normal_browsing" in result.stdout


def test_generate_rejects_an_unknown_scenario(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["generate", "--scenario", "nope", "--lines", "10", "--out", str(tmp_path / "x.log")],
    )

    assert result.exit_code == 1
    assert "nope" in result.output


def test_generate_can_skip_truth(tmp_path: Path) -> None:
    log = tmp_path / "big.log"

    result = runner.invoke(
        app, ["generate", "--scenario", "mixed", "--lines", "50", "--out", str(log)]
    )

    assert result.exit_code == 0
    assert not list(tmp_path.glob("*.truth.jsonl"))


def test_evaluate_reports_accuracy_per_category(
    generated: tuple[Path, Path], tmp_path: Path
) -> None:
    log, truth = generated
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["evaluate", "--case", str(case), "--truth", str(truth)])

    assert result.exit_code == 0, result.stdout
    assert "injection" in result.stdout
    assert "Precision" in result.stdout
    assert "Boundaries" in result.output


def test_evaluate_can_write_the_numbers_for_a_paper(
    generated: tuple[Path, Path], tmp_path: Path
) -> None:
    log, truth = generated
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    out = tmp_path / "evaluation.json"

    result = runner.invoke(
        app, ["evaluate", "--case", str(case), "--truth", str(truth), "--out", str(out)]
    )

    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["scenario"] == "sqli_campaign"
    assert payload["classification"]["macro_f1"] > 0
    assert payload["ruleset_fingerprint"]


@pytest.fixture
def interleaved(tmp_path: Path) -> tuple[Path, Path]:
    """One benign request between two runs of the same hostile category."""
    log = tmp_path / "interleaved.log"
    truth = tmp_path / "interleaved.truth.jsonl"
    targets = ["/?id=1+UNION+SELECT+x", "/", "/?id=2+UNION+SELECT+y"]
    log.write_text(
        "\n".join(
            f'203.0.113.5 - - [01/May/2024:12:00:0{index} +0000] "GET {target} HTTP/1.1" '
            '200 100 "-" "Mozilla/5.0"'
            for index, target in enumerate(targets)
        )
        + "\n",
        encoding="utf-8",
    )
    with TruthWriter(truth, scenario="absorption", seed=1, source_file_id=log.name) as writer:
        writer.write(TruthRecord(1, "203.0.113.5", ActivityCategory.INJECTION, "attack-1"))
        writer.write(TruthRecord(2, "203.0.113.5", ActivityCategory.BROWSING, "browse-1"))
        writer.write(TruthRecord(3, "203.0.113.5", ActivityCategory.INJECTION, "attack-2"))
    return log, truth


def test_turning_off_absorption_finds_more_boundaries_and_more_episodes(
    interleaved: tuple[Path, Path], tmp_path: Path
) -> None:
    """The ablation that makes the merge rule arguable instead of asserted.

    Absorption trades boundary recall for a graph that can be read. Being able
    to run both ways is what turns that from a claim into a measurement.

    The fixture states that the benign interlude is a real activity. Raw
    segmentation keeps its boundaries; absorption deliberately trades them for
    a shorter graph.
    """
    log, truth = interleaved
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    def run(*extra: str) -> dict[str, object]:
        out = tmp_path / f"scores{len(extra)}.json"
        result = runner.invoke(
            app,
            ["evaluate", "--case", str(case), "--truth", str(truth), "--out", str(out), *extra],
        )
        assert result.exit_code == 0, result.output
        return json.loads(out.read_text(encoding="utf-8"))["segmentation"]

    absorbed = run()
    raw = run("--no-absorb")

    assert raw["boundary_recall"] > absorbed["boundary_recall"]
    assert raw["predicted_episodes"] > absorbed["predicted_episodes"]


def test_thresholds_can_be_overridden_for_tuning(
    generated: tuple[Path, Path], tmp_path: Path
) -> None:
    log, truth = generated
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    out = tmp_path / "tuned.json"

    result = runner.invoke(
        app,
        [
            "evaluate", "--case", str(case), "--truth", str(truth), "--out", str(out),
            "--episode-gap", "60", "--idle-timeout", "600",
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    policy = json.loads(out.read_text(encoding="utf-8"))["policy"]
    assert policy["episode_max_gap_seconds"] == 60
    assert policy["idle_timeout_seconds"] == 600


def test_evaluate_refuses_a_file_that_is_not_ground_truth(tmp_path: Path) -> None:
    case = tmp_path / "case"
    log = tmp_path / "a.log"
    log.write_text(
        '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 26 "-" "curl/8"\n',
        encoding="utf-8",
    )
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    fake = tmp_path / "fake.jsonl"
    fake.write_text('{"nope": 1}\n', encoding="utf-8")

    result = runner.invoke(app, ["evaluate", "--case", str(case), "--truth", str(fake)])

    assert result.exit_code == 1
    assert "ground-truth" in result.output
