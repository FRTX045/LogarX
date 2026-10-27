"""The evaluate command, as a user meets it."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.core.activity import ActivityCategory
from logarc.devtools.main import app
from logarc.evaluation.truth import TruthRecord, TruthWriter

runner = CliRunner()

EXCERPT = Path(__file__).parent.parent / "data" / "apache-shopfront"


@pytest.fixture
def excerpt(tmp_path: Path) -> tuple[Path, Path]:
    """The fixture copied out, so a test that writes beside it cannot touch the original."""
    log = tmp_path / "excerpt.log"
    truth = tmp_path / "excerpt.truth.jsonl"
    shutil.copyfile(EXCERPT / "excerpt.log", log)
    shutil.copyfile(EXCERPT / "excerpt.truth.jsonl", truth)
    return log, truth


def test_evaluate_reports_accuracy_per_category(excerpt: tuple[Path, Path], tmp_path: Path) -> None:
    log, truth = excerpt
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["evaluate", "--case", str(case), "--truth", str(truth)])

    assert result.exit_code == 0, result.stdout
    assert "injection" in result.stdout
    assert "Precision" in result.stdout
    assert "Boundaries" in result.output


def test_evaluate_can_write_the_numbers_for_a_paper(
    excerpt: tuple[Path, Path], tmp_path: Path
) -> None:
    log, truth = excerpt
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    out = tmp_path / "evaluation.json"

    result = runner.invoke(
        app, ["evaluate", "--case", str(case), "--truth", str(truth), "--out", str(out)]
    )

    assert result.exit_code == 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["scenario"] == "apache-shopfront-medium-excerpt"
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
    excerpt: tuple[Path, Path], tmp_path: Path
) -> None:
    log, truth = excerpt
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


def test_an_enriched_case_can_be_scored_as_if_it_were_not(
    excerpt: tuple[Path, Path], tmp_path: Path
) -> None:
    """**Both numbers from one case, which is what makes measuring both the
    default rather than a chore.**

    Before this the only way to get the native figure out of an enriched case
    was to move `crs.jsonl` aside, score, and move it back — three steps with a
    window in the middle where the case on disk is not the case that was
    measured. Doing it by hand is how a native column comes to be quoted for a
    CRS run.
    """
    log, truth = excerpt
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    with_crs = tmp_path / "with.json"
    without = tmp_path / "without.json"
    runner.invoke(app, ["evaluate", "-c", str(case), "-t", str(truth), "-o", str(with_crs)])
    result = runner.invoke(
        app, ["evaluate", "-c", str(case), "-t", str(truth), "-o", str(without), "--no-crs"]
    )

    assert result.exit_code == 0, result.output
    scored = json.loads(without.read_text(encoding="utf-8"))
    assert scored["crs_fingerprint"] is None, "a --no-crs run must not name a CRS"


def test_scoring_without_crs_says_so_in_the_report(
    excerpt: tuple[Path, Path], tmp_path: Path
) -> None:
    """The flag is only honest if the file it writes cannot be mistaken for the
    other one. `crs_fingerprint` is how a reader tells them apart, so it has to
    be absent here even when the case beside it is enriched."""
    log, truth = excerpt
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    out = tmp_path / "native.json"

    runner.invoke(app, ["evaluate", "-c", str(case), "-t", str(truth), "-o", str(out), "--no-crs"])

    assert json.loads(out.read_text(encoding="utf-8"))["crs_fingerprint"] is None


def test_evaluate_records_a_partial_crs_run(excerpt: tuple[Path, Path], tmp_path: Path) -> None:
    """A score built on a stopped CRS run is not a complete-product measurement,
    and the numbers written for a paper have to say so."""
    from logarc.case import Case
    from logarc.detect.crs.store import write_detections

    log, truth = excerpt
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])
    with Case.open(case) as opened:
        write_detections(opened.root, [])
        opened.manifest.config.update(
            {
                "crs_fingerprint": "0123456789abcdef",
                "crs_replayed": 10,
                "crs_requests": 3825,
                "crs_complete": False,
            }
        )
        opened.manifest.save(opened.root)
    out = tmp_path / "evaluation.json"

    result = runner.invoke(
        app, ["evaluate", "--case", str(case), "--truth", str(truth), "--out", str(out)]
    )

    assert result.exit_code == 0, result.output
    assert "CRS stopped part way" in " ".join(result.output.split())
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["crs_coverage"] == {"replayed": 10, "requests": 3825}
