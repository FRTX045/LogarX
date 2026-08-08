"""The benchmark command. Tiny sizes: the harness is what is under test."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from logarc.cli.main import app

runner = CliRunner()


def test_benchmark_reports_throughput_and_memory(tmp_path: Path) -> None:
    result = runner.invoke(app, ["benchmark", "--lines", "2000", "--work", str(tmp_path)])

    assert result.exit_code == 0, result.output
    assert "Lines/s" in result.output
    assert "MB/s" in result.output
    assert "RSS" in result.output
    assert "Ratio" in result.output


def test_benchmark_measures_each_requested_size(tmp_path: Path) -> None:
    out = tmp_path / "bench.json"

    result = runner.invoke(
        app,
        [
            "benchmark", "--lines", "2000", "--lines", "4000",
            "--work", str(tmp_path), "--out", str(out),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert [row["lines"] for row in payload["runs"]] == [2000, 4000]
    assert payload["platform"]
    assert payload["python"]


def test_benchmark_leaves_a_named_working_directory_alone(tmp_path: Path) -> None:
    """It cleans up after itself and nothing else.

    Pointing --work at a directory that already holds files must not be a way
    to delete them.
    """
    work = tmp_path / "scratch"
    work.mkdir()
    bystander = work / "please-do-not-delete.txt"
    bystander.write_text("mine\n", encoding="utf-8")

    result = runner.invoke(app, ["benchmark", "--lines", "2000", "--work", str(work)])

    assert result.exit_code == 0, result.output
    assert bystander.exists()
    assert list(work.iterdir()) == [bystander]


def test_benchmark_keeps_its_working_files_on_request(tmp_path: Path) -> None:
    work = tmp_path / "scratch"

    runner.invoke(app, ["benchmark", "--lines", "2000", "--work", str(work), "--keep"])

    assert any(work.iterdir())


def test_benchmark_reports_a_failed_run(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["benchmark", "--lines", "1000", "--scenario", "nope", "--work", str(tmp_path)],
    )

    assert result.exit_code == 1
    assert "nope" in result.output
