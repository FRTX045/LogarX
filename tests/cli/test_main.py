"""Tests for the command line interface.

These check the contract a user sees — exit codes and what is printed — rather
than internals, which the layers below already cover.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.cli.main import app

runner = CliRunner()

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "GET /admin HTTP/1.1" 404 0 "-" "curl/8.0"',
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "POST /login HTTP/1.1" 302 0 "-" "curl/8.0"',
]


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


def test_ingest_reports_what_it_stored(log: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])

    assert result.exit_code == 0
    assert "3" in result.stdout
    assert "apache-combined" in result.stdout


def test_ingest_creates_a_usable_case(log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    assert (case / "case.json").exists()
    assert (case / "ip_index.parquet").exists()


def test_ingest_of_an_unrecognisable_file_fails_with_a_useful_message(
    tmp_path: Path,
) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("just some notes\n", encoding="utf-8")

    result = runner.invoke(app, ["ingest", str(path), "--case", str(tmp_path / "case")])

    assert result.exit_code != 0
    assert "--format" in result.output


def test_ingest_of_a_missing_file_fails_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["ingest", str(tmp_path / "gone.log"), "--case", str(tmp_path / "case")]
    )

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_ingest_refuses_to_overwrite_an_existing_case(log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    assert result.exit_code != 0
    assert "already exists" in result.output


def test_list_ips_shows_each_client(log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["list-ips", "--case", str(case)])

    assert result.exit_code == 0
    assert "203.0.113.5" in result.stdout
    assert "198.51.100.9" in result.stdout


def test_list_ips_honours_the_limit(log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["list-ips", "--case", str(case), "--limit", "1"])

    assert "203.0.113.5" in result.stdout
    assert "198.51.100.9" not in result.stdout


def test_list_ips_rejects_an_unknown_sort_key(log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    result = runner.invoke(app, ["list-ips", "--case", str(case), "--sort", "sideways"])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_list_ips_on_a_missing_case_fails_cleanly(tmp_path: Path) -> None:
    result = runner.invoke(app, ["list-ips", "--case", str(tmp_path / "nope")])

    assert result.exit_code != 0
    assert "Traceback" not in result.output


def test_formats_lists_what_can_be_parsed() -> None:
    result = runner.invoke(app, ["formats"])

    assert result.exit_code == 0
    assert "apache-combined" in result.stdout


def test_version_is_reported() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "logarc" in result.stdout
