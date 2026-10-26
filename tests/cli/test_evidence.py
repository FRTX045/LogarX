"""The evidence command: raw log lines behind a reconstruction."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.cli.main import app

runner = CliRunner()

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    *[
        f'203.0.113.5 - - [10/Oct/2020:13:55:{n:02d} +0000] "GET /admin/{n} HTTP/1.1" 404 0 '
        f'"-" "curl/8.0"'
        for n in range(1, 31)
    ],
    '198.51.100.9 - - [10/Oct/2020:13:56:00 +0000] "GET /about HTTP/1.1" 200 900 "-" "curl/8"',
]


@pytest.fixture
def case(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])
    assert result.exit_code == 0, result.output
    return tmp_path / "case"


def test_evidence_shows_the_raw_lines_behind_each_activity(case: Path) -> None:
    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "203.0.113.5"])

    assert result.exit_code == 0, result.output
    assert "access.log:1" in result.output
    assert "GET /" in result.output


def test_evidence_names_the_activity_each_line_belongs_to(case: Path) -> None:
    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "203.0.113.5"])

    assert "Enumeration" in result.output or "enumeration" in result.output.lower()


def test_evidence_can_be_narrowed_to_one_activity(case: Path) -> None:
    everything = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "203.0.113.5"])
    # Episode ids read as "<client>#<session>/<index>".
    episode = next(token for token in everything.output.split() if "#" in token and "/" in token)

    result = runner.invoke(
        app, ["evidence", "--case", str(case), "--ip", "203.0.113.5", "--episode", episode]
    )

    assert result.exit_code == 0, result.output
    assert result.output.count("access.log:") <= everything.output.count("access.log:")


def test_an_unknown_episode_is_refused_with_the_ones_that_exist(case: Path) -> None:
    result = runner.invoke(
        app, ["evidence", "--case", str(case), "--ip", "203.0.113.5", "--episode", "nope"]
    )

    assert result.exit_code == 1
    assert "nope" in result.output


def test_a_client_with_no_activity_says_so(case: Path) -> None:
    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "192.0.2.99"])

    assert result.exit_code == 0
    assert "No activity" in result.output


def test_a_missing_source_is_reported_not_crashed(case: Path, tmp_path: Path) -> None:
    """Evidence outlives its log. The command must still run."""
    (tmp_path / "access.log").unlink()

    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "203.0.113.5"])

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
    assert "unavailable" in result.output.lower() or "cannot" in result.output.lower()


def test_one_request_is_counted_in_the_singular(case: Path) -> None:
    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "198.51.100.9"])

    assert result.exit_code == 0, result.output
    assert "1 request," in result.output
    assert "1 requests" not in result.output


def test_one_line_left_over_is_counted_in_the_singular(tmp_path: Path) -> None:
    log = tmp_path / "pair.log"
    log.write_text(
        "".join(
            f'198.51.100.9 - - [10/Oct/2020:13:56:0{n} +0000] "GET /about HTTP/1.1" 200 900 '
            f'"-" "curl/8"\n'
            for n in (0, 5)
        ),
        encoding="utf-8",
    )
    ingested = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])
    assert ingested.exit_code == 0, ingested.output

    result = runner.invoke(
        app,
        ["evidence", "--case", str(tmp_path / "case"), "--ip", "198.51.100.9", "--limit", "1"],
    )

    assert result.exit_code == 0, result.output
    assert "1 more line in this activity" in result.output


def test_a_changed_source_is_named_with_what_was_found(case: Path, tmp_path: Path) -> None:
    """The reader's own account, sizes and all, not a fixed phrase: the same
    flag is raised when the source could not be checked at all, and that is not
    a change."""
    log = tmp_path / "access.log"
    log.write_text(log.read_text(encoding="utf-8") + "extra\n", encoding="utf-8")

    result = runner.invoke(app, ["evidence", "--case", str(case), "--ip", "203.0.113.5"])

    assert result.exit_code == 0, result.output
    printed = " ".join(result.output.split())
    assert "not verified" in printed
    assert "has changed size since ingest" in printed
