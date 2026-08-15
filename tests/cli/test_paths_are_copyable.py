"""Paths the CLI prints have to survive being copied.

Every one of them is the argument to the next command — `ingest` prints the case
folder that `analyze`, `evidence` and `export` all need. Rich wraps to the
console width and a path offers no spaces to break at, so a long one is cut
mid-word; in a table title it is cut *and* centred, arriving as three fragments
padded with spaces. What is printed has to be what can be pasted.

Measured at a fixed width rather than the terminal's, so the test asserts what
the code does instead of how wide the machine running it happens to be.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.cli import main as cli
from logarc.cli.main import app

LINE = '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'

#: Narrow enough that any real case path overflows it. A terminal this size is
#: ordinary, and the fault only shows once the path is longer than the width.
WIDTH = 60


@pytest.fixture
def narrow_console(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the width of both consoles the CLI writes through."""
    for console in (cli.console, cli.errors):
        monkeypatch.setattr(console, "_width", WIDTH)


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text(LINE + "\n", encoding="utf-8")
    return path


def test_the_case_path_can_be_copied_out_of_the_ingest_report(
    narrow_console: None, log: Path, tmp_path: Path
) -> None:
    """The path `ingest` reports is the one every later command is given. It was
    in the table title, where Rich broke it into centred fragments."""
    case = tmp_path / "case"

    result = CliRunner().invoke(app, ["ingest", str(log), "--case", str(case)])

    assert result.exit_code == 0, result.output
    assert str(case) in result.output, "the case path did not survive being printed"


def test_a_written_report_names_a_path_that_can_be_copied(
    narrow_console: None, log: Path, tmp_path: Path
) -> None:
    case = tmp_path / "case"
    runner = CliRunner()
    assert runner.invoke(app, ["ingest", str(log), "--case", str(case)]).exit_code == 0

    out = tmp_path / "report.html"
    result = runner.invoke(
        app,
        [
            "export", "--case", str(case), "--ip", "203.0.113.5",
            "--format", "html", "--out", str(out),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert str(out) in result.output


def test_the_quarantine_path_can_be_copied(narrow_console: None, tmp_path: Path) -> None:
    """Printed only when something failed to parse, which is when someone is
    most likely to go and look at it."""
    damaged = tmp_path / "damaged.log"
    # Enough good lines for the format to be detected; one bad one to quarantine.
    damaged.write_text(
        "\n".join([LINE] * 6 + ["this line is not a log line"]) + "\n", encoding="utf-8"
    )
    case = tmp_path / "case"

    result = CliRunner().invoke(app, ["ingest", str(damaged), "--case", str(case)])

    assert result.exit_code == 0, result.output
    assert "could not be parsed" in " ".join(result.output.split()), "premise: a line failed"
    assert str(case / "quarantine" / "unparsed.jsonl") in result.output
