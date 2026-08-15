"""The `enrich` command.

The sidecar itself is covered by the contract tests, which need the Go binary.
What is covered here needs no binary at all: the two refusals, which exist to
tell one problem from another. Sending someone to build a sidecar when their
real problem is an empty case wastes an afternoon on a Go toolchain they did not
need — the ordering in `enrich` is deliberate and nothing was holding it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.case import Case
from logarc.cli.main import app

runner = CliRunner()

LINE = '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 2326 "-" "curl/8.0"'


@pytest.fixture
def empty_case(tmp_path: Path) -> Path:
    """A case that finished ingesting and holds nothing.

    Built from a log whose every line is quarantined, not from a bare
    `Case.create` — that leaves the case *unfinalised*, which is a different
    situation with its own message and is covered in test_unfinalised_case.py.
    """
    junk = tmp_path / "not-a-log.txt"
    junk.write_text("nothing here parses\nnor here\n", encoding="utf-8")
    root = tmp_path / "empty"
    with Case.create(root) as case:
        case.ingest([junk], log_format="apache-combined")
    return root


@pytest.fixture
def ingested_case(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text(LINE + "\n", encoding="utf-8")
    root = tmp_path / "case"
    with Case.create(root) as case:
        case.ingest([log])
    return root


def test_an_empty_case_is_named_as_the_problem(empty_case: Path) -> None:
    """Not "build the sidecar". The check runs before CRS is reached precisely
    so that someone who has not ingested yet is told that, and the ordering is
    the whole point of the test."""
    result = runner.invoke(app, ["enrich", "--case", str(empty_case)])

    assert result.exit_code == 1
    printed = " ".join(result.output.split())
    assert "ingest a log first" in printed
    assert "sidecar" not in printed.lower(), "an empty case is not a build problem"


def test_a_missing_sidecar_says_how_to_build_one(ingested_case: Path, tmp_path: Path) -> None:
    """With events present, the refusal is allowed to be about CRS — and has to
    say where the instructions are, because building it is not obvious."""
    result = runner.invoke(
        app,
        ["enrich", "--case", str(ingested_case), "--sidecar", str(tmp_path / "no-such-binary")],
    )

    assert result.exit_code == 1
    assert "Traceback" not in result.output
    # The build command itself, not a pointer to a document. Someone stopped
    # here cannot proceed without it, and a reference they have to go and find
    # is a worse answer than the line they need to run.
    printed = " ".join(result.output.split())
    assert "go build" in printed
    assert "LOGARC_CRS_BINARY" in printed


def test_a_case_that_is_not_a_case_is_reported(tmp_path: Path) -> None:
    result = runner.invoke(app, ["enrich", "--case", str(tmp_path / "nowhere")])

    assert result.exit_code == 1
    assert "Traceback" not in result.output
