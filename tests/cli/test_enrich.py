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


def test_a_sidecar_that_crashes_is_reported_with_what_it_said(
    ingested_case: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CRS is the whole job here, so its own output is printed under the one
    line that says what happened: it is what a report of the fault needs."""
    from logarc.cli import main as cli_main
    from logarc.detect.crs import CrsUnavailableError

    def crash(*_args: object, **_kwargs: object) -> object:
        raise CrsUnavailableError(
            "CRS stopped unexpectedly (crs-sidecar exited 2: panic: wasm error)",
            detail="panic: wasm error\n\ngoroutine 1 [running]:\nmain.main()",
        )

    monkeypatch.setattr(cli_main.SidecarConfig, "check", lambda self: None)
    monkeypatch.setattr(cli_main, "enrich_case", crash)

    result = runner.invoke(app, ["enrich", "--case", str(ingested_case)])

    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert "CRS stopped unexpectedly" in result.output
    assert "goroutine 1 [running]:" in result.output


def test_a_case_that_is_not_a_case_is_reported(tmp_path: Path) -> None:
    result = runner.invoke(app, ["enrich", "--case", str(tmp_path / "nowhere")])

    assert result.exit_code == 1
    assert "Traceback" not in result.output


def _stopped_part_way(root: Path, *, replayed: int, requests: int) -> Path:
    """`root` as a stopped CRS run leaves it, without needing the sidecar."""
    from logarc.detect.crs.store import write_detections

    with Case.open(root) as case:
        write_detections(case.root, [])
        case.manifest.config.update(
            {
                "crs_fingerprint": "0123456789abcdef",
                "crs_replayed": replayed,
                "crs_requests": requests,
                "crs_complete": replayed == requests,
            }
        )
        case.manifest.save(case.root)
    return root


def test_analyze_says_when_crs_read_only_part_of_the_case(ingested_case: Path) -> None:
    """On every run, as "CRS not consulted" is: a request CRS never reached
    looks the same as one it read and passed."""
    _stopped_part_way(ingested_case, replayed=0, requests=1)

    result = runner.invoke(app, ["analyze", "--case", str(ingested_case), "--ip", "203.0.113.5"])

    assert result.exit_code == 0, result.output
    printed = " ".join(result.output.split())
    assert "CRS stopped part way" in printed
    assert "0 of 1 requests" in printed
    assert "CRS not consulted" not in printed


def test_analyze_says_nothing_about_a_complete_run(ingested_case: Path) -> None:
    _stopped_part_way(ingested_case, replayed=1, requests=1)

    result = runner.invoke(app, ["analyze", "--case", str(ingested_case), "--ip", "203.0.113.5"])

    assert result.exit_code == 0, result.output
    assert "part way" not in result.output
