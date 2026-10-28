"""`logarx-dev ingest` replaying the new case through CRS, which it does by default.

Decided 2026-10-05: CRS runs after every scan unless somebody says not to —
`--no-crs` for one run, `LOGARX_CRS=off` for a machine. `--crs` asks for it
whatever the machine says.

**The case is finished before CRS starts, and stays finished whatever CRS
does.** A missing sidecar, one that crashes, a log with nothing in it to
replay: each is a notice and exit 0, because the ingest the command was asked
for succeeded. `logarx-dev enrich` is the command that fails when CRS cannot run,
since there CRS is the whole job.

`tests/conftest.py` sets `LOGARX_CRS=off` for the suite; the tests here that are
about the default take it back off.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from logarx.case import Case
from logarx.detect.crs import AUTO_ENV, CrsUnavailableError, SidecarConfig
from logarx.detect.crs.sidecar import BINARY_ENV
from logarx.detect.crs.store import is_enriched
from logarx.devtools import main as cli_main
from logarx.devtools.main import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:36 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    "203.0.113.5 - - [10/Oct/2020:13:55:40 +0000] "
    '"GET /search?q=1%27%20UNION%20SELECT%20pw HTTP/1.1" 200 0 "-" "curl/8.0"',
]

_built = SidecarConfig()
_unbuilt = not _built.binary.exists() or not (_built.rules / "rules").is_dir()
needs_sidecar = pytest.mark.skipif(
    _unbuilt and os.environ.get("LOGARX_REQUIRE_CRS") != "1",
    reason="CRS sidecar or ruleset not built; see crs/README.md",
)


@pytest.fixture
def log(tmp_path: Path) -> Path:
    path = tmp_path / "access.log"
    path.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def no_sidecar(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A machine without CRS: the binary is pointed somewhere empty."""
    monkeypatch.setenv(BINARY_ENV, str(tmp_path / "no-such-sidecar"))


def _said(output: str) -> str:
    return " ".join(output.split())


@needs_sidecar
def test_a_new_case_is_replayed_through_crs_without_being_asked(
    log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real sidecar, end to end: CI builds it and requires it."""
    monkeypatch.delenv(AUTO_ENV, raising=False)
    case = tmp_path / "case"

    result = runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    assert result.exit_code == 0, result.output
    assert is_enriched(case), "ingest finished without running CRS"
    assert "CRS enrichment" in result.output


@needs_sidecar
def test_no_crs_reads_the_log_and_stops_there(
    log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(AUTO_ENV, raising=False)
    case = tmp_path / "case"

    result = runner.invoke(app, ["ingest", str(log), "--case", str(case), "--no-crs"])

    assert result.exit_code == 0, result.output
    assert not is_enriched(case)
    assert "CRS" not in result.output


@pytest.mark.usefixtures("no_sidecar")
def test_a_missing_sidecar_leaves_a_finished_case_and_says_so(
    log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The common state for an installation from source. The case is whole, so
    this is exit 0 — and the notice says how to stop seeing it, because it
    would otherwise arrive after every ingest on that machine."""
    monkeypatch.delenv(AUTO_ENV, raising=False)
    case = tmp_path / "case"

    result = runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    assert result.exit_code == 0, result.output
    said = _said(result.output)
    assert "complete without it" in said
    assert "--no-crs" in said
    assert AUTO_ENV in said
    assert not is_enriched(case)
    with Case.open(case) as opened:
        assert opened.manifest.total_events_parsed == 2


@pytest.mark.usefixtures("no_sidecar")
def test_a_missing_sidecar_names_the_one_command_that_sets_it_up(
    log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stopping the notice is one answer; getting CRS is the other, and from a
    source checkout that is one command rather than two to type correctly."""
    monkeypatch.delenv(AUTO_ENV, raising=False)

    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])

    assert "logarx-dev setup-crs" in _said(result.output)


@pytest.mark.usefixtures("no_sidecar")
def test_the_machine_wide_switch_means_crs_is_not_even_tried(log: Path, tmp_path: Path) -> None:
    """`LOGARX_CRS=off`, set by the suite's conftest. With no sidecar to find,
    a notice would be the proof it was looked for; there is none."""
    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])

    assert result.exit_code == 0, result.output
    assert "CRS" not in result.output


@pytest.mark.usefixtures("no_sidecar")
def test_asking_for_crs_outranks_the_machine_wide_switch(log: Path, tmp_path: Path) -> None:
    """`--crs` is somebody at the keyboard asking for this run. The switch is a
    default for runs nobody asked about, and this one was asked about."""
    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case"), "--crs"])

    assert result.exit_code == 0, result.output
    assert "complete without it" in _said(result.output)


@pytest.mark.usefixtures("no_sidecar")
def test_a_log_with_nothing_parsed_is_not_sent_to_crs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing to replay. Trying would end in `enrich_case`'s "ingest a log
    first", which is nonsense printed under an ingest that just ran."""
    monkeypatch.delenv(AUTO_ENV, raising=False)
    junk = tmp_path / "junk.log"
    junk.write_text("nothing here parses\nnor here\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["ingest", str(junk), "--case", str(tmp_path / "case"), "--format", "apache-combined"],
    )

    assert result.exit_code == 0, result.output
    said = _said(result.output)
    assert "CRS" not in said
    assert "ingest a log first" not in said


@pytest.mark.parametrize("failure", [CrsUnavailableError("crs-sidecar exited 2"), OSError(193)])
def test_crs_failing_part_way_leaves_the_case_and_says_how_to_retry(
    failure: Exception,
    log: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Installed, found, and then failing: a crash exits non-zero, which the
    sidecar module reports as `CrsUnavailableError`, and a damaged binary
    fails to start at all, which is an `OSError`. The ingest still happened."""
    monkeypatch.delenv(AUTO_ENV, raising=False)
    monkeypatch.setattr(cli_main.SidecarConfig, "check", lambda self: None)

    def broken(*_args: object, **_kwargs: object) -> object:
        raise failure

    monkeypatch.setattr(cli_main, "enrich_case", broken)
    case = tmp_path / "case"

    result = runner.invoke(app, ["ingest", str(log), "--case", str(case)])

    assert result.exit_code == 0, result.output
    assert "Traceback" not in result.output
    said = _said(result.output)
    assert "CRS did not finish" in said
    assert "logarx-dev enrich" in said
    assert str(case) in said
