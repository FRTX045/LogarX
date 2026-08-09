"""Tests for the HTML report.

This is the artefact that leaves the building. Everything else can be rerun by
whoever doubts it; the report is what gets attached to a case file and read by
someone who will never run the tool. It had no tests until the window started
offering it as an export, which is a thin place for a deliverable to be.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from logarc.analysis import analyse_ip
from logarc.case import Case
from logarc.report.html import render_report

START = datetime(2024, 5, 1, 12, 0, tzinfo=UTC)
ATTACKER = "203.0.113.66"
AGENT = "Mozilla/5.0 (X11; Linux x86_64)"


def line(seconds: int, target: str, *, status: int = 200, size: int = 512) -> str:
    when = (START + timedelta(seconds=seconds)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ATTACKER} - - [{when}] "GET {target} HTTP/1.1" {status} {size} "-" "{AGENT}"'


def build_case(tmp_path: Path, lines: list[str]) -> Case:
    log = tmp_path / "access.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with Case.create(tmp_path / "case") as case:
        case.ingest([log])
    return Case.open(tmp_path / "case")


@pytest.fixture
def campaign(tmp_path: Path) -> Case:
    lines = [line(0, "/"), line(20, "/products")]
    at = 60
    for index in range(25):
        lines.append(line(at, f"/admin/{index}", status=404))
        at += 1
    lines.append(line(at, "/p?id=1%20UNION%20SELECT%20pw%20FROM%20users", size=1_400_000))
    return build_case(tmp_path, lines)


def test_the_report_names_the_client_and_what_it_did(campaign: Case) -> None:
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert ATTACKER in page
    for episode in result.episodes:
        assert episode.label in page


def test_the_report_carries_the_provenance_of_the_case(campaign: Case) -> None:
    """A finding without the manifest behind it cannot be reproduced."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert campaign.manifest.tool_version in page
    assert campaign.manifest.sources[0].sha256 in page


def test_the_report_needs_no_network_to_read(campaign: Case) -> None:
    """It gets opened on machines that have no internet, and years later, when
    whatever it might have linked to is gone."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    assert not re.search(r'(?:src|href)\s*=\s*["\']https?://', page)
    assert "<iframe" not in page


def test_a_hostile_log_line_is_shown_not_executed(tmp_path: Path) -> None:
    """The report embeds strings an attacker chose. If they are not escaped,
    opening the report of an attack runs the attacker's script — in the
    investigator's browser, on the investigator's machine."""
    payload = "/<script>alert(1)</script>?x=%22onerror%3D%22alert(2)"
    case = build_case(tmp_path, [line(0, "/"), line(5, payload, status=404)])
    result = analyse_ip(case.store, ATTACKER)

    page = render_report(result, case.manifest)

    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    # Every script tag in the document is one the template put there.
    assert not re.search(r"<script[^>]*>(?!\s*</script>)", page)


def test_the_embedded_data_is_the_same_graph_the_cli_writes(campaign: Case) -> None:
    """`export --format html` and `export --format json` must not disagree
    about what happened; the report carries the JSON so the two cannot drift."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result, campaign.manifest)

    embedded = page.split("<details><summary>Machine-readable data</summary><pre>")[1]
    embedded = embedded.split("</pre>")[0]
    unescaped = embedded.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    unescaped = unescaped.replace("&#x27;", "'").replace("&quot;", '"')
    assert json.loads(unescaped) == result.to_dict()


def test_a_client_with_nothing_to_report_still_renders(campaign: Case) -> None:
    result = analyse_ip(campaign.store, "192.0.2.99")

    page = render_report(result, campaign.manifest)

    assert page.startswith("<!doctype html>") or page.lstrip().startswith("<!")
    assert "192.0.2.99" in page


def test_the_report_renders_without_a_manifest(campaign: Case) -> None:
    """`analyse_ip` output can be reported on its own, so the argument is
    optional; that path must not be the one nobody ever ran."""
    result = analyse_ip(campaign.store, ATTACKER)

    page = render_report(result)

    assert ATTACKER in page
