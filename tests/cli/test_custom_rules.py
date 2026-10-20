"""Loading a rule pack the investigator wrote.

"Detection is data, not code" is only true if a pack written outside the
package can actually be used. These cover the path a reader of
docs/writing-rules.md takes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from logarc.cli.main import app

runner = CliRunner()

LINES = [
    '203.0.113.5 - - [10/Oct/2020:13:55:00 +0000] "GET / HTTP/1.1" 200 2326 "-" "curl/8.0"',
    '203.0.113.5 - - [10/Oct/2020:13:55:04 +0000] "GET /cgi-bin/quux.pl HTTP/1.1" 200 12 '
    '"-" "curl/8.0"',
]

PACK = """
version: 1
rules:
  - id: house_cgi_probe
    name: House rule CGI probe
    category: injection
    severity: high
    match:
      any:
        - {field: path_decoded, regex: "/cgi-bin/quux"}
"""


@pytest.fixture
def case(tmp_path: Path) -> Path:
    log = tmp_path / "access.log"
    log.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    result = runner.invoke(app, ["ingest", str(log), "--case", str(tmp_path / "case")])
    assert result.exit_code == 0, result.output
    return tmp_path / "case"


@pytest.fixture
def pack(tmp_path: Path) -> Path:
    path = tmp_path / "house.yaml"
    path.write_text(PACK, encoding="utf-8")
    return path


def analysed(case: Path, target: Path, *extra: str) -> dict[str, Any]:
    """Run `analyze` to JSON. Asserting on the table would test Rich's column
    widths, which truncate the activity name in a narrow test terminal."""
    result = runner.invoke(
        app,
        ["analyze", "-c", str(case), "--ip", "203.0.113.5", "-o", str(target), *extra],
    )
    assert result.exit_code == 0, result.output
    return json.loads(target.read_text(encoding="utf-8"))


def test_a_local_pack_adds_to_the_bundled_rules(case: Path, pack: Path, tmp_path: Path) -> None:
    graph = analysed(case, tmp_path / "with.json", "--rules", str(pack))

    assert "House rule CGI probe" in json.dumps(graph)


def test_without_the_pack_the_same_request_is_not_flagged(case: Path, tmp_path: Path) -> None:
    """Otherwise the test above would pass on a bundled rule and prove nothing."""
    graph = analysed(case, tmp_path / "without.json")

    assert "House rule CGI probe" not in json.dumps(graph)


def test_a_local_pack_changes_the_ruleset_fingerprint(case: Path, pack: Path) -> None:
    """The report states which ruleset produced it. If a custom pack did not
    move the fingerprint, two different analyses would claim the same
    provenance."""
    plain = analysed(case, case.parent / "plain.json")
    custom = analysed(case, case.parent / "custom.json", "--rules", str(pack))

    assert plain["ruleset_fingerprint"] != custom["ruleset_fingerprint"]


def test_a_broken_pack_is_reported_rather_than_ignored(case: Path, tmp_path: Path) -> None:
    """Silently skipping an unloadable pack would mean an investigator believes
    their rules ran when they did not."""
    broken = tmp_path / "broken.yaml"
    broken.write_text("version: 1\nrules:\n  - id: x\n    nonsense: true\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["analyze", "-c", str(case), "--ip", "203.0.113.5", "--rules", str(broken)],
    )

    assert result.exit_code != 0
    assert "broken.yaml" in result.output or "x" in result.output


def test_a_missing_pack_is_reported(case: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["analyze", "-c", str(case), "--ip", "203.0.113.5", "--rules", str(tmp_path / "gone.yaml")],
    )

    assert result.exit_code != 0


def test_the_export_command_takes_the_same_rules(case: Path, pack: Path, tmp_path: Path) -> None:
    """A report that disagrees with the analysis it came from is worse than no
    report, so every command that applies rules must accept the same ones."""
    target = tmp_path / "report.html"

    result = runner.invoke(
        app,
        [
            "export", "-c", str(case), "--ip", "203.0.113.5",
            "--rules", str(pack), "-o", str(target),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.output
    assert "House rule CGI probe" in target.read_text(encoding="utf-8")


def test_the_evidence_command_takes_the_same_rules(case: Path, pack: Path) -> None:
    result = runner.invoke(
        app,
        ["evidence", "-c", str(case), "--ip", "203.0.113.5", "--rules", str(pack)],
    )

    assert result.exit_code == 0, result.output
    assert "House rule CGI probe" in result.output


def test_a_pack_copying_a_built_in_id_is_refused(case: Path, tmp_path: Path) -> None:
    """docs/writing-rules.md says a duplicate id is refused, and until 2026-10-21
    it was refused only between the packs given on the command line: a pack
    reusing a built-in id loaded, and two rules answered to one id."""
    copied = tmp_path / "copied.yaml"
    copied.write_text(PACK.replace("house_cgi_probe", "sqli_union_select"), encoding="utf-8")

    result = runner.invoke(
        app,
        ["analyze", "-c", str(case), "--ip", "203.0.113.5", "--rules", str(copied)],
    )

    assert result.exit_code != 0
    assert "sqli_union_select" in result.output
    assert "built-in" in result.output
