"""The score-crs command, as a user meets it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from logarc.cli.main import app

runner = CliRunner()

AGENT = "OWASP CRS test agent"


def _flat(text: str) -> str:
    """Output with its line wrapping undone, so a phrase can be asserted whole."""
    return " ".join(text.split())


def _stage(uri: str, *, expect: bool = True) -> dict[str, Any]:
    key = "expect_ids" if expect else "no_expect_ids"
    return {
        "input": {
            "method": "GET",
            "uri": uri,
            "version": "HTTP/1.1",
            "headers": {"Host": "localhost", "User-Agent": AGENT},
        },
        "output": {"log": {key: [942100]}},
    }


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    """A miniature coreruleset clone: two families, one caught, one missed."""
    clone = tmp_path / "coreruleset"
    cases = {
        "REQUEST-942-APPLICATION-ATTACK-SQLI": (
            "942100.yaml",
            942100,
            [
                _stage("/get?id=1' OR '1'='1"),
                _stage("/get?id=harmless"),
                _stage("/x", expect=False),
            ],
        ),
        "REQUEST-930-APPLICATION-ATTACK-LFI": (
            "930100.yaml",
            930100,
            [_stage("/get?arg=../../../etc/passwd")],
        ),
    }
    for directory, (filename, rule_id, stages) in cases.items():
        root = clone / "tests" / "regression" / "tests" / directory
        root.mkdir(parents=True)
        (root / filename).write_text(
            yaml.safe_dump(
                {
                    "rule_id": rule_id,
                    "tests": [
                        {"test_id": number, "desc": "case", "stages": [item]}
                        for number, item in enumerate(stages, start=1)
                    ],
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
    return clone


def test_score_crs_reports_a_rate_per_family(clone: Path) -> None:
    result = runner.invoke(app, ["score-crs", "--corpus", str(clone)])

    assert result.exit_code == 0, result.stdout
    assert "942" in result.stdout
    assert "SQLi" in result.stdout
    assert "930" in result.stdout


def test_score_crs_states_that_no_category_mapping_is_claimed(clone: Path) -> None:
    """The category column is descriptive, and the output has to say so."""
    result = runner.invoke(app, ["score-crs", "--corpus", str(clone)])

    assert result.exit_code == 0, result.stdout
    assert "no mapping between them is claimed" in _flat(result.stdout)


def test_score_crs_states_that_the_figure_is_a_floor(clone: Path) -> None:
    result = runner.invoke(app, ["score-crs", "--corpus", str(clone)])

    assert result.exit_code == 0, result.stdout
    assert "a floor rather than an estimate" in _flat(result.stdout)
    assert "the corpus has no responses" in _flat(result.stdout)


def test_score_crs_reports_the_negatives_separately(clone: Path) -> None:
    result = runner.invoke(app, ["score-crs", "--corpus", str(clone)])

    assert result.exit_code == 0, result.stdout
    assert "cases assert that no rule should fire" in _flat(result.stdout)


def test_score_crs_writes_the_misses_as_json(clone: Path, tmp_path: Path) -> None:
    """The rate is the summary; the uncaught payloads are the deliverable."""
    out = tmp_path / "crs.json"

    result = runner.invoke(
        app,
        [
            "score-crs",
            "--corpus", str(clone),
            "--out", str(out),
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.stdout
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["totals"]["scoreable"] == 3
    assert report["totals"]["detected"] == 2
    assert report["ruleset_fingerprint"]
    assert [item["uri"] for item in report["misses"]] == ["/get?id=harmless"]
    assert report["excluded"]["negative_assertion"] == 1


def test_score_crs_can_be_narrowed_to_one_family(clone: Path) -> None:
    result = runner.invoke(
        app,
        [
            "score-crs",
            "--corpus", str(clone),
            "--family", "930",
        ],
    )  # fmt: skip

    assert result.exit_code == 0, result.stdout
    assert "LFI" in result.stdout
    assert "SQLi" not in result.stdout


def test_score_crs_on_a_path_that_is_not_a_clone_exits_with_an_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["score-crs", "--corpus", str(tmp_path)])

    assert result.exit_code == 1
